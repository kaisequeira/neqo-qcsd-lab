"""Evaluation contracts for the 100-class QCSD classifier study.

The formal handoff is the sole accepted input.  This module validates its
cohort, intrinsic cohort-assembly evidence, and temporal dimensions; loads
identifier-free observer traces; and constructs protocol partitions.
Classifier backends receive only capture-relative time, client-relative
direction, and observer-frame length.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from .buflo_evaluation import (
    AttackResult,
    DlsvmKernelStore,
    ShapePacket,
    StudySample,
    _fit_predict_attack,
    _load_osad_library,
    _load_performance,
    _load_weka_backend,
    _performance_is_complete,
    _validate_dlsvm_matrix_semantics,
    classifier_reference_receipt,
    dlsvm_backend_receipt,
    dlsvm_sequence,
    paired_overheads,
    performance_breakdowns,
    summarize_paired_overheads,
    vngpp_backend_receipt,
)
from .class_cohort import validate_cohort_assembly_receipt
from .class_handoff import (
    _CORRECTNESS_RECEIPT,
    CLASS_STUDY_LAUNCH_INPUT,
    CLASS_STUDY_LAUNCHES_PATH,
    CLASSIFIER_FIELDS,
    COHORT_ASSEMBLY_INPUT,
    FORBIDDEN_CLASSIFIER_FIELDS,
    verify_class_handoff,
)
from .class_handoff import (
    ARTIFACT_TYPE as HANDOFF_ARTIFACT_TYPE,
)
from .class_study import (
    FINAL_CLASS_COUNT,
    FORMAL_BLOCK_COUNT,
    FORMAL_MODES,
    FORMAL_VISITS_PER_BLOCK,
    STUDY_ID,
    bind_receipt,
    canonical_json_bytes,
    load_study_receipt,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .util import LAB_ROOT, load_json, require_disjoint_path, sha256_file, source_metadata

FORMAL_SAMPLE_COUNT = 16_000
FORMAL_BOOTSTRAP_DRAWS = 10_000
FORMAL_BOOTSTRAP_SEED = 20260828
CLOSED_WORLD_RANDOM_CHANCE = 0.01
TEMPORAL_PROTOCOL = "primary-leakage-resistant-temporal"
ADAPTIVE_PROTOCOL = "adaptive-per-defense"
TRANSFER_PROTOCOL = "undefended-trained-transfer"
STRATIFIED_PROTOCOL = "secondary-paper-style-stratified-ten-fold"
CLASSIFIER_INPUT_FIELDS = CLASSIFIER_FIELDS
CLASSIFIER_ATTACKS = ("panchenko", "vngpp", "dlsvm")
EVALUATION_RECEIPT_TYPE = "qcsd-class-study-evaluation"
EVALUATION_ARTIFACT_TYPE = "qcsd-classifier-multiorigin100-evaluation"
EVALUATION_SCHEMA_VERSION = 1

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_TOKENS = frozenset(
    {
        *FORBIDDEN_CLASSIFIER_FIELDS,
        "cid",
        "connection-id",
        "ip",
        "source",
        "destination",
    }
)


@dataclass(frozen=True)
class _Dimensions:
    study_id: str
    classes: int
    modes: tuple[str, ...]
    blocks: int
    visits_per_block: int

    @property
    def sample_count(self) -> int:
        return self.classes * len(self.modes) * self.blocks * self.visits_per_block

    @property
    def train_blocks(self) -> tuple[int, ...]:
        return tuple(range(1, self.blocks - 1))

    @property
    def validation_blocks(self) -> tuple[int, ...]:
        return (self.blocks - 1,)

    @property
    def test_blocks(self) -> tuple[int, ...]:
        return (self.blocks,)


_FORMAL_DIMENSIONS = _Dimensions(
    study_id=STUDY_ID,
    classes=FINAL_CLASS_COUNT,
    modes=FORMAL_MODES,
    blocks=FORMAL_BLOCK_COUNT,
    visits_per_block=FORMAL_VISITS_PER_BLOCK,
)


def _formal_dimensions_for_study(study_id: str) -> _Dimensions:
    if study_id != STUDY_ID and not study_id.startswith(
        "classifier-multiorigin100-v2-"
    ):
        raise ValueError("formal class evaluation study identity is invalid")
    return _Dimensions(
        study_id=study_id,
        classes=FINAL_CLASS_COUNT,
        modes=FORMAL_MODES,
        blocks=FORMAL_BLOCK_COUNT,
        visits_per_block=FORMAL_VISITS_PER_BLOCK,
    )


def _is_formal_dimensions(dimensions: _Dimensions) -> bool:
    return (
        dimensions.classes == FINAL_CLASS_COUNT
        and dimensions.modes == FORMAL_MODES
        and dimensions.blocks == FORMAL_BLOCK_COUNT
        and dimensions.visits_per_block == FORMAL_VISITS_PER_BLOCK
        and (
            dimensions.study_id == STUDY_ID
            or dimensions.study_id.startswith("classifier-multiorigin100-v2-")
        )
    )
if _FORMAL_DIMENSIONS.sample_count != FORMAL_SAMPLE_COUNT:
    raise RuntimeError("class evaluation sample constant differs from the study contract")
if 1.0 / _FORMAL_DIMENSIONS.classes != CLOSED_WORLD_RANDOM_CHANCE:
    raise RuntimeError("class evaluation chance baseline differs from the study contract")


@dataclass(frozen=True)
class ClassStudySample:
    """One formal sample with coordinator metadata and shape-only trace data."""

    sample_id: str
    class_label: str
    workload_id: str
    mode: str
    acquisition_block: int
    split: str
    visit: int
    paired_class_visit_id: str
    trace: tuple[ShapePacket, ...]
    correctness: Mapping[str, Any] | None = None
    performance: Mapping[str, Any] | None = None

    @property
    def classifier_input(self) -> tuple[ShapePacket, ...]:
        """Return the complete and only classifier-visible packet sequence."""

        return self.trace


@dataclass(frozen=True)
class ClassStudyDataset:
    """A verified, immutable formal handoff projected onto evaluation fields."""

    root: Path
    study_id: str
    cohort_sha256: str
    cohort_payload_sha256: str
    cohort_assembly_sha256: str
    cohort_assembly_payload_sha256: str
    class_study_launch_sha256s: tuple[str, ...]
    classes: tuple[str, ...]
    modes: tuple[str, ...]
    samples: tuple[ClassStudySample, ...]

    @property
    def random_chance(self) -> float:
        return 1.0 / len(self.classes)


@dataclass(frozen=True)
class TemporalDatasetSplit:
    """Train/validation/held-out membership for one attack view."""

    protocol: str
    attack_view: str
    training_mode: str
    testing_mode: str
    train: tuple[ClassStudySample, ...]
    validation: tuple[ClassStudySample, ...]
    heldout_test: tuple[ClassStudySample, ...]


@dataclass(frozen=True)
class StratifiedFold:
    """One fold in the explicitly secondary paper-style protocol."""

    protocol: str
    mode: str
    fold: int
    train: tuple[ClassStudySample, ...]
    test: tuple[ClassStudySample, ...]


@dataclass(frozen=True)
class ClassificationPrediction:
    """One prediction and the two permitted bootstrap cluster identifiers."""

    sample_id: str
    acquisition_block: int
    workload_id: str
    expected: str
    predicted: str

    @classmethod
    def from_sample(
        cls,
        sample: ClassStudySample,
        predicted: str,
    ) -> ClassificationPrediction:
        return cls(
            sample_id=sample.sample_id,
            acquisition_block=sample.acquisition_block,
            workload_id=sample.workload_id,
            expected=sample.class_label,
            predicted=predicted,
        )


@dataclass(frozen=True)
class ClassificationMetrics:
    """Closed-world point metrics with an explicit class-axis order."""

    labels: tuple[str, ...]
    sample_count: int
    accuracy: float
    balanced_accuracy: float
    confusion_matrix: tuple[tuple[int, ...], ...]
    per_class_recall: Mapping[str, float]

    def as_dict(self) -> dict[str, Any]:
        return {
            "labels": list(self.labels),
            "sample_count": self.sample_count,
            "accuracy": self.accuracy,
            "balanced_accuracy": self.balanced_accuracy,
            "confusion_matrix": [list(row) for row in self.confusion_matrix],
            "per_class_recall": dict(self.per_class_recall),
        }


@dataclass(frozen=True)
class ClassAttackRun:
    """One completed classifier matrix and its exact backend/cache lineage."""

    attacks: tuple[str, ...]
    include_secondary: bool
    results: tuple[AttackResult, ...]
    classifier_provenance: Mapping[str, Any]
    dlsvm_cache: Mapping[str, Any] | None


@dataclass(frozen=True)
class _AttackSpec:
    attack: str
    protocol: str
    training_mode: str
    testing_mode: str
    training: tuple[ClassStudySample, ...]
    testing: tuple[ClassStudySample, ...]
    folds: tuple[StratifiedFold, ...] | None = None


HandoffVerifier = Callable[[Path, bool], Path]
CohortLoader = Callable[[Path], tuple[Mapping[str, Any], Any]]
AssemblyValidator = Callable[..., Mapping[str, Any]]
AttackExecutor = Callable[..., AttackResult]


def load_class_handoff(root: Path, *, deep_verify: bool = True) -> ClassStudyDataset:
    """Deeply verify and load the exact 16,000-sample formal handoff.

    ``deep_verify=True`` additionally re-derives observer traces from raw
    PCAPNG evidence through :func:`verify_class_handoff`.  Disabling it still
    revalidates the handoff's closed checksum inventory and source lineage.
    """

    dataset = _load_json_object(Path(root) / "dataset.json", "formal class dataset")
    study_id = dataset.get("study_id")
    if not isinstance(study_id, str):
        raise ValueError("formal class evaluation dataset has no study identity")
    return _load_class_handoff(
        root,
        dimensions=_formal_dimensions_for_study(study_id),
        handoff_verifier=_verify_handoff,
        cohort_loader=load_study_receipt,
        assembly_validator=validate_cohort_assembly_receipt,
        deep_verify=deep_verify,
    )


def run_class_attacks(
    dataset: ClassStudyDataset,
    *,
    attacks: Sequence[str] = CLASSIFIER_ATTACKS,
    include_secondary: bool = True,
    dlsvm_cache_directory: Path | None = None,
    formal: bool = False,
) -> ClassAttackRun:
    """Execute the temporal and secondary classifier matrix.

    The implementation delegates model fitting to the existing Panchenko,
    pinned-Weka VNG++, and clean-room DLSVM backends.  Formal execution
    requires the complete attack suite, the secondary view, pinned Weka, the
    native DLSVM accelerator, and a persistent create-only kernel cache.
    """

    return _run_class_attacks(
        dataset,
        attacks=attacks,
        include_secondary=include_secondary,
        dlsvm_cache_directory=dlsvm_cache_directory,
        formal=formal,
        attack_executor=_execute_attack,
        classifier_provenance_builder=_classifier_provenance,
    )


def write_class_evaluation_receipt(
    path: Path,
    *,
    handoff_root: Path,
    dlsvm_cache_directory: Path | None = None,
    deep_verify_handoff: bool = True,
) -> Path:
    """Execute the full formal matrix and publish one create-only receipt."""

    if deep_verify_handoff is not True:
        raise ValueError("formal class evaluation requires deep handoff verification")
    destination = Path(os.path.abspath(path))
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"class evaluation receipt already exists: {destination}")
    handoff = Path(handoff_root).resolve()
    destination = require_disjoint_path(
        destination,
        (handoff,),
        label="class evaluation receipt",
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    cache = (
        Path(dlsvm_cache_directory)
        if dlsvm_cache_directory is not None
        else destination.with_name(f"{destination.stem}.dlsvm-cache")
    )
    cache = require_disjoint_path(
        cache,
        (handoff, destination),
        label="class evaluation DLSVM cache",
    )
    dataset = load_class_handoff(handoff, deep_verify=deep_verify_handoff)
    handoff_binding = _handoff_binding(dataset)
    evaluator_source = _evaluator_source_binding(dataset, formal=True)
    attack_run = run_class_attacks(
        dataset,
        attacks=CLASSIFIER_ATTACKS,
        include_secondary=True,
        dlsvm_cache_directory=cache,
        formal=True,
    )
    verify_class_handoff(dataset.root, deep=False)
    if _evaluator_source_binding(dataset, formal=True) != evaluator_source:
        raise ValueError("class evaluator source changed during attack execution")
    if _handoff_binding(dataset) != handoff_binding:
        raise ValueError("class evaluation handoff changed during attack execution")
    envelope = _build_evaluation_envelope(
        dataset,
        attack_run,
        formal=True,
        evaluator_source=evaluator_source,
    )
    _validate_evaluation_envelope(
        envelope,
        dataset=dataset,
        expected_evaluator_source=evaluator_source,
        expected_classifier_provenance=attack_run.classifier_provenance,
        formal=True,
    )
    return write_create_only_json(destination, envelope)


def verify_class_evaluation_receipt(
    path: Path,
    *,
    handoff_root: Path,
    deep_verify_handoff: bool = True,
    replay_attacks: bool = True,
) -> dict[str, Any]:
    """Revalidate a formal receipt and optionally replay every fitted model."""

    if type(deep_verify_handoff) is not bool or type(replay_attacks) is not bool:
        raise ValueError("class evaluation verification flags must be booleans")
    receipt_path = Path(path).resolve()
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("class evaluation receipt is not a regular file")
    handoff = Path(handoff_root).resolve()
    require_disjoint_path(receipt_path, (handoff,), label="class evaluation receipt")
    dataset = load_class_handoff(handoff, deep_verify=deep_verify_handoff)
    try:
        value = load_json(receipt_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("class evaluation receipt is invalid JSON") from error
    if receipt_path.read_bytes() != canonical_json_bytes(value):
        raise ValueError("class evaluation receipt is not canonically encoded")
    evaluator_source = _evaluator_source_binding(dataset, formal=True)
    classifier_provenance = _classifier_provenance(CLASSIFIER_ATTACKS, formal=True)
    payload = _validate_evaluation_envelope(
        value,
        dataset=dataset,
        expected_evaluator_source=evaluator_source,
        expected_classifier_provenance=classifier_provenance,
        formal=True,
    )
    cache_value = payload.get("dlsvm_cache")
    if not isinstance(cache_value, Mapping) or not isinstance(cache_value.get("path"), str):
        raise ValueError("formal class evaluation has no replayable DLSVM cache")
    if not replay_attacks:
        _validate_dlsvm_cache_binding(
            cache_value,
            dataset=dataset,
            recompute_values=True,
        )
    if replay_attacks:
        replayed = run_class_attacks(
            dataset,
            attacks=CLASSIFIER_ATTACKS,
            include_secondary=True,
            dlsvm_cache_directory=Path(cache_value["path"]),
            formal=True,
        )
        if (
            _result_records(replayed.results, dataset.classes) != payload["results"]
            or replayed.dlsvm_cache != cache_value
        ):
            raise ValueError("class evaluation predictions differ from deterministic replay")
        verify_class_handoff(dataset.root, deep=False)
        if _handoff_binding(dataset) != payload["handoff"]:
            raise ValueError("class evaluation handoff changed during deterministic replay")
        if _evaluator_source_binding(dataset, formal=True) != payload["evaluator_source"]:
            raise ValueError("class evaluator source changed during deterministic replay")
    result = dict(payload)
    limitations = []
    if not deep_verify_handoff:
        limitations.append("raw trace and classic-PCAP derivations were not replayed")
    if not replay_attacks:
        limitations.append("classifier fitting and predictions were not replayed")
    result["verification_strength"] = {
        "level": "full-replay" if not limitations else "reduced",
        "deep_handoff": deep_verify_handoff,
        "classic_pcap_regenerated": deep_verify_handoff,
        "correctness_recomputed": True,
        "performance_summary_recomputed": True,
        "performance_raw_evidence_recomputed": deep_verify_handoff,
        "dlsvm_all_matrix_cells_recomputed": True,
        "classifier_attacks_replayed": replay_attacks,
        "limitations": limitations,
        "authorizes_final_attestation": False,
    }
    return result


def adaptive_temporal_splits(
    dataset: ClassStudyDataset,
) -> tuple[TemporalDatasetSplit, ...]:
    """Return one primary temporal train/validation/test split per defense."""

    return tuple(
        _temporal_split(
            dataset,
            attack_view=ADAPTIVE_PROTOCOL,
            training_mode=mode,
            testing_mode=mode,
        )
        for mode in dataset.modes
    )


def undefended_transfer_splits(
    dataset: ClassStudyDataset,
) -> tuple[TemporalDatasetSplit, ...]:
    """Return undefended-trained temporal transfer splits for every mode."""

    if "undefended" not in dataset.modes:
        raise ValueError("undefended-trained transfer requires an undefended mode")
    return tuple(
        _temporal_split(
            dataset,
            attack_view=TRANSFER_PROTOCOL,
            training_mode="undefended",
            testing_mode=mode,
        )
        for mode in dataset.modes
    )


def stratified_ten_fold_splits(
    dataset: ClassStudyDataset,
    mode: str,
    *,
    seed: int = FORMAL_BOOTSTRAP_SEED,
) -> tuple[StratifiedFold, ...]:
    """Build a deterministic, separately labelled ten-fold secondary view."""

    if mode not in dataset.modes:
        raise ValueError(f"stratified protocol mode is not in the handoff: {mode!r}")
    if type(seed) is not int:
        raise ValueError("stratified protocol seed must be an integer")
    by_class: dict[str, list[ClassStudySample]] = defaultdict(list)
    for sample in dataset.samples:
        if sample.mode == mode:
            by_class[sample.class_label].append(sample)
    if tuple(by_class) != dataset.classes:
        by_class = {label: by_class[label] for label in dataset.classes}

    assignments: list[list[ClassStudySample]] = [[] for _ in range(10)]
    expected_per_class = None
    for label in dataset.classes:
        members = by_class[label]
        if not members or len(members) % 10:
            raise ValueError("stratified ten-fold requires equal class counts divisible by ten")
        if expected_per_class is None:
            expected_per_class = len(members)
        elif len(members) != expected_per_class:
            raise ValueError("stratified ten-fold class counts are not balanced")
        ordered = sorted(
            members,
            key=lambda sample: (
                hashlib.sha256(
                    f"{seed}\0{mode}\0{label}\0{sample.sample_id}".encode("utf-8")
                ).hexdigest(),
                sample.sample_id,
            ),
        )
        for index, sample in enumerate(ordered):
            assignments[index % 10].append(sample)

    all_samples = tuple(
        sorted(
            (sample for members in assignments for sample in members),
            key=_sample_key,
        )
    )
    if len({sample.sample_id for sample in all_samples}) != len(all_samples):
        raise ValueError("stratified protocol sample membership is not unique")
    folds: list[StratifiedFold] = []
    for fold, testing in enumerate(assignments, start=1):
        test_ids = {sample.sample_id for sample in testing}
        train = tuple(sample for sample in all_samples if sample.sample_id not in test_ids)
        test = tuple(sorted(testing, key=_sample_key))
        if Counter(sample.class_label for sample in test) != {
            label: len(by_class[label]) // 10 for label in dataset.classes
        }:
            raise ValueError("stratified protocol fold is not class-balanced")
        folds.append(
            StratifiedFold(
                protocol=STRATIFIED_PROTOCOL,
                mode=mode,
                fold=fold,
                train=train,
                test=test,
            )
        )
    return tuple(folds)


def _run_class_attacks(
    dataset: ClassStudyDataset,
    *,
    attacks: Sequence[str],
    include_secondary: bool,
    dlsvm_cache_directory: Path | None,
    formal: bool,
    attack_executor: AttackExecutor,
    classifier_provenance_builder: Callable[[Sequence[str], bool], Mapping[str, Any]],
) -> ClassAttackRun:
    attack_order = _validate_attack_configuration(
        dataset,
        attacks=attacks,
        include_secondary=include_secondary,
        formal=formal,
    )
    provenance = dict(classifier_provenance_builder(attack_order, formal))
    _validate_classifier_provenance(provenance, attacks=attack_order, formal=formal)

    cache: Path | None = None
    if "dlsvm" in attack_order:
        if dlsvm_cache_directory is not None:
            cache = require_disjoint_path(
                Path(dlsvm_cache_directory),
                (dataset.root,),
                label="class evaluation DLSVM cache",
            )
        elif formal:
            raise ValueError("formal class DLSVM evaluation requires a persistent cache")
    backend_samples = tuple(_backend_sample(sample) for sample in dataset.samples)
    backend_by_id = {sample.sample_id: sample for sample in backend_samples}
    dlsvm_store = (
        DlsvmKernelStore(backend_samples, cache_directory=cache)
        if "dlsvm" in attack_order
        else None
    )

    results: list[AttackResult] = []
    specs = _attack_specs(
        dataset,
        attacks=attack_order,
        include_secondary=include_secondary,
    )
    for spec in specs:
        if spec.folds is None:
            results.append(
                attack_executor(
                    spec.attack,
                    [backend_by_id[sample.sample_id] for sample in spec.training],
                    [backend_by_id[sample.sample_id] for sample in spec.testing],
                    training_defense=spec.training_mode,
                    testing_defense=spec.testing_mode,
                    protocol=spec.protocol,
                    dlsvm_store=dlsvm_store,
                )
            )
            continue
        fold_results = tuple(
            attack_executor(
                spec.attack,
                [backend_by_id[sample.sample_id] for sample in fold.train],
                [backend_by_id[sample.sample_id] for sample in fold.test],
                training_defense=spec.training_mode,
                testing_defense=spec.testing_mode,
                protocol=spec.protocol,
                dlsvm_store=dlsvm_store,
            )
            for fold in spec.folds
        )
        results.append(_aggregate_secondary_results(spec, fold_results))

    cache_receipt = dlsvm_store.receipt() if dlsvm_store is not None else None
    result = ClassAttackRun(
        attacks=attack_order,
        include_secondary=include_secondary,
        results=tuple(results),
        classifier_provenance=provenance,
        dlsvm_cache=cache_receipt,
    )
    _validate_attack_run(result, dataset=dataset, formal=formal)
    return result


def _execute_attack(
    attack: str,
    training: Sequence[StudySample],
    testing: Sequence[StudySample],
    *,
    training_defense: str,
    testing_defense: str,
    protocol: str,
    dlsvm_store: DlsvmKernelStore | None,
) -> AttackResult:
    return _fit_predict_attack(
        attack,
        training,
        testing,
        training_defense=training_defense,
        testing_defense=testing_defense,
        protocol=protocol,
        dlsvm_store=dlsvm_store,
    )


def _attack_specs(
    dataset: ClassStudyDataset,
    *,
    attacks: Sequence[str],
    include_secondary: bool,
) -> tuple[_AttackSpec, ...]:
    adaptive = adaptive_temporal_splits(dataset)
    transfer = undefended_transfer_splits(dataset)
    specs: list[_AttackSpec] = []
    for attack in attacks:
        for phase in ("validation", "heldout-test"):
            for split in (*adaptive, *transfer):
                testing = split.validation if phase == "validation" else split.heldout_test
                specs.append(
                    _AttackSpec(
                        attack=attack,
                        protocol=f"temporal-{phase}-{split.attack_view}",
                        training_mode=split.training_mode,
                        testing_mode=split.testing_mode,
                        training=split.train,
                        testing=testing,
                    )
                )
        if include_secondary:
            for mode in dataset.modes:
                folds = stratified_ten_fold_splits(dataset, mode)
                members = tuple(
                    sorted(
                        (sample for sample in dataset.samples if sample.mode == mode),
                        key=_sample_key,
                    )
                )
                specs.append(
                    _AttackSpec(
                        attack=attack,
                        protocol=STRATIFIED_PROTOCOL,
                        training_mode=mode,
                        testing_mode=mode,
                        training=members,
                        testing=members,
                        folds=folds,
                    )
                )
    return tuple(specs)


def _aggregate_secondary_results(
    spec: _AttackSpec,
    fold_results: Sequence[AttackResult],
) -> AttackResult:
    if spec.folds is None or len(spec.folds) != 10 or len(fold_results) != 10:
        raise ValueError("secondary attack aggregation requires exactly ten folds")
    first = fold_results[0]
    if any(
        result.attack != spec.attack
        or result.backend != first.backend
        or result.training_defense != spec.training_mode
        or result.testing_defense != spec.testing_mode
        or result.protocol != STRATIFIED_PROTOCOL
        or result.labels != first.labels
        for result in fold_results
    ):
        raise ValueError("secondary attack folds have inconsistent identities")
    for fold, result in zip(spec.folds, fold_results, strict=True):
        if (
            result.train_samples != len(fold.train)
            or result.test_samples != len(fold.test)
            or result.protocol_details != _simple_protocol_details(fold.train, fold.test)
        ):
            raise ValueError("secondary attack fold membership changed during execution")
    predictions = tuple(prediction for result in fold_results for prediction in result.predictions)
    metrics = classification_metrics(
        [prediction.expected for prediction in predictions],
        [prediction.predicted for prediction in predictions],
        first.labels,
    )
    return AttackResult(
        attack=spec.attack,
        backend=first.backend,
        training_defense=spec.training_mode,
        testing_defense=spec.testing_mode,
        protocol=STRATIFIED_PROTOCOL,
        train_samples=_spec_train_sample_count(spec),
        test_samples=len(spec.testing),
        labels=metrics.labels,
        accuracy=metrics.accuracy,
        balanced_accuracy=metrics.balanced_accuracy,
        confusion_matrix=metrics.confusion_matrix,
        per_class_recall=metrics.per_class_recall,
        predictions=predictions,
        protocol_details=_secondary_protocol_details(spec.folds),
    )


def _backend_sample(sample: ClassStudySample) -> StudySample:
    """Project to the classifier backend without correctness/performance fields."""

    return StudySample(
        sample_id=sample.sample_id,
        class_label=sample.class_label,
        workload_id=sample.workload_id,
        defense=sample.mode,
        acquisition_block_index=sample.acquisition_block,
        paired_visit_id=sample.paired_class_visit_id,
        trace=sample.trace,
    )


def _performance_sample(sample: ClassStudySample) -> StudySample:
    """Project to the metrics backend; never pass this object to a classifier."""

    return StudySample(
        sample_id=sample.sample_id,
        class_label=sample.class_label,
        workload_id=sample.workload_id,
        defense=sample.mode,
        acquisition_block_index=sample.acquisition_block,
        paired_visit_id=sample.paired_class_visit_id,
        trace=sample.trace,
        performance=sample.performance,
    )


def _simple_protocol_details(
    training: Sequence[ClassStudySample],
    testing: Sequence[ClassStudySample],
) -> dict[str, Any]:
    training_ids = [sample.sample_id for sample in training]
    testing_ids = [sample.sample_id for sample in testing]
    return {
        "training_sample_ids": training_ids,
        "training_sample_ids_sha256": _compact_json_sha256(training_ids),
        "testing_sample_ids": testing_ids,
        "testing_sample_ids_sha256": _compact_json_sha256(testing_ids),
    }


def _secondary_protocol_details(folds: Sequence[StratifiedFold]) -> dict[str, Any]:
    membership = [
        {
            "fold": fold.fold,
            **_simple_protocol_details(fold.train, fold.test),
        }
        for fold in folds
    ]
    return {
        "splitter": "qcsd-sha256-round-robin-within-class",
        "protocol_label": STRATIFIED_PROTOCOL,
        "n_splits": 10,
        "seed": FORMAL_BOOTSTRAP_SEED,
        "folds": membership,
        "folds_sha256": _compact_json_sha256(membership),
    }


def _spec_train_sample_count(spec: _AttackSpec) -> int:
    """Return the number actually fitted for one protocol execution.

    A secondary record aggregates ten predictions folds, but each model is
    fitted on only nine folds.  Reporting the full mode inventory here would
    overstate every paper-style training set by one fold.
    """

    if spec.folds is None:
        return len(spec.training)
    counts = {len(fold.train) for fold in spec.folds}
    if len(counts) != 1:
        raise ValueError("secondary attack folds have unequal training sizes")
    return counts.pop()


def classification_metrics(
    expected: Sequence[str],
    predicted: Sequence[str],
    labels: Sequence[str],
) -> ClassificationMetrics:
    """Calculate accuracy, balanced accuracy, confusion, and per-class recall."""

    label_order = _validate_labels(labels)
    if not expected or len(expected) != len(predicted):
        raise ValueError("classification vectors must be non-empty and equally sized")
    indexes = {label: index for index, label in enumerate(label_order)}
    matrix = [[0 for _ in label_order] for _ in label_order]
    for actual, guess in zip(expected, predicted, strict=True):
        if actual not in indexes or guess not in indexes:
            raise ValueError("classification label is outside the declared cohort")
        matrix[indexes[actual]][indexes[guess]] += 1
    recalls = {
        label: (row[indexes[label]] / sum(row) if sum(row) else 0.0)
        for label, row in zip(label_order, matrix, strict=True)
    }
    correct = sum(matrix[index][index] for index in range(len(label_order)))
    return ClassificationMetrics(
        labels=label_order,
        sample_count=len(expected),
        accuracy=correct / len(expected),
        balanced_accuracy=float(np.mean(tuple(recalls.values()))),
        confusion_matrix=tuple(tuple(row) for row in matrix),
        per_class_recall=recalls,
    )


def formal_block_workload_bootstrap(
    predictions: Sequence[ClassificationPrediction],
    labels: Sequence[str],
    *,
    draws: int = FORMAL_BOOTSTRAP_DRAWS,
    seed: int = FORMAL_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Return deterministic 95% intervals over block/workload clusters."""

    if draws != FORMAL_BOOTSTRAP_DRAWS:
        raise ValueError(
            f"formal class evaluation requires exactly {FORMAL_BOOTSTRAP_DRAWS} bootstrap draws"
        )
    if type(seed) is not int:
        raise ValueError("bootstrap seed must be an integer")
    label_order = _validate_labels(labels)
    values = tuple(predictions)
    _validate_predictions(values, label_order)
    point = classification_metrics(
        [prediction.expected for prediction in values],
        [prediction.predicted for prediction in values],
        label_order,
    )

    clusters: dict[tuple[int, str], list[ClassificationPrediction]] = defaultdict(list)
    for prediction in values:
        clusters[(prediction.acquisition_block, prediction.workload_id)].append(prediction)
    blocks = tuple(sorted({key[0] for key in clusters}))
    expected_keys = {(block, workload) for block in blocks for workload in label_order}
    if set(clusters) != expected_keys:
        raise ValueError(
            "formal bootstrap requires a complete acquisition-block/workload rectangle"
        )
    sample_totals = np.zeros((len(blocks), len(label_order)), dtype=np.int64)
    correct_totals = np.zeros((len(blocks), len(label_order)), dtype=np.int64)
    for block_index, block in enumerate(blocks):
        for workload_index, workload in enumerate(label_order):
            cell = clusters[(block, workload)]
            sample_totals[block_index, workload_index] = len(cell)
            correct_totals[block_index, workload_index] = sum(
                prediction.expected == prediction.predicted for prediction in cell
            )

    rng = np.random.default_rng(seed)
    accuracy = np.empty(draws, dtype=np.float64)
    balanced = np.empty(draws, dtype=np.float64)
    recall = np.empty((draws, len(label_order)), dtype=np.float64)
    for draw in range(draws):
        block_multiplicity = np.bincount(
            rng.integers(0, len(blocks), size=len(blocks)),
            minlength=len(blocks),
        )
        workload_multiplicity = np.bincount(
            rng.integers(0, len(label_order), size=len(label_order)),
            minlength=len(label_order),
        )
        cell_weights = np.multiply.outer(block_multiplicity, workload_multiplicity)
        total = int(np.sum(cell_weights * sample_totals))
        accuracy[draw] = float(np.sum(cell_weights * correct_totals)) / total
        workload_totals = block_multiplicity @ sample_totals
        workload_correct = block_multiplicity @ correct_totals
        recall[draw] = np.divide(
            workload_correct,
            workload_totals,
            out=np.zeros(len(label_order), dtype=np.float64),
            where=workload_totals != 0,
        )
        balanced[draw] = float(workload_multiplicity @ recall[draw] / np.sum(workload_multiplicity))

    return {
        "draws": draws,
        "seed": seed,
        "cluster": "acquisition_block+workload_id",
        "method": "two-way-pigeonhole-product-weight-cluster-bootstrap",
        "cluster_dimensions": ["acquisition_block", "workload_id"],
        "resampling": {
            "acquisition_blocks": "independent multinomial-with-replacement",
            "workloads": "independent multinomial-with-replacement",
            "cell_weight": "block_multiplicity*workload_multiplicity",
            "per_class_recall": (
                "conditional-on-workload recall under block resampling; workload "
                "multiplicity weights balanced accuracy"
            ),
        },
        "point": point.as_dict(),
        "bootstrap_95": {
            "accuracy": _interval(accuracy),
            "balanced_accuracy": _interval(balanced),
            "per_class_recall": {
                label: _interval(recall[:, index]) for index, label in enumerate(label_order)
            },
        },
    }


def summarize_temporal_predictions(
    split: TemporalDatasetSplit,
    predictions: Sequence[ClassificationPrediction],
    labels: Sequence[str],
    *,
    phase: str = "heldout-test",
    draws: int = FORMAL_BOOTSTRAP_DRAWS,
    seed: int = FORMAL_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Validate exact temporal membership before calculating formal metrics."""

    if phase == "validation":
        expected_samples = split.validation
        use = "model-selection-only"
    elif phase == "heldout-test":
        expected_samples = split.heldout_test
        use = "final-report-no-tuning"
    else:
        raise ValueError("temporal prediction phase must be validation or heldout-test")
    values = tuple(predictions)
    expected_by_id = {sample.sample_id: sample for sample in expected_samples}
    if len(values) != len(expected_by_id) or {value.sample_id for value in values} != set(
        expected_by_id
    ):
        raise ValueError("temporal predictions do not exactly cover the declared partition")
    for prediction in values:
        sample = expected_by_id[prediction.sample_id]
        if (
            prediction.acquisition_block != sample.acquisition_block
            or prediction.workload_id != sample.workload_id
            or prediction.expected != sample.class_label
        ):
            raise ValueError("temporal prediction identity differs from its handoff sample")
    summary = formal_block_workload_bootstrap(values, labels, draws=draws, seed=seed)
    return {
        "protocol": split.protocol,
        "attack_view": split.attack_view,
        "phase": phase,
        "use": use,
        "training_mode": split.training_mode,
        "testing_mode": split.testing_mode,
        "class_count": len(tuple(labels)),
        "random_chance": 1.0 / len(tuple(labels)),
        "sample_count": len(values),
        "metrics": summary,
    }


def classifier_feature_rows(sample: ClassStudySample) -> tuple[dict[str, int | str], ...]:
    """Project one sample to the exact three identifier-free feature fields."""

    return tuple(
        {
            "relative_time_ns": packet.relative_time_ns,
            "direction": packet.direction,
            "observer_frame_length_bytes": packet.length_bytes,
        }
        for packet in sample.trace
    )


def _validate_attack_configuration(
    dataset: ClassStudyDataset,
    *,
    attacks: Sequence[str],
    include_secondary: bool,
    formal: bool,
) -> tuple[str, ...]:
    attack_order = tuple(attacks)
    if (
        not attack_order
        or len(set(attack_order)) != len(attack_order)
        or any(attack not in CLASSIFIER_ATTACKS for attack in attack_order)
        or attack_order != tuple(attack for attack in CLASSIFIER_ATTACKS if attack in attack_order)
    ):
        raise ValueError("class attack selection must be a non-empty canonical subset")
    if type(include_secondary) is not bool or type(formal) is not bool:
        raise ValueError("class attack protocol flags must be booleans")
    if formal and (
        (
            dataset.study_id != STUDY_ID
            and not dataset.study_id.startswith("classifier-multiorigin100-v2-")
        )
        or len(dataset.classes) != FINAL_CLASS_COUNT
        or dataset.modes != FORMAL_MODES
        or len(dataset.samples) != FORMAL_SAMPLE_COUNT
        or dataset.random_chance != CLOSED_WORLD_RANDOM_CHANCE
        or attack_order != CLASSIFIER_ATTACKS
        or not include_secondary
    ):
        raise ValueError("formal class attack execution differs from the preregistered matrix")
    if formal and (
        any(sample.correctness != _CORRECTNESS_RECEIPT for sample in dataset.samples)
        or any(
            not _performance_is_complete(_performance_sample(sample)) for sample in dataset.samples
        )
    ):
        raise ValueError(
            "formal class attack execution requires complete correctness/performance evidence"
        )
    return attack_order


def _classifier_provenance(
    attacks: Sequence[str],
    formal: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "classifier_input_fields": list(CLASSIFIER_INPUT_FIELDS),
        "forbidden_classifier_fields": list(FORBIDDEN_CLASSIFIER_FIELDS),
    }
    if "panchenko" in attacks:
        result["panchenko"] = {
            "backend": "clean-room-libsvm-compatible-rbf",
            "reference": classifier_reference_receipt(),
        }
    if "vngpp" in attacks:
        result["vngpp"] = vngpp_backend_receipt(formal=formal)
    if "dlsvm" in attacks:
        result["dlsvm"] = dlsvm_backend_receipt(formal=formal)
    _validate_classifier_provenance(result, attacks=attacks, formal=formal)
    if formal:
        _validate_formal_execution_runtime(result, attacks=attacks)
    return result


def _validate_formal_execution_runtime(
    provenance: Mapping[str, Any],
    *,
    attacks: Sequence[str],
) -> None:
    vngpp = provenance.get("vngpp")
    dlsvm = provenance.get("dlsvm")
    if "vngpp" in attacks:
        backend = _load_weka_backend()
        runtime = vngpp.get("runtime") if isinstance(vngpp, Mapping) else None
        expected_artifacts = (
            [{"path": str(path), "sha256": sha256_file(path)} for path in backend.artifacts]
            if backend is not None
            else None
        )
        if (
            backend is None
            or not isinstance(runtime, Mapping)
            or runtime.get("java_path") != str(backend.java)
            or runtime.get("java_sha256") != sha256_file(backend.java)
            or runtime.get("artifacts") != expected_artifacts
        ):
            raise ValueError("formal VNG++ execution runtime differs from its approved receipt")
    if "dlsvm" in attacks:
        loaded = _load_osad_library()
        native = dlsvm.get("native_library") if isinstance(dlsvm, Mapping) else None
        if (
            loaded is None
            or not isinstance(native, Mapping)
            or native
            != {
                "path": str(loaded[1]),
                "sha256": sha256_file(loaded[1]),
            }
        ):
            raise ValueError("formal DLSVM execution runtime differs from its approved receipt")
    if (
        "vngpp" in attacks
        and "dlsvm" in attacks
        and (vngpp.get("approved_runtime") != dlsvm.get("approved_runtime"))
    ):
        raise ValueError("formal classifiers do not share one approved runtime receipt")


def _validate_classifier_provenance(
    value: Mapping[str, Any],
    *,
    attacks: Sequence[str],
    formal: bool,
) -> None:
    expected_keys = {
        "schema_version",
        "classifier_input_fields",
        "forbidden_classifier_fields",
        *attacks,
    }
    if (
        set(value) != expected_keys
        or value.get("schema_version") != EVALUATION_SCHEMA_VERSION
        or value.get("classifier_input_fields") != list(CLASSIFIER_INPUT_FIELDS)
        or value.get("forbidden_classifier_fields") != list(FORBIDDEN_CLASSIFIER_FIELDS)
    ):
        raise ValueError("class evaluation classifier provenance is invalid")
    panchenko = value.get("panchenko")
    if "panchenko" in attacks and (
        not isinstance(panchenko, Mapping)
        or panchenko.get("backend") != "clean-room-libsvm-compatible-rbf"
        or not isinstance(panchenko.get("reference"), Mapping)
    ):
        raise ValueError("class evaluation Panchenko provenance is invalid")
    vngpp = value.get("vngpp")
    if "vngpp" in attacks and (
        not isinstance(vngpp, Mapping)
        or vngpp.get("backend") not in {"pinned-weka-3.7.5", "unavailable"}
    ):
        raise ValueError("class evaluation VNG++ provenance is invalid")
    dlsvm = value.get("dlsvm")
    if "dlsvm" in attacks and (
        not isinstance(dlsvm, Mapping)
        or dlsvm.get("engine") not in {"clean-room-native-c", "clean-room-python"}
    ):
        raise ValueError("class evaluation DLSVM provenance is invalid")
    if formal and "vngpp" in attacks and vngpp.get("backend") != "pinned-weka-3.7.5":
        raise ValueError("formal class evaluation requires the pinned Weka VNG++ backend")
    if formal and "dlsvm" in attacks and dlsvm.get("engine") != "clean-room-native-c":
        raise ValueError("formal class evaluation requires the native clean-room DLSVM backend")
    if (
        formal
        and "vngpp" in attacks
        and not _approved_runtime_binding_valid(vngpp.get("approved_runtime"))
    ):
        raise ValueError("formal class evaluation has no approved Java runtime receipt")
    if (
        formal
        and "dlsvm" in attacks
        and not _approved_runtime_binding_valid(dlsvm.get("approved_runtime"))
    ):
        raise ValueError("formal class evaluation has no approved OSAD runtime receipt")


def _approved_runtime_binding_valid(value: Any) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == {"path", "sha256", "payload_sha256", "artifact_type"}
        and value.get("artifact_type") == "qcsd-classifier-runtime-build"
        and isinstance(value.get("path"), str)
        and _is_digest(value.get("sha256"))
        and _is_digest(value.get("payload_sha256"))
    )


def _expected_backend(
    attack: str,
    provenance: Mapping[str, Any],
) -> str:
    if attack == "panchenko":
        return "clean-room-libsvm-compatible-rbf"
    if attack == "vngpp":
        value = provenance["vngpp"]
        return (
            "pinned-author-weka-3.7.5-kernel-naive-bayes"
            if value["backend"] == "pinned-weka-3.7.5"
            else "clean-room-gaussian-nb-contextual-nonformal-only"
        )
    if attack == "dlsvm":
        value = provenance["dlsvm"]
        return (
            "clean-room-ccs12-restricted-osa-svm-native"
            if value["engine"] == "clean-room-native-c"
            else "clean-room-ccs12-restricted-osa-svm-python"
        )
    raise ValueError(f"unsupported class attack: {attack}")


def _validate_attack_run(
    run: ClassAttackRun,
    *,
    dataset: ClassStudyDataset,
    formal: bool,
) -> None:
    attack_order = _validate_attack_configuration(
        dataset,
        attacks=run.attacks,
        include_secondary=run.include_secondary,
        formal=formal,
    )
    _validate_classifier_provenance(
        run.classifier_provenance,
        attacks=attack_order,
        formal=formal,
    )
    specs = _attack_specs(
        dataset,
        attacks=attack_order,
        include_secondary=run.include_secondary,
    )
    if len(run.results) != len(specs):
        raise ValueError("class attack result count differs from the protocol matrix")
    labels = tuple(sorted(dataset.classes))
    by_id = {sample.sample_id: sample for sample in dataset.samples}
    for result, spec in zip(run.results, specs, strict=True):
        expected_testing = (
            tuple(sample for fold in spec.folds for sample in fold.test)
            if spec.folds is not None
            else spec.testing
        )
        expected_details = (
            _secondary_protocol_details(spec.folds)
            if spec.folds is not None
            else _simple_protocol_details(spec.training, spec.testing)
        )
        if (
            result.attack != spec.attack
            or result.backend != _expected_backend(spec.attack, run.classifier_provenance)
            or result.training_defense != spec.training_mode
            or result.testing_defense != spec.testing_mode
            or result.protocol != spec.protocol
            or result.train_samples != _spec_train_sample_count(spec)
            or result.test_samples != len(expected_testing)
            or result.labels != labels
            or result.protocol_details != expected_details
            or [prediction.sample_id for prediction in result.predictions]
            != [sample.sample_id for sample in expected_testing]
        ):
            raise ValueError("class attack result identity or protocol membership is invalid")
        for prediction in result.predictions:
            sample = by_id.get(prediction.sample_id)
            if (
                sample is None
                or prediction.acquisition_block_index != sample.acquisition_block
                or prediction.workload_id != sample.workload_id
                or prediction.expected != sample.class_label
                or prediction.predicted not in labels
            ):
                raise ValueError("class attack prediction is not bound to its shape sample")
        metrics = classification_metrics(
            [prediction.expected for prediction in result.predictions],
            [prediction.predicted for prediction in result.predictions],
            labels,
        )
        if (
            result.accuracy != metrics.accuracy
            or result.balanced_accuracy != metrics.balanced_accuracy
            or result.confusion_matrix != metrics.confusion_matrix
            or result.per_class_recall != metrics.per_class_recall
        ):
            raise ValueError("class attack metrics differ from their predictions")
    if "dlsvm" in attack_order:
        if formal and run.dlsvm_cache is None:
            raise ValueError("formal class evaluation has no persistent DLSVM cache")
        if run.dlsvm_cache is not None:
            _validate_dlsvm_cache_binding(
                run.dlsvm_cache,
                dataset=dataset,
                recompute_values=False,
            )
    elif run.dlsvm_cache is not None:
        raise ValueError("class evaluation has an unexpected DLSVM cache")


def _correctness_evidence(
    dataset: ClassStudyDataset,
    *,
    formal: bool,
) -> dict[str, Any]:
    passed = sum(sample.correctness == _CORRECTNESS_RECEIPT for sample in dataset.samples)
    complete = passed == len(dataset.samples)
    if formal and not complete:
        raise ValueError("formal class evaluation correctness evidence is incomplete")
    return {
        "schema_version": 1,
        "passed": complete,
        "sample_count": len(dataset.samples),
        "passed_samples": passed,
        "coverage": {
            "class_count": len(dataset.classes),
            "classes_sha256": _compact_json_sha256(list(dataset.classes)),
            "modes": list(dataset.modes),
            "acquisition_blocks": sorted({sample.acquisition_block for sample in dataset.samples}),
            "visits_per_class_mode_block": (
                len(dataset.samples)
                // (
                    len(dataset.classes)
                    * len(dataset.modes)
                    * len({sample.acquisition_block for sample in dataset.samples})
                )
            ),
        },
        "checks": {
            "prepared_response_identity": "exact",
            "defense_fidelity": "independently-recomputed-eligible",
            "exact_receipt_match": True,
        },
    }


def _performance_evidence(
    dataset: ClassStudyDataset,
    *,
    formal: bool,
) -> dict[str, Any]:
    samples = tuple(_performance_sample(sample) for sample in dataset.samples)
    complete_count = sum(_performance_is_complete(sample) for sample in samples)
    complete = complete_count == len(samples)
    if not complete:
        if formal:
            raise ValueError("formal class evaluation performance evidence is incomplete")
        return {
            "schema_version": 1,
            "passed": False,
            "sample_count": len(samples),
            "complete_samples": complete_count,
            "reason": "handoff performance evidence is incomplete",
        }

    pairs = paired_overheads(samples)
    paired_visit_count = len({sample.paired_visit_id for sample in samples})
    expected_pairs = paired_visit_count * (len(dataset.modes) - 1)
    if len(pairs) != expected_pairs:
        raise ValueError("class evaluation defended/baseline pairing is incomplete")
    usage = [sample.performance["client_resource_usage"] for sample in samples]
    rapl_available = sum(value["rapl_energy_joules"] is not None for value in usage)
    return {
        "schema_version": 1,
        "passed": True,
        "sample_count": len(samples),
        "complete_samples": complete_count,
        "coverage": {
            "class_count": len(dataset.classes),
            "modes": list(dataset.modes),
            "acquisition_blocks": sorted({sample.acquisition_block for sample in dataset.samples}),
            "paired_visits": paired_visit_count,
            "defended_baseline_pairs": len(pairs),
        },
        "bootstrap": {
            "draws": FORMAL_BOOTSTRAP_DRAWS,
            "seed": FORMAL_BOOTSTRAP_SEED,
            "cluster": "acquisition_block+workload_id",
            "resampling": "joint-cluster-with-replacement",
        },
        "metric_inventory": [
            "ratio-of-sums wire and UDP-payload overhead",
            "packet-count overhead",
            "paired completion ratio and added seconds",
            "paired goodput",
            "client CPU, wall time, RSS, context switches, and timer wakeups",
            "transport retransmissions",
            "nullable RAPL energy",
            "direction/workload/acquisition-block breakdowns",
        ],
        "rapl": {
            "nullable": True,
            "available_samples": rapl_available,
            "unavailable_samples": len(samples) - rapl_available,
            "unavailable_reasons": sorted(
                {
                    str(value["rapl_unavailable_reason"])
                    for value in usage
                    if value["rapl_energy_joules"] is None
                }
            ),
        },
        "paired_by_mode": summarize_paired_overheads(
            pairs,
            bootstrap_draws=FORMAL_BOOTSTRAP_DRAWS,
            seed=FORMAL_BOOTSTRAP_SEED,
        ),
        "breakdowns": performance_breakdowns(
            samples,
            bootstrap_draws=FORMAL_BOOTSTRAP_DRAWS,
        ),
    }


def _build_evaluation_envelope(
    dataset: ClassStudyDataset,
    run: ClassAttackRun,
    *,
    formal: bool,
    evaluator_source: Mapping[str, Any],
) -> dict[str, Any]:
    _validate_attack_run(run, dataset=dataset, formal=formal)
    records = _result_records(run.results, dataset.classes)
    payload = {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "artifact_type": EVALUATION_ARTIFACT_TYPE,
        "study_id": dataset.study_id,
        "formal": formal,
        "sample_count": len(dataset.samples),
        "class_count": len(dataset.classes),
        "classes": list(dataset.classes),
        "modes": list(dataset.modes),
        "random_chance_accuracy": dataset.random_chance,
        "configuration": {
            "attacks": list(run.attacks),
            "include_secondary": run.include_secondary,
            "bootstrap_draws": FORMAL_BOOTSTRAP_DRAWS,
            "bootstrap_seed": FORMAL_BOOTSTRAP_SEED,
        },
        "observation": {
            "classifier_fields": list(CLASSIFIER_INPUT_FIELDS),
            "forbidden_fields": list(FORBIDDEN_CLASSIFIER_FIELDS),
            "layer": "capture-interface Ethernet observer frame",
            "raw_evidence_restricted": True,
        },
        "correctness": _correctness_evidence(dataset, formal=formal),
        "performance": _performance_evidence(dataset, formal=formal),
        "protocols": _evaluation_protocol_receipt(dataset),
        "handoff_verification": _handoff_verification_receipt(formal),
        "handoff": _handoff_binding(dataset),
        "cohort": {
            "sha256": dataset.cohort_sha256,
            "payload_sha256": dataset.cohort_payload_sha256,
            "classes_sha256": _compact_json_sha256(list(dataset.classes)),
        },
        "cohort_assembly": {
            "path": COHORT_ASSEMBLY_INPUT,
            "sha256": dataset.cohort_assembly_sha256,
            "payload_sha256": dataset.cohort_assembly_payload_sha256,
        },
        "class_study_launches": _class_study_launch_binding(dataset),
        "evaluator_source": dict(evaluator_source),
        "classifier_provenance": dict(run.classifier_provenance),
        "dlsvm_cache": dict(run.dlsvm_cache) if run.dlsvm_cache is not None else None,
        "result_count": len(records),
        "results_sha256": _compact_json_sha256(records),
        "results": records,
    }
    return bind_receipt(payload, receipt_type=EVALUATION_RECEIPT_TYPE)


def _validate_evaluation_envelope(
    value: Mapping[str, Any],
    *,
    dataset: ClassStudyDataset,
    expected_evaluator_source: Mapping[str, Any],
    expected_classifier_provenance: Mapping[str, Any],
    formal: bool,
) -> dict[str, Any]:
    payload = validate_hash_bound_receipt(value, expected_type=EVALUATION_RECEIPT_TYPE)
    expected_keys = {
        "schema_version",
        "artifact_type",
        "study_id",
        "formal",
        "sample_count",
        "class_count",
        "classes",
        "modes",
        "random_chance_accuracy",
        "configuration",
        "observation",
        "correctness",
        "performance",
        "protocols",
        "handoff_verification",
        "handoff",
        "cohort",
        "cohort_assembly",
        "class_study_launches",
        "evaluator_source",
        "classifier_provenance",
        "dlsvm_cache",
        "result_count",
        "results_sha256",
        "results",
    }
    configuration = payload.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("class evaluation receipt configuration is invalid")
    attacks = configuration.get("attacks")
    if not isinstance(attacks, list):
        raise ValueError("class evaluation receipt attack selection is invalid")
    attack_order = _validate_attack_configuration(
        dataset,
        attacks=attacks,
        include_secondary=configuration.get("include_secondary"),
        formal=formal,
    )
    if (
        set(payload) != expected_keys
        or payload.get("schema_version") != EVALUATION_SCHEMA_VERSION
        or payload.get("artifact_type") != EVALUATION_ARTIFACT_TYPE
        or payload.get("study_id") != dataset.study_id
        or payload.get("formal") is not formal
        or payload.get("sample_count") != len(dataset.samples)
        or payload.get("class_count") != len(dataset.classes)
        or payload.get("classes") != list(dataset.classes)
        or payload.get("modes") != list(dataset.modes)
        or payload.get("random_chance_accuracy") != dataset.random_chance
        or configuration
        != {
            "attacks": list(attack_order),
            "include_secondary": configuration["include_secondary"],
            "bootstrap_draws": FORMAL_BOOTSTRAP_DRAWS,
            "bootstrap_seed": FORMAL_BOOTSTRAP_SEED,
        }
        or payload.get("observation")
        != {
            "classifier_fields": list(CLASSIFIER_INPUT_FIELDS),
            "forbidden_fields": list(FORBIDDEN_CLASSIFIER_FIELDS),
            "layer": "capture-interface Ethernet observer frame",
            "raw_evidence_restricted": True,
        }
        or payload.get("correctness") != _correctness_evidence(dataset, formal=formal)
        or payload.get("performance") != _performance_evidence(dataset, formal=formal)
        or payload.get("protocols") != _evaluation_protocol_receipt(dataset)
        or payload.get("handoff_verification") != _handoff_verification_receipt(formal)
        or payload.get("handoff") != _handoff_binding(dataset)
        or payload.get("cohort")
        != {
            "sha256": dataset.cohort_sha256,
            "payload_sha256": dataset.cohort_payload_sha256,
            "classes_sha256": _compact_json_sha256(list(dataset.classes)),
        }
        or payload.get("cohort_assembly")
        != {
            "path": COHORT_ASSEMBLY_INPUT,
            "sha256": dataset.cohort_assembly_sha256,
            "payload_sha256": dataset.cohort_assembly_payload_sha256,
        }
        or payload.get("class_study_launches") != _class_study_launch_binding(dataset)
        or payload.get("evaluator_source") != dict(expected_evaluator_source)
        or payload.get("classifier_provenance") != dict(expected_classifier_provenance)
    ):
        raise ValueError("class evaluation receipt identity or lineage is invalid")
    _validate_classifier_provenance(
        expected_classifier_provenance,
        attacks=attack_order,
        formal=formal,
    )
    cache = payload.get("dlsvm_cache")
    if "dlsvm" in attack_order:
        if formal and not isinstance(cache, Mapping):
            raise ValueError("formal class evaluation receipt has no DLSVM cache")
        if cache is not None:
            _validate_dlsvm_cache_binding(
                cache,
                dataset=dataset,
                recompute_values=False,
            )
    elif cache is not None:
        raise ValueError("class evaluation receipt has an unexpected DLSVM cache")
    records = payload.get("results")
    if not isinstance(records, list):
        raise ValueError("class evaluation receipt results are invalid")
    _validate_result_records(
        records,
        dataset=dataset,
        attacks=attack_order,
        include_secondary=bool(configuration["include_secondary"]),
        classifier_provenance=expected_classifier_provenance,
    )
    if payload.get("result_count") != len(records) or payload.get(
        "results_sha256"
    ) != _compact_json_sha256(records):
        raise ValueError("class evaluation result inventory hash is invalid")
    return payload


def _result_records(
    results: Sequence[AttackResult],
    classes: Sequence[str],
) -> list[dict[str, Any]]:
    labels = tuple(sorted(classes))
    records: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        record = result.as_dict()
        predictions = tuple(
            ClassificationPrediction(
                sample_id=prediction.sample_id,
                acquisition_block=prediction.acquisition_block_index,
                workload_id=prediction.workload_id,
                expected=prediction.expected,
                predicted=prediction.predicted,
            )
            for prediction in result.predictions
        )
        record["block_workload_bootstrap_95"] = formal_block_workload_bootstrap(
            predictions,
            labels,
            seed=FORMAL_BOOTSTRAP_SEED + index,
        )
        records.append(record)
    return records


def _validate_result_records(
    records: Sequence[Mapping[str, Any]],
    *,
    dataset: ClassStudyDataset,
    attacks: Sequence[str],
    include_secondary: bool,
    classifier_provenance: Mapping[str, Any],
) -> None:
    specs = _attack_specs(
        dataset,
        attacks=attacks,
        include_secondary=include_secondary,
    )
    if len(records) != len(specs):
        raise ValueError("class evaluation receipt omits attack results")
    labels = tuple(sorted(dataset.classes))
    by_id = {sample.sample_id: sample for sample in dataset.samples}
    required = {
        "schema_version",
        "attack",
        "backend",
        "training_defense",
        "testing_defense",
        "protocol",
        "train_samples",
        "test_samples",
        "labels",
        "accuracy",
        "balanced_accuracy",
        "confusion_matrix",
        "per_class_recall",
        "predictions",
        "predictions_sha256",
        "protocol_details",
        "block_workload_bootstrap_95",
    }
    for index, (record, spec) in enumerate(zip(records, specs, strict=True)):
        if not isinstance(record, Mapping) or set(record) != required:
            raise ValueError("class evaluation attack record schema is invalid")
        expected_testing = (
            tuple(sample for fold in spec.folds for sample in fold.test)
            if spec.folds is not None
            else spec.testing
        )
        expected_details = (
            _secondary_protocol_details(spec.folds)
            if spec.folds is not None
            else _simple_protocol_details(spec.training, spec.testing)
        )
        predictions_value = record.get("predictions")
        if (
            record.get("schema_version") != 1
            or record.get("attack") != spec.attack
            or record.get("backend") != _expected_backend(spec.attack, classifier_provenance)
            or record.get("training_defense") != spec.training_mode
            or record.get("testing_defense") != spec.testing_mode
            or record.get("protocol") != spec.protocol
            or record.get("train_samples") != _spec_train_sample_count(spec)
            or record.get("test_samples") != len(expected_testing)
            or record.get("labels") != list(labels)
            or record.get("protocol_details") != expected_details
            or not isinstance(predictions_value, list)
            or record.get("predictions_sha256") != _compact_json_sha256(predictions_value)
        ):
            raise ValueError("class evaluation attack record identity is invalid")
        expected_ids = [sample.sample_id for sample in expected_testing]
        predictions: list[ClassificationPrediction] = []
        for prediction_value in predictions_value:
            if not isinstance(prediction_value, Mapping) or set(prediction_value) != {
                "sample_id",
                "acquisition_block_index",
                "workload_id",
                "expected",
                "predicted",
            }:
                raise ValueError("class evaluation prediction schema is invalid")
            sample = by_id.get(str(prediction_value.get("sample_id")))
            if (
                sample is None
                or prediction_value.get("acquisition_block_index") != sample.acquisition_block
                or prediction_value.get("workload_id") != sample.workload_id
                or prediction_value.get("expected") != sample.class_label
                or prediction_value.get("predicted") not in labels
            ):
                raise ValueError("class evaluation prediction is not bound to the handoff")
            predictions.append(
                ClassificationPrediction(
                    sample_id=sample.sample_id,
                    acquisition_block=sample.acquisition_block,
                    workload_id=sample.workload_id,
                    expected=sample.class_label,
                    predicted=str(prediction_value["predicted"]),
                )
            )
        if [prediction.sample_id for prediction in predictions] != expected_ids:
            raise ValueError("class evaluation prediction membership is invalid")
        metrics = classification_metrics(
            [prediction.expected for prediction in predictions],
            [prediction.predicted for prediction in predictions],
            labels,
        )
        if (
            record.get("accuracy") != metrics.accuracy
            or record.get("balanced_accuracy") != metrics.balanced_accuracy
            or record.get("confusion_matrix") != [list(row) for row in metrics.confusion_matrix]
            or record.get("per_class_recall") != metrics.per_class_recall
            or record.get("block_workload_bootstrap_95")
            != formal_block_workload_bootstrap(
                predictions,
                labels,
                seed=FORMAL_BOOTSTRAP_SEED + index,
            )
        ):
            raise ValueError("class evaluation metrics differ from their predictions")


def _handoff_binding(dataset: ClassStudyDataset) -> dict[str, str]:
    files = {
        "sha256sums_sha256": dataset.root / "SHA256SUMS",
        "dataset_sha256": dataset.root / "dataset.json",
        "samples_sha256": dataset.root / "samples.jsonl",
        "cohort_sha256": dataset.root / "inputs/class-study-cohort.json",
        "cohort_assembly_sha256": dataset.root / COHORT_ASSEMBLY_INPUT,
    }
    if any(path.is_symlink() or not path.is_file() for path in files.values()):
        raise ValueError("class evaluation handoff binding inventory is incomplete")
    result = {key: sha256_file(path) for key, path in files.items()}
    result["class_study_launches_sha256"] = _compact_json_sha256(
        _class_study_launch_binding(dataset)
    )
    return result


def _class_study_launch_binding(dataset: ClassStudyDataset) -> dict[str, Any]:
    blocks = [
        {
            "block": block_index,
            "path": f"{CLASS_STUDY_LAUNCHES_PATH}/block-{block_index:02d}.json",
            "sha256": digest,
        }
        for block_index, digest in enumerate(
            dataset.class_study_launch_sha256s,
            start=1,
        )
    ]
    return {
        "source_path": CLASS_STUDY_LAUNCH_INPUT,
        "blocks": blocks,
        "bindings_sha256": _compact_json_sha256(blocks),
    }


def _evaluation_protocol_receipt(dataset: ClassStudyDataset) -> dict[str, Any]:
    maximum = max(sample.acquisition_block for sample in dataset.samples)
    return {
        "primary": {
            "name": TEMPORAL_PROTOCOL,
            "train_blocks": list(range(1, maximum - 1)),
            "validation_blocks": [maximum - 1],
            "test_blocks": [maximum],
            "views": [ADAPTIVE_PROTOCOL, TRANSFER_PROTOCOL],
            "validation_use": "model-selection-only",
            "heldout_test_use": "final-report-no-tuning",
        },
        "secondary": {
            "name": STRATIFIED_PROTOCOL,
            "label": "secondary",
            "folds": 10,
            "stratification": "class_label",
            "assignment": "sha256-seeded-within-class-round-robin",
            "seed": FORMAL_BOOTSTRAP_SEED,
        },
    }


def _handoff_verification_receipt(formal: bool) -> dict[str, str]:
    return (
        {
            "pre_execution": "deep-raw-observer-rederivation",
            "post_execution": "closed-checksum-and-source-reverification",
            "classic_pcap": "regenerated-sha256-exact-from-raw-pcapng",
            "correctness": "prepared-response-and-defense-fidelity-recomputed",
            "performance": "raw-trace-and-run-metadata-recomputed",
            "classifier_execution": "fresh-full-protocol-matrix",
            "dlsvm_cache": "all-kernel-cells-deterministically-recomputed-on-reuse",
        }
        if formal
        else {
            "pre_execution": "caller-supplied-exploratory-dataset",
            "post_execution": "digest-bound-evaluation-input",
            "classic_pcap": "not-required",
            "correctness": "not-required",
            "performance": "not-required",
            "classifier_execution": "selected-exploratory-protocols",
            "dlsvm_cache": "complete-recomputation-when-present",
        }
    )


def _evaluator_source_binding(
    dataset: ClassStudyDataset,
    *,
    formal: bool,
) -> dict[str, Any]:
    module = Path(__file__).resolve()
    sources = {
        "src/qcsd_lab/class_evaluation.py": module,
        "src/qcsd_lab/class_handoff.py": module.with_name("class_handoff.py"),
        "src/qcsd_lab/buflo_evaluation.py": module.with_name("buflo_evaluation.py"),
        "tools/qcsd_osad.c": LAB_ROOT / "tools/qcsd_osad.c",
    }
    if any(path.is_symlink() or not path.is_file() for path in sources.values()):
        raise ValueError("class evaluator source inventory is incomplete")
    handoff_dataset = load_json(dataset.root / "dataset.json")
    execution = handoff_dataset.get("execution_source")
    capture_source = execution.get("value") if isinstance(execution, Mapping) else None
    exporter_source = handoff_dataset.get("exporter_source")
    current_source = source_metadata()
    if formal and not (
        isinstance(capture_source, Mapping)
        and isinstance(exporter_source, Mapping)
        and current_source == capture_source == exporter_source
    ):
        raise ValueError("formal class evaluator source differs from capture/export lineage")
    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "current_source": current_source,
        "capture_source": capture_source,
        "exporter_source": exporter_source,
        "source_files": {relative: sha256_file(path) for relative, path in sorted(sources.items())},
    }


def _validate_dlsvm_cache_binding(
    value: Mapping[str, Any],
    *,
    dataset: ClassStudyDataset,
    recompute_values: bool = True,
) -> None:
    """Bind every persisted matrix to current traces and optionally replay it.

    ``recompute_values=False`` is used only while packaging a just-computed
    in-process run.  Receipt verification either performs complete matrix
    recomputation here or reopens every matrix through ``DlsvmKernelStore``;
    there is deliberately no sampled-cell audit mode.
    """

    if type(recompute_values) is not bool:
        raise ValueError("class evaluation DLSVM replay flag must be a boolean")
    artifacts = value.get("artifacts")
    directory_value = value.get("path")
    if (
        set(value) != {"schema_version", "path", "artifacts"}
        or value.get("schema_version") != 1
        or not isinstance(directory_value, str)
        or not isinstance(artifacts, Mapping)
        or not artifacts
    ):
        raise ValueError("class evaluation DLSVM cache receipt is invalid")
    directory = Path(directory_value).resolve()
    if str(directory) != directory_value or directory.is_symlink() or not directory.is_dir():
        raise ValueError("class evaluation DLSVM cache path is invalid")
    by_id = {sample.sample_id: sample for sample in dataset.samples}
    if len(by_id) != len(dataset.samples):
        raise ValueError("class evaluation dataset has duplicate DLSVM sample IDs")
    expected_backend = dlsvm_backend_receipt()
    expected_files: set[str] = set()
    for name, binding in artifacts.items():
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name.endswith(".npy")
            or not isinstance(binding, Mapping)
            or set(binding)
            != {
                "identity",
                "identity_sha256",
                "sha256",
                "receipt",
                "receipt_sha256",
                "rows",
                "columns",
            }
        ):
            raise ValueError("class evaluation DLSVM cache artifact is invalid")
        receipt_name = binding.get("receipt")
        if not isinstance(receipt_name, str) or Path(receipt_name).name != receipt_name:
            raise ValueError("class evaluation DLSVM cache receipt path is invalid")
        matrix = directory / name
        seal = directory / receipt_name
        if (
            matrix.is_symlink()
            or not matrix.is_file()
            or seal.is_symlink()
            or not seal.is_file()
            or sha256_file(matrix) != binding.get("sha256")
            or sha256_file(seal) != binding.get("receipt_sha256")
            or binding.get("identity_sha256") != _compact_json_sha256(binding.get("identity"))
            or type(binding.get("rows")) is not int
            or type(binding.get("columns")) is not int
            or binding["rows"] <= 0
            or binding["columns"] <= 0
        ):
            raise ValueError("class evaluation DLSVM cache artifact digest is invalid")
        seal_value = load_json(seal)
        if (
            not isinstance(seal_value, Mapping)
            or set(seal_value)
            != {
                "schema_version",
                "artifact_type",
                "matrix_file",
                "matrix_sha256",
                "identity",
                "identity_sha256",
                "shape",
                "dtype",
            }
            or seal_value.get("schema_version") != 1
            or seal_value.get("artifact_type") != "qcsd-dlsvm-persisted-kernel-matrix"
            or seal_value.get("matrix_file") != name
            or seal_value.get("matrix_sha256") != binding["sha256"]
            or seal_value.get("identity") != binding["identity"]
            or seal_value.get("identity_sha256") != binding["identity_sha256"]
            or seal_value.get("shape") != [binding["rows"], binding["columns"]]
            or seal_value.get("dtype") != "float64"
        ):
            raise ValueError("class evaluation DLSVM matrix seal is invalid")
        matrix_value = np.load(matrix, allow_pickle=False, mmap_mode="r")
        if matrix_value.shape != (binding["rows"], binding["columns"]):
            raise ValueError("class evaluation DLSVM matrix shape is invalid")
        if matrix_value.dtype != np.float64:
            raise ValueError("class evaluation DLSVM matrix dtype is invalid")
        identity = binding["identity"]
        if (
            not isinstance(identity, Mapping)
            or set(identity) != {"schema_version", "kind", "rows", "columns", "backend"}
            or identity.get("schema_version") != 1
            or identity.get("kind") not in {"within", "cross"}
            or identity.get("backend") != expected_backend
            or not isinstance(identity.get("rows"), list)
            or not isinstance(identity.get("columns"), list)
            or len(identity["rows"]) != binding["rows"]
            or len(identity["columns"]) != binding["columns"]
        ):
            raise ValueError("class evaluation DLSVM matrix identity is invalid")

        def resolve_members(entries: Sequence[Any]) -> tuple[StudySample, ...]:
            members: list[StudySample] = []
            seen: set[str] = set()
            for entry in entries:
                if (
                    not isinstance(entry, Mapping)
                    or set(entry) != {"sample_id", "sequence_sha256"}
                    or not isinstance(entry.get("sample_id"), str)
                    or entry["sample_id"] in seen
                ):
                    raise ValueError("class evaluation DLSVM trace identity is invalid")
                seen.add(entry["sample_id"])
                sample = by_id.get(entry["sample_id"])
                if sample is None:
                    raise ValueError("class evaluation DLSVM sample is outside the handoff")
                sequence_sha256 = hashlib.sha256(
                    np.asarray(dlsvm_sequence(sample.trace), dtype="<i4").tobytes()
                ).hexdigest()
                if entry.get("sequence_sha256") != sequence_sha256:
                    raise ValueError(
                        "class evaluation DLSVM sequence differs from its handoff trace"
                    )
                members.append(_backend_sample(sample))
            return tuple(members)

        row_samples = resolve_members(identity["rows"])
        column_samples = resolve_members(identity["columns"])
        if identity["kind"] == "within" and identity["rows"] != identity["columns"]:
            raise ValueError("class evaluation DLSVM within-matrix axes differ")
        _validate_dlsvm_matrix_semantics(
            np.asarray(matrix_value),
            kind=str(identity["kind"]),
            row_samples=row_samples,
            column_samples=column_samples,
            identity_sha256=str(binding["identity_sha256"]),
            recompute_values=recompute_values,
        )
        expected_files.update({name, receipt_name})
    actual_files = set()
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("class evaluation DLSVM cache inventory is unsafe")
        actual_files.add(path.name)
    if actual_files != expected_files:
        raise ValueError("class evaluation DLSVM cache inventory is not closed")


def _load_class_handoff(
    root: Path,
    *,
    dimensions: _Dimensions,
    handoff_verifier: HandoffVerifier,
    cohort_loader: CohortLoader,
    assembly_validator: AssemblyValidator,
    deep_verify: bool,
) -> ClassStudyDataset:
    source = Path(root).resolve()
    if Path(root).is_symlink() or not source.is_dir():
        raise ValueError("formal class handoff root is not a regular directory")
    verified = Path(handoff_verifier(source, deep_verify)).resolve()
    if verified != source:
        raise ValueError("formal class handoff verifier returned a different root")
    dataset = _load_json_object(source / "dataset.json", "formal class dataset")
    if (
        dataset.get("schema_version") != 1
        or dataset.get("artifact_type") != HANDOFF_ARTIFACT_TYPE
        or dataset.get("study_id") != dimensions.study_id
        or dataset.get("evidence_role") != "formal"
        or dataset.get("closed_world") is not True
        or dataset.get("paper_equivalent") is not False
        or dataset.get("sample_count") != dimensions.sample_count
        or dataset.get("class_count") != dimensions.classes
        or dataset.get("modes") != list(dimensions.modes)
    ):
        raise ValueError("formal class evaluation dataset identity or dimensions are invalid")
    classes_value = dataset.get("classes")
    if not isinstance(classes_value, list):
        raise ValueError("formal class evaluation class inventory is invalid")
    classes = _validate_labels(classes_value)
    if len(classes) != dimensions.classes:
        raise ValueError("formal class evaluation class inventory has the wrong size")
    _validate_dataset_contract(dataset, dimensions=dimensions, classes=classes)

    cohort_path = source / "inputs/class-study-cohort.json"
    cohort = dataset.get("class_cohort")
    if not isinstance(cohort, Mapping):
        raise ValueError("formal class evaluation has no cohort binding")
    cohort_sha256 = sha256_file(cohort_path)
    cohort_value, selection = cohort_loader(cohort_path)
    cohort_payload_sha256 = cohort_value.get("payload_sha256")
    selected = tuple(str(candidate.candidate_id) for candidate in selection.final)
    if (
        cohort.get("path") != "inputs/class-study-cohort.json"
        or cohort.get("sha256") != cohort_sha256
        or cohort.get("payload_sha256") != cohort_payload_sha256
        or not _is_digest(cohort_sha256)
        or not _is_digest(cohort_payload_sha256)
        or selected != classes
    ):
        raise ValueError("formal class evaluation cohort binding is invalid")

    assembly_path = source / COHORT_ASSEMBLY_INPUT
    assembly = dataset.get("class_cohort_assembly")
    if not isinstance(assembly, Mapping):
        raise ValueError("formal class evaluation has no cohort-assembly binding")
    assembly_value = _load_json_object(
        assembly_path,
        "formal class cohort-assembly receipt",
    )
    assembly_sha256 = sha256_file(assembly_path)
    assembly_payload = assembly_validator(assembly_value, cohort=cohort_value)
    assembly_payload_sha256 = assembly_value.get("payload_sha256")
    if (
        not isinstance(assembly_payload, Mapping)
        or assembly
        != {
            "path": COHORT_ASSEMBLY_INPUT,
            "sha256": assembly_sha256,
            "payload_sha256": assembly_payload_sha256,
        }
        or not _is_digest(assembly_sha256)
        or not _is_digest(assembly_payload_sha256)
    ):
        raise ValueError("formal class evaluation cohort-assembly binding is invalid")

    class_study_launch_sha256s = _load_class_study_launch_bindings(
        source,
        dataset,
        dimensions=dimensions,
    )

    rows = _load_json_lines(source / "samples.jsonl")
    if len(rows) != dimensions.sample_count:
        raise ValueError("formal class evaluation sample inventory has the wrong size")
    samples = tuple(
        _load_sample(source, row, dimensions=dimensions, classes=classes) for row in rows
    )
    _validate_sample_matrix(samples, dimensions=dimensions, classes=classes)
    result = ClassStudyDataset(
        root=source,
        study_id=dimensions.study_id,
        cohort_sha256=cohort_sha256,
        cohort_payload_sha256=str(cohort_payload_sha256),
        cohort_assembly_sha256=assembly_sha256,
        cohort_assembly_payload_sha256=str(assembly_payload_sha256),
        class_study_launch_sha256s=class_study_launch_sha256s,
        classes=classes,
        modes=dimensions.modes,
        samples=samples,
    )
    if _is_formal_dimensions(dimensions) and (
        result.random_chance != CLOSED_WORLD_RANDOM_CHANCE
    ):
        raise ValueError("formal class random-chance baseline is not one percent")
    return result


def _load_class_study_launch_bindings(
    root: Path,
    dataset: Mapping[str, Any],
    *,
    dimensions: _Dimensions,
) -> tuple[str, ...]:
    value = dataset.get("class_study_launches")
    source_blocks = dataset.get("blocks")
    if (
        not isinstance(value, Mapping)
        or set(value) != {"source_path", "blocks"}
        or value.get("source_path") != CLASS_STUDY_LAUNCH_INPUT
        or not isinstance(value.get("blocks"), list)
        or len(value["blocks"]) != dimensions.blocks
        or not isinstance(source_blocks, list)
        or len(source_blocks) != dimensions.blocks
    ):
        raise ValueError("formal class evaluation has no complete first-launch binding")
    digests: list[str] = []
    for block_index, (binding, source_block) in enumerate(
        zip(value["blocks"], source_blocks, strict=True),
        start=1,
    ):
        expected_path = f"{CLASS_STUDY_LAUNCHES_PATH}/block-{block_index:02d}.json"
        if (
            not isinstance(binding, Mapping)
            or set(binding) != {"block", "path", "sha256"}
            or binding.get("block") != block_index
            or binding.get("path") != expected_path
            or not _is_digest(binding.get("sha256"))
            or not isinstance(source_block, Mapping)
            or source_block.get("block") != block_index
            or source_block.get("class_study_launch_sha256") != binding.get("sha256")
        ):
            raise ValueError("formal class evaluation first-launch binding is invalid")
        path = _safe_file(root, expected_path)
        if sha256_file(path) != binding["sha256"]:
            raise ValueError("formal class evaluation first-launch digest does not verify")
        digests.append(str(binding["sha256"]))
    if len(set(digests)) != dimensions.blocks:
        raise ValueError("formal class evaluation first-launch receipts are not unique")
    return tuple(digests)


def _verify_handoff(path: Path, deep: bool) -> Path:
    return verify_class_handoff(path, deep=deep)


def _validate_dataset_contract(
    dataset: Mapping[str, Any],
    *,
    dimensions: _Dimensions,
    classes: tuple[str, ...],
) -> None:
    per_mode = dimensions.classes * dimensions.blocks * dimensions.visits_per_block
    per_block = dimensions.classes * len(dimensions.modes) * dimensions.visits_per_block
    if dataset.get("counts_by_mode") != {mode: per_mode for mode in dimensions.modes}:
        raise ValueError("formal class evaluation mode counts are invalid")
    if dataset.get("counts_by_split") != {
        "train": (dimensions.blocks - 2) * per_block,
        "validation": per_block,
        "test": per_block,
    }:
        raise ValueError("formal class evaluation split counts are invalid")
    if dataset.get("temporal_protocol") != {
        "train_blocks": list(dimensions.train_blocks),
        "validation_blocks": list(dimensions.validation_blocks),
        "test_blocks": list(dimensions.test_blocks),
        "visits_per_class_mode": {
            "train": len(dimensions.train_blocks) * dimensions.visits_per_block,
            "validation": dimensions.visits_per_block,
            "test": dimensions.visits_per_block,
            "total": dimensions.blocks * dimensions.visits_per_block,
        },
    }:
        raise ValueError("formal class evaluation temporal protocol is invalid")
    observation = dataset.get("observation")
    if (
        not isinstance(observation, Mapping)
        or observation.get("classifier_fields") != list(CLASSIFIER_INPUT_FIELDS)
        or observation.get("forbidden_fields") != list(FORBIDDEN_CLASSIFIER_FIELDS)
        or observation.get("raw_evidence_restricted") is not True
    ):
        raise ValueError("formal class evaluation observer feature contract is invalid")
    role_exclusion = dataset.get("role_exclusion")
    if (
        not isinstance(role_exclusion, Mapping)
        or role_exclusion.get("included_evidence_roles") != ["formal"]
        or role_exclusion.get("excluded_modes") != ["static"]
    ):
        raise ValueError("formal class evaluation evidence-role exclusion is invalid")
    if tuple(dataset.get("classes", ())) != classes:
        raise ValueError("formal class evaluation class order changed")


def _load_sample(
    root: Path,
    row: Mapping[str, Any],
    *,
    dimensions: _Dimensions,
    classes: tuple[str, ...],
) -> ClassStudySample:
    sample_id = row.get("sample_id")
    class_label = row.get("class_label")
    workload_id = row.get("workload_id")
    mode = row.get("mode")
    block = row.get("acquisition_block")
    visit = row.get("visit")
    split = row.get("split")
    pair = row.get("paired_class_visit_id")
    expected_split = _split_for_block(block, dimensions) if type(block) is int else None
    if (
        not isinstance(sample_id, str)
        or not sample_id
        or class_label not in classes
        or workload_id != class_label
        or mode not in dimensions.modes
        or type(block) is not int
        or expected_split != split
        or type(visit) is not int
        or not 0 <= visit < dimensions.visits_per_block
        or pair != f"block-{block:02d}/{workload_id}/visit-{visit:02d}"
        or row.get("evidence_role") != "formal"
        or type(row.get("attempts")) is not int
        or not 1 <= row["attempts"] <= 3
        or row.get("baseline") is not (mode == "undefended")
        or row.get("classifier_feature_fields") != list(CLASSIFIER_INPUT_FIELDS)
    ):
        raise ValueError("formal class evaluation sample identity or protocol is invalid")
    products = row.get("products")
    trace_binding = products.get("trace_csv") if isinstance(products, Mapping) else None
    if not isinstance(trace_binding, Mapping) or set(trace_binding) != {"path", "sha256"}:
        raise ValueError("formal class evaluation trace binding is invalid")
    relative = trace_binding.get("path")
    digest = trace_binding.get("sha256")
    trace_path = _safe_file(root, relative)
    if not _is_digest(digest) or sha256_file(trace_path) != digest:
        raise ValueError("formal class evaluation trace digest does not verify")
    trace = _read_trace(trace_path)
    correctness_value = row.get("correctness")
    performance_value = row.get("performance")
    formal_sample = _is_formal_dimensions(dimensions)
    if correctness_value is None and not formal_sample:
        correctness = None
    elif correctness_value != _CORRECTNESS_RECEIPT:
        raise ValueError("formal class evaluation correctness receipt is invalid")
    else:
        correctness = dict(_CORRECTNESS_RECEIPT)
    performance = _load_performance(performance_value, trace)
    result = ClassStudySample(
        sample_id=sample_id,
        class_label=class_label,
        workload_id=workload_id,
        mode=mode,
        acquisition_block=block,
        split=split,
        visit=visit,
        paired_class_visit_id=pair,
        trace=trace,
        correctness=correctness,
        performance=performance,
    )
    if formal_sample and (
        result.correctness is None or not _performance_is_complete(_performance_sample(result))
    ):
        raise ValueError("formal class evaluation correctness/performance evidence is incomplete")
    return result


def _read_trace(path: Path) -> tuple[ShapePacket, ...]:
    packets: list[ShapePacket] = []
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        fields = reader.fieldnames
        if fields != list(CLASSIFIER_INPUT_FIELDS):
            extras = set(fields or ()) - set(CLASSIFIER_INPUT_FIELDS)
            forbidden = sorted(
                field
                for field in extras
                if any(token in field.lower().replace("_", "-") for token in _FORBIDDEN_TOKENS)
            )
            if forbidden:
                raise ValueError(
                    "formal class trace exposes forbidden classifier fields: "
                    + ", ".join(forbidden)
                )
            raise ValueError("formal class trace exposes fields outside the classifier contract")
        previous = -1
        for row in reader:
            if set(row) != set(CLASSIFIER_INPUT_FIELDS) or row["direction"] not in {
                "outgoing",
                "incoming",
            }:
                raise ValueError("formal class trace row is invalid")
            try:
                timestamp = int(row["relative_time_ns"])
                length = int(row["observer_frame_length_bytes"])
            except (TypeError, ValueError) as error:
                raise ValueError("formal class trace numeric value is invalid") from error
            if timestamp < 0 or timestamp < previous or length <= 0:
                raise ValueError("formal class trace time or length invariant failed")
            packets.append(ShapePacket(timestamp, row["direction"], length))
            previous = timestamp
    if not packets or packets[0].relative_time_ns != 0:
        raise ValueError("formal class trace must be non-empty and begin at zero")
    return tuple(packets)


def _validate_sample_matrix(
    samples: Sequence[ClassStudySample],
    *,
    dimensions: _Dimensions,
    classes: Sequence[str],
) -> None:
    if len({sample.sample_id for sample in samples}) != len(samples):
        raise ValueError("formal class evaluation sample IDs are not unique")
    expected = Counter(
        (block, class_label, visit, mode)
        for block in range(1, dimensions.blocks + 1)
        for class_label in classes
        for visit in range(dimensions.visits_per_block)
        for mode in dimensions.modes
    )
    actual = Counter(
        (sample.acquisition_block, sample.class_label, sample.visit, sample.mode)
        for sample in samples
    )
    if actual != expected:
        raise ValueError(
            "formal class evaluation matrix is not exactly block/class/visit/mode balanced"
        )


def _temporal_split(
    dataset: ClassStudyDataset,
    *,
    attack_view: str,
    training_mode: str,
    testing_mode: str,
) -> TemporalDatasetSplit:
    train_blocks = tuple(range(1, max(sample.acquisition_block for sample in dataset.samples) - 1))
    validation_block = max(train_blocks) + 1
    test_block = validation_block + 1
    train = _selected(dataset, mode=training_mode, blocks=train_blocks)
    validation = _selected(dataset, mode=testing_mode, blocks=(validation_block,))
    heldout_test = _selected(dataset, mode=testing_mode, blocks=(test_block,))
    if {sample.sample_id for sample in train} & {
        sample.sample_id for sample in (*validation, *heldout_test)
    }:
        raise ValueError("temporal evaluation partitions overlap")
    return TemporalDatasetSplit(
        protocol=TEMPORAL_PROTOCOL,
        attack_view=attack_view,
        training_mode=training_mode,
        testing_mode=testing_mode,
        train=train,
        validation=validation,
        heldout_test=heldout_test,
    )


def _selected(
    dataset: ClassStudyDataset,
    *,
    mode: str,
    blocks: Sequence[int],
) -> tuple[ClassStudySample, ...]:
    return tuple(
        sorted(
            (
                sample
                for sample in dataset.samples
                if sample.mode == mode and sample.acquisition_block in blocks
            ),
            key=_sample_key,
        )
    )


def _sample_key(sample: ClassStudySample) -> tuple[int, str, int, str]:
    return (sample.acquisition_block, sample.class_label, sample.visit, sample.sample_id)


def _validate_predictions(
    predictions: Sequence[ClassificationPrediction],
    labels: tuple[str, ...],
) -> None:
    if not predictions or len({prediction.sample_id for prediction in predictions}) != len(
        predictions
    ):
        raise ValueError("bootstrap predictions must be non-empty with unique sample IDs")
    allowed = set(labels)
    for prediction in predictions:
        if (
            not prediction.sample_id
            or type(prediction.acquisition_block) is not int
            or prediction.acquisition_block <= 0
            or not prediction.workload_id
            or prediction.expected not in allowed
            or prediction.predicted not in allowed
            or prediction.workload_id != prediction.expected
        ):
            raise ValueError("bootstrap prediction identity or label is invalid")


def _validate_labels(labels: Sequence[str]) -> tuple[str, ...]:
    result = tuple(labels)
    if (
        not result
        or len(set(result)) != len(result)
        or any(not isinstance(label, str) or not label for label in result)
    ):
        raise ValueError("classification labels must be unique non-empty strings")
    return result


def _split_for_block(block: int, dimensions: _Dimensions) -> str:
    if block in dimensions.train_blocks:
        return "train"
    if block in dimensions.validation_blocks:
        return "validation"
    if block in dimensions.test_blocks:
        return "test"
    raise ValueError("formal class acquisition block is outside the temporal protocol")


def _interval(values: np.ndarray) -> dict[str, float]:
    return {
        "low": float(np.quantile(values, 0.025)),
        "high": float(np.quantile(values, 0.975)),
    }


def _safe_file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise ValueError("formal class evaluation trace path is invalid")
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts or value.as_posix() != relative:
        raise ValueError("formal class evaluation trace path is unsafe")
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root) or candidate.is_symlink() or not candidate.is_file():
        raise ValueError("formal class evaluation trace is not a regular handoff file")
    return candidate


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_json_lines(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("formal class sample index is not a regular file")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"formal class sample row {line_number} is invalid JSON") from error
        if not isinstance(value, dict):
            raise ValueError(f"formal class sample row {line_number} is not an object")
        rows.append(value)
    return rows


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _compact_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
