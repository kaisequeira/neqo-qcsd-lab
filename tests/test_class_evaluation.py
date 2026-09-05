from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.buflo_handoff as buflo_handoff
from qcsd_lab.class_evaluation import (
    ADAPTIVE_PROTOCOL,
    CLASSIFIER_INPUT_FIELDS,
    CLOSED_WORLD_RANDOM_CHANCE,
    FORMAL_BOOTSTRAP_DRAWS,
    FORMAL_SAMPLE_COUNT,
    STRATIFIED_PROTOCOL,
    TEMPORAL_PROTOCOL,
    TRANSFER_PROTOCOL,
    ClassificationPrediction,
    _Dimensions,
    _load_class_handoff,
    _load_sample,
    adaptive_temporal_splits,
    classification_metrics,
    classifier_feature_rows,
    formal_block_workload_bootstrap,
    stratified_ten_fold_splits,
    summarize_temporal_predictions,
    undefended_transfer_splits,
)
from qcsd_lab.class_handoff import (
    ARTIFACT_TYPE,
    CLASSIFIER_FIELDS,
    FORBIDDEN_CLASSIFIER_FIELDS,
    SCHEMA_VERSION as HANDOFF_SCHEMA_VERSION,
)
from qcsd_lab.class_study import FORMAL_MODES

_CLASSES = ("class-a", "class-b")
_MODES = ("undefended", "front")
_DIMENSIONS = _Dimensions(
    study_id="classifier-tiny-v1",
    classes=2,
    modes=_MODES,
    blocks=10,
    visits_per_block=2,
)


def test_formal_sample_accepts_preserved_retry_success(tmp_path: Path) -> None:
    root, rows, _dataset, _calls, _cohort_loader, _assembly_validator = _fixture(tmp_path)
    row = dict(rows[0])
    row["attempts"] = 2

    sample = _load_sample(root, row, dimensions=_DIMENSIONS, classes=_CLASSES)

    assert sample.sample_id == row["sample_id"]


def test_candidate_sample_rederives_algorithm_diagnostics_from_bound_raw_products(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "handoff"
    root.mkdir()
    trace = root / "trace.csv"
    trace.write_text(
        ",".join(CLASSIFIER_INPUT_FIELDS) + "\n0,outgoing,1200\n",
        encoding="utf-8",
    )
    products = {
        "trace_csv": {"path": "trace.csv", "sha256": _sha256(trace)},
    }
    for label, name, content in (
        ("run", "run.json", "{}\n"),
        ("schedule", "schedule.csv", "fixture\n"),
        ("events", "events.csv", "fixture\n"),
        ("packets", "packets.csv", "fixture\n"),
    ):
        path = root / name
        path.write_text(content, encoding="utf-8")
        products[label] = {"path": name, "sha256": _sha256(path)}
    observed = {}

    def diagnostics(run, **kwargs):
        observed.update(kwargs)
        assert run == {}
        return {"schema_version": 4}

    monkeypatch.setattr(buflo_handoff, "_algorithm_diagnostics", diagnostics)
    dimensions = _Dimensions(
        study_id="classifier-candidate-tiny-v1",
        classes=1,
        modes=("buflo",),
        blocks=10,
        visits_per_block=2,
    )
    row = {
        "sample_id": "candidate-sample",
        "class_label": "class-a",
        "workload_id": "class-a",
        "mode": "buflo",
        "runtime_kind": "buflo",
        "baseline": False,
        "visit": 0,
        "attempts": 1,
        "evidence_role": "formal",
        "acquisition_block": 1,
        "split": "train",
        "paired_class_visit_id": "block-01/class-a/visit-00",
        "products": products,
        "classifier_feature_fields": list(CLASSIFIER_INPUT_FIELDS),
        "correctness": None,
        "performance": None,
    }

    sample = _load_sample(root, row, dimensions=dimensions, classes=("class-a",))

    assert sample.algorithm_diagnostics == {"schema_version": 4}
    assert observed["require_current"] is True
    assert observed["require_latest_cs"] is True
    assert observed["schedule_path"] == root / "schedule.csv"


_PAYLOAD_SHA256 = "f" * 64
_ASSEMBLY_PAYLOAD_SHA256 = "e" * 64


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path):
    root = tmp_path / "handoff"
    (root / "inputs").mkdir(parents=True)
    cohort = root / "inputs/class-study-cohort.json"
    cohort.write_text(
        json.dumps({"payload_sha256": _PAYLOAD_SHA256}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assembly = root / "inputs/class-study-cohort-assembly.json"
    assembly.write_text(
        json.dumps(
            {"fixture": True, "payload_sha256": _ASSEMBLY_PAYLOAD_SHA256},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    launch_bindings = []
    source_blocks = []
    for block in range(1, _DIMENSIONS.blocks + 1):
        launch = root / f"inputs/class-study-launches/block-{block:02d}.json"
        launch.parent.mkdir(parents=True, exist_ok=True)
        launch.write_text(json.dumps({"block": block}) + "\n", encoding="utf-8")
        digest = _sha256(launch)
        launch_bindings.append(
            {
                "block": block,
                "path": f"inputs/class-study-launches/block-{block:02d}.json",
                "sha256": digest,
            }
        )
        source_blocks.append({"block": block, "class_study_launch_sha256": digest})
    rows = []
    for block in range(1, _DIMENSIONS.blocks + 1):
        split = "train" if block <= 8 else "validation" if block == 9 else "test"
        for class_index, class_label in enumerate(_CLASSES):
            for visit in range(_DIMENSIONS.visits_per_block):
                for mode_index, mode in enumerate(_MODES):
                    sample_id = f"b{block:02d}-{class_label}-v{visit}-{mode}"
                    trace = root / f"traces/block-{block:02d}/{sample_id}.csv"
                    trace.parent.mkdir(parents=True, exist_ok=True)
                    length = 100 + class_index * 100 + mode_index * 10 + visit
                    trace.write_text(
                        ",".join(CLASSIFIER_FIELDS)
                        + f"\n0,outgoing,{length}\n1000,incoming,{length + 50}\n",
                        encoding="utf-8",
                    )
                    rows.append(
                        {
                            "schema_version": HANDOFF_SCHEMA_VERSION,
                            "sample_id": sample_id,
                            "class_label": class_label,
                            "workload_id": class_label,
                            "mode": mode,
                            "baseline": mode == "undefended",
                            "visit": visit,
                            "attempts": 1,
                            "evidence_role": "formal",
                            "acquisition_block": block,
                            "split": split,
                            "paired_class_visit_id": (
                                f"block-{block:02d}/{class_label}/visit-{visit:02d}"
                            ),
                            "kernel_tx_evidence": None,
                            "products": {
                                "trace_csv": {
                                    "path": trace.relative_to(root).as_posix(),
                                    "sha256": _sha256(trace),
                                }
                            },
                            "classifier_feature_fields": list(CLASSIFIER_FIELDS),
                        }
                    )
    samples_path = root / "samples.jsonl"
    samples_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    per_mode = _DIMENSIONS.classes * _DIMENSIONS.blocks * _DIMENSIONS.visits_per_block
    per_block = _DIMENSIONS.classes * len(_DIMENSIONS.modes) * _DIMENSIONS.visits_per_block
    dataset = {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "study_id": _DIMENSIONS.study_id,
        "evidence_role": "formal",
        "closed_world": True,
        "paper_equivalent": False,
        "sample_count": _DIMENSIONS.sample_count,
        "class_count": _DIMENSIONS.classes,
        "classes": list(_CLASSES),
        "modes": list(_MODES),
        "counts_by_mode": {mode: per_mode for mode in _MODES},
        "counts_by_split": {
            "train": 8 * per_block,
            "validation": per_block,
            "test": per_block,
        },
        "temporal_protocol": {
            "train_blocks": list(range(1, 9)),
            "validation_blocks": [9],
            "test_blocks": [10],
            "visits_per_class_mode": {
                "train": 16,
                "validation": 2,
                "test": 2,
                "total": 20,
            },
        },
        "observation": {
            "classifier_fields": list(CLASSIFIER_FIELDS),
            "forbidden_fields": list(FORBIDDEN_CLASSIFIER_FIELDS),
            "raw_evidence_restricted": True,
        },
        "role_exclusion": {
            "included_evidence_roles": ["formal"],
            "excluded_modes": ["static"],
        },
        "class_cohort": {
            "path": "inputs/class-study-cohort.json",
            "sha256": _sha256(cohort),
            "payload_sha256": _PAYLOAD_SHA256,
        },
        "class_cohort_assembly": {
            "path": "inputs/class-study-cohort-assembly.json",
            "sha256": _sha256(assembly),
            "payload_sha256": _ASSEMBLY_PAYLOAD_SHA256,
        },
        "class_study_launches": {
            "source_path": "inputs/class-study-launch.json",
            "blocks": launch_bindings,
        },
        "blocks": source_blocks,
    }
    (root / "dataset.json").write_text(
        json.dumps(dataset, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    verifier_calls: list[tuple[Path, bool]] = []

    def verifier(path: Path, deep: bool) -> Path:
        verifier_calls.append((path, deep))
        return path

    def cohort_loader(_path: Path):
        return (
            {"payload_sha256": _PAYLOAD_SHA256},
            SimpleNamespace(final=tuple(SimpleNamespace(candidate_id=value) for value in _CLASSES)),
        )

    def assembly_validator(value, *, cohort):
        assert cohort == {"payload_sha256": _PAYLOAD_SHA256}
        return value

    loaded = _load_class_handoff(
        root,
        dimensions=_DIMENSIONS,
        handoff_verifier=verifier,
        cohort_loader=cohort_loader,
        assembly_validator=assembly_validator,
        deep_verify=True,
    )
    return root, rows, loaded, verifier_calls, cohort_loader, assembly_validator


def test_formal_contract_is_100_classes_eight_modes_and_16000_samples() -> None:
    assert len(FORMAL_MODES) == 8
    assert FORMAL_SAMPLE_COUNT == 16_000
    assert FORMAL_BOOTSTRAP_DRAWS == 10_000
    assert CLOSED_WORLD_RANDOM_CHANCE == 0.01
    assert CLASSIFIER_INPUT_FIELDS == (
        "relative_time_ns",
        "direction",
        "observer_frame_length_bytes",
    )


def test_loader_binds_handoff_cohort_matrix_and_shape_only_features(tmp_path: Path) -> None:
    root, _rows, dataset, verifier_calls, _cohort_loader, _validator = _fixture(tmp_path)

    assert verifier_calls == [(root.resolve(), True)]
    assert dataset.classes == _CLASSES
    assert dataset.modes == _MODES
    assert dataset.cohort_assembly_sha256 == _sha256(
        root / "inputs/class-study-cohort-assembly.json"
    )
    assert dataset.cohort_assembly_payload_sha256 == _ASSEMBLY_PAYLOAD_SHA256
    assert dataset.class_study_launch_sha256s == tuple(
        _sha256(root / f"inputs/class-study-launches/block-{block:02d}.json")
        for block in range(1, _DIMENSIONS.blocks + 1)
    )
    assert len(dataset.samples) == 80
    assert dataset.random_chance == 0.5
    first = dataset.samples[0]
    assert first.classifier_input == first.trace
    assert classifier_feature_rows(first) == (
        {
            "relative_time_ns": 0,
            "direction": "outgoing",
            "observer_frame_length_bytes": 100,
        },
        {
            "relative_time_ns": 1000,
            "direction": "incoming",
            "observer_frame_length_bytes": 150,
        },
    )
    assert set(classifier_feature_rows(first)[0]) == set(CLASSIFIER_FIELDS)


def test_loader_rejects_identifier_or_transport_metadata_fields(tmp_path: Path) -> None:
    root, rows, _dataset, _calls, cohort_loader, assembly_validator = _fixture(tmp_path)
    first = root / rows[0]["products"]["trace_csv"]["path"]
    first.write_text(
        "relative_time_ns,direction,observer_frame_length_bytes,port\n0,outgoing,100,443\n",
        encoding="utf-8",
    )
    rows[0]["products"]["trace_csv"]["sha256"] = _sha256(first)
    (root / "samples.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden classifier fields: port"):
        _load_class_handoff(
            root,
            dimensions=_DIMENSIONS,
            handoff_verifier=lambda path, _deep: path,
            cohort_loader=cohort_loader,
            assembly_validator=assembly_validator,
            deep_verify=False,
        )


def test_loader_rejects_a_different_cohort_order(tmp_path: Path) -> None:
    root, _rows, _dataset, _calls, _cohort_loader, assembly_validator = _fixture(tmp_path)

    def reversed_cohort(_path: Path):
        return (
            {"payload_sha256": _PAYLOAD_SHA256},
            SimpleNamespace(
                final=tuple(SimpleNamespace(candidate_id=value) for value in reversed(_CLASSES))
            ),
        )

    with pytest.raises(ValueError, match="cohort binding"):
        _load_class_handoff(
            root,
            dimensions=_DIMENSIONS,
            handoff_verifier=lambda path, _deep: path,
            cohort_loader=reversed_cohort,
            assembly_validator=assembly_validator,
            deep_verify=False,
        )


def test_loader_intrinsically_validates_the_bound_cohort_assembly(tmp_path: Path) -> None:
    root, _rows, _dataset, _calls, cohort_loader, _validator = _fixture(tmp_path)
    received = []

    def rejecting_validator(value, *, cohort):
        received.append((value, cohort))
        raise ValueError("fixture assembly rejected")

    with pytest.raises(ValueError, match="fixture assembly rejected"):
        _load_class_handoff(
            root,
            dimensions=_DIMENSIONS,
            handoff_verifier=lambda path, _deep: path,
            cohort_loader=cohort_loader,
            assembly_validator=rejecting_validator,
            deep_verify=False,
        )

    assert received == [
        (
            {"fixture": True, "payload_sha256": _ASSEMBLY_PAYLOAD_SHA256},
            {"payload_sha256": _PAYLOAD_SHA256},
        )
    ]


def test_loader_rejects_a_mismatched_cohort_assembly_binding(tmp_path: Path) -> None:
    root, _rows, _dataset, _calls, cohort_loader, assembly_validator = _fixture(tmp_path)
    dataset_path = root / "dataset.json"
    dataset_value = json.loads(dataset_path.read_text(encoding="utf-8"))
    dataset_value["class_cohort_assembly"]["sha256"] = "0" * 64
    dataset_path.write_text(
        json.dumps(dataset_value, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cohort-assembly binding"):
        _load_class_handoff(
            root,
            dimensions=_DIMENSIONS,
            handoff_verifier=lambda path, _deep: path,
            cohort_loader=cohort_loader,
            assembly_validator=assembly_validator,
            deep_verify=False,
        )


def test_loader_rejects_missing_or_mismatched_first_launch_binding(tmp_path: Path) -> None:
    root, _rows, _dataset, _calls, cohort_loader, assembly_validator = _fixture(tmp_path)
    dataset_path = root / "dataset.json"
    dataset_value = json.loads(dataset_path.read_text(encoding="utf-8"))
    dataset_value["blocks"][0]["class_study_launch_sha256"] = "0" * 64
    dataset_path.write_text(
        json.dumps(dataset_value, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="first-launch binding"):
        _load_class_handoff(
            root,
            dimensions=_DIMENSIONS,
            handoff_verifier=lambda path, _deep: path,
            cohort_loader=cohort_loader,
            assembly_validator=assembly_validator,
            deep_verify=False,
        )


def test_primary_temporal_protocol_never_leaks_blocks_9_or_10_into_training(
    tmp_path: Path,
) -> None:
    _root, _rows, dataset, _calls, _cohort_loader, _validator = _fixture(tmp_path)

    adaptive = adaptive_temporal_splits(dataset)
    assert [split.testing_mode for split in adaptive] == list(_MODES)
    assert all(split.protocol == TEMPORAL_PROTOCOL for split in adaptive)
    assert all(split.attack_view == ADAPTIVE_PROTOCOL for split in adaptive)
    assert all(len(split.train) == 32 for split in adaptive)
    assert all(len(split.validation) == 4 for split in adaptive)
    assert all(len(split.heldout_test) == 4 for split in adaptive)
    assert all(
        {sample.acquisition_block for sample in split.train} == set(range(1, 9))
        for split in adaptive
    )
    assert all(
        {sample.acquisition_block for sample in split.validation} == {9} for split in adaptive
    )
    assert all(
        {sample.acquisition_block for sample in split.heldout_test} == {10} for split in adaptive
    )

    transfer = undefended_transfer_splits(dataset)
    assert [split.testing_mode for split in transfer] == list(_MODES)
    assert all(split.attack_view == TRANSFER_PROTOCOL for split in transfer)
    assert all(split.training_mode == "undefended" for split in transfer)
    assert all({sample.mode for sample in split.train} == {"undefended"} for split in transfer)


def test_secondary_stratified_ten_fold_is_balanced_and_deterministic(tmp_path: Path) -> None:
    _root, _rows, dataset, _calls, _cohort_loader, _validator = _fixture(tmp_path)

    folds = stratified_ten_fold_splits(dataset, "front", seed=17)
    repeated = stratified_ten_fold_splits(dataset, "front", seed=17)

    assert len(folds) == 10
    assert all(fold.protocol == STRATIFIED_PROTOCOL for fold in folds)
    assert all(len(fold.train) == 36 and len(fold.test) == 4 for fold in folds)
    assert all(
        Counter(sample.class_label for sample in fold.test) == {"class-a": 2, "class-b": 2}
        for fold in folds
    )
    assert [[sample.sample_id for sample in fold.test] for fold in folds] == [
        [sample.sample_id for sample in fold.test] for fold in repeated
    ]
    assert len({sample.sample_id for fold in folds for sample in fold.test}) == 40


def test_classification_metrics_use_declared_100_class_axes() -> None:
    labels = tuple(f"class-{index:03d}" for index in range(100))
    expected = list(labels)
    predicted = list(labels)
    predicted[0] = labels[1]

    metrics = classification_metrics(expected, predicted, labels)

    assert metrics.sample_count == 100
    assert metrics.accuracy == 0.99
    assert metrics.balanced_accuracy == 0.99
    assert len(metrics.confusion_matrix) == 100
    assert all(len(row) == 100 for row in metrics.confusion_matrix)
    assert metrics.confusion_matrix[0][1] == 1
    assert metrics.per_class_recall[labels[0]] == 0.0


def test_formal_bootstrap_is_deterministic_and_exactly_10000_draws() -> None:
    predictions = (
        ClassificationPrediction("a-1", 10, "a", "a", "a"),
        ClassificationPrediction("a-2", 10, "a", "a", "b"),
        ClassificationPrediction("b-1", 10, "b", "b", "b"),
        ClassificationPrediction("b-2", 10, "b", "b", "b"),
    )

    first = formal_block_workload_bootstrap(predictions, ("a", "b"), seed=9)
    second = formal_block_workload_bootstrap(predictions, ("a", "b"), seed=9)

    assert first == second
    assert first["draws"] == 10_000
    assert first["cluster"] == "acquisition_block+workload_id"
    assert first["method"] == "two-way-pigeonhole-product-weight-cluster-bootstrap"
    assert first["cluster_dimensions"] == ["acquisition_block", "workload_id"]
    assert first["point"]["accuracy"] == 0.75
    assert first["point"]["balanced_accuracy"] == 0.75
    assert first["point"]["confusion_matrix"] == [[1, 1], [0, 2]]
    assert set(first["bootstrap_95"]["per_class_recall"]) == {"a", "b"}

    with pytest.raises(ValueError, match="exactly 10000"):
        formal_block_workload_bootstrap(predictions, ("a", "b"), draws=9_999)


def test_formal_bootstrap_perfect_classifier_intervals_are_exact() -> None:
    labels = tuple(f"class-{index:03d}" for index in range(100))
    predictions = tuple(
        ClassificationPrediction(
            f"block-{block:02d}-{label}",
            block,
            label,
            label,
            label,
        )
        for block in range(1, 11)
        for label in labels
    )

    result = formal_block_workload_bootstrap(predictions, labels, seed=41)

    assert result["bootstrap_95"]["accuracy"] == {"low": 1.0, "high": 1.0}
    assert result["bootstrap_95"]["balanced_accuracy"] == {
        "low": 1.0,
        "high": 1.0,
    }
    assert all(
        interval == {"low": 1.0, "high": 1.0}
        for interval in result["bootstrap_95"]["per_class_recall"].values()
    )


def test_temporal_summary_requires_exact_heldout_membership(tmp_path: Path) -> None:
    _root, _rows, dataset, _calls, _cohort_loader, _validator = _fixture(tmp_path)
    split = adaptive_temporal_splits(dataset)[0]
    predictions = tuple(
        ClassificationPrediction.from_sample(sample, sample.class_label)
        for sample in split.heldout_test
    )

    summary = summarize_temporal_predictions(
        split,
        predictions,
        dataset.classes,
        seed=4,
    )

    assert summary["phase"] == "heldout-test"
    assert summary["use"] == "final-report-no-tuning"
    assert summary["training_mode"] == summary["testing_mode"] == "undefended"
    assert summary["metrics"]["point"]["accuracy"] == 1.0

    with pytest.raises(ValueError, match="exactly cover"):
        summarize_temporal_predictions(
            split,
            predictions[:-1],
            dataset.classes,
            seed=4,
        )
