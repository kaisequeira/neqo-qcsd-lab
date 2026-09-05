from __future__ import annotations

import copy
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

import qcsd_lab.buflo_evaluation as evaluation
import qcsd_lab.class_evaluation as class_evaluation
from qcsd_lab.buflo_evaluation import ShapePacket, TrustedClassifierRuntime
from qcsd_lab.class_evaluation import (
    ADAPTIVE_PROTOCOL,
    CLASSIFIER_ATTACKS,
    EVALUATION_ARTIFACT_TYPE,
    EVALUATION_RECEIPT_TYPE,
    STRATIFIED_PROTOCOL,
    TRANSFER_PROTOCOL,
    ClassStudyDataset,
    ClassStudySample,
    _backend_sample,
    _build_evaluation_envelope,
    _candidate_algorithm_evidence,
    _compact_json_sha256,
    _correctness_evidence,
    _dlsvm_preflight_binding,
    _dlsvm_preflight_samples,
    _performance_evidence,
    _validate_classifier_provenance,
    _validate_dlsvm_cache_binding,
    _validate_evaluation_envelope,
    run_class_attacks,
    write_class_evaluation_receipt,
)
from qcsd_lab.class_handoff import _CORRECTNESS_RECEIPT
from qcsd_lab.class_study import bind_receipt, write_create_only_json
from qcsd_lab.util import sha256_file, source_metadata

_CLASSES = ("class-a", "class-b")
_MODES = ("undefended", "front")


def _dataset(tmp_path: Path) -> ClassStudyDataset:
    root = tmp_path / "handoff"
    (root / "inputs").mkdir(parents=True)
    cohort = root / "inputs/class-study-cohort.json"
    cohort.write_text('{"fixture":true}\n', encoding="utf-8")
    assembly = root / "inputs/class-study-cohort-assembly.json"
    assembly.write_text('{"fixture":"assembly"}\n', encoding="utf-8")
    (root / "dataset.json").write_text('{"fixture":true}\n', encoding="utf-8")
    (root / "samples.jsonl").write_text('{"fixture":true}\n', encoding="utf-8")
    (root / "SHA256SUMS").write_text("fixture\n", encoding="utf-8")
    launch_sha256s = []
    for block in range(1, 11):
        launch = root / f"inputs/class-study-launches/block-{block:02d}.json"
        launch.parent.mkdir(parents=True, exist_ok=True)
        launch.write_text(json.dumps({"block": block}) + "\n", encoding="utf-8")
        launch_sha256s.append(sha256_file(launch))

    samples = []
    for block in range(1, 11):
        split = "train" if block <= 8 else "validation" if block == 9 else "test"
        for class_index, class_label in enumerate(_CLASSES):
            for visit in range(2):
                for mode_index, mode in enumerate(_MODES):
                    length = 100 + class_index * 500 + mode_index * 50 + visit * 5
                    sample_id = f"b{block:02d}-{class_label}-v{visit}-{mode}"
                    samples.append(
                        ClassStudySample(
                            sample_id=sample_id,
                            class_label=class_label,
                            workload_id=class_label,
                            mode=mode,
                            acquisition_block=block,
                            split=split,
                            visit=visit,
                            paired_class_visit_id=(
                                f"block-{block:02d}/{class_label}/visit-{visit:02d}"
                            ),
                            trace=(
                                ShapePacket(0, "outgoing", length),
                                ShapePacket(1_000_000, "incoming", length + 100),
                                ShapePacket(2_000_000, "incoming", length + block),
                            ),
                        )
                    )
    return ClassStudyDataset(
        root=root.resolve(),
        study_id="classifier-tiny-v1",
        cohort_sha256=sha256_file(cohort),
        cohort_payload_sha256="f" * 64,
        cohort_assembly_sha256=sha256_file(assembly),
        cohort_assembly_payload_sha256="e" * 64,
        class_study_launch_sha256s=tuple(launch_sha256s),
        classes=_CLASSES,
        modes=_MODES,
        samples=tuple(samples),
    )


def _dataset_with_performance(tmp_path: Path) -> ClassStudyDataset:
    dataset = _dataset(tmp_path)
    samples = []
    for sample in dataset.samples:
        wire = {
            direction: sum(
                packet.length_bytes for packet in sample.trace if packet.direction == direction
            )
            for direction in ("outgoing", "incoming")
        }
        packets = {
            direction: sum(packet.direction == direction for packet in sample.trace)
            for direction in ("outgoing", "incoming")
        }
        scale = 2 if sample.mode == "front" else 1
        performance = {
            "schema_version": 1,
            "application_duration_ns": scale * (1_000_000_000 + sample.acquisition_block),
            "application_response_bytes": 10_000,
            "wire_bytes": wire,
            "packet_count": packets,
            "udp_payload_bytes": {
                key: max(value - 42 * packets[key], 1) for key, value in wire.items()
            },
            "udp_payload_lengths_missing": {"outgoing": 0, "incoming": 0},
            "client_resource_usage": {
                "schema_version": 1,
                "source": "fixture",
                "user_cpu_seconds": 0.1 * scale,
                "system_cpu_seconds": 0.05 * scale,
                "wall_time_seconds": 1.0 * scale,
                "maximum_rss_bytes": 1_000_000 * scale,
                "voluntary_context_switches": 10 * scale,
                "involuntary_context_switches": scale,
                "timer_wakeups": 100 * scale,
                "timer_wakeups_unavailable_reason": None,
                "rapl_energy_joules": None,
                "rapl_unavailable_reason": "fixture platform has no RAPL",
            },
            "transport_retransmissions": 0,
        }
        samples.append(
            replace(
                sample,
                correctness=dict(_CORRECTNESS_RECEIPT),
                performance=performance,
            )
        )
    return replace(dataset, samples=tuple(samples))


def test_panchenko_executes_existing_backend_for_the_complete_protocol_matrix(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)

    run = run_class_attacks(
        dataset,
        attacks=("panchenko",),
        include_secondary=True,
        formal=False,
    )

    assert run.attacks == ("panchenko",)
    assert len(run.results) == 10
    assert all(result.backend == "clean-room-libsvm-compatible-rbf" for result in run.results)
    protocols = [result.protocol for result in run.results]
    assert protocols.count(f"temporal-validation-{ADAPTIVE_PROTOCOL}") == 2
    assert protocols.count(f"temporal-validation-{TRANSFER_PROTOCOL}") == 2
    assert protocols.count(f"temporal-heldout-test-{ADAPTIVE_PROTOCOL}") == 2
    assert protocols.count(f"temporal-heldout-test-{TRANSFER_PROTOCOL}") == 2
    assert protocols.count(STRATIFIED_PROTOCOL) == 2
    assert all(result.labels == tuple(sorted(_CLASSES)) for result in run.results)
    assert run.dlsvm_cache is None


def test_correctness_and_performance_receipts_are_complete_and_trace_separated(
    tmp_path: Path,
) -> None:
    dataset = _dataset_with_performance(tmp_path)

    correctness = _correctness_evidence(dataset, formal=True)
    performance = _performance_evidence(dataset, formal=True)

    assert correctness["passed"] is True
    assert correctness["passed_samples"] == 80
    assert correctness["checks"]["exact_receipt_match"] is True
    assert performance["passed"] is True
    assert performance["complete_samples"] == 80
    assert performance["coverage"]["paired_visits"] == 40
    assert performance["coverage"]["defended_baseline_pairs"] == 40
    assert performance["bootstrap"] == {
        "draws": 10_000,
        "seed": 20260828,
        "cluster": "acquisition_block+workload_id",
        "resampling": "joint-cluster-with-replacement",
    }
    assert performance["paired_by_mode"]["front"]["performance_evidence_available"] is True
    assert performance["breakdowns"]["directional"]
    assert performance["breakdowns"]["client"]
    assert performance["rapl"] == {
        "nullable": True,
        "available_samples": 0,
        "unavailable_samples": 80,
        "unavailable_reasons": ["fixture platform has no RAPL"],
    }
    assert _backend_sample(dataset.samples[0]).performance is None
    assert _backend_sample(dataset.samples[0]).algorithm_diagnostics is None

    missing = replace(
        dataset,
        samples=(replace(dataset.samples[0], performance=None), *dataset.samples[1:]),
    )
    with pytest.raises(ValueError, match="performance evidence is incomplete"):
        _performance_evidence(missing, formal=True)


def test_dlsvm_capacity_projection_maps_class_blocks_to_shared_protocol(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)

    projected = _dlsvm_preflight_samples(dataset)

    assert {sample.acquisition_block_index for sample in projected} == set(range(10))
    assert {sample.sample_id: sample.acquisition_block_index for sample in projected} == {
        sample.sample_id: sample.acquisition_block - 1 for sample in dataset.samples
    }
    assert all(sample.performance is None for sample in projected)
    assert all(sample.algorithm_diagnostics is None for sample in projected)


def test_candidate_algorithm_reporting_is_rederived_but_classifier_isolated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _dataset(tmp_path)
    samples = (
        replace(
            source.samples[0],
            mode="buflo",
            algorithm_diagnostics={"schema_version": 4},
        ),
        replace(
            source.samples[1],
            mode="cs-buflo",
            algorithm_diagnostics={"schema_version": 4},
        ),
    )
    dataset = replace(source, modes=("buflo", "cs-buflo"), samples=samples)
    observed: list[evaluation.StudySample] = []

    def aggregate(selected):
        observed.extend(selected)
        return {"available": True, "classifier_input": False, "schema_version": 3}

    monkeypatch.setattr(class_evaluation, "algorithm_breakdowns", aggregate)

    evidence = _candidate_algorithm_evidence(dataset, formal=False)

    assert evidence["passed"] is True
    assert evidence["coverage"]["diagnostic_schema_versions"] == [4]
    assert {sample.defense for sample in observed} == {"buflo", "cs-buflo"}
    assert all(sample.algorithm_diagnostics == {"schema_version": 4} for sample in observed)
    assert all(_backend_sample(sample).algorithm_diagnostics is None for sample in samples)


def test_dlsvm_preflight_binding_hashes_validated_capacity_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    path = tmp_path / "preflight.json"
    path.write_text('{"fixture":true}\n', encoding="utf-8")
    receipt = {
        "schema_version": 2,
        "artifact_type": "qcsd-dlsvm-native-capacity-preflight",
        "workload": {"cells": 123},
        "projection": {"projected_wall_seconds": 456.0},
        "execution_model": dict(class_evaluation.CLASS_DLSVM_EXECUTION_MODEL),
        "admission": {
            "wall_time_available": True,
            "memory_available": True,
            "cache_storage_available": True,
        },
    }
    calls = []

    def validate(source, *, samples, handoff_root, formal, expected_execution_model):
        calls.append((source, samples, handoff_root, formal, expected_execution_model))
        return receipt

    monkeypatch.setattr(class_evaluation, "validate_dlsvm_preflight", validate)

    binding = _dlsvm_preflight_binding(path, dataset=dataset, formal=True)

    assert binding["schema_version"] == 2
    assert binding["sha256"] == sha256_file(path)
    assert binding["admission"] == receipt["admission"]
    assert binding["execution_model"] == class_evaluation.CLASS_DLSVM_EXECUTION_MODEL
    assert binding["execution_model_sha256"] == class_evaluation.CLASS_DLSVM_EXECUTION_MODEL_SHA256
    assert calls[0][2:] == (
        dataset.root,
        True,
        class_evaluation.CLASS_DLSVM_EXECUTION_MODEL,
    )
    assert {sample.acquisition_block_index for sample in calls[0][1]} == set(range(10))


def test_class_dlsvm_preflight_binding_is_explicitly_formal_only(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)

    with pytest.raises(ValueError, match="formal-only"):
        _dlsvm_preflight_binding(
            tmp_path / "unused-schema-one-preflight.json",
            dataset=dataset,
            formal=False,
        )


def test_class_dlsvm_execution_model_covers_top_level_action_amplification() -> None:
    model = class_evaluation.CLASS_DLSVM_EXECUTION_MODEL
    pass_equivalents = model["total_full_matrix_passes"] * model["contingency_multiplier"]
    maximum_full_matrix_passes = {
        "evaluate": 2,
        "successor-comparison-review": 3,
        "attest": 4,
        "verify-existing-attestation": 2,
    }

    assert pass_equivalents == 4
    assert max(maximum_full_matrix_passes.values()) <= pass_equivalents


def test_formal_evaluation_requires_explicit_resumable_dlsvm_cache(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="--dlsvm-cache-directory"):
        write_class_evaluation_receipt(
            tmp_path / "evaluation.json",
            handoff_root=tmp_path / "handoff",
        )


@pytest.mark.parametrize("environment", evaluation._FORMAL_RUNTIME_OVERRIDE_ENV)
def test_formal_class_evaluation_rejects_runtime_overrides_before_any_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment: str,
) -> None:
    destination = tmp_path / "evaluation.json"
    cache = tmp_path / "dlsvm-cache"
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    monkeypatch.setenv(environment, "/tmp/qcsd-forged-runtime")

    with pytest.raises(RuntimeError, match="forbids runtime path overrides"):
        write_class_evaluation_receipt(
            destination,
            handoff_root=handoff,
            dlsvm_cache_directory=cache,
        )
    assert not destination.exists()
    assert not destination.with_name(destination.name + ".dlsvm-preflight.json").exists()
    assert not cache.exists()


def test_rejected_dlsvm_preflight_stops_before_classifier_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    classifier_started = False

    monkeypatch.setattr(
        class_evaluation,
        "_formal_classifier_runtime_receipts",
        lambda: {"fixture": True},
    )
    monkeypatch.setattr(
        class_evaluation,
        "load_class_handoff",
        lambda *_args, **_kwargs: dataset,
    )
    monkeypatch.setattr(
        class_evaluation,
        "_evaluator_source_binding",
        lambda *_args, **_kwargs: {"fixture": True},
    )

    def reject_preflight(*_args, **_kwargs):
        raise ValueError("formal DLSVM capacity preflight rejected")

    def start_classifier(*_args, **_kwargs):
        nonlocal classifier_started
        classifier_started = True
        raise AssertionError("classifier must not run after rejected preflight")

    monkeypatch.setattr(class_evaluation, "write_dlsvm_preflight", reject_preflight)
    monkeypatch.setattr(class_evaluation, "run_class_attacks", start_classifier)

    with pytest.raises(ValueError, match="capacity preflight rejected"):
        write_class_evaluation_receipt(
            tmp_path / "evaluation.json",
            handoff_root=dataset.root,
            dlsvm_cache_directory=tmp_path / "dlsvm-cache",
        )

    assert classifier_started is False
    assert not (tmp_path / "evaluation.json").exists()


def test_reused_preflight_is_currently_readmitted_before_classifier_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    destination = tmp_path / "evaluation.json"
    preflight = destination.with_name(destination.name + ".dlsvm-preflight.json")
    preflight.write_text('{"immutable":true}\n', encoding="utf-8")
    events: list[str] = []

    monkeypatch.setattr(
        class_evaluation,
        "_formal_classifier_runtime_receipts",
        lambda: {"fixture": True},
    )
    monkeypatch.setattr(
        class_evaluation,
        "load_class_handoff",
        lambda *_args, **_kwargs: dataset,
    )
    monkeypatch.setattr(
        class_evaluation,
        "_evaluator_source_binding",
        lambda *_args, **_kwargs: {"fixture": True},
    )

    def validate(*_args, **kwargs):
        events.append("validate-existing")
        assert kwargs["expected_execution_model"] == (class_evaluation.CLASS_DLSVM_EXECUTION_MODEL)
        return {"schema_version": 2}

    def bind(*_args, **_kwargs):
        events.append("bind")
        return {"schema_version": 2}

    def reject_current_capacity(*_args, **kwargs):
        events.append("readmit-current-capacity")
        assert kwargs["expected_execution_model"] == (class_evaluation.CLASS_DLSVM_EXECUTION_MODEL)
        raise ValueError("current-capacity admission failed")

    def start_classifier(*_args, **_kwargs):
        events.append("classifier")
        raise AssertionError("classifier must not run after current-capacity rejection")

    monkeypatch.setattr(class_evaluation, "validate_dlsvm_preflight", validate)
    monkeypatch.setattr(class_evaluation, "_dlsvm_preflight_binding", bind)
    monkeypatch.setattr(
        class_evaluation,
        "admit_dlsvm_preflight_capacity",
        reject_current_capacity,
    )
    monkeypatch.setattr(class_evaluation, "run_class_attacks", start_classifier)

    with pytest.raises(ValueError, match="current-capacity admission failed"):
        write_class_evaluation_receipt(
            destination,
            handoff_root=dataset.root,
            dlsvm_cache_directory=tmp_path / "dlsvm-cache",
        )

    assert events == ["validate-existing", "bind", "readmit-current-capacity"]
    assert not destination.exists()


@pytest.mark.parametrize("replay_attacks", [False, True])
def test_evaluation_replay_readmits_capacity_before_matrix_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replay_attacks: bool,
) -> None:
    dataset = _dataset(tmp_path)
    receipt = tmp_path / "evaluation.json"
    receipt_value = {"fixture": True}
    receipt.write_bytes(class_evaluation.canonical_json_bytes(receipt_value))
    preflight = tmp_path / "preflight.json"
    preflight.write_text('{"immutable":true}\n', encoding="utf-8")
    events: list[str] = []
    payload = {
        "dlsvm_capacity_preflight": {"path": str(preflight.resolve())},
        "dlsvm_cache": {"path": str((tmp_path / "cache").resolve())},
    }

    monkeypatch.setattr(
        class_evaluation,
        "_formal_classifier_runtime_receipts",
        lambda: {"fixture": True},
    )
    monkeypatch.setattr(
        class_evaluation,
        "load_class_handoff",
        lambda *_args, **_kwargs: dataset,
    )
    monkeypatch.setattr(
        class_evaluation,
        "_evaluator_source_binding",
        lambda *_args, **_kwargs: {"fixture": "source"},
    )
    monkeypatch.setattr(
        class_evaluation,
        "_classifier_provenance",
        lambda *_args, **_kwargs: {"fixture": "classifiers"},
    )
    monkeypatch.setattr(
        class_evaluation,
        "_validate_evaluation_envelope",
        lambda *_args, **_kwargs: payload,
    )

    def reject_current_capacity(*_args, **kwargs):
        events.append("readmit-current-capacity")
        assert kwargs["expected_execution_model"] == (class_evaluation.CLASS_DLSVM_EXECUTION_MODEL)
        raise ValueError("current-capacity replay admission failed")

    def matrix_work(*_args, **_kwargs):
        events.append("matrix-work")
        raise AssertionError("matrix work must follow current-capacity admission")

    monkeypatch.setattr(
        class_evaluation,
        "admit_dlsvm_preflight_capacity",
        reject_current_capacity,
    )
    monkeypatch.setattr(class_evaluation, "run_class_attacks", matrix_work)
    monkeypatch.setattr(class_evaluation, "_validate_dlsvm_cache_binding", matrix_work)

    with pytest.raises(ValueError, match="current-capacity replay admission failed"):
        class_evaluation.verify_class_evaluation_receipt(
            receipt,
            handoff_root=dataset.root,
            deep_verify_handoff=False,
            replay_attacks=replay_attacks,
        )

    assert events == ["readmit-current-capacity"]


def test_dlsvm_executes_clean_room_backend_and_seals_persistent_matrices(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)
    cache = tmp_path / "dlsvm-cache"

    run = run_class_attacks(
        dataset,
        attacks=("dlsvm",),
        include_secondary=True,
        dlsvm_cache_directory=cache,
        formal=False,
    )

    assert len(run.results) == 10
    assert all(
        result.backend
        in {
            "clean-room-ccs12-restricted-osa-svm-native",
            "clean-room-ccs12-restricted-osa-svm-python",
        }
        for result in run.results
    )
    assert run.dlsvm_cache is not None
    assert run.dlsvm_cache["path"] == str(cache.resolve())
    assert run.dlsvm_cache["artifacts"]
    _validate_dlsvm_cache_binding(run.dlsvm_cache, dataset=dataset)
    secondary = [result for result in run.results if result.protocol == STRATIFIED_PROTOCOL]
    assert secondary and all(result.train_samples == 36 for result in secondary)


def test_hash_bound_receipt_recomputes_membership_predictions_metrics_and_bootstrap(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)
    run = run_class_attacks(
        dataset,
        attacks=("panchenko",),
        include_secondary=True,
        formal=False,
    )
    evaluator_source = {"fixture": "source"}
    envelope = _build_evaluation_envelope(
        dataset,
        run,
        formal=False,
        evaluator_source=evaluator_source,
    )

    payload = _validate_evaluation_envelope(
        envelope,
        dataset=dataset,
        expected_evaluator_source=evaluator_source,
        expected_classifier_provenance=run.classifier_provenance,
        formal=False,
    )

    assert envelope["receipt_type"] == EVALUATION_RECEIPT_TYPE
    assert payload["artifact_type"] == EVALUATION_ARTIFACT_TYPE
    assert payload["cohort_assembly"] == {
        "path": "inputs/class-study-cohort-assembly.json",
        "sha256": dataset.cohort_assembly_sha256,
        "payload_sha256": dataset.cohort_assembly_payload_sha256,
    }
    assert payload["handoff"]["cohort_assembly_sha256"] == sha256_file(
        dataset.root / "inputs/class-study-cohort-assembly.json"
    )
    assert payload["class_study_launches"]["bindings_sha256"] == _compact_json_sha256(
        payload["class_study_launches"]["blocks"]
    )
    assert payload["handoff"]["class_study_launches_sha256"] == _compact_json_sha256(
        payload["class_study_launches"]
    )
    assert payload["result_count"] == 10
    assert payload["configuration"]["bootstrap_draws"] == 10_000
    assert payload["correctness"]["passed"] is False
    assert payload["performance"]["passed"] is False
    assert payload["observation"]["classifier_fields"] == [
        "relative_time_ns",
        "direction",
        "observer_frame_length_bytes",
    ]
    destination = tmp_path / "evaluation.json"
    assert write_create_only_json(destination, envelope) == destination
    with pytest.raises(FileExistsError, match="already exists"):
        write_create_only_json(destination, envelope)

    tampered_payload = copy.deepcopy(payload)
    tampered_payload["results"][0]["predictions"][0]["predicted"] = "class-b"
    tampered_payload["results"][0]["predictions_sha256"] = _compact_json_sha256(
        tampered_payload["results"][0]["predictions"]
    )
    tampered_payload["results_sha256"] = _compact_json_sha256(tampered_payload["results"])
    tampered = bind_receipt(
        tampered_payload,
        receipt_type=EVALUATION_RECEIPT_TYPE,
    )
    with pytest.raises(ValueError, match="metrics differ"):
        _validate_evaluation_envelope(
            tampered,
            dataset=dataset,
            expected_evaluator_source=evaluator_source,
            expected_classifier_provenance=run.classifier_provenance,
            formal=False,
        )

    assembly_tampered_payload = copy.deepcopy(payload)
    assembly_tampered_payload["cohort_assembly"]["sha256"] = "0" * 64
    assembly_tampered = bind_receipt(
        assembly_tampered_payload,
        receipt_type=EVALUATION_RECEIPT_TYPE,
    )
    with pytest.raises(ValueError, match="identity or lineage"):
        _validate_evaluation_envelope(
            assembly_tampered,
            dataset=dataset,
            expected_evaluator_source=evaluator_source,
            expected_classifier_provenance=run.classifier_provenance,
            formal=False,
        )

    launch_tampered_payload = copy.deepcopy(payload)
    launch_tampered_payload["class_study_launches"]["blocks"][0]["sha256"] = "0" * 64
    launch_tampered = bind_receipt(
        launch_tampered_payload,
        receipt_type=EVALUATION_RECEIPT_TYPE,
    )
    with pytest.raises(ValueError, match="identity or lineage"):
        _validate_evaluation_envelope(
            launch_tampered,
            dataset=dataset,
            expected_evaluator_source=evaluator_source,
            expected_classifier_provenance=run.classifier_provenance,
            formal=False,
        )


def test_formal_provenance_requires_pinned_weka_and_native_dlsvm() -> None:
    valid = {
        "schema_version": class_evaluation.EVALUATION_SCHEMA_VERSION,
        "classifier_input_fields": [
            "relative_time_ns",
            "direction",
            "observer_frame_length_bytes",
        ],
        "forbidden_classifier_fields": [
            "address",
            "connection_id",
            "hostname",
            "metadata",
            "payload",
            "port",
            "quic_header",
            "tls",
        ],
        "panchenko": {
            "backend": "clean-room-libsvm-compatible-rbf",
            "reference": {"fixture": True},
        },
        "vngpp": {
            "backend": "pinned-weka-3.7.5",
            "approved_runtime": {
                "path": "/usr/share/qcsd-lab/classifier-runtime-build.json",
                "sha256": "a" * 64,
                "payload_sha256": "b" * 64,
                "artifact_type": "qcsd-classifier-runtime-build",
            },
        },
        "dlsvm": {
            "engine": "clean-room-native-c",
            "approved_runtime": {
                "path": "/usr/share/qcsd-lab/classifier-runtime-build.json",
                "sha256": "a" * 64,
                "payload_sha256": "b" * 64,
                "artifact_type": "qcsd-classifier-runtime-build",
            },
        },
    }

    _validate_classifier_provenance(valid, attacks=CLASSIFIER_ATTACKS, formal=True)

    missing_weka = copy.deepcopy(valid)
    missing_weka["vngpp"]["backend"] = "unavailable"
    with pytest.raises(ValueError, match="pinned Weka"):
        _validate_classifier_provenance(
            missing_weka,
            attacks=CLASSIFIER_ATTACKS,
            formal=True,
        )
    missing_native = copy.deepcopy(valid)
    missing_native["dlsvm"]["engine"] = "clean-room-python"
    with pytest.raises(ValueError, match="native clean-room DLSVM"):
        _validate_classifier_provenance(
            missing_native,
            attacks=CLASSIFIER_ATTACKS,
            formal=True,
        )


def test_formal_execution_uses_the_same_approved_java_and_osad_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    java = tmp_path / "java"
    java.write_bytes(b"approved java")
    artifacts = tuple(tmp_path / name for name in ("a.jar", "b.jar", "c.jar"))
    for index, artifact in enumerate(artifacts):
        artifact.write_bytes(f"artifact-{index}".encode())
    library = tmp_path / "libqcsd_osad.so"
    library.write_bytes(b"approved osad")
    backend = evaluation.WekaBackend(java=java, artifacts=artifacts)
    monkeypatch.setattr(class_evaluation, "_load_weka_backend", lambda: backend)
    monkeypatch.setattr(
        class_evaluation,
        "_load_osad_library",
        lambda: (object(), library),
    )
    approved = {
        "path": "/receipt.json",
        "sha256": "a" * 64,
        "payload_sha256": "b" * 64,
        "artifact_type": "qcsd-classifier-runtime-build",
    }
    provenance = {
        "vngpp": {
            "approved_runtime": approved,
            "runtime": {
                "java_path": str(java),
                "java_sha256": sha256_file(java),
                "artifacts": [
                    {"path": str(path), "sha256": sha256_file(path)} for path in artifacts
                ],
            },
        },
        "dlsvm": {
            "approved_runtime": approved,
            "native_library": {
                "path": str(library),
                "sha256": sha256_file(library),
            },
        },
    }

    class_evaluation._validate_formal_execution_runtime(
        provenance,
        attacks=("vngpp", "dlsvm"),
    )
    substituted = copy.deepcopy(provenance)
    substituted["vngpp"]["runtime"]["java_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="VNG.*execution runtime"):
        class_evaluation._validate_formal_execution_runtime(
            substituted,
            attacks=("vngpp", "dlsvm"),
        )


@pytest.mark.parametrize(
    ("backend", "environment"),
    [
        (evaluation.dlsvm_backend_receipt, "QCSD_OSAD_LIBRARY"),
        (evaluation.vngpp_backend_receipt, "QCSD_JAVA"),
        (evaluation.vngpp_backend_receipt, "QCSD_WEKA_DIRECTORY"),
    ],
)
def test_formal_classifier_backends_reject_all_runtime_path_overrides(
    monkeypatch: pytest.MonkeyPatch,
    backend,
    environment: str,
) -> None:
    monkeypatch.setenv(environment, "/tmp/qcsd-forged-runtime")

    with pytest.raises(RuntimeError, match="forbids runtime path overrides"):
        backend(formal=True)


def test_typed_trusted_runtime_fixture_binds_java_osad_and_weka_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiler = shutil.which("cc")
    java = shutil.which("java")
    if compiler is None or java is None or shutil.which("dpkg-query") is None:
        pytest.skip("trusted runtime fixture requires cc, Java, and dpkg-query")
    for name in evaluation._FORMAL_RUNTIME_OVERRIDE_ENV:
        monkeypatch.delenv(name, raising=False)

    source = Path(__file__).resolve().parents[1] / "tools/qcsd_osad.c"
    library = tmp_path / "libqcsd_osad.so"
    subprocess.run(
        [
            compiler,
            "-O3",
            "-std=c11",
            "-fPIC",
            "-shared",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(library),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    weka = tmp_path / "weka"
    weka.mkdir()
    artifact_hashes = {}
    for name in evaluation._WEKA_ARTIFACTS:
        path = weka / name
        path.write_bytes(f"fixture:{name}\n".encode())
        artifact_hashes[name] = sha256_file(path)
    java_declared = Path(java)
    java_resolved = java_declared.resolve()
    java_owner = evaluation._owning_debian_package(java_resolved)
    java_packages = evaluation._package_versions(
        tuple(sorted({"default-jre-headless", java_owner}))
    )
    compiler_packages = evaluation._package_versions(("gcc", "libc6-dev"))
    runtime = TrustedClassifierRuntime(
        receipt=tmp_path / "classifier-runtime-build.json",
        osad_library=library,
        java_executable=java_declared,
        weka_directory=weka,
        weka_artifacts=artifact_hashes,
    )
    receipt = {
        "schema_version": 1,
        "artifact_type": "qcsd-classifier-runtime-build",
        "domain": evaluation._CLASSIFIER_RUNTIME_DOMAIN,
        "source": source_metadata(),
        "build_inputs": {
            "schema_version": 1,
            "artifact_type": "qcsd-study-build-inputs",
            "cargo_lock_sha256": "a" * 64,
            "debian_base_image": evaluation._DEBIAN_BASE_IMAGE,
            "rust_base_image": "docker.invalid/rust@sha256:" + "b" * 64,
            "uv_lock_sha256": "c" * 64,
        },
        "osad": {
            "source": {
                "path": "tools/qcsd_osad.c",
                "sha256": evaluation._OSAD_SOURCE_SHA256,
            },
            "compiler": {
                "path": str(Path(compiler).resolve()),
                "sha256": sha256_file(Path(compiler).resolve()),
                "version": subprocess.run(
                    [compiler, "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.splitlines()[0],
                "packages": compiler_packages,
            },
            "build_command": list(evaluation._OSAD_BUILD_COMMAND),
            "library": {"path": str(library.resolve()), "sha256": sha256_file(library)},
        },
        "java": {
            "declared_path": str(java_declared),
            "resolved_path": str(java_resolved),
            "sha256": sha256_file(java_resolved),
            "version": evaluation._java_version(java_resolved),
            "packages": java_packages,
        },
        "weka": {
            "directory": str(weka.resolve()),
            "artifacts": {
                name: {
                    "path": str(weka.resolve() / name),
                    "sha256": digest,
                }
                for name, digest in sorted(artifact_hashes.items())
            },
        },
    }
    receipt["payload_sha256"] = evaluation._classifier_runtime_payload_sha256(receipt)
    runtime.receipt.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    dlsvm = evaluation.dlsvm_backend_receipt(
        formal=True,
        trusted_runtime=runtime,
    )
    vngpp = evaluation.vngpp_backend_receipt(
        formal=True,
        trusted_runtime=runtime,
    )

    assert dlsvm["approved_runtime"]["sha256"] == sha256_file(runtime.receipt)
    assert dlsvm["native_library"]["sha256"] == sha256_file(library)
    assert vngpp["approved_runtime"] == dlsvm["approved_runtime"]
    assert vngpp["runtime"]["java_sha256"] == sha256_file(java_resolved)

    # The original inode is still mapped by ctypes.  Replace the pathname
    # atomically so this substitution test does not truncate a live shared
    # object and SIGBUS the interpreter during teardown.
    replacement = tmp_path / "libqcsd_osad-substitution.so"
    replacement.write_bytes(b"runtime substitution")
    replacement.replace(library)
    with pytest.raises(RuntimeError, match="approved OSAD"):
        evaluation.dlsvm_backend_receipt(formal=True, trusted_runtime=runtime)


def test_dlsvm_cache_binding_is_closed_hash_bound_and_shape_checked(tmp_path: Path) -> None:
    dataset = _dataset(tmp_path)
    cache = tmp_path / "cache"
    run = run_class_attacks(
        dataset,
        attacks=("dlsvm",),
        include_secondary=False,
        dlsvm_cache_directory=cache,
        formal=False,
    )
    assert run.dlsvm_cache is not None
    binding = run.dlsvm_cache
    matrix = cache / next(iter(binding["artifacts"]))

    _validate_dlsvm_cache_binding(binding, dataset=dataset)

    with matrix.open("ab") as output:
        output.write(b"tamper")
    with pytest.raises(ValueError, match="artifact digest"):
        _validate_dlsvm_cache_binding(binding, dataset=dataset)


def test_attack_spec_failure_occurs_before_dlsvm_cache_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = _dataset(tmp_path)
    cache = tmp_path / "cache"

    def fail_specs(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("invalid attack specification")

    monkeypatch.setattr(class_evaluation, "_attack_specs", fail_specs)
    with pytest.raises(RuntimeError, match="invalid attack specification"):
        run_class_attacks(
            dataset,
            attacks=("dlsvm",),
            include_secondary=False,
            dlsvm_cache_directory=cache,
            formal=False,
        )

    second = evaluation.DlsvmKernelStore((), cache_directory=cache)
    second.close()


def test_dlsvm_cache_rejects_coherent_matrix_and_seal_substitution(
    tmp_path: Path,
) -> None:
    dataset = _dataset(tmp_path)
    cache = tmp_path / "cache"
    first = run_class_attacks(
        dataset,
        attacks=("dlsvm",),
        include_secondary=False,
        dlsvm_cache_directory=cache,
        formal=False,
    )
    assert first.dlsvm_cache is not None
    name = next(name for name in first.dlsvm_cache["artifacts"] if name.startswith("cross-"))
    binding = first.dlsvm_cache["artifacts"][name]
    matrix_path = cache / name
    matrix = np.load(matrix_path, allow_pickle=False)
    matrix[0, 0] = 0.0 if matrix[0, 0] != 0.0 else 0.5
    with matrix_path.open("wb") as output:
        np.save(output, matrix, allow_pickle=False)
    seal_path = cache / binding["receipt"]
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["matrix_sha256"] = sha256_file(matrix_path)
    seal_path.write_text(
        json.dumps(seal, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="complete deterministic recomputation"):
        run_class_attacks(
            dataset,
            attacks=("dlsvm",),
            include_secondary=False,
            dlsvm_cache_directory=cache,
            formal=False,
        )
