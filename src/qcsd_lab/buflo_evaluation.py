"""Versioned BuFLO/CS-BuFLO study evaluation primitives.

This module deliberately does not import or execute the historical
``classifier_handoff.py`` contract.  It consumes only the identifier-free
timestamp/direction/frame-length projections in a new study handoff.

The feature extractors are clean-room implementations from the cited attack
descriptions.  The pinned author implementations remain external reference
oracles and are never imported into the QCSD package.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import importlib.metadata
import io
import json
import math
import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from .fidelity import (
    BUFLO_SCHEDULE_STOP_POLICY,
    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
    CS_BUFLO_EARLY_TERMINATION_SEMANTICS,
    CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION,
    CS_BUFLO_INCOMING_BOUNDARY_SEPARATION,
    CS_BUFLO_INCOMING_CADENCE_BOUNDARY,
    CS_BUFLO_INCOMING_TERMINAL_BOUNDARY,
    CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS,
    CS_BUFLO_TERMINATION_STOP_PHASES,
    CS_BUFLO_TERMINATION_STOP_POLICY,
    CS_BUFLO_TERMINATION_STOP_REASONS,
    buflo_terminal_state_valid,
)
from .util import LAB_ROOT, load_json, require_disjoint_path, sha256_file, source_metadata

SCHEMA_VERSION = 1
STUDY_HANDOFF_SCHEMA_VERSIONS = frozenset({1, 2})
EVALUATION_RECEIPT_SCHEMA_VERSION = 2
FORMAL_DEFENSES = ("undefended", "buflo", "cs-buflo")
FORMAL_BLOCKS = tuple(range(10))
FORMAL_CLASS_BY_WORKLOAD = {
    "getbootstrap-home-r4": "getbootstrap.com",
    "cloudflare-quiche-r4": "cloudflare-quic.com",
    "hyper-basic-client-r3": "hyper.rs",
    "serde-home-r2": "serde.rs",
    "rfc9114-text-r2": "www.rfc-editor.org",
}
FORMAL_WORKLOADS = tuple(FORMAL_CLASS_BY_WORKLOAD)
TRAIN_BLOCKS = tuple(range(8))
VALIDATION_BLOCK = 8
TEST_BLOCK = 9
FORMAL_BOOTSTRAP_DRAWS = 10_000
_DEFAULT_OSAD_LIBRARY = Path("/usr/local/lib/qcsd/libqcsd_osad.so")
_DEFAULT_JAVA_EXECUTABLE = Path("/usr/bin/java")
_CLASSIFIER_RUNTIME_RECEIPT = Path("/usr/share/qcsd-lab/classifier-runtime-build.json")
_CLASSIFIER_RUNTIME_DOMAIN = "qcsd-classifier-runtime-build-v1"
_OSAD_SOURCE_SHA256 = "7a07903cee2a3e2c4995083dda4c16441d48b02504f1553741d659e797314dca"
_OSAD_BUILD_COMMAND = (
    "cc",
    "-O3",
    "-std=c11",
    "-fPIC",
    "-shared",
    "-Wall",
    "-Wextra",
    "-Werror",
    "qcsd_osad.c",
    "-o",
    "/out/usr/local/lib/qcsd/libqcsd_osad.so",
)
_DEBIAN_BASE_IMAGE = (
    "docker.io/library/debian:bookworm-slim@"
    "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
)
_FORMAL_RUNTIME_OVERRIDE_ENV = (
    "QCSD_JAVA",
    "QCSD_OSAD_LIBRARY",
    "QCSD_WEKA_DIRECTORY",
)
_DLSVM_REFERENCE = LAB_ROOT / "config/reference/buflo-csbuflo/dlsvm-ccs-2012-v1.json"
_DLSVM_REFERENCE_RECEIPT = _DLSVM_REFERENCE.with_suffix(".receipt.json")
_DLSVM_REFERENCE_SHA256 = "f1f51ed1228e9599cbac05dbef75300f319885d32c2e9a4c9d16c57d2e0dc4a6"
_DLSVM_REFERENCE_RECEIPT_SHA256 = "5da96469bc6f66e65d6e8e9335a9c86d89acd1d3089f490121c7daf58a6a8b78"
_DLSVM_RANDOM_STATE = 20260827
_BUFLO_REFERENCE = LAB_ROOT / "config/reference/buflo-csbuflo/buflo-ieee-sp-2012-v1.json"
_CSBUFLO_REFERENCE = LAB_ROOT / "config/reference/buflo-csbuflo/csbuflo-wpes-2014-v1.json"
_CLASSIFIER_REFERENCE = LAB_ROOT / "config/reference/buflo-csbuflo/panchenko-vngpp-sp-2012-v1.json"
_CLASSIFIER_REFERENCE_RECEIPT = _CLASSIFIER_REFERENCE.with_suffix(".receipt.json")
_CLASSIFIER_REFERENCE_SHA256 = "474823778a1002a91eb0e60348974f317723e597d0c8f31827a6448d47157998"
_CLASSIFIER_REFERENCE_RECEIPT_SHA256 = (
    "1c41803dcba9ac69bb1693cff850336bc45020cb60151983c6f8b91ee8de131e"
)
_DEFAULT_WEKA_DIRECTORY = Path("/opt/qcsd/weka")
_WEKA_ARTIFACTS = {
    "weka-dev-3.7.5.jar": "4d20516c9d32e3433b402f8898a2430cb4b519734ba4877c39726878c18ec4ad",
    "pentaho-package-manager-0.9.9.jar": (
        "a336161c0e868d8334449eb5d695bc16c961fc545a51bae60ac091af1e5722ca"
    ),
    "java-cup-0.11a.jar": "9afcfd0996dcc9a933e66749988428ad964d8c1b678107fe688a6fa55325e17e",
}
_COMPARISON_CONTEXT_FIELDS = {
    "transport",
    "endpoint_cooperation",
    "dataset_size",
    "visits",
    "observation_layer",
    "header_accounting",
    "padding_variant",
    "early_termination_semantics",
    "overhead_formula",
    "latency_definition",
    "classifier_protocol",
}
_PERFORMANCE_KEYS = {
    "schema_version",
    "application_duration_ns",
    "application_response_bytes",
    "wire_bytes",
    "packet_count",
    "udp_payload_bytes",
    "udp_payload_lengths_missing",
    "client_resource_usage",
    "transport_retransmissions",
}
_RESOURCE_USAGE_KEYS = {
    "schema_version",
    "source",
    "user_cpu_seconds",
    "system_cpu_seconds",
    "wall_time_seconds",
    "maximum_rss_bytes",
    "voluntary_context_switches",
    "involuntary_context_switches",
    "timer_wakeups",
    "timer_wakeups_unavailable_reason",
    "rapl_energy_joules",
    "rapl_unavailable_reason",
}
_EVALUATION_ARTIFACT_TYPE = "qcsd-buflo-study-evaluation"
_EVALUATION_OBSERVATION_LAYER = "identifier-free-ethernet-frame-time-direction-length"
_EVALUATION_OVERHEAD_FORMULA = "ratio-of-aggregate-sums"
_EVALUATION_RANDOM_CHANCE_ACCURACY = 0.20
_EVALUATION_LIMITATIONS = (
    "five-class QUIC results are not absolute reproductions of 120/128/200-site TCP studies",
    "DLSVM omits TCP/Tor fixed-length ACK filtering because QUIC ACK frames are encrypted",
    "VNG++ uses a training-only feature vocabulary rather than the author ARFF "
    "writer's train-plus-test union, preventing held-out dimensionality leakage",
)
_EVALUATION_COMPARISON_ACCEPTANCE_RULE = (
    "historical numeric proximity is contextual only; unexplained differences block "
    "attestation, while strict acceptance comes from oracle/artifact conformance and "
    "live client correctness"
)
_EVALUATION_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "formal",
        "sample_count",
        "bootstrap_draws",
        "handoff",
        "evaluator_source",
        "dlsvm_preflight",
        "dlsvm_persistent_cache",
        "observation_layer",
        "overhead_formula",
        "five_class_random_chance_accuracy",
        "temporal_protocol",
        "paired_metrics",
        "paired_per_visit",
        "performance_breakdowns",
        "algorithm_breakdowns",
        "classifier_provenance",
        "classifier_workload",
        "attacks",
        "original_study_comparison",
        "limitations",
    }
)


def _evaluation_temporal_protocol() -> dict[str, Any]:
    return {
        "train_blocks": list(TRAIN_BLOCKS),
        "validation_block": VALIDATION_BLOCK,
        "test_block": TEST_BLOCK,
        "validation_use": "predeclared-prediction-gate-with-pinned-parameters;never-fit",
        "heldout_use": "evaluated-after-validation;never-tuned-or-fit",
    }


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ShapePacket:
    """One identifier-free observer packet."""

    relative_time_ns: int
    direction: str
    length_bytes: int

    @property
    def signed_length_bytes(self) -> int:
        return self.length_bytes if self.direction == "outgoing" else -self.length_bytes


@dataclass(frozen=True)
class StudySample:
    """The classifier-visible fields of one sealed study sample."""

    sample_id: str
    class_label: str
    workload_id: str
    defense: str
    acquisition_block_index: int
    paired_visit_id: str
    trace: tuple[ShapePacket, ...]
    performance: Mapping[str, Any] | None = None
    algorithm_diagnostics: Mapping[str, Any] | None = None

    @property
    def wire_bytes(self) -> int:
        return sum(packet.length_bytes for packet in self.trace)

    @property
    def duration_ns(self) -> int:
        return self.trace[-1].relative_time_ns if self.trace else 0

    @property
    def application_duration_ns(self) -> int:
        if self.performance is not None:
            value = self.performance.get("application_duration_ns")
            if type(value) is int and value > 0:
                return value
        return self.duration_ns


@dataclass(frozen=True)
class WekaBackend:
    """One hash-verified Weka 3.7.5 VNG++ execution environment."""

    java: Path
    artifacts: tuple[Path, ...]

    @property
    def classpath(self) -> str:
        return os.pathsep.join(str(path) for path in self.artifacts)


@dataclass(frozen=True)
class TrustedClassifierRuntime:
    """Explicit test seam or the fixed production classifier runtime.

    Formal command paths never construct this from environment variables.  A
    synthetic test may pass an instance directly while production uses the
    fixed receipt and installed paths below.
    """

    receipt: Path
    osad_library: Path
    java_executable: Path
    weka_directory: Path
    weka_artifacts: Mapping[str, str]


_PRODUCTION_CLASSIFIER_RUNTIME = TrustedClassifierRuntime(
    receipt=_CLASSIFIER_RUNTIME_RECEIPT,
    osad_library=_DEFAULT_OSAD_LIBRARY,
    java_executable=_DEFAULT_JAVA_EXECUTABLE,
    weka_directory=_DEFAULT_WEKA_DIRECTORY,
    weka_artifacts=_WEKA_ARTIFACTS,
)


class DlsvmKernelStore:
    """Compute each required OSAD matrix cell once and slice it across protocols."""

    def __init__(
        self,
        samples: Sequence[StudySample],
        *,
        cache_directory: Path | None = None,
    ) -> None:
        self._by_defense: dict[str, tuple[StudySample, ...]] = {}
        seen: set[str] = set()
        grouped: dict[str, list[StudySample]] = defaultdict(list)
        for sample in samples:
            if sample.sample_id in seen:
                raise ValueError("DLSVM kernel store requires unique sample IDs")
            seen.add(sample.sample_id)
            grouped[sample.defense].append(sample)
        self._by_defense = {
            defense: tuple(sorted(selected, key=lambda item: item.sample_id))
            for defense, selected in grouped.items()
        }
        self._within: dict[str, tuple[dict[str, int], np.ndarray]] = {}
        self._cross: dict[tuple[tuple[str, ...], tuple[str, ...]], np.ndarray] = {}
        self._cache_directory = cache_directory.resolve() if cache_directory is not None else None
        self._cache_artifacts: dict[str, dict[str, Any]] = {}
        if self._cache_directory is not None:
            if self._cache_directory.exists():
                if self._cache_directory.is_symlink() or not self._cache_directory.is_dir():
                    raise ValueError("DLSVM cache is not a regular directory")
            else:
                self._cache_directory.mkdir(mode=0o700)

    def kernels(
        self,
        training: Sequence[StudySample],
        testing: Sequence[StudySample],
    ) -> tuple[np.ndarray, np.ndarray]:
        if not training or not testing:
            raise ValueError("DLSVM kernel store requires non-empty sample sets")
        training_defenses = {sample.defense for sample in training}
        testing_defenses = {sample.defense for sample in testing}
        if len(training_defenses) != 1 or len(testing_defenses) != 1:
            raise ValueError("DLSVM kernel sets must each contain one defense")
        training_defense = next(iter(training_defenses))
        testing_defense = next(iter(testing_defenses))
        if training_defense == testing_defense:
            indexes, matrix = self._within_matrix(training_defense)
            try:
                train_indexes = [indexes[sample.sample_id] for sample in training]
                test_indexes = [indexes[sample.sample_id] for sample in testing]
            except KeyError as error:
                raise ValueError("DLSVM sample is absent from its kernel store") from error
            return (
                matrix[np.ix_(train_indexes, train_indexes)],
                matrix[np.ix_(test_indexes, train_indexes)],
            )

        training_ids = tuple(sample.sample_id for sample in training)
        testing_ids = tuple(sample.sample_id for sample in testing)
        key = (testing_ids, training_ids)
        matrix = self._cross.get(key)
        if matrix is None:
            testing_sequences = [dlsvm_sequence(sample.trace) for sample in testing]
            training_sequences = [dlsvm_sequence(sample.trace) for sample in training]
            matrix = self._cached_matrix(
                kind="cross",
                row_samples=testing,
                column_samples=training,
                shape=(len(testing), len(training)),
                compute=lambda: _dlsvm_kernel(
                    testing_sequences,
                    training_sequences,
                    symmetric=False,
                ),
            )
            self._cross[key] = matrix
        training_indexes, training_matrix = self._within_matrix(training_defense)
        try:
            selected_indexes = [training_indexes[sample.sample_id] for sample in training]
        except KeyError as error:
            raise ValueError("DLSVM training sample is absent from its kernel store") from error
        training_kernel = training_matrix[np.ix_(selected_indexes, selected_indexes)]
        return training_kernel, matrix

    def _within_matrix(self, defense: str) -> tuple[dict[str, int], np.ndarray]:
        existing = self._within.get(defense)
        if existing is not None:
            return existing
        selected = self._by_defense.get(defense)
        if not selected:
            raise ValueError(f"DLSVM defense is absent from its kernel store: {defense}")
        indexes = {sample.sample_id: index for index, sample in enumerate(selected)}
        sequences = [dlsvm_sequence(sample.trace) for sample in selected]
        matrix = self._cached_matrix(
            kind="within",
            row_samples=selected,
            column_samples=selected,
            shape=(len(selected), len(selected)),
            compute=lambda: _dlsvm_kernel(sequences, sequences, symmetric=True),
        )
        result = (indexes, matrix)
        self._within[defense] = result
        return result

    def _cached_matrix(
        self,
        *,
        kind: str,
        row_samples: Sequence[StudySample],
        column_samples: Sequence[StudySample],
        shape: tuple[int, int],
        compute: Any,
    ) -> np.ndarray:
        if self._cache_directory is None:
            return compute()
        identity = {
            "schema_version": 1,
            "kind": kind,
            "rows": [
                {
                    "sample_id": sample.sample_id,
                    "sequence_sha256": hashlib.sha256(
                        np.asarray(dlsvm_sequence(sample.trace), dtype="<i4").tobytes()
                    ).hexdigest(),
                }
                for sample in row_samples
            ],
            "columns": [
                {
                    "sample_id": sample.sample_id,
                    "sequence_sha256": hashlib.sha256(
                        np.asarray(dlsvm_sequence(sample.trace), dtype="<i4").tobytes()
                    ).hexdigest(),
                }
                for sample in column_samples
            ],
            "backend": dlsvm_backend_receipt(),
        }
        key = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        name = f"{kind}-{key}.npy"
        path = self._cache_directory / name
        seal_path = self._cache_directory / f"{name}.receipt.json"
        replayed_from_cache = path.exists()
        if replayed_from_cache:
            _validate_dlsvm_matrix_seal(
                path,
                seal_path,
                identity=identity,
                identity_sha256=key,
                shape=shape,
            )
            matrix = np.load(path, allow_pickle=False)
        else:
            if seal_path.exists() or seal_path.is_symlink():
                raise ValueError("DLSVM matrix receipt exists without its matrix")
            matrix = np.asarray(compute(), dtype=np.float64)
            _validate_dlsvm_matrix_semantics(
                matrix,
                kind=kind,
                row_samples=row_samples,
                column_samples=column_samples,
                identity_sha256=key,
                recompute_values=False,
            )
            temporary = self._cache_directory / f".{name}.{os.getpid()}.tmp"
            try:
                with temporary.open("xb") as output:
                    np.save(output, matrix, allow_pickle=False)
                    output.flush()
                    os.fsync(output.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    replayed_from_cache = True
                    _validate_dlsvm_matrix_seal(
                        path,
                        seal_path,
                        identity=identity,
                        identity_sha256=key,
                        shape=shape,
                    )
                    matrix = np.load(path, allow_pickle=False)
                else:
                    _write_dlsvm_matrix_seal(
                        seal_path,
                        matrix_path=path,
                        identity=identity,
                        identity_sha256=key,
                        shape=shape,
                    )
            finally:
                temporary.unlink(missing_ok=True)
        _validate_dlsvm_matrix_semantics(
            matrix,
            kind=kind,
            row_samples=row_samples,
            column_samples=column_samples,
            identity_sha256=key,
            recompute_values=replayed_from_cache,
        )
        matrix_sha256 = _sha256_file(path)
        seal_sha256 = _sha256_file(seal_path)
        self._cache_artifacts[name] = {
            "identity": identity,
            "identity_sha256": key,
            "sha256": matrix_sha256,
            "receipt": seal_path.name,
            "receipt_sha256": seal_sha256,
            "rows": shape[0],
            "columns": shape[1],
        }
        return matrix

    def receipt(self) -> dict[str, Any] | None:
        if self._cache_directory is None:
            return None
        items = tuple(self._cache_directory.iterdir())
        if any(item.is_symlink() or not item.is_file() for item in items):
            raise ValueError("DLSVM persistent cache contains a non-regular artifact")
        expected = set(self._cache_artifacts) | {
            str(value["receipt"]) for value in self._cache_artifacts.values()
        }
        actual = {item.name for item in items}
        if actual != expected:
            raise ValueError("DLSVM persistent cache inventory is not closed")
        return {
            "schema_version": 1,
            "path": str(self._cache_directory),
            "artifacts": {
                name: self._cache_artifacts[name] for name in sorted(self._cache_artifacts)
            },
        }


def _write_dlsvm_matrix_seal(
    path: Path,
    *,
    matrix_path: Path,
    identity: Mapping[str, Any],
    identity_sha256: str,
    shape: tuple[int, int],
) -> None:
    value = {
        "schema_version": 1,
        "artifact_type": "qcsd-dlsvm-persisted-kernel-matrix",
        "matrix_file": matrix_path.name,
        "matrix_sha256": _sha256_file(matrix_path),
        "identity": dict(identity),
        "identity_sha256": identity_sha256,
        "shape": list(shape),
        "dtype": "float64",
    }
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    except FileExistsError as error:
        raise ValueError("DLSVM matrix receipt unexpectedly already exists") from error
    finally:
        temporary.unlink(missing_ok=True)


def _validate_dlsvm_matrix_seal(
    matrix_path: Path,
    seal_path: Path,
    *,
    identity: Mapping[str, Any],
    identity_sha256: str,
    shape: tuple[int, int],
) -> None:
    if (
        matrix_path.is_symlink()
        or not matrix_path.is_file()
        or seal_path.is_symlink()
        or not seal_path.is_file()
    ):
        raise ValueError("DLSVM cached matrix or immutable receipt is not a regular file")
    try:
        value = load_json(seal_path)
    except (OSError, ValueError) as error:
        raise ValueError("DLSVM cached matrix receipt cannot be loaded") from error
    expected = {
        "schema_version": 1,
        "artifact_type": "qcsd-dlsvm-persisted-kernel-matrix",
        "matrix_file": matrix_path.name,
        "matrix_sha256": _sha256_file(matrix_path),
        "identity": dict(identity),
        "identity_sha256": identity_sha256,
        "shape": list(shape),
        "dtype": "float64",
    }
    if value != expected:
        raise ValueError("DLSVM cached matrix receipt or identity is invalid")


def _validate_dlsvm_matrix_semantics(
    matrix: np.ndarray,
    *,
    kind: str,
    row_samples: Sequence[StudySample],
    column_samples: Sequence[StudySample],
    identity_sha256: str,
    recompute_values: bool = True,
) -> None:
    shape = (len(row_samples), len(column_samples))
    if (
        matrix.shape != shape
        or matrix.dtype != np.float64
        or not np.all(np.isfinite(matrix))
        or np.any(matrix < 0.0)
        or np.any(matrix > 1.0)
    ):
        raise ValueError("DLSVM cached matrix shape or values are invalid")
    if kind == "within" and (
        shape[0] != shape[1]
        or not np.array_equal(matrix, matrix.T)
        or not np.array_equal(np.diag(matrix), np.ones(shape[0], dtype=np.float64))
    ):
        raise ValueError("DLSVM cached within-defense matrix invariants are invalid")

    if not recompute_values:
        return
    # A create-only hash seal detects accidental damage, not a coherent matrix
    # substitution followed by resealing.  Cache reuse therefore regenerates
    # every kernel value from the currently bound traces.  There is no sampled
    # audit path in formal or non-formal cache replay.
    if not isinstance(identity_sha256, str) or len(identity_sha256) != 64:
        raise ValueError("DLSVM cached matrix identity is invalid")
    expected = _dlsvm_kernel(
        [dlsvm_sequence(sample.trace) for sample in row_samples],
        [dlsvm_sequence(sample.trace) for sample in column_samples],
        symmetric=kind == "within",
    )
    if not np.array_equal(matrix, expected):
        raise ValueError("DLSVM cached matrix fails complete deterministic recomputation")


@dataclass(frozen=True)
class AttackResult:
    """One deterministic closed-world classifier result."""

    attack: str
    backend: str
    training_defense: str
    testing_defense: str
    protocol: str
    train_samples: int
    test_samples: int
    labels: tuple[str, ...]
    accuracy: float
    balanced_accuracy: float
    confusion_matrix: tuple[tuple[int, ...], ...]
    per_class_recall: Mapping[str, float]
    predictions: tuple[AttackPrediction, ...]
    protocol_details: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        predictions = [prediction.as_dict() for prediction in self.predictions]
        return {
            "schema_version": SCHEMA_VERSION,
            "attack": self.attack,
            "backend": self.backend,
            "training_defense": self.training_defense,
            "testing_defense": self.testing_defense,
            "protocol": self.protocol,
            "train_samples": self.train_samples,
            "test_samples": self.test_samples,
            "labels": list(self.labels),
            "accuracy": self.accuracy,
            "balanced_accuracy": self.balanced_accuracy,
            "confusion_matrix": [list(row) for row in self.confusion_matrix],
            "per_class_recall": dict(self.per_class_recall),
            "predictions": predictions,
            "predictions_sha256": _canonical_json_sha256(predictions),
            "protocol_details": dict(self.protocol_details),
        }


@dataclass(frozen=True)
class AttackPrediction:
    """One auditable held-out prediction and its permitted bootstrap strata."""

    sample_id: str
    acquisition_block_index: int
    workload_id: str
    expected: str
    predicted: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "acquisition_block_index": self.acquisition_block_index,
            "workload_id": self.workload_id,
            "expected": self.expected,
            "predicted": self.predicted,
        }


def load_shape_trace(path: Path) -> tuple[ShapePacket, ...]:
    """Load and strictly validate one classifier-facing trace CSV."""

    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"shape trace is not a regular file: {path}")
    packets: list[ShapePacket] = []
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != [
            "relative_time_ns",
            "direction",
            "length_bytes",
            "signed_length_bytes",
        ]:
            raise ValueError("shape trace columns are invalid")
        previous = -1
        for row in reader:
            try:
                relative = int(row["relative_time_ns"])
                length = int(row["length_bytes"])
                signed = int(row["signed_length_bytes"])
            except (TypeError, ValueError) as error:
                raise ValueError("shape trace contains a non-integer") from error
            direction = row["direction"]
            if direction not in {"outgoing", "incoming"}:
                raise ValueError("shape trace direction is invalid")
            expected_signed = length if direction == "outgoing" else -length
            if relative < 0 or relative < previous or length <= 0 or signed != expected_signed:
                raise ValueError("shape trace time or size invariant failed")
            packets.append(ShapePacket(relative, direction, length))
            previous = relative
    if not packets or packets[0].relative_time_ns != 0:
        raise ValueError("shape trace must be non-empty and start at zero")
    return tuple(packets)


def load_study_handoff(root: Path) -> tuple[StudySample, ...]:
    """Load a new study handoff without weakening historical handoff rules."""

    root = root.resolve()
    samples_path = root / "samples.jsonl"
    if root.is_symlink() or not root.is_dir() or not samples_path.is_file():
        raise ValueError("study handoff root is invalid")
    samples: list[StudySample] = []
    seen: set[str] = set()
    for line_number, line in enumerate(samples_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"study handoff JSONL line {line_number} is invalid") from error
        if (
            not isinstance(row, dict)
            or row.get("schema_version") not in STUDY_HANDOFF_SCHEMA_VERSIONS
        ):
            raise ValueError("study handoff sample schema is invalid")
        required_strings = (
            "sample_id",
            "class_label",
            "workload_id",
            "defense",
            "paired_visit_id",
            "trace_path",
            "trace_sha256",
        )
        if any(not isinstance(row.get(key), str) or not row[key] for key in required_strings):
            raise ValueError("study handoff sample identity is invalid")
        sample_id = row["sample_id"]
        if sample_id in seen:
            raise ValueError("study handoff sample IDs are not unique")
        seen.add(sample_id)
        block = row.get("acquisition_block_index")
        if type(block) is not int or block < 0:
            raise ValueError("study handoff acquisition block is invalid")
        relative = Path(row["trace_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("study handoff trace path is unsafe")
        trace_path = (root / relative).resolve()
        try:
            trace_path.relative_to(root)
        except ValueError as error:
            raise ValueError("study handoff trace escapes its root") from error
        if _sha256_file(trace_path) != row["trace_sha256"]:
            raise ValueError("study handoff trace digest mismatch")
        trace = load_shape_trace(trace_path)
        samples.append(
            StudySample(
                sample_id=sample_id,
                class_label=row["class_label"],
                workload_id=row["workload_id"],
                defense=row["defense"],
                acquisition_block_index=block,
                paired_visit_id=row["paired_visit_id"],
                trace=trace,
                performance=_load_performance(row.get("performance"), trace),
                algorithm_diagnostics=_load_algorithm_diagnostics(
                    row.get("algorithm_diagnostics"),
                    defense=row["defense"],
                ),
            )
        )
    if not samples:
        raise ValueError("study handoff contains no samples")
    return tuple(samples)


def _load_algorithm_diagnostics(value: Any, *, defense: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    legacy_keys = {
        "schema_version",
        "mode",
        "runtime_kind",
        "classifier_input",
        "peer_reproduction",
        "runner_rows",
        "directions",
        "cs_buflo_state",
    }
    current_keys = legacy_keys | {"buflo_state"}
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") not in {1, 2, 3, 4}
        or set(value) != (legacy_keys if value.get("schema_version") == 1 else current_keys)
        or value.get("mode") != defense
        or value.get("classifier_input") is not False
        or not isinstance(value.get("runner_rows"), dict)
        or set(value.get("directions", {})) != {"outgoing", "incoming"}
    ):
        raise ValueError("study handoff algorithm diagnostic schema is invalid")
    if value["schema_version"] in {2, 3, 4}:
        runtime_kind = value.get("runtime_kind")
        buflo_state = value.get("buflo_state")
        cs_state = value.get("cs_buflo_state")
        if value["schema_version"] == 4 and runtime_kind not in {"buflo", "cs_buflo"}:
            raise ValueError(
                "algorithm diagnostic schema 4 requires BuFLO or CS-BuFLO state"
            )
        if runtime_kind == "buflo":
            expected_state_schema = {1: 1, 2: 1, 3: 2, 4: 3}[value["schema_version"]]
            observed_state_schema = (
                buflo_state.get("schema_version", 1) if isinstance(buflo_state, Mapping) else None
            )
            if (
                observed_state_schema != expected_state_schema
                or not buflo_terminal_state_valid(buflo_state)
                or (
                    value["schema_version"] == 4
                    and not _current_buflo_schedule_stop_state_valid(
                        buflo_state, value["directions"]
                    )
                )
                or cs_state is not None
            ):
                raise ValueError("study handoff BuFLO algorithm state is invalid")
        elif runtime_kind == "cs_buflo":
            if (
                buflo_state is not None
                or not isinstance(cs_state, Mapping)
                or (
                    value["schema_version"] in {3, 4}
                    and not _current_cs_buflo_state_valid(
                        cs_state, schema_version=value["schema_version"]
                    )
                )
                or (
                    value["schema_version"] == 4
                    and not _current_cs_buflo_stop_drain_state_valid(cs_state, value["directions"])
                )
            ):
                raise ValueError("study handoff CS-BuFLO algorithm state is invalid")
        elif buflo_state is not None or cs_state is not None:
            raise ValueError("study handoff algorithm state contradicts its runtime kind")
    return value


_BUFLO_SCHEDULE_STOP_KEYS = frozenset(
    {
        "policy",
        "terminal_time_semantics",
        "latched",
        "latched_at_us",
        "available_bytes",
        "required_bytes",
        "directions",
    }
)
_BUFLO_SCHEDULE_STOP_DIRECTION_KEYS = frozenset(
    {
        "scheduled_cells_at_stop",
        "terminal_cells_at_stop",
        "drained_cells_after_stop",
        "last_scheduled_target_us",
        "last_terminal_at_us",
        "terminal_cells_strictly_before_stop",
        "terminal_cells_at_or_before_stop",
        "terminal_cells_at_stop_timestamp",
    }
)


def _current_buflo_schedule_stop_state_valid(
    value: Mapping[str, Any], algorithm_directions: Any
) -> bool:
    """Cross-check schema-3 BuFLO stop/drain state against final direction totals."""

    schedule_stop = value.get("schedule_stop")
    if not isinstance(schedule_stop, Mapping) or set(schedule_stop) != _BUFLO_SCHEDULE_STOP_KEYS:
        return False
    stop_us = schedule_stop.get("latched_at_us")
    terminal_us = value.get("terminal_latched_at_us")
    available = schedule_stop.get("available_bytes")
    required = schedule_stop.get("required_bytes")
    directions = schedule_stop.get("directions")
    if (
        schedule_stop.get("policy") != BUFLO_SCHEDULE_STOP_POLICY
        or schedule_stop.get("terminal_time_semantics")
        != BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS
        or schedule_stop.get("latched") is not True
        or type(stop_us) is not int
        or type(terminal_us) is not int
        or not 10_000_000 <= stop_us <= terminal_us
        or type(available) is not int
        or type(required) is not int
        or required != 1_200
        or not 0 <= available < required
        or not isinstance(directions, Mapping)
        or set(directions) != {"outgoing", "incoming"}
        or not isinstance(algorithm_directions, Mapping)
        or set(algorithm_directions) != {"outgoing", "incoming"}
    ):
        return False
    for direction in ("outgoing", "incoming"):
        state = directions[direction]
        metrics = algorithm_directions[direction]
        if (
            not isinstance(state, Mapping)
            or set(state) != _BUFLO_SCHEDULE_STOP_DIRECTION_KEYS
            or any(type(state[key]) is not int or state[key] < 0 for key in state)
            or not isinstance(metrics, Mapping)
        ):
            return False
        scheduled = state["scheduled_cells_at_stop"]
        terminal = state["terminal_cells_at_stop"]
        drained = state["drained_cells_after_stop"]
        strictly_before = state["terminal_cells_strictly_before_stop"]
        at_or_before = state["terminal_cells_at_or_before_stop"]
        at_timestamp = state["terminal_cells_at_stop_timestamp"]
        satisfaction = metrics.get("satisfaction_counts")
        if (
            type(metrics.get("scheduled_cells")) is not int
            or metrics["scheduled_cells"] != scheduled
            or not isinstance(satisfaction, Mapping)
            or any(type(item) is not int or item < 0 for item in satisfaction.values())
            or sum(satisfaction.values()) != scheduled
            or scheduled == 0
            or not 0 <= terminal <= scheduled
            or drained != scheduled - terminal
            or not 0 <= strictly_before <= terminal <= at_or_before <= scheduled
            or at_timestamp != at_or_before - strictly_before
            or state["last_scheduled_target_us"] > stop_us
            or state["last_terminal_at_us"] > terminal_us
            or (direction == "outgoing" and drained != 0)
        ):
            return False
    outgoing = directions["outgoing"]
    incoming = directions["incoming"]
    return bool(
        outgoing["scheduled_cells_at_stop"] == incoming["scheduled_cells_at_stop"]
        and outgoing["last_scheduled_target_us"]
        == incoming["last_scheduled_target_us"]
    )


_CS_BUFLO_STATE_V3_KEYS = frozenset(
    {
        "padding_variant",
        "early_termination_semantics",
        "incoming_boundaries",
        "rate_boundary_translation",
        "rate_transitions",
        "local_termination",
        "incoming_local_realized_cells",
        "directions",
    }
)
_CS_BUFLO_DIRECTION_V3_KEYS = frozenset(
    {
        "natural_bytes",
        "real_bearing_bytes",
        "post_local_et_natural_bytes",
        "terminal_interval_us",
        "rate_adaptations",
        "next_adaptation_boundary_bytes",
        "estimator_samples",
        "padding_basis_natural_bytes",
        "padding_basis_cover_bytes",
        "padding_basis_total_bytes",
        "padding_target_bytes",
        "power_of_two_crossed",
        "minimum_interval_opportunities",
        "minimum_interval_terminal",
        "minimum_interval_full",
        "minimum_interval_local_realized",
        "incoming_local_realized_cells",
        "rate_transitions",
    }
)
_CS_BUFLO_STOP_DRAIN_LEDGER_KEYS = frozenset(
    {
        "drained_cells_after_stop",
        "last_scheduled_target_us",
        "last_terminal_at_us",
        "terminal_cells_strictly_before_stop",
        "terminal_cells_at_or_before_stop",
        "terminal_cells_at_stop_timestamp",
    }
)
_CS_BUFLO_DIRECTION_V4_KEYS = _CS_BUFLO_DIRECTION_V3_KEYS | {
    "termination_accounted_bytes",
    "last_termination_increment_bytes",
    "termination_stop_latched",
    "termination_stop_crossing_total_bytes",
    "termination_stop_crossing_increment_bytes",
    "termination_stop_reason",
    "termination_stop_phase",
    "termination_stop_latched_at_us",
    "termination_stop_scheduled_cells_at_stop",
    "termination_stop_terminal_cells_at_stop",
    "termination_stop_progress_bytes_at_stop",
    "termination_stop_padding_target_bytes_at_stop",
    "termination_stop_provisional_invalidation_count",
    "stop_drain_ledger",
}


def _current_cs_buflo_state_valid(value: Mapping[str, Any], *, schema_version: int) -> bool:
    expected_state_keys = _CS_BUFLO_STATE_V3_KEYS | (
        {"early_termination_translation"} if schema_version == 4 else set()
    )
    expected_direction_keys = (
        _CS_BUFLO_DIRECTION_V4_KEYS if schema_version == 4 else _CS_BUFLO_DIRECTION_V3_KEYS
    )
    expected_semantics = (
        CS_BUFLO_EARLY_TERMINATION_SEMANTICS
        if schema_version == 4
        else CS_BUFLO_LEGACY_EARLY_TERMINATION_SEMANTICS
    )
    local = value.get("local_termination")
    expected_local_keys = {
        "latched",
        "pending_request_cancellations",
        "stream_cancellations",
        "latched_at_us",
        "before_application_complete",
        "application_receive_streams_handed_off",
        "application_parser_boundaries_handed_off",
        "application_parser_lease_bytes_handed_off",
        "application_send_endpoints_released",
        "post_local_et_natural_outgoing_bytes",
        "post_local_et_natural_incoming_bytes",
    }
    integer_local_keys = expected_local_keys - {
        "latched",
        "before_application_complete",
    }
    if (
        set(value) != expected_state_keys
        or value.get("early_termination_semantics") != expected_semantics
        or not isinstance(local, Mapping)
        or set(local) != expected_local_keys
        or local.get("latched") is not True
        or type(local.get("before_application_complete")) is not bool
        or any(type(local.get(key)) is not int or local[key] < 0 for key in integer_local_keys)
        or local["latched_at_us"] < 0
    ):
        return False
    handoff_keys = (
        "application_receive_streams_handed_off",
        "application_parser_boundaries_handed_off",
        "application_parser_lease_bytes_handed_off",
        "application_send_endpoints_released",
    )
    post_keys = (
        "post_local_et_natural_outgoing_bytes",
        "post_local_et_natural_incoming_bytes",
    )
    if local["before_application_complete"]:
        if not any(local[key] > 0 for key in handoff_keys):
            return False
    elif any(local[key] != 0 for key in (*handoff_keys, *post_keys)):
        return False
    directions = value.get("directions")
    if not isinstance(directions, Mapping) or set(directions) != {"outgoing", "incoming"}:
        return False
    for direction in ("outgoing", "incoming"):
        state = directions[direction]
        if not isinstance(state, Mapping) or set(state) != expected_direction_keys:
            return False
        natural = state.get("natural_bytes")
        frozen = state.get("padding_basis_natural_bytes")
        post = state.get("post_local_et_natural_bytes")
        real_bearing = state.get("real_bearing_bytes")
        if (
            any(type(item) is not int or item < 0 for item in (natural, frozen, post, real_bearing))
            or natural != frozen + post
            or real_bearing > frozen
            or post != local[f"post_local_et_natural_{direction}_bytes"]
        ):
            return False
    return True


def _current_cs_buflo_stop_drain_state_valid(
    value: Mapping[str, Any], algorithm_directions: Any
) -> bool:
    translation = value.get("early_termination_translation")
    if (
        not isinstance(translation, Mapping)
        or set(translation) != {"version", "stop_policy"}
        or type(translation.get("version")) is not int
        or translation.get("version") != CS_BUFLO_EARLY_TERMINATION_TRANSLATION_VERSION
        or translation.get("stop_policy") != CS_BUFLO_TERMINATION_STOP_POLICY
    ):
        return False
    directions = value.get("directions")
    local = value.get("local_termination")
    if (
        not isinstance(directions, Mapping)
        or set(directions) != {"outgoing", "incoming"}
        or not isinstance(algorithm_directions, Mapping)
        or set(algorithm_directions) != {"outgoing", "incoming"}
        or not isinstance(local, Mapping)
    ):
        return False
    local_latch_us = local.get("latched_at_us")
    for direction in ("outgoing", "incoming"):
        state = directions[direction]
        metrics = algorithm_directions[direction]
        if (
            not isinstance(state, Mapping)
            or not isinstance(metrics, Mapping)
            or state.get("termination_stop_latched") is not True
            or not isinstance(state.get("termination_stop_reason"), str)
            or state.get("termination_stop_reason") not in CS_BUFLO_TERMINATION_STOP_REASONS
            or not isinstance(state.get("termination_stop_phase"), str)
            or state.get("termination_stop_phase") not in CS_BUFLO_TERMINATION_STOP_PHASES
        ):
            return False
        crossing_total = state.get("termination_stop_crossing_total_bytes")
        crossing_increment = state.get("termination_stop_crossing_increment_bytes")
        final_total = state.get("termination_accounted_bytes")
        last_increment = state.get("last_termination_increment_bytes")
        stop_us = state.get("termination_stop_latched_at_us")
        scheduled_at_stop = state.get("termination_stop_scheduled_cells_at_stop")
        terminal_at_stop = state.get("termination_stop_terminal_cells_at_stop")
        progress_at_stop = state.get("termination_stop_progress_bytes_at_stop")
        target_at_stop = state.get("termination_stop_padding_target_bytes_at_stop")
        invalidations = state.get("termination_stop_provisional_invalidation_count")
        scheduled_final = metrics.get("scheduled_cells")
        satisfactions = metrics.get("satisfaction_counts")
        ledger = state.get("stop_drain_ledger")
        if any(
            type(item) is not int or item < 0
            for item in (
                crossing_total,
                crossing_increment,
                final_total,
                last_increment,
                stop_us,
                scheduled_at_stop,
                terminal_at_stop,
                progress_at_stop,
                target_at_stop,
                invalidations,
                scheduled_final,
                local_latch_us,
            )
        ) or (
            not isinstance(satisfactions, Mapping)
            or any(type(item) is not int or item < 0 for item in satisfactions.values())
            or sum(satisfactions.values()) != scheduled_final
            or not isinstance(ledger, Mapping)
            or set(ledger) != _CS_BUFLO_STOP_DRAIN_LEDGER_KEYS
            or any(type(item) is not int or item < 0 for item in ledger.values())
        ):
            return False
        no_crossing = crossing_total == 0 and crossing_increment == 0
        crossing_valid = (
            0 < crossing_increment <= crossing_total <= final_total
            and crossing_total > crossing_increment
            and (crossing_total - crossing_increment).bit_length() < crossing_total.bit_length()
        )
        final_crossing = (
            0 < last_increment <= final_total
            and (final_total - last_increment).bit_length() < final_total.bit_length()
        )
        reason = state["termination_stop_reason"]
        if (
            stop_us > local_latch_us
            or scheduled_at_stop != scheduled_final
            or terminal_at_stop > scheduled_at_stop
            or state.get("termination_stop_padding_target_bytes_at_stop")
            != state.get("padding_target_bytes")
            or state.get("power_of_two_crossed") is not final_crossing
            or not (no_crossing or crossing_valid)
            or (direction == "incoming" and crossing_valid and crossing_increment != 600)
            or (
                reason == "padding_target_reached"
                and (not no_crossing or progress_at_stop < target_at_stop)
            )
            or (reason == "power_of_two_crossing" and not crossing_valid)
            or ledger["drained_cells_after_stop"] != scheduled_at_stop - terminal_at_stop
            or not (
                ledger["terminal_cells_strictly_before_stop"]
                <= terminal_at_stop
                <= ledger["terminal_cells_at_or_before_stop"]
            )
            or ledger["terminal_cells_at_stop_timestamp"]
            != ledger["terminal_cells_at_or_before_stop"]
            - ledger["terminal_cells_strictly_before_stop"]
            or ledger["last_scheduled_target_us"] > stop_us
            or ledger["last_terminal_at_us"] > local_latch_us
        ):
            return False
    return True


def _load_performance(value: Any, trace: Sequence[ShapePacket]) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _PERFORMANCE_KEYS:
        raise ValueError("study handoff performance schema is invalid")
    if (
        value.get("schema_version") != 1
        or type(value.get("application_duration_ns")) is not int
        or value["application_duration_ns"] <= 0
        or type(value.get("application_response_bytes")) is not int
        or value["application_response_bytes"] < 0
    ):
        raise ValueError("study handoff application performance is invalid")
    expected_wire = {
        direction: sum(packet.length_bytes for packet in trace if packet.direction == direction)
        for direction in ("outgoing", "incoming")
    }
    expected_packets = {
        direction: sum(packet.direction == direction for packet in trace)
        for direction in ("outgoing", "incoming")
    }
    if value.get("wire_bytes") != expected_wire or value.get("packet_count") != expected_packets:
        raise ValueError("study handoff performance does not match its shape trace")
    for key in ("udp_payload_bytes", "udp_payload_lengths_missing"):
        record = value.get(key)
        if not isinstance(record, dict) or set(record) != {"outgoing", "incoming"}:
            raise ValueError("study handoff directional UDP performance is invalid")
    for direction in ("outgoing", "incoming"):
        udp = value["udp_payload_bytes"][direction]
        missing = value["udp_payload_lengths_missing"][direction]
        if (udp is not None and (type(udp) is not int or udp < 0)) or (
            type(missing) is not int or not 0 <= missing <= expected_packets[direction]
        ):
            raise ValueError("study handoff directional UDP values are invalid")
        if (missing == 0) != (udp is not None):
            raise ValueError("study handoff UDP availability declaration is inconsistent")
    retransmissions = value.get("transport_retransmissions")
    if retransmissions is not None and (type(retransmissions) is not int or retransmissions < 0):
        raise ValueError("study handoff retransmission count is invalid")
    usage = value.get("client_resource_usage")
    if usage is not None:
        _validate_resource_usage(usage)
    return value


def _validate_resource_usage(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != _RESOURCE_USAGE_KEYS:
        raise ValueError("study handoff client resource usage schema is invalid")
    if value.get("schema_version") != 1 or not isinstance(value.get("source"), str):
        raise ValueError("study handoff client resource usage identity is invalid")
    for key in (
        "user_cpu_seconds",
        "system_cpu_seconds",
        "wall_time_seconds",
        "maximum_rss_bytes",
        "voluntary_context_switches",
        "involuntary_context_switches",
    ):
        metric = value.get(key)
        if (
            isinstance(metric, bool)
            or not isinstance(metric, (int, float))
            or not math.isfinite(float(metric))
            or metric < 0
        ):
            raise ValueError(f"study handoff client resource metric is invalid: {key}")
    _validate_nullable_metric(value, "timer_wakeups", "timer_wakeups_unavailable_reason")
    _validate_nullable_metric(value, "rapl_energy_joules", "rapl_unavailable_reason")


def _validate_nullable_metric(value: Mapping[str, Any], metric: str, reason: str) -> None:
    measured = value.get(metric)
    unavailable = value.get(reason)
    if measured is None:
        if not isinstance(unavailable, str) or not unavailable:
            raise ValueError(f"study handoff unavailable metric has no reason: {metric}")
    elif (
        isinstance(measured, bool)
        or not isinstance(measured, (int, float))
        or not math.isfinite(float(measured))
        or measured < 0
        or unavailable is not None
    ):
        raise ValueError(f"study handoff nullable resource metric is invalid: {metric}")


def _performance_is_complete(sample: StudySample) -> bool:
    performance = sample.performance
    return bool(
        performance is not None
        and isinstance(performance.get("client_resource_usage"), Mapping)
        and performance.get("transport_retransmissions") is not None
        and performance.get("udp_payload_lengths_missing") == {"outgoing": 0, "incoming": 0}
    )


def validate_formal_cohort(
    samples: Sequence[StudySample],
    *,
    visits_per_block: int = 10,
    require_performance: bool = False,
) -> None:
    """Validate the exact focused 1,500-sample formal protocol."""

    if any(
        FORMAL_CLASS_BY_WORKLOAD.get(sample.workload_id) != sample.class_label for sample in samples
    ):
        raise ValueError("formal cohort workload/class identity is invalid")
    expected_total = (
        len(FORMAL_BLOCKS) * len(FORMAL_WORKLOADS) * visits_per_block * len(FORMAL_DEFENSES)
    )
    if len(samples) != expected_total:
        raise ValueError(f"formal cohort requires exactly {expected_total} samples")
    counts = Counter(
        (sample.acquisition_block_index, sample.workload_id, sample.defense) for sample in samples
    )
    expected_keys = {
        (block, workload, defense)
        for block in FORMAL_BLOCKS
        for workload in FORMAL_WORKLOADS
        for defense in FORMAL_DEFENSES
    }
    if set(counts) != expected_keys or any(value != visits_per_block for value in counts.values()):
        raise ValueError("formal cohort block/class/defense balance is invalid")
    paired: dict[str, set[str]] = defaultdict(set)
    paired_identity: dict[str, tuple[int, str, str]] = {}
    for sample in samples:
        if sample.defense in paired[sample.paired_visit_id]:
            raise ValueError("formal cohort has a duplicate paired defense")
        paired[sample.paired_visit_id].add(sample.defense)
        identity = (
            sample.acquisition_block_index,
            sample.class_label,
            sample.workload_id,
        )
        previous = paired_identity.setdefault(sample.paired_visit_id, identity)
        if previous != identity:
            raise ValueError("formal cohort pairs cross block or workload boundaries")
    if any(tuple(sorted(value)) != tuple(sorted(FORMAL_DEFENSES)) for value in paired.values()):
        raise ValueError("formal cohort paired visits are incomplete")
    if len(paired) != len(FORMAL_BLOCKS) * len(FORMAL_WORKLOADS) * visits_per_block:
        raise ValueError("formal cohort paired-visit count is invalid")
    if require_performance and any(not _performance_is_complete(sample) for sample in samples):
        raise ValueError("formal cohort performance evidence is incomplete")


def ratio_of_sums(defended: Iterable[int | float], baseline: Iterable[int | float]) -> float:
    """Paper-compatible ratio of aggregate sums, never a mean of ratios."""

    defended_total = math.fsum(float(value) for value in defended)
    baseline_total = math.fsum(float(value) for value in baseline)
    if not math.isfinite(defended_total) or defended_total < 0:
        raise ValueError("aggregate defended total must be finite and non-negative")
    if not math.isfinite(baseline_total) or baseline_total <= 0:
        raise ValueError("aggregate baseline must be positive")
    return defended_total / baseline_total


def paired_overheads(samples: Sequence[StudySample]) -> list[dict[str, Any]]:
    """Create paired wire/duration records for every defended visit."""

    visits: dict[str, dict[str, StudySample]] = defaultdict(dict)
    for sample in samples:
        if sample.defense in visits[sample.paired_visit_id]:
            raise ValueError("duplicate defense in paired visit")
        visits[sample.paired_visit_id][sample.defense] = sample
    rows: list[dict[str, Any]] = []
    for paired_visit_id, group in sorted(visits.items()):
        baseline = group.get("undefended")
        if baseline is None:
            raise ValueError("paired visit has no undefended baseline")
        if baseline.wire_bytes <= 0 or baseline.application_duration_ns <= 0:
            raise ValueError("paired baseline byte and duration totals must be positive")
        for defense, sample in sorted(group.items()):
            if defense == "undefended":
                continue
            wire_ratio = sample.wire_bytes / baseline.wire_bytes
            duration_ratio = sample.application_duration_ns / baseline.application_duration_ns
            rows.append(
                {
                    "paired_visit_id": paired_visit_id,
                    "acquisition_block_index": sample.acquisition_block_index,
                    "class_label": sample.class_label,
                    "workload_id": sample.workload_id,
                    "defense": defense,
                    "defended_wire_bytes": sample.wire_bytes,
                    "baseline_wire_bytes": baseline.wire_bytes,
                    "wire_ratio": wire_ratio,
                    "additional_wire_percent": 100.0 * (wire_ratio - 1.0),
                    "defended_duration_ns": sample.application_duration_ns,
                    "baseline_duration_ns": baseline.application_duration_ns,
                    "duration_ratio": duration_ratio,
                    "added_duration_seconds": (
                        sample.application_duration_ns - baseline.application_duration_ns
                    )
                    / 1_000_000_000,
                }
            )
            _add_optional_paired_performance(rows[-1], sample, baseline)
    return rows


def _add_optional_paired_performance(
    row: dict[str, Any], defended: StudySample, baseline: StudySample
) -> None:
    if defended.performance is None or baseline.performance is None:
        return
    defended_performance = defended.performance
    baseline_performance = baseline.performance
    for direction in ("outgoing", "incoming"):
        row[f"defended_{direction}_wire_bytes"] = defended_performance["wire_bytes"][direction]
        row[f"baseline_{direction}_wire_bytes"] = baseline_performance["wire_bytes"][direction]
        row[f"defended_{direction}_packet_count"] = defended_performance["packet_count"][direction]
        row[f"baseline_{direction}_packet_count"] = baseline_performance["packet_count"][direction]
    udp_values = (
        *defended_performance["udp_payload_bytes"].values(),
        *baseline_performance["udp_payload_bytes"].values(),
    )
    if any(value is None for value in udp_values):
        return
    defended_udp = sum(defended_performance["udp_payload_bytes"].values())
    baseline_udp = sum(baseline_performance["udp_payload_bytes"].values())
    for direction in ("outgoing", "incoming"):
        row[f"defended_{direction}_udp_payload_bytes"] = defended_performance["udp_payload_bytes"][
            direction
        ]
        row[f"baseline_{direction}_udp_payload_bytes"] = baseline_performance["udp_payload_bytes"][
            direction
        ]
    row.update(
        {
            "defended_udp_payload_bytes": defended_udp,
            "baseline_udp_payload_bytes": baseline_udp,
            "defended_packet_count": sum(defended_performance["packet_count"].values()),
            "baseline_packet_count": sum(baseline_performance["packet_count"].values()),
            "defended_application_response_bytes": defended_performance[
                "application_response_bytes"
            ],
            "baseline_application_response_bytes": baseline_performance[
                "application_response_bytes"
            ],
            "defended_goodput_bytes_per_second": (
                defended_performance["application_response_bytes"]
                * 1_000_000_000
                / defended.application_duration_ns
            ),
            "baseline_goodput_bytes_per_second": (
                baseline_performance["application_response_bytes"]
                * 1_000_000_000
                / baseline.application_duration_ns
            ),
            "defended_transport_retransmissions": defended_performance["transport_retransmissions"],
            "baseline_transport_retransmissions": baseline_performance["transport_retransmissions"],
        }
    )
    defended_usage = defended_performance.get("client_resource_usage")
    baseline_usage = baseline_performance.get("client_resource_usage")
    if isinstance(defended_usage, Mapping) and isinstance(baseline_usage, Mapping):
        for metric in (
            "user_cpu_seconds",
            "system_cpu_seconds",
            "wall_time_seconds",
            "maximum_rss_bytes",
            "voluntary_context_switches",
            "involuntary_context_switches",
            "timer_wakeups",
            "rapl_energy_joules",
        ):
            defended_value = defended_usage.get(metric)
            baseline_value = baseline_usage.get(metric)
            if defended_value is not None and baseline_value is not None:
                row[f"defended_{metric}"] = defended_value
                row[f"baseline_{metric}"] = baseline_value
    if baseline_performance["application_response_bytes"] > 0:
        row["goodput_ratio"] = (
            defended_performance["application_response_bytes"]
            / defended.application_duration_ns
            / (
                baseline_performance["application_response_bytes"]
                / baseline.application_duration_ns
            )
        )


def _add_optional_performance_summary(
    summary: dict[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    if not rows or any("defended_udp_payload_bytes" not in row for row in rows):
        summary["performance_evidence_available"] = False
        return
    summary["performance_evidence_available"] = True
    for label, numerator, denominator in (
        ("udp_payload_ratio_of_sums", "defended_udp_payload_bytes", "baseline_udp_payload_bytes"),
        ("packet_count_ratio_of_sums", "defended_packet_count", "baseline_packet_count"),
        (
            "outgoing_wire_ratio_of_sums",
            "defended_outgoing_wire_bytes",
            "baseline_outgoing_wire_bytes",
        ),
        (
            "incoming_wire_ratio_of_sums",
            "defended_incoming_wire_bytes",
            "baseline_incoming_wire_bytes",
        ),
    ):
        summary[label] = ratio_of_sums(
            (float(row[numerator]) for row in rows),
            (float(row[denominator]) for row in rows),
        )
    summary["goodput_bytes_per_second"] = {
        "defended": ratio_of_sums(
            (float(row["defended_application_response_bytes"]) for row in rows),
            (float(row["defended_duration_ns"]) / 1_000_000_000 for row in rows),
        ),
        "baseline": ratio_of_sums(
            (float(row["baseline_application_response_bytes"]) for row in rows),
            (float(row["baseline_duration_ns"]) / 1_000_000_000 for row in rows),
        ),
    }
    if all("goodput_ratio" in row for row in rows):
        summary["goodput_ratio_pair_quantiles"] = _quantiles(rows, "goodput_ratio")


def performance_breakdowns(
    samples: Sequence[StudySample], *, bootstrap_draws: int = 10_000
) -> dict[str, Any]:
    """Aggregate directional traffic and client costs by the required strata."""

    if any(not _performance_is_complete(sample) for sample in samples):
        raise ValueError("performance breakdown requires complete handoff evidence")
    directional: dict[tuple[str, str, int, str], list[StudySample]] = defaultdict(list)
    client: dict[tuple[str, str, int], list[StudySample]] = defaultdict(list)
    for sample in samples:
        for direction in ("outgoing", "incoming"):
            directional[
                (sample.defense, sample.workload_id, sample.acquisition_block_index, direction)
            ].append(sample)
        client[(sample.defense, sample.workload_id, sample.acquisition_block_index)].append(sample)

    directional_rows = []
    for (defense, workload, block, direction), group in sorted(directional.items()):
        directional_rows.append(
            {
                "defense": defense,
                "workload_id": workload,
                "acquisition_block_index": block,
                "direction": direction,
                "samples": len(group),
                "wire_bytes": sum(
                    int(sample.performance["wire_bytes"][direction]) for sample in group
                ),
                "udp_payload_bytes": sum(
                    int(sample.performance["udp_payload_bytes"][direction]) for sample in group
                ),
                "packet_count": sum(
                    int(sample.performance["packet_count"][direction]) for sample in group
                ),
            }
        )

    client_rows = []
    for (defense, workload, block), group in sorted(client.items()):
        application_bytes = sum(
            int(sample.performance["application_response_bytes"]) for sample in group
        )
        application_seconds = math.fsum(
            sample.application_duration_ns / 1_000_000_000 for sample in group
        )
        usage = [sample.performance["client_resource_usage"] for sample in group]
        client_rows.append(
            {
                "defense": defense,
                "workload_id": workload,
                "acquisition_block_index": block,
                "samples": len(group),
                "application_response_bytes": application_bytes,
                "application_seconds": application_seconds,
                "completion_time_seconds": _numeric_quantiles(
                    [sample.application_duration_ns / 1_000_000_000 for sample in group]
                ),
                "goodput_bytes_per_second": application_bytes / application_seconds,
                "transport_retransmissions": sum(
                    int(sample.performance["transport_retransmissions"]) for sample in group
                ),
                "resource_usage": _summarize_resource_usage(usage),
            }
        )
    paired = (
        paired_overheads(samples)
        if any(sample.defense == "undefended" for sample in samples)
        else []
    )
    paired_directional: dict[tuple[str, str, int, str], list[Mapping[str, Any]]] = defaultdict(list)
    paired_client: dict[tuple[str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
    mode_direction: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    mode_client: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in paired:
        defense = str(row["defense"])
        workload = str(row["workload_id"])
        block = int(row["acquisition_block_index"])
        paired_client[(defense, workload, block)].append(row)
        mode_client[defense].append(row)
        for direction in ("outgoing", "incoming"):
            paired_directional[(defense, workload, block, direction)].append(row)
            mode_direction[(defense, direction)].append(row)

    paired_directional_rows = [
        {
            "defense": defense,
            "workload_id": workload,
            "acquisition_block_index": block,
            "direction": direction,
            **_paired_directional_performance(group, direction=direction),
        }
        for (defense, workload, block, direction), group in sorted(paired_directional.items())
    ]
    paired_client_rows = [
        {
            "defense": defense,
            "workload_id": workload,
            "acquisition_block_index": block,
            **_paired_client_performance(group),
        }
        for (defense, workload, block), group in sorted(paired_client.items())
    ]
    mode_direction_rows = [
        {
            "defense": defense,
            "direction": direction,
            **_paired_directional_performance(
                group,
                direction=direction,
                bootstrap_draws=bootstrap_draws,
            ),
        }
        for (defense, direction), group in sorted(mode_direction.items())
    ]
    mode_client_rows = [
        {
            "defense": defense,
            **_paired_client_performance(group, bootstrap_draws=bootstrap_draws),
        }
        for defense, group in sorted(mode_client.items())
    ]
    return {
        "directional": directional_rows,
        "client": client_rows,
        "paired_directional_by_workload_block": paired_directional_rows,
        "paired_client_by_workload_block": paired_client_rows,
        "paired_mode_direction_block_workload_bootstrap_95": mode_direction_rows,
        "paired_mode_client_block_workload_bootstrap_95": mode_client_rows,
    }


def _paired_directional_performance(
    rows: Sequence[Mapping[str, Any]],
    *,
    direction: str,
    bootstrap_draws: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"pairs": len(rows)}
    for offset, (metric, suffix) in enumerate(
        (("wire", "wire_bytes"), ("udp_payload", "udp_payload_bytes"), ("packet", "packet_count"))
    ):
        numerator = f"defended_{direction}_{suffix}"
        denominator = f"baseline_{direction}_{suffix}"
        ratio = ratio_of_sums(
            (float(row[numerator]) for row in rows),
            (float(row[denominator]) for row in rows),
        )
        pair_values = [float(row[numerator]) / float(row[denominator]) for row in rows]
        result[f"{metric}_ratio_of_sums"] = ratio
        result[f"{metric}_additional_percent"] = 100.0 * (ratio - 1.0)
        result[f"{metric}_ratio_pair_quantiles"] = _numeric_quantiles(pair_values)
        if bootstrap_draws is not None:
            result[f"{metric}_ratio_block_workload_bootstrap_95"] = _cluster_bootstrap_ratio(
                rows,
                numerator=numerator,
                denominator=denominator,
                draws=bootstrap_draws,
                seed=20260827 ^ (offset + (0 if direction == "outgoing" else 16)),
            )
    return result


def _paired_client_performance(
    rows: Sequence[Mapping[str, Any]], *, bootstrap_draws: int | None = None
) -> dict[str, Any]:
    duration_ratio = ratio_of_sums(
        (float(row["defended_duration_ns"]) for row in rows),
        (float(row["baseline_duration_ns"]) for row in rows),
    )
    defended_goodput = ratio_of_sums(
        (float(row["defended_application_response_bytes"]) for row in rows),
        (float(row["defended_duration_ns"]) / 1_000_000_000 for row in rows),
    )
    baseline_goodput = ratio_of_sums(
        (float(row["baseline_application_response_bytes"]) for row in rows),
        (float(row["baseline_duration_ns"]) / 1_000_000_000 for row in rows),
    )
    result: dict[str, Any] = {
        "pairs": len(rows),
        "completion_ratio_of_sums": duration_ratio,
        "completion_additional_percent": 100.0 * (duration_ratio - 1.0),
        "completion_ratio_pair_quantiles": _quantiles(rows, "duration_ratio"),
        "added_seconds_pair_quantiles": _quantiles(rows, "added_duration_seconds"),
        "completion_tail_seconds": {
            "defended": _numeric_quantiles(
                [float(row["defended_duration_ns"]) / 1_000_000_000 for row in rows]
            ),
            "baseline": _numeric_quantiles(
                [float(row["baseline_duration_ns"]) / 1_000_000_000 for row in rows]
            ),
        },
        "goodput_bytes_per_second": {
            "defended": defended_goodput,
            "baseline": baseline_goodput,
        },
        "goodput_ratio": defended_goodput / baseline_goodput,
        "goodput_ratio_pair_quantiles": _quantiles(rows, "goodput_ratio"),
    }
    paired_costs: dict[str, Any] = {}
    for metric in (
        "user_cpu_seconds",
        "system_cpu_seconds",
        "wall_time_seconds",
        "maximum_rss_bytes",
        "voluntary_context_switches",
        "involuntary_context_switches",
        "timer_wakeups",
        "rapl_energy_joules",
        "transport_retransmissions",
    ):
        numerator = f"defended_{metric}"
        denominator = f"baseline_{metric}"
        if any(numerator not in row or denominator not in row for row in rows):
            paired_costs[metric] = {"available": False}
            continue
        defended_values = [float(row[numerator]) for row in rows]
        baseline_values = [float(row[denominator]) for row in rows]
        differences = [
            defended - baseline
            for defended, baseline in zip(defended_values, baseline_values, strict=True)
        ]
        metric_result: dict[str, Any] = {
            "available": True,
            "defended_sum": math.fsum(defended_values),
            "baseline_sum": math.fsum(baseline_values),
            "paired_difference_quantiles": _numeric_quantiles(differences),
            "paired_values": [
                {"defended": defended, "baseline": baseline, "difference": difference}
                for defended, baseline, difference in zip(
                    defended_values, baseline_values, differences, strict=True
                )
            ],
        }
        if math.fsum(baseline_values) > 0 and all(value > 0 for value in baseline_values):
            ratio = ratio_of_sums(defended_values, baseline_values)
            metric_result.update(
                {
                    "ratio_of_sums": ratio,
                    "additional_percent": 100.0 * (ratio - 1.0),
                    "paired_ratio_quantiles": _numeric_quantiles(
                        [
                            defended / baseline
                            for defended, baseline in zip(
                                defended_values, baseline_values, strict=True
                            )
                        ]
                    ),
                }
            )
            if bootstrap_draws is not None:
                metric_result["ratio_block_workload_bootstrap_95"] = _cluster_bootstrap_ratio(
                    rows,
                    numerator=numerator,
                    denominator=denominator,
                    draws=bootstrap_draws,
                    seed=20260827
                    ^ int.from_bytes(hashlib.sha256(metric.encode("ascii")).digest()[:4], "big"),
                )
        if bootstrap_draws is not None:
            metric_result["difference_block_workload_bootstrap_95"] = _cluster_bootstrap_difference(
                rows,
                defended=numerator,
                baseline=denominator,
                draws=bootstrap_draws,
                seed=20260827
                ^ int.from_bytes(
                    hashlib.sha256((metric + "-difference").encode("ascii")).digest()[:4],
                    "big",
                ),
            )
        paired_costs[metric] = metric_result
    result["paired_client_costs"] = paired_costs
    if bootstrap_draws is not None:
        result["completion_ratio_block_workload_bootstrap_95"] = _cluster_bootstrap_ratio(
            rows,
            numerator="defended_duration_ns",
            denominator="baseline_duration_ns",
            draws=bootstrap_draws,
            seed=20260827 ^ 0xC011,
        )
        result["goodput_ratio_block_workload_bootstrap_95"] = _cluster_bootstrap_goodput_ratio(
            rows,
            draws=bootstrap_draws,
            seed=20260827 ^ 0x600D,
        )
        result["added_seconds_block_workload_bootstrap_95"] = _cluster_bootstrap_difference(
            rows,
            defended="defended_duration_ns",
            baseline="baseline_duration_ns",
            draws=bootstrap_draws,
            seed=20260827 ^ 0xADD5,
            scale=1 / 1_000_000_000,
        )
    return result


def algorithm_breakdowns(samples: Sequence[StudySample]) -> dict[str, Any]:
    """Aggregate sealed runner algorithm evidence without exposing it to classifiers."""

    if any(sample.algorithm_diagnostics is None for sample in samples):
        return {
            "available": False,
            "reason": "handoff runner algorithm diagnostics are incomplete",
        }
    if not samples:
        return {
            "available": True,
            "classifier_input": False,
            "strata": [],
            "buflo_terminal_tail_strata": [],
        }
    diagnostic_version_values = [
        sample.algorithm_diagnostics["schema_version"]
        for sample in samples
        if sample.algorithm_diagnostics is not None
    ]
    if any(type(version) is not int for version in diagnostic_version_values):
        raise ValueError("study handoff has an invalid algorithm diagnostic schema version")
    diagnostic_versions = set(diagnostic_version_values)
    if len(diagnostic_versions) != 1 and not diagnostic_versions <= {3, 4}:
        raise ValueError("study handoff mixes algorithm diagnostic schema versions")
    groups: dict[tuple[str, str, int, str], list[Mapping[str, Any]]] = defaultdict(list)
    terminal_tail_groups: dict[tuple[str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
    schedule_stop_groups: dict[tuple[str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
    cs_local_et_groups: dict[tuple[str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
    for sample in samples:
        assert sample.algorithm_diagnostics is not None
        directions = sample.algorithm_diagnostics["directions"]
        buflo_state = sample.algorithm_diagnostics.get("buflo_state")
        cs_state = sample.algorithm_diagnostics.get("cs_buflo_state")
        if isinstance(buflo_state, Mapping):
            terminal_tail_groups[
                (sample.defense, sample.workload_id, sample.acquisition_block_index)
            ].append(buflo_state)
            if sample.algorithm_diagnostics["schema_version"] == 4:
                schedule_stop_groups[
                    (sample.defense, sample.workload_id, sample.acquisition_block_index)
                ].append(buflo_state["schedule_stop"])
        sample_diagnostic_version = sample.algorithm_diagnostics["schema_version"]
        if sample_diagnostic_version in {3, 4} and isinstance(cs_state, Mapping):
            cs_local_et_groups[
                (sample.defense, sample.workload_id, sample.acquisition_block_index)
            ].append(cs_state["local_termination"])
        for direction in ("outgoing", "incoming"):
            groups[
                (
                    sample.defense,
                    sample.workload_id,
                    sample.acquisition_block_index,
                    direction,
                )
            ].append(
                {
                    "direction": directions[direction],
                    "cs_buflo_state": sample.algorithm_diagnostics.get("cs_buflo_state"),
                    "algorithm_schema_version": sample_diagnostic_version,
                }
            )
    rows = []
    for (defense, workload, block, direction), group in sorted(groups.items()):
        directional = [item["direction"] for item in group]
        target_histogram: Counter[str] = Counter()
        satisfaction: Counter[str] = Counter()
        congestion: Counter[str] = Counter()
        composition: Counter[str] = Counter()
        for item in directional:
            target_histogram.update(item["target_size_bytes"]["histogram"])
            satisfaction.update(item["satisfaction_counts"])
            congestion.update(item["congestion_reason_counts"])
            composition.update(item["traffic_composition_bytes"])
        cs_rows = [
            item["cs_buflo_state"]["directions"][direction]
            for item in group
            if isinstance(item["cs_buflo_state"], Mapping)
        ]
        cs_v4_rows = [
            item["cs_buflo_state"]["directions"][direction]
            for item in group
            if item["algorithm_schema_version"] == 4 and isinstance(item["cs_buflo_state"], Mapping)
        ]
        variants = sorted(
            {
                str(item["cs_buflo_state"]["padding_variant"])
                for item in group
                if isinstance(item["cs_buflo_state"], Mapping)
            }
        )
        transition_histogram = Counter(
            f"{transition['from_interval_us']}->{transition['to_interval_us']}"
            for item in directional
            for transition in item["inferred_nearest_nominal_transitions"]
        )
        explicit_transition_histogram = Counter(
            f"{transition['previous_interval_us']}->{transition['resulting_interval_us']}"
            for item in cs_rows
            for transition in item["rate_transitions"]
        )
        rows.append(
            {
                "defense": defense,
                "workload_id": workload,
                "acquisition_block_index": block,
                "direction": direction,
                "samples": len(group),
                "scheduled_cells": sum(int(item["scheduled_cells"]) for item in directional),
                "target_size_histogram": dict(sorted(target_histogram.items())),
                "desired_udp_bytes": sum(int(item["desired_udp_bytes"]) for item in directional),
                "observed_udp_bytes": sum(int(item["observed_udp_bytes"]) for item in directional),
                "target_realization_ratio": (
                    sum(int(item["observed_udp_bytes"]) for item in directional)
                    / sum(int(item["desired_udp_bytes"]) for item in directional)
                    if sum(int(item["desired_udp_bytes"]) for item in directional)
                    else None
                ),
                "satisfaction_counts": dict(sorted(satisfaction.items())),
                "congestion_reason_counts": dict(sorted(congestion.items())),
                "traffic_composition_bytes": dict(sorted(composition.items())),
                "inter_target_delta_us": _merge_algorithm_summaries(
                    [item["inter_target_delta_us"] for item in directional]
                ),
                "estimated_jitter_us": _merge_algorithm_summaries(
                    [item["estimated_jitter_from_nearest_nominal_us"] for item in directional]
                ),
                "scheduling_lateness_us": _merge_algorithm_summaries(
                    [item["scheduling_lateness_us"] for item in directional]
                ),
                "receive_credit_advertisement": {
                    "semantics": (
                        "complete local MAX_STREAM_DATA on-wire advertisement; this rearms "
                        "cadence but is not peer consumption"
                    ),
                    "advertised_cells": sum(
                        int(item["receive_credit_advertisement"]["advertised_cells"])
                        for item in directional
                    ),
                    "delay_us": _merge_algorithm_summaries(
                        [item["receive_credit_advertisement"]["delay_us"] for item in directional]
                    ),
                },
                "receive_credit_consumption": {
                    "semantics": (
                        "eventual peer stream-offset consumption; terminal and measured "
                        "separately from allocation and local advertisement"
                    ),
                    "consumed_cells": sum(
                        int(item["receive_credit_consumption"]["consumed_cells"])
                        for item in directional
                    ),
                    "delay_us": _merge_algorithm_summaries(
                        [item["receive_credit_consumption"]["delay_us"] for item in directional]
                    ),
                },
                "inferred_rate_transition_count": sum(
                    len(item["inferred_nearest_nominal_transitions"]) for item in directional
                ),
                "inferred_rate_transition_histogram": dict(sorted(transition_histogram.items())),
                "cs_buflo": (
                    {
                        "padding_variants": variants,
                        "rate_adaptations": sum(int(item["rate_adaptations"]) for item in cs_rows),
                        "explicit_rate_transition_count": sum(
                            len(item["rate_transitions"]) for item in cs_rows
                        ),
                        "explicit_rate_transition_histogram": dict(
                            sorted(explicit_transition_histogram.items())
                        ),
                        "retained_on_empty_transition_count": sum(
                            transition["retained_current_interval"] is True
                            for item in cs_rows
                            for transition in item["rate_transitions"]
                        ),
                        "terminal_interval_histogram_us": dict(
                            sorted(
                                Counter(
                                    str(item["terminal_interval_us"]) for item in cs_rows
                                ).items()
                            )
                        ),
                        "padding_target_bytes": _numeric_quantiles(
                            [int(item["padding_target_bytes"]) for item in cs_rows]
                        ),
                        "next_adaptation_boundary_bytes": _numeric_quantiles(
                            [int(item["next_adaptation_boundary_bytes"]) for item in cs_rows]
                        ),
                        "estimator_samples": _numeric_quantiles(
                            [int(item["estimator_samples"]) for item in cs_rows]
                        ),
                        "power_of_two_crossed": sum(
                            item["power_of_two_crossed"] is True for item in cs_rows
                        ),
                        "termination_stop_evidence": (
                            {
                                "available": True,
                                "schema_version": 4,
                                "samples_with_evidence": len(cs_v4_rows),
                                "historical_samples_without_evidence": (
                                    len(cs_rows) - len(cs_v4_rows)
                                ),
                                "latched": sum(
                                    item["termination_stop_latched"] is True for item in cs_v4_rows
                                ),
                                "reason_counts": dict(
                                    sorted(
                                        Counter(
                                            str(item["termination_stop_reason"])
                                            for item in cs_v4_rows
                                        ).items()
                                    )
                                ),
                                "phase_counts": dict(
                                    sorted(
                                        Counter(
                                            str(item["termination_stop_phase"])
                                            for item in cs_v4_rows
                                        ).items()
                                    )
                                ),
                                "crossing_samples": sum(
                                    int(item["termination_stop_crossing_total_bytes"]) > 0
                                    for item in cs_v4_rows
                                ),
                                "crossing_total_bytes": (
                                    _numeric_quantiles(
                                        [
                                            int(item["termination_stop_crossing_total_bytes"])
                                            for item in cs_v4_rows
                                            if int(item["termination_stop_crossing_total_bytes"])
                                            > 0
                                        ]
                                    )
                                    if any(
                                        int(item["termination_stop_crossing_total_bytes"]) > 0
                                        for item in cs_v4_rows
                                    )
                                    else None
                                ),
                                "drained_cells_after_stop": _numeric_quantiles(
                                    [
                                        int(item["stop_drain_ledger"]["drained_cells_after_stop"])
                                        for item in cs_v4_rows
                                    ]
                                ),
                            }
                            if cs_v4_rows
                            else {
                                "available": False,
                                "schema_version": None,
                                "samples_with_evidence": 0,
                                "historical_samples_without_evidence": len(cs_rows),
                            }
                        ),
                        "minimum_interval_opportunities": sum(
                            int(item["minimum_interval_opportunities"]) for item in cs_rows
                        ),
                        "minimum_interval_terminal": sum(
                            int(item["minimum_interval_terminal"]) for item in cs_rows
                        ),
                        "minimum_interval_full": sum(
                            int(item["minimum_interval_full"]) for item in cs_rows
                        ),
                        "minimum_interval_local_realized": (
                            sum(int(item["minimum_interval_local_realized"]) for item in cs_rows)
                            if direction == "incoming"
                            else None
                        ),
                        "incoming_local_realized_cells": (
                            sum(int(item["incoming_local_realized_cells"]) for item in cs_rows)
                            if direction == "incoming"
                            else None
                        ),
                    }
                    if cs_rows
                    else None
                ),
            }
        )
    terminal_tail_rows = [
        {
            "defense": defense,
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": len(group),
            "samples_with_cancellation": sum(
                int(item["stream_cancellations"]) > 0 for item in group
            ),
            "terminal_subcell_policy": sorted(
                {str(item["terminal_subcell_policy"]) for item in group}
            ),
            "terminal_subcell_observer_effect": sorted(
                {str(item["terminal_subcell_observer_effect"]) for item in group}
            ),
            "control_evidence_semantics": sorted(
                {str(item["control_evidence_semantics"]) for item in group}
            ),
            "stream_cancellations": sum(int(item["stream_cancellations"]) for item in group),
            "receipt_cancellations": sum(int(item["receipt_cancellations"]) for item in group),
            "typed_cancellation_action_events": sum(
                int(item["typed_cancellation_action_events"]) for item in group
            ),
            "pending_request_cancellations": sum(
                int(item["pending_request_cancellations"]) for item in group
            ),
            "open_streams_at_latch": sum(int(item["open_streams_at_latch"]) for item in group),
            "parser_lease_bytes_at_latch": sum(
                int(item["parser_lease_bytes_at_latch"]) for item in group
            ),
            "pending_parser_boundaries_at_latch": sum(
                int(item["pending_parser_boundaries_at_latch"]) for item in group
            ),
            **(
                {
                    "pending_application_parser_boundaries_at_latch": sum(
                        int(item["pending_application_parser_boundaries_at_latch"])
                        for item in group
                    )
                }
                if all("pending_application_parser_boundaries_at_latch" in item for item in group)
                else {}
            ),
            "exact_capacity_bytes_cancelled": {
                "total": sum(int(item["exact_capacity_bytes_cancelled"]) for item in group),
                "minimum": min(int(item["exact_capacity_bytes_cancelled"]) for item in group),
                "maximum": max(int(item["exact_capacity_bytes_cancelled"]) for item in group),
                **_numeric_quantiles(
                    [int(item["exact_capacity_bytes_cancelled"]) for item in group]
                ),
            },
            "terminal_latched_at_us": _numeric_quantiles(
                [int(item["terminal_latched_at_us"]) for item in group]
            ),
            "post_cancellation_unscheduled_defense_control_packets": sum(
                int(item["post_cancellation_unscheduled_defense_control_packets"]) for item in group
            ),
            "post_cancellation_unscheduled_defense_control_bytes": sum(
                int(item["post_cancellation_unscheduled_defense_control_bytes"]) for item in group
            ),
        }
        for (defense, workload, block), group in sorted(terminal_tail_groups.items())
    ]

    def ranged_quantiles(values: Sequence[int]) -> dict[str, int | float]:
        return {
            "minimum": min(values),
            "maximum": max(values),
            **_numeric_quantiles(values),
        }

    schedule_stop_rows = []
    for (defense, workload, block), group in sorted(schedule_stop_groups.items()):
        direction_rows: dict[str, Any] = {}
        for direction in ("outgoing", "incoming"):
            states = [item["directions"][direction] for item in group]
            direction_rows[direction] = {
                **{
                    field: sum(int(item[field]) for item in states)
                    for field in (
                        "scheduled_cells_at_stop",
                        "terminal_cells_at_stop",
                        "drained_cells_after_stop",
                        "terminal_cells_strictly_before_stop",
                        "terminal_cells_at_or_before_stop",
                        "terminal_cells_at_stop_timestamp",
                    )
                },
                "last_scheduled_target_us": ranged_quantiles(
                    [int(item["last_scheduled_target_us"]) for item in states]
                ),
                "last_terminal_at_us": ranged_quantiles(
                    [int(item["last_terminal_at_us"]) for item in states]
                ),
            }
        available = [int(item["available_bytes"]) for item in group]
        incoming_drains = [
            int(item["directions"]["incoming"]["drained_cells_after_stop"])
            for item in group
        ]
        schedule_stop_rows.append(
            {
                "defense": defense,
                "workload_id": workload,
                "acquisition_block_index": block,
                "samples": len(group),
                "policy": sorted({str(item["policy"]) for item in group}),
                "terminal_time_semantics": sorted(
                    {str(item["terminal_time_semantics"]) for item in group}
                ),
                "latched_samples": sum(item["latched"] is True for item in group),
                "latched_at_us": ranged_quantiles(
                    [int(item["latched_at_us"]) for item in group]
                ),
                "available_bytes": {
                    "total": sum(available),
                    **ranged_quantiles(available),
                },
                "required_bytes": sorted({int(item["required_bytes"]) for item in group}),
                "samples_with_incoming_drain": sum(value > 0 for value in incoming_drains),
                "directions": direction_rows,
            }
        )
    cs_local_et_rows = [
        {
            "defense": defense,
            "workload_id": workload,
            "acquisition_block_index": block,
            "samples": len(group),
            "before_application_complete_samples": sum(
                item["before_application_complete"] is True for item in group
            ),
            "latched_at_us": _numeric_quantiles([int(item["latched_at_us"]) for item in group]),
            **{
                field: sum(int(item[field]) for item in group)
                for field in (
                    "pending_request_cancellations",
                    "stream_cancellations",
                    "application_receive_streams_handed_off",
                    "application_parser_boundaries_handed_off",
                    "application_parser_lease_bytes_handed_off",
                    "application_send_endpoints_released",
                    "post_local_et_natural_outgoing_bytes",
                    "post_local_et_natural_incoming_bytes",
                )
            },
        }
        for (defense, workload, block), group in sorted(cs_local_et_groups.items())
    ]
    result = {
        "available": True,
        "classifier_input": False,
        "strata": rows,
        "buflo_terminal_tail_strata": terminal_tail_rows,
    }
    if schedule_stop_rows:
        result["buflo_schedule_stop_strata"] = schedule_stop_rows
    if diagnostic_versions & {3, 4}:
        result["schema_version"] = 3 if 4 in diagnostic_versions else 2
        result["cs_buflo_local_termination_strata"] = cs_local_et_rows
    return result


def _merge_algorithm_summaries(values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    populated = [value for value in values if int(value["count"]) > 0]
    count = sum(int(value["count"]) for value in populated)
    if not count:
        return {
            "count": 0,
            "minimum": None,
            "maximum": None,
            "weighted_mean": None,
            "sample_p50_range": None,
            "sample_p95_range": None,
        }
    return {
        "count": count,
        "minimum": min(int(value["minimum"]) for value in populated),
        "maximum": max(int(value["maximum"]) for value in populated),
        "weighted_mean": sum(float(value["mean"]) * int(value["count"]) for value in populated)
        / count,
        "sample_p50_range": {
            "minimum": min(int(value["p50"]) for value in populated),
            "maximum": max(int(value["p50"]) for value in populated),
        },
        "sample_p95_range": {
            "minimum": min(int(value["p95"]) for value in populated),
            "maximum": max(int(value["p95"]) for value in populated),
        },
    }


def _summarize_resource_usage(values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in (
        "user_cpu_seconds",
        "system_cpu_seconds",
        "wall_time_seconds",
        "maximum_rss_bytes",
        "voluntary_context_switches",
        "involuntary_context_switches",
    ):
        observations = np.asarray([float(value[key]) for value in values], dtype=np.float64)
        result[key] = {
            "mean": float(np.mean(observations)),
            "p50": float(np.quantile(observations, 0.50)),
            "p90": float(np.quantile(observations, 0.90)),
            "p95": float(np.quantile(observations, 0.95)),
        }
    for metric, reason in (
        ("timer_wakeups", "timer_wakeups_unavailable_reason"),
        ("rapl_energy_joules", "rapl_unavailable_reason"),
    ):
        available = [value[metric] for value in values if value[metric] is not None]
        result[metric] = (
            {
                "available": True,
                "mean": float(np.mean(np.asarray(available, dtype=np.float64))),
            }
            if len(available) == len(values)
            else {
                "available": False,
                "reasons": sorted(
                    {str(value[reason]) for value in values if value[metric] is None}
                ),
            }
        )
    return result


def summarize_paired_overheads(
    rows: Sequence[Mapping[str, Any]],
    *,
    bootstrap_draws: int = 10_000,
    seed: int = 20260827,
) -> dict[str, dict[str, Any]]:
    """Summarize paired overhead with block/workload-cluster bootstrap CIs."""

    by_defense: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_defense[str(row["defense"])].append(row)
    result: dict[str, dict[str, Any]] = {}
    for defense, defense_rows in sorted(by_defense.items()):
        wire_ratio = ratio_of_sums(
            (float(row["defended_wire_bytes"]) for row in defense_rows),
            (float(row["baseline_wire_bytes"]) for row in defense_rows),
        )
        duration_ratio = ratio_of_sums(
            (float(row["defended_duration_ns"]) for row in defense_rows),
            (float(row["baseline_duration_ns"]) for row in defense_rows),
        )
        result[defense] = {
            "pairs": len(defense_rows),
            "wire_ratio_of_sums": wire_ratio,
            "additional_wire_percent": 100.0 * (wire_ratio - 1.0),
            "duration_ratio_of_sums": duration_ratio,
            "wire_ratio_pair_quantiles": _quantiles(defense_rows, "wire_ratio"),
            "duration_ratio_pair_quantiles": _quantiles(defense_rows, "duration_ratio"),
            "added_seconds_pair_quantiles": _quantiles(defense_rows, "added_duration_seconds"),
            "wire_ratio_bootstrap_95": _cluster_bootstrap_ratio(
                defense_rows,
                numerator="defended_wire_bytes",
                denominator="baseline_wire_bytes",
                draws=bootstrap_draws,
                seed=seed,
            ),
            "duration_ratio_bootstrap_95": _cluster_bootstrap_ratio(
                defense_rows,
                numerator="defended_duration_ns",
                denominator="baseline_duration_ns",
                draws=bootstrap_draws,
                seed=seed ^ 0xC5B0F10,
            ),
        }
        _add_optional_performance_summary(result[defense], defense_rows)
    return result


def panchenko_features(trace: Sequence[ShapePacket]) -> dict[str, float]:
    """Clean-room Panchenko feature map using observer frame lengths."""

    if not trace:
        return {}
    features: Counter[str] = Counter()
    for packet in trace:
        features[f"packet/{packet.direction}/{packet.length_bytes}"] += 1
    for direction, burst in _direction_bursts(trace):
        burst_bytes = sum(packet.length_bytes for packet in burst)
        features[f"burst-bytes/{direction}/{_round_to(burst_bytes, 600)}"] += 1
        features[f"burst-count/{direction}/{_panchenko_count_marker(len(burst))}"] += 1

    outgoing_seen = 0
    incoming_seen = 0
    initial_incoming_bytes = 0
    for packet in trace:
        if packet.direction == "outgoing":
            outgoing_seen += 1
            if outgoing_seen > 1 and incoming_seen > 0:
                break
        else:
            incoming_seen += 1
            initial_incoming_bytes += packet.length_bytes
    features[f"html/{_round_to(initial_incoming_bytes, 600)}"] = 1

    directions = ("outgoing", "incoming")
    for direction in directions:
        selected = [packet for packet in trace if packet.direction == direction]
        features[f"unique-sizes/{direction}"] = _round_to(
            len({packet.length_bytes for packet in selected}), 2
        )
        features[f"percentage/{direction}"] = _round_to(100 * len(selected) / len(trace), 5)
        features[f"packet-count/{direction}"] = _round_to(len(selected), 15)
        total = sum(packet.length_bytes for packet in selected)
        features[f"bandwidth/{direction}/{_round_to(total, 10_000)}"] = 1
    return {key: float(value) for key, value in features.items()}


def vngpp_features(trace: Sequence[ShapePacket]) -> dict[str, float]:
    """Clean-room VNG++ feature map using directional burst markers."""

    features: Counter[str] = Counter()
    for direction, burst in _direction_bursts(trace):
        burst_bytes = sum(packet.length_bytes for packet in burst)
        features[f"burst-bytes/{direction}/{_round_to(burst_bytes, 600)}"] += 1
    for direction in ("outgoing", "incoming"):
        features[f"bandwidth/{direction}"] = sum(
            packet.length_bytes for packet in trace if packet.direction == direction
        )
    # The pinned input parser rounds every capture-relative timestamp to an
    # integer millisecond before constructing the author's Packet, and VNG++
    # then takes the maximum Packet time.  Preserve that ordering instead of
    # exposing a fractional millisecond feature to Weka.
    features["duration-ms"] = (
        max(_author_packet_time_ms(packet.relative_time_ns) for packet in trace) if trace else 0
    )
    return {key: float(value) for key, value in features.items()}


def dlsvm_sequence(trace: Sequence[ShapePacket]) -> tuple[int, ...]:
    """Return the QUIC observer adaptation of DLSVM's signed packet string.

    TCP/Tor-specific fixed-size ACK deletion is intentionally absent: QUIC ACK
    frames are encrypted and do not have a stable observer-frame length.
    """

    return tuple(packet.signed_length_bytes for packet in trace)


def damerau_levenshtein_distance(
    left: Sequence[int],
    right: Sequence[int],
    *,
    insertion_cost: float = 2.0,
    deletion_cost: float = 2.0,
    substitution_cost: float = 2.0,
    transposition_cost: float = 0.1,
) -> float:
    """Restricted OSA distance with the CCS'12 DLSVM operation costs."""

    costs = (insertion_cost, deletion_cost, substitution_cost, transposition_cost)
    if any(not math.isfinite(cost) or cost <= 0 for cost in costs):
        raise ValueError("edit operation costs must be finite and positive")
    if not left:
        return insertion_cost * len(right)
    if not right:
        return deletion_cost * len(left)
    previous_previous: list[float] | None = None
    previous = [insertion_cost * index for index in range(len(right) + 1)]
    for left_index, left_value in enumerate(left, 1):
        current = [deletion_cost * left_index] + [0.0] * len(right)
        for right_index, right_value in enumerate(right, 1):
            substitution = 0.0 if left_value == right_value else substitution_cost
            value = min(
                previous[right_index] + deletion_cost,
                current[right_index - 1] + insertion_cost,
                previous[right_index - 1] + substitution,
            )
            if (
                previous_previous is not None
                and left_index > 1
                and right_index > 1
                and left_value == right[right_index - 2]
                and left[left_index - 2] == right_value
            ):
                value = min(value, previous_previous[right_index - 2] + transposition_cost)
            current[right_index] = value
        previous_previous, previous = previous, current
    return previous[-1]


def normalized_dlsvm_distance(left: Sequence[int], right: Sequence[int]) -> float:
    """Normalize DLSVM distance by the shorter non-empty trace length."""

    left_tuple = _dlsvm_value_tuple(left)
    right_tuple = _dlsvm_value_tuple(right)
    if right_tuple < left_tuple:
        left_tuple, right_tuple = right_tuple, left_tuple
    return _cached_normalized_dlsvm_distance(left_tuple, right_tuple)


def _dlsvm_value_tuple(value: Sequence[int]) -> tuple[int, ...]:
    result = tuple(value)
    if any(type(item) is not int or not -(2**31) <= item < 2**31 for item in result):
        raise ValueError("DLSVM symbols must be signed 32-bit integers")
    return result


@cache
def _cached_normalized_dlsvm_distance(left: tuple[int, ...], right: tuple[int, ...]) -> float:
    if not left and not right:
        return 0.0
    denominator = min(len(left), len(right))
    if denominator == 0:
        return damerau_levenshtein_distance(left, right)
    loaded = _load_osad_library()
    distance = (
        _native_osad_distance(loaded[0], left, right)
        if loaded is not None
        else damerau_levenshtein_distance(left, right)
    )
    return distance / denominator


@lru_cache(maxsize=1)
def _load_osad_library() -> tuple[ctypes.CDLL, Path] | None:
    configured = os.environ.get("QCSD_OSAD_LIBRARY")
    path = Path(configured).resolve() if configured else _DEFAULT_OSAD_LIBRARY
    return _load_osad_library_path(path, required=bool(configured))


def _load_osad_library_path(
    path: Path,
    *,
    required: bool,
) -> tuple[ctypes.CDLL, Path] | None:
    path = Path(path).resolve()
    if path.is_symlink() or not path.is_file():
        if required:
            raise RuntimeError(f"required QCSD OSA accelerator is unavailable: {path}")
        return None
    library = ctypes.CDLL(os.fspath(path))
    function = library.qcsd_osad_distance
    function.argtypes = (
        ctypes.POINTER(ctypes.c_int32),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int32),
        ctypes.c_size_t,
    )
    function.restype = ctypes.c_double
    return library, path


@cache
def _native_osad_values(value: tuple[int, ...]) -> Any:
    return (ctypes.c_int32 * len(value))(*value)


def _native_osad_distance(
    library: ctypes.CDLL, left: tuple[int, ...], right: tuple[int, ...]
) -> float:
    result = float(
        library.qcsd_osad_distance(
            _native_osad_values(left),
            len(left),
            _native_osad_values(right),
            len(right),
        )
    )
    if not math.isfinite(result) or result < 0:
        raise RuntimeError("native QCSD OSA accelerator failed")
    return result


def dlsvm_backend_receipt(
    *,
    formal: bool = False,
    trusted_runtime: TrustedClassifierRuntime | None = None,
) -> dict[str, Any]:
    """Describe and hash the exact clean-room DLSVM backend in use."""

    approved_runtime = None
    if formal:
        _reject_formal_runtime_overrides()
        runtime = trusted_runtime or _PRODUCTION_CLASSIFIER_RUNTIME
        approved_runtime = _validate_trusted_classifier_runtime(runtime)
        loaded = _load_osad_library_path(runtime.osad_library, required=True)
    else:
        if trusted_runtime is not None:
            raise ValueError("trusted classifier runtime is a formal-only test seam")
        loaded = _load_osad_library()
    try:
        import sklearn.svm._libsvm as sklearn_libsvm
    except ImportError as error:
        raise RuntimeError("DLSVM requires the pinned scikit-learn LIBSVM backend") from error
    libsvm_path = Path(str(sklearn_libsvm.__file__)).resolve()
    if libsvm_path.is_symlink() or not libsvm_path.is_file():
        raise RuntimeError("DLSVM scikit-learn LIBSVM module is not a regular file")
    result: dict[str, Any] = {
        "schema_version": 1,
        "algorithm": "restricted-optimal-string-alignment",
        "costs": {
            "insertion": 2.0,
            "deletion": 2.0,
            "substitution": 2.0,
            "adjacent_transposition": 0.1,
        },
        "normalization": "distance/minimum-nonempty-trace-length",
        "kernel": "exp(-(normalized_distance**2))",
        "svm_c": 4,
        "engine": "clean-room-native-c" if loaded is not None else "clean-room-python",
        "runtime": {
            "numpy_version": importlib.metadata.version("numpy"),
            "scikit_learn_version": importlib.metadata.version("scikit-learn"),
            "libsvm_implementation": "scikit-learn-bundled-libsvm",
            "libsvm_module_path": str(libsvm_path),
            "libsvm_module_sha256": sha256_file(libsvm_path),
        },
        "reference": dlsvm_reference_receipt(),
    }
    if loaded is not None:
        result["native_library"] = {
            "path": str(loaded[1]),
            "sha256": sha256_file(loaded[1]),
        }
    if approved_runtime is not None:
        result["approved_runtime"] = approved_runtime
    return result


def dlsvm_reference_receipt() -> dict[str, str]:
    """Fail closed unless the DLSVM specification and receipt are byte-exact."""

    expected = (
        (_DLSVM_REFERENCE, _DLSVM_REFERENCE_SHA256),
        (_DLSVM_REFERENCE_RECEIPT, _DLSVM_REFERENCE_RECEIPT_SHA256),
    )
    for path, digest in expected:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"DLSVM primary-reference evidence is unavailable: {path}")
        observed = sha256_file(path)
        if observed != digest:
            raise RuntimeError(
                f"DLSVM primary-reference hash mismatch for {path}: "
                f"expected {digest}, observed {observed}"
            )
    value = load_json(_DLSVM_REFERENCE_RECEIPT)
    if (
        not isinstance(value, Mapping)
        or value.get("reference_id") != "dlsvm-ccs-2012-v1"
        or not isinstance(value.get("reference_file"), Mapping)
        or value["reference_file"].get("sha256") != _DLSVM_REFERENCE_SHA256
    ):
        raise RuntimeError("DLSVM primary-reference receipt semantics are invalid")
    return {
        "path": str(_DLSVM_REFERENCE),
        "sha256": _DLSVM_REFERENCE_SHA256,
        "receipt_path": str(_DLSVM_REFERENCE_RECEIPT),
        "receipt_sha256": _DLSVM_REFERENCE_RECEIPT_SHA256,
    }


def _reject_formal_runtime_overrides() -> None:
    configured = [name for name in _FORMAL_RUNTIME_OVERRIDE_ENV if name in os.environ]
    if configured:
        raise RuntimeError(
            "formal classifier evaluation forbids runtime path overrides: " + ", ".join(configured)
        )


def _classifier_runtime_payload_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("payload_sha256", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(_CLASSIFIER_RUNTIME_DOMAIN.encode("utf-8") + b"\0" + encoded).hexdigest()


def _package_versions(names: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in names:
        if (
            not isinstance(name, str)
            or not name
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789+.-" for character in name)
        ):
            raise RuntimeError("classifier runtime receipt has an invalid package name")
        completed = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        version = completed.stdout.strip()
        if completed.returncode != 0 or not version:
            raise RuntimeError(f"classifier runtime package is unavailable: {name}")
        result[name] = version
    return result


def _owning_debian_package(path: Path) -> str:
    completed = subprocess.run(
        ["dpkg-query", "-S", str(Path(path).resolve())],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError(f"classifier runtime binary has no package owner: {path}")
    return completed.stdout.splitlines()[0].split(":", 1)[0].split(",", 1)[0]


def _java_version(java: Path) -> str:
    completed = subprocess.run(
        [str(java), "-version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError("Java runtime failed while validating classifier provenance")
    value = (completed.stderr or completed.stdout).strip()
    if not value:
        raise RuntimeError("Java runtime returned no version identity")
    return value


def _validate_trusted_classifier_runtime(
    runtime: TrustedClassifierRuntime,
) -> dict[str, str]:
    receipt_path = Path(runtime.receipt).resolve()
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RuntimeError(f"approved classifier runtime receipt is unavailable: {receipt_path}")
    try:
        value = load_json(receipt_path)
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError("approved classifier runtime receipt is invalid") from error
    required_keys = {
        "schema_version",
        "artifact_type",
        "domain",
        "source",
        "build_inputs",
        "osad",
        "java",
        "weka",
        "payload_sha256",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != required_keys
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-classifier-runtime-build"
        or value.get("domain") != _CLASSIFIER_RUNTIME_DOMAIN
        or value.get("payload_sha256") != _classifier_runtime_payload_sha256(value)
    ):
        raise RuntimeError("approved classifier runtime receipt identity is invalid")

    source = value.get("source")
    current_source = source_metadata()
    if (
        not isinstance(source, Mapping)
        or set(source) != set(current_source)
        or any(
            source.get(key) != current_source.get(key)
            for key in current_source
            if key != "image_digest"
        )
    ):
        raise RuntimeError("approved classifier runtime source differs from evaluator source")
    build_inputs = value.get("build_inputs")
    if (
        not isinstance(build_inputs, Mapping)
        or set(build_inputs)
        != {
            "schema_version",
            "artifact_type",
            "cargo_lock_sha256",
            "debian_base_image",
            "rust_base_image",
            "uv_lock_sha256",
        }
        or build_inputs.get("schema_version") != 1
        or build_inputs.get("artifact_type") != "qcsd-study-build-inputs"
        or build_inputs.get("debian_base_image") != _DEBIAN_BASE_IMAGE
        or any(
            not isinstance(build_inputs.get(key), str) or len(str(build_inputs[key])) != 64
            for key in ("cargo_lock_sha256", "uv_lock_sha256")
        )
        or not isinstance(build_inputs.get("rust_base_image"), str)
        or "@sha256:" not in str(build_inputs["rust_base_image"])
    ):
        raise RuntimeError("approved classifier runtime build inputs are invalid")

    osad = value.get("osad")
    osad_source = osad.get("source") if isinstance(osad, Mapping) else None
    osad_compiler = osad.get("compiler") if isinstance(osad, Mapping) else None
    osad_library = osad.get("library") if isinstance(osad, Mapping) else None
    osad_source_path = LAB_ROOT / "tools/qcsd_osad.c"
    library_path = Path(runtime.osad_library).resolve()
    if (
        not isinstance(osad, Mapping)
        or set(osad) != {"source", "compiler", "build_command", "library"}
        or osad_source != {"path": "tools/qcsd_osad.c", "sha256": _OSAD_SOURCE_SHA256}
        or osad_source_path.is_symlink()
        or not osad_source_path.is_file()
        or sha256_file(osad_source_path) != _OSAD_SOURCE_SHA256
        or osad.get("build_command") != list(_OSAD_BUILD_COMMAND)
        or not isinstance(osad_compiler, Mapping)
        or set(osad_compiler) != {"path", "sha256", "version", "packages"}
        or not isinstance(osad_compiler.get("path"), str)
        or not isinstance(osad_compiler.get("sha256"), str)
        or len(osad_compiler["sha256"]) != 64
        or not isinstance(osad_compiler.get("version"), str)
        or not osad_compiler["version"]
        or not isinstance(osad_compiler.get("packages"), Mapping)
        or set(osad_compiler["packages"]) != {"gcc", "libc6-dev"}
        or any(
            not isinstance(version, str) or not version
            for version in osad_compiler["packages"].values()
        )
        or not isinstance(osad_library, Mapping)
        or osad_library != {"path": str(library_path), "sha256": sha256_file(library_path)}
    ):
        raise RuntimeError("approved OSAD build or binary receipt is invalid")

    java = value.get("java")
    declared_java = Path(runtime.java_executable)
    resolved_java = declared_java.resolve()
    if (
        not isinstance(java, Mapping)
        or set(java)
        != {
            "declared_path",
            "resolved_path",
            "sha256",
            "version",
            "packages",
        }
        or java.get("declared_path") != str(declared_java)
        or java.get("resolved_path") != str(resolved_java)
        or resolved_java.is_symlink()
        or not resolved_java.is_file()
        or java.get("sha256") != sha256_file(resolved_java)
        or java.get("version") != _java_version(resolved_java)
        or not isinstance(java.get("packages"), Mapping)
        or set(java["packages"]) != {"default-jre-headless", _owning_debian_package(resolved_java)}
        or dict(java["packages"]) != _package_versions(tuple(sorted(java["packages"])))
    ):
        raise RuntimeError("approved Java package or executable receipt is invalid")

    weka = value.get("weka")
    expected_artifacts = {
        name: {
            "path": str(Path(runtime.weka_directory).resolve() / name),
            "sha256": digest,
        }
        for name, digest in sorted(runtime.weka_artifacts.items())
    }
    if (
        not isinstance(weka, Mapping)
        or set(weka) != {"directory", "artifacts"}
        or weka.get("directory") != str(Path(runtime.weka_directory).resolve())
        or weka.get("artifacts") != expected_artifacts
    ):
        raise RuntimeError("approved Weka artifact receipt is invalid")
    for artifact in expected_artifacts.values():
        artifact_path = Path(artifact["path"])
        if (
            artifact_path.is_symlink()
            or not artifact_path.is_file()
            or sha256_file(artifact_path) != artifact["sha256"]
        ):
            raise RuntimeError("approved Weka artifact bytes are unavailable")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": str(value["payload_sha256"]),
        "artifact_type": "qcsd-classifier-runtime-build",
    }


@lru_cache(maxsize=1)
def _load_weka_backend() -> WekaBackend | None:
    """Resolve Weka only when every pinned byte is present and hash-correct."""

    configured_directory = os.environ.get("QCSD_WEKA_DIRECTORY")
    directory = (
        Path(configured_directory).resolve() if configured_directory else _DEFAULT_WEKA_DIRECTORY
    )
    configured_java = os.environ.get("QCSD_JAVA")
    java_candidate = configured_java or shutil.which("java")
    artifact_paths = tuple(directory / name for name in _WEKA_ARTIFACTS)
    missing = [path for path in artifact_paths if not path.is_file() or path.is_symlink()]
    if java_candidate is None or missing:
        if configured_directory or configured_java:
            details = []
            if java_candidate is None:
                details.append("Java runtime unavailable")
            if missing:
                details.append("missing artifacts: " + ", ".join(str(path) for path in missing))
            raise RuntimeError(
                "configured VNG++ Weka backend is unavailable: " + "; ".join(details)
            )
        return None
    java = Path(java_candidate).resolve()
    if not java.is_file():
        if configured_java:
            raise RuntimeError(f"configured Java runtime is unavailable: {java}")
        return None
    for path in artifact_paths:
        observed = sha256_file(path)
        expected = _WEKA_ARTIFACTS[path.name]
        if observed != expected:
            raise RuntimeError(
                f"VNG++ Weka artifact hash mismatch for {path}: "
                f"expected {expected}, observed {observed}"
            )
    return WekaBackend(java=java, artifacts=artifact_paths)


def vngpp_backend_receipt(
    *,
    formal: bool = False,
    trusted_runtime: TrustedClassifierRuntime | None = None,
) -> dict[str, Any]:
    """Describe the exact VNG++ feature and classifier implementation in use."""

    approved_runtime = None
    if formal:
        _reject_formal_runtime_overrides()
        runtime = trusted_runtime or _PRODUCTION_CLASSIFIER_RUNTIME
        approved_runtime = _validate_trusted_classifier_runtime(runtime)
        backend = WekaBackend(
            java=Path(runtime.java_executable).resolve(),
            artifacts=tuple(
                Path(runtime.weka_directory).resolve() / name for name in runtime.weka_artifacts
            ),
        )
    else:
        if trusted_runtime is not None:
            raise ValueError("trusted classifier runtime is a formal-only test seam")
        backend = _load_weka_backend()
    reference = classifier_reference_receipt()
    result: dict[str, Any] = {
        "schema_version": 1,
        "feature_definition": "clean-room-dyer-sp-2012-vngplusplus",
        "rounding": "python2-round-half-away-from-zero-for-nonnegative-values",
        "feature_vocabulary": (
            "training-only; held-out feature names never enter model dimensionality"
        ),
        "classifier": "weka.classifiers.bayes.NaiveBayes -K",
        "backend": "pinned-weka-3.7.5" if backend is not None else "unavailable",
    }
    if backend is not None:
        result["runtime"] = {
            "java_path": str(backend.java),
            "java_sha256": sha256_file(backend.java),
            "java_version": _java_version(backend.java),
            "artifacts": [
                {"path": str(path), "sha256": sha256_file(path)} for path in backend.artifacts
            ],
        }
    if approved_runtime is not None:
        result["approved_runtime"] = approved_runtime
    result["reference"] = reference
    return result


def classifier_reference_receipt() -> dict[str, str]:
    """Fail closed unless the pinned Panchenko/VNG++ receipt is byte-exact."""

    expected = (
        (_CLASSIFIER_REFERENCE, _CLASSIFIER_REFERENCE_SHA256),
        (_CLASSIFIER_REFERENCE_RECEIPT, _CLASSIFIER_REFERENCE_RECEIPT_SHA256),
    )
    for path, digest in expected:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"classifier primary-reference evidence is unavailable: {path}")
        observed = sha256_file(path)
        if observed != digest:
            raise RuntimeError(
                f"classifier primary-reference hash mismatch for {path}: "
                f"expected {digest}, observed {observed}"
            )
    return {
        "reference_path": str(_CLASSIFIER_REFERENCE),
        "reference_sha256": _CLASSIFIER_REFERENCE_SHA256,
        "receipt_path": str(_CLASSIFIER_REFERENCE_RECEIPT),
        "receipt_sha256": _CLASSIFIER_REFERENCE_RECEIPT_SHA256,
    }


def _weka_vngpp_predict(
    training: Sequence[StudySample],
    testing: Sequence[StudySample],
    backend: WekaBackend,
) -> tuple[str, ...]:
    """Run the pinned Weka 3.7.5 ``NaiveBayes -K`` classifier offline."""

    training_features = [vngpp_features(sample.trace) for sample in training]
    testing_features = [vngpp_features(sample.trace) for sample in testing]
    feature_names = sorted({key for features in training_features for key in features})
    if not feature_names:
        feature_names = ["qcsd-constant-zero"]
    labels = sorted({sample.class_label for sample in training})
    if {sample.class_label for sample in testing} != set(labels):
        raise ValueError("VNG++ train/test class sets differ")
    label_to_arff = {label: f"c{index}" for index, label in enumerate(labels)}
    arff_to_label = {encoded: label for label, encoded in label_to_arff.items()}

    def arff_text(samples: Sequence[StudySample], features: Sequence[Mapping[str, float]]) -> str:
        header = ["@RELATION qcsd_vngplusplus"]
        header.extend(f"@ATTRIBUTE f{index} NUMERIC" for index in range(len(feature_names)))
        header.append("@ATTRIBUTE class {" + ",".join(arff_to_label) + "}")
        header.append("@DATA")
        rows = []
        for sample, values in zip(samples, features, strict=True):
            numeric = []
            for name in feature_names:
                value = float(values.get(name, 0.0))
                if not math.isfinite(value):
                    raise ValueError("VNG++ features must be finite")
                numeric.append(format(value, ".17g"))
            rows.append(",".join((*numeric, label_to_arff[sample.class_label])))
        return "\n".join((*header, *rows, ""))

    with tempfile.TemporaryDirectory(prefix="qcsd-vngpp-") as temporary:
        temporary_root = Path(temporary)
        training_path = temporary_root / "training.arff"
        testing_path = temporary_root / "testing.arff"
        training_path.write_text(arff_text(training, training_features), encoding="utf-8")
        testing_path.write_text(arff_text(testing, testing_features), encoding="utf-8")
        command = [
            str(backend.java),
            f"-Duser.home={temporary_root}",
            f"-Djava.io.tmpdir={temporary_root}",
            "-Dweka.packageManager.loadPackages=false",
            "-cp",
            backend.classpath,
            "weka.classifiers.bayes.NaiveBayes",
            "-K",
            "-t",
            str(training_path),
            "-T",
            str(testing_path),
            "-classifications",
            "weka.classifiers.evaluation.output.prediction.CSV",
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
            cwd=temporary_root,
            env={**os.environ, "HOME": str(temporary_root)},
        )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"pinned Weka VNG++ execution failed: {detail}")
    header = "inst#,actual,predicted,error,prediction"
    header_offset = completed.stdout.find(header)
    if header_offset < 0:
        raise RuntimeError("pinned Weka VNG++ output has no prediction table")
    reader = csv.DictReader(io.StringIO(completed.stdout[header_offset:]))
    predicted = []
    for row in reader:
        encoded = (row.get("predicted") or "").partition(":")[2]
        label = arff_to_label.get(encoded)
        if label is None:
            raise RuntimeError(f"pinned Weka VNG++ emitted an invalid prediction: {encoded!r}")
        predicted.append(label)
    if len(predicted) != len(testing):
        raise RuntimeError(
            "pinned Weka VNG++ prediction count mismatch: "
            f"expected {len(testing)}, observed {len(predicted)}"
        )
    return tuple(predicted)


def dlsvm_workload_census(samples: Sequence[StudySample]) -> dict[str, Any]:
    """Report the exact matrix-union upper bound before DLSVM execution."""

    by_defense: dict[str, list[StudySample]] = defaultdict(list)
    for sample in samples:
        by_defense[sample.defense].append(sample)
    within_rows = []
    total_pairs = 0
    total_cells = 0
    dense_matrix_elements = 0
    for defense, selected in sorted(by_defense.items()):
        lengths = [len(sample.trace) for sample in selected]
        length_sum = sum(lengths)
        pairs = len(lengths) * (len(lengths) + 1) // 2
        cells = (length_sum * length_sum + sum(length * length for length in lengths)) // 2
        total_pairs += pairs
        total_cells += cells
        dense_elements = len(lengths) * len(lengths)
        dense_matrix_elements += dense_elements
        within_rows.append(
            {
                "defense": defense,
                "samples": len(lengths),
                "trace_packets": {
                    "minimum": min(lengths),
                    "maximum": max(lengths),
                    "mean": float(np.mean(np.asarray(lengths, dtype=np.float64))),
                    **_numeric_quantiles(lengths),
                },
                "unique_pair_upper_bound": pairs,
                "dynamic_programming_cell_upper_bound": cells,
                "persisted_dense_matrix_elements": dense_elements,
            }
        )

    transfer_rows = []
    undefended_train = [
        sample
        for sample in by_defense.get("undefended", ())
        if sample.acquisition_block_index in TRAIN_BLOCKS
    ]
    undefended_lengths = [len(sample.trace) for sample in undefended_train]
    for split, block in (("validation", VALIDATION_BLOCK), ("heldout-test", TEST_BLOCK)):
        for defense in sorted(set(by_defense) - {"undefended"}):
            defended_test = [
                sample for sample in by_defense[defense] if sample.acquisition_block_index == block
            ]
            defended_lengths = [len(sample.trace) for sample in defended_test]
            pairs = len(undefended_lengths) * len(defended_lengths)
            cells = sum(undefended_lengths) * sum(defended_lengths)
            total_pairs += pairs
            total_cells += cells
            dense_elements = len(undefended_lengths) * len(defended_lengths)
            dense_matrix_elements += dense_elements
            transfer_rows.append(
                {
                    "split": split,
                    "training_defense": "undefended",
                    "testing_defense": defense,
                    "training_samples": len(undefended_lengths),
                    "testing_samples": len(defended_lengths),
                    "unique_pair_upper_bound": pairs,
                    "dynamic_programming_cell_upper_bound": cells,
                    "persisted_dense_matrix_elements": dense_elements,
                }
            )
    return {
        "schema_version": 1,
        "cache_scope": "all-temporal-and-historical-DLSVM-runs",
        "within_defense": within_rows,
        "undefended_transfer": transfer_rows,
        "unique_distance_calls_upper_bound": total_pairs,
        "dynamic_programming_cells_upper_bound": total_cells,
        "persisted_dense_matrix_elements": dense_matrix_elements,
        "persisted_dense_matrix_bytes": dense_matrix_elements * 8,
        "workers": _osad_workers() if _load_osad_library() is not None else 1,
        "duplicate_sequence_note": "identical signed-length sequences may reduce actual work",
    }


def _available_memory_bytes() -> int | None:
    path = Path("/proc/meminfo")
    if not path.is_file() or path.is_symlink():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            if len(fields) == 3 and fields[1].isdecimal() and fields[2] == "kB":
                return int(fields[1]) * 1_024
    return None


def _configured_dlsvm_wall_seconds(override: float | None = None) -> float | None:
    value: Any = override
    if value is None:
        value = os.environ.get("QCSD_DLSVM_AVAILABLE_WALL_SECONDS")
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError("QCSD_DLSVM_AVAILABLE_WALL_SECONDS must be numeric") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError("QCSD_DLSVM_AVAILABLE_WALL_SECONDS must be positive")
    return parsed


def dlsvm_preflight_benchmark(
    samples: Sequence[StudySample],
    *,
    handoff_root: Path,
    available_wall_seconds: float | None = None,
) -> dict[str, Any]:
    """Measure the exact native OSA engine and project the sealed cohort workload."""

    loaded = _load_osad_library()
    if loaded is None:
        raise RuntimeError("DLSVM preflight requires the clean-room native OSA backend")
    lengths = sorted(len(sample.trace) for sample in samples)
    if not lengths:
        raise ValueError("DLSVM preflight requires non-empty traces")
    positions = (0, len(lengths) // 2, math.ceil(len(lengths) * 0.95) - 1, len(lengths) - 1)
    actual_representatives = sorted({lengths[index] for index in positions})
    executed_lengths = sorted({max(1, min(length, 12_000)) for length in actual_representatives})
    measurements = []
    for length in executed_lengths:
        left = tuple(600 if index % 2 == 0 else -600 for index in range(length))
        right = tuple(1_200 if index % 3 == 0 else -600 for index in range(length))
        started = time.perf_counter_ns()
        value = _native_osad_distance(loaded[0], left, right)
        elapsed_ns = time.perf_counter_ns() - started
        if elapsed_ns <= 0:
            raise RuntimeError("DLSVM preflight benchmark clock did not advance")
        seconds = elapsed_ns / 1_000_000_000
        cells = length * length
        measurements.append(
            {
                "trace_length": length,
                "dynamic_programming_cells": cells,
                "elapsed_seconds": seconds,
                "pairs_per_second": 1.0 / seconds,
                "cells_per_second": cells / seconds,
                "distance": value,
            }
        )
    census = dlsvm_workload_census(samples)
    conservative_cells_per_second = min(
        float(measurement["cells_per_second"]) for measurement in measurements
    )
    workers = int(census["workers"])
    worker_efficiency = 0.65
    safety_factor = 2.0
    projected_wall_seconds = (
        float(census["dynamic_programming_cells_upper_bound"])
        / (conservative_cells_per_second * workers * worker_efficiency)
        * safety_factor
    )
    projected_matrix_bytes = int(census["persisted_dense_matrix_bytes"])
    maximum_trace = max(lengths)
    projected_working_bytes = maximum_trace * 3 * 8 * workers
    projected_memory_bytes = projected_matrix_bytes + projected_working_bytes
    available_memory = _available_memory_bytes()
    available_wall = _configured_dlsvm_wall_seconds(available_wall_seconds)
    handoff_root = handoff_root.resolve()
    binding = {
        "sha256sums_sha256": _sha256_file(handoff_root / "SHA256SUMS"),
        "dataset_sha256": _sha256_file(handoff_root / "dataset.json"),
        "samples_sha256": _sha256_file(handoff_root / "samples.jsonl"),
    }
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-dlsvm-native-capacity-preflight",
        "handoff": binding,
        "engine": {
            "path": str(loaded[1]),
            "sha256": _sha256_file(loaded[1]),
            "source_sha256": _sha256_file(LAB_ROOT / "tools/qcsd_osad.c"),
        },
        "source": source_metadata(),
        "trace_length_census": {
            "samples": len(lengths),
            "minimum": lengths[0],
            "maximum": lengths[-1],
            "mean": float(np.mean(np.asarray(lengths, dtype=np.float64))),
            **_numeric_quantiles(lengths),
            "representative_actual_lengths": actual_representatives,
            "benchmark_cap_length": 12_000,
        },
        "measurements": measurements,
        "workload": census,
        "projection": {
            "conservative_single_worker_cells_per_second": conservative_cells_per_second,
            "workers": workers,
            "worker_efficiency": worker_efficiency,
            "safety_factor": safety_factor,
            "projected_wall_seconds": projected_wall_seconds,
            "available_wall_seconds": available_wall,
            "projected_matrix_bytes": projected_matrix_bytes,
            "projected_worker_memory_bytes": projected_working_bytes,
            "projected_memory_bytes": projected_memory_bytes,
            "available_memory_bytes": available_memory,
        },
        "admission": {
            "wall_time_available": (
                available_wall is not None and available_wall >= projected_wall_seconds
            ),
            "memory_available": (
                available_memory is not None
                and available_memory >= math.ceil(projected_memory_bytes * 1.5)
            ),
        },
    }


def write_dlsvm_preflight(
    path: Path,
    *,
    samples: Sequence[StudySample],
    handoff_root: Path,
    formal: bool,
    available_wall_seconds: float | None = None,
) -> Path:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"DLSVM preflight destination already exists: {path}")
    receipt = dlsvm_preflight_benchmark(
        samples,
        handoff_root=handoff_root,
        available_wall_seconds=available_wall_seconds,
    )
    _validate_dlsvm_preflight_value(
        receipt,
        samples=samples,
        handoff_root=handoff_root,
        formal=formal,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    return path


def validate_dlsvm_preflight(
    path: Path,
    *,
    samples: Sequence[StudySample],
    handoff_root: Path,
    formal: bool,
) -> dict[str, Any]:
    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("DLSVM preflight is not a regular file")
    value = load_json(path)
    return _validate_dlsvm_preflight_value(
        value,
        samples=samples,
        handoff_root=handoff_root,
        formal=formal,
    )


def _validate_dlsvm_preflight_value(
    value: Any,
    *,
    samples: Sequence[StudySample],
    handoff_root: Path,
    formal: bool,
) -> dict[str, Any]:
    census = dlsvm_workload_census(samples)
    expected_handoff = {
        "sha256sums_sha256": _sha256_file(handoff_root / "SHA256SUMS"),
        "dataset_sha256": _sha256_file(handoff_root / "dataset.json"),
        "samples_sha256": _sha256_file(handoff_root / "samples.jsonl"),
    }
    projection = value.get("projection") if isinstance(value, Mapping) else None
    admission = value.get("admission") if isinstance(value, Mapping) else None
    measurements = value.get("measurements") if isinstance(value, Mapping) else None
    trace_census = value.get("trace_length_census") if isinstance(value, Mapping) else None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "qcsd-dlsvm-native-capacity-preflight"
        or value.get("handoff") != expected_handoff
        or value.get("workload") != census
        or value.get("source") != source_metadata()
        or not isinstance(projection, Mapping)
        or not isinstance(admission, Mapping)
        or not isinstance(measurements, list)
        or not measurements
        or not isinstance(trace_census, Mapping)
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("cells_per_second"), (int, float))
            or item["cells_per_second"] <= 0
            for item in measurements
        )
    ):
        raise ValueError("DLSVM preflight schema or cohort binding is invalid")
    engine = value.get("engine")
    loaded = _load_osad_library()
    if (
        loaded is None
        or not isinstance(engine, Mapping)
        or set(engine) != {"path", "sha256", "source_sha256"}
        or engine.get("sha256") != _sha256_file(loaded[1])
        or engine.get("source_sha256") != _sha256_file(LAB_ROOT / "tools/qcsd_osad.c")
    ):
        raise ValueError("DLSVM preflight engine binding is invalid")
    projected = projection.get("projected_wall_seconds")
    memory = projection.get("projected_memory_bytes")
    lengths = sorted(len(sample.trace) for sample in samples)
    positions = (0, len(lengths) // 2, math.ceil(len(lengths) * 0.95) - 1, len(lengths) - 1)
    representatives = sorted({lengths[index] for index in positions})
    expected_trace_census = {
        "samples": len(lengths),
        "minimum": lengths[0],
        "maximum": lengths[-1],
        "mean": float(np.mean(np.asarray(lengths, dtype=np.float64))),
        **_numeric_quantiles(lengths),
        "representative_actual_lengths": representatives,
        "benchmark_cap_length": 12_000,
    }
    expected_executed = sorted({max(1, min(length, 12_000)) for length in representatives})
    if (
        trace_census != expected_trace_census
        or [item.get("trace_length") for item in measurements] != expected_executed
    ):
        raise ValueError("DLSVM preflight trace census is invalid")
    for item in measurements:
        length = item["trace_length"]
        elapsed = item.get("elapsed_seconds")
        cells = length * length
        left = tuple(600 if index % 2 == 0 else -600 for index in range(length))
        right = tuple(1_200 if index % 3 == 0 else -600 for index in range(length))
        expected_distance = _native_osad_distance(loaded[0], left, right)
        if (
            set(item)
            != {
                "trace_length",
                "dynamic_programming_cells",
                "elapsed_seconds",
                "pairs_per_second",
                "cells_per_second",
                "distance",
            }
            or item.get("dynamic_programming_cells") != cells
            or isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or elapsed <= 0
            or not math.isclose(item["pairs_per_second"], 1.0 / elapsed, rel_tol=1e-12)
            or not math.isclose(item["cells_per_second"], cells / elapsed, rel_tol=1e-12)
            or item.get("distance") != expected_distance
        ):
            raise ValueError("DLSVM preflight benchmark derivation is invalid")
    conservative_rate = min(float(item["cells_per_second"]) for item in measurements)
    workers = int(census["workers"])
    expected_wall = (
        float(census["dynamic_programming_cells_upper_bound"])
        / (conservative_rate * workers * 0.65)
        * 2.0
    )
    expected_matrix = int(census["persisted_dense_matrix_bytes"])
    expected_working = max(lengths) * 3 * 8 * workers
    expected_memory = expected_matrix + expected_working
    available_wall = projection.get("available_wall_seconds")
    available_memory = projection.get("available_memory_bytes")
    if (
        set(projection)
        != {
            "conservative_single_worker_cells_per_second",
            "workers",
            "worker_efficiency",
            "safety_factor",
            "projected_wall_seconds",
            "available_wall_seconds",
            "projected_matrix_bytes",
            "projected_worker_memory_bytes",
            "projected_memory_bytes",
            "available_memory_bytes",
        }
        or set(admission) != {"wall_time_available", "memory_available"}
        or isinstance(projected, bool)
        or not isinstance(projected, (int, float))
        or projected <= 0
        or type(memory) is not int
        or memory <= 0
        or projection.get("conservative_single_worker_cells_per_second") != conservative_rate
        or projection.get("workers") != workers
        or projection.get("worker_efficiency") != 0.65
        or projection.get("safety_factor") != 2.0
        or not math.isclose(float(projected), expected_wall, rel_tol=1e-12)
        or projection.get("projected_matrix_bytes") != expected_matrix
        or projection.get("projected_worker_memory_bytes") != expected_working
        or memory != expected_memory
        or (
            available_wall is not None
            and (
                isinstance(available_wall, bool)
                or not isinstance(available_wall, (int, float))
                or available_wall <= 0
            )
        )
        or (
            available_memory is not None
            and (type(available_memory) is not int or available_memory <= 0)
        )
    ):
        raise ValueError("DLSVM preflight projection is invalid")
    expected_admission = {
        "wall_time_available": (available_wall is not None and available_wall >= expected_wall),
        "memory_available": (
            available_memory is not None and available_memory >= math.ceil(expected_memory * 1.5)
        ),
    }
    if admission != expected_admission:
        raise ValueError("DLSVM preflight admission was not derived from its projection")
    if formal and (
        admission.get("wall_time_available") is not True
        or admission.get("memory_available") is not True
    ):
        raise ValueError("formal DLSVM capacity preflight did not pass wall and memory admission")
    return value


def run_temporal_attacks(
    samples: Sequence[StudySample],
    *,
    attacks: Sequence[str] = ("panchenko", "vngpp", "dlsvm"),
    dlsvm_store: DlsvmKernelStore | None = None,
) -> tuple[AttackResult, ...]:
    """Run adaptive and undefended-transfer held-out temporal evaluations."""

    results: list[AttackResult] = []
    if "dlsvm" in attacks and dlsvm_store is None:
        dlsvm_store = DlsvmKernelStore(samples)
    defenses = sorted({sample.defense for sample in samples})
    temporal_splits = (("validation", VALIDATION_BLOCK), ("heldout-test", TEST_BLOCK))
    for attack in attacks:
        for split, test_block in temporal_splits:
            for defense in defenses:
                train = [
                    sample
                    for sample in samples
                    if sample.defense == defense and sample.acquisition_block_index in TRAIN_BLOCKS
                ]
                test = [
                    sample
                    for sample in samples
                    if sample.defense == defense and sample.acquisition_block_index == test_block
                ]
                results.append(
                    _fit_predict_attack(
                        attack,
                        train,
                        test,
                        training_defense=defense,
                        testing_defense=defense,
                        protocol=f"temporal-{split}-adaptive",
                        dlsvm_store=dlsvm_store,
                    )
                )
            transfer_train = [
                sample
                for sample in samples
                if sample.defense == "undefended" and sample.acquisition_block_index in TRAIN_BLOCKS
            ]
            for defense in defenses:
                transfer_test = [
                    sample
                    for sample in samples
                    if sample.defense == defense and sample.acquisition_block_index == test_block
                ]
                results.append(
                    _fit_predict_attack(
                        attack,
                        transfer_train,
                        transfer_test,
                        training_defense="undefended",
                        testing_defense=defense,
                        protocol=f"temporal-{split}-undefended-transfer",
                        dlsvm_store=dlsvm_store,
                    )
                )
    return tuple(results)


def run_historical_attacks(
    samples: Sequence[StudySample],
    *,
    attacks: Sequence[str] = ("panchenko", "vngpp", "dlsvm"),
    random_state: int = _DLSVM_RANDOM_STATE,
    dlsvm_store: DlsvmKernelStore | None = None,
) -> tuple[AttackResult, ...]:
    """Run the explicitly secondary paper-style stratified ten-fold view."""

    try:
        from sklearn.model_selection import StratifiedKFold
    except ImportError as error:
        raise RuntimeError(
            "attack evaluation requires the pinned 'evaluation' optional dependency"
        ) from error

    results: list[AttackResult] = []
    if "dlsvm" in attacks and dlsvm_store is None:
        dlsvm_store = DlsvmKernelStore(samples)
    for defense in sorted({sample.defense for sample in samples}):
        defense_samples = sorted(
            (sample for sample in samples if sample.defense == defense),
            key=lambda sample: sample.sample_id,
        )
        labels = np.asarray([sample.class_label for sample in defense_samples])
        splitter = StratifiedKFold(n_splits=10, shuffle=True, random_state=random_state)
        for attack in attacks:
            folds: list[AttackResult] = []
            for train_indexes, test_indexes in splitter.split(np.zeros(len(labels)), labels):
                training = [defense_samples[int(index)] for index in train_indexes]
                testing = [defense_samples[int(index)] for index in test_indexes]
                folds.append(
                    _fit_predict_attack(
                        attack,
                        training,
                        testing,
                        training_defense=defense,
                        testing_defense=defense,
                        protocol="historical-stratified-10fold",
                        dlsvm_store=dlsvm_store,
                    )
                )
            results.append(
                _aggregate_fold_results(
                    folds,
                    unique_samples=len(defense_samples),
                    random_state=random_state,
                )
            )
    return tuple(results)


def original_study_comparison_rows() -> tuple[dict[str, Any], ...]:
    """Return row-complete historical anchors with non-comparability context."""

    from .buflo_reference import validate_reference_receipt

    validate_reference_receipt(_BUFLO_REFERENCE)
    validate_reference_receipt(_CSBUFLO_REFERENCE)
    buflo = load_json(_BUFLO_REFERENCE)
    csbuflo = load_json(_CSBUFLO_REFERENCE)
    rows: list[dict[str, Any]] = []

    buflo_context = {
        "transport": (
            "ideal simulated transformation of HTTP traffic captured through an "
            "OpenSSH single-hop SOCKS proxy over IPv4/TCP"
        ),
        "endpoint_cooperation": (
            "ideal bidirectional simulator with application start/end knowledge; "
            "not a deployed peer protocol"
        ),
        "dataset_size": "closed-world k=128 sampled from the 775-page Herrmann corpus",
        "visits": (
            "20 chronological traces per selected site and trial: 16 train, 4 test; "
            "256 randomized trials at k=128"
        ),
        "observation_layer": "encrypted-tunnel packet timestamp, direction, and length",
        "header_accounting": (
            "52-byte IPv4/TCP accounting; pure 52-byte ACKs contribute no buffered payload"
        ),
        "early_termination_semantics": (
            "none; continue until timer>tau, source exhausted, and both buffers empty"
        ),
        "overhead_formula": (
            "100*(sum(defended bytes)/sum(baseline bytes)-1); additional overhead percent"
        ),
        "latency_definition": (
            "absolute simulated maximum packet-buffer waiting-delay statistic in seconds; "
            "not a completion-time ratio"
        ),
        "classifier_protocol": (
            "repeated randomized closed-world trials; both train and test traces transformed"
        ),
    }
    for result in buflo["published_results"]:
        profile = result["profile"]
        rows.append(
            {
                "anchor_id": (
                    f"buflo-tau{profile['tau_ms']}-rho{profile['rho_ms']}-d{profile['d_bytes']}"
                ),
                "source": "Dyer et al., IEEE S&P 2012, Figure 12",
                "result_scope": "original-study",
                **buflo_context,
                "padding_variant": (
                    f"BuFLO tau={profile['tau_ms']}ms,rho={profile['rho_ms']}ms,"
                    f"d={profile['d_bytes']}B IPv4/TCP packet"
                ),
                "metrics": result,
            }
        )

    cs_context = {
        "transport": (
            "empirical Firefox HTTP through modified OpenSSH 5.9p1 SOCKS proxies over IPv4/TCP"
        ),
        "endpoint_cooperation": (
            "modified client and server, browser onLoad plugin, and client-to-server "
            "padding-complete notification"
        ),
        "visits": "20 traces per site, cache cleared, round-robin collection; stratified folds",
        "observation_layer": "tshark-captured packet timestamp, direction, and wire length",
        "header_accounting": (
            "548-byte socket write mapped to a nominal 600-byte IPv4/TCP packet; "
            "captured-wire bandwidth accounting"
        ),
        "overhead_formula": (
            "E[defended captured bytes]/E[paired immediate SSH captured bytes]; bandwidth ratio"
        ),
        "latency_definition": (
            "E[defended total packet-trace duration]/E[paired immediate SSH trace duration]"
        ),
        "classifier_protocol": (
            "adaptive attacker within each defense using paper-style stratified ten-fold "
            "cross-validation"
        ),
    }
    for result in csbuflo["main_results"]:
        rows.append(
            {
                "anchor_id": (
                    f"csbuflo-sites{result['sites']}-{result['padding_profile'].lower()}-"
                    f"et{int(bool(result['early_termination']))}"
                ),
                "source": "Cai et al., WPES 2014, main security/performance evaluation",
                "result_scope": "original-study",
                **cs_context,
                "dataset_size": f"closed-world Alexa set of {result['sites']} sites",
                "padding_variant": result["padding_profile"],
                "early_termination_semantics": (
                    "bilateral early termination: client padding-complete signal lets the "
                    "server stop after website idle and empty buffers"
                ),
                "metrics": result,
            }
        )
    for result in csbuflo["early_termination_ablation"]:
        early = result["early_termination"]
        rows.append(
            {
                "anchor_id": (
                    f"csbuflo-sites{result['sites']}-{result['padding_profile'].lower()}-"
                    f"et{int(bool(result['early_termination']))}"
                ),
                "source": "Cai et al., WPES 2014, Table 3 early-termination ablation",
                "result_scope": "original-study",
                **cs_context,
                "dataset_size": f"closed-world ablation set of {result['sites']} sites",
                "padding_variant": result["padding_profile"],
                "early_termination_semantics": (
                    "bilateral padding-complete notification enabled"
                    if early
                    else "no early termination; server retains its padding tail"
                ),
                "metrics": result,
            }
        )
    if len({row["anchor_id"] for row in rows}) != len(rows) or any(
        not _COMPARISON_CONTEXT_FIELDS <= set(row) for row in rows
    ):
        raise RuntimeError("original-study comparison row omitted required context")
    return tuple(rows)


def historical_anchor_metric_inventory(
    rows: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Freeze every published numeric outcome under one stable anchor identity."""

    selected = tuple(rows) if rows is not None else original_study_comparison_rows()
    inventory: list[dict[str, Any]] = []
    for row in selected:
        anchor_id = row.get("anchor_id")
        metrics = row.get("metrics")
        if not isinstance(anchor_id, str) or not anchor_id or not isinstance(metrics, Mapping):
            raise ValueError("historical comparison anchor identity is invalid")
        paths: list[str] = []

        def visit(prefix: str, value: Any, output: list[str]) -> None:
            if isinstance(value, Mapping):
                for key in sorted(value):
                    child = f"{prefix}.{key}" if prefix else str(key)
                    visit(child, value[key], output)
                return
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or prefix == "sites"
                or prefix.startswith("profile.")
            ):
                return
            if not math.isfinite(float(value)):
                raise ValueError("historical comparison metric is not finite")
            output.append(prefix)

        visit("", metrics, paths)
        if not paths:
            raise ValueError("historical comparison anchor has no numeric outcome metrics")
        inventory.append(
            {
                "anchor_id": anchor_id,
                "historical_row_sha256": _canonical_json_sha256(row),
                "metric_paths": paths,
            }
        )
    if len({item["anchor_id"] for item in inventory}) != len(inventory):
        raise ValueError("historical comparison anchor inventory is not unique")
    return tuple(inventory)


def _qcsd_comparison_rows(
    samples: Sequence[StudySample],
    paired_summary: Mapping[str, Any],
    attack_results: Sequence[AttackResult],
) -> tuple[dict[str, Any], ...]:
    labels = sorted({sample.class_label for sample in samples})
    rows = []
    for defense in sorted(set(paired_summary)):
        selected = [sample for sample in samples if sample.defense == defense]
        per_class = Counter(sample.class_label for sample in selected)
        if defense == "buflo":
            padding_variant = "1200-byte desired UDP-payload BuFLO cell"
            early_termination = (
                "inclusive 10-second minimum; drain every allocatable whole cell, then "
                "client-locally cancel only an unallocatable reviewed-chaff sub-cell tail "
                "with standard HTTP/3 control; no bilateral padding-complete signal"
            )
        elif defense == "cs-buflo":
            padding_variant = (
                "CTSP adaptation: outgoing total, incoming payload, 600-byte desired UDP payload"
            )
            early_termination = (
                "client-only ApplicationComplete or strict-quiet phase; stop new opportunities "
                "at the first eligible frozen padding target or directional power-of-two "
                "crossing, using outgoing observed UDP payload and incoming fully consumed "
                "scheduled credit, then drain already-advertised credit exactly once before "
                "local termination; no peer padding-done signal"
            )
        else:
            padding_variant = "mode-specific; bound by the sample's resolved run receipt"
            early_termination = "mode-specific; bound by the sample's resolved run receipt"
        context = {
            "transport": "HTTP/3 over QUIC with standard QUIC packets and ordinary servers",
            "endpoint_cooperation": (
                "none; defense scheduling, chaff, credit attempts, and local termination are "
                "client-only"
            ),
            "dataset_size": {
                "classes": len(labels),
                "workloads": labels,
                "samples_for_mode": len(selected),
            },
            "visits": {
                "per_class": dict(sorted(per_class.items())),
                "acquisition_blocks": sorted(
                    {sample.acquisition_block_index for sample in selected}
                ),
            },
            "observation_layer": (
                "identifier-free Ethernet observer-frame timestamp, direction, and length"
            ),
            "header_accounting": (
                "Ethernet observer frames with separate UDP-payload metrics; not the papers' "
                "52-byte IPv4/TCP model"
            ),
            "padding_variant": padding_variant,
            "early_termination_semantics": early_termination,
            "incoming_boundary_semantics": (
                {
                    "cadence": CS_BUFLO_INCOMING_CADENCE_BOUNDARY,
                    "terminal": CS_BUFLO_INCOMING_TERMINAL_BOUNDARY,
                    "separation": CS_BUFLO_INCOMING_BOUNDARY_SEPARATION,
                }
                if defense == "cs-buflo"
                else "mode-specific; bound by the sample's resolved run receipt"
            ),
            "overhead_formula": (
                "ratio of aggregate defended/baseline sums; additional percent is 100*(ratio-1)"
            ),
            "latency_definition": (
                "paired application-completion time ratio and added seconds; defense-tail "
                "duration is separately receipted"
            ),
            "classifier_protocol": sorted(
                {result.protocol for result in attack_results if result.testing_defense == defense}
            ),
        }
        rows.append(
            {
                "source": "QCSD BuFLO focused study",
                "result_scope": "qcsd-client-only-quic-adaptation",
                "defense": defense,
                "implementation_scope": "client_only_quic",
                "paper_equivalent": False,
                **context,
                "metrics": paired_summary[defense],
                "classifier_results": [
                    {
                        "attack": result.attack,
                        "backend": result.backend,
                        "protocol": result.protocol,
                        "training_defense": result.training_defense,
                        "accuracy": result.accuracy,
                        "balanced_accuracy": result.balanced_accuracy,
                    }
                    for result in attack_results
                    if result.testing_defense == defense
                ],
                "known_expected_differences": [
                    {
                        "difference": "transport-and-observation-layer",
                        "classification": "expected",
                        "reason": "client-only QUIC adaptation versus the paper's IPv4/TCP setting",
                    },
                    {
                        "difference": "endpoint-cooperation-and-peer-datagram-unavailability",
                        "classification": "expected",
                        "reason": "ordinary HTTP/3 server versus ideal or modified bilateral endpoints",
                    },
                    {
                        "difference": "closed-world-dataset-and-classifier-protocol",
                        "classification": "expected",
                        "reason": "five QCSD workloads and temporal holdout versus historical site corpora",
                    },
                ]
                + (
                    [
                        {
                            "difference": "buflo-terminal-subcell-client-local-cancellation",
                            "classification": "expected",
                            "reason": (
                                "after every allocatable 1,200-byte reviewed-chaff cell is "
                                "drained, an unallocatable response tail is terminalized with "
                                "standard client-local HTTP/3 STOP_SENDING/RESET_STREAM; those "
                                "unscheduled defense-control bytes are separately receipted and "
                                "are not part of the paper's bilateral TCP model"
                            ),
                        }
                    ]
                    if defense == "buflo"
                    else []
                )
                + (
                    [
                        {
                            "difference": (
                                "csbuflo-author-total-transmitted-vs-live-fresh-"
                                "application-stream-byte-adaptation-counter"
                            ),
                            "classification": "expected",
                            "reason": (
                                "the pinned author endpoint counts every transmitted real-plus-"
                                "junk byte, while the client-only QUIC translation counts exact "
                                "fresh outgoing application STREAM bytes, excludes retransmission "
                                "and defense-added bytes, and approximates incoming progress with "
                                "consumed application offsets"
                            ),
                        },
                        {
                            "difference": "csbuflo-incoming-boundary-translation",
                            "classification": "expected",
                            "reason": (
                                "the client-only adaptation rearms its incoming cadence at a "
                                "complete local MAX_STREAM_DATA advertisement, terminalizes the "
                                "slot only after eventual peer stream-offset consumption, and "
                                "does not claim the paper's modified-server datagram or "
                                "padding-complete timing"
                            ),
                        },
                        {
                            "difference": (
                                "csbuflo-paper-source-and-client-only-early-termination-translation"
                            ),
                            "classification": "expected",
                            "reason": (
                                "paper Algorithm 4 uses an active bilateral padding-done or "
                                "current-write crossing input, while the pinned source has zero "
                                "active padding-done consumers and uses transcript-end/zero-w2w; "
                                "the client-only QCSD adaptation instead stops local opportunities "
                                "at a frozen target or directional crossing and drains already-"
                                "advertised receive credit before local termination"
                            ),
                        },
                    ]
                    if defense == "cs-buflo"
                    else []
                ),
                "numeric_discrepancy_classification": "unreviewed",
                "numeric_discrepancy_explanation": None,
                "attestation_eligible": False,
            }
        )
    if any(not _COMPARISON_CONTEXT_FIELDS <= set(row) for row in rows):
        raise RuntimeError("QCSD comparison row omitted required context")
    return tuple(rows)


def _evaluator_source_binding(handoff_root: Path | None, *, formal: bool) -> dict[str, Any]:
    module_path = Path(__file__).resolve()
    handoff_module = module_path.with_name("buflo_handoff.py")
    native_source = LAB_ROOT / "tools/qcsd_osad.c"
    required_sources = {
        "src/qcsd_lab/buflo_evaluation.py": module_path,
        "src/qcsd_lab/buflo_handoff.py": handoff_module,
        "tools/qcsd_osad.c": native_source,
    }
    if any(path.is_symlink() or not path.is_file() for path in required_sources.values()):
        raise ValueError("evaluation source inventory is incomplete")
    current_source = source_metadata()
    handoff_source = None
    if handoff_root is not None:
        dataset = load_json(handoff_root / "dataset.json")
        if not isinstance(dataset, Mapping):
            raise ValueError("evaluation handoff dataset is invalid")
        handoff_source = {
            "execution_source": dataset.get("execution_source"),
            "exporter_source": dataset.get("exporter_source"),
        }
        if formal and not (
            current_source
            == handoff_source["execution_source"]
            == handoff_source["exporter_source"]
        ):
            raise ValueError("formal evaluation source differs from capture/export source lineage")
    elif formal:
        raise ValueError("formal evaluation requires a sealed handoff source binding")
    osad = _load_osad_library()
    installed_native = (
        {
            "path": str(osad[1]),
            "sha256": _sha256_file(osad[1]),
        }
        if osad is not None
        else None
    )
    if formal and installed_native is None:
        raise ValueError("formal evaluation has no hash-bound native OSAD library")
    return {
        "schema_version": 1,
        "current_source": current_source,
        "handoff_source": handoff_source,
        "source_files": {
            relative: _sha256_file(path) for relative, path in sorted(required_sources.items())
        },
        "native_library": installed_native,
        "weka_backend": vngpp_backend_receipt(),
        "dlsvm_backend": dlsvm_backend_receipt(),
    }


def write_evaluation_receipt(
    path: Path,
    *,
    samples: Sequence[StudySample],
    attack_results: Sequence[AttackResult],
    bootstrap_draws: int = 10_000,
    handoff_root: Path | None = None,
    formal: bool = False,
    dlsvm_preflight: Path | None = None,
    dlsvm_cache: Mapping[str, Any] | None = None,
) -> Path:
    """Create one non-overwriting, canonical evaluation receipt."""

    if path.exists() or path.is_symlink():
        raise FileExistsError(f"evaluation receipt already exists: {path}")
    if formal and bootstrap_draws != FORMAL_BOOTSTRAP_DRAWS:
        raise ValueError(
            f"formal evaluation requires exactly {FORMAL_BOOTSTRAP_DRAWS} bootstrap draws"
        )
    paired = paired_overheads(samples)
    paired_summary = summarize_paired_overheads(paired, bootstrap_draws=bootstrap_draws)
    attacks = []
    for index, result in enumerate(attack_results):
        record = result.as_dict()
        record["block_workload_bootstrap_95"] = attack_bootstrap_intervals(
            result,
            draws=bootstrap_draws,
            seed=20260827 + index,
        )
        attacks.append(record)
    handoff_binding = None
    if handoff_root is not None:
        handoff_root = handoff_root.resolve()
        handoff_binding = {
            "sha256sums_sha256": _sha256_file(handoff_root / "SHA256SUMS"),
            "dataset_sha256": _sha256_file(handoff_root / "dataset.json"),
            "samples_sha256": _sha256_file(handoff_root / "samples.jsonl"),
        }
    evaluator_source = _evaluator_source_binding(handoff_root, formal=formal)
    receipt = {
        "schema_version": EVALUATION_RECEIPT_SCHEMA_VERSION,
        "artifact_type": _EVALUATION_ARTIFACT_TYPE,
        "formal": formal,
        "sample_count": len(samples),
        "bootstrap_draws": bootstrap_draws,
        "handoff": handoff_binding,
        "evaluator_source": evaluator_source,
        "dlsvm_preflight": (
            {
                "path": str(dlsvm_preflight.resolve()),
                "sha256": _sha256_file(dlsvm_preflight),
            }
            if dlsvm_preflight is not None
            else None
        ),
        "dlsvm_persistent_cache": dict(dlsvm_cache) if dlsvm_cache is not None else None,
        "observation_layer": _EVALUATION_OBSERVATION_LAYER,
        "overhead_formula": _EVALUATION_OVERHEAD_FORMULA,
        "five_class_random_chance_accuracy": _EVALUATION_RANDOM_CHANCE_ACCURACY,
        "temporal_protocol": _evaluation_temporal_protocol(),
        "paired_metrics": paired_summary,
        "paired_per_visit": paired,
        "performance_breakdowns": (
            performance_breakdowns(samples, bootstrap_draws=bootstrap_draws)
            if all(_performance_is_complete(sample) for sample in samples)
            else {"available": False, "reason": "handoff performance evidence is incomplete"}
        ),
        "algorithm_breakdowns": algorithm_breakdowns(samples),
        "classifier_provenance": {
            "panchenko_vngpp": classifier_reference_receipt(),
            "vngpp": vngpp_backend_receipt(),
            "dlsvm": dlsvm_backend_receipt(),
        },
        "classifier_workload": {"dlsvm": dlsvm_workload_census(samples)},
        "attacks": attacks,
        "original_study_comparison": {
            "acceptance_rule": _EVALUATION_COMPARISON_ACCEPTANCE_RULE,
            "historical_rows": list(original_study_comparison_rows()),
            "anchor_metric_inventory": list(historical_anchor_metric_inventory()),
            "qcsd_rows": list(_qcsd_comparison_rows(samples, paired_summary, attack_results)),
            "numeric_discrepancy_review_required": True,
        },
        "limitations": list(_EVALUATION_LIMITATIONS),
    }
    _validate_evaluation_receipt_value(
        receipt,
        samples=samples,
        handoff_root=handoff_root,
        formal=formal,
        deep=True,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as output:
        output.write(encoded)
    return path


def validate_evaluation_receipt(
    path: Path,
    *,
    handoff_root: Path,
    formal: bool,
    deep: bool = True,
) -> dict[str, Any]:
    """Independently revalidate classifier membership, predictions, and metrics."""

    from .buflo_handoff import validate_study_handoff

    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("evaluation receipt is not a regular file")
    root = validate_study_handoff(handoff_root, formal=formal, deep=deep)
    samples = load_study_handoff(root)
    value = load_json(path)
    return _validate_evaluation_receipt_value(
        value,
        samples=samples,
        handoff_root=root,
        formal=formal,
        deep=deep,
    )


def _validate_evaluation_receipt_value(
    value: Any,
    *,
    samples: Sequence[StudySample],
    handoff_root: Path | None,
    formal: bool,
    deep: bool,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _EVALUATION_RECEIPT_KEYS
        or value.get("schema_version") != EVALUATION_RECEIPT_SCHEMA_VERSION
        or value.get("artifact_type") != _EVALUATION_ARTIFACT_TYPE
        or value.get("formal") is not formal
        or value.get("sample_count") != len(samples)
        or type(value.get("bootstrap_draws")) is not int
        or value["bootstrap_draws"] <= 0
        or not isinstance(value.get("attacks"), list)
        or value.get("observation_layer") != _EVALUATION_OBSERVATION_LAYER
        or value.get("overhead_formula") != _EVALUATION_OVERHEAD_FORMULA
        or value.get("five_class_random_chance_accuracy") != _EVALUATION_RANDOM_CHANCE_ACCURACY
        or value.get("temporal_protocol") != _evaluation_temporal_protocol()
        or value.get("limitations") != list(_EVALUATION_LIMITATIONS)
    ):
        raise ValueError("evaluation receipt schema or cohort count is invalid")
    draws = int(value["bootstrap_draws"])
    if formal:
        if draws != FORMAL_BOOTSTRAP_DRAWS:
            raise ValueError(
                f"formal evaluation requires exactly {FORMAL_BOOTSTRAP_DRAWS} bootstrap draws"
            )
        validate_formal_cohort(samples, require_performance=True)
    expected_handoff = None
    if handoff_root is not None:
        handoff_root = handoff_root.resolve()
        expected_handoff = {
            "sha256sums_sha256": _sha256_file(handoff_root / "SHA256SUMS"),
            "dataset_sha256": _sha256_file(handoff_root / "dataset.json"),
            "samples_sha256": _sha256_file(handoff_root / "samples.jsonl"),
        }
    if value.get("handoff") != expected_handoff:
        raise ValueError("evaluation receipt handoff binding is invalid")
    if value.get("evaluator_source") != _evaluator_source_binding(handoff_root, formal=formal):
        raise ValueError("evaluation receipt source/backend lineage is invalid")
    expected_classifier_provenance = {
        "panchenko_vngpp": classifier_reference_receipt(),
        "vngpp": vngpp_backend_receipt(),
        "dlsvm": dlsvm_backend_receipt(),
    }
    if value.get("classifier_provenance") != expected_classifier_provenance:
        raise ValueError("evaluation receipt classifier provenance is invalid")
    if value.get("classifier_workload") != {"dlsvm": dlsvm_workload_census(samples)}:
        raise ValueError("evaluation receipt classifier workload census is invalid")

    attack_results = tuple(
        _validate_attack_record(record, samples=samples) for record in value["attacks"]
    )
    identities = [
        (
            result.attack,
            result.training_defense,
            result.testing_defense,
            result.protocol,
        )
        for result in attack_results
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("evaluation receipt repeats an attack result identity")
    if identities != _expected_attack_identities(samples):
        raise ValueError("evaluation receipt does not contain the exact attack matrix")
    for index, (record, result) in enumerate(zip(value["attacks"], attack_results, strict=True)):
        expected_interval = attack_bootstrap_intervals(
            result,
            draws=draws,
            seed=20260827 + index,
        )
        if record.get("block_workload_bootstrap_95") != expected_interval:
            raise ValueError("evaluation attack bootstrap metrics are invalid")

    paired = paired_overheads(samples)
    expected_summary = summarize_paired_overheads(paired, bootstrap_draws=draws)
    if value.get("paired_per_visit") != paired or value.get("paired_metrics") != expected_summary:
        raise ValueError("evaluation paired-overhead evidence is invalid")
    expected_performance = (
        performance_breakdowns(samples, bootstrap_draws=draws)
        if all(_performance_is_complete(sample) for sample in samples)
        else {"available": False, "reason": "handoff performance evidence is incomplete"}
    )
    if value.get("performance_breakdowns") != expected_performance:
        raise ValueError("evaluation performance breakdowns are invalid")
    if value.get("algorithm_breakdowns") != algorithm_breakdowns(samples):
        raise ValueError("evaluation algorithm breakdowns are invalid")

    preflight = value.get("dlsvm_preflight")
    cache = value.get("dlsvm_persistent_cache")
    if formal:
        if (
            handoff_root is None
            or not isinstance(preflight, Mapping)
            or set(preflight) != {"path", "sha256"}
        ):
            raise ValueError("formal evaluation has no DLSVM preflight binding")
        preflight_path = Path(str(preflight["path"])).resolve()
        if _sha256_file(preflight_path) != preflight.get("sha256"):
            raise ValueError("formal evaluation DLSVM preflight digest is invalid")
        validate_dlsvm_preflight(
            preflight_path,
            samples=samples,
            handoff_root=handoff_root,
            formal=True,
        )
        _validate_dlsvm_cache_receipt(cache, samples=samples, deep=deep)
    elif preflight is not None:
        raise ValueError("non-formal evaluation unexpectedly binds a formal preflight")
    elif cache is not None:
        _validate_dlsvm_cache_receipt(cache, samples=samples, deep=deep)

    if deep:
        _validate_attack_replay(
            value["attacks"],
            attack_results,
            samples=samples,
            dlsvm_cache=cache,
        )

    comparison = value.get("original_study_comparison")
    if (
        not isinstance(comparison, Mapping)
        or set(comparison)
        != {
            "acceptance_rule",
            "historical_rows",
            "anchor_metric_inventory",
            "qcsd_rows",
            "numeric_discrepancy_review_required",
        }
        or comparison.get("acceptance_rule") != _EVALUATION_COMPARISON_ACCEPTANCE_RULE
        or comparison.get("historical_rows") != list(original_study_comparison_rows())
        or comparison.get("anchor_metric_inventory") != list(historical_anchor_metric_inventory())
        or comparison.get("qcsd_rows")
        != list(_qcsd_comparison_rows(samples, expected_summary, attack_results))
        or comparison.get("numeric_discrepancy_review_required") is not True
    ):
        raise ValueError("evaluation original-study comparison is invalid")
    return value


def _validate_attack_record(record: Any, *, samples: Sequence[StudySample]) -> AttackResult:
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
    if not isinstance(record, Mapping) or set(record) != required:
        raise ValueError("evaluation attack result schema is invalid")
    predictions_value = record.get("predictions")
    labels_value = record.get("labels")
    attack = record.get("attack")
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or attack not in {"panchenko", "vngpp", "dlsvm"}
        or record.get("backend") != _expected_attack_backend(str(attack))
        or not isinstance(predictions_value, list)
        or not predictions_value
        or not isinstance(labels_value, list)
        or not labels_value
        or labels_value != sorted(set(labels_value))
        or record.get("predictions_sha256") != _canonical_json_sha256(predictions_value)
    ):
        raise ValueError("evaluation attack identity or prediction hash is invalid")
    by_id = {sample.sample_id: sample for sample in samples}
    predictions: list[AttackPrediction] = []
    for item in predictions_value:
        if not isinstance(item, Mapping) or set(item) != {
            "sample_id",
            "acquisition_block_index",
            "workload_id",
            "expected",
            "predicted",
        }:
            raise ValueError("evaluation attack prediction schema is invalid")
        sample = by_id.get(str(item.get("sample_id")))
        if (
            sample is None
            or item.get("acquisition_block_index") != sample.acquisition_block_index
            or item.get("workload_id") != sample.workload_id
            or item.get("expected") != sample.class_label
            or item.get("predicted") not in labels_value
        ):
            raise ValueError("evaluation attack prediction is not bound to its sample")
        predictions.append(
            AttackPrediction(
                sample_id=sample.sample_id,
                acquisition_block_index=sample.acquisition_block_index,
                workload_id=sample.workload_id,
                expected=sample.class_label,
                predicted=str(item["predicted"]),
            )
        )
    if len({prediction.sample_id for prediction in predictions}) != len(predictions):
        raise ValueError("evaluation attack prediction set contains duplicate samples")
    protocol = str(record.get("protocol"))
    details = record.get("protocol_details")
    expected_details, expected_train_samples, expected_test_ids = _expected_protocol_details(
        protocol,
        training_defense=str(record.get("training_defense")),
        testing_defense=str(record.get("testing_defense")),
        samples=samples,
    )
    if details != expected_details:
        raise ValueError("evaluation attack protocol membership is invalid")
    if [prediction.sample_id for prediction in predictions] != expected_test_ids:
        raise ValueError("evaluation predictions do not follow the exact held-out membership")
    expected_labels = tuple(str(label) for label in labels_value)
    accuracy, balanced, matrix, recalls = _classification_metrics(
        [prediction.expected for prediction in predictions],
        [prediction.predicted for prediction in predictions],
        expected_labels,
    )
    if (
        record.get("train_samples") != expected_train_samples
        or record.get("test_samples") != len(expected_test_ids)
        or record.get("accuracy") != accuracy
        or record.get("balanced_accuracy") != balanced
        or record.get("confusion_matrix") != [list(row) for row in matrix]
        or record.get("per_class_recall") != recalls
    ):
        raise ValueError("evaluation attack metrics were not derived from predictions")
    return AttackResult(
        attack=str(record["attack"]),
        backend=str(record["backend"]),
        training_defense=str(record["training_defense"]),
        testing_defense=str(record["testing_defense"]),
        protocol=protocol,
        train_samples=expected_train_samples,
        test_samples=len(expected_test_ids),
        labels=expected_labels,
        accuracy=accuracy,
        balanced_accuracy=balanced,
        confusion_matrix=matrix,
        per_class_recall=recalls,
        predictions=tuple(predictions),
        protocol_details=dict(expected_details),
    )


def _expected_attack_backend(attack: str) -> str:
    if attack == "panchenko":
        return "clean-room-libsvm-compatible-rbf"
    if attack == "vngpp":
        return (
            "pinned-author-weka-3.7.5-kernel-naive-bayes"
            if _load_weka_backend() is not None
            else "clean-room-gaussian-nb-contextual-nonformal-only"
        )
    if attack == "dlsvm":
        return (
            "clean-room-ccs12-restricted-osa-svm-native"
            if _load_osad_library() is not None
            else "clean-room-ccs12-restricted-osa-svm-python"
        )
    raise ValueError(f"unsupported attack: {attack}")


def _validate_attack_replay(
    records: Sequence[Mapping[str, Any]],
    results: Sequence[AttackResult],
    *,
    samples: Sequence[StudySample],
    dlsvm_cache: Any,
) -> None:
    """Deterministically replay every fitted model from the exact sealed inputs."""

    dlsvm_store: DlsvmKernelStore | None = None
    if any(result.attack == "dlsvm" for result in results):
        cache_directory = None
        if isinstance(dlsvm_cache, Mapping) and isinstance(dlsvm_cache.get("path"), str):
            cache_directory = Path(dlsvm_cache["path"])
        dlsvm_store = DlsvmKernelStore(samples, cache_directory=cache_directory)

    for record, result in zip(records, results, strict=True):
        replayed = _replay_attack_result(result, samples=samples, dlsvm_store=dlsvm_store)
        submitted = dict(record)
        submitted.pop("block_workload_bootstrap_95", None)
        if submitted != replayed.as_dict():
            raise ValueError("evaluation attack predictions do not match deterministic replay")

    if dlsvm_store is not None and dlsvm_cache is not None:
        if dlsvm_store.receipt() != dlsvm_cache:
            raise ValueError("evaluation replay did not consume the exact DLSVM cache")


def _replay_attack_result(
    result: AttackResult,
    *,
    samples: Sequence[StudySample],
    dlsvm_store: DlsvmKernelStore | None,
) -> AttackResult:
    if result.protocol == "historical-stratified-10fold":
        selected = [sample for sample in samples if sample.defense == result.training_defense]
        replayed = run_historical_attacks(
            selected,
            attacks=(result.attack,),
            random_state=_DLSVM_RANDOM_STATE,
            dlsvm_store=dlsvm_store,
        )
        if len(replayed) != 1:
            raise ValueError("evaluation historical replay produced an invalid result count")
        return replayed[0]

    if result.protocol.startswith("temporal-validation-"):
        test_block = VALIDATION_BLOCK
    elif result.protocol.startswith("temporal-heldout-test-"):
        test_block = TEST_BLOCK
    else:
        raise ValueError("evaluation replay encountered an unknown protocol")
    training = [
        sample
        for sample in samples
        if sample.defense == result.training_defense
        and sample.acquisition_block_index in TRAIN_BLOCKS
    ]
    testing = [
        sample
        for sample in samples
        if sample.defense == result.testing_defense and sample.acquisition_block_index == test_block
    ]
    return _fit_predict_attack(
        result.attack,
        training,
        testing,
        training_defense=result.training_defense,
        testing_defense=result.testing_defense,
        protocol=result.protocol,
        dlsvm_store=dlsvm_store,
    )


def _expected_attack_identities(
    samples: Sequence[StudySample],
) -> list[tuple[str, str, str, str]]:
    defenses = sorted({sample.defense for sample in samples})
    identities: list[tuple[str, str, str, str]] = []
    for attack in ("panchenko", "vngpp", "dlsvm"):
        for split in ("validation", "heldout-test"):
            for defense in defenses:
                identities.append(
                    (
                        attack,
                        defense,
                        defense,
                        f"temporal-{split}-adaptive",
                    )
                )
            for defense in defenses:
                identities.append(
                    (
                        attack,
                        "undefended",
                        defense,
                        f"temporal-{split}-undefended-transfer",
                    )
                )
    for defense in defenses:
        for attack in ("panchenko", "vngpp", "dlsvm"):
            identities.append(
                (
                    attack,
                    defense,
                    defense,
                    "historical-stratified-10fold",
                )
            )
    return identities


def _expected_protocol_details(
    protocol: str,
    *,
    training_defense: str,
    testing_defense: str,
    samples: Sequence[StudySample],
) -> tuple[dict[str, Any], int, list[str]]:
    if protocol.startswith("temporal-"):
        pieces = protocol.split("-")
        if len(pieces) < 3:
            raise ValueError("evaluation temporal protocol is invalid")
        if protocol.startswith("temporal-validation-"):
            test_block = VALIDATION_BLOCK
        elif protocol.startswith("temporal-heldout-test-"):
            test_block = TEST_BLOCK
        else:
            raise ValueError("evaluation temporal split is invalid")
        if protocol.endswith("-adaptive"):
            if training_defense != testing_defense:
                raise ValueError("evaluation adaptive protocol crosses defenses")
        elif protocol.endswith("-undefended-transfer"):
            if training_defense != "undefended":
                raise ValueError("evaluation transfer protocol defense identity is invalid")
        else:
            raise ValueError("evaluation temporal protocol kind is invalid")
        training = [
            sample
            for sample in samples
            if sample.defense == training_defense and sample.acquisition_block_index in TRAIN_BLOCKS
        ]
        testing = [
            sample
            for sample in samples
            if sample.defense == testing_defense and sample.acquisition_block_index == test_block
        ]
        train_ids = [sample.sample_id for sample in training]
        test_ids = [sample.sample_id for sample in testing]
        details = {
            "training_sample_ids": train_ids,
            "training_sample_ids_sha256": _canonical_json_sha256(train_ids),
            "testing_sample_ids": test_ids,
            "testing_sample_ids_sha256": _canonical_json_sha256(test_ids),
        }
        return details, len(train_ids), test_ids
    if protocol != "historical-stratified-10fold" or training_defense != testing_defense:
        raise ValueError("evaluation attack protocol is invalid")
    try:
        from sklearn.model_selection import StratifiedKFold
    except ImportError as error:
        raise RuntimeError("evaluation validation requires scikit-learn") from error
    selected = sorted(
        (sample for sample in samples if sample.defense == training_defense),
        key=lambda sample: sample.sample_id,
    )
    labels = np.asarray([sample.class_label for sample in selected])
    splitter = StratifiedKFold(n_splits=10, shuffle=True, random_state=_DLSVM_RANDOM_STATE)
    folds = []
    test_ids: list[str] = []
    for index, (train_indexes, test_indexes) in enumerate(
        splitter.split(np.zeros(len(labels)), labels)
    ):
        training_ids = [selected[int(item)].sample_id for item in train_indexes]
        testing_ids = [selected[int(item)].sample_id for item in test_indexes]
        test_ids.extend(testing_ids)
        folds.append(
            {
                "fold_index": index,
                "training_sample_ids": training_ids,
                "training_sample_ids_sha256": _canonical_json_sha256(training_ids),
                "testing_sample_ids": testing_ids,
                "testing_sample_ids_sha256": _canonical_json_sha256(testing_ids),
            }
        )
    details = {
        "splitter": "sklearn.model_selection.StratifiedKFold",
        "n_splits": 10,
        "shuffle": True,
        "random_state": _DLSVM_RANDOM_STATE,
        "folds": folds,
        "folds_sha256": _canonical_json_sha256(folds),
    }
    return details, len(selected), test_ids


def _validate_dlsvm_cache_receipt(
    value: Any, *, samples: Sequence[StudySample], deep: bool
) -> None:
    if (
        not isinstance(value, Mapping)
        or value.get("schema_version") != 1
        or not isinstance(value.get("path"), str)
        or not isinstance(value.get("artifacts"), Mapping)
        or not value["artifacts"]
    ):
        raise ValueError("formal evaluation DLSVM cache receipt is invalid")
    root = Path(value["path"]).resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("formal evaluation DLSVM cache directory is invalid")
    artifacts = value["artifacts"]
    expected_files: set[str] = set()
    by_id = {sample.sample_id: sample for sample in samples}
    for name, artifact in artifacts.items():
        if not isinstance(name, str) or not isinstance(artifact, Mapping):
            raise ValueError("formal evaluation DLSVM cache artifact is invalid")
        matrix_path = root / name
        receipt_name = artifact.get("receipt")
        if not isinstance(receipt_name, str):
            raise ValueError("formal evaluation DLSVM cache receipt name is invalid")
        seal_path = root / receipt_name
        identity = artifact.get("identity")
        if not isinstance(identity, Mapping):
            raise ValueError("formal evaluation DLSVM cache identity is invalid")
        rows = identity.get("rows")
        columns = identity.get("columns")
        if not isinstance(rows, list) or not isinstance(columns, list):
            raise ValueError("formal evaluation DLSVM cache sample order is invalid")
        try:
            row_samples = [by_id[str(item["sample_id"])] for item in rows]
            column_samples = [by_id[str(item["sample_id"])] for item in columns]
        except (KeyError, TypeError) as error:
            raise ValueError("formal evaluation DLSVM cache sample identity is invalid") from error
        expected_identity = {
            "schema_version": 1,
            "kind": identity.get("kind"),
            "rows": [
                {
                    "sample_id": sample.sample_id,
                    "sequence_sha256": hashlib.sha256(
                        np.asarray(dlsvm_sequence(sample.trace), dtype="<i4").tobytes()
                    ).hexdigest(),
                }
                for sample in row_samples
            ],
            "columns": [
                {
                    "sample_id": sample.sample_id,
                    "sequence_sha256": hashlib.sha256(
                        np.asarray(dlsvm_sequence(sample.trace), dtype="<i4").tobytes()
                    ).hexdigest(),
                }
                for sample in column_samples
            ],
            "backend": dlsvm_backend_receipt(),
        }
        identity_sha256 = _canonical_json_sha256(expected_identity)
        shape = (len(row_samples), len(column_samples))
        if (
            dict(identity) != expected_identity
            or artifact.get("identity_sha256") != identity_sha256
            or artifact.get("sha256") != _sha256_file(matrix_path)
            or artifact.get("receipt_sha256") != _sha256_file(seal_path)
            or artifact.get("rows") != shape[0]
            or artifact.get("columns") != shape[1]
        ):
            raise ValueError("formal evaluation DLSVM cache binding is invalid")
        _validate_dlsvm_matrix_seal(
            matrix_path,
            seal_path,
            identity=expected_identity,
            identity_sha256=identity_sha256,
            shape=shape,
        )
        if deep:
            matrix = np.load(matrix_path, allow_pickle=False)
            _validate_dlsvm_matrix_semantics(
                matrix,
                kind=str(identity["kind"]),
                row_samples=row_samples,
                column_samples=column_samples,
                identity_sha256=identity_sha256,
            )
        expected_files.update({name, receipt_name})
    actual_files = {item.name for item in root.iterdir() if item.is_file()}
    if actual_files != expected_files or any(item.is_symlink() for item in root.iterdir()):
        raise ValueError("formal evaluation DLSVM cache inventory is not closed")


def evaluate_handoff(
    handoff: Path,
    destination: Path,
    *,
    formal: bool,
    bootstrap_draws: int = 10_000,
    dlsvm_available_wall_seconds: float | None = None,
) -> Path:
    """Validate, evaluate, and bind one focused-study handoff in one call."""

    if formal and bootstrap_draws != FORMAL_BOOTSTRAP_DRAWS:
        raise ValueError(
            f"formal evaluation requires exactly {FORMAL_BOOTSTRAP_DRAWS} bootstrap draws"
        )

    # Local import avoids weakening the handoff module's dependency boundary.
    from .buflo_handoff import validate_study_handoff

    destination = require_disjoint_path(
        destination,
        (handoff, LAB_ROOT / "handoffs/classifier-multiorigin5-v2"),
        label="study evaluation destination",
    )
    preflight_candidate = destination.with_name(destination.name + ".dlsvm-preflight.json")
    cache_candidate = destination.with_name(destination.name + ".dlsvm-kernels")
    require_disjoint_path(
        preflight_candidate,
        (handoff, LAB_ROOT / "handoffs/classifier-multiorigin5-v2"),
        label="DLSVM preflight destination",
    )
    require_disjoint_path(
        cache_candidate,
        (handoff, LAB_ROOT / "handoffs/classifier-multiorigin5-v2"),
        label="DLSVM cache destination",
    )
    if formal and _load_osad_library() is None:
        raise RuntimeError("formal DLSVM evaluation requires the clean-room native OSA backend")
    if formal and _load_weka_backend() is None:
        raise RuntimeError("formal VNG++ evaluation requires the pinned Weka 3.7.5 backend")
    root = validate_study_handoff(handoff, formal=formal, deep=True)
    samples = load_study_handoff(root)
    if formal:
        validate_formal_cohort(samples, require_performance=True)
    preflight_path: Path | None = None
    if formal:
        preflight_path = preflight_candidate
        if preflight_path.exists() or preflight_path.is_symlink():
            validate_dlsvm_preflight(
                preflight_path,
                samples=samples,
                handoff_root=root,
                formal=True,
            )
        else:
            write_dlsvm_preflight(
                preflight_path,
                samples=samples,
                handoff_root=root,
                formal=True,
                available_wall_seconds=dlsvm_available_wall_seconds,
            )
    cache_directory = cache_candidate
    dlsvm_store = DlsvmKernelStore(samples, cache_directory=cache_directory)
    temporal = run_temporal_attacks(samples, dlsvm_store=dlsvm_store)
    historical = run_historical_attacks(samples, dlsvm_store=dlsvm_store)
    return write_evaluation_receipt(
        destination,
        samples=samples,
        attack_results=(*temporal, *historical),
        bootstrap_draws=bootstrap_draws,
        handoff_root=root,
        formal=formal,
        dlsvm_preflight=preflight_path,
        dlsvm_cache=dlsvm_store.receipt(),
    )


def attack_bootstrap_intervals(
    result: AttackResult,
    *,
    draws: int = 10_000,
    seed: int = 20260827,
) -> dict[str, Any]:
    """Bootstrap attack metrics over acquisition-block/workload clusters."""

    if draws <= 0 or not result.predictions:
        raise ValueError("attack bootstrap requires positive draws and predictions")
    clusters: dict[tuple[int, str], list[AttackPrediction]] = defaultdict(list)
    for prediction in result.predictions:
        clusters[(prediction.acquisition_block_index, prediction.workload_id)].append(prediction)
    keys = sorted(clusters)
    rng = np.random.default_rng(seed)
    accuracy = np.empty(draws, dtype=np.float64)
    balanced = np.empty(draws, dtype=np.float64)
    recalls = {label: np.empty(draws, dtype=np.float64) for label in result.labels}
    for draw in range(draws):
        indexes = rng.integers(0, len(keys), size=len(keys))
        selected = [item for index in indexes for item in clusters[keys[int(index)]]]
        expected = [item.expected for item in selected]
        predicted = [item.predicted for item in selected]
        accuracy[draw], balanced[draw], _, per_class = _classification_metrics(
            expected, predicted, result.labels
        )
        for label in result.labels:
            recalls[label][draw] = per_class[label]

    def interval(values: np.ndarray) -> dict[str, float]:
        return {
            "low": float(np.quantile(values, 0.025)),
            "high": float(np.quantile(values, 0.975)),
        }

    return {
        "draws": draws,
        "seed": seed,
        "cluster": "acquisition_block_index+workload_id",
        "accuracy": interval(accuracy),
        "balanced_accuracy": interval(balanced),
        "per_class_recall": {label: interval(values) for label, values in sorted(recalls.items())},
    }


def _fit_predict_attack(
    attack: str,
    training: Sequence[StudySample],
    testing: Sequence[StudySample],
    *,
    training_defense: str,
    testing_defense: str,
    protocol: str,
    dlsvm_store: DlsvmKernelStore | None,
) -> AttackResult:
    if not training or not testing:
        raise ValueError("attack evaluation requires non-empty train and test sets")
    try:
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.svm import SVC
    except ImportError as error:
        raise RuntimeError(
            "attack evaluation requires the pinned 'evaluation' optional dependency"
        ) from error

    train_labels = [sample.class_label for sample in training]
    test_labels = [sample.class_label for sample in testing]
    labels = tuple(sorted(set(train_labels) | set(test_labels)))
    if set(train_labels) != set(test_labels):
        raise ValueError("attack train/test class sets differ")

    backend: str
    if attack == "panchenko":
        # The historical attack uses an RBF kernel, for which libsvm forms a
        # dense kernel matrix regardless.  Dense vectors also avoid scipy's
        # platform-dependent sparse index width entering the evidence path.
        vectorizer = DictVectorizer(sparse=False, sort=True)
        train_x = vectorizer.fit_transform(
            [panchenko_features(sample.trace) for sample in training]
        )
        test_x = vectorizer.transform([panchenko_features(sample.trace) for sample in testing])
        classifier = SVC(C=131_072, gamma=2**-19, kernel="rbf")
        classifier.fit(train_x, train_labels)
        predicted = classifier.predict(test_x)
        backend = "clean-room-libsvm-compatible-rbf"
    elif attack == "vngpp":
        weka = _load_weka_backend()
        if weka is not None:
            predicted = _weka_vngpp_predict(training, testing, weka)
            backend = "pinned-author-weka-3.7.5-kernel-naive-bayes"
        else:
            try:
                from sklearn.naive_bayes import GaussianNB
            except ImportError as error:
                raise RuntimeError(
                    "contextual VNG++ fallback requires the pinned evaluation dependency"
                ) from error
            vectorizer = DictVectorizer(sparse=False, sort=True)
            train_x = vectorizer.fit_transform(
                [vngpp_features(sample.trace) for sample in training]
            )
            test_x = vectorizer.transform([vngpp_features(sample.trace) for sample in testing])
            classifier = GaussianNB()
            classifier.fit(train_x, train_labels)
            predicted = classifier.predict(test_x)
            backend = "clean-room-gaussian-nb-contextual-nonformal-only"
    elif attack == "dlsvm":
        if dlsvm_store is None:
            raise ValueError("DLSVM evaluation has no shared kernel store")
        train_kernel, test_kernel = dlsvm_store.kernels(training, testing)
        classifier = SVC(C=4, kernel="precomputed")
        classifier.fit(train_kernel, train_labels)
        predicted = classifier.predict(test_kernel)
        backend = (
            "clean-room-ccs12-restricted-osa-svm-native"
            if _load_osad_library() is not None
            else "clean-room-ccs12-restricted-osa-svm-python"
        )
    else:
        raise ValueError(f"unsupported attack: {attack}")
    accuracy, balanced, matrix, recalls = _classification_metrics(
        test_labels, [str(value) for value in predicted], labels
    )
    return AttackResult(
        attack=attack,
        backend=backend,
        training_defense=training_defense,
        testing_defense=testing_defense,
        protocol=protocol,
        train_samples=len(training),
        test_samples=len(testing),
        labels=labels,
        accuracy=accuracy,
        balanced_accuracy=balanced,
        confusion_matrix=matrix,
        per_class_recall=recalls,
        predictions=tuple(
            AttackPrediction(
                sample_id=sample.sample_id,
                acquisition_block_index=sample.acquisition_block_index,
                workload_id=sample.workload_id,
                expected=expected,
                predicted=str(guess),
            )
            for sample, expected, guess in zip(testing, test_labels, predicted, strict=True)
        ),
        protocol_details={
            "training_sample_ids": [sample.sample_id for sample in training],
            "training_sample_ids_sha256": _canonical_json_sha256(
                [sample.sample_id for sample in training]
            ),
            "testing_sample_ids": [sample.sample_id for sample in testing],
            "testing_sample_ids_sha256": _canonical_json_sha256(
                [sample.sample_id for sample in testing]
            ),
        },
    )


def _dlsvm_kernel(
    left: Sequence[Sequence[int]],
    right: Sequence[Sequence[int]],
    *,
    symmetric: bool,
) -> np.ndarray:
    left_values = tuple(_dlsvm_value_tuple(value) for value in left)
    right_values = tuple(_dlsvm_value_tuple(value) for value in right)
    if symmetric and left_values != right_values:
        raise ValueError("symmetric DLSVM kernel requires identical sequence order")
    kernel = np.empty((len(left_values), len(right_values)), dtype=np.float64)

    def calculate_row(left_index: int) -> tuple[int, int, tuple[float, ...]]:
        start = left_index if symmetric else 0
        values = tuple(
            math.exp(
                -(_cached_normalized_dlsvm_distance_canonical(left_values[left_index], item) ** 2)
            )
            for item in right_values[start:]
        )
        return left_index, start, values

    indexes = range(len(left_values))
    loaded = _load_osad_library()
    if loaded is not None and len(left_values) * len(right_values) >= 1_000:
        with ThreadPoolExecutor(max_workers=_osad_workers()) as executor:
            rows = executor.map(calculate_row, indexes)
            for left_index, start, values in rows:
                kernel[left_index, start:] = values
                if symmetric:
                    kernel[start:, left_index] = values
    else:
        for left_index in indexes:
            _, start, values = calculate_row(left_index)
            kernel[left_index, start:] = values
            if symmetric:
                kernel[start:, left_index] = values
    return kernel


def _cached_normalized_dlsvm_distance_canonical(
    left: tuple[int, ...], right: tuple[int, ...]
) -> float:
    return (
        _cached_normalized_dlsvm_distance(right, left)
        if right < left
        else _cached_normalized_dlsvm_distance(left, right)
    )


def _osad_workers() -> int:
    configured = os.environ.get("QCSD_OSAD_WORKERS")
    if configured is None:
        return max(1, min(12, os.cpu_count() or 1))
    try:
        workers = int(configured)
    except ValueError as error:
        raise ValueError("QCSD_OSAD_WORKERS must be an integer") from error
    if not 1 <= workers <= 256:
        raise ValueError("QCSD_OSAD_WORKERS must be between 1 and 256")
    return workers


def _classification_metrics(
    expected: Sequence[str],
    predicted: Sequence[str],
    labels: Sequence[str],
) -> tuple[float, float, tuple[tuple[int, ...], ...], dict[str, float]]:
    if len(expected) != len(predicted) or not expected:
        raise ValueError("classification vectors are invalid")
    indexes = {label: index for index, label in enumerate(labels)}
    matrix = [[0 for _ in labels] for _ in labels]
    for actual, guess in zip(expected, predicted, strict=True):
        if actual not in indexes or guess not in indexes:
            raise ValueError("classification label is outside the declared set")
        matrix[indexes[actual]][indexes[guess]] += 1
    recalls: dict[str, float] = {}
    for label, row in zip(labels, matrix, strict=True):
        total = sum(row)
        recalls[label] = row[indexes[label]] / total if total else 0.0
    correct = sum(matrix[index][index] for index in range(len(labels)))
    accuracy = correct / len(expected)
    balanced = math.fsum(recalls.values()) / len(labels)
    return accuracy, balanced, tuple(tuple(row) for row in matrix), recalls


def _aggregate_fold_results(
    folds: Sequence[AttackResult], *, unique_samples: int, random_state: int
) -> AttackResult:
    if len(folds) != 10:
        raise ValueError("historical attack aggregation requires exactly ten folds")
    first = folds[0]
    if any(
        result.attack != first.attack
        or result.backend != first.backend
        or result.labels != first.labels
        or result.training_defense != first.training_defense
        or result.testing_defense != first.testing_defense
        or result.protocol != first.protocol
        for result in folds
    ):
        raise ValueError("historical attack folds have inconsistent identities")
    matrix = [
        [
            sum(result.confusion_matrix[row][column] for result in folds)
            for column in range(len(first.labels))
        ]
        for row in range(len(first.labels))
    ]
    recalls: dict[str, float] = {}
    for index, label in enumerate(first.labels):
        total = sum(matrix[index])
        recalls[label] = matrix[index][index] / total if total else 0.0
    tested = sum(sum(row) for row in matrix)
    correct = sum(matrix[index][index] for index in range(len(first.labels)))
    fold_membership = [
        {
            "fold_index": index,
            **dict(result.protocol_details),
        }
        for index, result in enumerate(folds)
    ]
    return AttackResult(
        attack=first.attack,
        backend=first.backend,
        training_defense=first.training_defense,
        testing_defense=first.testing_defense,
        protocol=first.protocol,
        train_samples=unique_samples,
        test_samples=tested,
        labels=first.labels,
        accuracy=correct / tested,
        balanced_accuracy=math.fsum(recalls.values()) / len(recalls),
        confusion_matrix=tuple(tuple(row) for row in matrix),
        per_class_recall=recalls,
        predictions=tuple(prediction for result in folds for prediction in result.predictions),
        protocol_details={
            "splitter": "sklearn.model_selection.StratifiedKFold",
            "n_splits": 10,
            "shuffle": True,
            "random_state": random_state,
            "folds": fold_membership,
            "folds_sha256": _canonical_json_sha256(fold_membership),
        },
    )


def _direction_bursts(
    trace: Sequence[ShapePacket],
) -> Iterable[tuple[str, tuple[ShapePacket, ...]]]:
    if not trace:
        return
    direction = trace[0].direction
    burst: list[ShapePacket] = []
    for packet in trace:
        if packet.direction != direction:
            yield direction, tuple(burst)
            direction = packet.direction
            burst = []
        burst.append(packet)
    if burst:
        yield direction, tuple(burst)


def _round_to(value: float, base: int) -> int:
    if base <= 0 or not math.isfinite(value):
        raise ValueError("rounding requires a finite value and positive base")
    scaled = float(value) / base
    # The pinned classifiers execute under Python 2, whose round() resolves
    # half-way values away from zero.  Python 3's bankers rounding would alter
    # burst, count, percentage, and bandwidth markers at exact boundaries.
    rounded = math.floor(scaled + 0.5) if scaled >= 0 else math.ceil(scaled - 0.5)
    return int(base * rounded)


def _author_packet_time_ms(relative_time_ns: int) -> int:
    """Reproduce the pinned parser's non-negative Python-2 millisecond rounding."""

    if type(relative_time_ns) is not int or relative_time_ns < 0:
        raise ValueError("author packet time requires non-negative integer nanoseconds")
    return (relative_time_ns + 500_000) // 1_000_000


def _panchenko_count_marker(value: int) -> int:
    if value in {4, 5}:
        return 3
    if value in {7, 8}:
        return 6
    if value in {10, 11, 12, 13}:
        return 9
    return value


def _quantiles(rows: Sequence[Mapping[str, Any]], field: str) -> dict[str, float]:
    return _numeric_quantiles([float(row[field]) for row in rows])


def _numeric_quantiles(values: Sequence[int | float]) -> dict[str, float]:
    observations = np.asarray(values, dtype=np.float64)
    if not observations.size or not np.all(np.isfinite(observations)):
        raise ValueError("quantiles require finite observations")
    return {
        "p50": float(np.quantile(observations, 0.50)),
        "p90": float(np.quantile(observations, 0.90)),
        "p95": float(np.quantile(observations, 0.95)),
    }


def _cluster_bootstrap_ratio(
    rows: Sequence[Mapping[str, Any]],
    *,
    numerator: str,
    denominator: str,
    draws: int,
    seed: int,
) -> dict[str, float | int]:
    if draws <= 0:
        raise ValueError("bootstrap draws must be positive")
    clusters: dict[tuple[int, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        clusters[(int(row["acquisition_block_index"]), str(row["workload_id"]))].append(row)
    keys = sorted(clusters)
    if not keys:
        raise ValueError("bootstrap requires at least one cluster")
    rng = np.random.default_rng(seed)
    estimates = np.empty(draws, dtype=np.float64)
    for draw in range(draws):
        sampled = rng.integers(0, len(keys), size=len(keys))
        selected = [row for index in sampled for row in clusters[keys[int(index)]]]
        estimates[draw] = ratio_of_sums(
            (float(row[numerator]) for row in selected),
            (float(row[denominator]) for row in selected),
        )
    return {
        "draws": draws,
        "seed": seed,
        "low": float(np.quantile(estimates, 0.025)),
        "high": float(np.quantile(estimates, 0.975)),
    }


def _cluster_bootstrap_goodput_ratio(
    rows: Sequence[Mapping[str, Any]], *, draws: int, seed: int
) -> dict[str, float | int]:
    if draws <= 0:
        raise ValueError("bootstrap draws must be positive")
    clusters: dict[tuple[int, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        clusters[(int(row["acquisition_block_index"]), str(row["workload_id"]))].append(row)
    keys = sorted(clusters)
    if not keys:
        raise ValueError("bootstrap requires at least one cluster")
    rng = np.random.default_rng(seed)
    estimates = np.empty(draws, dtype=np.float64)
    for draw in range(draws):
        sampled = rng.integers(0, len(keys), size=len(keys))
        selected = [row for index in sampled for row in clusters[keys[int(index)]]]
        defended = ratio_of_sums(
            (float(row["defended_application_response_bytes"]) for row in selected),
            (float(row["defended_duration_ns"]) / 1_000_000_000 for row in selected),
        )
        baseline = ratio_of_sums(
            (float(row["baseline_application_response_bytes"]) for row in selected),
            (float(row["baseline_duration_ns"]) / 1_000_000_000 for row in selected),
        )
        estimates[draw] = defended / baseline
    return {
        "draws": draws,
        "seed": seed,
        "low": float(np.quantile(estimates, 0.025)),
        "high": float(np.quantile(estimates, 0.975)),
    }


def _cluster_bootstrap_difference(
    rows: Sequence[Mapping[str, Any]],
    *,
    defended: str,
    baseline: str,
    draws: int,
    seed: int,
    scale: float = 1.0,
) -> dict[str, float | int]:
    if draws <= 0 or not math.isfinite(scale):
        raise ValueError("bootstrap draws and scale are invalid")
    clusters: dict[tuple[int, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        clusters[(int(row["acquisition_block_index"]), str(row["workload_id"]))].append(row)
    keys = sorted(clusters)
    if not keys:
        raise ValueError("bootstrap requires at least one cluster")
    rng = np.random.default_rng(seed)
    estimates = np.empty(draws, dtype=np.float64)
    for draw in range(draws):
        sampled = rng.integers(0, len(keys), size=len(keys))
        selected = [row for index in sampled for row in clusters[keys[int(index)]]]
        estimates[draw] = math.fsum(
            (float(row[defended]) - float(row[baseline])) * scale for row in selected
        ) / len(selected)
    return {
        "draws": draws,
        "seed": seed,
        "low": float(np.quantile(estimates, 0.025)),
        "high": float(np.quantile(estimates, 0.975)),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
