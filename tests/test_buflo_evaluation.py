from __future__ import annotations

import hashlib
import json
import math
import random
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

import qcsd_lab.buflo_evaluation as evaluation
from qcsd_lab.buflo_evaluation import (
    FORMAL_CLASS_BY_WORKLOAD,
    AttackResult,
    DlsvmKernelStore,
    ShapePacket,
    StudySample,
    admit_dlsvm_preflight_capacity,
    algorithm_breakdowns,
    attack_bootstrap_intervals,
    damerau_levenshtein_distance,
    dlsvm_reference_receipt,
    dlsvm_sequence,
    dlsvm_workload_census,
    load_study_handoff,
    normalized_dlsvm_distance,
    original_study_comparison_rows,
    paired_overheads,
    panchenko_features,
    performance_breakdowns,
    ratio_of_sums,
    run_historical_attacks,
    run_temporal_attacks,
    summarize_paired_overheads,
    validate_dlsvm_preflight,
    validate_formal_cohort,
    vngpp_features,
    write_dlsvm_preflight,
)
from qcsd_lab.class_evaluation import CLASS_DLSVM_EXECUTION_MODEL
from qcsd_lab.fidelity import (
    BUFLO_SCHEDULE_STOP_POLICY,
    BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS,
    BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
    BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
    BUFLO_TERMINAL_SUBCELL_POLICY,
)

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


def _trace(scale: int = 1) -> tuple[ShapePacket, ...]:
    return (
        ShapePacket(0, "outgoing", 100 * scale),
        ShapePacket(1_000_000, "incoming", 200 * scale),
        ShapePacket(2_000_000, "incoming", 300 * scale),
        ShapePacket(3_000_000, "outgoing", 120 * scale),
    )


def _sample(
    sample_id: str,
    label: str,
    defense: str,
    block: int,
    paired: str,
    *,
    scale: int = 1,
) -> StudySample:
    return StudySample(sample_id, label, label, defense, block, paired, _trace(scale))


def test_reference_attack_feature_maps_use_only_shape_fields() -> None:
    trace = _trace()
    panchenko = panchenko_features(trace)
    assert panchenko["packet/outgoing/100"] == 1
    assert panchenko["packet/incoming/200"] == 1
    assert panchenko["burst-count/incoming/2"] == 1
    assert panchenko["packet-count/outgoing"] == 0
    assert panchenko["percentage/incoming"] == 50

    vngpp = vngpp_features(trace)
    assert vngpp["bandwidth/outgoing"] == 220
    assert vngpp["bandwidth/incoming"] == 500
    assert vngpp["duration-ms"] == 3
    assert dlsvm_sequence(trace) == (100, -200, -300, 120)


def test_dlsvm_reference_and_bundled_libsvm_are_hash_bound() -> None:
    reference = dlsvm_reference_receipt()
    assert reference["sha256"] == evaluation._DLSVM_REFERENCE_SHA256
    assert reference["receipt_sha256"] == evaluation._DLSVM_REFERENCE_RECEIPT_SHA256
    runtime = evaluation.dlsvm_backend_receipt()["runtime"]
    assert runtime["libsvm_implementation"] == "scikit-learn-bundled-libsvm"
    assert len(runtime["libsvm_module_sha256"]) == 64
    assert runtime["scikit_learn_version"]


def test_classifier_markers_retain_python2_half_away_rounding() -> None:
    assert evaluation._round_to(300, 600) == 600
    assert evaluation._round_to(2.5, 5) == 5
    assert evaluation._round_to(-300, 600) == -600


def test_vngpp_duration_uses_pinned_pcapparser_integer_milliseconds() -> None:
    below_half = (ShapePacket(3_499_999, "outgoing", 100),)
    exact_half = (ShapePacket(3_500_000, "outgoing", 100),)

    assert vngpp_features(below_half)["duration-ms"] == 3
    assert vngpp_features(exact_half)["duration-ms"] == 4
    reference = json.loads(evaluation._CLASSIFIER_REFERENCE.read_text(encoding="utf-8"))
    assert reference["feature_semantics"]["common"]["trace_time"] == (
        "maximum of per-packet times quantized by pcapparser.py as "
        "int(round((ts-start)*1000,0)) under Python 2 (non-negative half-way values round up)"
    )


def test_pinned_weka_vngpp_backend_when_installed() -> None:
    evaluation._load_weka_backend.cache_clear()
    backend = evaluation._load_weka_backend()
    if backend is None:
        pytest.skip("the pinned Weka 3.7.5 backend is not installed")
    training = [
        _sample("a-1", "a", "undefended", 0, "a-1", scale=1),
        _sample("a-2", "a", "undefended", 1, "a-2", scale=1),
        _sample("b-1", "b", "undefended", 0, "b-1", scale=8),
        _sample("b-2", "b", "undefended", 1, "b-2", scale=9),
    ]
    testing = [
        _sample("a-3", "a", "undefended", 2, "a-3", scale=1),
        _sample("b-3", "b", "undefended", 2, "b-3", scale=8),
    ]
    predicted = evaluation._weka_vngpp_predict(training, testing, backend)
    assert predicted == ("a", "b")
    receipt = evaluation.vngpp_backend_receipt()
    assert receipt["backend"] == "pinned-weka-3.7.5"
    assert [item["sha256"] for item in receipt["runtime"]["artifacts"]] == list(
        evaluation._WEKA_ARTIFACTS.values()
    )


def test_classifier_primary_reference_receipt_is_byte_exact() -> None:
    receipt = evaluation.classifier_reference_receipt()
    assert receipt["reference_sha256"] == evaluation._CLASSIFIER_REFERENCE_SHA256
    assert receipt["receipt_sha256"] == evaluation._CLASSIFIER_REFERENCE_RECEIPT_SHA256
    reference = json.loads(evaluation._CLASSIFIER_REFERENCE.read_text(encoding="utf-8"))
    resolution = reference["author_artifact"]["panchenko"]["runtime_resolution"]
    assert resolution["status"] == "clean-room-backend-required"
    assert "not a checksum-pinned Weka LibSVM" in resolution["reason"]


def test_original_study_comparison_is_row_complete_and_preserves_anchors() -> None:
    rows = original_study_comparison_rows()

    assert len(rows) == 16
    assert len({row["anchor_id"] for row in rows}) == 16
    assert all(row["result_scope"] == "original-study" for row in rows)
    assert all(_COMPARISON_CONTEXT_FIELDS <= row.keys() for row in rows)

    first_buflo = next(
        row
        for row in rows
        if row["metrics"].get("profile") == {"tau_ms": 0, "rho_ms": 40, "d_bytes": 1000}
    )
    assert first_buflo["metrics"]["extra_bandwidth_percent"] == 93.5
    assert first_buflo["metrics"]["latency_seconds"] == 6.0
    assert first_buflo["metrics"]["accuracy"]["panchenko"] == {
        "mean_percent": 27.3,
        "plus_minus_percent": 1.8,
    }
    assert first_buflo["anchor_id"] == "buflo-tau0-rho40-d1000"

    ctsp_200 = next(
        row
        for row in rows
        if row["metrics"].get("sites") == 200 and row["metrics"].get("padding_profile") == "CTSP"
    )
    assert ctsp_200["metrics"]["bandwidth_ratio"] == 2.796
    assert ctsp_200["metrics"]["latency_ratio"] == 3.271
    assert ctsp_200["metrics"]["dlsvm_percent"] == 20.6

    cpsp_et = next(
        row
        for row in rows
        if "early-termination ablation" in row["source"]
        and row["metrics"]["padding_profile"] == "CPSP"
        and row["metrics"]["early_termination"] is True
    )
    assert cpsp_et["metrics"]["bandwidth_ratio"] == 2.6
    assert cpsp_et["metrics"]["latency_ratio"] == 2.87
    assert cpsp_et["metrics"]["vng_plus_plus_percent"] == 34.2

    inventory = evaluation.historical_anchor_metric_inventory(rows)
    assert len(inventory) == 16
    assert sum(len(item["metric_paths"]) for item in inventory) == 136
    first_inventory = next(
        item for item in inventory if item["anchor_id"] == first_buflo["anchor_id"]
    )
    assert "extra_bandwidth_percent" in first_inventory["metric_paths"]
    assert "accuracy.panchenko.mean_percent" in first_inventory["metric_paths"]
    assert "profile.tau_ms" not in first_inventory["metric_paths"]


def test_qcsd_numeric_comparison_remains_unreviewed_until_explained() -> None:
    samples = (
        _sample("u", "site", "undefended", 0, "pair"),
        _sample("b", "site", "buflo", 0, "pair", scale=2),
    )
    summary = summarize_paired_overheads(paired_overheads(samples), bootstrap_draws=5)

    (row,) = evaluation._qcsd_comparison_rows(samples, summary, ())

    assert row["numeric_discrepancy_classification"] == "unreviewed"
    assert row["numeric_discrepancy_explanation"] is None
    assert row["attestation_eligible"] is False
    assert all(
        difference["classification"] == "expected"
        for difference in row["known_expected_differences"]
    )
    assert any(
        difference["difference"] == "buflo-terminal-subcell-client-local-cancellation"
        for difference in row["known_expected_differences"]
    )


def test_cs_comparison_labels_local_cadence_and_eventual_consumption() -> None:
    samples = (
        _sample("u", "site", "undefended", 0, "pair"),
        _sample("c", "site", "cs-buflo", 0, "pair", scale=2),
    )
    summary = summarize_paired_overheads(paired_overheads(samples), bootstrap_draws=5)

    (row,) = evaluation._qcsd_comparison_rows(samples, summary, ())

    assert row["incoming_boundary_semantics"] == {
        "cadence": "complete_local_on_wire_max_stream_data_advertisement",
        "terminal": "eventual_peer_stream_offset_consumption",
        "separation": (
            "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption"
        ),
    }
    assert any(
        item["difference"] == "csbuflo-incoming-boundary-translation"
        for item in row["known_expected_differences"]
    )


def test_dlsvm_weighted_transposition_and_normalization() -> None:
    assert damerau_levenshtein_distance((1, 2), (2, 1)) == pytest.approx(0.1)
    assert normalized_dlsvm_distance((1, 2), (2, 1)) == pytest.approx(0.05)
    assert normalized_dlsvm_distance((), ()) == 0
    assert normalized_dlsvm_distance((), (1, 2)) == 4
    with pytest.raises(ValueError, match="operation costs"):
        damerau_levenshtein_distance((1,), (1,), transposition_cost=0)


def test_native_osad_accelerator_matches_clean_room_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is unavailable")
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
    monkeypatch.setenv("QCSD_OSAD_LIBRARY", str(library))
    evaluation._load_osad_library.cache_clear()
    evaluation._cached_normalized_dlsvm_distance.cache_clear()
    evaluation._native_osad_values.cache_clear()
    generator = random.Random(20260827)
    try:
        for _ in range(50):
            left = tuple(generator.randrange(-4, 5) for _ in range(generator.randrange(0, 12)))
            right = tuple(generator.randrange(-4, 5) for _ in range(generator.randrange(0, 12)))
            raw = damerau_levenshtein_distance(left, right)
            denominator = min(len(left), len(right))
            expected = raw / denominator if denominator else raw
            assert normalized_dlsvm_distance(left, right) == pytest.approx(expected)
        assert evaluation.dlsvm_backend_receipt()["engine"] == "clean-room-native-c"
    finally:
        evaluation._load_osad_library.cache_clear()
        evaluation._cached_normalized_dlsvm_distance.cache_clear()
        evaluation._native_osad_values.cache_clear()


def test_dlsvm_kernel_store_persists_exact_matrices(tmp_path: Path) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    store = DlsvmKernelStore(samples, cache_directory=cache)
    first, testing = store.kernels(samples, samples)
    receipt = store.receipt()

    assert first.shape == testing.shape == (2, 2)
    assert receipt is not None and len(receipt["artifacts"]) == 1
    artifact = next(cache.glob("*.npy"))
    second_store = DlsvmKernelStore(samples, cache_directory=cache)
    second, _ = second_store.kernels(samples, samples)
    assert second.tolist() == first.tolist()
    assert second_store.receipt() == receipt

    artifact.write_bytes(b"not-an-npy")
    broken = DlsvmKernelStore(samples, cache_directory=cache)
    with pytest.raises((ValueError, OSError), match="cached|pickle|load|format"):
        broken.kernels(samples, samples)


def test_dlsvm_matrix_creation_and_replay_bypass_pair_result_cache(
    tmp_path: Path,
) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    sequences = tuple(dlsvm_sequence(sample.trace) for sample in samples)
    expected = np.asarray(
        [
            [math.exp(-(normalized_dlsvm_distance(left, right) ** 2)) for right in sequences]
            for left in sequences
        ],
        dtype=np.float64,
    )
    assert evaluation._cached_normalized_dlsvm_distance.cache_info().currsize > 0
    evaluation._cached_normalized_dlsvm_distance.cache_clear()
    cache = tmp_path / "kernels"
    try:
        created, _ = DlsvmKernelStore(samples, cache_directory=cache).kernels(samples, samples)
        assert np.array_equal(created, expected)
        assert evaluation._cached_normalized_dlsvm_distance.cache_info().currsize == 0

        replayed, _ = DlsvmKernelStore(samples, cache_directory=cache).kernels(samples, samples)
        assert np.array_equal(replayed, created)
        assert evaluation._cached_normalized_dlsvm_distance.cache_info().currsize == 0
    finally:
        evaluation._cached_normalized_dlsvm_distance.cache_clear()


def test_dlsvm_kernel_store_excludes_concurrent_cache_lifecycles(
    tmp_path: Path,
) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    first = DlsvmKernelStore(samples, cache_directory=cache)
    try:
        with pytest.raises(RuntimeError, match="lifecycle lock"):
            DlsvmKernelStore(samples, cache_directory=cache)
    finally:
        first.close()

    resumed = DlsvmKernelStore(samples, cache_directory=cache)
    resumed.close()


def test_dlsvm_kernel_store_discards_only_recognised_crash_temporaries(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "kernels"
    cache.mkdir()
    recognised = cache / (f".within-{'a' * 64}.npy{evaluation.ATOMIC_TEMP_MARKER}deadbeef")
    unrelated = cache / ".unrelated.qcsd-tmp-deadbeef"
    recognised.write_bytes(b"uncommitted")
    unrelated.write_bytes(b"retain")

    store = DlsvmKernelStore((), cache_directory=cache)
    try:
        assert not recognised.exists()
        assert unrelated.read_bytes() == b"retain"
    finally:
        store.close()


def test_dlsvm_kernel_store_rejects_symbolic_cache_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    cache = tmp_path / "kernels"
    cache.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        DlsvmKernelStore((), cache_directory=cache)


def test_dlsvm_kernel_store_replays_complete_cache_read_only(tmp_path: Path) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    created_store = DlsvmKernelStore(samples, cache_directory=cache)
    created, _ = created_store.kernels(samples, samples)
    receipt = created_store.receipt()
    assert receipt is not None
    for item in cache.iterdir():
        item.chmod(0o400)
    cache.chmod(0o500)
    try:
        replayed_store = DlsvmKernelStore(
            samples,
            cache_directory=cache,
            cache_read_only=True,
        )
        replayed, _ = replayed_store.kernels(samples, samples)
        assert np.array_equal(replayed, created)
        assert replayed_store.receipt() == receipt
    finally:
        cache.chmod(0o700)
        for item in cache.iterdir():
            item.chmod(0o600)


def test_read_only_dlsvm_store_never_repairs_incomplete_cache(tmp_path: Path) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    created_store = DlsvmKernelStore(samples, cache_directory=cache)
    created_store.kernels(samples, samples)
    receipt = created_store.receipt()
    assert receipt is not None
    seal = cache / next(iter(receipt["artifacts"].values()))["receipt"]
    seal.unlink()

    replayed_store = DlsvmKernelStore(
        samples,
        cache_directory=cache,
        cache_read_only=True,
    )
    try:
        with pytest.raises(ValueError, match="complete sealed matrix"):
            replayed_store.kernels(samples, samples)
        assert not seal.exists()
    finally:
        replayed_store.close()


def test_read_only_dlsvm_store_rejects_temporary_without_deleting_it(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "kernels"
    cache.mkdir()
    (cache / evaluation._DLSVM_CACHE_LOCK_NAME).write_bytes(b"")
    temporary = cache / (f".within-{'a' * 64}.npy{evaluation.ATOMIC_TEMP_MARKER}interrupted")
    temporary.write_bytes(b"uncommitted")

    with pytest.raises(ValueError, match="uncommitted temporary"):
        DlsvmKernelStore((), cache_directory=cache, cache_read_only=True)
    assert temporary.read_bytes() == b"uncommitted"


def test_dlsvm_kernel_store_recovers_exact_matrix_without_seal(
    tmp_path: Path,
) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    created_store = DlsvmKernelStore(samples, cache_directory=cache)
    created, _ = created_store.kernels(samples, samples)
    receipt = created_store.receipt()
    assert receipt is not None
    matrix = next(cache.glob("*.npy"))
    seal = cache / next(iter(receipt["artifacts"].values()))["receipt"]
    seal.unlink()

    resumed_store = DlsvmKernelStore(samples, cache_directory=cache)
    resumed, _ = resumed_store.kernels(samples, samples)
    resumed_receipt = resumed_store.receipt()
    assert np.array_equal(resumed, created)
    assert seal.is_file()
    assert resumed_receipt == receipt
    assert evaluation.sha256_file(matrix) == next(iter(receipt["artifacts"].values()))["sha256"]


def test_dlsvm_kernel_store_recovers_exact_seal_without_matrix(
    tmp_path: Path,
) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    created_store = DlsvmKernelStore(samples, cache_directory=cache)
    created, _ = created_store.kernels(samples, samples)
    receipt = created_store.receipt()
    assert receipt is not None
    matrix = next(cache.glob("*.npy"))
    matrix.unlink()

    resumed_store = DlsvmKernelStore(samples, cache_directory=cache)
    resumed, _ = resumed_store.kernels(samples, samples)
    resumed_receipt = resumed_store.receipt()
    assert np.array_equal(resumed, created)
    assert matrix.is_file()
    assert resumed_receipt == receipt


def test_native_threaded_dlsvm_matrix_creation_and_replay_are_cache_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is unavailable")
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
    )
    monkeypatch.setenv("QCSD_OSAD_LIBRARY", str(library))
    monkeypatch.setenv("QCSD_OSAD_WORKERS", "2")
    monkeypatch.setattr(evaluation.os, "sched_getaffinity", lambda _pid: {0, 1})
    monkeypatch.setattr(
        evaluation,
        "_cgroup_cpu_quota_runtime",
        lambda: {
            "schema_version": 1,
            "source": "test-unlimited",
            "constraints": [],
            "finite_worker_limit": None,
            "unavailable_reason": "test fixture",
        },
    )
    evaluation._load_osad_library.cache_clear()
    samples = tuple(
        _sample(f"sample-{index:02d}", "site", "buflo", index % 10, str(index), scale=index + 1)
        for index in range(32)
    )
    sequences = tuple(dlsvm_sequence(sample.trace) for sample in samples)
    expected = np.asarray(
        [
            [math.exp(-(normalized_dlsvm_distance(left, right) ** 2)) for right in sequences]
            for left in sequences
        ],
        dtype=np.float64,
    )
    evaluation._cached_normalized_dlsvm_distance.cache_clear()
    cache = tmp_path / "kernels"
    try:
        created_store = DlsvmKernelStore(samples, cache_directory=cache)
        created, _ = created_store.kernels(samples, samples)
        created_receipt = created_store.receipt()
        assert np.array_equal(created, expected)
        assert evaluation._cached_normalized_dlsvm_distance.cache_info().currsize == 0

        replayed_store = DlsvmKernelStore(samples, cache_directory=cache)
        replayed, _ = replayed_store.kernels(samples, samples)
        assert np.array_equal(replayed, created)
        assert replayed_store.receipt() == created_receipt
        assert evaluation._cached_normalized_dlsvm_distance.cache_info().currsize == 0
    finally:
        evaluation._cached_normalized_dlsvm_distance.cache_clear()
        evaluation._load_osad_library.cache_clear()


def test_dlsvm_kernel_store_rejects_same_shape_finite_matrix_forgery(
    tmp_path: Path,
) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    DlsvmKernelStore(samples, cache_directory=cache).kernels(samples, samples)
    artifact = next(cache.glob("*.npy"))
    with artifact.open("wb") as output:
        np.save(output, np.full((2, 2), 0.25, dtype=np.float64), allow_pickle=False)

    broken = DlsvmKernelStore(samples, cache_directory=cache)
    with pytest.raises(ValueError, match="receipt|semantic|invariant"):
        broken.kernels(samples, samples)


def test_dlsvm_resume_credit_cleans_temporary_and_credits_lone_matrix(
    tmp_path: Path,
) -> None:
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    cache = tmp_path / "kernels"
    store = DlsvmKernelStore(samples, cache_directory=cache)
    store.kernels(samples, samples)
    receipt = store.receipt()
    assert receipt is not None

    sealed = evaluation._dlsvm_cache_resume_credit(cache, samples=samples)
    assert sealed["sealed_matrix_count"] == 1
    assert sealed["uncommitted_matrix_count"] == 0
    assert sealed["credited_payload_bytes"] == 2 * 2 * 8

    seal_path = cache / next(iter(receipt["artifacts"].values()))["receipt"]
    seal_path.unlink()
    temporary = cache / (f".within-{'f' * 64}.npy{evaluation.ATOMIC_TEMP_MARKER}interrupted")
    temporary.write_bytes(b"reclaimable crash temporary")
    uncommitted = evaluation._dlsvm_cache_resume_credit(cache, samples=samples)
    assert not temporary.exists()
    assert uncommitted["sealed_matrix_count"] == 0
    assert uncommitted["uncommitted_matrix_count"] == 1
    assert uncommitted["credited_payload_bytes"] == 2 * 2 * 8

    with pytest.raises(ValueError, match="uncommitted matrix"):
        evaluation._dlsvm_cache_resume_credit(
            cache,
            samples=samples,
            cache_read_only=True,
        )


def test_dlsvm_cross_cache_axes_are_canonical_for_shuffled_callers(
    tmp_path: Path,
) -> None:
    undefended = (
        _sample("u-z", "site", "undefended", 0, "uz"),
        _sample("u-a", "site", "undefended", 1, "ua", scale=2),
    )
    defended = (
        _sample("b-z", "site", "buflo", 8, "bz", scale=3),
        _sample("b-a", "site", "buflo", 8, "ba", scale=4),
    )
    samples = (defended[0], undefended[0], defended[1], undefended[1])
    cache = tmp_path / "kernels"
    store = DlsvmKernelStore(samples, cache_directory=cache)
    training_first, testing_first = store.kernels(undefended, defended)
    training_reversed, testing_reversed = store.kernels(
        tuple(reversed(undefended)),
        tuple(reversed(defended)),
    )
    receipt = store.receipt()
    assert receipt is not None
    assert np.array_equal(training_reversed, training_first[::-1, ::-1])
    assert np.array_equal(testing_reversed, testing_first[::-1, ::-1])

    credit = evaluation._dlsvm_cache_resume_credit(cache, samples=samples)
    assert credit["sealed_matrix_count"] == 2
    assert credit["uncommitted_matrix_count"] == 0
    assert credit["credited_payload_bytes"] == 2 * (2 * 2 * 8)


def test_memory_capacity_accepts_wsl_leaf_pair_when_root_has_no_pair(
    tmp_path: Path,
) -> None:
    meminfo = tmp_path / "meminfo"
    membership = tmp_path / "self-cgroup"
    cgroup = tmp_path / "cgroup"
    leaf = cgroup / "init.scope"
    leaf.mkdir(parents=True)
    meminfo.write_text("MemAvailable: 1000 kB\n", encoding="ascii")
    membership.write_text("0::/init.scope\n", encoding="ascii")
    (leaf / "memory.max").write_text("max\n", encoding="ascii")
    (leaf / "memory.current").write_text("123\n", encoding="ascii")

    capacity = evaluation._memory_capacity_runtime(
        meminfo_path=meminfo,
        proc_cgroup_path=membership,
        cgroup_root=cgroup,
    )
    assert capacity["effective_available_bytes"] == 1_024_000
    assert capacity["controller_version"] == 2
    assert [item["path"] for item in capacity["constraints"]] == [str(leaf)]
    assert evaluation._validated_memory_capacity_runtime(capacity) == capacity


def test_memory_capacity_falls_back_to_v1_on_hybrid_mount_without_v2_memory_files(
    tmp_path: Path,
) -> None:
    meminfo = tmp_path / "meminfo"
    membership = tmp_path / "self-cgroup"
    cgroup = tmp_path / "cgroup"
    (cgroup / "unified").mkdir(parents=True)
    memory_root = cgroup / "memory"
    leaf = memory_root / "leaf"
    leaf.mkdir(parents=True)
    meminfo.write_text("MemAvailable: 1000 kB\n", encoding="ascii")
    membership.write_text("0::/unified\n5:memory:/leaf\n", encoding="ascii")
    (leaf / "memory.limit_in_bytes").write_text("800\n", encoding="ascii")
    (leaf / "memory.usage_in_bytes").write_text("125\n", encoding="ascii")

    capacity = evaluation._memory_capacity_runtime(
        meminfo_path=meminfo,
        proc_cgroup_path=membership,
        cgroup_root=cgroup,
    )
    assert capacity["controller_version"] == 1
    assert capacity["membership"] == "/leaf"
    assert capacity["finite_cgroup_remaining_bytes"] == 675
    assert capacity["effective_available_bytes"] == 675
    assert evaluation._validated_memory_capacity_runtime(capacity) == capacity


def test_memory_capacity_uses_tightest_v2_ancestor_and_zero_remaining(
    tmp_path: Path,
) -> None:
    meminfo = tmp_path / "meminfo"
    membership = tmp_path / "self-cgroup"
    cgroup = tmp_path / "cgroup"
    leaf = cgroup / "parent" / "child"
    leaf.mkdir(parents=True)
    meminfo.write_text("MemAvailable: 10000 kB\n", encoding="ascii")
    membership.write_text("0::/parent/child\n", encoding="ascii")
    for directory, limit, current in (
        (cgroup, "1000", "100"),
        (cgroup / "parent", "500", "100"),
        (leaf, "300", "400"),
    ):
        (directory / "memory.max").write_text(limit + "\n", encoding="ascii")
        (directory / "memory.current").write_text(current + "\n", encoding="ascii")

    capacity = evaluation._memory_capacity_runtime(
        meminfo_path=meminfo,
        proc_cgroup_path=membership,
        cgroup_root=cgroup,
    )
    assert capacity["finite_cgroup_remaining_bytes"] == 0
    assert capacity["effective_available_bytes"] == 0
    assert capacity["availability_source"] == ("minimum-of-host-and-finite-cgroup-remaining")


def test_memory_capacity_rejects_partial_or_symlinked_cgroup_pair(
    tmp_path: Path,
) -> None:
    meminfo = tmp_path / "meminfo"
    membership = tmp_path / "self-cgroup"
    cgroup = tmp_path / "cgroup"
    leaf = cgroup / "leaf"
    leaf.mkdir(parents=True)
    meminfo.write_text("MemAvailable: 1000 kB\n", encoding="ascii")
    membership.write_text("0::/leaf\n", encoding="ascii")
    (leaf / "memory.max").write_text("1000\n", encoding="ascii")

    with pytest.raises(ValueError, match="pair is missing or unsafe"):
        evaluation._memory_capacity_runtime(
            meminfo_path=meminfo,
            proc_cgroup_path=membership,
            cgroup_root=cgroup,
        )

    target = tmp_path / "usage"
    target.write_text("10\n", encoding="ascii")
    (leaf / "memory.current").symlink_to(target)
    with pytest.raises(ValueError, match="pair is missing or unsafe"):
        evaluation._memory_capacity_runtime(
            meminfo_path=meminfo,
            proc_cgroup_path=membership,
            cgroup_root=cgroup,
        )


def test_memory_capacity_supports_v1_unlimited_parent_and_finite_child(
    tmp_path: Path,
) -> None:
    meminfo = tmp_path / "meminfo"
    membership = tmp_path / "self-cgroup"
    memory_root = tmp_path / "cgroup" / "memory"
    leaf = memory_root / "child"
    leaf.mkdir(parents=True)
    meminfo.write_text("MemAvailable: 1000 kB\n", encoding="ascii")
    membership.write_text("5:memory:/child\n", encoding="ascii")
    (memory_root / "memory.limit_in_bytes").write_text(
        f"{evaluation._CGROUP_V1_MEMORY_UNLIMITED_MIN}\n",
        encoding="ascii",
    )
    (memory_root / "memory.usage_in_bytes").write_text("50\n", encoding="ascii")
    (leaf / "memory.limit_in_bytes").write_text("900\n", encoding="ascii")
    (leaf / "memory.usage_in_bytes").write_text("200\n", encoding="ascii")

    capacity = evaluation._memory_capacity_runtime(
        meminfo_path=meminfo,
        proc_cgroup_path=membership,
        cgroup_root=tmp_path / "cgroup",
    )
    assert capacity["controller_version"] == 1
    assert capacity["finite_cgroup_remaining_bytes"] == 700
    assert capacity["effective_available_bytes"] == 700


def test_dlsvm_preflight_is_create_only_and_handoff_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is unavailable")
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
    )
    monkeypatch.setenv("QCSD_OSAD_LIBRARY", str(library))
    monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", raising=False)
    evaluation._load_osad_library.cache_clear()
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    for name in ("SHA256SUMS", "dataset.json", "samples.jsonl"):
        (handoff / name).write_text(name + "\n", encoding="utf-8")
    destination = tmp_path / "preflight.json"
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    try:
        rejected = tmp_path / "rejected-preflight.json"
        with pytest.raises(ValueError, match="wall and memory admission"):
            write_dlsvm_preflight(
                rejected,
                samples=samples,
                handoff_root=handoff,
                formal=True,
            )
        assert not rejected.exists()
        monkeypatch.setenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", "1000000")

        interrupted = tmp_path / "interrupted-preflight.json"
        orphan = tmp_path / (f".{interrupted.name}{evaluation.ATOMIC_TEMP_MARKER}deadbeef")
        original_durable_create = evaluation.durable_create

        def interrupt_before_publication(path: Path, value: bytes) -> None:
            assert path == interrupted
            orphan.write_bytes(value[:17])
            raise RuntimeError("simulated SIGKILL before publication")

        monkeypatch.setattr(evaluation, "durable_create", interrupt_before_publication)
        with pytest.raises(RuntimeError, match="simulated SIGKILL"):
            write_dlsvm_preflight(
                interrupted,
                samples=samples,
                handoff_root=handoff,
                formal=True,
            )
        assert not interrupted.exists()
        monkeypatch.setattr(evaluation, "durable_create", original_durable_create)
        write_dlsvm_preflight(
            interrupted,
            samples=samples,
            handoff_root=handoff,
            formal=True,
        )
        validate_dlsvm_preflight(
            interrupted,
            samples=samples,
            handoff_root=handoff,
            formal=True,
        )

        write_dlsvm_preflight(
            destination,
            samples=samples,
            handoff_root=handoff,
            formal=True,
        )
        receipt = validate_dlsvm_preflight(
            destination,
            samples=samples,
            handoff_root=handoff,
            formal=True,
        )
        assert receipt["admission"] == {
            "wall_time_available": True,
            "memory_available": True,
        }
        assert receipt["measurements"][0]["cells_per_second"] > 0
        with pytest.raises(FileExistsError):
            write_dlsvm_preflight(
                destination,
                samples=samples,
                handoff_root=handoff,
                formal=True,
            )
    finally:
        evaluation._load_osad_library.cache_clear()


def test_schema_two_dlsvm_preflight_models_both_passes_and_readmits_current_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is unavailable")
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
    )
    monkeypatch.setenv("QCSD_OSAD_LIBRARY", str(library))
    monkeypatch.setenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", "1000000")
    evaluation._load_osad_library.cache_clear()
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    for name in ("SHA256SUMS", "dataset.json", "samples.jsonl"):
        (handoff / name).write_text(name + "\n", encoding="utf-8")
    destination = tmp_path / "class-preflight.json"
    cache = tmp_path / "class-cache"
    samples = (
        _sample("a", "site", "buflo", 0, "a"),
        _sample("b", "site", "buflo", 1, "b", scale=2),
    )
    try:
        write_dlsvm_preflight(
            destination,
            samples=samples,
            handoff_root=handoff,
            cache_directory=cache,
            formal=True,
            execution_model=CLASS_DLSVM_EXECUTION_MODEL,
        )
        receipt = validate_dlsvm_preflight(
            destination,
            samples=samples,
            handoff_root=handoff,
            formal=True,
            expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
        )
        projection = receipt["projection"]
        assert receipt["schema_version"] == 2
        assert receipt["execution_model"] == CLASS_DLSVM_EXECUTION_MODEL
        assert (
            projection["worker_capacity"]["policy"]
            == (CLASS_DLSVM_EXECUTION_MODEL["worker_capacity_policy"])
        )
        assert projection["worker_capacity"]["selected_workers"] == projection["workers"]
        assert CLASS_DLSVM_EXECUTION_MODEL["cache_resumption_granularity"] == (
            "completed-sealed-whole-matrix"
        )
        assert projection["full_matrix_passes"] == 2
        assert projection["modeled_execution_seconds"] == pytest.approx(
            projection["single_full_matrix_pass_seconds"] * 2
        )
        assert projection["projected_wall_seconds"] == pytest.approx(
            projection["modeled_execution_seconds"]
            * CLASS_DLSVM_EXECUTION_MODEL["contingency_multiplier"]
        )
        assert projection["largest_recomputed_matrix_bytes"] > 0
        assert projection["retained_sequence_native_array_bytes"] > 0
        assert projection["projected_native_dp_worker_memory_bytes"] > 0
        assert projection["projected_kernel_row_worker_memory_bytes"] > 0
        assert projection["projected_memory_bytes"] == sum(
            projection[field]
            for field in (
                "resident_matrix_union_bytes",
                "largest_recomputed_matrix_bytes",
                "retained_sequence_native_array_bytes",
                "projected_native_dp_worker_memory_bytes",
                "projected_kernel_row_worker_memory_bytes",
            )
        )

        forged_engine_path = json.loads(json.dumps(receipt))
        forged_engine_path["engine"]["path"] = "/tmp/not-the-loaded-osad-library.so"
        with pytest.raises(ValueError, match="engine binding"):
            evaluation._validate_dlsvm_preflight_value(
                forged_engine_path,
                samples=samples,
                handoff_root=handoff,
                formal=True,
                expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
            )

        monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS")
        with pytest.raises(ValueError, match="current-capacity admission"):
            admit_dlsvm_preflight_capacity(
                destination,
                samples=samples,
                handoff_root=handoff,
                formal=True,
                expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
                cache_directory=cache,
            )

        monkeypatch.setenv(
            "QCSD_DLSVM_AVAILABLE_WALL_SECONDS",
            str(projection["projected_wall_seconds"] / 2),
        )
        with pytest.raises(ValueError, match="current-capacity admission"):
            admit_dlsvm_preflight_capacity(
                destination,
                samples=samples,
                handoff_root=handoff,
                formal=True,
                expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
                cache_directory=cache,
            )

        monkeypatch.setenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", "1000000")

        filesystem_capacity = evaluation._dlsvm_cache_filesystem_capacity

        def insufficient_storage(path: Path) -> dict[str, object]:
            capacity = filesystem_capacity(path)
            return {
                **capacity,
                "available_bytes": projection["cache_storage"]["required_free_bytes"] - 1,
            }

        monkeypatch.setattr(
            evaluation,
            "_dlsvm_cache_filesystem_capacity",
            insufficient_storage,
        )
        with pytest.raises(ValueError, match="current-capacity admission"):
            admit_dlsvm_preflight_capacity(
                destination,
                samples=samples,
                handoff_root=handoff,
                formal=True,
                expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
                cache_directory=cache,
            )
        monkeypatch.setattr(
            evaluation,
            "_dlsvm_cache_filesystem_capacity",
            filesystem_capacity,
        )

        def memory_capacity(available: int) -> dict[str, object]:
            return {
                **projection["memory_capacity"],
                "host_mem_available_bytes": available,
                "controller_version": None,
                "membership": None,
                "constraints": [],
                "finite_cgroup_remaining_bytes": None,
                "effective_available_bytes": available,
                "availability_source": "host-memavailable",
                "unavailable_reason": None,
            }

        monkeypatch.setattr(
            evaluation,
            "_memory_capacity_runtime",
            lambda: memory_capacity(projection["required_memory_bytes"] - 1),
        )
        with pytest.raises(ValueError, match="current-capacity admission"):
            admit_dlsvm_preflight_capacity(
                destination,
                samples=samples,
                handoff_root=handoff,
                formal=True,
                expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
                cache_directory=cache,
            )

        monkeypatch.setattr(
            evaluation,
            "_memory_capacity_runtime",
            lambda: memory_capacity(projection["required_memory_bytes"]),
        )
        monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS")
        admission = admit_dlsvm_preflight_capacity(
            destination,
            samples=samples,
            handoff_root=handoff,
            formal=True,
            expected_execution_model=CLASS_DLSVM_EXECUTION_MODEL,
            available_wall_seconds=1_000_000,
            cache_directory=cache,
        )
        assert admission["wall_time_available"] is True
        assert admission["memory_available"] is True
        assert admission["cache_storage_available"] is True
    finally:
        evaluation._load_osad_library.cache_clear()


def test_osad_workers_reject_effective_cpu_oversubscription(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluation.os, "sched_getaffinity", lambda _pid: {2, 3})
    monkeypatch.setattr(
        evaluation,
        "_cgroup_cpu_quota_runtime",
        lambda: {
            "schema_version": 1,
            "source": "test-cgroup",
            "constraints": [
                {
                    "path": "/test/cpu.max",
                    "quota_us": 150_000,
                    "period_us": 100_000,
                    "worker_limit_floor": 1,
                }
            ],
            "finite_worker_limit": 1,
            "unavailable_reason": None,
        },
    )
    monkeypatch.setenv("QCSD_OSAD_WORKERS", "2")
    with pytest.raises(ValueError, match="effective CPU worker limit"):
        evaluation._osad_workers()

    monkeypatch.setenv("QCSD_OSAD_WORKERS", "1")
    capacity = evaluation._osad_worker_capacity()
    assert capacity["affinity_cpu_count"] == 2
    assert capacity["effective_worker_limit"] == 1
    assert capacity["requested_worker_source"] == "QCSD_OSAD_WORKERS"
    assert capacity["selected_workers"] == 1


def test_cgroup_cpu_quota_falls_back_to_v1_on_hybrid_without_v2_cpu_files(
    tmp_path: Path,
) -> None:
    membership = tmp_path / "self-cgroup"
    cgroup = tmp_path / "cgroup"
    (cgroup / "unified").mkdir(parents=True)
    leaf = cgroup / "cpu" / "leaf"
    leaf.mkdir(parents=True)
    membership.write_text("0::/unified\n5:cpu,cpuacct:/leaf\n", encoding="ascii")
    (leaf / "cpu.cfs_quota_us").write_text("150000\n", encoding="ascii")
    (leaf / "cpu.cfs_period_us").write_text("100000\n", encoding="ascii")

    capacity = evaluation._cgroup_cpu_quota_runtime(
        proc_cgroup_path=membership,
        cgroup_root=cgroup,
    )
    assert capacity["finite_worker_limit"] == 1
    assert [item["path"] for item in capacity["constraints"]] == [str(leaf / "cpu.cfs_quota_us")]
    assert capacity["unavailable_reason"] is None


def test_cgroup_cpu_quota_uses_tightest_constraint_across_hybrid_controllers(
    tmp_path: Path,
) -> None:
    membership = tmp_path / "self-cgroup"
    cgroup = tmp_path / "cgroup"
    unified = cgroup / "unified"
    unified.mkdir(parents=True)
    v1_leaf = cgroup / "cpu" / "leaf"
    v1_leaf.mkdir(parents=True)
    membership.write_text("0::/unified\n5:cpu,cpuacct:/leaf\n", encoding="ascii")
    (unified / "cpu.max").write_text("300000 100000\n", encoding="ascii")
    (v1_leaf / "cpu.cfs_quota_us").write_text("100000\n", encoding="ascii")
    (v1_leaf / "cpu.cfs_period_us").write_text("100000\n", encoding="ascii")

    capacity = evaluation._cgroup_cpu_quota_runtime(
        proc_cgroup_path=membership,
        cgroup_root=cgroup,
    )
    assert capacity["finite_worker_limit"] == 1
    assert [item["worker_limit_floor"] for item in capacity["constraints"]] == [3, 1]


def test_focused_deep_cache_validation_readmits_before_matrix_recomputation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, object]] = []
    samples = (_sample("a", "site", "buflo", 0, "a"),)
    preflight = tmp_path / "preflight.json"
    handoff = tmp_path / "handoff"

    def validate_preflight(path: Path, **kwargs: object) -> dict[str, object]:
        calls.append(("validate", kwargs))
        assert path == preflight
        return {}

    def admit(path: Path, **kwargs: object) -> dict[str, object]:
        calls.append(("admit", kwargs))
        assert path == preflight
        return {}

    def validate_cache(value: object, **kwargs: object) -> None:
        calls.append(("cache", kwargs))
        assert value == {"cache": True, "path": str(tmp_path / "cache")}

    monkeypatch.setattr(evaluation, "validate_dlsvm_preflight", validate_preflight)
    monkeypatch.setattr(evaluation, "admit_dlsvm_preflight_capacity", admit)
    monkeypatch.setattr(evaluation, "_validate_dlsvm_cache_receipt", validate_cache)

    evaluation._validate_focused_dlsvm_evidence(
        preflight_path=preflight,
        cache={"cache": True, "path": str(tmp_path / "cache")},
        samples=samples,
        handoff_root=handoff,
        deep=True,
        dlsvm_available_wall_seconds=321.0,
    )
    assert [name for name, _ in calls] == ["validate", "admit", "cache"]
    assert calls[0][1]["expected_execution_model"] == evaluation.FOCUSED_DLSVM_EXECUTION_MODEL
    assert calls[1][1]["expected_execution_model"] == evaluation.FOCUSED_DLSVM_EXECUTION_MODEL
    assert calls[1][1]["available_wall_seconds"] == 321.0
    assert calls[1][1]["cache_directory"] == tmp_path / "cache"
    assert calls[1][1]["cache_read_only"] is True
    assert calls[2][1]["deep"] is True

    calls.clear()
    evaluation._validate_focused_dlsvm_evidence(
        preflight_path=preflight,
        cache={"cache": True, "path": str(tmp_path / "cache")},
        samples=samples,
        handoff_root=handoff,
        deep=False,
        dlsvm_available_wall_seconds=None,
    )
    assert [name for name, _ in calls] == ["validate", "cache"]
    assert calls[1][1]["deep"] is False

    def reject_capacity(path: Path, **kwargs: object) -> dict[str, object]:
        calls.append(("admit", kwargs))
        raise ValueError("current-capacity admission rejected")

    calls.clear()
    monkeypatch.setattr(evaluation, "admit_dlsvm_preflight_capacity", reject_capacity)
    with pytest.raises(ValueError, match="current-capacity"):
        evaluation._validate_focused_dlsvm_evidence(
            preflight_path=preflight,
            cache={"cache": True, "path": str(tmp_path / "cache")},
            samples=samples,
            handoff_root=handoff,
            deep=True,
            dlsvm_available_wall_seconds=1.0,
        )
    assert [name for name, _ in calls] == ["validate", "admit"]


def test_formal_cohort_requires_exact_1500_balanced_samples() -> None:
    samples = []
    for block in range(10):
        for workload_id, label in FORMAL_CLASS_BY_WORKLOAD.items():
            for visit in range(10):
                paired = f"block-{block}/{workload_id}/visit-{visit}"
                for defense in ("undefended", "buflo", "cs-buflo"):
                    samples.append(
                        StudySample(
                            f"{paired}/{defense}",
                            label,
                            workload_id,
                            defense,
                            block,
                            paired,
                            _trace(),
                        )
                    )
    validate_formal_cohort(samples)
    census = dlsvm_workload_census(samples)
    assert census["unique_distance_calls_upper_bound"] == 455_750
    assert census["dynamic_programming_cells_upper_bound"] == 455_750 * 16
    assert census["persisted_dense_matrix_elements"] == 830_000
    assert census["persisted_dense_matrix_bytes"] == 6_640_000
    with pytest.raises(ValueError, match="1500"):
        validate_formal_cohort(samples[:-1])

    first_pair = samples[0].paired_visit_id
    second_pair = samples[30].paired_visit_id
    crossed = list(samples)
    first_buflo = next(
        index
        for index, sample in enumerate(crossed)
        if sample.paired_visit_id == first_pair and sample.defense == "buflo"
    )
    second_buflo = next(
        index
        for index, sample in enumerate(crossed)
        if sample.paired_visit_id == second_pair and sample.defense == "buflo"
    )
    crossed[first_buflo] = replace(crossed[first_buflo], paired_visit_id=second_pair)
    crossed[second_buflo] = replace(crossed[second_buflo], paired_visit_id=first_pair)
    with pytest.raises(ValueError, match="cross block or workload"):
        validate_formal_cohort(crossed)


def test_overhead_uses_ratio_of_sums_and_cluster_bootstrap() -> None:
    samples = []
    for visit, scale in enumerate((1, 2)):
        paired = f"visit-{visit}"
        samples.extend(
            (
                _sample(f"u-{visit}", "site", "undefended", visit, paired, scale=scale),
                _sample(f"b-{visit}", "site", "buflo", visit, paired, scale=scale * 2),
            )
        )
    rows = paired_overheads(samples)
    assert (
        ratio_of_sums(
            [row["defended_wire_bytes"] for row in rows],
            [row["baseline_wire_bytes"] for row in rows],
        )
        == 2
    )
    summary = summarize_paired_overheads(rows, bootstrap_draws=20, seed=7)
    assert summary["buflo"]["wire_ratio_of_sums"] == 2
    assert summary["buflo"]["additional_wire_percent"] == 100
    assert summary["buflo"]["wire_ratio_bootstrap_95"]["draws"] == 20


def test_nullable_udp_performance_is_reported_unavailable_without_type_error() -> None:
    performance = {
        "wire_bytes": {"outgoing": 220, "incoming": 500},
        "packet_count": {"outgoing": 2, "incoming": 2},
        "udp_payload_bytes": {"outgoing": None, "incoming": None},
        "application_response_bytes": 1_000,
    }
    samples = (
        StudySample("u", "site", "site", "undefended", 0, "pair", _trace(), performance),
        StudySample("b", "site", "site", "buflo", 0, "pair", _trace(2), performance),
    )

    summary = summarize_paired_overheads(paired_overheads(samples), bootstrap_draws=5)

    assert summary["buflo"]["performance_evidence_available"] is False


def test_performance_breakdown_reports_direction_and_client_costs() -> None:
    usage = {
        "schema_version": 1,
        "source": "gnu-time-v",
        "user_cpu_seconds": 0.1,
        "system_cpu_seconds": 0.2,
        "wall_time_seconds": 1.0,
        "maximum_rss_bytes": 10_000,
        "voluntary_context_switches": 2,
        "involuntary_context_switches": 1,
        "timer_wakeups": None,
        "timer_wakeups_unavailable_reason": "unavailable",
        "rapl_energy_joules": None,
        "rapl_unavailable_reason": "unavailable",
    }
    performance = {
        "schema_version": 1,
        "application_duration_ns": 2_000_000_000,
        "application_response_bytes": 1_000,
        "wire_bytes": {"outgoing": 220, "incoming": 500},
        "packet_count": {"outgoing": 2, "incoming": 2},
        "udp_payload_bytes": {"outgoing": 150, "incoming": 430},
        "udp_payload_lengths_missing": {"outgoing": 0, "incoming": 0},
        "client_resource_usage": usage,
        "transport_retransmissions": 3,
    }
    baseline = StudySample("u", "site", "site", "undefended", 0, "p", _trace(), performance)
    sample = StudySample("s", "site", "site", "buflo", 0, "p", _trace(), performance)

    breakdown = performance_breakdowns([baseline, sample], bootstrap_draws=20)

    assert len(breakdown["directional"]) == 4
    assert breakdown["client"][0]["goodput_bytes_per_second"] == 500
    assert breakdown["client"][0]["transport_retransmissions"] == 3
    assert breakdown["client"][0]["resource_usage"]["timer_wakeups"]["available"] is False
    paired = breakdown["paired_directional_by_workload_block"][0]
    assert paired["wire_ratio_of_sums"] == 1
    assert paired["udp_payload_additional_percent"] == 0
    assert paired["packet_ratio_pair_quantiles"]["p95"] == 1
    client = breakdown["paired_mode_client_block_workload_bootstrap_95"][0]
    assert client["completion_ratio_of_sums"] == 1
    assert client["goodput_ratio"] == 1
    assert client["completion_ratio_block_workload_bootstrap_95"]["draws"] == 20


def test_algorithm_breakdown_retains_non_classifier_runner_strata() -> None:
    summary = {
        "count": 1,
        "minimum": 4_096,
        "maximum": 4_096,
        "mean": 4_096.0,
        "p50": 4_096,
        "p95": 4_096,
    }
    direction = {
        "scheduled_cells": 1,
        "target_size_bytes": {"summary": summary, "histogram": {"600": 1}},
        "desired_udp_bytes": 600,
        "observed_udp_bytes": 600,
        "realization_ratio": 1.0,
        "satisfaction_counts": {"full": 1},
        "congestion_reason_counts": {},
        "inter_target_delta_us": summary,
        "nearest_nominal_interval_us": summary,
        "estimated_jitter_from_nearest_nominal_us": {
            **summary,
            "minimum": 0,
            "maximum": 0,
            "mean": 0.0,
            "p50": 0,
            "p95": 0,
        },
        "inferred_nearest_nominal_transitions": [],
        "jitter_semantics": "target-delta-minus-nearest-allowed-live-interval; descriptive-only",
        "scheduling_lateness_us": {
            **summary,
            "minimum": 3,
            "maximum": 3,
            "mean": 3.0,
            "p50": 3,
            "p95": 3,
        },
        "traffic_composition_bytes": {
            "application_stream_bytes": 500,
            "retransmission_stream_bytes": 0,
            "chaff_stream_bytes": 100,
            "defense_control_bytes": 0,
            "quic_padding_bytes": 0,
            "other_quic_bytes": 0,
        },
        "receive_credit_advertisement": {
            "semantics": (
                "complete local MAX_STREAM_DATA on-wire advertisement; this rearms cadence "
                "without claiming peer datagram timing, size, or consumption"
            ),
            "advertised_cells": 1,
            "delay_us": {
                **summary,
                "minimum": 100,
                "maximum": 100,
                "mean": 100.0,
                "p50": 100,
                "p95": 100,
            },
        },
        "receive_credit_consumption": {
            "semantics": (
                "eventual peer stream-offset consumption terminal boundary; measured "
                "separately from allocation and local advertisement"
            ),
            "consumed_cells": 1,
            "delay_us": {
                **summary,
                "minimum": 500,
                "maximum": 500,
                "mean": 500.0,
                "p50": 500,
                "p95": 500,
            },
        },
    }
    cs_direction = {
        "terminal_interval_us": 4_096,
        "rate_adaptations": 2,
        "next_adaptation_boundary_bytes": 65_536,
        "estimator_samples": 10,
        "padding_basis_natural_bytes": 1_000,
        "padding_basis_cover_bytes": 24,
        "padding_basis_total_bytes": 1_024,
        "padding_target_bytes": 1_024,
        "power_of_two_crossed": True,
        "minimum_interval_opportunities": 5,
        "minimum_interval_terminal": 5,
        "minimum_interval_full": 5,
        "minimum_interval_local_realized": 5,
        "incoming_local_realized_cells": 9,
        "rate_transitions": [
            {
                "schema_version": 1,
                "direction": "outgoing",
                "at_us": 50_000,
                "boundary_bytes": 16_384,
                "real_bearing_bytes": 17_000,
                "eligible_samples": 4,
                "median_interval_us": 6_000,
                "previous_interval_us": 8_192,
                "resulting_interval_us": 4_096,
                "retained_current_interval": False,
            }
        ],
    }
    diagnostics = {
        "schema_version": 1,
        "mode": "cs-buflo",
        "runtime_kind": "cs_buflo",
        "classifier_input": False,
        "runner_rows": {
            "schedule": 2,
            "events": 1,
            "packets": 1,
            "typed_events": 1,
            "typed_packets": 1,
        },
        "directions": {"outgoing": direction, "incoming": direction},
        "cs_buflo_state": {
            "padding_variant": "CTSP",
            "early_termination_semantics": "udp_client_only_observed_udp_power_of_two_crossing",
            "incoming_local_realized_cells": 9,
            "incoming_boundaries": {
                "cadence": "complete_local_on_wire_max_stream_data_advertisement",
                "terminal": "eventual_peer_stream_offset_consumption",
                "separation": (
                    "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption"
                ),
            },
            "rate_boundary_translation": {
                "version": 2,
                "live_counter_semantics": (
                    "client_only_quic_fresh_application_stream_bytes_outgoing_"
                    "retransmission_excluded_and_consumed_application_offsets_incoming"
                ),
                "author_counter_semantics": (
                    "per_direction_actually_transmitted_real_plus_junk_bytes"
                ),
                "expected_difference": (
                    "author advances on actually transmitted real-plus-junk bytes; "
                    "the client-only QCSD translation advances on exact fresh application "
                    "STREAM bytes and excludes retransmission and defense-added bytes"
                ),
            },
            "rate_transitions": cs_direction["rate_transitions"] * 2,
            "local_termination": {
                "latched": True,
                "pending_request_cancellations": 0,
                "stream_cancellations": 0,
            },
            "directions": {"outgoing": cs_direction, "incoming": cs_direction},
        },
    }
    sample = StudySample("s", "site", "site", "cs-buflo", 0, "p", _trace(), None, diagnostics)

    result = algorithm_breakdowns([sample])

    assert result["available"] is True
    assert result["classifier_input"] is False
    assert len(result["strata"]) == 2
    assert result["strata"][0]["target_size_histogram"] == {"600": 1}
    assert result["strata"][0]["cs_buflo"]["rate_adaptations"] == 2
    assert result["strata"][0]["cs_buflo"]["explicit_rate_transition_histogram"] == {
        "8192->4096": 1
    }
    assert result["strata"][0]["cs_buflo"]["minimum_interval_full"] == 5
    incoming = next(row for row in result["strata"] if row["direction"] == "incoming")
    assert incoming["cs_buflo"]["minimum_interval_local_realized"] == 5
    assert incoming["cs_buflo"]["incoming_local_realized_cells"] == 9
    assert incoming["receive_credit_consumption"]["consumed_cells"] == 1
    assert all(
        row["cs_buflo"]["termination_stop_evidence"]
        == {
            "available": False,
            "schema_version": None,
            "samples_with_evidence": 0,
            "historical_samples_without_evidence": 1,
        }
        for row in result["strata"]
    )

    current = json.loads(json.dumps(diagnostics))
    current["schema_version"] = 3
    current["peer_reproduction"] = {}
    current["buflo_state"] = None
    current["cs_buflo_state"]["local_termination"].update(
        latched_at_us=2_000_000,
        before_application_complete=True,
        application_receive_streams_handed_off=1,
        application_parser_boundaries_handed_off=0,
        application_parser_lease_bytes_handed_off=0,
        application_send_endpoints_released=0,
        post_local_et_natural_outgoing_bytes=50,
        post_local_et_natural_incoming_bytes=25,
    )
    for direction_name, post in (("outgoing", 50), ("incoming", 25)):
        current_direction = current["cs_buflo_state"]["directions"][direction_name]
        current_direction.update(
            natural_bytes=1_000 + post,
            real_bearing_bytes=900,
            post_local_et_natural_bytes=post,
        )
    assert evaluation._load_algorithm_diagnostics(current, defense="cs-buflo") == current
    current_v4 = json.loads(json.dumps(current))
    current_v4["schema_version"] = 4
    current_v4["cs_buflo_state"]["early_termination_semantics"] = (
        "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
    )
    current_v4["cs_buflo_state"]["early_termination_translation"] = {
        "version": 2,
        "stop_policy": (
            "stop_new_opportunities_at_first_eligible_padding_target_or_power_of_two_"
            "crossing_then_drain_advertised_credit_exactly_once"
        ),
    }
    for direction_name in ("outgoing", "incoming"):
        direction_metrics = current_v4["directions"][direction_name]
        direction_metrics["scheduled_cells"] = 1
        direction_metrics["satisfaction_counts"] = {"full": 1}
        current_v4["cs_buflo_state"]["directions"][direction_name].update(
            termination_accounted_bytes=2_048,
            last_termination_increment_bytes=600,
            termination_stop_latched=True,
            termination_stop_crossing_total_bytes=1_200,
            termination_stop_crossing_increment_bytes=600,
            termination_stop_reason="power_of_two_crossing",
            termination_stop_phase="application_complete",
            termination_stop_latched_at_us=1_900_000,
            termination_stop_scheduled_cells_at_stop=1,
            termination_stop_terminal_cells_at_stop=1,
            termination_stop_progress_bytes_at_stop=1_000,
            termination_stop_padding_target_bytes_at_stop=1_024,
            termination_stop_provisional_invalidation_count=0,
            stop_drain_ledger={
                "drained_cells_after_stop": 0,
                "last_scheduled_target_us": 1_800_000,
                "last_terminal_at_us": 1_900_000,
                "terminal_cells_strictly_before_stop": 1,
                "terminal_cells_at_or_before_stop": 1,
                "terminal_cells_at_stop_timestamp": 0,
            },
        )
    assert evaluation._load_algorithm_diagnostics(current_v4, defense="cs-buflo") == current_v4
    invalid_translation_version = json.loads(json.dumps(current_v4))
    invalid_translation_version["cs_buflo_state"]["early_termination_translation"]["version"] = 2.0
    with pytest.raises(ValueError, match="CS-BuFLO algorithm state"):
        evaluation._load_algorithm_diagnostics(invalid_translation_version, defense="cs-buflo")
    invalid_reason_type = json.loads(json.dumps(current_v4))
    invalid_reason_type["cs_buflo_state"]["directions"]["incoming"]["termination_stop_reason"] = []
    with pytest.raises(ValueError, match="CS-BuFLO algorithm state"):
        evaluation._load_algorithm_diagnostics(invalid_reason_type, defense="cs-buflo")
    invalid_v4 = json.loads(json.dumps(current_v4))
    invalid_v4["cs_buflo_state"]["directions"]["incoming"][
        "termination_stop_crossing_total_bytes"
    ] = 1_800
    with pytest.raises(ValueError, match="CS-BuFLO algorithm state"):
        evaluation._load_algorithm_diagnostics(invalid_v4, defense="cs-buflo")
    invalid_current = json.loads(json.dumps(current))
    invalid_current["cs_buflo_state"]["local_termination"][
        "application_receive_streams_handed_off"
    ] = 0
    with pytest.raises(ValueError, match="CS-BuFLO algorithm state"):
        evaluation._load_algorithm_diagnostics(invalid_current, defense="cs-buflo")
    current_sample = StudySample(
        "current", "site", "site", "cs-buflo", 0, "current-pair", _trace(), None, current
    )
    current_result = algorithm_breakdowns([current_sample])
    assert current_result["schema_version"] == 2
    assert current_result["cs_buflo_local_termination_strata"] == [
        {
            "defense": "cs-buflo",
            "workload_id": "site",
            "acquisition_block_index": 0,
            "samples": 1,
            "before_application_complete_samples": 1,
            "latched_at_us": {"p50": 2_000_000.0, "p90": 2_000_000.0, "p95": 2_000_000.0},
            "pending_request_cancellations": 0,
            "stream_cancellations": 0,
            "application_receive_streams_handed_off": 1,
            "application_parser_boundaries_handed_off": 0,
            "application_parser_lease_bytes_handed_off": 0,
            "application_send_endpoints_released": 0,
            "post_local_et_natural_outgoing_bytes": 50,
            "post_local_et_natural_incoming_bytes": 25,
        }
    ]


def test_buflo_schema_four_diagnostics_aggregate_stop_drain_and_preserve_history() -> None:
    empty_summary = {"count": 0}
    direction = {
        "scheduled_cells": 5,
        "target_size_bytes": {"summary": empty_summary, "histogram": {}},
        "desired_udp_bytes": 0,
        "observed_udp_bytes": 0,
        "realization_ratio": None,
        "satisfaction_counts": {"full": 5},
        "congestion_reason_counts": {},
        "inter_target_delta_us": empty_summary,
        "estimated_jitter_from_nearest_nominal_us": empty_summary,
        "inferred_nearest_nominal_transitions": [],
        "scheduling_lateness_us": empty_summary,
        "traffic_composition_bytes": {},
        "receive_credit_advertisement": {
            "advertised_cells": 0,
            "delay_us": empty_summary,
        },
        "receive_credit_consumption": {
            "consumed_cells": 0,
            "delay_us": empty_summary,
        },
    }
    state = {
        "schema_version": 3,
        "terminal_subcell_policy": BUFLO_TERMINAL_SUBCELL_POLICY,
        "terminal_subcell_observer_effect": BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
        "pending_request_cancellations": 0,
        "stream_cancellations": 1,
        "receipt_cancellations": 1,
        "exact_capacity_bytes_cancelled": 1_199,
        "whole_cell_floor_bytes": 1_200,
        "terminal_latched": True,
        "terminal_latched_at_us": 10_000_020,
        "open_streams_at_latch": 1,
        "parser_lease_bytes_at_latch": 0,
        "pending_parser_boundaries_at_latch": 1,
        "pending_application_parser_boundaries_at_latch": 0,
        "typed_cancellation_action_events": 1,
        "first_cancellation_monotonic_us": 10_000_030,
        "last_exact_outgoing_cell_monotonic_us": 9_999_990,
        "last_scheduled_terminal_monotonic_us": 10_000_000,
        "control_evidence_semantics": BUFLO_TERMINAL_CONTROL_EVIDENCE_SEMANTICS,
        "post_cancellation_unscheduled_defense_control_packets": 1,
        "post_cancellation_unscheduled_defense_control_bytes": 4,
        "first_post_cancellation_defense_control_monotonic_us": 10_000_040,
        "last_post_cancellation_defense_control_monotonic_us": 10_000_040,
        "schedule_stop": {
            "policy": BUFLO_SCHEDULE_STOP_POLICY,
            "terminal_time_semantics": (BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS),
            "latched": True,
            "latched_at_us": 10_000_000,
            "available_bytes": 1_199,
            "required_bytes": 1_200,
            "directions": {
                "outgoing": {
                    "scheduled_cells_at_stop": 5,
                    "terminal_cells_at_stop": 5,
                    "drained_cells_after_stop": 0,
                    "last_scheduled_target_us": 10_000_000,
                    "last_terminal_at_us": 9_999_995,
                    "terminal_cells_strictly_before_stop": 5,
                    "terminal_cells_at_or_before_stop": 5,
                    "terminal_cells_at_stop_timestamp": 0,
                },
                "incoming": {
                    "scheduled_cells_at_stop": 5,
                    "terminal_cells_at_stop": 3,
                    "drained_cells_after_stop": 2,
                    "last_scheduled_target_us": 10_000_000,
                    "last_terminal_at_us": 10_000_015,
                    "terminal_cells_strictly_before_stop": 3,
                    "terminal_cells_at_or_before_stop": 3,
                    "terminal_cells_at_stop_timestamp": 0,
                },
            },
        },
        "paper_equivalent": False,
        "implementation_scope": "client_only_quic",
    }
    diagnostics = {
        "schema_version": 4,
        "mode": "buflo",
        "runtime_kind": "buflo",
        "classifier_input": False,
        "peer_reproduction": {},
        "runner_rows": {
            "schedule": 0,
            "events": 1,
            "packets": 1,
            "typed_events": 1,
            "typed_packets": 1,
        },
        "directions": {"outgoing": direction, "incoming": direction},
        "buflo_state": state,
        "cs_buflo_state": None,
    }
    loaded = evaluation._load_algorithm_diagnostics(diagnostics, defense="buflo")
    wrong_runtime = json.loads(json.dumps(diagnostics))
    wrong_runtime["runtime_kind"] = "front"
    wrong_runtime["buflo_state"] = None
    with pytest.raises(ValueError, match="schema 4 requires BuFLO or CS-BuFLO"):
        evaluation._load_algorithm_diagnostics(wrong_runtime, defense="buflo")
    sample = StudySample("b", "site", "site", "buflo", 0, "pair", _trace(), None, loaded)
    result = algorithm_breakdowns([sample])
    assert result["available"] is True
    assert result["schema_version"] == 3
    assert len(result["buflo_terminal_tail_strata"]) == 1
    tail = result["buflo_terminal_tail_strata"][0]
    assert tail["stream_cancellations"] == 1
    assert tail["pending_parser_boundaries_at_latch"] == 1
    assert tail["pending_application_parser_boundaries_at_latch"] == 0
    assert tail["exact_capacity_bytes_cancelled"] == {
        "total": 1_199,
        "minimum": 1_199,
        "maximum": 1_199,
        "p50": 1_199.0,
        "p90": 1_199.0,
        "p95": 1_199.0,
    }
    assert tail["post_cancellation_unscheduled_defense_control_bytes"] == 4
    schedule_stop = result["buflo_schedule_stop_strata"][0]
    assert schedule_stop["policy"] == [BUFLO_SCHEDULE_STOP_POLICY]
    assert schedule_stop["terminal_time_semantics"] == [BUFLO_SCHEDULE_STOP_TERMINAL_TIME_SEMANTICS]
    assert schedule_stop["latched_samples"] == 1
    assert schedule_stop["available_bytes"] == {
        "total": 1_199,
        "minimum": 1_199,
        "maximum": 1_199,
        "p50": 1_199.0,
        "p90": 1_199.0,
        "p95": 1_199.0,
    }
    assert schedule_stop["samples_with_incoming_drain"] == 1
    assert schedule_stop["directions"]["outgoing"]["drained_cells_after_stop"] == 0
    assert schedule_stop["directions"]["incoming"]["drained_cells_after_stop"] == 2

    for field, changed in (
        ("parser_lease_bytes_at_latch", 1),
        ("pending_application_parser_boundaries_at_latch", 1),
        ("pending_parser_boundaries_at_latch", 2),
        ("first_cancellation_monotonic_us", 9_999_999),
        ("terminal_subcell_policy", "drifted"),
    ):
        invalid = json.loads(json.dumps(diagnostics))
        invalid["buflo_state"][field] = changed
        with pytest.raises(ValueError, match="BuFLO algorithm state"):
            evaluation._load_algorithm_diagnostics(invalid, defense="buflo")

    for path, changed in (
        (("terminal_time_semantics",), "drifted"),
        (("required_bytes",), 1_199),
        (("available_bytes",), 1_200),
        (("directions", "outgoing", "drained_cells_after_stop"), 1),
        (("directions", "incoming", "last_scheduled_target_us"), 10_000_001),
    ):
        invalid = json.loads(json.dumps(diagnostics))
        target = invalid["buflo_state"]["schedule_stop"]
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = changed
        with pytest.raises(ValueError, match="BuFLO algorithm state"):
            evaluation._load_algorithm_diagnostics(invalid, defense="buflo")

    previous_state = json.loads(json.dumps(state))
    previous_state["schema_version"] = 2
    previous_state.pop("schedule_stop")
    previous = json.loads(json.dumps(diagnostics))
    previous["schema_version"] = 3
    previous["buflo_state"] = previous_state
    assert evaluation._load_algorithm_diagnostics(previous, defense="buflo") == previous
    previous_result = algorithm_breakdowns(
        [StudySample("p", "site", "site", "buflo", 0, "previous", _trace(), None, previous)]
    )
    assert "buflo_schedule_stop_strata" not in previous_result

    legacy_state = json.loads(json.dumps(previous_state))
    legacy_state.pop("schema_version")
    legacy_state.pop("pending_application_parser_boundaries_at_latch")
    legacy_state["pending_parser_boundaries_at_latch"] = 0
    legacy = json.loads(json.dumps(diagnostics))
    legacy["schema_version"] = 2
    legacy["buflo_state"] = legacy_state
    assert evaluation._load_algorithm_diagnostics(legacy, defense="buflo") == legacy

    legacy_without_state = {
        key: value for key, value in diagnostics.items() if key != "buflo_state"
    }
    legacy_without_state["schema_version"] = 1
    assert (
        evaluation._load_algorithm_diagnostics(legacy_without_state, defense="buflo")
        == legacy_without_state
    )
    legacy_without_state["buflo_state"] = None
    with pytest.raises(ValueError, match="schema is invalid"):
        evaluation._load_algorithm_diagnostics(legacy_without_state, defense="buflo")

    legacy_sample = StudySample(
        "legacy", "site", "site", "buflo", 0, "legacy-pair", _trace(), None, legacy
    )
    with pytest.raises(ValueError, match="mixes algorithm diagnostic schema versions"):
        algorithm_breakdowns([sample, legacy_sample])


@pytest.mark.parametrize("schema_version", [1, 2])
def test_handoff_loader_checks_trace_digest_and_shape_contract(
    tmp_path: Path,
    schema_version: int,
) -> None:
    traces = tmp_path / "traces"
    traces.mkdir()
    trace = traces / "sample.csv"
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n"
        "0,outgoing,100,100\n"
        "5,incoming,200,-200\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(trace.read_bytes()).hexdigest()
    row = {
        "schema_version": schema_version,
        "sample_id": "sample",
        "class_label": "site",
        "workload_id": "site-r1",
        "defense": "buflo",
        "acquisition_block_index": 0,
        "paired_visit_id": "pair",
        "trace_path": "traces/sample.csv",
        "trace_sha256": digest,
    }
    (tmp_path / "samples.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    loaded = load_study_handoff(tmp_path)
    assert loaded[0].trace[1].signed_length_bytes == -200

    row["trace_sha256"] = "0" * 64
    (tmp_path / "samples.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="digest"):
        load_study_handoff(tmp_path)


def test_temporal_panchenko_attack_has_explicit_protocol_and_backend() -> None:
    samples = []
    for block in range(10):
        for label, scale in (("small", 1), ("large", 5)):
            samples.append(
                _sample(
                    f"{block}-{label}",
                    label,
                    "undefended",
                    block,
                    f"{block}-{label}",
                    scale=scale,
                )
            )
    results = run_temporal_attacks(samples, attacks=("panchenko",))
    assert all(isinstance(result, AttackResult) for result in results)
    assert {result.protocol for result in results} == {
        "temporal-validation-adaptive",
        "temporal-validation-undefended-transfer",
        "temporal-heldout-test-adaptive",
        "temporal-heldout-test-undefended-transfer",
    }
    assert all(result.backend == "clean-room-libsvm-compatible-rbf" for result in results)
    assert all(result.test_samples == 2 for result in results)
    assert all(len(result.predictions) == 2 for result in results)
    interval = attack_bootstrap_intervals(results[0], draws=20, seed=4)
    assert interval["draws"] == 20
    assert interval["cluster"] == "acquisition_block_index+workload_id"


def test_historical_panchenko_attack_is_secondary_stratified_ten_fold() -> None:
    samples = []
    for visit in range(10):
        for label, scale in (("small", 1), ("large", 5)):
            samples.append(
                _sample(
                    f"{visit}-{label}",
                    label,
                    "buflo",
                    visit,
                    f"{visit}-{label}",
                    scale=scale,
                )
            )
    (result,) = run_historical_attacks(samples, attacks=("panchenko",), random_state=3)
    assert result.protocol == "historical-stratified-10fold"
    assert result.training_defense == result.testing_defense == "buflo"
    assert result.train_samples == result.test_samples == 20
    assert sum(sum(row) for row in result.confusion_matrix) == 20
    assert result.protocol_details["random_state"] == 3
    assert len(result.protocol_details["folds"]) == 10
    assert all(
        len(fold["training_sample_ids"]) == 18 and len(fold["testing_sample_ids"]) == 2
        for fold in result.protocol_details["folds"]
    )
    record = result.as_dict()
    assert record["predictions_sha256"] == evaluation._canonical_json_sha256(record["predictions"])


def test_attack_receipt_validator_recomputes_membership_predictions_and_metrics() -> None:
    samples = []
    for visit in range(10):
        for label, scale in (("small", 1), ("large", 5)):
            samples.append(
                _sample(
                    f"{visit}-{label}",
                    label,
                    "buflo",
                    visit,
                    f"{visit}-{label}",
                    scale=scale,
                )
            )
    (result,) = run_historical_attacks(
        samples,
        attacks=("panchenko",),
        random_state=evaluation._DLSVM_RANDOM_STATE,
    )
    record = result.as_dict()
    record["block_workload_bootstrap_95"] = attack_bootstrap_intervals(
        result, draws=5, seed=20260827
    )
    checked = evaluation._validate_attack_record(record, samples=samples)
    assert checked.accuracy == result.accuracy

    forged = json.loads(json.dumps(record))
    forged["predictions"][0]["predicted"] = forged["labels"][-1]
    with pytest.raises(ValueError, match="hash"):
        evaluation._validate_attack_record(forged, samples=samples)
    forged["predictions_sha256"] = evaluation._canonical_json_sha256(forged["predictions"])
    with pytest.raises(ValueError, match="metrics"):
        evaluation._validate_attack_record(forged, samples=samples)

    forged = json.loads(json.dumps(record))
    forged["protocol_details"]["folds"][0]["testing_sample_ids"].reverse()
    with pytest.raises(ValueError, match="membership"):
        evaluation._validate_attack_record(forged, samples=samples)

    forged = json.loads(json.dumps(record))
    forged["backend"] = "plausible-but-unreceipted-backend"
    with pytest.raises(ValueError, match="identity"):
        evaluation._validate_attack_record(forged, samples=samples)


def test_attack_replay_rejects_consistent_prediction_and_metric_forgery() -> None:
    samples = []
    for visit in range(10):
        for label, scale in (("small", 1), ("large", 5)):
            samples.append(
                _sample(
                    f"{visit}-{label}",
                    label,
                    "buflo",
                    visit,
                    f"{visit}-{label}",
                    scale=scale,
                )
            )
    (result,) = run_historical_attacks(
        samples,
        attacks=("panchenko",),
        random_state=evaluation._DLSVM_RANDOM_STATE,
    )
    forged = result.as_dict()
    forged["block_workload_bootstrap_95"] = attack_bootstrap_intervals(
        result, draws=5, seed=20260827
    )
    prediction = forged["predictions"][0]
    prediction["predicted"] = next(
        label for label in forged["labels"] if label != prediction["predicted"]
    )
    forged["predictions_sha256"] = evaluation._canonical_json_sha256(forged["predictions"])
    accuracy, balanced, matrix, recalls = evaluation._classification_metrics(
        [item["expected"] for item in forged["predictions"]],
        [item["predicted"] for item in forged["predictions"]],
        forged["labels"],
    )
    forged["accuracy"] = accuracy
    forged["balanced_accuracy"] = balanced
    forged["confusion_matrix"] = [list(row) for row in matrix]
    forged["per_class_recall"] = recalls

    structurally_valid = evaluation._validate_attack_record(forged, samples=samples)
    with pytest.raises(ValueError, match="deterministic replay"):
        evaluation._validate_attack_replay(
            [forged],
            [structurally_valid],
            samples=samples,
            dlsvm_cache=None,
        )


def test_evaluation_receipt_static_contract_is_exact_and_fail_closed(tmp_path: Path) -> None:
    destination = tmp_path / "evaluation.json"
    evaluation.write_evaluation_receipt(
        destination,
        samples=(),
        attack_results=(),
        bootstrap_draws=1,
    )
    canonical = json.loads(destination.read_text(encoding="utf-8"))
    assert set(canonical) == evaluation._EVALUATION_RECEIPT_KEYS
    assert canonical["schema_version"] == evaluation.EVALUATION_RECEIPT_SCHEMA_VERSION
    evaluation._validate_evaluation_receipt_value(
        canonical,
        samples=(),
        handoff_root=None,
        formal=False,
        deep=False,
    )

    with pytest.raises(ValueError, match="exactly 10000 bootstrap draws"):
        evaluation.write_evaluation_receipt(
            tmp_path / "formal-wrong-draws.json",
            samples=(),
            attack_results=(),
            bootstrap_draws=9_999,
            formal=True,
        )

    missing = json.loads(json.dumps(canonical))
    del missing["observation_layer"]
    with pytest.raises(ValueError, match="schema"):
        evaluation._validate_evaluation_receipt_value(
            missing,
            samples=(),
            handoff_root=None,
            formal=False,
            deep=False,
        )

    extra = json.loads(json.dumps(canonical))
    extra["unbound_extension"] = True
    with pytest.raises(ValueError, match="schema"):
        evaluation._validate_evaluation_receipt_value(
            extra,
            samples=(),
            handoff_root=None,
            formal=False,
            deep=False,
        )

    semantic_tampers = {
        "observation_layer": "udp-payload-only",
        "overhead_formula": "mean-of-per-trace-ratios",
        "five_class_random_chance_accuracy": 0.25,
        "temporal_protocol": {
            **canonical["temporal_protocol"],
            "heldout_use": "tuned-on-block-10",
        },
        "limitations": canonical["limitations"][:-1],
    }
    for field, replacement in semantic_tampers.items():
        tampered = json.loads(json.dumps(canonical))
        tampered[field] = replacement
        with pytest.raises(ValueError, match="schema"):
            evaluation._validate_evaluation_receipt_value(
                tampered,
                samples=(),
                handoff_root=None,
                formal=False,
                deep=False,
            )


def test_evaluation_receipt_interruption_never_publishes_partial_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "evaluation.json"
    orphan = tmp_path / (f".{destination.name}{evaluation.ATOMIC_TEMP_MARKER}interrupted")
    durable_create = evaluation.durable_create

    def interrupt(path: Path, value: bytes) -> None:
        assert path == destination
        orphan.write_bytes(value[:23])
        raise RuntimeError("simulated publication interruption")

    monkeypatch.setattr(evaluation, "durable_create", interrupt)
    with pytest.raises(RuntimeError, match="publication interruption"):
        evaluation.write_evaluation_receipt(
            destination,
            samples=(),
            attack_results=(),
            bootstrap_draws=1,
        )
    assert not destination.exists()
    assert orphan.is_file()

    monkeypatch.setattr(evaluation, "durable_create", durable_create)
    evaluation.write_evaluation_receipt(
        destination,
        samples=(),
        attack_results=(),
        bootstrap_draws=1,
    )
    assert destination.is_file()


def test_historical_dlsvm_reuses_one_exact_within_defense_matrix() -> None:
    samples = []
    for visit in range(10):
        for label, scale in (("small", 1), ("large", 5)):
            samples.append(
                _sample(
                    f"{visit}-{label}",
                    label,
                    "buflo",
                    visit,
                    f"{visit}-{label}",
                    scale=scale,
                )
            )

    (result,) = run_historical_attacks(samples, attacks=("dlsvm",), random_state=3)

    assert result.protocol == "historical-stratified-10fold"
    assert result.backend.startswith("clean-room-ccs12-restricted-osa-svm-")
    assert result.test_samples == 20


def test_evaluation_destination_cannot_overlap_handoff(tmp_path: Path) -> None:
    handoff_root = tmp_path / "handoff"
    handoff_root.mkdir()
    with pytest.raises(ValueError, match="overlaps protected input"):
        evaluation.evaluate_handoff(
            handoff_root,
            handoff_root / "evaluation.json",
            formal=False,
        )


def test_existing_evaluation_destination_fails_before_handoff_or_cache_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import qcsd_lab.buflo_handoff as handoff_module

    handoff = tmp_path / "handoff"
    handoff.mkdir()
    destination = tmp_path / "evaluation.json"
    destination.write_text('{"existing":true}\n', encoding="utf-8")

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("handoff validation began for an existing destination")

    monkeypatch.setattr(handoff_module, "validate_study_handoff", forbidden)
    with pytest.raises(FileExistsError, match="already exists"):
        evaluation.evaluate_handoff(handoff, destination, formal=False)
    assert not destination.with_name(destination.name + ".dlsvm-preflight.json").exists()
    assert not destination.with_name(destination.name + ".dlsvm-kernels").exists()


@pytest.mark.parametrize("environment", evaluation._FORMAL_RUNTIME_OVERRIDE_ENV)
def test_formal_evaluate_rejects_runtime_overrides_before_any_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment: str,
) -> None:
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    destination = tmp_path / "evaluation.json"
    monkeypatch.setenv(environment, "/tmp/qcsd-forged-runtime")

    with pytest.raises(RuntimeError, match="forbids runtime path overrides"):
        evaluation.evaluate_handoff(handoff, destination, formal=True)
    assert not destination.exists()
    assert not destination.with_name(destination.name + ".dlsvm-preflight.json").exists()
    assert not destination.with_name(destination.name + ".dlsvm-kernels").exists()


def test_formal_evaluate_rejects_preloaded_alternate_runtime_before_any_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved_java = tmp_path / "approved-java"
    alternate_java = tmp_path / "alternate-java"
    approved_jar = tmp_path / "approved.jar"
    alternate_jar = tmp_path / "alternate.jar"
    approved_osad = tmp_path / "approved-osad.so"
    alternate_osad = tmp_path / "alternate-osad.so"
    for path in (
        approved_java,
        alternate_java,
        approved_jar,
        alternate_jar,
        approved_osad,
        alternate_osad,
    ):
        path.write_bytes(path.name.encode("ascii"))
    approved_runtime = {"sha256": "a" * 64}
    approved = {
        "vngpp": {
            "backend": "pinned-weka-3.7.5",
            "runtime": {
                "java_path": str(approved_java),
                "java_sha256": evaluation.sha256_file(approved_java),
                "java_version": "fixture-java",
                "artifacts": [
                    {"path": str(approved_jar), "sha256": evaluation.sha256_file(approved_jar)}
                ],
            },
            "approved_runtime": approved_runtime,
        },
        "dlsvm": {
            "engine": "clean-room-native-c",
            "native_library": {
                "path": str(approved_osad),
                "sha256": evaluation.sha256_file(approved_osad),
            },
            "approved_runtime": approved_runtime,
        },
    }
    monkeypatch.setattr(evaluation, "vngpp_backend_receipt", lambda **_kwargs: approved["vngpp"])
    monkeypatch.setattr(evaluation, "dlsvm_backend_receipt", lambda **_kwargs: approved["dlsvm"])

    def forbidden_java_version(path: Path) -> str:
        raise AssertionError(f"alternate Java was executed during rejection: {path}")

    monkeypatch.setattr(evaluation, "_java_version", forbidden_java_version)
    monkeypatch.setattr(
        evaluation,
        "_load_weka_backend",
        lambda: evaluation.WekaBackend(java=alternate_java, artifacts=(alternate_jar,)),
    )
    monkeypatch.setattr(
        evaluation,
        "_load_osad_library",
        lambda: (object(), alternate_osad),
    )
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    destination = tmp_path / "evaluation.json"

    with pytest.raises(RuntimeError, match="loaded classifier runtime differs"):
        evaluation.evaluate_handoff(handoff, destination, formal=True)
    assert not destination.exists()
    assert not destination.with_name(destination.name + ".dlsvm-preflight.json").exists()
    assert not destination.with_name(destination.name + ".dlsvm-kernels").exists()


def test_formal_evaluate_handoff_readmits_before_initial_matrix_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import qcsd_lab.buflo_handoff as handoff_module

    handoff = tmp_path / "handoff"
    handoff.mkdir()
    destination = tmp_path / "evaluation.json"
    samples = (_sample("a", "site", "buflo", 0, "a"),)
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        evaluation,
        "_formal_classifier_runtime_receipts",
        lambda: {"fixture": True},
    )
    monkeypatch.setattr(evaluation, "_load_osad_library", lambda: object())
    monkeypatch.setattr(evaluation, "_load_weka_backend", lambda: object())
    monkeypatch.setattr(
        handoff_module,
        "validate_study_handoff",
        lambda path, *, formal, deep: handoff,
    )
    monkeypatch.setattr(evaluation, "load_study_handoff", lambda root: samples)
    monkeypatch.setattr(
        evaluation,
        "validate_formal_cohort",
        lambda selected, *, require_performance: None,
    )

    def write_preflight(path: Path, **kwargs: object) -> Path:
        calls.append(("write", kwargs))
        return path

    def reject_capacity(path: Path, **kwargs: object) -> dict[str, object]:
        calls.append(("admit", kwargs))
        raise ValueError("current-capacity admission rejected")

    class ForbiddenKernelStore:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("matrix construction began before current admission")

    monkeypatch.setattr(evaluation, "write_dlsvm_preflight", write_preflight)
    monkeypatch.setattr(evaluation, "admit_dlsvm_preflight_capacity", reject_capacity)
    monkeypatch.setattr(evaluation, "DlsvmKernelStore", ForbiddenKernelStore)

    with pytest.raises(ValueError, match="current-capacity"):
        evaluation.evaluate_handoff(
            handoff,
            destination,
            formal=True,
            dlsvm_available_wall_seconds=654.0,
        )
    assert [name for name, _ in calls] == ["write", "admit"]
    assert calls[0][1]["execution_model"] == evaluation.FOCUSED_DLSVM_EXECUTION_MODEL
    assert calls[0][1]["available_wall_seconds"] == 654.0
    assert calls[1][1]["expected_execution_model"] == evaluation.FOCUSED_DLSVM_EXECUTION_MODEL
    assert calls[1][1]["available_wall_seconds"] == 654.0
