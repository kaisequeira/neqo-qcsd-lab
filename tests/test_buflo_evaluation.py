from __future__ import annotations

import hashlib
import json
import random
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

import qcsd_lab.buflo_evaluation as evaluation
from qcsd_lab.buflo_evaluation import (
    AttackResult,
    DlsvmKernelStore,
    FORMAL_CLASS_BY_WORKLOAD,
    ShapePacket,
    StudySample,
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
    algorithm_breakdowns,
    ratio_of_sums,
    run_historical_attacks,
    run_temporal_attacks,
    summarize_paired_overheads,
    validate_formal_cohort,
    vngpp_features,
    validate_dlsvm_preflight,
    write_dlsvm_preflight,
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

    artifact.write_bytes(b"not-an-npy")
    broken = DlsvmKernelStore(samples, cache_directory=cache)
    with pytest.raises((ValueError, OSError), match="cached|pickle|load|format"):
        broken.kernels(samples, samples)


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
        "runner_rows": {"schedule": 2, "events": 1, "packets": 1, "typed_events": 1, "typed_packets": 1},
        "directions": {"outgoing": direction, "incoming": direction},
        "cs_buflo_state": {
            "padding_variant": "CTSP",
            "early_termination_semantics": "udp_client_only_observed_udp_power_of_two_crossing",
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
    sample = StudySample(
        "s", "site", "site", "cs-buflo", 0, "p", _trace(), None, diagnostics
    )

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


def test_handoff_loader_checks_trace_digest_and_shape_contract(tmp_path: Path) -> None:
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
        "schema_version": 1,
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
        len(fold["training_sample_ids"]) == 18
        and len(fold["testing_sample_ids"]) == 2
        for fold in result.protocol_details["folds"]
    )
    record = result.as_dict()
    assert record["predictions_sha256"] == evaluation._canonical_json_sha256(
        record["predictions"]
    )


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
    forged["predictions_sha256"] = evaluation._canonical_json_sha256(
        forged["predictions"]
    )
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
    forged["predictions_sha256"] = evaluation._canonical_json_sha256(
        forged["predictions"]
    )
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
    evaluation._validate_evaluation_receipt_value(
        canonical,
        samples=(),
        handoff_root=None,
        formal=False,
        deep=False,
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
