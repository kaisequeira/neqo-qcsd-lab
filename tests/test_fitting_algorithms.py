from __future__ import annotations

import copy
import itertools
import math
from pathlib import Path
from types import SimpleNamespace

import pytest
import qcsd_lab.fitting_walkie_talkie as walkie_module

from qcsd_lab.fitting import (
    _validate_traffic_morphing_receipt,
    _validate_walkie_talkie_receipt,
)
from qcsd_lab.fitting_morphing import (
    fit_traffic_morphing,
    minimum_cost_derangement,
    morphing_matrix,
)
from qcsd_lab.fitting_trace import FittingTrace, PacketObservation, TypedObservation
from qcsd_lab.fitting_walkie_talkie import (
    BurstPair,
    ProfileEnvelope,
    burst_sequence,
    componentwise_envelope,
    fit_walkie_talkie,
    minimum_weight_perfect_matching,
    mold,
    mold_padding_cost,
    symmetric_mold,
    symmetric_mold_padding_cost,
)
from qcsd_lab.fitting_wtfpad import (
    ModelCandidate,
    _apportion_tokens,
    _direction_populations,
    _fit_population,
    _select_candidate,
    corpus_mean_bandwidth,
    fit_wtf_pad,
)

import numpy as np


def _packets(shift: int = 0) -> tuple[PacketObservation, ...]:
    values = [
        ("outgoing", 100, 80 + shift),
        ("outgoing", 200, 140 + shift),
        ("incoming", 300, 180 + shift),
        ("outgoing", 400, 280 + shift),
        ("incoming", 450, 320 + shift),
        ("incoming", 650, 460 + shift),
        ("outgoing", 20_400, 680 + shift),
        ("outgoing", 20_550, 880 + shift),
        ("incoming", 25_650, 1_000 + shift),
        ("incoming", 25_800, 1_100 + shift),
        ("outgoing", 60_550, 1_180),
        ("outgoing", 60_750, 300 + shift),
        ("incoming", 70_800, 700 + shift),
        ("incoming", 71_100, 900 + shift),
    ]
    return tuple(
        PacketObservation(direction, time * 1_000, 1, length) for direction, time, length in values
    )


def _trace(name: str, visit: int, *, shift: int = 0) -> FittingTrace:
    return FittingTrace(
        sample_id=f"{name}-{visit}",
        workload_id=name,
        request_policy="as-defined",
        visit=visit,
        root=Path(name),
        packets=_packets(shift),
        observations=(),
        training_input_sha256=f"{visit + shift + 1:064x}",
    )


def _observation(sequence: int, kind: str, **fields: object) -> TypedObservation:
    details = {
        "type": kind,
        "production_monotonic_ns": sequence * 1_000,
        "production_sequence": sequence,
        **fields,
    }
    return TypedObservation(sequence, sequence * 1_000, 1, kind, details)


def test_traffic_morphing_fits_padding_only_derangement_deterministically() -> None:
    traces = {
        name: tuple(_trace(name, visit, shift=index * 5 + visit) for visit in range(2))
        for index, name in enumerate(("alpha", "bravo", "charlie", "delta"))
    }
    first, receipt = fit_traffic_morphing(traces)
    second, second_receipt = fit_traffic_morphing(traces)

    assert first == second
    assert receipt == second_receipt
    profiles = first["profiles"]
    assert sorted(profile["source"] for profile in profiles) == sorted(traces)
    assert sorted(profile["target"] for profile in profiles) == sorted(traces)
    assert all(profile["source"] != profile["target"] for profile in profiles)
    for profile in profiles:
        for direction in ("outgoing", "incoming"):
            rows = profile[direction]["rows"]
            assert all(sum(row) == pytest.approx(1.0, abs=1e-8) for row in rows)
            assert all(
                all(weight == pytest.approx(0.0, abs=1e-10) for weight in row[:index])
                for index, row in enumerate(rows)
            )


def test_traffic_morphing_row_major_tie_stage_canonicalizes_conditional_flow() -> None:
    source = np.asarray([0.5, 0.5, 0.0])
    target = np.asarray([0.0, 0.5, 0.5])
    first = morphing_matrix(source, target, (64, 150, 1_200))
    second = morphing_matrix(source, target, (64, 150, 1_200))
    assert first == second
    assert first.rows[0] == pytest.approx((0.0, 0.0, 1.0), abs=1e-7)
    assert first.rows[1] == pytest.approx((0.0, 1.0, 0.0), abs=1e-7)


def test_traffic_morphing_unsupported_source_rows_are_exact_identity() -> None:
    result = morphing_matrix(
        np.asarray([1.0, 0.0, 0.0]),
        np.asarray([0.0, 0.0, 1.0]),
        (64, 150, 1_200),
    )
    assert result.rows[1] == (0.0, 1.0, 0.0)
    assert result.rows[2] == (0.0, 0.0, 1.0)


def test_traffic_morphing_second_objective_minimizes_bytes_at_fixed_l1() -> None:
    # Moving row zero to the middle bucket and leaving it in place have the
    # same irreducible L1 distance because the high source mass cannot move
    # down.  The second objective must retain the lower-byte identity flow.
    result = morphing_matrix(
        np.asarray([0.5, 0.0, 0.5]),
        np.asarray([0.5, 0.5, 0.0]),
        (64, 150, 1_200),
    )
    assert result.l1_distance == pytest.approx(1.0)
    assert result.expected_added_bytes == 0.0
    assert result.rows[0] == (1.0, 0.0, 0.0)


def test_traffic_morphing_assignment_tie_uses_lexical_target_vector() -> None:
    traces = {name: (_trace(name, 0),) for name in ("zulu", "alpha", "mike")}
    artifact, _receipt = fit_traffic_morphing(traces)
    assert [(profile["source"], profile["target"]) for profile in artifact["profiles"]] == [
        ("zulu", "alpha"),
        ("alpha", "mike"),
        ("mike", "zulu"),
    ]


def test_traffic_morphing_assignment_preserves_near_cost_ordering() -> None:
    names = ("alpha", "bravo", "charlie")
    candidates = {
        (source, target): SimpleNamespace(fidelity_cost=0.0, byte_cost=0.0)
        for source in names
        for target in names
        if source != target
    }
    candidates[("alpha", "bravo")] = SimpleNamespace(fidelity_cost=4e-16, byte_cost=0.0)
    assert minimum_cost_derangement(names, candidates) == (
        ("alpha", "charlie"),
        ("bravo", "alpha"),
        ("charlie", "bravo"),
    )


def test_traffic_morphing_assignment_preserves_near_byte_cost_ordering() -> None:
    names = ("alpha", "bravo", "charlie")
    candidates = {
        (source, target): SimpleNamespace(fidelity_cost=0.0, byte_cost=0.0)
        for source in names
        for target in names
        if source != target
    }
    candidates[("alpha", "bravo")] = SimpleNamespace(
        fidelity_cost=0.0,
        byte_cost=4e-16,
    )
    assert minimum_cost_derangement(names, candidates) == (
        ("alpha", "charlie"),
        ("bravo", "alpha"),
        ("charlie", "bravo"),
    )


def test_traffic_morphing_receipt_rejects_a_nonminimum_derangement() -> None:
    names = ("alpha", "bravo", "charlie", "delta")
    _artifact, receipt = fit_traffic_morphing({name: (_trace(name, 0),) for name in names})
    selected_targets = tuple(item["target"] for item in receipt["selected_mapping"])
    alternative = next(
        targets
        for targets in itertools.permutations(names)
        if targets != selected_targets
        and all(source != target for source, target in zip(names, targets, strict=True))
    )
    candidate_by_edge = {
        (item["source"], item["target"]): item for item in receipt["candidate_costs"]
    }
    tampered = copy.deepcopy(receipt)
    tampered["selected_mapping"] = [
        copy.deepcopy(candidate_by_edge[(source, target)])
        for source, target in zip(names, alternative, strict=True)
    ]
    with pytest.raises(ValueError, match="not the recorded optimum"):
        _validate_traffic_morphing_receipt(tampered, names)


def test_wtf_pad_uses_one_global_threshold_and_exact_token_populations() -> None:
    traces = tuple(_trace("alpha", visit, shift=visit) for visit in range(10))
    first, receipt = fit_wtf_pad(traces, fitted_from="a" * 64)
    second, second_receipt = fit_wtf_pad(traces, fitted_from="a" * 64)

    assert first == second
    assert receipt == second_receipt
    threshold = first["fitting"]["bandwidth_threshold_bytes_per_second"]
    assert threshold > 0
    for direction in ("outgoing", "incoming"):
        assert "bandwidth_threshold_bytes_per_second" not in first[direction]["fit"]
        for state in ("burst", "gap"):
            histogram = first[direction][state]
            assert len(histogram["edges_us"]) == 19
            assert sum(histogram["tokens"]) == 10_000
            assert histogram["infinity_tokens"] > 0
            population = first[direction]["fit"][state]
            assert [candidate["name"] for candidate in population["candidates"]] == [
                "normal",
                "lognormal",
            ]


def test_wtf_pad_rejects_degenerate_delay_populations() -> None:
    packets = tuple(
        PacketObservation(direction, time * 1_000, 1, 600)
        for direction in ("outgoing", "incoming")
        for time in (0, 100, 200, 20_000, 20_100)
    )
    packets = tuple(sorted(packets, key=lambda packet: packet.monotonic_us))
    trace = FittingTrace("sample", "alpha", "as-defined", 0, Path("alpha"), packets, (), "a" * 64)
    with pytest.raises(ValueError, match="distinct values"):
        fit_wtf_pad((trace,), fitted_from="a" * 64)


def test_wtf_pad_rejects_sparse_and_nonpositive_state_populations() -> None:
    with pytest.raises(ValueError, match="at least 20"):
        _fit_population(
            np.arange(1, 20, dtype=np.int64),
            infinity_tokens=1,
            label="sparse",
            tuning_percentile=None,
        )
    with pytest.raises(ValueError, match="positive delays"):
        _fit_population(
            np.asarray([*range(1, 20), 0], dtype=np.int64),
            infinity_tokens=1,
            label="nonpositive",
            tuning_percentile=None,
        )


def test_wtf_pad_never_constructs_an_interarrival_across_visits() -> None:
    traces = tuple(
        FittingTrace(
            sample_id=f"sample-{visit}",
            workload_id="alpha",
            request_policy="as-defined",
            visit=visit,
            root=Path("alpha"),
            packets=(
                PacketObservation("outgoing", 100, 1, 100 + visit),
                PacketObservation("incoming", 150, 1, 200 + visit),
                PacketObservation("outgoing", 300, 1, 300 + visit),
                PacketObservation("incoming", 350, 1, 400 + visit),
            ),
            observations=(),
            training_input_sha256=f"{visit + 1:064x}",
        )
        for visit in range(2)
    )
    intra, between, lengths = _direction_populations(
        traces,
        "outgoing",
        threshold=1e30,
    )
    assert len(intra) == 0
    assert len(between) == 2
    assert len(lengths) == 4


def test_wtf_pad_corpus_threshold_uses_sum_of_per_trace_active_durations() -> None:
    traces = (
        FittingTrace(
            "one",
            "alpha",
            "as-defined",
            0,
            Path("alpha"),
            (
                PacketObservation("outgoing", 100, 1, 100),
                PacketObservation("incoming", 300, 1, 200),
            ),
            (),
            "a" * 64,
        ),
        FittingTrace(
            "two",
            "alpha",
            "as-defined",
            1,
            Path("alpha"),
            (
                PacketObservation("outgoing", 1_000, 1, 300),
                PacketObservation("incoming", 1_400, 1, 400),
            ),
            (),
            "b" * 64,
        ),
    )
    assert corpus_mean_bandwidth(traces) == pytest.approx(
        1_000_000_000 * (100 + 200 + 300 + 400) / ((300 - 100) + (1_400 - 1_000))
    )


def test_wtf_pad_normal_wins_an_exact_ks_tie() -> None:
    candidates = (
        ModelCandidate("normal", (100.0, 10.0), 0.25),
        ModelCandidate("lognormal", (1.0, 0.0, 100.0), 0.25),
    )
    assert _select_candidate(candidates).name == "normal"


def test_wtf_pad_selects_a_full_precision_near_tie() -> None:
    candidates = (
        ModelCandidate("normal", (100.0, 10.0), 0.1000000000000001),
        ModelCandidate("lognormal", (1.0, 0.0, 100.0), 0.1),
    )
    assert _select_candidate(candidates).name == "lognormal"


def test_wtf_pad_largest_remainder_uses_the_lower_bin_on_an_exact_tie() -> None:
    tokens = _apportion_tokens(np.ones(19, dtype=float), 20)
    assert tokens == (2, *([1] * 18))


def test_wtf_pad_infinity_tokens_match_the_runtime_formulas() -> None:
    artifact, _receipt = fit_wtf_pad(
        tuple(_trace("alpha", visit, shift=visit) for visit in range(10)),
        fitted_from="a" * 64,
    )
    assert artifact["fitting"]["infinity_token_formulas"] == {
        "burst": "k_inf = (1 - p_fake) / p_fake * K",
        "gap": "k_inf = (K - mean_burst_length + 1) / (mean_burst_length - 1)",
    }
    expected_burst = math.ceil((1.0 - 0.9) / 0.9 * 10_000)
    for direction in ("outgoing", "incoming"):
        mean = artifact[direction]["fit"]["mean_burst_length_packets"]
        expected_gap = math.ceil((10_000 - mean + 1) / (mean - 1))
        assert artifact[direction]["burst"]["infinity_tokens"] == expected_burst
        assert artifact[direction]["gap"]["infinity_tokens"] == expected_gap
        for state in ("burst", "gap"):
            lognormal = artifact[direction]["fit"][state]["candidates"][1]
            assert lognormal["name"] == "lognormal"
            assert lognormal["parameters"][1] == 0.0


def test_wtf_pad_cutoff_is_model_percentile_not_observed_maximum(monkeypatch) -> None:
    candidates = (
        ModelCandidate("normal", (100.0, 10.0), 0.1),
        ModelCandidate("lognormal", (1.0, 0.0, 100.0), 0.2),
    )
    monkeypatch.setattr("qcsd_lab.fitting_wtfpad._model_candidates", lambda _values: candidates)
    histogram, fitted = _fit_population(
        np.asarray([*range(90, 109), 1_000_000], dtype=np.int64),
        infinity_tokens=10,
        label="long-tail",
        tuning_percentile=None,
    )
    assert histogram["edges_us"][-1] == fitted["histogram_max_us"]
    assert fitted["histogram_max_us"] < 1_000_000


def test_wtf_pad_rejects_nonpositive_direction_interarrival() -> None:
    packets = (
        PacketObservation("outgoing", 100_000, 1, 600),
        PacketObservation("incoming", 100_000, 1, 600),
        PacketObservation("outgoing", 100_000, 1, 700),
        PacketObservation("incoming", 200_000, 1, 700),
    )
    trace = FittingTrace("sample", "alpha", "as-defined", 0, Path("alpha"), packets, (), "a" * 64)
    with pytest.raises(ValueError, match="nonpositive inter-arrival"):
        fit_wtf_pad((trace,), fitted_from="a" * 64)


def test_walkie_talkie_uses_typed_batches_and_deduplicates_stream_ranges() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_300,
        ),
        _observation(
            3,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=1_000,
            bytes=300,
        ),
        _observation(4, "bytes_read", endpoint=1, stream=4, bytes=2_400),
        _observation(5, "application_batch_completed"),
        _observation(6, "application_complete"),
    )
    trace = FittingTrace(
        "sample",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    assert burst_sequence(trace) == (BurstPair(outgoing=2, incoming=2, batch_end=True),)


def test_walkie_talkie_cell_conversion_uses_ceiling_division() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_201,
        ),
        _observation(3, "bytes_read", endpoint=1, stream=4, bytes=1),
        _observation(4, "application_batch_completed"),
        _observation(5, "application_complete"),
    )
    trace = FittingTrace(
        "ceil",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    assert burst_sequence(trace) == (BurstPair(2, 1, True),)


def test_walkie_talkie_ignores_valid_zero_byte_reads_without_direction_changes() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "bytes_read", endpoint=1, stream=4, bytes=0),
        _observation(2, "application_batch_started"),
        _observation(
            3,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_200,
        ),
        _observation(4, "bytes_read", endpoint=1, stream=4, bytes=0),
        _observation(5, "bytes_read", endpoint=1, stream=4, bytes=1_200),
        _observation(6, "bytes_read", endpoint=1, stream=4, bytes=0),
        _observation(7, "application_batch_completed"),
        _observation(8, "bytes_read", endpoint=1, stream=4, bytes=0),
        _observation(9, "application_complete"),
    )
    trace = FittingTrace(
        "zero-no-op",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    assert burst_sequence(trace) == (BurstPair(1, 1, True),)


def test_walkie_talkie_zero_only_reads_do_not_satisfy_incoming_batch() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_200,
        ),
        _observation(3, "bytes_read", endpoint=1, stream=4, bytes=0),
        _observation(4, "application_batch_completed"),
        _observation(5, "application_complete"),
    )
    trace = FittingTrace(
        "zero-only",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    with pytest.raises(ValueError, match="requires outgoing then incoming"):
        burst_sequence(trace)


@pytest.mark.parametrize("invalid", [-1, 1.5, 2**64])
def test_walkie_talkie_rejects_invalid_zero_domain_reads(invalid: object) -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_200,
        ),
        _observation(3, "bytes_read", endpoint=1, stream=4, bytes=invalid),
        _observation(4, "application_batch_completed"),
        _observation(5, "application_complete"),
    )
    trace = FittingTrace(
        "invalid-read",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    with pytest.raises(ValueError, match="bytes is not an unsigned integer"):
        burst_sequence(trace)


def test_walkie_talkie_zero_read_still_requires_stream_binding() -> None:
    observations = (
        _observation(0, "application_batch_started"),
        _observation(1, "bytes_read", endpoint=1, stream=4, bytes=0),
        _observation(2, "application_batch_completed"),
        _observation(3, "application_complete"),
    )
    trace = FittingTrace(
        "unbound-zero",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    with pytest.raises(ValueError, match="no stream-open evidence"):
        burst_sequence(trace)


def test_walkie_talkie_excludes_chaff_and_transport_control_events() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(
            1,
            "stream_opened",
            endpoint=1,
            stream=8,
            role={"chaff": {"resource_id": 9}},
        ),
        _observation(2, "application_batch_started"),
        _observation(3, "header_progress", endpoint=1, stream=4, min_remaining=99),
        _observation(
            4,
            "stream_data_transmitted",
            endpoint=1,
            stream=8,
            role={"chaff": {"resource_id": 9}},
            offset=0,
            bytes=9_999,
        ),
        _observation(
            5,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_200,
        ),
        _observation(6, "bytes_read", endpoint=1, stream=8, bytes=9_999),
        _observation(7, "bytes_read", endpoint=1, stream=4, bytes=1_200),
        _observation(8, "application_batch_completed"),
        _observation(9, "application_complete"),
    )
    trace = FittingTrace(
        "control",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    assert burst_sequence(trace) == (BurstPair(1, 1, True),)


def test_walkie_talkie_matching_is_full_cohort_and_lexically_tied() -> None:
    envelope = componentwise_envelope(((BurstPair(2, 3, True),),))
    selected = minimum_weight_perfect_matching(
        {name: envelope for name in ("alpha", "bravo", "charlie", "delta")}
    )
    assert selected == (("alpha", "bravo", 0), ("charlie", "delta", 0))
    with pytest.raises(ValueError, match="even workload count"):
        minimum_weight_perfect_matching({"alpha": envelope})


def test_walkie_talkie_runtime_mould_adds_one_cell_to_each_incoming_component() -> None:
    real = (
        BurstPair(2, 3, False),
        BurstPair(4, 0, True),
        BurstPair(1, 2, True),
    )
    decoy = (
        BurstPair(3, 1, False),
        BurstPair(1, 0, True),
        BurstPair(2, 4, True),
    )

    assert symmetric_mold(real, decoy) == [
        BurstPair(3, 3, False),
        BurstPair(4, 0, True),
        BurstPair(2, 4, True),
    ]
    assert mold(real, decoy) == [
        BurstPair(3, 4, False),
        BurstPair(4, 0, True),
        BurstPair(2, 5, True),
    ]
    assert symmetric_mold_padding_cost(real, decoy) == 9
    assert mold_padding_cost(real, decoy) == 13


def test_walkie_talkie_receiver_continuation_rejects_u32_overflow() -> None:
    maximum = (BurstPair(1, 2**32 - 1, True),)
    with pytest.raises(ValueError, match="adapted incoming component exceeds u32"):
        mold(maximum, maximum)


@pytest.mark.parametrize(
    ("cost", "label"),
    [
        (symmetric_mold_padding_cost, "base"),
        (mold_padding_cost, "runtime"),
    ],
)
def test_walkie_talkie_matching_cost_rejects_u64_overflow(
    monkeypatch: pytest.MonkeyPatch,
    cost: object,
    label: str,
) -> None:
    totals = iter((2**63, 1, 1))
    monkeypatch.setattr(walkie_module, "_total_packets", lambda _bursts: next(totals))
    sequence = (BurstPair(1, 1, True),)
    with pytest.raises(ValueError, match=rf"{label} matching cost exceeds u64"):
        cost(sequence, sequence)  # type: ignore[operator]


def test_walkie_talkie_matching_ignores_nonlexical_input_order() -> None:
    envelope = componentwise_envelope(((BurstPair(2, 3, True),),))
    selected = minimum_weight_perfect_matching(
        {name: envelope for name in ("delta", "alpha", "charlie", "bravo")}
    )
    assert selected == (("alpha", "bravo", 0), ("charlie", "delta", 0))


def test_walkie_talkie_pairing_uses_base_cost_before_receiver_adaptation() -> None:
    def envelope(values: list[tuple[int, int]]) -> ProfileEnvelope:
        return ProfileEnvelope(
            tuple(
                BurstPair(outgoing, incoming, index == len(values) - 1)
                for index, (outgoing, incoming) in enumerate(values)
            ),
            1,
            0,
            0,
        )

    envelopes = {
        "alpha": envelope([(1, 2), (3, 5)]),
        "bravo": envelope([(1, 5), (3, 2), (4, 4), (5, 5)]),
        "charlie": envelope([(5, 1), (4, 5), (2, 1)]),
        "delta": envelope([(2, 2), (5, 2)]),
    }

    # The base-cost optimum is alpha/charlie + bravo/delta (9 + 24).
    # Minimizing adapted cost instead would select alpha/delta + bravo/charlie
    # (10 + 35 rather than 15 + 32), so this fixture binds the intended stage.
    assert minimum_weight_perfect_matching(envelopes) == (
        ("alpha", "charlie", 9),
        ("bravo", "delta", 24),
    )


def test_walkie_talkie_receipt_rejects_a_nonminimum_lexical_matching() -> None:
    names = ("delta", "alpha", "charlie", "bravo")
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_200,
        ),
        _observation(3, "bytes_read", endpoint=1, stream=4, bytes=1_200),
        _observation(4, "application_batch_completed"),
        _observation(5, "application_complete"),
    )
    traces = {
        name: tuple(
            FittingTrace(
                f"{name}-{visit}",
                name,
                "half-duplex",
                visit,
                Path(name),
                _packets(),
                observations,
                f"{index * 10 + visit + 1:064x}",
            )
            for visit in range(10)
        )
        for index, name in enumerate(names)
    }
    artifact, receipt = fit_walkie_talkie(traces)
    assert artifact["schema_version"] == 6
    assert all(
        candidate["matching_cost_packets"] == candidate["base_matching_cost_packets"] + 2
        for candidate in receipt["candidate_pair_costs"]
    )
    assert all(
        selected["matching_cost_packets"] == selected["base_matching_cost_packets"] + 2
        for selected in receipt["selected_pairs"]
    )
    for field in ("base_matching_cost_packets", "matching_cost_packets"):
        tampered_cost = copy.deepcopy(receipt)
        tampered_cost["candidate_pair_costs"][0][field] += 1
        with pytest.raises(ValueError, match="disagree with training envelopes"):
            _validate_walkie_talkie_receipt(tampered_cost, names)
    tampered = copy.deepcopy(receipt)
    tampered["selected_pairs"] = [
        {
            "real": "alpha",
            "decoy": "charlie",
            "base_matching_cost_packets": 0,
            "matching_cost_packets": 2,
        },
        {
            "real": "bravo",
            "decoy": "delta",
            "base_matching_cost_packets": 0,
            "matching_cost_packets": 2,
        },
    ]
    with pytest.raises(ValueError, match="not the recorded optimum"):
        _validate_walkie_talkie_receipt(tampered, names)


def test_walkie_talkie_rejects_visit_direction_structure_changes() -> None:
    with pytest.raises(ValueError, match="direction structure"):
        componentwise_envelope(
            (
                (BurstPair(2, 2, True),),
                (BurstPair(2, 0, True),),
            )
        )


def test_walkie_talkie_rejects_visit_batch_count_changes() -> None:
    with pytest.raises(ValueError, match="same application-batch count"):
        componentwise_envelope(
            (
                (BurstPair(2, 2, True),),
                (BurstPair(2, 2, True), BurstPair(1, 1, True)),
            )
        )


def test_walkie_talkie_rejects_duplicate_training_inputs() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=0,
            bytes=1_200,
        ),
        _observation(3, "bytes_read", endpoint=1, stream=4, bytes=1_200),
        _observation(4, "application_batch_completed"),
        _observation(5, "application_complete"),
    )
    repeated = tuple(
        FittingTrace(
            f"alpha-{visit}",
            "alpha",
            "half-duplex",
            visit,
            Path("alpha"),
            _packets(),
            observations,
            "a" * 64,
        )
        for visit in range(2)
    )
    with pytest.raises(ValueError, match="repeats a training input"):
        fit_walkie_talkie({"alpha": repeated, "bravo": (repeated[0],)})


def test_walkie_talkie_rejects_stream_range_overflow() -> None:
    observations = (
        _observation(0, "stream_opened", endpoint=1, stream=4, role="application"),
        _observation(1, "application_batch_started"),
        _observation(
            2,
            "stream_data_transmitted",
            endpoint=1,
            stream=4,
            role="application",
            offset=2**64 - 1,
            bytes=1,
        ),
        _observation(3, "bytes_read", endpoint=1, stream=4, bytes=1),
        _observation(4, "application_batch_completed"),
        _observation(5, "application_complete"),
    )
    trace = FittingTrace(
        "overflow",
        "alpha",
        "half-duplex",
        0,
        Path("alpha"),
        _packets(),
        observations,
        "a" * 64,
    )
    with pytest.raises(ValueError, match="range exceeds u64"):
        burst_sequence(trace)


def test_walkie_talkie_rejects_cell_count_overflow() -> None:
    with pytest.raises(ValueError, match="training burst"):
        componentwise_envelope(((BurstPair(2**32, 1, True),),))
