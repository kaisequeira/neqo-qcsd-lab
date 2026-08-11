from __future__ import annotations

import copy
import itertools
from pathlib import Path
from types import SimpleNamespace

import pytest

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
    burst_sequence,
    componentwise_envelope,
    minimum_weight_perfect_matching,
)
from qcsd_lab.fitting_wtfpad import (
    ModelCandidate,
    _fit_population,
    _select_candidate,
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


def test_walkie_talkie_matching_is_full_cohort_and_lexically_tied() -> None:
    envelope = componentwise_envelope(((BurstPair(2, 3, True),),))
    selected = minimum_weight_perfect_matching(
        {name: envelope for name in ("alpha", "bravo", "charlie", "delta")}
    )
    assert selected == (("alpha", "bravo", 0), ("charlie", "delta", 0))
    with pytest.raises(ValueError, match="even workload count"):
        minimum_weight_perfect_matching({"alpha": envelope})


def test_walkie_talkie_matching_ignores_nonlexical_input_order() -> None:
    envelope = componentwise_envelope(((BurstPair(2, 3, True),),))
    selected = minimum_weight_perfect_matching(
        {name: envelope for name in ("delta", "alpha", "charlie", "bravo")}
    )
    assert selected == (("alpha", "bravo", 0), ("charlie", "delta", 0))


def test_walkie_talkie_receipt_rejects_a_nonminimum_lexical_matching() -> None:
    names = ("delta", "alpha", "charlie", "bravo")
    lexical = tuple(sorted(names))
    receipt = {
        "algorithm": "full-cohort-minimum-weight-perfect-matching",
        "candidate_pair_costs": [
            {"left": left, "right": right, "matching_cost_packets": 0}
            for index, left in enumerate(lexical)
            for right in lexical[index + 1 :]
        ],
        "selected_pairs": [
            {"real": "alpha", "decoy": "charlie", "matching_cost_packets": 0},
            {"real": "bravo", "decoy": "delta", "matching_cost_packets": 0},
        ],
    }
    with pytest.raises(ValueError, match="not the recorded optimum"):
        _validate_walkie_talkie_receipt(receipt, names)


def test_walkie_talkie_rejects_visit_direction_structure_changes() -> None:
    with pytest.raises(ValueError, match="direction structure"):
        componentwise_envelope(
            (
                (BurstPair(2, 2, True),),
                (BurstPair(2, 0, True),),
            )
        )
