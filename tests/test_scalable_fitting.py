from __future__ import annotations

import itertools
import math
import random
from types import SimpleNamespace
from typing import Mapping, Sequence

import pytest
import qcsd_lab.fitting as fitting_module

from qcsd_lab.fitting_morphing import minimum_cost_derangement
from qcsd_lab.fitting_walkie_talkie import (
    BurstPair,
    ProfileEnvelope,
    minimum_weight_perfect_matching,
    minimum_weight_perfect_matching_from_costs,
    symmetric_mold_padding_cost,
)


def _exhaustive_derangement(
    names: Sequence[str],
    candidates: Mapping[tuple[str, str], SimpleNamespace],
) -> tuple[tuple[str, str], ...]:
    ordered = tuple(names)
    eligible = (
        targets
        for targets in itertools.permutations(ordered)
        if all(source != target for source, target in zip(ordered, targets, strict=True))
    )
    selected = min(
        eligible,
        key=lambda targets: (
            math.fsum(
                candidates[(source, target)].fidelity_cost
                for source, target in zip(ordered, targets, strict=True)
            ),
            math.fsum(
                candidates[(source, target)].byte_cost
                for source, target in zip(ordered, targets, strict=True)
            ),
            targets,
        ),
    )
    return tuple(zip(ordered, selected, strict=True))


@pytest.mark.parametrize("size", (2, 3, 4, 5, 6, 7))
def test_scalable_derangement_matches_small_exhaustive_oracle(size: int) -> None:
    names = tuple(f"workload-{index:02d}" for index in range(size))
    random_source = random.Random(0x51A1 + size)
    candidates = {
        (source, target): SimpleNamespace(
            fidelity_cost=float(random_source.randrange(4)),
            byte_cost=float(random_source.randrange(7)),
        )
        for source in names
        for target in names
        if source != target
    }

    assert minimum_cost_derangement(names, candidates) == _exhaustive_derangement(
        names, candidates
    )


def test_scalable_derangement_handles_one_hundred_classes_deterministically() -> None:
    names = tuple(f"workload-{index:03d}" for index in range(100))
    candidates = {
        (source, target): SimpleNamespace(
            fidelity_cost=float(target_index != (source_index + 1) % len(names)),
            byte_cost=0.0,
        )
        for source_index, source in enumerate(names)
        for target_index, target in enumerate(names)
        if source != target
    }
    expected = tuple(
        (source, names[(source_index + 1) % len(names)])
        for source_index, source in enumerate(names)
    )

    assert minimum_cost_derangement(names, candidates) == expected
    assert minimum_cost_derangement(tuple(reversed(names)), candidates) == tuple(
        (source, names[(names.index(source) + 1) % len(names)])
        for source in reversed(names)
    )


def test_traffic_morphing_receipt_validation_scales_to_one_hundred_classes() -> None:
    names = tuple(f"workload-{index:03d}" for index in range(100))
    candidate_costs = [
        {
            "source": source,
            "target": target,
            "l1_cost": float(target_index != (source_index + 1) % len(names)),
            "estimated_added_bytes": 0.0,
        }
        for source_index, source in enumerate(names)
        for target_index, target in enumerate(names)
        if source != target
    ]
    candidate_by_edge = {
        (record["source"], record["target"]): record for record in candidate_costs
    }
    receipt = {
        "algorithm": "all-directed-padding-only-lp-then-minimum-cost-derangement",
        "candidate_costs": candidate_costs,
        "corpus_bucket_counts": [
            {
                "workload_id": name,
                "outgoing": [1, 0, 0, 0, 0, 0, 0, 0],
                "incoming": [1, 0, 0, 0, 0, 0, 0, 0],
            }
            for name in names
        ],
        "selected_mapping": [
            dict(candidate_by_edge[(source, names[(index + 1) % len(names)])])
            for index, source in enumerate(names)
        ],
    }

    fitting_module._validate_traffic_morphing_receipt(receipt, names)


def _envelope(*pairs: tuple[int, int]) -> ProfileEnvelope:
    return ProfileEnvelope(
        tuple(
            BurstPair(outgoing, incoming, index == len(pairs) - 1)
            for index, (outgoing, incoming) in enumerate(pairs)
        ),
        1,
        0,
        0,
    )


def _exhaustive_matching(
    envelopes: Mapping[str, ProfileEnvelope],
) -> tuple[tuple[str, str, int], ...]:
    names = tuple(sorted(envelopes))
    costs = {
        (left, right): symmetric_mold_padding_cost(
            envelopes[left].bursts, envelopes[right].bursts
        )
        for index, left in enumerate(names)
        for right in names[index + 1 :]
    }

    def choose(remaining: tuple[str, ...]) -> tuple[int, tuple[tuple[str, str], ...]]:
        if not remaining:
            return 0, ()
        left = remaining[0]
        options: list[tuple[int, tuple[tuple[str, str], ...]]] = []
        for index in range(1, len(remaining)):
            right = remaining[index]
            rest = remaining[1:index] + remaining[index + 1 :]
            rest_cost, rest_pairs = choose(rest)
            options.append((costs[(left, right)] + rest_cost, ((left, right), *rest_pairs)))
        return min(options)

    _cost, pairs = choose(names)
    return tuple((left, right, costs[(left, right)]) for left, right in pairs)


@pytest.mark.parametrize("size", (2, 4, 6, 8))
def test_scalable_matching_matches_small_exhaustive_oracle(size: int) -> None:
    random_source = random.Random(0x7A11 + size)
    envelopes = {
        f"workload-{index:02d}": _envelope(
            (random_source.randrange(1, 20), random_source.randrange(1, 20)),
            (random_source.randrange(1, 20), random_source.randrange(1, 20)),
        )
        for index in range(size)
    }

    assert minimum_weight_perfect_matching(envelopes) == _exhaustive_matching(envelopes)


@pytest.mark.parametrize("size", (20, 100))
def test_scalable_matching_handles_large_complete_cohorts(size: int) -> None:
    names = tuple(f"workload-{index:03d}" for index in range(size))
    envelopes = {
        name: _envelope((index + 1, 2 * (index + 1)))
        for index, name in enumerate(names)
    }
    expected_pairs = tuple((names[index], names[index + 1]) for index in range(0, size, 2))

    selected = minimum_weight_perfect_matching(envelopes)

    assert tuple((left, right) for left, right, _cost in selected) == expected_pairs
    assert sum(cost for _left, _right, cost in selected) == 3 * (size // 2)


def test_matching_feasible_pairs_restrict_and_can_make_cohort_infeasible() -> None:
    envelopes = {
        name: _envelope((index + 1, index + 2))
        for index, name in enumerate(("alpha", "bravo", "charlie", "delta"))
    }

    assert tuple(
        (left, right)
        for left, right, _cost in minimum_weight_perfect_matching(
            envelopes,
            feasible_pairs={("alpha", "delta"), ("charlie", "bravo")},
        )
    ) == (("alpha", "delta"), ("bravo", "charlie"))
    with pytest.raises(ValueError, match="no feasible perfect matching"):
        minimum_weight_perfect_matching(
            envelopes,
            feasible_pairs={("alpha", "bravo")},
        )


def test_matching_rejects_invalid_feasible_pair() -> None:
    envelopes = {
        "alpha": _envelope((1, 2)),
        "bravo": _envelope((2, 3)),
    }
    with pytest.raises(ValueError, match="invalid workload"):
        minimum_weight_perfect_matching(
            envelopes,
            feasible_pairs={("alpha", "missing")},
        )


def test_matching_rejects_objectives_outside_exact_binary64_domain() -> None:
    names = ("alpha", "bravo", "charlie", "delta")
    magnitude = 2**60
    costs = {
        ("alpha", "bravo"): 0,
        ("alpha", "charlie"): 0,
        ("alpha", "delta"): 0,
        ("bravo", "charlie"): magnitude + 1,
        ("bravo", "delta"): magnitude + 2,
        ("charlie", "delta"): magnitude,
    }

    with pytest.raises(ValueError, match="exact binary64 integer range"):
        minimum_weight_perfect_matching_from_costs(names, costs)


def test_matching_normalisation_accepts_large_common_u64_cost() -> None:
    names = ("alpha", "bravo", "charlie", "delta")
    common = 2**60
    costs = {
        (left, right): common
        for index, left in enumerate(names)
        for right in names[index + 1 :]
    }

    selected = minimum_weight_perfect_matching_from_costs(names, costs)

    assert selected == (
        ("alpha", "bravo", common),
        ("charlie", "delta", common),
    )


@pytest.mark.parametrize("contract_version", (2, 6))
def test_walkie_talkie_receipt_validators_delegate_to_scalable_solver(
    monkeypatch: pytest.MonkeyPatch,
    contract_version: int,
) -> None:
    names = ("alpha", "bravo")
    training_visits = []
    sequence = 0
    for name in names:
        visits = []
        for visit in range(10):
            visits.append(
                {
                    "visit": visit,
                    "training_input_sha256": f"{sequence + 1:064x}",
                    "bursts": [{"outgoing": 1, "incoming": 1}],
                    "batch_ends": [0],
                }
            )
            sequence += 1
        training_visits.append({"workload_id": name, "visits": visits})

    calls: list[tuple[tuple[str, ...], dict[tuple[str, str], int]]] = []

    def scalable_solver(
        workload_names: Sequence[str],
        pair_costs: Mapping[tuple[str, str], int],
    ) -> tuple[tuple[str, str, int], ...]:
        calls.append((tuple(workload_names), dict(pair_costs)))
        return (("alpha", "bravo", 0),)

    monkeypatch.setattr(
        fitting_module.fitting_walkie_talkie,
        "minimum_weight_perfect_matching_from_costs",
        scalable_solver,
    )
    if contract_version == 2:
        receipt = {
            "algorithm": "full-cohort-minimum-weight-perfect-matching",
            "candidate_pair_costs": [
                {"left": "alpha", "right": "bravo", "matching_cost_packets": 0}
            ],
            "selected_pairs": [
                {"real": "alpha", "decoy": "bravo", "matching_cost_packets": 0}
            ],
            "training_visits": training_visits,
        }
    else:
        receipt = {
            "algorithm": "full-cohort-minimum-weight-perfect-matching",
            "pairing_objective": "minimum-base-symmetric-mold-padding-cost",
            "receiver_continuation": (
                fitting_module.fitting_walkie_talkie.receiver_continuation_contract()
            ),
            "candidate_pair_costs": [
                {
                    "left": "alpha",
                    "right": "bravo",
                    "base_matching_cost_packets": 0,
                    "matching_cost_packets": 4,
                }
            ],
            "selected_pairs": [
                {
                    "real": "alpha",
                    "decoy": "bravo",
                    "base_matching_cost_packets": 0,
                    "matching_cost_packets": 4,
                }
            ],
            "training_visits": training_visits,
        }

    fitting_module._validate_walkie_talkie_receipt(
        receipt,
        names,
        contract_version=contract_version,
    )

    assert calls == [(names, {("alpha", "bravo"): 0})]
