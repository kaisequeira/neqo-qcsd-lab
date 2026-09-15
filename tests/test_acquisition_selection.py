from __future__ import annotations

import random
from copy import deepcopy
from dataclasses import replace

import pytest

from qcsd_lab.acquisition_selection import (
    ACQUISITION_SELECTION_POLICY,
    derive_acquisition_selection,
)
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    FINAL_CLASS_COUNT,
    PILOT_CLASSES_PER_STRATUM,
    PILOT_COUNT,
    RESERVE_COUNT,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    deterministic_candidate_order,
    select_cohort,
)

LIST_SHA = "a" * 64


@pytest.fixture
def candidates() -> tuple[ClassCandidate, ...]:
    return tuple(
        ClassCandidate(
            candidate_id=f"class-{stratum_index}-{offset:03d}",
            domain=f"site-{stratum_index}-{offset:03d}.example",
            rank=stratum.minimum_rank + offset,
            eligible=False,
        )
        for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA)
        for offset in range(CANDIDATES_PER_STRATUM)
    )


def _groups(candidates):
    ordered = deterministic_candidate_order(candidates, tranco_list_sha256=LIST_SHA)
    return [[candidate.candidate_id for candidate in ordered if candidate.stratum == stratum]
            for stratum in TRANCO_RANK_STRATA]


def _derive(candidates, terminals):
    return derive_acquisition_selection(
        candidates, tranco_list_sha256=LIST_SHA, terminal_eligibility=terminals,
    )


def _partition(plan):
    assert len(plan["candidate_ids"]) == CANDIDATE_COUNT
    assert set(plan["terminal_ids"]).isdisjoint(plan["remaining_ids"])
    assert set(plan["terminal_ids"]) | set(plan["remaining_ids"]) == set(plan["candidate_ids"])
    assert set(plan["needed_ids"]).isdisjoint(plan["unassessed_ids"])
    assert set(plan["needed_ids"]) | set(plan["unassessed_ids"]) == set(plan["remaining_ids"])
    for field in ("terminal_ids", "prefix_ids", "needed_ids", "admission_ids", "remaining_ids", "unassessed_ids", "pilot_ids"):
        members = set(plan[field])
        assert plan[field] == [candidate_id for candidate_id in plan["candidate_ids"] if candidate_id in members]


def test_empty_terminal_inventory_does_not_use_catalogue_eligibility(candidates):
    plan = _derive(candidates, {})
    assert plan["policy"] == ACQUISITION_SELECTION_POLICY
    assert plan["complete"] is False
    assert plan["pilot_ids"] == plan["terminal_ids"] == plan["unassessed_ids"] == []
    assert plan["needed_ids"] == plan["remaining_ids"] == plan["candidate_ids"]
    assert plan["admission_ids"] == [candidate_id for group in _groups(candidates) for candidate_id in group[:24]]
    assert plan["quota_unmet_strata"] == []
    assert _derive(tuple(replace(candidate, eligible=True) for candidate in candidates), {}) == plan
    _partition(plan)


def test_exact_prefix_stops_at_24_eligible_preserving_unassessed_tail(candidates):
    groups = _groups(candidates)
    terminals = {candidate_id: index % 5 != 0
                 for group in groups for index, candidate_id in enumerate(group[:30])}
    before = deepcopy(terminals)
    plan = _derive(candidates, terminals)
    assert plan["complete"] is True
    assert len(plan["pilot_ids"]) == PILOT_COUNT
    assert len(plan["prefix_ids"]) == len(plan["terminal_ids"]) == 150
    assert len(plan["unassessed_ids"]) == 450
    assert plan["needed_ids"] == plan["quota_unmet_strata"] == []
    assert plan["remaining_ids"] == plan["unassessed_ids"]
    assert all(row["cutoff_id"] == group[29] for row, group in zip(plan["strata"], groups, strict=True))
    assert all(candidate.eligible is False for candidate in candidates)
    assert terminals == before
    _partition(plan)


@pytest.mark.parametrize("early_eligible", [False, True])
def test_earlier_unresolved_candidate_blocks_24_later_finishes(candidates, early_eligible):
    groups = _groups(candidates)
    terminals = {candidate_id: True for group in groups for candidate_id in group[:24]}
    first = groups[0]
    del terminals[first[0]]
    terminals[first[24]] = True
    pending = _derive(candidates, terminals)
    assert pending["complete"] is False
    assert pending["pilot_ids"] == []
    assert pending["needed_ids"] == [first[0]]
    assert pending["strata"][0]["prefix_ids"] == first[:25]
    assert pending["strata"][0]["eligible_ids"] == first[1:25]
    assert pending["strata"][0]["admission_ids"] == first[:24]
    terminals[first[0]] = early_eligible
    complete = _derive(candidates, terminals)
    assert complete["complete"] is True
    assert complete["pilot_ids"][:24] == (first[:24] if early_eligible else first[1:25])
    assert complete["strata"][0]["admission_ids"] == complete["pilot_ids"][:24]
    assert first[24] in complete["terminal_ids"]  # Never erase an overshoot terminal.
    assert first[24] not in complete["unassessed_ids"]
    _partition(pending)
    _partition(complete)


@pytest.mark.parametrize("seed", range(8))
def test_catalogue_and_terminal_insertion_order_cannot_change_selection(candidates, seed):
    groups = _groups(candidates)
    pairs = [(candidate_id, index % 5 != 0)
             for group in groups for index, candidate_id in enumerate(group[:40])]
    expected = _derive(candidates, dict(pairs))
    shuffled = list(candidates)
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    rng.shuffle(pairs)
    assert _derive(iter(shuffled), dict(pairs)) == expected
    _partition(expected)


@pytest.mark.parametrize("seed", range(3))
def test_random_out_of_order_completion_stream_never_selects_first_finishers(candidates, seed):
    groups = _groups(candidates)
    pairs = [(candidate_id, index % 5 != 0)
             for group in groups for index, candidate_id in enumerate(group[:40])]
    expected = _derive(candidates, dict(pairs))
    random.Random(seed).shuffle(pairs)
    terminals = {}
    for candidate_id, eligible in pairs:
        terminals[candidate_id] = eligible
        plan = _derive(candidates, terminals)
        for row in plan["strata"]:
            if row["complete"]:
                assert all(member in terminals for member in row["prefix_ids"])
                assert len(row["eligible_ids"]) == PILOT_CLASSES_PER_STRATUM
        if plan["complete"]:
            assert plan["pilot_ids"] == expected["pilot_ids"]
        else:
            assert plan["pilot_ids"] == []
    assert plan == expected


def test_terminal_tail_is_preserved_without_changing_established_pilot(candidates):
    groups = _groups(candidates)
    terminals = {candidate_id: True for group in groups for candidate_id in group[:24]}
    initial = _derive(candidates, terminals)
    tail_true, tail_false = groups[0][-2:]
    terminals.update({tail_true: True, tail_false: False})
    final = _derive(candidates, terminals)
    assert final["pilot_ids"] == initial["pilot_ids"]
    assert final["prefix_ids"] == initial["prefix_ids"]
    assert len(final["terminal_ids"]) == 122
    assert len(final["unassessed_ids"]) == 478
    assert tail_true in final["terminal_ids"] and tail_false in final["terminal_ids"]
    _partition(final)


def test_exhausted_stratum_below_quota_does_not_authorise_completion(candidates):
    groups = _groups(candidates)
    terminals = {candidate_id: index < 23 for index, candidate_id in enumerate(groups[0])}
    terminals.update({candidate_id: True for group in groups[1:] for candidate_id in group[:24]})
    plan = _derive(candidates, terminals)
    assert plan["complete"] is False
    assert plan["pilot_ids"] == plan["needed_ids"] == []
    assert plan["quota_unmet_strata"] == [TRANCO_RANK_STRATA[0].id]
    assert plan["strata"][0]["quota_unmet"] is True
    assert plan["strata"][0]["cutoff_id"] is None
    assert plan["strata"][0]["prefix_ids"] == groups[0]
    _partition(plan)


@pytest.mark.parametrize("value", [None, 0, 1, "eligible", "false", {}, []])
def test_malformed_terminal_eligibility_is_not_truthy_evidence(candidates, value):
    with pytest.raises(ValueError, match="must be booleans"):
        _derive(candidates, {candidates[0].candidate_id: value})


@pytest.mark.parametrize("terminals", [None, [], [("class-0-000", True)]])
def test_terminal_inventory_requires_mapping(candidates, terminals):
    with pytest.raises(ValueError, match="mapping"):
        _derive(candidates, terminals)


@pytest.mark.parametrize("key", ["unknown-candidate", None, 1])
def test_unknown_terminal_candidate_rejected(candidates, key):
    with pytest.raises(ValueError, match="unknown candidate"):
        _derive(candidates, {key: True})


def test_catalogue_size_stratum_quotas_and_eligibility_type_remain_strict(candidates):
    with pytest.raises(ValueError, match="exactly 600"):
        _derive(candidates[:-1], {})
    changed = list(candidates)
    changed[120] = replace(changed[120], rank=201)
    with pytest.raises(ValueError, match="exactly 120"):
        _derive(changed, {})
    changed = list(candidates)
    changed[0] = replace(changed[0], eligible=1)
    with pytest.raises(ValueError, match="eligibility must be boolean"):
        _derive(changed, {})


def test_prefix_matches_existing_cohort_selection_and_preserves_pairing(candidates):
    groups = _groups(candidates)
    outcomes = {candidate_id: index % 5 != 0
                for group in groups for index, candidate_id in enumerate(group)}
    assessed = tuple(replace(candidate, eligible=outcomes[candidate.candidate_id]) for candidate in candidates)
    oracle = select_cohort(assessed, tranco_list_sha256=LIST_SHA)
    terminals = {candidate_id: outcomes[candidate_id] for group in groups for candidate_id in group[:30]}
    plan = _derive(candidates, terminals)
    assert plan["pilot_ids"] == [candidate.candidate_id for candidate in oracle.pilot]
    assert len(oracle.candidates) == 600
    assert len(oracle.final) == FINAL_CLASS_COUNT and len(oracle.reserves) == RESERVE_COUNT
    paired_ids = [candidate.candidate_id for stratum in TRANCO_RANK_STRATA
                  for candidate in [member for member in oracle.pilot if member.stratum == stratum][4:]]
    pairs = [(paired_ids[index], paired_ids[index + 1]) for index in range(0, len(paired_ids), 2)]
    paired = select_cohort(assessed, tranco_list_sha256=LIST_SHA, feasible_pairs=pairs)
    assert [candidate.candidate_id for candidate in paired.pilot] == plan["pilot_ids"]
    assert [candidate.candidate_id for candidate in paired.final] == paired_ids
    assert len(paired.final) == 100 and len(paired.reserves) == 20 and len(paired.matching) == 50
