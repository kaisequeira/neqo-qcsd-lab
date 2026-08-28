from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    COMPATIBILITY_MODES,
    EVIDENCE_ROLES,
    FINAL_CLASS_COUNT,
    FORMAL_MODES,
    PILOT_COUNT,
    RECEIPT_TYPE,
    RESERVE_COUNT,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    build_study_receipt,
    campaign_sample_counts,
    canonical_json_bytes,
    canonical_json_sha256,
    deterministic_candidate_order,
    formal_split_counts,
    load_study_receipt,
    select_cohort,
    validate_evidence_role,
    validate_study_receipt,
    write_study_receipt,
)

LIST_SHA = "a" * 64
OTHER_LIST_SHA = "b" * 64


def _candidates() -> tuple[ClassCandidate, ...]:
    candidates = []
    for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA):
        for offset in range(CANDIDATES_PER_STRATUM):
            sequence = stratum_index * CANDIDATES_PER_STRATUM + offset
            candidates.append(
                ClassCandidate(
                    candidate_id=f"class-{sequence:03d}",
                    domain=f"site-{sequence:03d}.example",
                    rank=stratum.minimum_rank + offset,
                    eligible=True,
                )
            )
    return tuple(candidates)


def _forced_pair_graph() -> tuple[tuple[str, str], ...]:
    pilot = select_cohort(_candidates(), tranco_list_sha256=LIST_SHA).pilot
    selected = tuple(
        candidate
        for stratum in TRANCO_RANK_STRATA
        for candidate in tuple(item for item in pilot if item.stratum == stratum)[4:]
    )
    return tuple(
        (selected[index].candidate_id, selected[index + 1].candidate_id)
        for index in range(0, len(selected), 2)
    )


def _receipt(*, pair_graph: tuple[tuple[str, str], ...] | None = None) -> dict:
    return build_study_receipt(
        _candidates(),
        tranco_list_id="TEST-LIST-ID",
        tranco_list_sha256=LIST_SHA,
        feasible_pairs=pair_graph,
    )


def test_contract_defines_exact_modes_roles_and_campaign_arithmetic() -> None:
    assert COMPATIBILITY_MODES == (
        "undefended",
        "static",
        "front",
        "tamaraw",
        "traffic-morphing",
        "wtf-pad",
        "walkie-talkie",
        "buflo",
        "cs-buflo",
    )
    assert FORMAL_MODES == tuple(mode for mode in COMPATIBILITY_MODES if mode != "static")
    assert EVIDENCE_ROLES == (
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    )
    assert validate_evidence_role("formal") == "formal"
    with pytest.raises(ValueError, match="unsupported"):
        validate_evidence_role("qualification")

    assert campaign_sample_counts() == {
        "nine_mode_regression": 18,
        "controlled_gate": 160,
        "pilot_fitting": 480,
        "pilot_full_qualification": 720,
        "pilot_compatibility": 1_080,
        "authoritative_fitting": 2_000,
        "final_full_qualification": 600,
        "final_certification": 900,
        "per_block_canaries": 1_000,
        "formal": 16_000,
    }
    splits = formal_split_counts()
    assert splits == {
        "train": {"blocks": tuple(range(1, 9)), "visits_per_class_mode": 16, "samples": 12_800},
        "validation": {"blocks": (9,), "visits_per_class_mode": 2, "samples": 1_600},
        "test": {"blocks": (10,), "visits_per_class_mode": 2, "samples": 1_600},
    }
    assert sum(split["samples"] for split in splits.values()) == 16_000


def test_hash_order_and_unconstrained_selection_are_deterministic() -> None:
    candidates = _candidates()
    first = deterministic_candidate_order(candidates, tranco_list_sha256=LIST_SHA)
    assert first == deterministic_candidate_order(reversed(candidates), tranco_list_sha256=LIST_SHA)
    assert first != deterministic_candidate_order(candidates, tranco_list_sha256=OTHER_LIST_SHA)

    selection = select_cohort(candidates, tranco_list_sha256=LIST_SHA)
    assert len(selection.candidates) == CANDIDATE_COUNT
    assert len(selection.pilot) == PILOT_COUNT
    assert len(selection.final) == FINAL_CLASS_COUNT
    assert len(selection.reserves) == RESERVE_COUNT
    assert selection.matching is None
    assert set(selection.final).isdisjoint(selection.reserves)
    assert set(selection.final) | set(selection.reserves) == set(selection.pilot)
    assert Counter(candidate.stratum.id for candidate in selection.candidates) == {
        stratum.id: CANDIDATES_PER_STRATUM for stratum in TRANCO_RANK_STRATA
    }
    assert Counter(candidate.stratum.id for candidate in selection.pilot) == {
        stratum.id: 24 for stratum in TRANCO_RANK_STRATA
    }
    assert Counter(candidate.stratum.id for candidate in selection.final) == {
        stratum.id: 20 for stratum in TRANCO_RANK_STRATA
    }
    assert Counter(candidate.stratum.id for candidate in selection.reserves) == {
        stratum.id: 4 for stratum in TRANCO_RANK_STRATA
    }


def test_boolean_eligibility_is_the_only_unconstrained_selection_input() -> None:
    candidates = list(_candidates())
    baseline = select_cohort(candidates, tranco_list_sha256=LIST_SHA)
    rejected = baseline.pilot[0]
    candidates[candidates.index(rejected)] = replace(rejected, eligible=False)

    changed = select_cohort(candidates, tranco_list_sha256=LIST_SHA)
    assert rejected not in changed.pilot
    assert len(changed.pilot) == PILOT_COUNT
    assert changed == select_cohort(reversed(candidates), tranco_list_sha256=LIST_SHA)


def test_optional_pair_graph_deterministically_selects_and_covers_final_cohort() -> None:
    graph = _forced_pair_graph()
    selection = select_cohort(
        _candidates(), tranco_list_sha256=LIST_SHA, feasible_pairs=reversed(graph)
    )
    assert selection.feasible_pairs is not None
    assert selection.matching is not None
    assert len(selection.matching) == FINAL_CLASS_COUNT // 2
    matched = [candidate_id for pair in selection.matching for candidate_id in pair]
    assert len(matched) == len(set(matched)) == FINAL_CLASS_COUNT
    assert set(matched) == {candidate.candidate_id for candidate in selection.final}
    assert Counter(candidate.stratum.id for candidate in selection.final) == {
        stratum.id: 20 for stratum in TRANCO_RANK_STRATA
    }

    # The graph intentionally leaves the four earliest pilot members in each
    # stratum without an edge, proving that it is a permitted selection input.
    unconstrained = select_cohort(_candidates(), tranco_list_sha256=LIST_SHA)
    assert selection.final != unconstrained.final
    assert selection == select_cohort(
        reversed(_candidates()), tranco_list_sha256=LIST_SHA, feasible_pairs=graph
    )


def test_selection_rejects_bad_inventories_and_infeasible_pair_graphs() -> None:
    candidates = _candidates()
    with pytest.raises(ValueError, match=f"exactly {CANDIDATE_COUNT}"):
        select_cohort(candidates[:-1], tranco_list_sha256=LIST_SHA)

    duplicate = (*candidates[:-1], replace(candidates[-1], rank=candidates[0].rank))
    with pytest.raises(ValueError, match="duplicate Tranco rank"):
        select_cohort(duplicate, tranco_list_sha256=LIST_SHA)

    eligible = list(candidates)
    ordered = deterministic_candidate_order(eligible, tranco_list_sha256=LIST_SHA)
    first_stratum = [
        candidate for candidate in ordered if candidate.stratum == TRANCO_RANK_STRATA[0]
    ]
    for candidate in first_stratum[: CANDIDATES_PER_STRATUM - 23]:
        eligible[eligible.index(candidate)] = replace(candidate, eligible=False)
    with pytest.raises(ValueError, match="23 eligible"):
        select_cohort(eligible, tranco_list_sha256=LIST_SHA)

    with pytest.raises(ValueError, match="cannot select a perfect"):
        select_cohort(candidates, tranco_list_sha256=LIST_SHA, feasible_pairs=())
    with pytest.raises(ValueError, match="unknown candidate"):
        select_cohort(
            candidates,
            tranco_list_sha256=LIST_SHA,
            feasible_pairs=((candidates[0].candidate_id, "not-a-candidate"),),
        )


def test_study_receipt_is_self_contained_hash_bound_and_semantically_validated() -> None:
    graph = _forced_pair_graph()
    receipt = _receipt(pair_graph=graph)
    assert receipt["receipt_type"] == RECEIPT_TYPE
    assert receipt["payload_sha256"] == canonical_json_sha256(receipt["payload"])
    selection = validate_study_receipt(receipt)
    assert len(selection.candidates) == CANDIDATE_COUNT
    assert len(selection.final) == 100
    assert receipt == _receipt(pair_graph=tuple(reversed(graph)))

    tampered = json.loads(json.dumps(receipt))
    tampered["payload"]["inventories"]["final"][0] = "forged-class"
    with pytest.raises(ValueError, match="SHA-256"):
        validate_study_receipt(tampered)

    # Rehashing an altered payload cannot bypass independently derived mode,
    # cohort, split, and count invariants.
    forged_payload = json.loads(json.dumps(receipt["payload"]))
    forged_payload["modes"]["formal"].append("static")
    rehashed = bind_receipt(forged_payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="derived contract"):
        validate_study_receipt(rehashed)


def test_canonical_receipt_writer_is_create_only_and_load_revalidates(tmp_path: Path) -> None:
    receipt = _receipt()
    destination = tmp_path / "cohort.json"
    assert write_study_receipt(destination, receipt) == destination
    assert destination.read_bytes() == canonical_json_bytes(receipt)
    loaded, selection = load_study_receipt(destination)
    assert loaded == receipt
    assert len(selection.final) == 100

    original = destination.read_bytes()
    with pytest.raises(FileExistsError, match="create-only"):
        write_study_receipt(destination, receipt)
    assert destination.read_bytes() == original


def test_receipt_rejects_candidate_and_envelope_tampering_even_when_rehashed() -> None:
    receipt = _receipt()
    extra_field = json.loads(json.dumps(receipt))
    extra_field["unexpected"] = True
    with pytest.raises(ValueError, match="envelope"):
        validate_study_receipt(extra_field)

    payload = json.loads(json.dumps(receipt["payload"]))
    payload["candidates"][0]["stratum"] = TRANCO_RANK_STRATA[-1].id
    forged = bind_receipt(payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="incorrect rank stratum"):
        validate_study_receipt(forged)

    payload = json.loads(json.dumps(receipt["payload"]))
    payload["campaign_sample_counts"]["formal"] -= 1
    forged = bind_receipt(payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="derived contract"):
        validate_study_receipt(forged)


def test_canonical_json_rejects_non_json_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"not_json": float("nan")})
