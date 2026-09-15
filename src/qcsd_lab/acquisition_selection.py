"""Pure, deterministic terminal-prefix policy for prospective acquisition.

This module neither validates evidence nor selects final/reserve pairs.  The
caller must authenticate terminal receipts before projecting their outcomes to
booleans, and must separately establish that no active work or recovery remains.
``class_study.select_cohort`` continues to own pilot/final/reserve selection.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    PILOT_CLASSES_PER_STRATUM,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    deterministic_candidate_order,
)

ACQUISITION_SELECTION_POLICY = "first-24-eligible-terminal-prefix-per-stratum-v1"
ACQUISITION_SELECTION_SCHEMA_VERSION = 1


def derive_acquisition_selection(
    candidates: Iterable[ClassCandidate],
    *,
    tranco_list_sha256: str,
    terminal_eligibility: Mapping[str, bool],
) -> dict[str, Any]:
    """Derive acquisition needs without converting unknown eligibility to false.

    Only IDs present in ``terminal_eligibility`` are terminal.  Their values must
    be actual booleans derived from validated eligible/rejection receipts; the
    catalogue's prospective ``eligible`` placeholders are not evidence.

    A stratum's current prefix ends at its 24th known eligible terminal, or at
    the catalogue end if fewer are known.  Every unresolved prefix member is
    ``needed``.  Unresolved members after that boundary are ``unassessed`` and
    cannot affect the first 24 eligible choices.  ``remaining_ids`` partitions
    exactly into those two inventories.  Unassessed describes absent terminal
    eligibility, not an assertion that no preliminary observations exist.

    Completion requires 24 eligible members and terminal evidence for every
    earlier candidate in all five strata.  Until then ``pilot_ids`` is empty;
    per-stratum eligible inventories are observations, not provisional choices.
    A fully terminal stratum below quota reports ``quota_unmet`` rather than
    authorising completion.  All inventories retain frozen stratum/hash order,
    including any terminal evidence already collected beyond a final cutoff.
    ``admission_ids`` separately limits new work to the first 24 non-rejected
    members per stratum.  A slot advances only after an explicit rejection;
    previously active work outside this frontier must still drain or recover.
    """

    ordered = deterministic_candidate_order(candidates, tranco_list_sha256=tranco_list_sha256)
    if len(ordered) != CANDIDATE_COUNT:
        raise ValueError(f"candidate inventory must contain exactly {CANDIDATE_COUNT} records")
    candidate_ids = [candidate.candidate_id for candidate in ordered]
    if not isinstance(terminal_eligibility, Mapping):
        raise ValueError("terminal eligibility must be an ID-to-boolean mapping")
    terminals = dict(terminal_eligibility)
    if any(not isinstance(key, str) or key not in candidate_ids for key in terminals):
        raise ValueError("terminal eligibility references an unknown candidate")
    if any(type(value) is not bool for value in terminals.values()):
        raise ValueError("terminal eligibility values must be booleans")

    strata = []
    for stratum in TRANCO_RANK_STRATA:
        members = [candidate.candidate_id for candidate in ordered if candidate.stratum == stratum]
        if len(members) != CANDIDATES_PER_STRATUM:
            raise ValueError(
                f"stratum {stratum.id} must contain exactly {CANDIDATES_PER_STRATUM} candidates"
            )
        eligible_ids: list[str] = []
        cutoff = len(members)
        cutoff_id = None
        for index, candidate_id in enumerate(members):
            if terminals.get(candidate_id) is True:
                eligible_ids.append(candidate_id)
                if len(eligible_ids) == PILOT_CLASSES_PER_STRATUM:
                    cutoff, cutoff_id = index + 1, candidate_id
                    break
        prefix_ids = members[:cutoff]
        needed_ids = [candidate_id for candidate_id in prefix_ids if candidate_id not in terminals]
        quota_met = len(eligible_ids) == PILOT_CLASSES_PER_STRATUM
        admission_ids = [candidate_id for candidate_id in members
                         if terminals.get(candidate_id) is not False][:PILOT_CLASSES_PER_STRATUM]
        strata.append({
            "id": stratum.id,
            "complete": quota_met and not needed_ids,
            "quota_unmet": not quota_met and not needed_ids,
            "cutoff_id": cutoff_id,
            "prefix_ids": prefix_ids,
            "eligible_ids": eligible_ids,
            "needed_ids": needed_ids,
            "admission_ids": admission_ids,
            "unassessed_ids": [candidate_id for candidate_id in members[cutoff:]
                               if candidate_id not in terminals],
        })

    complete = all(stratum["complete"] for stratum in strata)
    return {
        "schema_version": ACQUISITION_SELECTION_SCHEMA_VERSION,
        "policy": ACQUISITION_SELECTION_POLICY,
        "tranco_list_sha256": tranco_list_sha256,
        "complete": complete,
        "quota_unmet_strata": [stratum["id"] for stratum in strata if stratum["quota_unmet"]],
        "candidate_ids": candidate_ids,
        "terminal_ids": [candidate_id for candidate_id in candidate_ids if candidate_id in terminals],
        "prefix_ids": [candidate_id for stratum in strata for candidate_id in stratum["prefix_ids"]],
        "needed_ids": [candidate_id for stratum in strata for candidate_id in stratum["needed_ids"]],
        "admission_ids": [candidate_id for stratum in strata for candidate_id in stratum["admission_ids"]],
        "remaining_ids": [candidate_id for candidate_id in candidate_ids if candidate_id not in terminals],
        "unassessed_ids": [candidate_id for stratum in strata for candidate_id in stratum["unassessed_ids"]],
        "pilot_ids": [candidate_id for stratum in strata for candidate_id in stratum["eligible_ids"]]
                     if complete else [],
        "strata": strata,
    }
