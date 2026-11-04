"""Pure, deterministic terminal-prefix policy for prospective acquisition.

This module neither validates evidence nor selects final/reserve pairs.  The
caller must authenticate terminal receipts before projecting their outcomes to
booleans, and must separately establish that no active work or recovery remains.
``class_study.select_cohort`` continues to own pilot/final/reserve selection.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from collections.abc import Sequence
from typing import Any

from .class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    PILOT_CLASSES_PER_STRATUM,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    canonical_json_bytes,
    deterministic_candidate_order,
)

ACQUISITION_SELECTION_POLICY = "first-24-eligible-terminal-prefix-per-stratum-v1"
ACQUISITION_SELECTION_SCHEMA_VERSION = 1
OPERATIONAL_CENSOR_SELECTION_POLICY = "first-quota-eligible-resolved-prefix-with-operational-censor-v2"
OPERATIONAL_CENSOR_SELECTION_SCHEMA_VERSION = 2
GLOBAL_OPERATIONAL_CENSOR_SELECTION_POLICY = (
    "first-global-quota-eligible-resolved-prefix-with-operational-censor-v3"
)
GLOBAL_OPERATIONAL_CENSOR_SELECTION_SCHEMA_VERSION = 3


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


def derive_operational_censor_selection(
    candidates: Iterable[ClassCandidate],
    *,
    tranco_list_sha256: str,
    terminal_disposition: Mapping[str, str],
    quota_per_stratum: int = PILOT_CLASSES_PER_STRATUM,
) -> dict[str, Any]:
    """Select the ordered eligible prefix while separately exposing censored sites.

    The caller authenticates each disposition against its terminal and attempt
    ledger. A censor consumes no pilot slot and makes no claim about the site.
    The quota is an explicit prospective contract input; historical v1 always
    keeps its original fixed quota and boolean projection.
    """

    if type(quota_per_stratum) is not int or not 1 <= quota_per_stratum <= CANDIDATES_PER_STRATUM:
        raise ValueError("prospective acquisition quota is invalid")
    if not isinstance(terminal_disposition, Mapping):
        raise ValueError("terminal disposition must be a mapping")
    dispositions = dict(terminal_disposition)
    if any(value not in {"eligible", "site-rejected", "operational-censor"}
           or type(value) is not str for value in dispositions.values()):
        raise ValueError("terminal disposition has an invalid outcome")
    eligible = {candidate_id: value == "eligible" for candidate_id, value in dispositions.items()}
    base = derive_acquisition_selection(
        candidates, tranco_list_sha256=tranco_list_sha256,
        terminal_eligibility=eligible,
    ) if quota_per_stratum == PILOT_CLASSES_PER_STRATUM else None
    if base is not None:
        # Reuse the historical ordering and cutoff arithmetic at the unchanged
        # quota, then bind the additional disposition inventories explicitly.
        base["policy"] = OPERATIONAL_CENSOR_SELECTION_POLICY
        base["schema_version"] = OPERATIONAL_CENSOR_SELECTION_SCHEMA_VERSION
        base["quota_per_stratum"] = quota_per_stratum
        base["operational_censor_ids"] = [
            candidate_id for candidate_id in base["candidate_ids"]
            if dispositions.get(candidate_id) == "operational-censor"
        ]
        base["site_rejected_ids"] = [
            candidate_id for candidate_id in base["candidate_ids"]
            if dispositions.get(candidate_id) == "site-rejected"
        ]
        for stratum in base["strata"]:
            members = set(stratum["prefix_ids"] + stratum["unassessed_ids"])
            stratum["operational_censor_ids"] = [
                candidate_id for candidate_id in base["operational_censor_ids"]
                if candidate_id in members
            ]
            stratum["site_rejected_ids"] = [
                candidate_id for candidate_id in base["site_rejected_ids"]
                if candidate_id in members
            ]
        return base

    # Keep a prospective quota change local to this policy. The final cohort
    # contract must independently accept that quota before any promotion.
    ordered = deterministic_candidate_order(candidates, tranco_list_sha256=tranco_list_sha256)
    if len(ordered) != CANDIDATE_COUNT:
        raise ValueError(f"candidate inventory must contain exactly {CANDIDATE_COUNT} records")
    candidate_ids = [candidate.candidate_id for candidate in ordered]
    if any(not isinstance(key, str) or key not in candidate_ids for key in dispositions):
        raise ValueError("terminal disposition references an unknown candidate")
    strata = []
    for stratum in TRANCO_RANK_STRATA:
        members = [candidate.candidate_id for candidate in ordered if candidate.stratum == stratum]
        if len(members) != CANDIDATES_PER_STRATUM:
            raise ValueError(f"stratum {stratum.id} must contain exactly {CANDIDATES_PER_STRATUM} candidates")
        eligible_ids = [candidate_id for candidate_id in members
                        if dispositions.get(candidate_id) == "eligible"][:quota_per_stratum]
        quota_met = len(eligible_ids) == quota_per_stratum
        cutoff = members.index(eligible_ids[-1]) + 1 if quota_met else len(members)
        prefix = members[:cutoff]
        needed = [candidate_id for candidate_id in prefix if candidate_id not in dispositions]
        strata.append({
            "id": stratum.id, "complete": quota_met and not needed,
            "quota_unmet": not quota_met and not needed,
            "cutoff_id": eligible_ids[-1] if quota_met else None,
            "prefix_ids": prefix, "eligible_ids": eligible_ids, "needed_ids": needed,
            "admission_ids": [candidate_id for candidate_id in members
                              if dispositions.get(candidate_id) not in {"site-rejected", "operational-censor"}][:quota_per_stratum],
            "unassessed_ids": [candidate_id for candidate_id in members[cutoff:]
                               if candidate_id not in dispositions],
            "operational_censor_ids": [candidate_id for candidate_id in members
                                       if dispositions.get(candidate_id) == "operational-censor"],
            "site_rejected_ids": [candidate_id for candidate_id in members
                                  if dispositions.get(candidate_id) == "site-rejected"],
        })
    complete = all(row["complete"] for row in strata)
    return {
        "schema_version": OPERATIONAL_CENSOR_SELECTION_SCHEMA_VERSION,
        "policy": OPERATIONAL_CENSOR_SELECTION_POLICY,
        "quota_per_stratum": quota_per_stratum,
        "tranco_list_sha256": tranco_list_sha256,
        "complete": complete,
        "quota_unmet_strata": [row["id"] for row in strata if row["quota_unmet"]],
        "candidate_ids": candidate_ids,
        "terminal_ids": [candidate_id for candidate_id in candidate_ids if candidate_id in dispositions],
        "prefix_ids": [candidate_id for row in strata for candidate_id in row["prefix_ids"]],
        "needed_ids": [candidate_id for row in strata for candidate_id in row["needed_ids"]],
        "admission_ids": [candidate_id for row in strata for candidate_id in row["admission_ids"]],
        "remaining_ids": [candidate_id for candidate_id in candidate_ids if candidate_id not in dispositions],
        "unassessed_ids": [candidate_id for row in strata for candidate_id in row["unassessed_ids"]],
        "pilot_ids": [candidate_id for row in strata for candidate_id in row["eligible_ids"]] if complete else [],
        "operational_censor_ids": [candidate_id for candidate_id in candidate_ids
                                   if dispositions.get(candidate_id) == "operational-censor"],
        "site_rejected_ids": [candidate_id for candidate_id in candidate_ids
                              if dispositions.get(candidate_id) == "site-rejected"],
        "strata": strata,
    }


def derive_global_operational_censor_selection(
    candidates: Iterable[ClassCandidate],
    *,
    tranco_list_sha256: str,
    ordered_candidate_ids: Sequence[str],
    order_policy: str,
    eligible_quota: int,
    terminal_disposition: Mapping[str, str],
) -> dict[str, Any]:
    """Derive a global eligible prefix from a separately frozen order contract.

    This does not choose final/reserve classes or set their stratum caps. The
    caller must independently bind and verify the order policy and catalogue.
    """

    catalogue_order = deterministic_candidate_order(
        candidates, tranco_list_sha256=tranco_list_sha256
    )
    if len(catalogue_order) != CANDIDATE_COUNT:
        raise ValueError(f"candidate inventory must contain exactly {CANDIDATE_COUNT} records")
    canonical_ids = [candidate.candidate_id for candidate in catalogue_order]
    if (
        not isinstance(ordered_candidate_ids, Sequence)
        or isinstance(ordered_candidate_ids, (str, bytes))
        or len(ordered_candidate_ids) != CANDIDATE_COUNT
        or any(not isinstance(item, str) for item in ordered_candidate_ids)
        or set(ordered_candidate_ids) != set(canonical_ids)
        or len(set(ordered_candidate_ids)) != CANDIDATE_COUNT
    ):
        raise ValueError("global acquisition order is not an exact catalogue permutation")
    if not isinstance(order_policy, str) or not order_policy:
        raise ValueError("global acquisition order policy is missing")
    if type(eligible_quota) is not int or not 1 <= eligible_quota <= CANDIDATE_COUNT:
        raise ValueError("global acquisition quota is invalid")
    if not isinstance(terminal_disposition, Mapping):
        raise ValueError("terminal disposition must be a mapping")
    dispositions = dict(terminal_disposition)
    if any(not isinstance(key, str) or key not in canonical_ids for key in dispositions):
        raise ValueError("terminal disposition references an unknown candidate")
    if any(type(value) is not str or value not in {
        "eligible", "site-rejected", "operational-censor"
    } for value in dispositions.values()):
        raise ValueError("terminal disposition has an invalid outcome")

    ordered_ids = list(ordered_candidate_ids)
    eligible_ids = [candidate_id for candidate_id in ordered_ids
                    if dispositions.get(candidate_id) == "eligible"][:eligible_quota]
    quota_met = len(eligible_ids) == eligible_quota
    cutoff = ordered_ids.index(eligible_ids[-1]) + 1 if quota_met else len(ordered_ids)
    prefix_ids = ordered_ids[:cutoff]
    needed_ids = [candidate_id for candidate_id in prefix_ids
                  if candidate_id not in dispositions]
    complete = quota_met and not needed_ids
    order_sha256 = hashlib.sha256(canonical_json_bytes(ordered_ids)).hexdigest()
    return {
        "schema_version": GLOBAL_OPERATIONAL_CENSOR_SELECTION_SCHEMA_VERSION,
        "policy": GLOBAL_OPERATIONAL_CENSOR_SELECTION_POLICY,
        "tranco_list_sha256": tranco_list_sha256,
        "order_policy": order_policy,
        "order_sha256": order_sha256,
        "ordered_candidate_ids": ordered_ids,
        "candidate_ids": ordered_ids,
        "eligible_quota": eligible_quota,
        "complete": complete,
        "quota_unmet": not quota_met and not needed_ids,
        "cutoff_id": eligible_ids[-1] if quota_met else None,
        "terminal_ids": [candidate_id for candidate_id in ordered_ids
                         if candidate_id in dispositions],
        "prefix_ids": prefix_ids,
        "needed_ids": needed_ids,
        "admission_ids": [candidate_id for candidate_id in ordered_ids
                          if dispositions.get(candidate_id) not in {
                              "site-rejected", "operational-censor"
                          }][:eligible_quota],
        "remaining_ids": [candidate_id for candidate_id in ordered_ids
                          if candidate_id not in dispositions],
        "unassessed_ids": [candidate_id for candidate_id in ordered_ids[cutoff:]
                           if candidate_id not in dispositions],
        "eligible_ids": eligible_ids,
        "pilot_ids": eligible_ids if complete else [],
        "operational_censor_ids": [candidate_id for candidate_id in ordered_ids
                                   if dispositions.get(candidate_id) == "operational-censor"],
        "site_rejected_ids": [candidate_id for candidate_id in ordered_ids
                              if dispositions.get(candidate_id) == "site-rejected"],
    }
