from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab.class_catalogue import (
    CANDIDATE_RECEIPT_TYPE,
    CATALOGUE_SCHEMA_VERSION,
    TRANCO_MAX_RANK,
    validate_candidate_catalogue_receipt,
)
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    deterministic_candidate_order,
)


def _receipt() -> dict[str, object]:
    list_sha256 = "a" * 64
    candidates = deterministic_candidate_order(
        (
            ClassCandidate(
                candidate_id=f"candidate-{stratum_index}-{offset:02d}",
                domain=f"site-{stratum_index}-{offset:02d}.example",
                rank=stratum.minimum_rank + offset,
                eligible=False,
            )
            for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA)
            for offset in range(CANDIDATES_PER_STRATUM)
        ),
        tranco_list_sha256=list_sha256,
    )
    return bind_receipt(
        {
            "study_id": STUDY_ID,
            "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
            "tranco": {
                "list_id": "TEST1",
                "list_sha256": list_sha256,
                "source_url": "https://tranco-list.eu/download/TEST1/1000000",
                "retrieved_at": "2026-08-28T00:00:00Z",
                "row_count": TRANCO_MAX_RANK,
                "entries_sha256": "b" * 64,
            },
            "selection": {
                "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
                "per_stratum": CANDIDATES_PER_STRATUM,
                "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
                "outcome_fields_used": [],
            },
            "candidates": [candidate.as_dict() for candidate in candidates],
        },
        receipt_type=CANDIDATE_RECEIPT_TYPE,
    )


def test_candidate_catalogue_validates_exact_600_domain_population() -> None:
    candidates = validate_candidate_catalogue_receipt(_receipt())

    assert len(candidates) == CANDIDATE_COUNT
    assert all(candidate.eligible is False for candidate in candidates)
    assert {
        stratum.id: sum(candidate.stratum == stratum for candidate in candidates)
        for stratum in TRANCO_RANK_STRATA
    } == {stratum.id: CANDIDATES_PER_STRATUM for stratum in TRANCO_RANK_STRATA}


def test_candidate_catalogue_rejects_outcome_and_order_tampering() -> None:
    receipt = _receipt()
    payload = copy.deepcopy(receipt["payload"])
    payload["candidates"][0]["eligible"] = True
    tampered = bind_receipt(payload, receipt_type=CANDIDATE_RECEIPT_TYPE)
    with pytest.raises(ValueError, match="carries an outcome"):
        validate_candidate_catalogue_receipt(tampered)

    payload = copy.deepcopy(receipt["payload"])
    payload["candidates"][0], payload["candidates"][1] = (
        payload["candidates"][1],
        payload["candidates"][0],
    )
    tampered = bind_receipt(payload, receipt_type=CANDIDATE_RECEIPT_TYPE)
    with pytest.raises(ValueError, match="order differs"):
        validate_candidate_catalogue_receipt(tampered)


def test_checked_in_candidate_catalogue_and_study_binding_verify() -> None:
    root = Path(__file__).resolve().parents[1]
    catalogue_path = (
        root
        / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
    )
    study = json.loads(
        (root / "config/class-study/v1/study.json").read_text(encoding="utf-8")
    )
    candidates = validate_candidate_catalogue_receipt(
        json.loads(catalogue_path.read_text(encoding="utf-8"))
    )

    binding = study["population"]["candidate_catalogue"]
    assert len(candidates) == CANDIDATE_COUNT
    assert hashlib.sha256(catalogue_path.read_bytes()).hexdigest() == binding["sha256"]
    assert binding["candidate_count"] == CANDIDATE_COUNT
    assert binding["superseded_300_domain_draft"] == {
        "sha256": "d6152f468b49627f2c5a696f51e9aa7da26f26e59f07c9618caba4a8669a673c",
        "payload_sha256": "403e80b35fd27952a37b4ec361d6beed7d51ad33dac4f4fae0b1847c46eeb13b",
        "ordered_candidate_ids_sha256": (
            "3973e9e94aa11fdee8a1a128f8f1755298b96ee371607e83b96abe12201fe87e"
        ),
        "relationship": (
            "all-300-candidate-identities-are-a-proper-subset-of-the-expanded-catalogue"
        ),
    }
