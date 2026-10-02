"""Adversarial receipt checks for the prospective 20-site cohort."""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab.class_catalogue import load_candidate_catalogue_receipt
from qcsd_lab.class_acquisition import SCHEMA_VERSION as ACQUISITION_SCHEMA_VERSION
from qcsd_lab.acquisition_selection import derive_global_operational_censor_selection
from qcsd_lab.class_cohort20 import (
    ASSEMBLY_RECEIPT_TYPE,
    COHORT_RECEIPT_TYPE,
    _validated_global_selection,
    load_validated_profile_cohort,
    validate_profile_cohort_receipt,
)
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    bind_receipt,
    canonical_json_bytes,
    deterministic_profile_candidate_order,
)
from qcsd_lab.util import sha256_bytes, sha256_file


LAB_ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = (
    LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
)


def _pilot_receipt() -> dict:
    catalogue, candidates = load_candidate_catalogue_receipt(CATALOGUE)
    from qcsd_lab.class_study import load_class20_profile_contract
    from qcsd_lab.util import sha256_file

    profile = load_class20_profile_contract()
    tranco = catalogue["payload"]["tranco"]
    ordered = deterministic_profile_candidate_order(
        candidates, tranco_list_sha256=tranco["list_sha256"], profile=profile
    )
    resolved = tuple(
        replace(candidate, eligible=index < profile.pilot_count)
        for index, candidate in enumerate(ordered)
    )
    return bind_receipt(
        {
            "study_id": profile.study_id,
            "cohort_schema_version": 1,
            "profile_sha256": sha256_file(
                LAB_ROOT / "config/class-study/v2/study.json"
            ),
            "stage": "pilot",
            "tranco": {
                "list_id": tranco["list_id"],
                "list_sha256": tranco["list_sha256"],
            },
            "candidates": [item.as_dict() for item in resolved],
            "pilot_ids": [item.candidate_id for item in resolved[: profile.pilot_count]],
            "final_ids": [],
            "reserve_ids": [],
            "matching": [],
            "final_selection": None,
        },
        receipt_type=COHORT_RECEIPT_TYPE,
    )


def _rebind(receipt: dict) -> dict:
    return bind_receipt(receipt["payload"], receipt_type=COHORT_RECEIPT_TYPE)


def test_profile_pilot_receipt_accepts_only_first_thirty_eligible() -> None:
    receipt = _pilot_receipt()
    pilot, final = validate_profile_cohort_receipt(
        receipt, profile=CLASS20_PROFILE
    )
    assert len(pilot) == 30
    assert final == ()

    skipped = copy.deepcopy(receipt)
    skipped["payload"]["pilot_ids"][0] = skipped["payload"]["candidates"][30]["candidate_id"]
    with pytest.raises(ValueError, match="pilot differs"):
        validate_profile_cohort_receipt(_rebind(skipped), profile=CLASS20_PROFILE)


def test_profile_pilot_receipt_rejects_premature_final_and_changed_order() -> None:
    receipt = _pilot_receipt()
    premature = copy.deepcopy(receipt)
    premature["payload"]["final_ids"] = premature["payload"]["pilot_ids"][:20]
    with pytest.raises(ValueError, match="prematurely claims final"):
        validate_profile_cohort_receipt(_rebind(premature), profile=CLASS20_PROFILE)

    reordered = copy.deepcopy(receipt)
    candidates = reordered["payload"]["candidates"]
    candidates[30], candidates[31] = candidates[31], candidates[30]
    with pytest.raises(ValueError, match="priority order differs"):
        validate_profile_cohort_receipt(_rebind(reordered), profile=CLASS20_PROFILE)


def test_profile_final_receipt_cannot_promote_hashes_without_deep_verifier() -> None:
    receipt = _pilot_receipt()
    final = copy.deepcopy(receipt)
    final["payload"]["stage"] = "final"
    final["payload"]["final_ids"] = final["payload"]["pilot_ids"][:20]
    final["payload"]["reserve_ids"] = final["payload"]["pilot_ids"][20:]
    final["payload"]["final_selection"] = {
        "path": "config/class-study/v2/fake-final-selection.json",
        "sha256": "a" * 64,
        "pilot_cohort": {"path": "config/class-study/v2/fake-pilot.json", "sha256": "b" * 64},
        "pilot_assembly": {"path": "config/class-study/v2/fake-assembly.json", "sha256": "c" * 64},
    }
    with pytest.raises(ValueError, match="not canonical"):
        validate_profile_cohort_receipt(_rebind(final), profile=CLASS20_PROFILE)


def test_frozen_final_receipt_checks_partition_without_live_pair_roots() -> None:
    receipt = _pilot_receipt()
    payload = copy.deepcopy(receipt["payload"])
    pilot_ids = payload["pilot_ids"]
    payload["stage"] = "final"
    payload["final_ids"] = pilot_ids[:20]
    payload["reserve_ids"] = pilot_ids[20:]
    payload["matching"] = [pilot_ids[index:index + 2] for index in range(0, 20, 2)]
    study_id = CLASS20_PROFILE.study_id
    payload["final_selection"] = {
        "path": f"config/class-study/v2/{study_id}-final-selection.json",
        "sha256": "a" * 64,
        "pilot_cohort": {
            "path": f"config/class-study/v2/{study_id}-pilot-cohort.json",
            "sha256": "b" * 64,
        },
        "pilot_assembly": {
            "path": f"config/class-study/v2/{study_id}-pilot-cohort-assembly.json",
            "sha256": "c" * 64,
        },
    }
    frozen = bind_receipt(payload, receipt_type=COHORT_RECEIPT_TYPE)
    assert validate_profile_cohort_receipt(
        frozen, profile=CLASS20_PROFILE, require_deep=False,
    ) == (tuple(pilot_ids), tuple(pilot_ids[:20]))
    with pytest.raises(ValueError, match="regular file"):
        validate_profile_cohort_receipt(frozen, profile=CLASS20_PROFILE)

    malformed = copy.deepcopy(payload)
    malformed["matching"][0] = [pilot_ids[0], pilot_ids[20]]
    with pytest.raises(ValueError, match="matching differs from final sites"):
        validate_profile_cohort_receipt(
            bind_receipt(malformed, receipt_type=COHORT_RECEIPT_TYPE),
            profile=CLASS20_PROFILE, require_deep=False,
        )


def test_global_selection_rejects_incomplete_prefix() -> None:
    catalogue, candidates = load_candidate_catalogue_receipt(CATALOGUE)
    ordered = deterministic_profile_candidate_order(
        candidates,
        tranco_list_sha256=catalogue["payload"]["tranco"]["list_sha256"],
        profile=CLASS20_PROFILE,
    )
    completion = {
        "study_id": CLASS20_PROFILE.study_id,
        "acquisition_schema_version": ACQUISITION_SCHEMA_VERSION,
        "completion_schema_version": 5,
        "selection": bind_receipt(
            {"complete": False, "needed_ids": [ordered[0].candidate_id], "terminal_ids": []},
            receipt_type="qcsd-class-study-acquisition-selection",
        ),
        "terminal_receipts": {},
    }
    with pytest.raises(ValueError, match="global selection does not verify"):
        _validated_global_selection(
            candidates, completion_payload=completion, completion_root=LAB_ROOT,
            tranco_list_sha256=catalogue["payload"]["tranco"]["list_sha256"],
            profile=CLASS20_PROFILE,
        )


def test_frozen_pilot_copy_verifies_intrinsically_without_live_acquisition(
    tmp_path: Path,
) -> None:
    cohort = _pilot_receipt()
    records = []
    for candidate in cohort["payload"]["candidates"]:
        candidate_id = candidate["candidate_id"]
        if candidate["eligible"]:
            records.append({
                "candidate_id": candidate_id,
                "eligible": True,
                "selected_page": {
                    "candidate_domain": candidate["domain"],
                    "registrable_domain": candidate["domain"],
                    "url": f"https://{candidate['domain']}/",
                    "source": "canonical-homepage",
                    "ordinal": 0,
                    "discovery_content_type": None,
                },
                "stability_receipt": {
                    "path": f"{candidate_id}/page-00.json",
                    "sha256": "a" * 64,
                    "payload_sha256": "b" * 64,
                },
                "prepared_workload": {
                    "path": f"{candidate_id}.json", "sha256": "c" * 64,
                },
                "reasons": [],
                "disposition": "eligible",
            })
        else:
            records.append({
                "candidate_id": candidate_id,
                "eligible": False,
                "selected_page": None,
                "stability_receipt": None,
                "prepared_workload": None,
                "reasons": ["unassessed-deterministic-prefix-tail"],
                "disposition": "unassessed",
            })
    catalogue = load_candidate_catalogue_receipt(CATALOGUE)[0]
    selection = derive_global_operational_censor_selection(
        load_candidate_catalogue_receipt(CATALOGUE)[1],
        tranco_list_sha256=cohort["payload"]["tranco"]["list_sha256"],
        ordered_candidate_ids=[item["candidate_id"] for item in cohort["payload"]["candidates"]],
        order_policy="round-robin-five-frozen-within-stratum-orders",
        eligible_quota=30,
        terminal_disposition={candidate_id: "eligible" for candidate_id in cohort["payload"]["pilot_ids"]},
    )
    assembly = bind_receipt({
        "study_id": CLASS20_PROFILE.study_id,
        "assembly_schema_version": 1,
        "profile": {
            "path": "config/class-study/v2/study.json",
            "sha256": sha256_file(LAB_ROOT / "config/class-study/v2/study.json"),
        },
        "candidate_catalogue": {
            "path": "config/class-study/v1/classifier-multiorigin100-v1-candidates.json",
            "sha256": sha256_file(CATALOGUE),
            "payload_sha256": catalogue["payload_sha256"],
        },
        "acquisition_completion": {
            "path": f"artifacts/{CLASS20_PROFILE.study_id}-acquisition-v999/completion.json",
            "sha256": "d" * 64,
            "payload_sha256": "e" * 64,
            "provenance_sha256": "f" * 64,
            "selection_payload_sha256": sha256_bytes(canonical_json_bytes(selection)),
        },
        "acquisition_selection": selection,
        "stability_root": f"artifacts/{CLASS20_PROFILE.study_id}-stability-v999",
        "workload_root": f"config/{CLASS20_PROFILE.study_id}-workloads-v999",
        "candidates": records,
        "eligible_count": 30,
        "selected_evidence_count": 30,
        "cohort": {
            "receipt_type": cohort["receipt_type"],
            "payload_sha256": cohort["payload_sha256"],
            "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
        },
    }, receipt_type=ASSEMBLY_RECEIPT_TYPE)
    cohort_path = tmp_path / "inputs-class-study-cohort.json"
    assembly_path = tmp_path / "inputs-class-study-cohort-assembly.json"
    cohort_path.write_bytes(canonical_json_bytes(cohort))
    assembly_path.write_bytes(canonical_json_bytes(assembly))

    pilot, final = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=CLASS20_PROFILE, require_deep=False
    )
    assert len(pilot) == 30 and final == ()
    with pytest.raises(ValueError, match="regular file"):
        load_validated_profile_cohort(
            cohort_path, assembly_path, profile=CLASS20_PROFILE, require_deep=True
        )

    tampered = copy.deepcopy(assembly)
    tampered["payload"]["candidates"][0]["eligible"] = False
    assembly_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="SHA-256|hash|payload"):
        load_validated_profile_cohort(
            cohort_path, assembly_path, profile=CLASS20_PROFILE, require_deep=False
        )
