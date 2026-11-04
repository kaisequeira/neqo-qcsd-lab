"""Evidence-bound cohort receipts for the prospective 20-site class study.

The frozen 100-site receipts remain owned by :mod:`class_cohort`.  This module
can publish a pilot only from a completed 30-site *global* acquisition prefix.
The final cohort additionally requires a deep-verified pair selection input;
pair hashes supplied by a caller are never sufficient authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any
import re

from . import util
from .acquisition_selection import (
    GLOBAL_OPERATIONAL_CENSOR_SELECTION_POLICY,
    derive_global_operational_censor_selection,
)
from .class_acquisition import (
    COMPLETION_SCHEMA_VERSION,
    SCHEMA_VERSION as ACQUISITION_SCHEMA_VERSION,
    SELECTION_TYPE,
    TERMINAL_TYPE,
    validate_acquisition_completion,
)
from .class_catalogue import load_candidate_catalogue_receipt
from .class_cohort import (
    _candidate_acquisition_evidence,
    _reconcile_acquisition_terminal,
    _require_current_acquisition_completion,
    _validate_eligible_evidence,
    _write_or_verify,
)
from .class_layout import require_canonical_fresh_child, require_cohort_publication_roots
from .class_pipeline import ProfileFinalSelection
from .class_study import (
    CLASS20_PROFILE,
    ClassCandidate,
    ClassStudyProfile,
    bind_receipt,
    canonical_json_bytes,
    deterministic_profile_candidate_order,
    load_class20_profile_contract,
    select_profile_pilot,
    validate_hash_bound_receipt,
)
from .util import load_json, sha256_bytes, sha256_file

COHORT_RECEIPT_TYPE = "qcsd-class-study-profile-cohort"
ASSEMBLY_RECEIPT_TYPE = "qcsd-class-study-profile-cohort-assembly"
SCHEMA_VERSION = 1
ORDER_POLICY = "round-robin-five-frozen-within-stratum-orders"
_CATALOGUE = Path("config/class-study/v1/classifier-multiorigin100-v1-candidates.json")
_PROFILE = Path("config/class-study/v2/study.json")


def build_evidenced_profile_cohort(
    candidate_catalogue_path: Path,
    *,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    profile: ClassStudyProfile,
    final_selection_receipt_path: Path | None = None,
    pilot_cohort_path: Path | None = None,
    pilot_assembly_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebuild a prospective receipt from every completed acquisition terminal.

    Final publication requires the separate 15-pair receipt to be rebuilt
    from fitting, prefix, and qualification evidence.
    """

    _require_profile(profile)
    lab_root = Path(util.LAB_ROOT).resolve()
    catalogue_path = _regular_file(candidate_catalogue_path, "candidate catalogue")
    if catalogue_path != lab_root / _CATALOGUE:
        raise ValueError("20-site cohort requires the frozen catalogue path")
    catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
    catalogue_payload = validate_hash_bound_receipt(
        catalogue, expected_type="qcsd-class-study-candidate-catalogue"
    )
    completion_path = _regular_file(acquisition_completion_path, "acquisition completion")
    stability = _regular_directory(stability_root, "stability receipt root")
    workloads = _regular_directory(workload_root, "prepared workload root")
    require_cohort_publication_roots(
        completion_path.parent, stability, workloads,
        require_versioned=True, profile=profile,
    )
    completion = load_json(completion_path)
    completion_payload = validate_acquisition_completion(
        completion, candidate_catalogue_path=catalogue_path,
        runner_root=completion_path.parent,
    )
    _require_current_acquisition_completion(
        completion_payload, runner_root=completion_path.parent
    )
    selection, dispositions, ordered = _validated_global_selection(
        candidates, completion_payload=completion_payload,
        completion_root=completion_path.parent,
        tranco_list_sha256=catalogue_payload["tranco"]["list_sha256"],
        profile=profile,
    )
    known_ids = {candidate.candidate_id for candidate in candidates}
    unexpected = sorted(item.name for item in stability.iterdir() if item.name not in known_ids)
    if unexpected:
        raise ValueError("stability root contains unknown candidates: " + ", ".join(unexpected))

    resolved: list[ClassCandidate] = []
    evidence: list[dict[str, Any]] = []
    for candidate in ordered:
        eligible, record = _candidate_acquisition_evidence(
            candidate, completion_payload=completion_payload,
            stability_root=stability, workload_root=workloads,
            tranco=catalogue_payload["tranco"],
        )
        _reconcile_acquisition_terminal(
            candidate.candidate_id, record, completion_payload=completion_payload,
            completion_root=completion_path.parent, stability_root=stability,
            workload_root=workloads,
        )
        disposition = dispositions.get(candidate.candidate_id, "unassessed")
        if eligible != (disposition == "eligible"):
            raise ValueError("cohort eligibility differs from acquisition terminal")
        record = dict(record)
        record["disposition"] = disposition
        if disposition == "operational-censor":
            record["reasons"] = ["operational-censor"]
        resolved.append(replace(candidate, eligible=eligible))
        evidence.append(record)

    pilot = select_profile_pilot(
        resolved, tranco_list_sha256=catalogue_payload["tranco"]["list_sha256"],
        profile=profile,
    )
    pilot_ids = [candidate.candidate_id for candidate in pilot]
    if selection["pilot_ids"] != pilot_ids:
        raise ValueError("pilot cohort differs from completed global acquisition prefix")

    stage = "pilot"
    final_ids: list[str] = []
    reserve_ids: list[str] = []
    matching: list[list[str]] = []
    final_binding: dict[str, Any] | None = None
    if final_selection_receipt_path is not None:
        stage = "final"
        if pilot_cohort_path is None or pilot_assembly_path is None:
            raise ValueError("final cohort requires pilot cohort and assembly receipts")
        final_selection = _deep_final_selection(
            final_selection_receipt_path, pilot_cohort_path=pilot_cohort_path,
            pilot_assembly_path=pilot_assembly_path, profile=profile,
        )
        _require_same_pilot(final_selection, pilot_ids)
        final_ids = [item.candidate_id for item in final_selection.final]
        reserve_ids = [item.candidate_id for item in final_selection.reserves]
        matching = [list(pair) for pair in final_selection.matching]
        final_binding = {
            "path": _relative_to_lab(final_selection_receipt_path, lab_root),
            "sha256": sha256_file(final_selection_receipt_path),
            "pilot_cohort": {
                "path": _relative_to_lab(pilot_cohort_path, lab_root),
                "sha256": sha256_file(pilot_cohort_path),
            },
            "pilot_assembly": {
                "path": _relative_to_lab(pilot_assembly_path, lab_root),
                "sha256": sha256_file(pilot_assembly_path),
            },
        }
    elif pilot_cohort_path is not None or pilot_assembly_path is not None:
        raise ValueError("pilot cohort cannot bind a final-selection input")

    cohort_payload = {
        "study_id": profile.study_id,
        "cohort_schema_version": SCHEMA_VERSION,
        "profile_sha256": sha256_file(lab_root / _PROFILE),
        "stage": stage,
        "tranco": {
            "list_id": catalogue_payload["tranco"]["list_id"],
            "list_sha256": catalogue_payload["tranco"]["list_sha256"],
        },
        "candidates": [candidate.as_dict() for candidate in resolved],
        "pilot_ids": pilot_ids,
        "final_ids": final_ids,
        "reserve_ids": reserve_ids,
        "matching": matching,
        "final_selection": final_binding,
    }
    cohort = bind_receipt(cohort_payload, receipt_type=COHORT_RECEIPT_TYPE)
    assembly_payload = {
        "study_id": profile.study_id,
        "assembly_schema_version": SCHEMA_VERSION,
        "profile": {
            "path": _PROFILE.as_posix(),
            "sha256": sha256_file(lab_root / _PROFILE),
        },
        "candidate_catalogue": {
            "path": _CATALOGUE.as_posix(),
            "sha256": sha256_file(catalogue_path),
            "payload_sha256": catalogue["payload_sha256"],
        },
        "acquisition_completion": {
            "path": _relative_to_lab(completion_path, lab_root),
            "sha256": sha256_file(completion_path),
            "payload_sha256": completion["payload_sha256"],
            "provenance_sha256": completion_payload["provenance_sha256"],
            "selection_payload_sha256": completion_payload["selection"]["payload_sha256"],
        },
        "acquisition_selection": selection,
        "stability_root": _relative_to_lab(stability, lab_root),
        "workload_root": _relative_to_lab(workloads, lab_root),
        "candidates": evidence,
        "eligible_count": sum(item.eligible for item in resolved),
        "selected_evidence_count": len(pilot_ids),
        "cohort": {
            "receipt_type": cohort["receipt_type"],
            "payload_sha256": cohort["payload_sha256"],
            "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
        },
    }
    assembly = bind_receipt(assembly_payload, receipt_type=ASSEMBLY_RECEIPT_TYPE)
    validate_profile_cohort_assembly_receipt(assembly, cohort=cohort, profile=profile)
    return cohort, assembly


def publish_evidenced_profile_cohort(
    cohort_destination: Path,
    assembly_destination: Path,
    *,
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    profile: ClassStudyProfile,
    final_selection_receipt_path: Path | None = None,
    pilot_cohort_path: Path | None = None,
    pilot_assembly_path: Path | None = None,
) -> tuple[Path, Path]:
    """Publish a profile cohort only from independently rebuilt evidence.

    Existing files can be resumed only when byte-identical to that rebuild.
    Final publication requires the deep 15-pair selection receipt verifier.
    """

    _require_profile(profile)
    stage = "final" if final_selection_receipt_path is not None else "pilot"
    cohort_name = (
        f"{profile.study_id}-cohort.json"
        if stage == "final" else f"{profile.study_id}-pilot-cohort.json"
    )
    assembly_name = (
        f"{profile.study_id}-cohort-assembly.json"
        if stage == "final" else f"{profile.study_id}-pilot-cohort-assembly.json"
    )
    require_canonical_fresh_child(
        cohort_destination, field="study_config_root", filename=cohort_name,
        profile=profile, label="20-site cohort receipt",
    )
    require_canonical_fresh_child(
        assembly_destination, field="study_config_root", filename=assembly_name,
        profile=profile, label="20-site cohort assembly",
    )
    cohort, assembly = build_evidenced_profile_cohort(
        candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        profile=profile,
        final_selection_receipt_path=final_selection_receipt_path,
        pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path,
    )
    assembly_path = _write_or_verify(assembly_destination, assembly)
    cohort_path = _write_or_verify(cohort_destination, cohort)
    load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    return cohort_path, assembly_path


def validate_profile_cohort_receipt(
    value: Mapping[str, Any], *, profile: ClassStudyProfile,
    require_deep: bool = True,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Check cohort structure; optionally replay the live 15-pair evidence.

    The explicit intrinsic mode is for sealed historical inputs whose fresh
    acquisition and qualification roots may no longer exist.  Publication
    and admission use the default deep mode.
    """

    _require_profile(profile)
    if type(require_deep) is not bool:
        raise ValueError("20-site cohort verification mode must be boolean")
    payload = validate_hash_bound_receipt(value, expected_type=COHORT_RECEIPT_TYPE)
    if set(payload) != {
        "study_id", "cohort_schema_version", "profile_sha256", "stage", "tranco",
        "candidates", "pilot_ids", "final_ids", "reserve_ids", "matching",
        "final_selection",
    } or payload["study_id"] != profile.study_id or payload["cohort_schema_version"] != SCHEMA_VERSION:
        raise ValueError("20-site cohort receipt contract differs")
    if payload["profile_sha256"] != sha256_file(Path(util.LAB_ROOT).resolve() / _PROFILE):
        raise ValueError("20-site cohort profile binding differs")
    tranco = payload["tranco"]
    if (
        not isinstance(tranco, Mapping)
        or set(tranco) != {"list_id", "list_sha256"}
        or not isinstance(tranco["list_id"], str)
        or not tranco["list_id"]
        or not isinstance(tranco["list_sha256"], str)
    ):
        raise ValueError("20-site cohort Tranco binding is invalid")
    raw_candidates = payload["candidates"]
    if not isinstance(raw_candidates, list) or len(raw_candidates) != profile.candidate_count:
        raise ValueError("20-site cohort candidate inventory is incomplete")
    candidates: list[ClassCandidate] = []
    for raw in raw_candidates:
        if not isinstance(raw, Mapping) or set(raw) != {
            "candidate_id", "domain", "rank", "stratum", "eligible"
        } or type(raw["eligible"]) is not bool:
            raise ValueError("20-site cohort candidate record is invalid")
        candidate = ClassCandidate(
            candidate_id=raw["candidate_id"], domain=raw["domain"],
            rank=raw["rank"], eligible=raw["eligible"],
        )
        if candidate.as_dict() != raw:
            raise ValueError("20-site cohort candidate stratum differs")
        candidates.append(candidate)
    ordered = deterministic_profile_candidate_order(
        candidates, tranco_list_sha256=tranco["list_sha256"], profile=profile
    )
    if [candidate.as_dict() for candidate in ordered] != raw_candidates:
        raise ValueError("20-site cohort candidate priority order differs")
    pilot = select_profile_pilot(
        ordered, tranco_list_sha256=tranco["list_sha256"], profile=profile
    )
    pilot_ids = tuple(item.candidate_id for item in pilot)
    if payload["pilot_ids"] != list(pilot_ids):
        raise ValueError("20-site cohort pilot differs from eligible priority order")
    if payload["stage"] == "pilot":
        if (
            payload["final_ids"] != []
            or payload["reserve_ids"] != []
            or payload["matching"] != []
            or payload["final_selection"] is not None
        ):
            raise ValueError("pilot cohort prematurely claims final selection")
        return pilot_ids, ()
    if payload["stage"] != "final":
        raise ValueError("20-site cohort stage is invalid")
    binding = _validated_final_binding(
        payload["final_selection"], profile=profile, require_deep=require_deep,
    )
    _validate_intrinsic_final_partition(payload, pilot)
    if not require_deep:
        return pilot_ids, tuple(payload["final_ids"])
    final_selection = _deep_final_selection(
        Path(util.LAB_ROOT).resolve() / binding["path"],
        pilot_cohort_path=Path(util.LAB_ROOT).resolve() / binding["pilot_cohort"]["path"],
        pilot_assembly_path=Path(util.LAB_ROOT).resolve() / binding["pilot_assembly"]["path"],
        profile=profile,
    )
    _require_same_pilot(final_selection, pilot_ids)
    if (
        payload["final_ids"] != [item.candidate_id for item in final_selection.final]
        or payload["reserve_ids"] != [item.candidate_id for item in final_selection.reserves]
        or payload["matching"] != [list(pair) for pair in final_selection.matching]
    ):
        raise ValueError("20-site final cohort differs from qualified pilot pairs")
    return pilot_ids, tuple(payload["final_ids"])


def validate_profile_cohort_assembly_receipt(
    value: Mapping[str, Any], *, cohort: Mapping[str, Any], profile: ClassStudyProfile,
    require_deep: bool = True,
) -> dict[str, Any]:
    """Validate the complete 600-candidate intrinsic evidence inventory."""

    pilot_ids, _final_ids = validate_profile_cohort_receipt(
        cohort, profile=profile, require_deep=require_deep,
    )
    cohort_payload = validate_hash_bound_receipt(cohort, expected_type=COHORT_RECEIPT_TYPE)
    payload = validate_hash_bound_receipt(value, expected_type=ASSEMBLY_RECEIPT_TYPE)
    if set(payload) != {
        "study_id", "assembly_schema_version", "profile", "candidate_catalogue",
        "acquisition_completion", "acquisition_selection", "stability_root",
        "workload_root", "candidates",
        "eligible_count", "selected_evidence_count", "cohort",
    } or payload["study_id"] != profile.study_id or payload["assembly_schema_version"] != SCHEMA_VERSION:
        raise ValueError("20-site cohort assembly contract differs")
    lab_root = Path(util.LAB_ROOT).resolve()
    if payload["profile"] != {
        "path": _PROFILE.as_posix(), "sha256": sha256_file(lab_root / _PROFILE)
    }:
        raise ValueError("20-site cohort assembly profile binding differs")
    catalogue = payload["candidate_catalogue"]
    if (
        not isinstance(catalogue, Mapping)
        or set(catalogue) != {"path", "sha256", "payload_sha256"}
        or catalogue["path"] != _CATALOGUE.as_posix()
        or catalogue["sha256"] != sha256_file(lab_root / _CATALOGUE)
    ):
        raise ValueError("20-site assembly candidate catalogue differs")
    completion = payload["acquisition_completion"]
    if not isinstance(completion, Mapping) or set(completion) != {
        "path", "sha256", "payload_sha256", "provenance_sha256",
        "selection_payload_sha256",
    }:
        raise ValueError("20-site assembly acquisition completion binding is invalid")
    acquisition_path = completion["path"]
    if not isinstance(acquisition_path, str):
        raise ValueError("20-site completion path is invalid")
    acquisition_match = re.fullmatch(
        rf"artifacts/{re.escape(profile.study_id)}-acquisition-v([1-9][0-9]*)/completion[.]json",
        acquisition_path,
    )
    if acquisition_match is None:
        raise ValueError("20-site completion path is not canonical")
    version = acquisition_match.group(1)
    if (
        payload["stability_root"]
        != f"artifacts/{profile.study_id}-stability-v{version}"
        or payload["workload_root"]
        != f"config/{profile.study_id}-workloads-v{version}"
        or any(
            not _digest(completion[key])
            for key in (
                "sha256", "payload_sha256", "provenance_sha256",
                "selection_payload_sha256",
            )
        )
        or not _digest(catalogue["payload_sha256"])
    ):
        raise ValueError("20-site assembly publication roots or input hashes differ")
    sealed_selection = payload["acquisition_selection"]
    if (
        not isinstance(sealed_selection, Mapping)
        or completion["selection_payload_sha256"]
        != sha256_bytes(canonical_json_bytes(sealed_selection))
    ):
        raise ValueError("20-site assembly acquisition selection hash differs")
    if payload["cohort"] != {
        "receipt_type": cohort["receipt_type"],
        "payload_sha256": cohort["payload_sha256"],
        "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
    }:
        raise ValueError("20-site assembly does not bind the supplied cohort")
    records = payload["candidates"]
    candidates = cohort_payload["candidates"]
    if not isinstance(records, list) or len(records) != len(candidates):
        raise ValueError("20-site assembly candidate evidence inventory is incomplete")
    selected = set(pilot_ids)
    eligible_count = 0
    dispositions: dict[str, str] = {}
    for candidate_raw, record in zip(candidates, records, strict=True):
        if not isinstance(record, Mapping) or set(record) != {
            "candidate_id", "eligible", "selected_page", "stability_receipt",
            "prepared_workload", "reasons", "disposition",
        }:
            raise ValueError("20-site assembly candidate evidence is malformed")
        if (
            record["candidate_id"] != candidate_raw["candidate_id"]
            or type(record["eligible"]) is not bool
            or record["eligible"] != candidate_raw["eligible"]
            or record["disposition"] not in {
                "eligible", "site-rejected", "operational-censor", "unassessed"
            }
        ):
            raise ValueError("20-site assembly candidate disposition differs")
        reasons = record["reasons"]
        if not isinstance(reasons, list) or any(
            not isinstance(item, str) or not item for item in reasons
        ) or len(set(reasons)) != len(reasons):
            raise ValueError("20-site assembly candidate reasons are malformed")
        if record["eligible"]:
            eligible_count += 1
            if record["disposition"] != "eligible" or reasons:
                raise ValueError("eligible candidate carries rejection or censor evidence")
            _validate_eligible_evidence(
                ClassCandidate(
                    candidate_id=candidate_raw["candidate_id"],
                    domain=candidate_raw["domain"], rank=candidate_raw["rank"],
                    eligible=True,
                ), record,
            )
        elif (
            record["disposition"] == "eligible"
            or any(record[key] is not None for key in (
                "selected_page", "stability_receipt", "prepared_workload"
            ))
            or not reasons
            or (record["disposition"] == "operational-censor" and reasons != ["operational-censor"])
            or (record["disposition"] == "unassessed" and reasons != ["unassessed-deterministic-prefix-tail"])
        ):
            raise ValueError("ineligible candidate has inconsistent evidence")
        if record["disposition"] != "unassessed":
            dispositions[record["candidate_id"]] = record["disposition"]
    resolved = tuple(
        ClassCandidate(
            candidate_id=item["candidate_id"], domain=item["domain"],
            rank=item["rank"], eligible=item["eligible"],
        ) for item in candidates
    )
    derived = derive_global_operational_censor_selection(
        resolved, tranco_list_sha256=cohort_payload["tranco"]["list_sha256"],
        ordered_candidate_ids=[item.candidate_id for item in resolved],
        order_policy=ORDER_POLICY, eligible_quota=profile.pilot_count,
        terminal_disposition=dispositions,
    )
    if (
        dict(sealed_selection) != derived
        or derived["policy"] != GLOBAL_OPERATIONAL_CENSOR_SELECTION_POLICY
        or derived["complete"] is not True
        or derived["needed_ids"] != []
        or derived["pilot_ids"] != list(pilot_ids)
    ):
        raise ValueError("20-site assembly global prefix differs from terminal inventory")
    if (
        type(payload["eligible_count"]) is not int
        or payload["eligible_count"] != eligible_count
        or type(payload["selected_evidence_count"]) is not int
        or payload["selected_evidence_count"] != len(selected)
        or not selected.issubset({record["candidate_id"] for record in records if record["eligible"]})
    ):
        raise ValueError("20-site assembly evidence counts are invalid")
    return payload


def load_validated_profile_cohort(
    cohort_receipt: Path,
    cohort_assembly_receipt: Path,
    *,
    profile: ClassStudyProfile,
    require_deep: bool = True,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Verify IDs; fresh publication additionally rebuilds all live evidence.

    Frozen campaign-input copies retain the complete hash-bound 600-candidate
    inventory but may outlive the original acquisition directories.  Callers
    must explicitly choose this historical replay mode.
    """

    _require_profile(profile)
    cohort = load_json(_regular_file(cohort_receipt, "profile cohort receipt"))
    assembly = load_json(_regular_file(cohort_assembly_receipt, "profile cohort assembly"))
    if type(require_deep) is not bool:
        raise ValueError("20-site cohort verification mode must be boolean")
    payload = validate_profile_cohort_assembly_receipt(
        assembly, cohort=cohort, profile=profile, require_deep=require_deep,
    )
    if not require_deep:
        return validate_profile_cohort_receipt(
            cohort, profile=profile, require_deep=False,
        )
    lab_root = Path(util.LAB_ROOT).resolve()
    final_binding = validate_hash_bound_receipt(
        cohort, expected_type=COHORT_RECEIPT_TYPE
    )["final_selection"]
    final_args: dict[str, Path] = {}
    if final_binding is not None:
        bound = _validated_final_binding(final_binding, profile=profile)
        final_args = {
            "final_selection_receipt_path": lab_root / bound["path"],
            "pilot_cohort_path": lab_root / bound["pilot_cohort"]["path"],
            "pilot_assembly_path": lab_root / bound["pilot_assembly"]["path"],
        }
    rebuilt_cohort, rebuilt_assembly = build_evidenced_profile_cohort(
        lab_root / _CATALOGUE,
        stability_root=lab_root / payload["stability_root"],
        workload_root=lab_root / payload["workload_root"],
        acquisition_completion_path=lab_root / payload["acquisition_completion"]["path"],
        profile=profile, **final_args,
    )
    if (
        canonical_json_bytes(cohort) != canonical_json_bytes(rebuilt_cohort)
        or canonical_json_bytes(assembly) != canonical_json_bytes(rebuilt_assembly)
    ):
        raise ValueError("20-site cohort differs from independently rebuilt evidence")
    return validate_profile_cohort_receipt(cohort, profile=profile)


def _validated_global_selection(
    candidates: Sequence[ClassCandidate], *, completion_payload: Mapping[str, Any],
    completion_root: Path, tranco_list_sha256: str, profile: ClassStudyProfile,
) -> tuple[dict[str, Any], dict[str, str], tuple[ClassCandidate, ...]]:
    if (
        completion_payload.get("study_id") != profile.study_id
        or completion_payload.get("acquisition_schema_version") != ACQUISITION_SCHEMA_VERSION
        or completion_payload.get("completion_schema_version") != COMPLETION_SCHEMA_VERSION
    ):
        raise ValueError("20-site cohort requires current profile acquisition completion")
    sealed = validate_hash_bound_receipt(
        completion_payload["selection"], expected_type=SELECTION_TYPE
    )
    ordered = deterministic_profile_candidate_order(
        candidates, tranco_list_sha256=tranco_list_sha256, profile=profile
    )
    dispositions: dict[str, str] = {}
    bindings = completion_payload["terminal_receipts"]
    if not isinstance(bindings, Mapping):
        raise ValueError("20-site completion terminal bindings are malformed")
    selected_terminal_ids = sealed.get("terminal_ids")
    if not isinstance(selected_terminal_ids, list):
        raise ValueError("20-site completion selection terminal inventory is missing")
    for candidate_id, binding in bindings.items():
        if not isinstance(binding, Mapping) or set(binding) != {"path", "sha256"}:
            raise ValueError("20-site completion terminal binding is malformed")
        terminal_path = _regular_file(
            completion_root / str(binding["path"]), "acquisition terminal"
        )
        if sha256_file(terminal_path) != binding["sha256"]:
            raise ValueError("20-site completion terminal changed")
        terminal = validate_hash_bound_receipt(
            load_json(terminal_path), expected_type=TERMINAL_TYPE
        )
        if terminal.get("candidate_id") != candidate_id:
            raise ValueError("20-site completion terminal identity differs")
        if candidate_id in selected_terminal_ids:
            kind = terminal.get("kind")
            if kind not in {
                "eligible", "operational-censor", "pre-probe-rejection",
                "stable-page-unavailable",
            }:
                raise ValueError("20-site selection promotes a non-scientific terminal")
            dispositions[candidate_id] = (
                "eligible" if kind == "eligible"
                else "operational-censor" if kind == "operational-censor"
                else "site-rejected"
            )
    derived = derive_global_operational_censor_selection(
        candidates, tranco_list_sha256=tranco_list_sha256,
        ordered_candidate_ids=[item.candidate_id for item in ordered],
        order_policy=ORDER_POLICY, eligible_quota=profile.pilot_count,
        terminal_disposition=dispositions,
    )
    if (
        sealed != derived or sealed["policy"] != GLOBAL_OPERATIONAL_CENSOR_SELECTION_POLICY
        or sealed["complete"] is not True or sealed["needed_ids"] != []
    ):
        raise ValueError("20-site acquisition global selection does not verify")
    return derived, dispositions, ordered


def _deep_final_selection(
    path: Path, *, pilot_cohort_path: Path, pilot_assembly_path: Path,
    profile: ClassStudyProfile,
) -> ProfileFinalSelection:
    """Replay every planned pair before admitting the selected final cohort."""

    from .class_final_selection20 import validate_profile_final_selection_receipt

    result = validate_profile_final_selection_receipt(
        path, pilot_cohort_path=pilot_cohort_path,
        pilot_assembly_path=pilot_assembly_path, profile=profile,
    )
    if not isinstance(result, ProfileFinalSelection) or result.profile != profile:
        raise ValueError("deep final-selection verifier returned an invalid result")
    return result


def _validated_final_binding(
    value: object, *, profile: ClassStudyProfile,
    require_deep: bool = True,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "path", "sha256", "pilot_cohort", "pilot_assembly"
    }:
        raise ValueError("final selection binding is malformed")
    if type(require_deep) is not bool:
        raise ValueError("final selection binding verification mode must be boolean")
    names = {
        "path": f"{profile.study_id}-final-selection.json",
        "pilot_cohort": f"{profile.study_id}-pilot-cohort.json",
        "pilot_assembly": f"{profile.study_id}-pilot-cohort-assembly.json",
    }
    lab_root = Path(util.LAB_ROOT).resolve()
    for label, filename in names.items():
        item = value if label == "path" else value[label]
        if not isinstance(item, Mapping) or (
            label != "path" and set(item) != {"path", "sha256"}
        ):
            raise ValueError(f"final selection {label} binding is malformed")
        path = item.get("path")
        digest = item.get("sha256")
        expected = f"config/class-study/v2/{filename}"
        if path != expected or not _digest(digest):
            raise ValueError(f"final selection {label} binding is not canonical")
        if require_deep and sha256_file(_bound_file(path, lab_root, label)) != digest:
            raise ValueError(f"final selection {label} receipt changed")
    return value


def _validate_intrinsic_final_partition(
    payload: Mapping[str, Any], pilot: Sequence[ClassCandidate],
) -> None:
    """Check a frozen final inventory without inferring pair qualification."""

    pilot_ids = [item.candidate_id for item in pilot]
    order = {candidate_id: index for index, candidate_id in enumerate(pilot_ids)}
    final = payload["final_ids"]
    reserves = payload["reserve_ids"]
    pairs = payload["matching"]
    if (
        not isinstance(final, list) or len(final) != CLASS20_PROFILE.final_count
        or not isinstance(reserves, list) or len(reserves) != CLASS20_PROFILE.reserve_count
        or any(not isinstance(item, str) or item not in order for item in final + reserves)
        or len(set(final + reserves)) != len(pilot_ids)
        or set(final + reserves) != set(pilot_ids)
        or final != [item for item in pilot_ids if item in set(final)]
        or reserves != [item for item in pilot_ids if item in set(reserves)]
        or not isinstance(pairs, list) or len(pairs) != CLASS20_PROFILE.final_count // 2
    ):
        raise ValueError("20-site frozen final inventory is not a pilot partition")
    seen: set[str] = set()
    first_indices: list[int] = []
    for pair in pairs:
        if (
            not isinstance(pair, list) or len(pair) != 2
            or any(not isinstance(item, str) or item not in order for item in pair)
            or pair[0] == pair[1] or order[pair[0]] >= order[pair[1]]
            or any(item in seen for item in pair)
        ):
            raise ValueError("20-site frozen final matching is malformed")
        seen.update(pair)
        first_indices.append(order[pair[0]])
    if seen != set(final) or first_indices != sorted(first_indices):
        raise ValueError("20-site frozen final matching differs from final sites")
    by_id = {item.candidate_id: item for item in pilot}
    strata = Counter(by_id[candidate_id].stratum.id for candidate_id in final)
    if any(count > CLASS20_PROFILE.max_final_per_stratum for count in strata.values()):
        raise ValueError("20-site frozen final inventory exceeds the rank-group cap")


def _require_same_pilot(selection: ProfileFinalSelection, pilot_ids: Sequence[str]) -> None:
    if [item.candidate_id for item in selection.pilot] != list(pilot_ids):
        raise ValueError("final selection uses another pilot cohort")


def _require_profile(profile: ClassStudyProfile) -> None:
    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("20-site cohort requires its source-pinned profile")


def _relative_to_lab(path: Path, lab_root: Path) -> str:
    value = Path(path).absolute()
    try:
        relative = value.relative_to(lab_root)
    except ValueError as error:
        raise ValueError("cohort evidence path is outside the Lab root") from error
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("cohort evidence path is not canonical")
    return relative.as_posix()


def _bound_file(value: object, lab_root: Path, label: str) -> Path:
    return _regular_file(_bound_path(value, lab_root), label)


def _bound_directory(value: object, lab_root: Path, label: str) -> Path:
    return _regular_directory(_bound_path(value, lab_root), label)


def _bound_path(value: object, lab_root: Path) -> Path:
    if (
        not isinstance(value, str) or not value
        or Path(value).is_absolute()
        or any(part in {"", ".", ".."} for part in Path(value).parts)
    ):
        raise ValueError("cohort evidence relative path is invalid")
    return lab_root / value


def _regular_file(path: Path, label: str) -> Path:
    value = Path(path).absolute()
    if value.is_symlink() or not value.is_file():
        raise ValueError(f"{label} is not a regular file: {value}")
    return value


def _regular_directory(path: Path, label: str) -> Path:
    value = Path(path).absolute()
    if value.is_symlink() or not value.is_dir():
        raise ValueError(f"{label} is not a regular directory: {value}")
    return value


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
