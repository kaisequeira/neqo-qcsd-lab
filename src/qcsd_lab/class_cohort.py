"""Evidence-backed cohort assembly for ``classifier-multiorigin100-v1``.

The prospective Tranco catalogue contains no outcome fields.  This module is
the only bridge from create-only 30-second/24-hour/72-hour stability receipts
to the boolean eligibility consumed by :mod:`qcsd_lab.class_study`.  It also
binds the selected prepared workload bytes, so a caller cannot turn an
arbitrary ``eligible=true`` bit into a campaign class.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from .class_acquisition import (
    TERMINAL_TYPE,
    validate_acquisition_completion,
    validate_class_study_preparation,
)
from .class_catalogue import (
    STABILITY_RECEIPT_TYPE,
    PageCandidate,
    choose_first_stable_page,
    load_candidate_catalogue_receipt,
    validate_page_candidate,
    validate_stability_receipt,
)
from .class_study import (
    STUDY_ID,
    ClassCandidate,
    bind_receipt,
    build_study_receipt,
    canonical_json_bytes,
    validate_hash_bound_receipt,
    validate_study_receipt,
)
from .util import load_json, sha256_bytes, sha256_file

SCHEMA_VERSION = 3
ASSEMBLY_RECEIPT_TYPE = "qcsd-class-study-cohort-assembly"
FINAL_SELECTION_RECEIPT_TYPE = "qcsd-class-study-final-selection-input"
_PAGE_FILE = re.compile(r"page-([0-4][0-9])[.]json\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def build_evidenced_cohort(
    candidate_catalogue_path: Path,
    *,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    feasible_pairs: Sequence[Sequence[str]] | None = None,
    final_selection_receipt_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the cohort and its independently auditable evidence index.

    Stability files use ``STABILITY_ROOT/CANDIDATE_ID/page-NN.json``.  Missing
    candidate directories are ordinary ineligible outcomes.  A present
    directory, however, must contain only a contiguous page sequence beginning
    at the canonical homepage.  This fails closed on stale or ambiguous files.
    """

    catalogue_path = _regular_file(candidate_catalogue_path, "candidate catalogue")
    catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
    catalogue_payload = validate_hash_bound_receipt(
        catalogue, expected_type="qcsd-class-study-candidate-catalogue"
    )
    stability = _regular_directory(stability_root, "stability receipt root")
    workloads = _regular_directory(workload_root, "prepared workload root")
    completion_path = _regular_file(
        acquisition_completion_path, "acquisition completion"
    )
    completion = load_json(completion_path)
    completion_payload = validate_acquisition_completion(
        completion,
        candidate_catalogue_path=catalogue_path,
        runner_root=completion_path.parent,
    )
    known_ids = {candidate.candidate_id for candidate in candidates}
    unexpected = sorted(
        entry.name for entry in stability.iterdir() if entry.name not in known_ids
    )
    if unexpected:
        raise ValueError(
            "stability root contains entries outside the prospective catalogue: "
            + ", ".join(unexpected)
        )

    resolved: list[ClassCandidate] = []
    evidence: list[dict[str, Any]] = []
    for candidate in candidates:
        eligible, record = _candidate_evidence(
            candidate,
            stability_root=stability,
            workload_root=workloads,
            tranco=catalogue_payload["tranco"],
        )
        _reconcile_acquisition_terminal(
            candidate.candidate_id,
            record,
            completion_payload=completion_payload,
            completion_root=completion_path.parent,
            stability_root=stability,
            workload_root=workloads,
        )
        resolved.append(replace(candidate, eligible=eligible))
        evidence.append(record)

    cohort = build_study_receipt(
        resolved,
        tranco_list_id=catalogue_payload["tranco"]["list_id"],
        tranco_list_sha256=catalogue_payload["tranco"]["list_sha256"],
        feasible_pairs=feasible_pairs,
    )
    selection = validate_study_receipt(cohort)
    final_selection = _final_selection_binding(
        final_selection_receipt_path,
        feasible_pairs=selection.feasible_pairs,
        selected_matching=selection.matching,
    )
    selected_ids = {
        candidate.candidate_id
        for candidate in (*selection.pilot, *selection.final, *selection.reserves)
    }
    assembly_payload = {
        "study_id": STUDY_ID,
        "assembly_schema_version": SCHEMA_VERSION,
        "eligibility_policy": {
            "source": "three-window-page-stability-receipt-only",
            "probe_windows": ["t+30s", "t+24h", "t+72h"],
            "page_order": "canonical-homepage-then-hash-ordered-safe-same-domain-links",
            "outcome_optimisation": False,
            "classifier_or_defence_measurements_used": False,
            "prepared_workload_sha256_required": True,
        },
        "candidate_catalogue": {
            "path": catalogue_path.name,
            "sha256": sha256_file(catalogue_path),
            "payload_sha256": catalogue["payload_sha256"],
        },
        "acquisition_completion": {
            "path": completion_path.name,
            "sha256": sha256_file(completion_path),
            "payload_sha256": completion["payload_sha256"],
            "provenance_sha256": completion_payload["provenance_sha256"],
        },
        "final_selection": final_selection,
        "stability_root": stability.name,
        "workload_root": workloads.name,
        "candidates": evidence,
        "eligible_count": sum(candidate.eligible for candidate in resolved),
        "selected_evidence_count": sum(
            record["candidate_id"] in selected_ids and record["eligible"]
            for record in evidence
        ),
        "cohort": {
            "receipt_type": cohort["receipt_type"],
            "payload_sha256": cohort["payload_sha256"],
            "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
        },
    }
    assembly = bind_receipt(assembly_payload, receipt_type=ASSEMBLY_RECEIPT_TYPE)
    validate_cohort_assembly(
        assembly,
        cohort=cohort,
        candidate_catalogue_path=catalogue_path,
        stability_root=stability,
        workload_root=workloads,
        acquisition_completion_path=completion_path,
        final_selection_receipt_path=final_selection_receipt_path,
    )
    return cohort, assembly


def validate_cohort_assembly(
    value: Mapping[str, Any],
    *,
    cohort: Mapping[str, Any],
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    final_selection_receipt_path: Path | None = None,
) -> dict[str, Any]:
    """Rebuild the assembly from immutable inputs and compare exact bytes."""

    payload = validate_cohort_assembly_receipt(value, cohort=cohort)
    selection = validate_study_receipt(cohort)
    pair_graph = selection.feasible_pairs
    rebuilt_cohort, rebuilt = build_evidenced_cohort_unchecked(
        candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        feasible_pairs=pair_graph,
        final_selection_receipt_path=final_selection_receipt_path,
    )
    if canonical_json_bytes(rebuilt_cohort) != canonical_json_bytes(cohort):
        raise ValueError("cohort receipt differs from its stability evidence")
    rebuilt_payload = validate_hash_bound_receipt(
        rebuilt, expected_type=ASSEMBLY_RECEIPT_TYPE
    )
    if payload != rebuilt_payload:
        raise ValueError("cohort assembly differs from independently rebuilt evidence")
    return payload


def validate_cohort_assembly_receipt(
    value: Mapping[str, Any],
    *,
    cohort: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a frozen assembly intrinsically and bind it to one cohort.

    Current publication additionally calls :func:`validate_cohort_assembly` to
    rebuild this receipt from all 600 stability directories.  Campaign inputs
    retain this smaller, hash-bound receipt so frozen replay can still prove
    that every selected workload byte is the one admitted by that rebuild.
    """

    payload = validate_hash_bound_receipt(value, expected_type=ASSEMBLY_RECEIPT_TYPE)
    schema_version = payload.get("assembly_schema_version")
    expected_keys = {
        "study_id",
        "assembly_schema_version",
        "eligibility_policy",
        "candidate_catalogue",
        "acquisition_completion",
        "final_selection",
        "stability_root",
        "workload_root",
        "candidates",
        "eligible_count",
        "selected_evidence_count",
        "cohort",
    }
    if schema_version in {1, 2}:
        expected_keys.remove("final_selection")
    if schema_version == 1:
        # Historical prospective fixtures remain readable; only schema three
        # can be newly rebuilt/published by this module.
        expected_keys.remove("acquisition_completion")
    if set(payload) != expected_keys:
        raise ValueError("cohort assembly payload fields differ from the contract")
    if payload["study_id"] != STUDY_ID or schema_version not in {1, 2, SCHEMA_VERSION}:
        raise ValueError("cohort assembly identifies the wrong study or schema")
    if payload["eligibility_policy"] != {
        "source": "three-window-page-stability-receipt-only",
        "probe_windows": ["t+30s", "t+24h", "t+72h"],
        "page_order": "canonical-homepage-then-hash-ordered-safe-same-domain-links",
        "outcome_optimisation": False,
        "classifier_or_defence_measurements_used": False,
        "prepared_workload_sha256_required": True,
    }:
        raise ValueError("cohort assembly eligibility policy differs from the contract")

    selection = validate_study_receipt(cohort)
    cohort_binding = payload["cohort"]
    expected_cohort_binding = {
        "receipt_type": cohort.get("receipt_type"),
        "payload_sha256": cohort.get("payload_sha256"),
        "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
    }
    if cohort_binding != expected_cohort_binding:
        raise ValueError("cohort assembly does not bind the supplied cohort receipt")

    catalogue = payload["candidate_catalogue"]
    if (
        not isinstance(catalogue, Mapping)
        or set(catalogue) != {"path", "sha256", "payload_sha256"}
        or not isinstance(catalogue["path"], str)
        or Path(catalogue["path"]).name != catalogue["path"]
        or not _digest(catalogue["sha256"])
        or not _digest(catalogue["payload_sha256"])
    ):
        raise ValueError("cohort assembly candidate-catalogue binding is invalid")
    if schema_version in {2, SCHEMA_VERSION}:
        completion = payload["acquisition_completion"]
        if (
            not isinstance(completion, Mapping)
            or set(completion)
            != {"path", "sha256", "payload_sha256", "provenance_sha256"}
            or not isinstance(completion["path"], str)
            or Path(completion["path"]).name != completion["path"]
            or not all(
                _digest(completion[key])
                for key in ("sha256", "payload_sha256", "provenance_sha256")
            )
        ):
            raise ValueError(
                "cohort assembly acquisition-completion binding is invalid"
            )
    if schema_version == SCHEMA_VERSION:
        final_binding = payload["final_selection"]
        if selection.feasible_pairs is None:
            if final_binding is not None:
                raise ValueError("pilot cohort assembly must not bind final selection")
        elif (
            not isinstance(final_binding, Mapping)
            or set(final_binding)
            != {
                "path",
                "sha256",
                "payload_sha256",
                "payload",
            }
            or not isinstance(final_binding["path"], str)
            or Path(final_binding["path"]).name != final_binding["path"]
            or not _digest(final_binding["sha256"])
            or not _digest(final_binding["payload_sha256"])
        ):
            raise ValueError("final cohort assembly selection lineage is invalid")
        if selection.feasible_pairs is not None:
            embedded_payload = final_binding["payload"]
            if not isinstance(embedded_payload, Mapping):
                raise ValueError("final cohort assembly selection payload is invalid")
            envelope = bind_receipt(
                embedded_payload, receipt_type=FINAL_SELECTION_RECEIPT_TYPE
            )
            if (
                envelope["payload_sha256"] != final_binding["payload_sha256"]
                or sha256_bytes(canonical_json_bytes(envelope))
                != final_binding["sha256"]
            ):
                raise ValueError("final cohort assembly selection hashes do not verify")
            _validate_final_selection_payload(
                embedded_payload,
                feasible_pairs=selection.feasible_pairs,
                selected_matching=selection.matching,
            )
    for key in ("stability_root", "workload_root"):
        root_name = payload[key]
        if (
            not isinstance(root_name, str)
            or not root_name
            or Path(root_name).name != root_name
            or root_name in {".", ".."}
        ):
            raise ValueError(f"cohort assembly {key} identity is invalid")

    records = payload["candidates"]
    if not isinstance(records, list) or len(records) != len(selection.candidates):
        raise ValueError("cohort assembly candidate evidence inventory is invalid")
    selected_ids = {candidate.candidate_id for candidate in selection.pilot}
    eligible_count = 0
    selected_count = 0
    for candidate, raw_record in zip(selection.candidates, records, strict=True):
        if not isinstance(raw_record, Mapping):
            raise ValueError("cohort assembly candidate evidence must be an object")
        record = dict(raw_record)
        if set(record) != {
            "candidate_id",
            "eligible",
            "selected_page",
            "stability_receipt",
            "prepared_workload",
            "reasons",
        }:
            raise ValueError("cohort assembly candidate evidence fields are invalid")
        if (
            record["candidate_id"] != candidate.candidate_id
            or not isinstance(record["eligible"], bool)
            or record["eligible"] != candidate.eligible
        ):
            raise ValueError(
                "cohort assembly candidate identity or eligibility is invalid"
            )
        reasons = record["reasons"]
        if (
            not isinstance(reasons, list)
            or any(not isinstance(reason, str) or not reason for reason in reasons)
            or len(reasons) != len(set(reasons))
        ):
            raise ValueError("cohort assembly candidate reasons are invalid")
        if record["eligible"]:
            eligible_count += 1
            if candidate.candidate_id in selected_ids:
                selected_count += 1
            if reasons:
                raise ValueError(
                    "eligible cohort candidate cannot carry rejection reasons"
                )
            _validate_eligible_evidence(candidate, record)
        elif (
            any(
                record[key] is not None
                for key in ("selected_page", "stability_receipt", "prepared_workload")
            )
            or not reasons
        ):
            raise ValueError("ineligible cohort candidate has inconsistent evidence")
    if (
        type(payload["eligible_count"]) is not int
        or payload["eligible_count"] != eligible_count
        or type(payload["selected_evidence_count"]) is not int
        or payload["selected_evidence_count"] != selected_count
        or selected_count != len(selected_ids)
    ):
        raise ValueError("cohort assembly evidence counts are invalid")
    return payload


def cohort_workload_hashes(
    assembly: Mapping[str, Any],
    *,
    cohort: Mapping[str, Any],
    workload_ids: Sequence[str],
) -> dict[str, str]:
    """Resolve exact prepared-workload hashes for an ordered cohort subset."""

    payload = validate_cohort_assembly_receipt(assembly, cohort=cohort)
    evidence = {record["candidate_id"]: record for record in payload["candidates"]}
    result: dict[str, str] = {}
    for workload_id in workload_ids:
        record = evidence.get(workload_id)
        prepared = (
            record.get("prepared_workload") if isinstance(record, Mapping) else None
        )
        if not isinstance(prepared, Mapping) or not _digest(prepared.get("sha256")):
            raise ValueError(
                f"cohort assembly has no admitted workload hash for {workload_id}"
            )
        result[workload_id] = str(prepared["sha256"])
    return result


def build_evidenced_cohort_unchecked(
    candidate_catalogue_path: Path,
    *,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    feasible_pairs: Sequence[Sequence[str]] | None = None,
    final_selection_receipt_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Internal rebuild entry point that avoids recursive validation."""

    # The public builder performs a final self-check.  Temporarily dispatch to
    # the shared implementation with that last step disabled.
    return _build_evidenced_cohort(
        candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        feasible_pairs=feasible_pairs,
        final_selection_receipt_path=final_selection_receipt_path,
    )


def _build_evidenced_cohort(
    candidate_catalogue_path: Path,
    *,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    feasible_pairs: Sequence[Sequence[str]] | None,
    final_selection_receipt_path: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Implementation used by the validator; see ``build_evidenced_cohort``."""

    catalogue_path = _regular_file(candidate_catalogue_path, "candidate catalogue")
    catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
    catalogue_payload = validate_hash_bound_receipt(
        catalogue, expected_type="qcsd-class-study-candidate-catalogue"
    )
    stability = _regular_directory(stability_root, "stability receipt root")
    workloads = _regular_directory(workload_root, "prepared workload root")
    completion_path = _regular_file(
        acquisition_completion_path, "acquisition completion"
    )
    completion = load_json(completion_path)
    completion_payload = validate_acquisition_completion(
        completion,
        candidate_catalogue_path=catalogue_path,
        runner_root=completion_path.parent,
    )
    known_ids = {candidate.candidate_id for candidate in candidates}
    unexpected = sorted(
        entry.name for entry in stability.iterdir() if entry.name not in known_ids
    )
    if unexpected:
        raise ValueError(
            "stability root contains entries outside the prospective catalogue: "
            + ", ".join(unexpected)
        )
    resolved: list[ClassCandidate] = []
    evidence: list[dict[str, Any]] = []
    for candidate in candidates:
        eligible, record = _candidate_evidence(
            candidate,
            stability_root=stability,
            workload_root=workloads,
            tranco=catalogue_payload["tranco"],
        )
        _reconcile_acquisition_terminal(
            candidate.candidate_id,
            record,
            completion_payload=completion_payload,
            completion_root=completion_path.parent,
            stability_root=stability,
            workload_root=workloads,
        )
        resolved.append(replace(candidate, eligible=eligible))
        evidence.append(record)
    cohort = build_study_receipt(
        resolved,
        tranco_list_id=catalogue_payload["tranco"]["list_id"],
        tranco_list_sha256=catalogue_payload["tranco"]["list_sha256"],
        feasible_pairs=feasible_pairs,
    )
    selection = validate_study_receipt(cohort)
    final_selection = _final_selection_binding(
        final_selection_receipt_path,
        feasible_pairs=selection.feasible_pairs,
        selected_matching=selection.matching,
    )
    selected_ids = {
        candidate.candidate_id
        for candidate in (*selection.pilot, *selection.final, *selection.reserves)
    }
    assembly = bind_receipt(
        {
            "study_id": STUDY_ID,
            "assembly_schema_version": SCHEMA_VERSION,
            "eligibility_policy": {
                "source": "three-window-page-stability-receipt-only",
                "probe_windows": ["t+30s", "t+24h", "t+72h"],
                "page_order": (
                    "canonical-homepage-then-hash-ordered-safe-same-domain-links"
                ),
                "outcome_optimisation": False,
                "classifier_or_defence_measurements_used": False,
                "prepared_workload_sha256_required": True,
            },
            "candidate_catalogue": {
                "path": catalogue_path.name,
                "sha256": sha256_file(catalogue_path),
                "payload_sha256": catalogue["payload_sha256"],
            },
            "acquisition_completion": {
                "path": completion_path.name,
                "sha256": sha256_file(completion_path),
                "payload_sha256": completion["payload_sha256"],
                "provenance_sha256": completion_payload["provenance_sha256"],
            },
            "final_selection": final_selection,
            "stability_root": stability.name,
            "workload_root": workloads.name,
            "candidates": evidence,
            "eligible_count": sum(candidate.eligible for candidate in resolved),
            "selected_evidence_count": sum(
                record["candidate_id"] in selected_ids and record["eligible"]
                for record in evidence
            ),
            "cohort": {
                "receipt_type": cohort["receipt_type"],
                "payload_sha256": cohort["payload_sha256"],
                "canonical_file_sha256": sha256_bytes(canonical_json_bytes(cohort)),
            },
        },
        receipt_type=ASSEMBLY_RECEIPT_TYPE,
    )
    return cohort, assembly


def publish_evidenced_cohort(
    cohort_destination: Path,
    assembly_destination: Path,
    *,
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    feasible_pairs: Sequence[Sequence[str]] | None = None,
    final_selection_receipt_path: Path | None = None,
) -> tuple[Path, Path]:
    """Idempotently publish two immutable, exact JSON files.

    An interrupted two-file publication can be resumed only when an existing
    file is byte-identical to the independently rebuilt value.
    """

    cohort, assembly = build_evidenced_cohort(
        candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        feasible_pairs=feasible_pairs,
        final_selection_receipt_path=final_selection_receipt_path,
    )
    assembly_path = _write_or_verify(assembly_destination, assembly)
    cohort_path = _write_or_verify(cohort_destination, cohort)
    return cohort_path, assembly_path


def _reconcile_acquisition_terminal(
    candidate_id: str,
    record: Mapping[str, Any],
    *,
    completion_payload: Mapping[str, Any],
    completion_root: Path,
    stability_root: Path,
    workload_root: Path,
) -> None:
    """Prove cohort evidence is the exact terminal choice of this acquisition."""

    terminals = completion_payload.get("terminal_receipts")
    binding = terminals.get(candidate_id) if isinstance(terminals, Mapping) else None
    if not isinstance(binding, Mapping) or set(binding) != {"path", "sha256"}:
        raise ValueError(f"acquisition has no terminal binding for {candidate_id}")
    terminal_path = completion_root / str(binding["path"])
    if (
        terminal_path.is_symlink()
        or not terminal_path.is_file()
        or sha256_file(terminal_path) != binding["sha256"]
    ):
        raise ValueError(f"acquisition terminal does not verify for {candidate_id}")
    terminal = validate_hash_bound_receipt(
        load_json(terminal_path), expected_type=TERMINAL_TYPE
    )
    if terminal.get("candidate_id") != candidate_id:
        raise ValueError("acquisition terminal candidate identity differs")

    eligible = record.get("eligible") is True
    if not eligible:
        if terminal.get("kind") == "eligible":
            raise ValueError(
                f"cohort marks acquisition-eligible candidate {candidate_id} ineligible"
            )
        return
    if terminal.get("kind") != "eligible":
        raise ValueError(
            f"cohort eligibility for {candidate_id} differs from acquisition terminal"
        )
    stability = record.get("stability_receipt")
    workload = record.get("prepared_workload")
    terminal_stability = terminal.get("stability_receipt")
    terminal_workload = terminal.get("admitted_workload")
    if not all(
        isinstance(value, Mapping)
        for value in (stability, workload, terminal_stability, terminal_workload)
    ):
        raise ValueError("eligible acquisition/cohort lineage is incomplete")
    expected_stability_path = (
        stability_root / str(stability["path"])
    ).resolve()
    expected_workload_path = (workload_root / str(workload["path"])).resolve()
    if (
        Path(str(terminal_stability["path"])).resolve() != expected_stability_path
        or terminal_stability.get("sha256") != stability.get("sha256")
        or Path(str(terminal_workload["path"])).resolve() != expected_workload_path
        or terminal_workload.get("sha256") != workload.get("sha256")
    ):
        raise ValueError(
            f"cohort evidence for {candidate_id} differs from acquisition terminal choice"
        )


def _candidate_evidence(
    candidate: ClassCandidate,
    *,
    stability_root: Path,
    workload_root: Path,
    tranco: Mapping[str, Any],
) -> tuple[bool, dict[str, Any]]:
    root = stability_root / candidate.candidate_id
    if not root.exists() and not root.is_symlink():
        return False, {
            "candidate_id": candidate.candidate_id,
            "eligible": False,
            "selected_page": None,
            "stability_receipt": None,
            "prepared_workload": None,
            "reasons": ["no-stability-receipts"],
        }
    root = _regular_directory(root, f"stability directory for {candidate.candidate_id}")
    indexed: list[tuple[int, Path, Mapping[str, Any]]] = []
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"stability entry is not a regular file: {path}")
        match = _PAGE_FILE.fullmatch(path.name)
        if match is None:
            raise ValueError(f"stability filename is not canonical: {path.name}")
        value = load_json(path)
        validate_stability_receipt(value)
        payload = validate_hash_bound_receipt(
            value, expected_type=STABILITY_RECEIPT_TYPE
        )
        if (
            payload["candidate"]["candidate_id"] != candidate.candidate_id
            or payload["candidate"]["domain"] != candidate.domain
            or payload["candidate"]["rank"] != candidate.rank
            or payload["tranco"]
            != {"list_id": tranco["list_id"], "list_sha256": tranco["list_sha256"]}
            or payload["page"]["ordinal"] != int(match.group(1))
        ):
            raise ValueError(
                "stability receipt identity differs from its catalogue path"
            )
        indexed.append((int(match.group(1)), path, value))
    indexed.sort(key=lambda item: item[0])
    if not indexed or tuple(item[0] for item in indexed) != tuple(range(len(indexed))):
        raise ValueError("stability pages must form a contiguous sequence from page-00")
    pages = tuple(
        PageCandidate(
            **validate_hash_bound_receipt(value, expected_type=STABILITY_RECEIPT_TYPE)[
                "page"
            ]
        )
        for _index, _path, value in indexed
    )
    by_url = {
        validate_hash_bound_receipt(value, expected_type=STABILITY_RECEIPT_TYPE)[
            "page"
        ]["url"]: value
        for _index, _path, value in indexed
    }
    selected = choose_first_stable_page(candidate, pages, by_url)
    if selected is None:
        reasons = sorted(
            {
                reason
                for _index, _path, value in indexed
                for reason in validate_hash_bound_receipt(
                    value, expected_type=STABILITY_RECEIPT_TYPE
                )["decision"]["reasons"]
            }
        )
        return False, {
            "candidate_id": candidate.candidate_id,
            "eligible": False,
            "selected_page": None,
            "stability_receipt": None,
            "prepared_workload": None,
            "reasons": reasons or ["no-stable-page"],
        }
    selected_index = next(index for index, page in enumerate(pages) if page == selected)
    _ordinal, receipt_path, receipt = indexed[selected_index]
    payload = validate_hash_bound_receipt(receipt, expected_type=STABILITY_RECEIPT_TYPE)
    stable = payload["decision"]["stable_values"]
    if not isinstance(stable, Mapping):
        raise ValueError("selected stability receipt has no stable values")
    workload_path = _regular_file(
        workload_root / f"{candidate.candidate_id}.json",
        f"prepared workload for {candidate.candidate_id}",
    )
    if sha256_file(workload_path) != stable["prepared_workload_sha256"]:
        raise ValueError(
            "selected prepared workload differs from its stability receipt"
        )
    validate_class_study_preparation(
        load_json(workload_path), workload_id=candidate.candidate_id
    )
    return True, {
        "candidate_id": candidate.candidate_id,
        "eligible": True,
        "selected_page": selected.as_dict(),
        "stability_receipt": {
            "path": receipt_path.relative_to(stability_root).as_posix(),
            "sha256": sha256_file(receipt_path),
            "payload_sha256": receipt["payload_sha256"],
        },
        "prepared_workload": {
            "path": workload_path.name,
            "sha256": sha256_file(workload_path),
        },
        "reasons": [],
    }


def _validate_eligible_evidence(
    candidate: ClassCandidate,
    record: Mapping[str, Any],
) -> None:
    page_value = record["selected_page"]
    if not isinstance(page_value, Mapping) or set(page_value) != {
        "candidate_domain",
        "registrable_domain",
        "url",
        "source",
        "ordinal",
        "discovery_content_type",
    }:
        raise ValueError("eligible cohort candidate has an invalid selected page")
    try:
        page = PageCandidate(**page_value)
    except TypeError as error:
        raise ValueError(
            "eligible cohort candidate selected page is malformed"
        ) from error
    validate_page_candidate(page)
    if page.candidate_domain != candidate.domain:
        raise ValueError(
            "eligible cohort selected page differs from its candidate domain"
        )

    stability = record["stability_receipt"]
    if not isinstance(stability, Mapping) or set(stability) != {
        "path",
        "sha256",
        "payload_sha256",
    }:
        raise ValueError("eligible cohort candidate has an invalid stability binding")
    stability_path = stability["path"]
    if (
        not isinstance(stability_path, str)
        or Path(stability_path).parts
        != (candidate.candidate_id, f"page-{page.ordinal:02d}.json")
        or not _digest(stability["sha256"])
        or not _digest(stability["payload_sha256"])
    ):
        raise ValueError("eligible cohort candidate stability binding is malformed")

    prepared = record["prepared_workload"]
    if (
        not isinstance(prepared, Mapping)
        or set(prepared) != {"path", "sha256"}
        or prepared["path"] != f"{candidate.candidate_id}.json"
        or not _digest(prepared["sha256"])
    ):
        raise ValueError(
            "eligible cohort candidate prepared-workload binding is invalid"
        )


def _final_selection_binding(
    path: Path | None,
    *,
    feasible_pairs: Sequence[Sequence[str]] | None,
    selected_matching: Sequence[Sequence[str]] | None,
) -> dict[str, Any] | None:
    if feasible_pairs is None:
        if path is not None or selected_matching is not None:
            raise ValueError("pilot cohort must not bind a final-selection receipt")
        return None
    if path is None or selected_matching is None:
        raise ValueError(
            "authoritative cohort requires a typed final-selection receipt and matching"
        )
    source = _regular_file(path, "final-selection receipt")
    value = load_json(source)
    payload = validate_hash_bound_receipt(
        value, expected_type=FINAL_SELECTION_RECEIPT_TYPE
    )
    _validate_final_selection_payload(
        payload,
        feasible_pairs=feasible_pairs,
        selected_matching=selected_matching,
    )
    return {
        "path": source.name,
        "sha256": sha256_file(source),
        "payload_sha256": value["payload_sha256"],
        "payload": payload,
    }


def _validate_final_selection_payload(
    payload: Mapping[str, Any],
    *,
    feasible_pairs: Sequence[Sequence[str]],
    selected_matching: Sequence[Sequence[str]],
) -> None:
    """Validate the exact current final-selection evidence contract."""

    required = {
        "study_id",
        "selection_schema_version",
        "selection_policy",
        "pilot_cohort",
        "pilot_cohort_assembly",
        "pilot_numeric_fitting",
        "pilot_compatibility",
        "feasible_pair_rule",
        "feasible_pair_evidence",
        "feasible_pair_graph",
        "selected_final_perfect_matching",
    }
    if (
        set(payload) != required
        or payload["study_id"] != STUDY_ID
        or type(payload["selection_schema_version"]) is not int
        or payload["selection_schema_version"] != 1
        or not isinstance(payload["selection_policy"], str)
        or payload["selection_policy"] not in {
            "tranco-bound-order-with-qualified-selected-wt6-pairs",
            "sealed-class-incompatibility-successor-v2",
        }
    ):
        raise ValueError("final-selection receipt fields differ from the contract")

    expected_graph = [list(pair) for pair in feasible_pairs]
    if payload["feasible_pair_graph"] != expected_graph:
        raise ValueError(
            "final cohort feasible graph differs from final-selection receipt"
        )
    graph_keys, graph_endpoints = _pair_inventory(
        expected_graph,
        label="final-selection feasible graph",
    )

    evidence = payload["feasible_pair_evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(expected_graph):
        raise ValueError("final-selection qualified-pair evidence is incomplete")
    evidence_fields = {
        "left",
        "right",
        "runtime_profile_real",
        "runtime_profile_decoy",
        "runtime_profile_sha256",
        "endpoint_qualification",
    }
    endpoint_fields = {
        "workload_id",
        "chaff_qualification_sidecar_sha256",
        "prefix_pack_spec_sha256",
        "qualified_chaff_manifest_sha256",
        "qualified_parallel_chaff_streams",
        "walkie_talkie_required_chaff_streams",
    }
    evidence_pairs: list[tuple[str, str]] = []
    for expected_pair, record in zip(expected_graph, evidence, strict=True):
        if not isinstance(record, Mapping) or set(record) != evidence_fields:
            raise ValueError(
                "final-selection qualified-pair evidence fields differ from the contract"
            )
        left, right = record["left"], record["right"]
        if [left, right] != expected_pair:
            raise ValueError(
                "final-selection qualified-pair evidence orientation differs "
                "from the feasible graph"
            )
        evidence_pairs.append((left, right))

        real = record["runtime_profile_real"]
        decoy = record["runtime_profile_decoy"]
        if (
            not isinstance(real, str)
            or not isinstance(decoy, str)
            or real == decoy
            or {real, decoy} != {left, right}
            or not _digest(record["runtime_profile_sha256"])
        ):
            raise ValueError(
                "final-selection qualified-pair runtime profile is invalid"
            )

        endpoint_qualification = record["endpoint_qualification"]
        if (
            not isinstance(endpoint_qualification, list)
            or len(endpoint_qualification) != 2
        ):
            raise ValueError(
                "final-selection qualified-pair endpoint evidence is incomplete"
            )
        for workload_id, endpoint in zip(
            (left, right), endpoint_qualification, strict=True
        ):
            if not isinstance(endpoint, Mapping) or set(endpoint) != endpoint_fields:
                raise ValueError(
                    "final-selection endpoint qualification fields differ "
                    "from the contract"
                )
            required = endpoint["walkie_talkie_required_chaff_streams"]
            qualified = endpoint["qualified_parallel_chaff_streams"]
            if (
                endpoint["workload_id"] != workload_id
                or not _digest(endpoint["chaff_qualification_sidecar_sha256"])
                or not _digest(endpoint["prefix_pack_spec_sha256"])
                or not _digest(endpoint["qualified_chaff_manifest_sha256"])
                or type(required) is not int
                or type(qualified) is not int
                or required < 1
                or qualified < required
            ):
                raise ValueError(
                    "final-selection endpoint qualification is invalid"
                )

    evidence_keys, evidence_endpoints = _pair_inventory(
        evidence_pairs,
        label="final-selection qualified-pair evidence",
    )
    if evidence_keys != graph_keys or evidence_endpoints != graph_endpoints:
        raise ValueError(
            "final-selection qualified-pair evidence differs from the feasible graph"
        )

    expected_matching = [list(pair) for pair in selected_matching]
    if payload["selected_final_perfect_matching"] != expected_matching:
        raise ValueError(
            "final cohort matching differs from final-selection receipt"
        )
    matching_keys, _matching_endpoints = _pair_inventory(
        expected_matching,
        label="final-selection selected matching",
    )
    if not matching_keys.issubset(graph_keys):
        raise ValueError("final-selection selected matching uses an unqualified edge")

    for label in ("pilot_cohort", "pilot_cohort_assembly"):
        binding = payload[label]
        if (
            not isinstance(binding, Mapping)
            or set(binding) != {"sha256", "payload_sha256"}
            or not _digest(binding["sha256"])
            or not _digest(binding["payload_sha256"])
        ):
            raise ValueError(f"final-selection {label} binding is invalid")
    _validate_pilot_numeric_fitting(payload["pilot_numeric_fitting"])
    _validate_pilot_compatibility(payload["pilot_compatibility"])
    _validate_feasible_pair_rule(
        payload["feasible_pair_rule"],
        selection_policy=payload["selection_policy"],
        qualified_pair_edges=len(expected_graph),
    )


def _validate_pilot_numeric_fitting(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "numeric_provenance_sha256",
        "walkie_talkie_artifact_sha256",
        "source_result",
    }:
        raise ValueError("final-selection pilot_numeric_fitting evidence is invalid")
    if not _digest(value["numeric_provenance_sha256"]) or not _digest(
        value["walkie_talkie_artifact_sha256"]
    ):
        raise ValueError("final-selection pilot numeric fitting hashes are invalid")

    # Import lazily: class_fitting imports this module for cohort validation.
    from .class_fitting import PILOT_STAGE, _validate_source_result

    _validate_source_result(value["source_result"], PILOT_STAGE)


def _validate_pilot_compatibility(value: object) -> None:
    fields = {
        "campaign",
        "evidence_sha256",
        "experiment_sha256",
        "accepted_samples",
        "unique_class_mode_pairs",
        "fitted_parameter_sha256",
        "finalized_bundle",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("final-selection pilot_compatibility evidence is invalid")
    if (
        value["campaign"] != f"{STUDY_ID}-pilot-compatibility-1080-1200"
        or value["accepted_samples"] != 1_080
        or value["unique_class_mode_pairs"] != 1_080
        or not _digest(value["evidence_sha256"])
        or not _digest(value["experiment_sha256"])
    ):
        raise ValueError("final-selection pilot compatibility result is invalid")
    parameter_hashes = value["fitted_parameter_sha256"]
    if (
        not isinstance(parameter_hashes, Mapping)
        or set(parameter_hashes) != {
            "traffic-morphing",
            "wtf-pad",
            "walkie-talkie",
        }
        or not all(_digest(digest) for digest in parameter_hashes.values())
    ):
        raise ValueError("final-selection pilot compatibility parameters are invalid")
    finalized = value["finalized_bundle"]
    if (
        not isinstance(finalized, Mapping)
        or set(finalized) != {
            "source",
            "provenance_sha256",
            "artifact_sha256",
        }
        or finalized["source"] != "frozen-pilot-compatibility-inputs"
        or not _digest(finalized["provenance_sha256"])
        or finalized["artifact_sha256"] != parameter_hashes
    ):
        raise ValueError("final-selection finalized pilot bundle is invalid")


def _validate_feasible_pair_rule(
    value: object,
    *,
    selection_policy: object,
    qualified_pair_edges: int,
) -> None:
    if selection_policy == "tranco-bound-order-with-qualified-selected-wt6-pairs":
        possible_pair_count = 120 * 119 // 2
        expected = {
            "source": (
                "finalized-selected-wt6-profile-and-both-endpoint-qualification"
            ),
            "candidate_unordered_pairs": possible_pair_count,
            "qualified_pair_edges": qualified_pair_edges,
            "unqualified_alternate_pairs_excluded": (
                possible_pair_count - qualified_pair_edges
            ),
            "pair_specific_finalized_runtime_profile_required": True,
            "both_endpoint_frozen_prefix_qualification_required": True,
            "unselected_pairs_inferred_from_endpoint_compatibility": False,
            "numeric_fit_selected_runtime_profiles_used": True,
            "final_20_per_stratum_perfect_matching_required": True,
            "classifier_outcomes_used": False,
            "measured_bandwidth_latency_or_privacy_outcomes_used": False,
        }
        if value != expected:
            raise ValueError("final-selection root feasible-pair rule is invalid")
        return

    fields = {
        "source",
        "selection",
        "cumulative_failed_classes_excluded",
        "replacement_generation",
        "decision_payload_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("final-selection successor feasible-pair rule is invalid")
    failed = value["cumulative_failed_classes_excluded"]
    generation = value["replacement_generation"]
    if (
        value["source"] != "qualified-root-120-class-60-edge-graph"
        or value["selection"] != "decision-bound-successor-50-edge-matching"
        or not isinstance(failed, list)
        or not failed
        or not all(isinstance(candidate_id, str) and candidate_id for candidate_id in failed)
        or len(set(failed)) != len(failed)
        or type(generation) is not int
        or generation < 1
        or not _digest(value["decision_payload_sha256"])
    ):
        raise ValueError("final-selection successor feasible-pair rule is invalid")


def _pair_inventory(
    pairs: Sequence[Sequence[str]],
    *,
    label: str,
) -> tuple[set[frozenset[str]], set[str]]:
    keys: set[frozenset[str]] = set()
    endpoints: set[str] = set()
    for raw_pair in pairs:
        if (
            not isinstance(raw_pair, Sequence)
            or isinstance(raw_pair, (str, bytes))
            or len(raw_pair) != 2
            or not all(isinstance(candidate_id, str) for candidate_id in raw_pair)
            or raw_pair[0] == raw_pair[1]
        ):
            raise ValueError(f"{label} contains a malformed edge")
        left, right = raw_pair
        key = frozenset((left, right))
        if key in keys:
            raise ValueError(f"{label} contains a duplicate edge")
        if left in endpoints or right in endpoints:
            raise ValueError(f"{label} contains duplicate endpoints")
        keys.add(key)
        endpoints.update((left, right))
    return keys, endpoints


def _write_or_verify(path: Path, value: Mapping[str, Any]) -> Path:
    destination = Path(os.path.abspath(path))
    parent = _regular_directory(destination.parent, "cohort publication root")
    destination = parent / destination.name
    encoded = canonical_json_bytes(value)
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != encoded
        ):
            raise FileExistsError(
                f"immutable cohort output already differs: {destination}"
            )
        return destination
    with destination.open("xb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return destination


def _regular_file(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    if value.is_symlink() or not value.is_file():
        raise ValueError(f"{label} is not a regular file: {value}")
    return value


def _regular_directory(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    if value.is_symlink() or not value.is_dir():
        raise ValueError(f"{label} is not a regular directory: {value}")
    return value


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None
