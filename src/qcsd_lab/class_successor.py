"""Fail-closed successor selection for the 100-class QCSD study.

It defines the immutable policy and decision boundary needed to replace a
class only after a sealed, incomplete first-launch certification proves a
class-level incompatibility.  It can also publish a distinct, hash-derived
restart plan for the mandatory 2,000/600/900 successor gates.  Infrastructure
failures never authorise automatic replacement.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .class_cohort import (
    FINAL_SELECTION_RECEIPT_TYPE,
    validate_cohort_assembly_receipt,
)
from .class_study import (
    COMPATIBILITY_MODES,
    FINAL_CLASS_COUNT,
    FINAL_CLASSES_PER_STRATUM,
    PILOT_CLASSES_PER_STRATUM,
    PILOT_COUNT,
    RESERVE_COUNT,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    CohortSelection,
    bind_receipt,
    build_study_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    load_study_receipt,
    validate_study_receipt,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .util import load_json, require_disjoint_path, sha256_file
from .verification import VerifiedResult, verify_result

SCHEMA_VERSION = 1
POLICY_RECEIPT_TYPE = "qcsd-class-study-successor-policy"
DECISION_RECEIPT_TYPE = "qcsd-class-study-successor-decision"
RESTART_RECEIPT_TYPE = "qcsd-class-study-successor-restart"
SUCCESSOR_COHORT_RECEIPT_TYPE = "qcsd-class-study-successor-cohort"
QUALIFICATION_PLAN_RECEIPT_TYPE = "qcsd-class-study-successor-qualification-plan"
READINESS_RECEIPT_TYPE = "qcsd-class-study-readiness-attestation"
SUCCESSOR_STUDY_PREFIX = "classifier-multiorigin100-v2"
CERTIFICATION_NAME = f"{STUDY_ID}-certification-900-1200"
CERTIFICATION_SAMPLE_COUNT = FINAL_CLASS_COUNT * len(COMPATIBILITY_MODES)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CLASS_INCOMPATIBILITY_FAILURES = frozenset(
    {
        ("fidelity", "StrictDefenseFidelityFailure"),
        ("fidelity", "StrictPreparedResponseIdentityFailure"),
    }
)
_INFRASTRUCTURE_FAILURE_TYPES = frozenset(
    {
        "HardInterruption",
        "StrictCaptureClockIntegrityFailure",
    }
)

DOWNSTREAM_RESTART = {
    "authoritative_fitting_samples": 2_000,
    "final_qualification_executions": 600,
    "first_launch_certification_cells": 900,
    "certification_scope": "complete-100-class-by-9-mode-cross-product",
    "reuse_predecessor_authoritative_artifacts": False,
    "all_downstream_gates_restart": True,
}

_SUCCESSOR_READINESS_GATES = (
    "successor-authority-and-cohort-admission",
    "successor-authoritative-fitting-2000-of-2000",
    "successor-final-qualification-600-of-600",
    "successor-first-launch-certification-900-of-900",
)


@dataclass(frozen=True)
class SuccessorSelection:
    """A deterministic 100/20 successor partition over one frozen pilot."""

    pilot: tuple[ClassCandidate, ...]
    final: tuple[ClassCandidate, ...]
    reserves: tuple[ClassCandidate, ...]
    matching: tuple[tuple[str, str], ...]
    failed_class_ids: tuple[str, ...]
    retained_predecessor_ids: tuple[str, ...]
    replaced_predecessor_ids: tuple[str, ...]
    activated_reserve_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "pilot": [candidate.candidate_id for candidate in self.pilot],
            "final": [candidate.candidate_id for candidate in self.final],
            "reserves": [candidate.candidate_id for candidate in self.reserves],
            "matching": [list(pair) for pair in self.matching],
            "failed_class_ids": list(self.failed_class_ids),
            "retained_predecessor_ids": list(self.retained_predecessor_ids),
            "replaced_predecessor_ids": list(self.replaced_predecessor_ids),
            "activated_reserve_ids": list(self.activated_reserve_ids),
            "counts": {
                "pilot": len(self.pilot),
                "final": len(self.final),
                "reserves": len(self.reserves),
                "matching_edges": len(self.matching),
                "retained_predecessor": len(self.retained_predecessor_ids),
                "replaced_predecessor": len(self.replaced_predecessor_ids),
                "activated_reserves": len(self.activated_reserve_ids),
            },
            "final_per_stratum": {
                stratum.id: sum(candidate.stratum == stratum for candidate in self.final)
                for stratum in TRANCO_RANK_STRATA
            },
        }


def create_successor_policy(destination: Path) -> Path:
    """Create the immutable, outcome-independent successor policy exactly once."""

    receipt = bind_receipt(_policy_payload(), receipt_type=POLICY_RECEIPT_TYPE)
    output = write_create_only_json(destination, receipt)
    validate_successor_policy(output)
    return output.resolve()


def validate_successor_policy(path: Path) -> dict[str, Any]:
    """Validate a successor policy and return its detached payload."""

    value = _load_json_object(path, "successor policy")
    payload = validate_hash_bound_receipt(value, expected_type=POLICY_RECEIPT_TYPE)
    if payload != _policy_payload():
        raise ValueError("class-study successor policy differs from schema one")
    return payload


def create_successor_decision(
    destination: Path,
    *,
    policy_receipt: Path,
    certification_result_root: Path,
    predecessor_cohort_receipt: Path,
    predecessor_cohort_assembly: Path,
    predecessor_final_selection: Path,
    predecessor_foundation_attestation: Path,
) -> Path:
    """Create one successor decision without mutating predecessor evidence."""

    protected = (
        _regular_file(policy_receipt, "successor policy"),
        _regular_directory(certification_result_root, "certification result"),
        _regular_file(predecessor_cohort_receipt, "predecessor cohort"),
        _regular_file(predecessor_cohort_assembly, "predecessor cohort assembly"),
        _regular_file(predecessor_final_selection, "predecessor final selection"),
        _regular_file(predecessor_foundation_attestation, "predecessor foundation"),
    )
    output_path = require_disjoint_path(
        destination,
        protected,
        label="class-study successor decision destination",
    )
    payload = _decision_payload(
        policy_receipt=protected[0],
        certification_result_root=protected[1],
        predecessor_cohort_receipt=protected[2],
        predecessor_cohort_assembly=protected[3],
        predecessor_final_selection=protected[4],
        predecessor_foundation_attestation=protected[5],
        deep_foundation=True,
    )
    output = write_create_only_json(
        output_path,
        bind_receipt(payload, receipt_type=DECISION_RECEIPT_TYPE),
    )
    validate_successor_decision(output, deep_foundation=False)
    return output.resolve()


def validate_successor_decision(
    path: Path,
    *,
    deep_foundation: bool = True,
) -> dict[str, Any]:
    """Reconstruct a successor decision from every path and evidence seal."""

    value = _load_json_object(path, "successor decision")
    payload = validate_hash_bound_receipt(value, expected_type=DECISION_RECEIPT_TYPE)
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "policy",
        "certification_result",
        "predecessor_cohort",
        "predecessor_cohort_assembly",
        "predecessor_final_selection",
        "predecessor_foundation",
    }:
        raise ValueError("class-study successor decision evidence is incomplete")
    expected = _decision_payload(
        policy_receipt=_path_from_file_binding(evidence["policy"], "successor policy"),
        certification_result_root=_path_from_result_binding(
            evidence["certification_result"], "certification result"
        ),
        predecessor_cohort_receipt=_path_from_file_binding(
            evidence["predecessor_cohort"], "predecessor cohort"
        ),
        predecessor_cohort_assembly=_path_from_file_binding(
            evidence["predecessor_cohort_assembly"],
            "predecessor cohort assembly",
        ),
        predecessor_final_selection=_path_from_file_binding(
            evidence["predecessor_final_selection"],
            "predecessor final selection",
        ),
        predecessor_foundation_attestation=_path_from_file_binding(
            evidence["predecessor_foundation"], "predecessor foundation"
        ),
        deep_foundation=deep_foundation,
    )
    if canonical_json_bytes(payload) != canonical_json_bytes(expected):
        raise ValueError("class-study successor decision differs from reconstructed evidence")
    return payload


def create_successor_restart(
    destination: Path,
    *,
    decision_receipt: Path,
) -> Path:
    """Publish the immutable successor restart plan and all 22 campaigns.

    The plan is intentionally not a readiness attestation.  It creates a
    distinct successor namespace and requires fresh 2,000/600/900 evidence;
    no predecessor fitting, qualification, or certification output is an
    admissible successor gate.
    """

    decision_path = _regular_file(decision_receipt, "successor decision")
    decision = validate_successor_decision(decision_path)
    successor = decision["successor"]
    study_id = successor["study_id"]
    root = Path(os.path.abspath(destination))
    if root.name != study_id:
        raise ValueError(f"successor restart root must use its hash-derived study ID: {study_id}")
    protected = [decision_path]
    evidence = decision["evidence"]
    for label, binding in evidence.items():
        if label == "certification_result":
            protected.append(_path_from_result_binding(binding, "predecessor certification result"))
        else:
            protected.append(_path_from_file_binding(binding, f"predecessor {label}"))
    require_disjoint_path(
        root,
        tuple(protected),
        label="class-study successor restart root",
    )
    parent = _regular_directory(root.parent, "successor restart parent")
    if root.exists() or root.is_symlink():
        if root.is_symlink() or not root.is_dir():
            raise ValueError("successor restart root must be a regular directory")
    else:
        root.mkdir(mode=0o755)
        _fsync_directory(parent)
    plan_root = root / "plan"
    campaigns_root = plan_root / "campaigns"
    runtime_directories = (
        root / "artifacts",
        root / "qualification",
        root / "qualification/work",
        root / "attestations",
    )
    for directory in (plan_root, campaigns_root, *runtime_directories):
        if directory.exists() or directory.is_symlink():
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("successor restart plan path must be a regular directory")
        else:
            directory.mkdir(mode=0o755)
            _fsync_directory(directory.parent)
    receipt_path = plan_root / "successor-restart.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        raise FileExistsError(f"create-only successor restart already exists: {receipt_path}")

    files = _successor_restart_files(decision, restart_root=root)
    for relative, encoded in files.items():
        _create_or_verify_bytes(plan_root / relative, encoded, label=relative)
    payload = _successor_restart_payload(
        decision_path,
        decision,
        restart_root=root,
        files=files,
    )
    output = write_create_only_json(
        receipt_path,
        bind_receipt(payload, receipt_type=RESTART_RECEIPT_TYPE),
    )
    validate_successor_restart(output, deep_decision=False)
    return output.resolve()


def validate_successor_restart(
    path: Path,
    *,
    deep_decision: bool = True,
) -> dict[str, Any]:
    """Deeply reconstruct one successor restart plan and every immutable file."""

    source = _regular_file(path, "successor restart receipt")
    value = _load_json_object(source, "successor restart receipt")
    payload = validate_hash_bound_receipt(value, expected_type=RESTART_RECEIPT_TYPE)
    decision_binding = payload.get("successor_decision")
    decision_path = _path_from_file_binding(decision_binding, "successor decision")
    decision = validate_successor_decision(
        decision_path,
        deep_foundation=deep_decision,
    )
    restart_root = source.parent.parent
    if restart_root.name != decision["successor"]["study_id"]:
        raise ValueError("successor restart root differs from its hash-derived identity")
    files = _successor_restart_files(decision, restart_root=restart_root)
    plan_root = restart_root / "plan"
    _require_exact_restart_inventory(plan_root, files)
    for relative, expected_bytes in files.items():
        artifact = _regular_file(plan_root / relative, f"successor restart {relative}")
        if artifact.read_bytes() != expected_bytes:
            raise ValueError(f"successor restart artifact changed: {relative}")
    expected = _successor_restart_payload(
        decision_path,
        decision,
        restart_root=restart_root,
        files=files,
    )
    if canonical_json_bytes(payload) != canonical_json_bytes(expected):
        raise ValueError("successor restart receipt differs from reconstructed evidence")
    return payload


def create_successor_readiness(
    destination: Path,
    *,
    restart_receipt: Path,
    foundation_attestation: Path,
    authoritative_fitting_result_root: Path,
    authoritative_fitting_bundle_root: Path,
    qualification_workload_root: Path,
    qualification_sidecar_root: Path,
    qualification_prefix_root: Path,
    certification_result_root: Path,
) -> Path:
    """Create formal authority only after fresh successor 2,000/600/900 gates."""

    protected = (
        restart_receipt,
        foundation_attestation,
        authoritative_fitting_result_root,
        authoritative_fitting_bundle_root,
        qualification_workload_root,
        qualification_sidecar_root,
        qualification_prefix_root,
        certification_result_root,
    )
    output = require_disjoint_path(
        destination,
        tuple(Path(path) for path in protected),
        label="successor readiness destination",
    )
    payload = _successor_readiness_value(
        restart_receipt=restart_receipt,
        foundation_attestation=foundation_attestation,
        authoritative_fitting_result_root=authoritative_fitting_result_root,
        authoritative_fitting_bundle_root=authoritative_fitting_bundle_root,
        qualification_workload_root=qualification_workload_root,
        qualification_sidecar_root=qualification_sidecar_root,
        qualification_prefix_root=qualification_prefix_root,
        certification_result_root=certification_result_root,
        deep_code_gate=True,
    )
    receipt = write_create_only_json(
        output,
        bind_receipt(payload, receipt_type=READINESS_RECEIPT_TYPE),
    )
    validate_successor_readiness(receipt, deep_code_gate=False)
    return receipt.resolve()


def validate_successor_readiness(
    path: Path,
    *,
    deep_code_gate: bool = True,
) -> dict[str, Any]:
    """Reconstruct one successor readiness receipt from all live evidence."""

    source = _regular_file(path, "successor readiness")
    value = _load_json_object(source, "successor readiness")
    payload = validate_hash_bound_receipt(
        value, expected_type=READINESS_RECEIPT_TYPE
    )
    if not str(payload.get("study_id", "")).startswith(
        f"{SUCCESSOR_STUDY_PREFIX}-"
    ):
        raise ValueError("successor readiness has the wrong study identity")
    evidence = payload.get("evidence")
    qualification = (
        evidence.get("qualification_context")
        if isinstance(evidence, Mapping)
        else None
    )
    if not isinstance(evidence, Mapping) or not isinstance(
        qualification, Mapping
    ):
        raise ValueError("successor readiness evidence is incomplete")
    expected = _successor_readiness_value(
        restart_receipt=_path_from_file_binding(
            evidence.get("successor_restart"), "successor restart"
        ),
        foundation_attestation=_path_from_file_binding(
            evidence.get("foundation"), "successor foundation"
        ),
        authoritative_fitting_result_root=_path_from_result_binding(
            evidence.get("authoritative_fitting_result"),
            "successor authoritative fitting",
        ),
        authoritative_fitting_bundle_root=_root_from_bundle_binding(
            evidence.get("authoritative_fitting_bundle"),
            "successor authoritative bundle",
        ),
        qualification_workload_root=_root_from_directory_binding(
            qualification.get("workload_root"), "successor workload root"
        ),
        qualification_sidecar_root=_root_from_directory_binding(
            qualification.get("sidecar_root"), "successor qualification root"
        ),
        qualification_prefix_root=_root_from_directory_binding(
            qualification.get("prefix_spec_root"), "successor prefix root"
        ),
        certification_result_root=_path_from_result_binding(
            evidence.get("certification_result"), "successor certification"
        ),
        deep_code_gate=deep_code_gate,
    )
    if canonical_json_bytes(payload) != canonical_json_bytes(expected):
        raise ValueError("successor readiness differs from reconstructed evidence")
    return {
        "path": str(source),
        "sha256": sha256_file(source),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def _successor_readiness_value(
    *,
    restart_receipt: Path,
    foundation_attestation: Path,
    authoritative_fitting_result_root: Path,
    authoritative_fitting_bundle_root: Path,
    qualification_workload_root: Path,
    qualification_sidecar_root: Path,
    qualification_prefix_root: Path,
    certification_result_root: Path,
    deep_code_gate: bool,
) -> dict[str, Any]:
    from .class_attestation import (
        _class_result_binding,
        _directory_binding,
        _fitting_bundle_binding,
        _hard_gate_records,
        _one_build_execution_identity,
        _validate_result_environment,
        class_qualification_authority,
        validate_class_foundation_attestation,
    )
    from .class_fitting import (
        PROVENANCE_FILE,
        AUTHORITATIVE_STAGE,
        QualificationContext,
        verify_class_fitting_bundle,
    )
    from .class_pipeline import (
        verify_class_study_result,
        verify_successor_cohort_admission,
    )
    from .class_study import COMPATIBILITY_MODES, FINAL_CLASS_COUNT
    from .util import source_metadata

    if type(deep_code_gate) is not bool:
        raise ValueError("successor readiness deep-code flag must be boolean")
    restart_path = _regular_file(restart_receipt, "successor restart")
    restart = validate_successor_restart(restart_path)
    study_id = str(restart["study_id"])
    foundation_path = _regular_file(
        foundation_attestation, "successor foundation"
    )
    foundation = validate_class_foundation_attestation(
        foundation_path,
        deep_code_gate=deep_code_gate,
        runtime_role="collection",
    )
    current_source = source_metadata()
    if (
        foundation.get("source") != current_source
        or sha256_file(foundation_path)
        != restart.get("predecessor_foundation_sha256")
        or canonical_json_sha256(current_source) != restart.get("source_sha256")
        or canonical_json_sha256(foundation.get("build_execution_identity"))
        != restart.get("build_execution_identity_sha256")
    ):
        raise ValueError("successor readiness source/build/foundation differs")

    admission = verify_successor_cohort_admission(restart_path)
    fitting_result = verify_class_study_result(
        authoritative_fitting_result_root,
        admission=admission,
        expected_role="authoritative-fitting",
    )
    certification = verify_class_study_result(
        certification_result_root,
        admission=admission,
        expected_role="certification",
    )
    restart_sha256 = sha256_file(restart_path)
    for label, record, count in (
        ("authoritative fitting", fitting_result, 2_000),
        ("certification", certification, 900),
    ):
        if (
            record.get("class_study_id") != study_id
            or record.get("class_study_successor_sha256") != restart_sha256
            or record.get("class_study_foundation_sha256")
            != sha256_file(foundation_path)
            or record.get("samples") != count
            or record.get("accepted") != count
        ):
            raise ValueError(f"successor {label} is not fresh complete evidence")
    if certification.get("first_launch_unique_class_mode_pairs") != 900:
        raise ValueError("successor certification is not exact first-launch evidence")

    qualification_authority = class_qualification_authority(
        foundation_path,
        deep_code_gate=deep_code_gate,
        runtime_role="collection",
    )
    qualification_context = QualificationContext(
        workload_root=_regular_directory(
            qualification_workload_root, "successor workload root"
        ),
        sidecar_root=_regular_directory(
            qualification_sidecar_root, "successor qualification root"
        ),
        prefix_spec_root=_regular_directory(
            qualification_prefix_root, "successor prefix root"
        ),
        qualification_authority=qualification_authority,
        expected_qualification_set=f"{study_id}-final-full",
    )
    fitting = verify_class_fitting_bundle(
        authoritative_fitting_bundle_root,
        qualification_context=qualification_context,
        source_result_root=authoritative_fitting_result_root,
    )
    bindings = fitting.provenance.get("qualification_inputs", {}).get(
        "qualification_bindings"
    )
    if (
        fitting.stage != AUTHORITATIVE_STAGE
        or fitting.provenance.get("runtime_authorized") is not True
        or fitting.provenance.get("cohort", {}).get("receipt_sha256")
        != admission.cohort_sha256
        or fitting.provenance.get("cohort", {}).get("assembly_receipt_sha256")
        != admission.assembly_sha256
        or not isinstance(bindings, list)
        or len(bindings) != FINAL_CLASS_COUNT
    ):
        raise ValueError("successor fitting/qualification evidence is incomplete")
    fitted_parameters = {
        "traffic-morphing": fitting.artifact_hashes["traffic_morphing"],
        "wtf-pad": fitting.artifact_hashes["wtf_pad"],
        "walkie-talkie": fitting.artifact_hashes["walkie_talkie"],
    }
    certification_parameters = certification.get("defense_parameter_sha256")
    if (
        not isinstance(certification_parameters, Mapping)
        or any(
            certification_parameters.get(mode) != digest
            for mode, digest in fitted_parameters.items()
        )
    ):
        raise ValueError("successor certification used different fitted parameters")
    runtime_inputs = certification.get("defense_runtime_inputs")
    if not isinstance(runtime_inputs, Mapping) or set(runtime_inputs) != set(
        COMPATIBILITY_MODES
    ):
        raise ValueError("successor certification runtime identity is incomplete")
    qualification_inputs = fitting.provenance["qualification_inputs"]
    manifest_sha256 = qualification_inputs.get("qualification_manifest_sha256")
    if (
        not isinstance(manifest_sha256, str)
        or _DIGEST.fullmatch(manifest_sha256) is None
        or certification.get("chaff_qualification_set_manifest_sha256")
        != manifest_sha256
    ):
        raise ValueError("successor certification used another qualification set")

    verified_results = tuple(
        verify_result(Path(path))
        for path in (
            authoritative_fitting_result_root,
            certification_result_root,
        )
    )
    environments = []
    for verified in verified_results:
        if verified.experiment.get("source") != current_source:
            raise ValueError("successor result uses a different source")
        environments.append(_validate_result_environment(verified, current_source))
    if _one_build_execution_identity(environments) != foundation.get(
        "build_execution_identity"
    ):
        raise ValueError("successor results use a different no-cache build")

    evidence = {
        "successor_restart": _file_binding(restart_path),
        "foundation": _file_binding(foundation_path),
        "final_selection": _file_binding(
            restart_path.parent / "successor-final-selection.json"
        ),
        "final_cohort": _file_binding(admission.cohort_path),
        "final_cohort_assembly": _file_binding(admission.assembly_path),
        "authoritative_fitting_result": _class_result_binding(
            authoritative_fitting_result_root
        ),
        "authoritative_fitting_bundle": _fitting_bundle_binding(
            fitting.root,
            provenance_name=PROVENANCE_FILE,
            artifact_hashes=fitting.artifact_hashes,
        ),
        "qualification_context": {
            "workload_root": _directory_binding(qualification_context.workload_root),
            "sidecar_root": _directory_binding(qualification_context.sidecar_root),
            "prefix_spec_root": _directory_binding(
                qualification_context.prefix_spec_root
            ),
            "qualification_authority": qualification_authority,
        },
        "certification_result": _class_result_binding(certification_result_root),
    }
    gate_evidence = {
        "successor-authority-and-cohort-admission": [
            evidence["successor_restart"]["sha256"],
            evidence["foundation"]["sha256"],
            evidence["final_cohort"]["sha256"],
            evidence["final_cohort_assembly"]["sha256"],
        ],
        "successor-authoritative-fitting-2000-of-2000": [
            evidence["authoritative_fitting_result"]["evidence_sha256"]
        ],
        "successor-final-qualification-600-of-600": [
            manifest_sha256,
            qualification_inputs["qualification_bindings_sha256"],
        ],
        "successor-first-launch-certification-900-of-900": [
            evidence["certification_result"]["evidence_sha256"]
        ],
    }
    return {
        "attestation_schema_version": SCHEMA_VERSION,
        "artifact_type": READINESS_RECEIPT_TYPE,
        "study_id": study_id,
        "cohort_version": foundation["cohort_version"],
        "implementation_status": "candidate-ready-for-formal-capture",
        "promotion_authority": False,
        "implementation_scope": "client_only_quic",
        "paper_equivalent": False,
        "no_waivers": True,
        "source": current_source,
        "build_execution_identity": foundation["build_execution_identity"],
        "evidence": evidence,
        "summary": {
            "final_classes": FINAL_CLASS_COUNT,
            "reserve_classes": 20,
            "authoritative_fitting_samples": 2_000,
            "final_qualification_executions": 600,
            "certification_samples": 900,
            "certification_unique_first_launch_pairs": 900,
            "fitted_parameter_sha256": fitted_parameters,
            "certification_defense_parameter_sha256": dict(
                certification_parameters
            ),
            "certification_defense_runtime_inputs": dict(runtime_inputs),
            "final_qualification_set_manifest_sha256": manifest_sha256,
            "predecessor_downstream_evidence_reused": False,
        },
        "hard_gates": _hard_gate_records(
            _SUCCESSOR_READINESS_GATES, gate_evidence
        ),
        "all_readiness_gates_passed": True,
    }


def _require_exact_restart_inventory(
    plan_root: Path,
    files: Mapping[str, bytes],
) -> None:
    """Reject unreceipted plan files instead of silently ignoring them."""

    root = _regular_directory(plan_root, "successor restart plan")
    expected_top = {
        "successor-restart.json",
        *(Path(relative).parts[0] for relative in files),
    }
    observed_top = {entry.name for entry in root.iterdir()}
    if observed_top != expected_top:
        raise ValueError("successor restart plan contains unexpected or missing entries")
    campaigns = _regular_directory(root / "campaigns", "successor campaign plan")
    expected_campaigns = {
        Path(relative).name for relative in files if relative.startswith("campaigns/")
    }
    observed_campaigns = {entry.name for entry in campaigns.iterdir()}
    if observed_campaigns != expected_campaigns:
        raise ValueError("successor restart campaigns contain unexpected or missing entries")


def select_successor_cohort(
    predecessor: CohortSelection,
    failed_class_ids: Iterable[str],
) -> SuccessorSelection:
    """Select a maximum-retention successor from the frozen qualified graph.

    The 60 graph edges must be a one-to-one matching over the exact frozen
    120-class pilot.  Selection omits ten whole edges, including every edge
    containing a failed class, while omitting exactly four endpoints per rank
    stratum.  It first minimises the number of predecessor-final classes
    omitted, then uses frozen pilot order as the sole tie-breaker.
    """

    pilot = tuple(predecessor.pilot)
    previous_final = tuple(predecessor.final)
    previous_reserves = tuple(predecessor.reserves)
    if (
        len(pilot) != PILOT_COUNT
        or len(previous_final) != FINAL_CLASS_COUNT
        or len(previous_reserves) != RESERVE_COUNT
    ):
        raise ValueError("successor selection requires the frozen 120/100/20 predecessor")
    pilot_ids = tuple(candidate.candidate_id for candidate in pilot)
    if len(set(pilot_ids)) != PILOT_COUNT:
        raise ValueError("successor pilot contains duplicate class identities")
    order = {candidate_id: index for index, candidate_id in enumerate(pilot_ids)}
    previous_final_ids = {candidate.candidate_id for candidate in previous_final}
    previous_reserve_ids = {candidate.candidate_id for candidate in previous_reserves}
    if (
        previous_final_ids & previous_reserve_ids
        or previous_final_ids | previous_reserve_ids != set(pilot_ids)
    ):
        raise ValueError("successor predecessor final/reserve partition is invalid")
    _require_stratum_counts(pilot, PILOT_CLASSES_PER_STRATUM, label="pilot")
    _require_stratum_counts(previous_final, FINAL_CLASSES_PER_STRATUM, label="predecessor final")

    graph = _normalised_qualified_graph(predecessor.feasible_pairs, order)
    previous_matching = _normalised_matching(predecessor.matching, order)
    if len(previous_matching) != FINAL_CLASS_COUNT // 2:
        raise ValueError("successor predecessor matching must contain exactly 50 edges")
    if any(pair not in set(graph) for pair in previous_matching):
        raise ValueError("successor predecessor matching uses an unqualified edge")
    matched = {candidate_id for pair in previous_matching for candidate_id in pair}
    if matched != previous_final_ids:
        raise ValueError("successor predecessor matching does not cover its final cohort")

    failed_set = set(failed_class_ids)
    if not failed_set or any(
        not isinstance(candidate_id, str) or candidate_id not in previous_final_ids
        for candidate_id in failed_set
    ):
        raise ValueError("successor failures must identify predecessor-final classes")
    failed = tuple(candidate_id for candidate_id in pilot_ids if candidate_id in failed_set)

    edge_by_candidate = {
        candidate_id: edge_index for edge_index, pair in enumerate(graph) for candidate_id in pair
    }
    forced_edges = frozenset(edge_by_candidate[candidate_id] for candidate_id in failed)
    target_omitted_by_stratum = tuple(
        PILOT_CLASSES_PER_STRATUM - FINAL_CLASSES_PER_STRATUM for _stratum in TRANCO_RANK_STRATA
    )
    stratum_index = {stratum.id: index for index, stratum in enumerate(TRANCO_RANK_STRATA)}
    candidate_by_id = {candidate.candidate_id: candidate for candidate in pilot}

    def contribution(edge_index: int) -> tuple[int, ...]:
        counts = [0] * len(TRANCO_RANK_STRATA)
        for candidate_id in graph[edge_index]:
            counts[stratum_index[candidate_by_id[candidate_id].stratum.id]] += 1
        return tuple(counts)

    contributions = tuple(contribution(index) for index in range(len(graph)))
    forced_counts = tuple(
        sum(contributions[edge_index][position] for edge_index in forced_edges)
        for position in range(len(TRANCO_RANK_STRATA))
    )
    if len(forced_edges) > RESERVE_COUNT // 2 or any(
        observed > target
        for observed, target in zip(forced_counts, target_omitted_by_stratum, strict=True)
    ):
        raise ValueError("failed classes leave no quota-feasible qualified successor")

    states: dict[tuple[int, tuple[int, ...]], tuple[int, ...]] = {
        (len(forced_edges), forced_counts): tuple(sorted(forced_edges))
    }
    for edge_index in range(len(graph)):
        if edge_index in forced_edges:
            continue
        edge_counts = contributions[edge_index]
        updated = dict(states)
        for (omitted_count, counts), omitted in states.items():
            if omitted_count >= RESERVE_COUNT // 2:
                continue
            next_counts = tuple(
                counts[position] + edge_counts[position]
                for position in range(len(TRANCO_RANK_STRATA))
            )
            if any(
                observed > target
                for observed, target in zip(next_counts, target_omitted_by_stratum, strict=True)
            ):
                continue
            key = (omitted_count + 1, next_counts)
            candidate = (*omitted, edge_index)
            incumbent = updated.get(key)
            if incumbent is None or _prefer_omitted_edges(
                candidate,
                incumbent,
                graph=graph,
                order=order,
                previous_final_ids=previous_final_ids,
            ):
                updated[key] = candidate
        states = updated

    omitted_key = (RESERVE_COUNT // 2, target_omitted_by_stratum)
    omitted_edges = states.get(omitted_key)
    if omitted_edges is None:
        raise ValueError("failed classes leave no quota-feasible qualified successor")
    omitted_set = set(omitted_edges)
    matching = tuple(pair for index, pair in enumerate(graph) if index not in omitted_set)
    final_ids = {candidate_id for pair in matching for candidate_id in pair}
    final = tuple(candidate for candidate in pilot if candidate.candidate_id in final_ids)
    reserves = tuple(candidate for candidate in pilot if candidate.candidate_id not in final_ids)
    if failed_set & final_ids:
        raise AssertionError("successor selection retained a failed class")
    if len(matching) != FINAL_CLASS_COUNT // 2 or len(final) != FINAL_CLASS_COUNT:
        raise AssertionError("successor selection produced the wrong final cardinality")
    _require_stratum_counts(final, FINAL_CLASSES_PER_STRATUM, label="successor final")

    retained = tuple(
        candidate.candidate_id
        for candidate in final
        if candidate.candidate_id in previous_final_ids
    )
    replaced = tuple(
        candidate.candidate_id
        for candidate in previous_final
        if candidate.candidate_id not in final_ids
    )
    activated = tuple(
        candidate.candidate_id
        for candidate in final
        if candidate.candidate_id in previous_reserve_ids
    )
    if len(replaced) != len(activated):
        raise AssertionError("successor replacement accounting is unbalanced")
    return SuccessorSelection(
        pilot=pilot,
        final=final,
        reserves=reserves,
        matching=matching,
        failed_class_ids=failed,
        retained_predecessor_ids=retained,
        replaced_predecessor_ids=replaced,
        activated_reserve_ids=activated,
    )


def _successor_restart_files(
    decision: Mapping[str, Any],
    *,
    restart_root: Path,
) -> dict[str, bytes]:
    successor = decision.get("successor")
    selection = decision.get("successor_selection")
    predecessor = decision.get("predecessor")
    if (
        not isinstance(successor, Mapping)
        or not isinstance(selection, Mapping)
        or not isinstance(predecessor, Mapping)
    ):
        raise TypeError("successor decision lacks restart authority")
    study_id = successor.get("study_id")
    identity_sha256 = successor.get("identity_sha256")
    launch_namespace = successor.get("launch_namespace")
    final_ids = selection.get("final")
    reserve_ids = selection.get("reserves")
    matching = selection.get("matching")
    if (
        not isinstance(study_id, str)
        or not isinstance(identity_sha256, str)
        or _DIGEST.fullmatch(identity_sha256) is None
        or not isinstance(launch_namespace, str)
        or not isinstance(final_ids, list)
        or len(final_ids) != FINAL_CLASS_COUNT
        or len(set(final_ids)) != FINAL_CLASS_COUNT
        or not all(isinstance(item, str) and item for item in final_ids)
        or not isinstance(reserve_ids, list)
        or len(reserve_ids) != RESERVE_COUNT
        or not isinstance(matching, list)
        or len(matching) != FINAL_CLASS_COUNT // 2
    ):
        raise ValueError("successor restart selection is malformed")
    decision_sha256 = canonical_json_sha256(decision)
    compatible_cohort, compatible_assembly, successor_final_selection = (
        _successor_compatible_cohort_files(decision)
    )
    cohort = bind_receipt(
        {
            "successor_cohort_schema_version": SCHEMA_VERSION,
            "study_id": study_id,
            "predecessor_study_id": STUDY_ID,
            "decision_payload_sha256": decision_sha256,
            "identity_sha256": identity_sha256,
            "source_sha256": predecessor["source_sha256"],
            "build_execution_identity_sha256": predecessor["build_execution_identity_sha256"],
            "selection": {
                "pilot": list(selection["pilot"]),
                "final": list(final_ids),
                "reserves": list(reserve_ids),
                "matching": list(matching),
                "failed_class_ids": list(selection["failed_class_ids"]),
                "retained_predecessor_ids": list(selection["retained_predecessor_ids"]),
                "replaced_predecessor_ids": list(selection["replaced_predecessor_ids"]),
                "activated_reserve_ids": list(selection["activated_reserve_ids"]),
                "final_per_stratum": dict(selection["final_per_stratum"]),
            },
            "predecessor_downstream_artifact_reuse_permitted": False,
            "runtime_compatibility_cohort": {
                "path": "successor-compatible-cohort.json",
                "sha256": hashlib.sha256(
                    canonical_json_bytes(compatible_cohort)
                ).hexdigest(),
            },
            "runtime_compatibility_cohort_assembly": {
                "path": "successor-compatible-cohort-assembly.json",
                "sha256": hashlib.sha256(
                    canonical_json_bytes(compatible_assembly)
                ).hexdigest(),
            },
            "successor_final_selection": {
                "path": "successor-final-selection.json",
                "sha256": hashlib.sha256(
                    canonical_json_bytes(successor_final_selection)
                ).hexdigest(),
            },
        },
        receipt_type=SUCCESSOR_COHORT_RECEIPT_TYPE,
    )
    qualification_set = f"{study_id}-final-full"
    qualification_plan = bind_receipt(
        {
            "qualification_plan_schema_version": SCHEMA_VERSION,
            "study_id": study_id,
            "decision_payload_sha256": decision_sha256,
            "qualification_set": qualification_set,
            "workload_ids": list(final_ids),
            "workload_count": FINAL_CLASS_COUNT,
            "per_workload": {
                "response_identity_runs": 3,
                "prefix_pack_runs": 3,
                "total_executions": 6,
            },
            "total_executions": 600,
            "inputs": {
                "numeric_bundle": (
                    f"artifacts/{STUDY_ID}-authoritative-fitting-numeric"
                ),
                "prefix_spec_root": (
                    f"artifacts/{STUDY_ID}-authoritative-fitting-prefix-specs"
                ),
                "workload_source": "canonical-prepared-workloads-bound-by-successor-cohort",
            },
            "outputs": {
                "qualification_root": f"qualification/{qualification_set}",
                "qualification_manifest": (
                    f"qualification/{qualification_set}/_qualification-set.json"
                ),
                "final_bundle": f"artifacts/{STUDY_ID}-authoritative-fitting",
            },
            "predecessor_qualification_reuse_permitted": False,
            "completion_authority": (
                "all-100-workloads-with-three-response-and-three-prefix-runs-"
                "deeply-verified-under-successor-source-build-and-decision"
            ),
        },
        receipt_type=QUALIFICATION_PLAN_RECEIPT_TYPE,
    )
    campaigns = _successor_campaign_documents(
        study_id=study_id,
        workload_ids=tuple(final_ids),
        qualification_set=qualification_set,
        restart_root=restart_root,
    )
    files: dict[str, bytes] = {
        "successor-cohort.json": canonical_json_bytes(cohort),
        "successor-compatible-cohort.json": canonical_json_bytes(compatible_cohort),
        "successor-compatible-cohort-assembly.json": canonical_json_bytes(
            compatible_assembly
        ),
        "successor-final-selection.json": canonical_json_bytes(
            successor_final_selection
        ),
        "final-qualification-plan.json": canonical_json_bytes(qualification_plan),
    }
    files.update(
        {
            f"campaigns/{filename}": yaml.safe_dump(
                value,
                sort_keys=False,
                width=100,
            ).encode("utf-8")
            for filename, value in campaigns.items()
        }
    )
    return files


def _successor_compatible_cohort_files(
    decision: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Derive intrinsically valid v1-format admission from the frozen pilot.

    The envelope remains compatible with existing fitting and capture readers,
    while the surrounding restart receipt supplies the distinct successor
    identity.  Only already-qualified successor matching edges are retained,
    forcing the exact replacement selection without changing acquisition
    eligibility or any predecessor file.
    """

    evidence = decision.get("evidence")
    successor_selection = decision.get("successor_selection")
    if not isinstance(evidence, Mapping) or not isinstance(
        successor_selection, Mapping
    ):
        raise TypeError("successor decision lacks compatible cohort evidence")
    predecessor_path = _path_from_file_binding(
        evidence.get("predecessor_cohort"), "predecessor cohort"
    )
    predecessor_value, predecessor = load_study_receipt(predecessor_path)
    predecessor_payload = predecessor_value["payload"]
    matching = successor_selection.get("matching")
    if not isinstance(matching, list):
        raise TypeError("successor decision matching is malformed")
    compatible = build_study_receipt(
        predecessor.candidates,
        tranco_list_id=predecessor_payload["tranco"]["list_id"],
        tranco_list_sha256=predecessor_payload["tranco"]["list_sha256"],
        feasible_pairs=matching,
    )
    selection = validate_study_receipt(compatible)
    if [candidate.candidate_id for candidate in selection.final] != list(
        successor_selection["final"]
    ) or [list(pair) for pair in selection.matching or ()] != matching:
        raise ValueError(
            "successor matching cannot be represented by the runtime cohort contract"
        )

    predecessor_assembly_path = _path_from_file_binding(
        evidence.get("predecessor_cohort_assembly"),
        "predecessor cohort assembly",
    )
    predecessor_assembly_value = _load_json_object(
        predecessor_assembly_path, "predecessor cohort assembly"
    )
    predecessor_assembly = validate_cohort_assembly_receipt(
        predecessor_assembly_value,
        cohort=predecessor_value,
    )
    prior_selection = predecessor_assembly.get("final_selection")
    prior_payload = (
        prior_selection.get("payload")
        if isinstance(prior_selection, Mapping)
        else None
    )
    if not isinstance(prior_payload, Mapping):
        raise TypeError("predecessor cohort has no final-selection lineage")
    final_payload = dict(prior_payload)
    final_payload.update(
        selection_policy="sealed-class-incompatibility-successor-v1",
        feasible_pair_rule={
            "source": "qualified-predecessor-60-edge-graph",
            "selection": "decision-bound-successor-50-edge-matching",
            "failed_classes_excluded": True,
            "decision_payload_sha256": canonical_json_sha256(decision),
        },
        feasible_pair_graph=[list(pair) for pair in selection.feasible_pairs or ()],
    )
    successor_final_selection = bind_receipt(
        final_payload,
        receipt_type=FINAL_SELECTION_RECEIPT_TYPE,
    )
    assembly_payload = dict(predecessor_assembly)
    assembly_payload["final_selection"] = {
        "path": "successor-final-selection.json",
        "sha256": hashlib.sha256(
            canonical_json_bytes(successor_final_selection)
        ).hexdigest(),
        "payload_sha256": successor_final_selection["payload_sha256"],
        "payload": final_payload,
    }
    assembly_payload["cohort"] = {
        "receipt_type": compatible["receipt_type"],
        "payload_sha256": compatible["payload_sha256"],
        "canonical_file_sha256": hashlib.sha256(
            canonical_json_bytes(compatible)
        ).hexdigest(),
    }
    compatible_assembly = bind_receipt(
        assembly_payload,
        receipt_type="qcsd-class-study-cohort-assembly",
    )
    validate_cohort_assembly_receipt(compatible_assembly, cohort=compatible)
    return compatible, compatible_assembly, successor_final_selection


def _successor_campaign_documents(
    *,
    study_id: str,
    workload_ids: tuple[str, ...],
    qualification_set: str,
    restart_root: Path,
) -> dict[str, dict[str, Any]]:
    if len(workload_ids) != FINAL_CLASS_COUNT or len(set(workload_ids)) != FINAL_CLASS_COUNT:
        raise ValueError("successor campaigns require exactly 100 unique classes")
    campaign_root = restart_root / "plan/campaigns"

    def reference(path: Path) -> str:
        return os.path.relpath(path, campaign_root)

    cohort_reference = "../successor-compatible-cohort.json"
    assembly_reference = "../successor-compatible-cohort-assembly.json"
    restart_reference = "../successor-restart.json"
    bundle_reference = reference(
        restart_root / "artifacts" / f"{STUDY_ID}-authoritative-fitting"
    )
    static_reference = reference(
        Path(__file__).resolve().parents[2] / "config/defense-params/static-control-1200.csv"
    )
    buflo_reference = reference(
        Path(__file__).resolve().parents[2] / "config/defense-params/buflo-live.json"
    )
    cs_buflo_reference = reference(
        Path(__file__).resolve().parents[2] / "config/defense-params/cs-buflo-ctsp-live.json"
    )
    fitting_name = f"{study_id}-authoritative-fitting-2000-1200"
    certification_name = f"{study_id}-certification-900-1200"

    def common(name: str, role: str) -> dict[str, Any]:
        return {
            "schema": 2,
            "name": name,
            "purpose": (
                "fitting"
                if role == "authoritative-fitting"
                else "evaluation"
                if role == "formal"
                else "smoke"
            ),
            "evidence_role": role,
            "seed": int.from_bytes(
                hashlib.sha256(f"{study_id}\0{name}".encode()).digest()[:4],
                "big",
            ),
            "profile": "research-1200",
            "class_study_cohort": cohort_reference,
            "class_study_cohort_assembly": assembly_reference,
            "class_study_successor": restart_reference,
            "sample_order": {
                "scheme": "origin-aware-windowed",
                "window_size": 16,
            },
            "limits": {
                "timeout_seconds": 120,
                "max_response_bytes": 1_048_576,
                "capture_seconds": 180,
                "capture_megabytes": 64,
                "max_attempts": 1 if role == "certification" else 3,
                "per_origin_cooldown_seconds": 30,
                "settle_seconds": 1,
            },
        }

    fitting = {
        **common(fitting_name, "authoritative-fitting"),
        "workloads": {workload_id: 10 for workload_id in workload_ids},
        "request_policies": ["as-defined", "half-duplex"],
        "defenses": ["undefended"],
    }
    certification = {
        **common(certification_name, "certification"),
        "workloads": {workload_id: 1 for workload_id in workload_ids},
        "request_policies": ["as-defined"],
        "defenses": [
            "undefended",
            {
                "name": "static",
                "kind": "static",
                "schedule": static_reference,
                "mode": "chaff-only",
            },
            "front",
            "tamaraw",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": f"{bundle_reference}/traffic-morphing.json",
            },
            {
                "name": "wtf-pad",
                "kind": "wtf_pad",
                "parameters": f"{bundle_reference}/wtf-pad.json",
            },
            {
                "name": "walkie-talkie",
                "kind": "walkie_talkie",
                "parameters": f"{bundle_reference}/walkie-talkie.json",
            },
            {
                "name": "buflo",
                "kind": "buflo",
                "parameters": buflo_reference,
            },
            {
                "name": "cs-buflo",
                "kind": "cs_buflo",
                "parameters": cs_buflo_reference,
            },
        ],
        "chaff_qualification_set": qualification_set,
        "defense_order": {"scheme": "cyclic-latin-square", "block": 0},
    }
    documents = {
        f"{fitting_name}.yml": fitting,
        f"{certification_name}.yml": certification,
    }
    for block in range(1, 11):
        canary_name = f"{study_id}-canary-{block:02d}-1200"
        formal_name = f"{study_id}-formal-{block:02d}-1200"
        canary = {
            **common(canary_name, "canary"),
            "workloads": {workload_id: 1 for workload_id in workload_ids},
            "request_policies": ["as-defined"],
            "defenses": ["undefended"],
            "defense_order": {
                "scheme": "cyclic-latin-square",
                "block": block - 1,
            },
        }
        formal = {
            **common(formal_name, "formal"),
            "workloads": {workload_id: 2 for workload_id in workload_ids},
            "request_policies": ["as-defined"],
            "defenses": [
                "undefended",
                "front",
                "tamaraw",
                {
                    "name": "traffic-morphing",
                    "kind": "traffic_morphing",
                    "parameters": f"{bundle_reference}/traffic-morphing.json",
                },
                {
                    "name": "wtf-pad",
                    "kind": "wtf_pad",
                    "parameters": f"{bundle_reference}/wtf-pad.json",
                },
                {
                    "name": "walkie-talkie",
                    "kind": "walkie_talkie",
                    "parameters": f"{bundle_reference}/walkie-talkie.json",
                },
                {
                    "name": "buflo",
                    "kind": "buflo",
                    "parameters": buflo_reference,
                },
                {
                    "name": "cs-buflo",
                    "kind": "cs_buflo",
                    "parameters": cs_buflo_reference,
                },
            ],
            "chaff_qualification_set": qualification_set,
            "defense_order": {
                "scheme": "cyclic-latin-square",
                "block": block - 1,
            },
        }
        documents[f"{canary_name}.yml"] = canary
        documents[f"{formal_name}.yml"] = formal
    sample_counts = {
        role: sum(document["workloads"].values())
        * len(document["request_policies"])
        * len(document["defenses"])
        for role, document in (
            ("authoritative-fitting", fitting),
            ("certification", certification),
        )
    }
    expected_counts = {
        "authoritative-fitting": 2_000,
        "certification": 900,
        "canary": 1_000,
        "formal": 16_000,
    }
    for document in documents.values():
        role = document["evidence_role"]
        if role in {"authoritative-fitting", "certification"}:
            continue
        sample_counts[role] = sample_counts.get(role, 0) + (
            sum(document["workloads"].values())
            * len(document["request_policies"])
            * len(document["defenses"])
        )
    if sample_counts != expected_counts:
        raise AssertionError("successor restart campaign arithmetic drifted")
    return documents


def _successor_restart_payload(
    decision_path: Path,
    decision: Mapping[str, Any],
    *,
    restart_root: Path,
    files: Mapping[str, bytes],
) -> dict[str, Any]:
    successor = decision["successor"]
    study_id = successor["study_id"]
    decision_binding = _file_binding(decision_path)
    decision_binding["payload_sha256"] = canonical_json_sha256(decision)
    artifact_bindings = {
        relative: {
            "path": relative,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
        for relative, encoded in files.items()
    }
    return {
        "restart_schema_version": SCHEMA_VERSION,
        "artifact_type": RESTART_RECEIPT_TYPE,
        "study_id": study_id,
        "predecessor_study_id": STUDY_ID,
        "successor_identity_sha256": successor["identity_sha256"],
        "successor_decision": decision_binding,
        "source_sha256": decision["predecessor"]["source_sha256"],
        "build_execution_identity_sha256": decision["predecessor"][
            "build_execution_identity_sha256"
        ],
        "predecessor_foundation_sha256": decision["evidence"][
            "predecessor_foundation"
        ]["sha256"],
        "selection_sha256": canonical_json_sha256(decision["successor_selection"]),
        "namespace": {
            "restart_root_name": restart_root.name,
            "launch_namespace": successor["launch_namespace"],
            "results_root": "results",
            "authoritative_numeric_root": (
                f"artifacts/{STUDY_ID}-authoritative-fitting-numeric"
            ),
            "authoritative_prefix_root": (
                f"artifacts/{STUDY_ID}-authoritative-fitting-prefix-specs"
            ),
            "authoritative_final_root": (
                f"artifacts/{STUDY_ID}-authoritative-fitting"
            ),
            "final_qualification_root": f"qualification/{study_id}-final-full",
        },
        "immutable_plan_artifacts": artifact_bindings,
        "required_restart_gates": [
            {
                "gate": "authoritative-fitting",
                "samples": 2_000,
                "campaign": f"{study_id}-authoritative-fitting-2000-1200",
                "predecessor_result_reuse_permitted": False,
            },
            {
                "gate": "final-qualification",
                "executions": 600,
                "workloads": 100,
                "response_runs_per_workload": 3,
                "prefix_runs_per_workload": 3,
                "predecessor_result_reuse_permitted": False,
            },
            {
                "gate": "first-launch-certification",
                "cells": 900,
                "campaign": f"{study_id}-certification-900-1200",
                "max_attempts": 1,
                "predecessor_result_reuse_permitted": False,
            },
        ],
        "downstream_restart": DOWNSTREAM_RESTART,
        "readiness": {
            "authorised": False,
            "promotion_authority": False,
            "required_before_readiness": [
                "successor-authoritative-fitting-2000-of-2000",
                "successor-final-qualification-600-of-600",
                "successor-first-launch-certification-900-of-900",
            ],
            "status": "restart-plan-only-no-readiness-authority",
        },
        "predecessor_downstream_artifact_reuse_permitted": False,
    }


def _policy_payload() -> dict[str, Any]:
    return {
        "policy_schema_version": SCHEMA_VERSION,
        "predecessor_study_id": STUDY_ID,
        "successor_identity": {
            "study_id": (f"{SUCCESSOR_STUDY_PREFIX}-<first-12-hex-of-hash-bound-decision-basis>"),
            "launch_namespace": ".<successor-study-id>-launches",
            "distinct_from_predecessor_required": True,
        },
        "failure_policy": {
            "source": "sealed-incomplete-900-cell-first-launch-certification-only",
            "class_incompatibility_types": [
                {"stage": stage, "type": failure_type}
                for stage, failure_type in sorted(_CLASS_INCOMPATIBILITY_FAILURES)
            ],
            "infrastructure_or_unclassified_failure_authorises_replacement": False,
            "all_failed_classes_excluded": True,
            "manual_failure_classification_permitted": False,
        },
        "selection_policy": {
            "candidate_universe": "frozen-predecessor-120-class-pilot-only",
            "edge_universe": "frozen-predecessor-qualified-60-edge-graph-only",
            "qualified_edges_required": 60,
            "selected_edges": 50,
            "final_classes": 100,
            "reserves": 20,
            "final_per_stratum": 20,
            "objective": [
                "maximum-unchanged-predecessor-final-classes",
                "frozen-pilot-order",
            ],
            "classifier_or_performance_outcomes_used": False,
        },
        "predecessor_mutation_permitted": False,
        "downstream_restart": DOWNSTREAM_RESTART,
    }


def _decision_payload(
    *,
    policy_receipt: Path,
    certification_result_root: Path,
    predecessor_cohort_receipt: Path,
    predecessor_cohort_assembly: Path,
    predecessor_final_selection: Path,
    predecessor_foundation_attestation: Path,
    deep_foundation: bool,
) -> dict[str, Any]:
    policy_path = _regular_file(policy_receipt, "successor policy")
    policy = validate_successor_policy(policy_path)
    cohort_path = _regular_file(predecessor_cohort_receipt, "predecessor cohort")
    cohort_value, predecessor = load_study_receipt(cohort_path)
    if predecessor.feasible_pairs is None or predecessor.matching is None:
        raise ValueError("successor predecessor cohort has no qualified final matching")

    assembly_path = _regular_file(predecessor_cohort_assembly, "predecessor cohort assembly")
    assembly_value = _load_json_object(assembly_path, "predecessor cohort assembly")
    assembly = validate_cohort_assembly_receipt(assembly_value, cohort=cohort_value)
    selection_path = _regular_file(predecessor_final_selection, "predecessor final selection")
    selection_value = _load_json_object(selection_path, "predecessor final selection")
    selection_payload = _validate_final_selection_receipt(selection_value, predecessor)
    _require_assembly_selection_binding(
        assembly,
        final_selection_path=selection_path,
        final_selection_value=selection_value,
        final_selection_payload=selection_payload,
    )

    foundation_path = _regular_file(predecessor_foundation_attestation, "predecessor foundation")
    foundation = _validate_foundation(foundation_path, deep=deep_foundation)
    source = foundation.get("source")
    build_identity = foundation.get("build_execution_identity")
    if not isinstance(source, Mapping) or not source:
        raise ValueError("successor predecessor foundation has no immutable source")
    if not isinstance(build_identity, Mapping) or not build_identity:
        raise ValueError("successor predecessor foundation has no no-cache build identity")

    certification = _certification_failure_evidence(
        certification_result_root,
        predecessor=predecessor,
        cohort_path=cohort_path,
        assembly_path=assembly_path,
        foundation_path=foundation_path,
        source=source,
        build_identity=build_identity,
    )
    failed_class_ids = tuple(certification["failed_class_ids"])
    successor_selection = select_successor_cohort(predecessor, failed_class_ids)

    policy_binding = _file_binding(policy_path)
    policy_binding["payload_sha256"] = canonical_json_sha256(policy)
    decision_basis = {
        "policy_sha256": policy_binding["sha256"],
        "certification_evidence_sha256": certification["evidence_sha256"],
        "predecessor_cohort_sha256": sha256_file(cohort_path),
        "predecessor_cohort_assembly_sha256": sha256_file(assembly_path),
        "predecessor_final_selection_sha256": sha256_file(selection_path),
        "predecessor_foundation_sha256": sha256_file(foundation_path),
        "failed_cells_sha256": canonical_json_sha256(certification["failed_cells"]),
        "successor_selection_sha256": canonical_json_sha256(successor_selection.as_dict()),
    }
    identity_sha256 = canonical_json_sha256(decision_basis)
    successor_study_id = f"{SUCCESSOR_STUDY_PREFIX}-{identity_sha256[:12]}"
    launch_namespace = f".{successor_study_id}-launches"
    if successor_study_id == STUDY_ID or launch_namespace == f".{STUDY_ID}-launches":
        raise AssertionError("successor identity collides with its predecessor")

    evidence = {
        "policy": policy_binding,
        "certification_result": {
            "root": certification["root"],
            "evidence_sha256": certification["evidence_sha256"],
            "experiment_sha256": certification["experiment_sha256"],
        },
        "predecessor_cohort": _file_binding(cohort_path),
        "predecessor_cohort_assembly": _file_binding(assembly_path),
        "predecessor_final_selection": _file_binding(selection_path),
        "predecessor_foundation": _file_binding(foundation_path),
    }
    return {
        "decision_schema_version": SCHEMA_VERSION,
        "predecessor_study_id": STUDY_ID,
        "successor": {
            "study_id": successor_study_id,
            "launch_namespace": launch_namespace,
            "identity_sha256": identity_sha256,
            "identity_basis": decision_basis,
        },
        "predecessor": {
            "source": json.loads(canonical_json_bytes(source)),
            "source_sha256": canonical_json_sha256(source),
            "build_execution_identity": json.loads(canonical_json_bytes(build_identity)),
            "build_execution_identity_sha256": canonical_json_sha256(build_identity),
            "final_classes": [candidate.candidate_id for candidate in predecessor.final],
            "reserve_classes": [candidate.candidate_id for candidate in predecessor.reserves],
            "qualified_pair_graph_sha256": canonical_json_sha256(
                [list(pair) for pair in predecessor.feasible_pairs]
            ),
        },
        "certification_failure": certification,
        "successor_selection": successor_selection.as_dict(),
        "predecessor_mutation_permitted": False,
        "downstream_restart": DOWNSTREAM_RESTART,
        "evidence": evidence,
    }


def _certification_failure_evidence(
    root: Path,
    *,
    predecessor: CohortSelection,
    cohort_path: Path,
    assembly_path: Path,
    foundation_path: Path,
    source: Mapping[str, Any],
    build_identity: Mapping[str, Any],
) -> dict[str, Any]:
    result_root = _regular_directory(root, "certification result")
    verified = verify_result(result_root)
    experiment = verified.experiment
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise TypeError("successor certification has no frozen configuration")
    if (
        experiment.get("name") != CERTIFICATION_NAME
        or experiment.get("status") != "incomplete"
        or not isinstance(experiment.get("summary"), Mapping)
        or experiment["summary"].get("passed") is not False
        or configuration.get("evidence_role") != "certification"
    ):
        raise ValueError("successor decision requires sealed incomplete certification")
    if experiment.get("source") != dict(source):
        raise ValueError("successor certification source differs from its foundation")

    cohort_sha256 = sha256_file(cohort_path)
    assembly_sha256 = sha256_file(assembly_path)
    foundation_sha256 = sha256_file(foundation_path)
    if (
        configuration.get("class_study_cohort_sha256") != cohort_sha256
        or configuration.get("class_study_cohort_assembly_sha256") != assembly_sha256
        or configuration.get("class_study_foundation_sha256") != foundation_sha256
    ):
        raise ValueError("successor certification uses different predecessor authority")
    _require_frozen_input(
        verified,
        "inputs/class-study-cohort.json",
        cohort_path,
        label="predecessor cohort",
    )
    _require_frozen_input(
        verified,
        "inputs/class-study-cohort-assembly.json",
        assembly_path,
        label="predecessor cohort assembly",
    )
    _require_frozen_input(
        verified,
        "inputs/class-study-foundation.json",
        foundation_path,
        label="predecessor foundation",
    )
    launch_path = _regular_file(
        result_root / "inputs/class-study-launch.json",
        "certification first-launch claim",
    )
    launch_sha256 = sha256_file(launch_path)
    if (
        verified.checksums.get("inputs/class-study-launch.json") != launch_sha256
        or configuration.get("class_study_launch_sha256") != launch_sha256
    ):
        raise ValueError("successor certification lacks a sealed first-launch claim")
    _require_result_build(verified, source=source, build_identity=build_identity)

    defense_records = configuration.get("defenses")
    if not isinstance(defense_records, list) or tuple(
        record.get("name") for record in defense_records if isinstance(record, Mapping)
    ) != tuple(COMPATIBILITY_MODES):
        raise ValueError("successor certification defense order differs from the contract")
    final_ids = tuple(candidate.candidate_id for candidate in predecessor.final)
    workload_records = configuration.get("workloads")
    if (
        not isinstance(workload_records, list)
        or tuple(record.get("id") for record in workload_records if isinstance(record, Mapping))
        != final_ids
    ):
        raise ValueError("successor certification workload order differs from its cohort")

    samples = experiment.get("samples")
    if not isinstance(samples, list) or len(samples) != CERTIFICATION_SAMPLE_COUNT:
        raise ValueError("successor certification must contain exactly 900 planned cells")
    expected = {
        (workload_id, defense, 0) for workload_id in final_ids for defense in COMPATIBILITY_MODES
    }
    observed: set[tuple[str, str, int]] = set()
    failed_cells: list[dict[str, Any]] = []
    accepted_count = 0
    final_order = {candidate_id: index for index, candidate_id in enumerate(final_ids)}
    defense_order = {defense: index for index, defense in enumerate(COMPATIBILITY_MODES)}
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise TypeError("successor certification sample is malformed")
        identity = (sample.get("workload_id"), sample.get("defense"), sample.get("visit"))
        if identity not in expected or identity in observed:
            raise ValueError("successor certification is not the exact class/mode cross-product")
        if sample.get("request_policy") != "as-defined" or sample.get("attempts") != 1:
            raise ValueError("successor certification cells must be first-launch as-defined")
        observed.add(identity)  # type: ignore[arg-type]
        if sample.get("state") == "accepted" and sample.get("eligible") is True:
            accepted_count += 1
            continue
        if sample.get("state") != "failed" or sample.get("eligible") is not False:
            raise ValueError("successor certification contains a nonterminal cell")
        failure = sample.get("failure")
        classification = _failure_classification(failure)
        if classification != "class-incompatibility":
            raise ValueError(
                "infrastructure or unclassified certification failure cannot "
                "authorise automatic class replacement"
            )
        if not isinstance(sample.get("sample_id"), str):
            raise TypeError("successor certification failed cell has no sample ID")
        failed_cells.append(
            {
                "sample_id": sample["sample_id"],
                "workload_id": identity[0],
                "defense": identity[1],
                "visit": identity[2],
                "attempts": sample["attempts"],
                "classification": classification,
                "failure": json.loads(canonical_json_bytes(failure)),
                "failure_sha256": canonical_json_sha256(failure),
            }
        )
    if observed != expected or not failed_cells:
        raise ValueError("successor decision requires at least one exact failed cell")
    failed_cells.sort(
        key=lambda cell: (
            final_order[str(cell["workload_id"])],
            defense_order[str(cell["defense"])],
            str(cell["sample_id"]),
        )
    )
    accepted_samples = len(verified.accepted_samples)
    if accepted_samples != accepted_count or accepted_count + len(failed_cells) != 900:
        raise ValueError("successor certification accepted/failed accounting is inconsistent")

    experiment_path = _regular_file(result_root / "experiment.json", "certification experiment")
    experiment_sha256 = sha256_file(experiment_path)
    if verified.checksums.get("experiment.json") != experiment_sha256:
        raise ValueError("successor certification seal does not bind experiment.json")
    evidence_path = _regular_file(result_root / "evidence.sha256", "certification evidence seal")
    failed_class_set = {str(cell["workload_id"]) for cell in failed_cells}
    failed_class_ids = [
        candidate_id for candidate_id in final_ids if candidate_id in failed_class_set
    ]
    return {
        "root": str(result_root),
        "name": CERTIFICATION_NAME,
        "evidence_sha256": sha256_file(evidence_path),
        "experiment_sha256": experiment_sha256,
        "class_study_launch_sha256": launch_sha256,
        "planned_cells": 900,
        "accepted_cells": accepted_count,
        "failed_cell_count": len(failed_cells),
        "failed_class_ids": failed_class_ids,
        "failed_cells": failed_cells,
        "classification": "class-incompatibility-only",
        "infrastructure_failure_count": 0,
    }


def _normalised_qualified_graph(
    value: Sequence[Sequence[str]] | None,
    order: Mapping[str, int],
) -> tuple[tuple[str, str], ...]:
    if value is None or len(value) != PILOT_COUNT // 2:
        raise ValueError("successor requires exactly 60 already-qualified pair edges")
    observed: set[tuple[str, str]] = set()
    covered: set[str] = set()
    for raw_pair in value:
        if (
            not isinstance(raw_pair, Sequence)
            or isinstance(raw_pair, (str, bytes))
            or len(raw_pair) != 2
            or not all(isinstance(item, str) and item in order for item in raw_pair)
            or raw_pair[0] == raw_pair[1]
        ):
            raise ValueError("successor qualified pair edge is invalid")
        left, right = sorted((raw_pair[0], raw_pair[1]), key=order.__getitem__)
        pair = (left, right)
        if pair in observed or left in covered or right in covered:
            raise ValueError("successor qualified graph is not a one-to-one pilot matching")
        observed.add(pair)
        covered.update(pair)
    if covered != set(order):
        raise ValueError("successor qualified graph does not cover the frozen pilot")
    return tuple(sorted(observed, key=lambda pair: (order[pair[0]], order[pair[1]])))


def _normalised_matching(
    value: Sequence[Sequence[str]] | None,
    order: Mapping[str, int],
) -> tuple[tuple[str, str], ...]:
    if value is None:
        raise ValueError("successor predecessor has no selected matching")
    pairs: set[tuple[str, str]] = set()
    for raw_pair in value:
        if (
            not isinstance(raw_pair, Sequence)
            or isinstance(raw_pair, (str, bytes))
            or len(raw_pair) != 2
            or not all(isinstance(item, str) and item in order for item in raw_pair)
            or raw_pair[0] == raw_pair[1]
        ):
            raise ValueError("successor predecessor matching edge is invalid")
        pair = tuple(sorted((raw_pair[0], raw_pair[1]), key=order.__getitem__))
        if pair in pairs:
            raise ValueError("successor predecessor matching contains duplicate edges")
        pairs.add(pair)  # type: ignore[arg-type]
    return tuple(sorted(pairs, key=lambda pair: (order[pair[0]], order[pair[1]])))


def _prefer_omitted_edges(
    candidate: tuple[int, ...],
    incumbent: tuple[int, ...],
    *,
    graph: Sequence[tuple[str, str]],
    order: Mapping[str, int],
    previous_final_ids: set[str],
) -> bool:
    def objective(indices: tuple[int, ...]) -> tuple[int, tuple[int, ...]]:
        omitted_ids = [candidate_id for index in indices for candidate_id in graph[index]]
        predecessor_classes = sum(
            candidate_id in previous_final_ids for candidate_id in omitted_ids
        )
        # For fixed-size complements, the lexicographically smallest selected
        # pilot inventory is induced by the lexicographically largest omitted
        # pilot inventory.
        omitted_order = tuple(sorted(order[candidate_id] for candidate_id in omitted_ids))
        return predecessor_classes, omitted_order

    candidate_cost, candidate_order = objective(candidate)
    incumbent_cost, incumbent_order = objective(incumbent)
    return candidate_cost < incumbent_cost or (
        candidate_cost == incumbent_cost and candidate_order > incumbent_order
    )


def _require_stratum_counts(
    candidates: Sequence[ClassCandidate],
    expected: int,
    *,
    label: str,
) -> None:
    counts = Counter(candidate.stratum.id for candidate in candidates)
    if counts != Counter({stratum.id: expected for stratum in TRANCO_RANK_STRATA}):
        raise ValueError(f"successor {label} rank-stratum quotas are invalid")


def _validate_final_selection_receipt(
    value: Mapping[str, Any],
    predecessor: CohortSelection,
) -> dict[str, Any]:
    payload = validate_hash_bound_receipt(value, expected_type=FINAL_SELECTION_RECEIPT_TYPE)
    expected_fields = {
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
    if set(payload) != expected_fields or payload.get("study_id") != STUDY_ID:
        raise ValueError("successor predecessor final-selection schema is invalid")
    if payload.get("feasible_pair_graph") != [
        list(pair) for pair in predecessor.feasible_pairs or ()
    ] or payload.get("selected_final_perfect_matching") != [
        list(pair) for pair in predecessor.matching or ()
    ]:
        raise ValueError("successor predecessor final-selection graph was substituted")
    return payload


def _require_assembly_selection_binding(
    assembly: Mapping[str, Any],
    *,
    final_selection_path: Path,
    final_selection_value: Mapping[str, Any],
    final_selection_payload: Mapping[str, Any],
) -> None:
    binding = assembly.get("final_selection")
    if (
        not isinstance(binding, Mapping)
        or binding.get("sha256") != sha256_file(final_selection_path)
        or binding.get("payload_sha256") != final_selection_value.get("payload_sha256")
        or binding.get("payload") != dict(final_selection_payload)
    ):
        raise ValueError("successor predecessor assembly has different final selection")


def _validate_foundation(path: Path, *, deep: bool) -> dict[str, Any]:
    from .class_attestation import validate_class_foundation_attestation

    value = validate_class_foundation_attestation(
        path,
        deep_code_gate=deep,
        runtime_role="collection",
    )
    if not isinstance(value, Mapping):
        raise TypeError("successor predecessor foundation is malformed")
    return dict(value)


def _require_result_build(
    verified: VerifiedResult,
    *,
    source: Mapping[str, Any],
    build_identity: Mapping[str, Any],
) -> None:
    path = _regular_file(
        verified.root / "inputs/study-environment.json",
        "certification study environment",
    )
    if verified.checksums.get("inputs/study-environment.json") != sha256_file(path):
        raise ValueError("successor certification seal does not bind its environment")
    from .buflo_study import validate_study_environment_receipt

    environment = validate_study_environment_receipt(
        _load_json_object(path, "certification study environment"),
        expected_image_digest=source.get("image_digest"),
    )
    observed = environment.get("build_execution")
    if not isinstance(observed, Mapping) or {
        key: observed.get(key) for key in build_identity
    } != dict(build_identity):
        raise ValueError("successor certification uses a different no-cache build")


def _failure_classification(value: object) -> str:
    if not isinstance(value, Mapping):
        return "unclassified"
    stage = value.get("stage")
    failure_type = value.get("type")
    if (stage, failure_type) in _CLASS_INCOMPATIBILITY_FAILURES:
        return "class-incompatibility"
    if stage in {"collection", "interruption"} or failure_type in (_INFRASTRUCTURE_FAILURE_TYPES):
        return "infrastructure"
    return "unclassified"


def _require_frozen_input(
    verified: VerifiedResult,
    relative: str,
    expected: Path,
    *,
    label: str,
) -> None:
    frozen = _regular_file(verified.root / relative, f"frozen {label}")
    digest = sha256_file(frozen)
    if digest != sha256_file(expected) or verified.checksums.get(relative) != digest:
        raise ValueError(f"successor certification frozen {label} differs")


def _file_binding(path: Path) -> dict[str, str]:
    source = _regular_file(path, "successor evidence file")
    return {"path": str(source), "sha256": sha256_file(source)}


def _path_from_file_binding(value: object, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or set(value) not in ({"path", "sha256"}, {"path", "sha256", "payload_sha256"})
        or not isinstance(value.get("path"), str)
        or not isinstance(value.get("sha256"), str)
        or _DIGEST.fullmatch(value["sha256"]) is None
    ):
        raise ValueError(f"class-study successor {label} binding is invalid")
    path = _regular_file(Path(value["path"]), label)
    if sha256_file(path) != value["sha256"]:
        raise ValueError(f"class-study successor {label} digest changed")
    if "payload_sha256" in value:
        receipt = _load_json_object(path, label)
        if receipt.get("payload_sha256") != value["payload_sha256"]:
            raise ValueError(f"class-study successor {label} payload digest changed")
    return path


def _path_from_result_binding(value: object, label: str) -> Path:
    keys = set(value) if isinstance(value, Mapping) else set()
    decision_keys = {"root", "evidence_sha256", "experiment_sha256"}
    class_binding = (
        isinstance(value, Mapping)
        and "experiment_sha256" not in value
        and {"root", "evidence_sha256", "class_study_launch_sha256"}.issubset(
            value
        )
    )
    if (
        not isinstance(value, Mapping)
        or (
            keys
            not in (decision_keys, {*decision_keys, "class_study_launch_sha256"})
            and not class_binding
        )
        or not isinstance(value.get("root"), str)
        or not isinstance(value.get("evidence_sha256"), str)
        or _DIGEST.fullmatch(value["evidence_sha256"]) is None
    ):
        raise ValueError(f"class-study successor {label} binding is invalid")
    root = _regular_directory(Path(value["root"]), label)
    if sha256_file(_regular_file(root / "evidence.sha256", label)) != value[
        "evidence_sha256"
    ]:
        raise ValueError(f"class-study successor {label} digest changed")
    if class_binding:
        from .class_attestation import _class_result_binding

        if _class_result_binding(root) != dict(value):
            raise ValueError(f"class-study successor {label} authority changed")
    elif (
        not isinstance(value.get("experiment_sha256"), str)
        or _DIGEST.fullmatch(value["experiment_sha256"]) is None
        or sha256_file(_regular_file(root / "experiment.json", label))
        != value["experiment_sha256"]
    ):
        raise ValueError(f"class-study successor {label} experiment changed")
    return root


def _root_from_bundle_binding(value: object, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"root", "provenance", "provenance_sha256", "artifacts"}
        or not isinstance(value.get("root"), str)
        or not isinstance(value.get("provenance"), str)
        or Path(value["provenance"]).name != value["provenance"]
        or not isinstance(value.get("artifacts"), Mapping)
    ):
        raise ValueError(f"class-study successor {label} binding is invalid")
    root = _regular_directory(Path(value["root"]), label)
    if sha256_file(_regular_file(root / value["provenance"], label)) != value.get(
        "provenance_sha256"
    ):
        raise ValueError(f"class-study successor {label} provenance changed")
    return root


def _root_from_directory_binding(value: object, label: str) -> Path:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"root"}
        or not isinstance(value.get("root"), str)
    ):
        raise ValueError(f"class-study successor {label} binding is invalid")
    return _regular_directory(Path(value["root"]), label)


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    source = _regular_file(path, label)
    try:
        value = load_json(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object")
    return value


def _create_or_verify_bytes(path: Path, value: bytes, *, label: str) -> None:
    parent = _regular_directory(path.parent, f"successor {label} parent")
    destination = parent / path.name
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError(f"successor {label} is not a regular file")
        if destination.read_bytes() != value:
            raise ValueError(f"successor {label} changed during restart publication")
        return
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "xb",
            dir=parent,
            prefix=f".{destination.name}.",
            suffix=".qcsd-tmp",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if (
                destination.is_symlink()
                or not destination.is_file()
                or destination.read_bytes() != value
            ):
                raise ValueError(
                    f"successor {label} raced with different restart evidence"
                ) from None
        _fsync_directory(parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _regular_file(path: Path, label: str) -> Path:
    absolute = _reject_symlink_components(path, label=label)
    if not absolute.is_file():
        raise ValueError(f"{label} must be a regular file: {absolute}")
    return absolute


def _regular_directory(path: Path, label: str) -> Path:
    absolute = _reject_symlink_components(path, label=label)
    if not absolute.is_dir():
        raise ValueError(f"{label} must be a regular directory: {absolute}")
    return absolute


def _reject_symlink_components(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symbolic link: {current}")
    return absolute
