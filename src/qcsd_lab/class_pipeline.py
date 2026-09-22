"""Evidence-ordered coordinator for ``classifier-multiorigin100-v1``.

The coordinator is intentionally conservative.  It delegates scientific work
to the independently validated catalogue, cohort, fitting, qualification,
capture, handoff, and evaluation modules, and never treats a path merely
existing as evidence that a stage completed.  Its acquisition actions invoke
the fail-closed browser/Neqo backend through bounded, resumable checkpoints;
the resulting receipts, rather than a successful process exit, establish
progress.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .acquisition_timing import (
    GLOBAL_LIVE_PAGE_CAP,
    MAX_CANDIDATES_PER_ACTION,
    RUN_WAIT_POLICY,
)
from .chaff_qualification import (
    CLASS_STUDY_QUALIFICATION_SCHEMA_VERSION,
    FULL_QUALIFICATION_SCOPE,
    NAMED_QUALIFICATION_PREFIX_DIRECTORY,
    NAMED_QUALIFICATION_SET_MANIFEST,
    _qualification_execution_context,
    initialize_named_qualification_checkpoint,
    load_named_qualification_set,
    pending_named_qualification_workloads,
    publish_named_qualification_set_from_checkpoint,
    qualify_chaff,
    reconcile_named_qualification_checkpoint,
    record_named_qualification_checkpoint,
)
from .class_campaigns import CAPTURE_LIMITS, campaign_documents, validate_campaign_documents
from .class_catalogue import (
    STABILITY_PROBE_WINDOWS,
    STABILITY_RECEIPT_TYPE,
    PageCandidate,
    ProbeCallback,
    StabilityObservation,
    build_stability_receipt,
    collect_stability_observations,
    load_candidate_catalogue_receipt,
    load_stability_receipt,
    validate_hash_bound_receipt,
    write_stability_receipt,
)
from .class_cohort import (
    FINAL_SELECTION_SCHEMA_VERSION,
    publish_evidenced_cohort,
    validate_cohort_assembly,
)
from .class_fitting import (
    AUTHORITATIVE_QUALIFICATION_SET,
    AUTHORITATIVE_STAGE,
    BUNDLE_FILES,
    NUMERIC_PROVENANCE_FILE,
    PILOT_QUALIFICATION_SET,
    PILOT_STAGE,
    PROVENANCE_FILE,
    QualificationContext,
    VerifiedClassFittingBundle,
    VerifiedNumericFittingBundle,
    create_numeric_fitting_bundle,
    derive_schema_six_prefix_specs,
    finalize_fitting_bundle,
    require_successor_fitting_identity,
    validate_class_fitting_result,
    validate_schema_six_prefix_spec,
    verify_class_fitting_artifact_root,
    verify_class_fitting_bundle,
    verify_numeric_fitting_bundle,
)
from .class_handoff import export_class_handoff, verify_class_handoff
from .class_layout import (
    AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
    AUTHORITATIVE_COHORT_FILENAME,
    DEFAULT_AUTHORITATIVE_FINAL_REFERENCE,
    DEFAULT_COHORT_ASSEMBLY_REFERENCE,
    DEFAULT_COHORT_REFERENCE,
    DEFAULT_PILOT_FINAL_REFERENCE,
    FINAL_SELECTION_FILENAME,
    PILOT_COHORT_ASSEMBLY_FILENAME,
    PILOT_COHORT_FILENAME,
    canonical_campaign_reference,
    class_study_layout,
    require_canonical_campaign_reference,
    require_canonical_fresh_child,
    require_canonical_fresh_path,
)
from .class_run_binding import (
    resolve_class_sample_run_binding,
    validate_class_sample_run_binding,
)
from .class_study import (
    COMPATIBILITY_MODES,
    FINAL_CLASS_COUNT,
    FORMAL_BLOCK_COUNT,
    FORMAL_MODES,
    PILOT_COUNT,
    STUDY_ID,
    CohortSelection,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    is_successor_study_id,
    load_study_receipt,
    parse_class_study_campaign_name,
    select_cohort,
)
from .class_study import (
    RECEIPT_TYPE as COHORT_RECEIPT_TYPE,
)
from .class_study import (
    validate_hash_bound_receipt as validate_study_bound_receipt,
)
from .defenses import defense_from_runtime_identity
from .experiment import ACCEPTED_ARTIFACTS, resolved_sample_directory
from .fidelity import (
    _schedule_realization_metrics_from_path,
    fidelity_eligible,
    new_defense_terminal_receipts_valid,
)
from .orchestrator import (
    CLASS_STUDY_LAUNCH_INPUT,
    CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY,
    CLASS_STUDY_SUCCESSOR_INPUT,
    _class_study_coordinator_capture_authority,
    preflight_campaign,
    resume_campaign,
    run_campaign,
    verify_class_study_fitting_generation,
)
from .util import load_json, sha256_file
from .verification import VerifiedResult, verify_result

SCHEMA_VERSION = 1
ACTION_RESULT_TYPE = "qcsd-class-study-coordinator-result"
STABILITY_BATCH_TYPE = "qcsd-class-study-stability-observation-batch"
CAMPAIGN_SET_FILES = 24
CERTIFICATION_PAIR_COUNT = FINAL_CLASS_COUNT * len(COMPATIBILITY_MODES)
CANARY_SAMPLE_COUNT = FINAL_CLASS_COUNT * FORMAL_BLOCK_COUNT
FORMAL_SAMPLE_COUNT = FINAL_CLASS_COUNT * len(FORMAL_MODES) * 2 * FORMAL_BLOCK_COUNT
FINAL_SELECTION_RECEIPT_TYPE = "qcsd-class-study-final-selection-input"
CLASS_STUDY_FOUNDATION_INPUT = "inputs/class-study-foundation.json"
CLASS_STUDY_READINESS_INPUT = "inputs/class-study-readiness.json"
CLASS_STUDY_HISTORICAL_PRE_INPUT = "inputs/class-study-historical-pre-snapshot.json"
CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY = "class_study_foundation_sha256"
CLASS_STUDY_READINESS_CONFIGURATION_KEY = "class_study_readiness_sha256"
CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY = "class_study_historical_pre_snapshot_sha256"
_CURRENT_CANDIDATE_RUNTIME_KINDS = {
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}

STUDY_ACTIONS = (
    "status",
    "acquisition-authority",
    "acquisition-init",
    "acquisition-run",
    "acquisition-status",
    "acquisition-complete",
    "stability",
    "cohort",
    "campaigns",
    "fit-numeric",
    "prefix-specs",
    "qualify-prefix",
    "finalize-fitting",
    "capture",
    "resume",
    "export",
    "evaluate",
    "foundation",
    "readiness",
    "historical-snapshot",
    "comparison-review",
    "attest",
    "successor-policy",
    "successor-decision",
    "successor-restart",
    "successor-verify",
    "verify",
)

_FRESH_LAYOUT_ACTIONS = frozenset(
    {
        "acquisition-authority",
        "acquisition-init",
        "acquisition-run",
        "acquisition-status",
        "acquisition-complete",
        "stability",
        "cohort",
        "campaigns",
        "fit-numeric",
        "prefix-specs",
        "qualify-prefix",
        "finalize-fitting",
        "capture",
        "foundation",
        "readiness",
        "historical-snapshot",
        "comparison-review",
        "attest",
    }
)

_STABILITY_FILENAME = re.compile(r"page-([0-4][0-9])[.]json\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_RUNTIME_KIND_BY_MODE = {
    "undefended": "none",
    "static": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}
_EXTERNAL_PARAMETER_MODES = frozenset(
    {
        "traffic-morphing",
        "wtf-pad",
        "walkie-talkie",
        "buflo",
        "cs-buflo",
    }
)
_STABILITY_BATCH_KEYS = {
    "schema_version",
    "artifact_type",
    "candidate_id",
    "baseline_started_at",
    "page",
    "observations",
}
_PAGE_KEYS = {
    "candidate_domain",
    "registrable_domain",
    "url",
    "source",
    "ordinal",
    "discovery_content_type",
}
_OBSERVATION_KEYS = {
    "probe_id",
    "observed_at",
    "elapsed_ms",
    "final_url",
    "status",
    "content_type",
    "body_bytes",
    "body_sha256",
    "resource_graph_sha256",
    "prepared_workload_sha256",
}
_NON_FITTING_COUNTS = {
    "pilot-compatibility": PILOT_COUNT * len(COMPATIBILITY_MODES),
    "certification": CERTIFICATION_PAIR_COUNT,
    "canary": FINAL_CLASS_COUNT,
    "formal": FINAL_CLASS_COUNT * len(FORMAL_MODES) * 2,
}
_CANONICAL_NAMES = {
    "pilot-fitting": f"{STUDY_ID}-pilot-fitting-1200",
    "pilot-compatibility": f"{STUDY_ID}-pilot-compatibility-1080-1200",
    "authoritative-fitting": f"{STUDY_ID}-authoritative-fitting-1200",
    "certification": f"{STUDY_ID}-certification-900-1200",
}


@dataclass(frozen=True)
class ClassStudyActionResult:
    """One JSON-safe coordinator outcome.

    ``complete`` is reserved for an action whose output was independently
    verified.  ``ready`` and ``pending`` never imply scientific completion.
    """

    action: str
    status: str
    details: Mapping[str, Any]
    blockers: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema_version"] = SCHEMA_VERSION
        value["artifact_type"] = ACTION_RESULT_TYPE
        value["blockers"] = list(self.blockers)
        return value


@dataclass(frozen=True)
class CohortAdmission:
    """Verified bridge from stability evidence to selected workload bytes."""

    cohort_path: Path
    assembly_path: Path
    selection: CohortSelection
    cohort_sha256: str
    assembly_sha256: str
    prepared_workload_sha256: Mapping[str, str]
    acquisition_completion_sha256: str | None = None
    acquisition_completion_payload_sha256: str | None = None
    final_selection_sha256: str | None = None
    final_selection_payload_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": True,
            "cohort": str(self.cohort_path),
            "cohort_sha256": self.cohort_sha256,
            "assembly": str(self.assembly_path),
            "assembly_sha256": self.assembly_sha256,
            "pilot_classes": len(self.selection.pilot),
            "final_classes": len(self.selection.final),
            "reserve_classes": len(self.selection.reserves),
            "prepared_workload_count": len(self.prepared_workload_sha256),
            "acquisition_completion_sha256": self.acquisition_completion_sha256,
            "acquisition_completion_payload_sha256": (self.acquisition_completion_payload_sha256),
            "final_selection_sha256": self.final_selection_sha256,
            "final_selection_payload_sha256": self.final_selection_payload_sha256,
        }


ACQUISITION_RUN_WAIT_POLICY = dict(RUN_WAIT_POLICY)


def stability_gate() -> dict[str, Any]:
    """Return the exact, human-readable three-window admission contract."""

    return {
        "required_windows": [window.as_dict() for window in STABILITY_PROBE_WINDOWS],
        "labels": [window.probe_id for window in STABILITY_PROBE_WINDOWS],
        "all_three_required_per_page_receipt": True,
        "acquisition_owner": "resumable-qcsd-class-study-production-runner",
        "batching": {
            "maximum_candidates_per_action": MAX_CANDIDATES_PER_ACTION,
            "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
        },
        "runner_wait_policy": dict(ACQUISITION_RUN_WAIT_POLICY),
    }


def acquire_stability_receipt(
    candidate_catalogue_path: Path,
    stability_root: Path,
    *,
    candidate_id: str,
    page: PageCandidate,
    baseline_started_at: str,
    probe: ProbeCallback,
) -> Path:
    """Run an injected three-window callback and publish one immutable receipt.

    The callback owns sleeping and browser/preparation execution.  This bridge
    supplies the fixed schedule and converts typed observations into the exact
    evidence format consumed by cohort assembly.
    """

    observations = collect_stability_observations(page, probe=probe)
    return admit_stability_observations(
        candidate_catalogue_path,
        stability_root,
        candidate_id=candidate_id,
        page=page,
        baseline_started_at=baseline_started_at,
        observations=observations,
    )


def admit_stability_observation_batch(
    candidate_catalogue_path: Path,
    stability_root: Path,
    observation_batch_path: Path,
) -> Path:
    """Convert a strict runner-produced observation batch into a receipt."""

    batch = _load_json_object(observation_batch_path, "stability observation batch")
    if set(batch) != _STABILITY_BATCH_KEYS:
        raise ValueError("stability observation batch has an invalid exact schema")
    if (
        batch["schema_version"] != SCHEMA_VERSION
        or batch["artifact_type"] != STABILITY_BATCH_TYPE
        or not isinstance(batch["candidate_id"], str)
        or not isinstance(batch["baseline_started_at"], str)
    ):
        raise ValueError("stability observation batch identity is invalid")
    raw_page = batch["page"]
    if not isinstance(raw_page, Mapping) or set(raw_page) != _PAGE_KEYS:
        raise ValueError("stability observation batch page is invalid")
    page = PageCandidate(**dict(raw_page))
    raw_observations = batch["observations"]
    if not isinstance(raw_observations, list) or len(raw_observations) != len(
        STABILITY_PROBE_WINDOWS
    ):
        raise ValueError("stability observation batch requires exactly three observations")
    observations: list[StabilityObservation] = []
    for raw in raw_observations:
        if not isinstance(raw, Mapping) or set(raw) != _OBSERVATION_KEYS:
            raise ValueError("stability observation has an invalid exact schema")
        observations.append(StabilityObservation(**dict(raw)))
    return admit_stability_observations(
        candidate_catalogue_path,
        stability_root,
        candidate_id=batch["candidate_id"],
        page=page,
        baseline_started_at=batch["baseline_started_at"],
        observations=tuple(observations),
    )


def admit_stability_observations(
    candidate_catalogue_path: Path,
    stability_root: Path,
    *,
    candidate_id: str,
    page: PageCandidate,
    baseline_started_at: str,
    observations: Sequence[StabilityObservation],
) -> Path:
    """Build and idempotently publish one evidence-bound page receipt."""

    catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    matches = tuple(candidate for candidate in candidates if candidate.candidate_id == candidate_id)
    if len(matches) != 1:
        raise ValueError("stability candidate is not uniquely present in the catalogue")
    [candidate] = matches
    if page.candidate_domain != candidate.domain:
        raise ValueError("stability page domain differs from the catalogue candidate")
    payload = validate_hash_bound_receipt(
        catalogue,
        expected_type="qcsd-class-study-candidate-catalogue",
    )
    receipt = build_stability_receipt(
        candidate,
        page,
        tranco_list_id=payload["tranco"]["list_id"],
        tranco_list_sha256=payload["tranco"]["list_sha256"],
        baseline_started_at=baseline_started_at,
        observations=tuple(observations),
    )
    root = _regular_directory(stability_root, "stability receipt root")
    candidate_root = root / candidate_id
    if candidate_root.exists() or candidate_root.is_symlink():
        _regular_directory(candidate_root, f"stability directory for {candidate_id}")
    else:
        candidate_root.mkdir(mode=0o755)
        _fsync_directory(root)
    destination = candidate_root / f"page-{page.ordinal:02d}.json"
    encoded = canonical_json_bytes(receipt)
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != encoded
        ):
            raise FileExistsError(f"immutable stability receipt already differs: {destination}")
        load_stability_receipt(destination)
        return destination.resolve()
    written = write_stability_receipt(destination, receipt)
    _fsync_directory(candidate_root)
    return written.resolve()


def stability_status(
    candidate_catalogue_path: Path,
    stability_root: Path,
) -> dict[str, Any]:
    """Validate all present stability receipts and report resumable coverage."""

    catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    catalogue_payload = validate_hash_bound_receipt(
        catalogue,
        expected_type="qcsd-class-study-candidate-catalogue",
    )
    root = _regular_directory(stability_root, "stability receipt root")
    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    unknown = sorted(path.name for path in root.iterdir() if path.name not in by_id)
    if unknown:
        raise ValueError(
            "stability root contains entries outside the prospective catalogue: "
            + ", ".join(unknown)
        )
    receipt_count = 0
    eligible_receipts = 0
    candidate_count = 0
    candidates_with_eligible_page = 0
    for candidate_id in sorted(path.name for path in root.iterdir()):
        directory = _regular_directory(
            root / candidate_id, f"stability directory for {candidate_id}"
        )
        entries: list[tuple[int, Path]] = []
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"stability entry is not a regular file: {path}")
            match = _STABILITY_FILENAME.fullmatch(path.name)
            if match is None:
                raise ValueError(f"stability filename is not canonical: {path.name}")
            entries.append((int(match.group(1)), path))
        entries.sort()
        if not entries or tuple(index for index, _path in entries) != tuple(range(len(entries))):
            raise ValueError("stability pages must be contiguous from page-00")
        candidate_count += 1
        any_eligible = False
        for index, path in entries:
            value, decision = load_stability_receipt(path)
            payload = validate_hash_bound_receipt(value, expected_type=STABILITY_RECEIPT_TYPE)
            if (
                payload["candidate"]["candidate_id"] != candidate_id
                or payload["candidate"]["domain"] != by_id[candidate_id].domain
                or payload["candidate"]["rank"] != by_id[candidate_id].rank
                or payload["page"]["ordinal"] != index
                or payload["tranco"]
                != {
                    "list_id": catalogue_payload["tranco"]["list_id"],
                    "list_sha256": catalogue_payload["tranco"]["list_sha256"],
                }
            ):
                raise ValueError("stability receipt differs from its catalogue path")
            receipt_count += 1
            if decision.eligible:
                eligible_receipts += 1
                any_eligible = True
        candidates_with_eligible_page += int(any_eligible)
    return {
        "valid": True,
        "gate": stability_gate(),
        "prospective_candidates": len(candidates),
        "candidates_with_receipts": candidate_count,
        "candidates_without_receipts": len(candidates) - candidate_count,
        "page_receipts": receipt_count,
        "eligible_page_receipts": eligible_receipts,
        "candidates_with_eligible_page": candidates_with_eligible_page,
        "complete_population_probe_claimed": False,
    }


def verify_cohort_admission(
    cohort_receipt_path: Path,
    cohort_assembly_path: Path,
    *,
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion_path: Path,
    final_selection_receipt_path: Path | None = None,
) -> CohortAdmission:
    """Rebuild the stability-to-workload bridge and return its exact bindings."""

    cohort_path = _regular_file(cohort_receipt_path, "class-study cohort receipt")
    assembly_path = _regular_file(cohort_assembly_path, "class-study cohort assembly")
    cohort, selection = load_study_receipt(cohort_path)
    assembly = _load_json_object(assembly_path, "class-study cohort assembly")
    payload = validate_cohort_assembly(
        assembly,
        cohort=cohort,
        candidate_catalogue_path=candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        final_selection_receipt_path=final_selection_receipt_path,
    )
    selected_ids = {
        item.candidate_id for item in (*selection.pilot, *selection.final, *selection.reserves)
    }
    bindings: dict[str, str] = {}
    for record in payload["candidates"]:
        if record["candidate_id"] not in selected_ids:
            continue
        prepared = record.get("prepared_workload")
        if record.get("eligible") is not True or not isinstance(prepared, Mapping):
            raise ValueError("selected cohort candidate lacks eligible prepared-workload evidence")
        digest = prepared.get("sha256")
        if not isinstance(digest, str):
            raise TypeError("selected cohort prepared-workload binding is malformed")
        bindings[record["candidate_id"]] = digest
    if set(bindings) != selected_ids:
        raise ValueError("cohort assembly does not bind every selected workload")
    completion = payload.get("acquisition_completion")
    if not isinstance(completion, Mapping):
        raise TypeError("cohort assembly does not bind acquisition completion")
    final_selection = payload.get("final_selection")
    if selection.feasible_pairs is None:
        if final_selection is not None:
            raise ValueError("pilot cohort admission unexpectedly binds final selection")
    elif not isinstance(final_selection, Mapping):
        raise TypeError("final cohort admission does not bind final selection")
    return CohortAdmission(
        cohort_path=cohort_path,
        assembly_path=assembly_path,
        selection=selection,
        cohort_sha256=sha256_file(cohort_path),
        assembly_sha256=sha256_file(assembly_path),
        prepared_workload_sha256=bindings,
        acquisition_completion_sha256=str(completion["sha256"]),
        acquisition_completion_payload_sha256=str(completion["payload_sha256"]),
        final_selection_sha256=(
            str(final_selection["sha256"]) if isinstance(final_selection, Mapping) else None
        ),
        final_selection_payload_sha256=(
            str(final_selection["payload_sha256"]) if isinstance(final_selection, Mapping) else None
        ),
    )


def verify_successor_cohort_admission(restart_receipt: Path) -> CohortAdmission:
    """Rebuild one successor's compatibility cohort from frozen v1 evidence.

    The successor receipt and every generated plan file are reconstructed
    first.  Admission then replays the original acquisition/stability bridge
    against the exact successor selection; an intrinsic plan file alone is
    never sufficient.
    """

    from .class_successor import validate_successor_restart

    restart_path = _regular_file(restart_receipt, "successor restart receipt")
    validate_successor_restart(restart_path)
    plan_root = restart_path.parent
    layout = class_study_layout()
    return verify_cohort_admission(
        plan_root / "successor-compatible-cohort.json",
        plan_root / "successor-compatible-cohort-assembly.json",
        candidate_catalogue_path=(layout.study_config_root / f"{STUDY_ID}-candidates.json"),
        stability_root=layout.stability_root,
        workload_root=layout.workload_root,
        acquisition_completion_path=layout.acquisition_root / "completion.json",
        final_selection_receipt_path=plan_root / "successor-final-selection.json",
    )


def build_final_selection_input(
    pilot_admission: CohortAdmission,
    *,
    pilot_fitting_result_root: Path,
    pilot_numeric_bundle_root: Path,
    pilot_compatibility_result_root: Path,
    qualification_authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the only accepted input to final/reserve cohort selection.

    An edge is admitted only when the finalized pilot bundle contains that
    exact WT6 runtime profile and frozen qualification proves the profile's
    capacity at both endpoints.  Qualification of each endpoint under some
    other pairing is deliberately not extrapolated to an alternate edge.
    """

    authority = _validated_qualification_authority(qualification_authority)
    numeric = verify_numeric_fitting_bundle(
        pilot_numeric_bundle_root,
        source_result_root=pilot_fitting_result_root,
    )
    if numeric.stage != PILOT_STAGE:
        raise ValueError("final selection requires the verified pilot numeric fitting bundle")
    workload_order = tuple(numeric.provenance["fitting_contract"]["workload_order"])
    pilot_ids = tuple(item.candidate_id for item in pilot_admission.selection.pilot)
    if workload_order != pilot_ids:
        raise ValueError("pilot numeric fitting workload order differs from pilot admission")
    cohort_binding = numeric.provenance.get("cohort")
    if (
        not isinstance(cohort_binding, Mapping)
        or cohort_binding.get("receipt_sha256") != pilot_admission.cohort_sha256
        or cohort_binding.get("assembly_receipt_sha256") != pilot_admission.assembly_sha256
    ):
        raise ValueError("pilot numeric fitting is bound to a different cohort admission")

    compatibility = verify_class_study_result(
        pilot_compatibility_result_root,
        admission=pilot_admission,
        expected_role="pilot-compatibility",
    )
    foundation = authority["foundation_attestation"]
    if compatibility.get("class_study_foundation_sha256") != foundation["sha256"]:
        raise ValueError("pilot compatibility uses a different qualification foundation")
    finalized = _verify_pilot_compatibility_fitting_bundle(
        Path(compatibility["root"]),
        numeric=numeric,
        qualification_authority=authority,
    )
    compatibility_parameters = compatibility.get("defense_parameter_sha256")
    expected_parameters = {
        "traffic-morphing": finalized.artifact_hashes["traffic_morphing"],
        "wtf-pad": finalized.artifact_hashes["wtf_pad"],
        "walkie-talkie": finalized.artifact_hashes["walkie_talkie"],
    }
    if not isinstance(compatibility_parameters, Mapping) or any(
        compatibility_parameters.get(name) != digest for name, digest in expected_parameters.items()
    ):
        raise ValueError("pilot compatibility did not execute the exact pilot fitted parameters")
    cohort = _load_json_object(pilot_admission.cohort_path, "pilot cohort receipt")
    assembly = _load_json_object(pilot_admission.assembly_path, "pilot cohort assembly")
    pairs_tuple, pair_evidence = _qualified_pilot_pair_graph(finalized, pilot_ids)
    final_pair_selection = _qualified_final_pair_selection(
        pilot_admission,
        pilot_cohort=cohort,
        feasible_pairs=pairs_tuple,
    )
    if final_pair_selection.matching is None:
        raise ValueError("qualified pilot pair graph did not produce a final perfect matching")
    possible_pair_count = len(pilot_ids) * (len(pilot_ids) - 1) // 2
    payload = {
        "study_id": STUDY_ID,
        "selection_schema_version": FINAL_SELECTION_SCHEMA_VERSION,
        "selection_policy": "tranco-bound-order-with-qualified-selected-wt6-pairs",
        "pilot_cohort": {
            "sha256": pilot_admission.cohort_sha256,
            "payload_sha256": cohort.get("payload_sha256"),
        },
        "pilot_cohort_assembly": {
            "sha256": pilot_admission.assembly_sha256,
            "payload_sha256": assembly.get("payload_sha256"),
        },
        "pilot_numeric_fitting": {
            "numeric_provenance_sha256": sha256_file(numeric.root / NUMERIC_PROVENANCE_FILE),
            "walkie_talkie_artifact_sha256": numeric.artifact_hashes["walkie_talkie"],
            "source_result": numeric.provenance["source_result"],
        },
        "pilot_compatibility": {
            "campaign": compatibility["name"],
            "evidence_sha256": compatibility["evidence_sha256"],
            "experiment_sha256": compatibility["experiment_sha256"],
            "accepted_samples": compatibility["accepted"],
            "unique_class_mode_pairs": compatibility["unique_class_mode_pairs"],
            "fitted_parameter_sha256": expected_parameters,
            "finalized_bundle": {
                "source": "frozen-pilot-compatibility-inputs",
                "provenance_sha256": sha256_file(finalized.root / PROVENANCE_FILE),
                "artifact_sha256": expected_parameters,
                "qualification_authority": authority,
                "qualification_authority_sha256": canonical_json_sha256(authority),
            },
        },
        "feasible_pair_rule": {
            "source": "finalized-selected-wt6-profile-and-both-endpoint-qualification",
            "candidate_unordered_pairs": possible_pair_count,
            "qualified_pair_edges": len(pairs_tuple),
            "unqualified_alternate_pairs_excluded": possible_pair_count - len(pairs_tuple),
            "pair_specific_finalized_runtime_profile_required": True,
            "both_endpoint_frozen_prefix_qualification_required": True,
            "unselected_pairs_inferred_from_endpoint_compatibility": False,
            "numeric_fit_selected_runtime_profiles_used": True,
            "final_20_per_stratum_perfect_matching_required": True,
            "classifier_outcomes_used": False,
            "measured_bandwidth_latency_or_privacy_outcomes_used": False,
        },
        "feasible_pair_evidence": list(pair_evidence),
        "feasible_pair_graph": [list(pair) for pair in pairs_tuple],
        "selected_final_perfect_matching": [list(pair) for pair in final_pair_selection.matching],
    }
    return bind_receipt(payload, receipt_type=FINAL_SELECTION_RECEIPT_TYPE)


def _verify_pilot_compatibility_fitting_bundle(
    compatibility_result_root: Path,
    *,
    numeric: VerifiedNumericFittingBundle,
    qualification_authority: Mapping[str, Any],
) -> VerifiedClassFittingBundle:
    """Verify the finalized pilot bundle frozen by compatibility capture.

    Finalization adds qualification bindings to the Walkie-Talkie parameter, so
    its runtime hash intentionally differs from the numeric staging hash.  The
    compatibility result is the authoritative record of the bundle that was
    actually executed; this verifier also proves that its numeric content and
    optimiser receipts came from the supplied pilot staging bundle.
    """

    authority = _validated_qualification_authority(qualification_authority)
    result = _regular_directory(compatibility_result_root, "pilot compatibility result root")
    inputs = _regular_directory(result / "inputs", "pilot compatibility inputs")
    context = QualificationContext(
        workload_root=inputs / "workloads",
        sidecar_root=inputs / "chaff-qualifications",
        prefix_spec_root=inputs / "chaff-prefix-specs",
        require_current_implementation=False,
        qualification_authority=authority,
    )
    finalized = verify_class_fitting_bundle(
        inputs / "defense-parameters" / "class-study",
        qualification_context=context,
    )
    if finalized.stage != PILOT_STAGE:
        raise ValueError("pilot compatibility froze a non-pilot fitting bundle")
    qualification_inputs = finalized.provenance.get("qualification_inputs")
    if (
        not isinstance(qualification_inputs, Mapping)
        or qualification_inputs.get("qualification_authority") != authority
    ):
        raise ValueError("pilot compatibility finalized bundle uses another foundation")

    lineage_fields = (
        "source_result",
        "cohort",
        "fitting_contract",
        "sample_contributions",
        "algorithms",
    )
    if any(
        finalized.provenance.get(field) != numeric.provenance.get(field) for field in lineage_fields
    ):
        raise ValueError("pilot compatibility finalized bundle differs from pilot numeric lineage")
    for kind in ("traffic_morphing", "wtf_pad"):
        if finalized.artifact_hashes[kind] != numeric.artifact_hashes[kind]:
            raise ValueError(
                "pilot compatibility finalized bundle differs from pilot numeric artifacts"
            )

    finalized_walkie = load_json(finalized.root / BUNDLE_FILES["walkie_talkie"])
    numeric_walkie = load_json(numeric.root / BUNDLE_FILES["walkie_talkie"])
    if not isinstance(finalized_walkie, Mapping) or not isinstance(numeric_walkie, Mapping):
        raise TypeError("pilot Walkie-Talkie fitting artifact is malformed")
    unbound_walkie = dict(finalized_walkie)
    if unbound_walkie.pop("qualification_bindings", None) is None:
        raise ValueError("pilot finalized Walkie-Talkie artifact lacks qualification bindings")
    if canonical_json_bytes(unbound_walkie) != canonical_json_bytes(numeric_walkie):
        raise ValueError("pilot compatibility finalized Walkie-Talkie differs from numeric fitting")
    return finalized


def _qualified_pilot_pair_graph(
    finalized: VerifiedClassFittingBundle,
    pilot_ids: Sequence[str],
) -> tuple[tuple[tuple[str, str], ...], tuple[dict[str, Any], ...]]:
    """Return only pair-specific WT6 edges proven by frozen endpoint capacity."""

    order = {workload_id: index for index, workload_id in enumerate(pilot_ids)}
    if len(order) != len(pilot_ids) or len(pilot_ids) % 2:
        raise ValueError("pilot pair graph requires a unique positive even workload cohort")
    walkie = _load_json_object(
        finalized.root / BUNDLE_FILES["walkie_talkie"],
        "finalized pilot Walkie-Talkie artifact",
    )
    profiles = walkie.get("profiles")
    bindings = walkie.get("qualification_bindings")
    if not isinstance(profiles, list) or not isinstance(bindings, list):
        raise ValueError("finalized pilot Walkie-Talkie pair evidence is incomplete")

    binding_by_workload: dict[str, Mapping[str, Any]] = {}
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise ValueError("finalized pilot qualification binding is malformed")
        workload_id = binding.get("workload_id")
        if not isinstance(workload_id, str) or workload_id in binding_by_workload:
            raise ValueError("finalized pilot qualification binding is duplicated")
        binding_by_workload[workload_id] = binding
    if set(binding_by_workload) != set(pilot_ids):
        raise ValueError("finalized pilot qualification does not exactly cover the pilot cohort")

    receipts: list[tuple[tuple[str, str], dict[str, Any]]] = []
    covered: set[str] = set()
    observed_pairs: set[tuple[str, str]] = set()
    capacity_keys = (
        "chaff_qualification_sidecar_sha256",
        "prefix_pack_spec_sha256",
        "qualified_chaff_manifest_sha256",
        "qualified_parallel_chaff_streams",
        "walkie_talkie_required_chaff_streams",
    )
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise ValueError("finalized pilot Walkie-Talkie profile is malformed")
        real, decoy = profile.get("real"), profile.get("decoy")
        if (
            not isinstance(real, str)
            or not isinstance(decoy, str)
            or real == decoy
            or real not in order
            or decoy not in order
        ):
            raise ValueError("finalized pilot Walkie-Talkie profile pair is invalid")
        left, right = (real, decoy) if order[real] < order[decoy] else (decoy, real)
        pair = (left, right)
        if pair in observed_pairs or real in covered or decoy in covered:
            raise ValueError("finalized pilot Walkie-Talkie profiles are not one-to-one")
        observed_pairs.add(pair)
        covered.update((real, decoy))

        endpoint_receipts: list[dict[str, Any]] = []
        for workload_id in pair:
            binding = binding_by_workload[workload_id]
            required = binding.get("walkie_talkie_required_chaff_streams")
            qualified = binding.get("qualified_parallel_chaff_streams")
            if (
                type(required) is not int
                or type(qualified) is not int
                or required < 1
                or qualified < required
            ):
                raise ValueError(
                    "finalized pilot Walkie-Talkie pair lacks qualified endpoint capacity"
                )
            endpoint_receipts.append(
                {
                    "workload_id": workload_id,
                    **{key: binding[key] for key in capacity_keys},
                }
            )
        receipts.append(
            (
                pair,
                {
                    "left": left,
                    "right": right,
                    "runtime_profile_real": real,
                    "runtime_profile_decoy": decoy,
                    "runtime_profile_sha256": canonical_json_sha256(profile),
                    "endpoint_qualification": endpoint_receipts,
                },
            )
        )
    if covered != set(pilot_ids) or len(observed_pairs) != len(pilot_ids) // 2:
        raise ValueError("finalized pilot Walkie-Talkie pair graph is not a perfect matching")
    receipts.sort(key=lambda item: (order[item[0][0]], order[item[0][1]]))
    return (
        tuple(pair for pair, _receipt in receipts),
        tuple(receipt for _pair, receipt in receipts),
    )


def _qualified_final_pair_selection(
    pilot_admission: CohortAdmission,
    *,
    pilot_cohort: Mapping[str, Any],
    feasible_pairs: Sequence[Sequence[str]],
) -> CohortSelection:
    """Fail closed unless qualified edges pair the exact 100-class final cohort."""

    payload = validate_study_bound_receipt(
        pilot_cohort,
        expected_type=COHORT_RECEIPT_TYPE,
    )
    tranco = payload.get("tranco")
    list_sha256 = tranco.get("list_sha256") if isinstance(tranco, Mapping) else None
    if not isinstance(list_sha256, str):
        raise ValueError("pilot cohort lacks its Tranco list binding")
    try:
        selection = select_cohort(
            pilot_admission.selection.candidates,
            tranco_list_sha256=list_sha256,
            feasible_pairs=feasible_pairs,
        )
    except ValueError as error:
        raise ValueError(
            "qualified pilot pair graph cannot select a perfect 20-per-stratum final cohort"
        ) from error
    if (
        tuple(item.candidate_id for item in selection.pilot)
        != tuple(item.candidate_id for item in pilot_admission.selection.pilot)
        or len(selection.final) != FINAL_CLASS_COUNT
        or selection.matching is None
        or len(selection.matching) != FINAL_CLASS_COUNT // 2
    ):
        raise ValueError("qualified pilot pair graph produced an invalid final perfect matching")
    return selection


def validate_final_selection_input(
    value: Mapping[str, Any],
    *,
    pilot_admission: CohortAdmission,
    pilot_fitting_result_root: Path,
    pilot_numeric_bundle_root: Path,
    pilot_compatibility_result_root: Path,
    qualification_authority: Mapping[str, Any],
) -> tuple[tuple[str, str], ...]:
    """Recompute and return the exact pilot-bound feasible-pair graph."""

    payload = validate_study_bound_receipt(
        value, expected_type=FINAL_SELECTION_RECEIPT_TYPE
    )
    selection_schema_version = payload.get("selection_schema_version")
    if type(selection_schema_version) is int and selection_schema_version == 1:
        raise ValueError(
            "final-selection schema 1 is pre-publication and non-evidentiary"
        )
    if (
        type(selection_schema_version) is not int
        or selection_schema_version != FINAL_SELECTION_SCHEMA_VERSION
    ):
        raise ValueError("final-selection schema version is invalid")
    expected = build_final_selection_input(
        pilot_admission,
        pilot_fitting_result_root=pilot_fitting_result_root,
        pilot_numeric_bundle_root=pilot_numeric_bundle_root,
        pilot_compatibility_result_root=pilot_compatibility_result_root,
        qualification_authority=qualification_authority,
    )
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ValueError("final-selection input differs from verified pilot evidence")
    return tuple(tuple(pair) for pair in payload["feasible_pair_graph"])  # type: ignore[misc]


def write_final_selection_input(
    destination: Path,
    *,
    pilot_admission: CohortAdmission,
    pilot_fitting_result_root: Path,
    pilot_numeric_bundle_root: Path,
    pilot_compatibility_result_root: Path,
    qualification_authority: Mapping[str, Any],
) -> Path:
    """Create or byte-verify one immutable final-selection input receipt."""

    path = require_canonical_fresh_child(
        destination,
        field="study_config_root",
        filename=FINAL_SELECTION_FILENAME,
        label="final-selection input",
    )
    _require_fresh_admission_paths(pilot_admission, stage=PILOT_STAGE)
    require_canonical_fresh_path(
        pilot_numeric_bundle_root,
        field="pilot_numeric_root",
        label="pilot numeric bundle",
    )
    receipt = build_final_selection_input(
        pilot_admission,
        pilot_fitting_result_root=pilot_fitting_result_root,
        pilot_numeric_bundle_root=pilot_numeric_bundle_root,
        pilot_compatibility_result_root=pilot_compatibility_result_root,
        qualification_authority=qualification_authority,
    )
    _write_or_verify_bytes(
        path,
        canonical_json_bytes(receipt),
        label="final-selection input",
    )
    validate_final_selection_input(
        _load_json_object(path, "final-selection input"),
        pilot_admission=pilot_admission,
        pilot_fitting_result_root=pilot_fitting_result_root,
        pilot_numeric_bundle_root=pilot_numeric_bundle_root,
        pilot_compatibility_result_root=pilot_compatibility_result_root,
        qualification_authority=qualification_authority,
    )
    return path.resolve()


def publish_campaign_set(
    stage: str,
    pilot_admission: CohortAdmission,
    destination: Path,
    *,
    final_admission: CohortAdmission | None = None,
    pilot_cohort_reference: str | None = None,
    pilot_cohort_assembly_reference: str | None = None,
    final_cohort_reference: str | None = None,
    final_cohort_assembly_reference: str | None = None,
    pilot_bundle_reference: str = DEFAULT_PILOT_FINAL_REFERENCE,
    authoritative_bundle_reference: str = DEFAULT_AUTHORITATIVE_FINAL_REFERENCE,
) -> tuple[Path, ...]:
    """Publish two pilot documents, then 22 post-compatibility documents."""

    stage = _required_stage(stage)
    _require_fresh_admission_paths(pilot_admission, stage=PILOT_STAGE)
    pilot_cohort_reference = pilot_cohort_reference or canonical_campaign_reference(
        field="study_config_root",
        filename=pilot_admission.cohort_path.name,
    )
    pilot_cohort_assembly_reference = (
        pilot_cohort_assembly_reference
        or canonical_campaign_reference(
            field="study_config_root",
            filename=pilot_admission.assembly_path.name,
        )
    )
    final_cohort_reference = final_cohort_reference or (
        canonical_campaign_reference(
            field="study_config_root",
            filename=final_admission.cohort_path.name,
        )
        if final_admission is not None
        else DEFAULT_COHORT_REFERENCE
    )
    final_cohort_assembly_reference = final_cohort_assembly_reference or (
        canonical_campaign_reference(
            field="study_config_root",
            filename=final_admission.assembly_path.name,
        )
        if final_admission is not None
        else DEFAULT_COHORT_ASSEMBLY_REFERENCE
    )
    require_canonical_campaign_reference(
        pilot_cohort_reference,
        field="study_config_root",
        filename=pilot_admission.cohort_path.name,
        label="pilot cohort reference",
    )
    require_canonical_campaign_reference(
        pilot_cohort_assembly_reference,
        field="study_config_root",
        filename=pilot_admission.assembly_path.name,
        label="pilot cohort-assembly reference",
    )
    root = _regular_directory(
        require_canonical_fresh_path(
            destination,
            field="campaign_root",
            label="class-study campaign destination",
        ),
        "class-study campaign destination",
    )
    pilot_documents = _campaign_documents_with_assembly(
        pilot_admission.cohort_path,
        pilot_admission.assembly_path,
        cohort_reference=pilot_cohort_reference,
        cohort_assembly_reference=pilot_cohort_assembly_reference,
        pilot_bundle_reference=pilot_bundle_reference,
        authoritative_bundle_reference=authoritative_bundle_reference,
    )
    documents = {
        name: document
        for name, document in pilot_documents.items()
        if document["evidence_role"] in {"pilot-fitting", "pilot-compatibility"}
    }
    if len(documents) != 2:
        raise AssertionError("class campaign generator did not return two pilot roles")
    if stage == AUTHORITATIVE_STAGE:
        if final_admission is None:
            raise ValueError("authoritative campaign publication requires final cohort admission")
        _require_fresh_admission_paths(
            final_admission,
            stage=AUTHORITATIVE_STAGE,
        )
        require_canonical_campaign_reference(
            final_cohort_reference,
            field="study_config_root",
            filename=final_admission.cohort_path.name,
            label="final cohort reference",
        )
        require_canonical_campaign_reference(
            final_cohort_assembly_reference,
            field="study_config_root",
            filename=final_admission.assembly_path.name,
            label="final cohort-assembly reference",
        )
        final_documents = _campaign_documents_with_assembly(
            final_admission.cohort_path,
            final_admission.assembly_path,
            cohort_reference=final_cohort_reference,
            cohort_assembly_reference=final_cohort_assembly_reference,
            pilot_bundle_reference=pilot_bundle_reference,
            authoritative_bundle_reference=authoritative_bundle_reference,
        )
        documents.update(
            {
                name: document
                for name, document in final_documents.items()
                if document["evidence_role"] not in {"pilot-fitting", "pilot-compatibility"}
            }
        )
        if len(documents) != CAMPAIGN_SET_FILES:
            raise AssertionError("class campaign generator did not return the full role set")

    expected_names = set(documents)
    unexpected = sorted(path.name for path in root.iterdir() if path.name not in expected_names)
    if unexpected:
        raise ValueError(
            "class-study campaign destination contains unexpected entries: " + ", ".join(unexpected)
        )
    paths: list[Path] = []
    for filename, document in documents.items():
        encoded = yaml.safe_dump(document, sort_keys=False, width=100).encode("utf-8")
        path = root / filename
        _write_or_verify_bytes(path, encoded, label="campaign")
        paths.append(path.resolve())
    _fsync_directory(root)
    verify_campaign_set(
        root,
        pilot_admission=pilot_admission,
        final_admission=final_admission,
        expected_stage=stage,
    )
    return tuple(paths)


def verify_campaign_set(
    root: Path,
    *,
    pilot_admission: CohortAdmission,
    final_admission: CohortAdmission | None = None,
    expected_stage: str,
) -> dict[str, Any]:
    """Validate the exact stage inventory and distinct cohort bindings."""

    stage = _required_stage(expected_stage)
    directory = _regular_directory(root, "class-study campaign root")
    files = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
    expected_files = 2 if stage == PILOT_STAGE else CAMPAIGN_SET_FILES
    if len(files) != expected_files or any(
        path.is_symlink() or not path.is_file() or path.suffix != ".yml" for path in files
    ):
        raise ValueError(
            f"class-study {stage} campaign root must contain exactly "
            f"{expected_files} regular YAML files"
        )
    documents: dict[str, Mapping[str, Any]] = {}
    for path in files:
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValueError(f"class-study campaign is invalid YAML: {path}") from error
        if not isinstance(value, Mapping):
            raise TypeError(f"class-study campaign is not an object: {path}")
        role = value.get("evidence_role")
        admission = (
            pilot_admission if role in {"pilot-fitting", "pilot-compatibility"} else final_admission
        )
        if admission is None:
            raise ValueError("post-pilot campaign has no final cohort admission")
        _require_campaign_reference_binding(
            directory,
            value.get("class_study_cohort"),
            expected_path=admission.cohort_path,
            expected_sha256=admission.cohort_sha256,
            label="cohort",
        )
        _require_campaign_reference_binding(
            directory,
            value.get("class_study_cohort_assembly"),
            expected_path=admission.assembly_path,
            expected_sha256=admission.assembly_sha256,
            label="cohort assembly",
        )
        documents[path.name] = value
    pilot_ids = tuple(item.candidate_id for item in pilot_admission.selection.pilot)
    if stage == PILOT_STAGE:
        if {document["evidence_role"] for document in documents.values()} != {
            "pilot-fitting",
            "pilot-compatibility",
        }:
            raise ValueError("pilot campaign root contains a post-pilot evidence role")
        _validate_pilot_campaign_documents(documents, pilot_admission)
    else:
        if final_admission is None:
            raise ValueError("full campaign verification requires final cohort admission")
        final_ids = tuple(item.candidate_id for item in final_admission.selection.final)
        validate_campaign_documents(documents, pilot_ids=pilot_ids, final_ids=final_ids)
        _validate_full_campaign_documents(
            documents,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
        )
    return {
        "valid": True,
        "root": str(directory),
        "stage": stage,
        "files": expected_files,
        "pilot_cohort_sha256": pilot_admission.cohort_sha256,
        "pilot_cohort_assembly_sha256": pilot_admission.assembly_sha256,
        "final_cohort_sha256": (
            final_admission.cohort_sha256 if final_admission is not None else None
        ),
        "final_cohort_assembly_sha256": (
            final_admission.assembly_sha256 if final_admission is not None else None
        ),
        "campaign_sha256": {path.name: sha256_file(path) for path in files},
    }


def verify_class_study_result(
    root: Path,
    *,
    admission: CohortAdmission,
    expected_role: str | None = None,
    expected_block: int | None = None,
) -> dict[str, Any]:
    """Verify a sealed result, its evidence role, exact cross-product and admission."""

    verified = verify_result(root)
    return _validate_verified_class_result(
        verified,
        admission=admission,
        expected_role=expected_role,
        expected_block=expected_block,
    )


def class_study_status(
    *,
    candidate_catalogue_path: Path | None = None,
    stability_root: Path | None = None,
    workload_root: Path | None = None,
    acquisition_completion_path: Path | None = None,
    acquisition_root: Path | None = None,
    pilot_cohort_receipt_path: Path | None = None,
    pilot_cohort_assembly_path: Path | None = None,
    final_cohort_receipt_path: Path | None = None,
    final_cohort_assembly_path: Path | None = None,
    final_selection_path: Path | None = None,
    campaign_root: Path | None = None,
    result_roots: Sequence[Path] = (),
    numeric_bundle_roots: Sequence[Path] = (),
    prefix_spec_roots: Sequence[Path] = (),
    qualification_manifests: Sequence[Path] = (),
    final_bundle_roots: Sequence[Path] = (),
    handoff: Path | None = None,
    evaluation_receipt: Path | None = None,
    foundation_attestation: Path | None = None,
    acquisition_authority: Path | None = None,
    readiness_attestation: Path | None = None,
    historical_pre_snapshot: Path | None = None,
    historical_post_snapshot: Path | None = None,
    comparison_review: Path | None = None,
    validation_attestation: Path | None = None,
    deep: bool = False,
) -> dict[str, Any]:
    """Return an evidence-derived progress ledger without creating anything."""

    stages: dict[str, Any] = {}
    from .class_attestation import (
        class_qualification_authority,
        validate_class_acquisition_authority,
        validate_class_comparison_review,
        validate_class_foundation_attestation,
        validate_class_historical_snapshot,
        validate_class_readiness_attestation,
        validate_class_validation_attestation,
        validate_current_acquisition_completion_authority,
    )

    verified_foundation: dict[str, Any] | None = None
    if foundation_attestation is not None:
        verified_foundation = validate_class_foundation_attestation(
            foundation_attestation,
            # A displayed acquisition state is only verified after the same
            # complete foundation reconstruction required by live acquisition.
            deep_code_gate=deep or acquisition_root is not None,
            runtime_role="collection",
        )
        stages["foundation"] = {"state": "verified", **verified_foundation}
    else:
        stages["foundation"] = {"state": "absent"}
    verified_acquisition = None
    if acquisition_authority is not None:
        inspected_acquisition = validate_class_acquisition_authority(
            acquisition_authority,
            runtime_role="collection",
            allow_historical=True,
        )
        historical_acquisition = (
            inspected_acquisition.get("verification_status") == "historical-verify-only"
        )
        stages["acquisition_authority"] = {
            "state": "historical-verify-only" if historical_acquisition else "verified",
            **inspected_acquisition,
        }
        if not historical_acquisition:
            verified_acquisition = inspected_acquisition
    else:
        stages["acquisition_authority"] = {"state": "absent"}
    acquisition_gate = verified_acquisition or verified_foundation
    qualification_authority: dict[str, Any] | None = None
    if qualification_manifests or final_bundle_roots or final_selection_path is not None:
        if foundation_attestation is None:
            raise ValueError(
                "qualification/final fitting/selection status requires --foundation-attestation"
            )
        qualification_authority = class_qualification_authority(
            foundation_attestation,
            deep_code_gate=deep,
            runtime_role="collection",
        )
    stages["stability"] = {
        "state": "absent",
        "gate": stability_gate(),
    }
    if candidate_catalogue_path is not None:
        _receipt, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
        stages["catalogue"] = {
            "state": "verified",
            "path": str(Path(candidate_catalogue_path).resolve()),
            "candidate_count": len(candidates),
        }
        if stability_root is not None:
            stages["stability"] = {
                "state": "verified-present-receipts",
                **stability_status(candidate_catalogue_path, stability_root),
            }
    else:
        stages["catalogue"] = {"state": "absent"}

    if acquisition_root is None:
        stages["acquisition_runner"] = {"state": "absent", "gate": stability_gate()}
    elif candidate_catalogue_path is None:
        stages["acquisition_runner"] = {
            "state": "unverified",
            "reason": "acquisition runner status requires the candidate catalogue",
            "gate": stability_gate(),
        }
    else:
        from . import class_acquisition

        runner_status = class_acquisition.acquisition_status(
            acquisition_root,
            candidate_catalogue_path=candidate_catalogue_path,
        )
        acquisition_stage = {
            **runner_status,
            "state": "unverified",
            "root": str(Path(acquisition_root).resolve()),
            "gate": stability_gate(),
            "authoritative": False,
        }
        if acquisition_gate is None:
            acquisition_stage["reason"] = (
                "acquisition runner status requires --acquisition-authority or "
                "--foundation-attestation for "
                "current deep gate verification"
            )
        elif (
            runner_status.get("acquisition_schema_version")
            != class_acquisition.SCHEMA_VERSION
        ):
            acquisition_stage["reason"] = (
                "historical acquisition runners are verify-only and cannot carry "
                "current gate authority"
            )
        else:
            provenance_path = _regular_file(
                Path(acquisition_root) / "provenance.json",
                "class acquisition provenance",
            )
            provenance = validate_hash_bound_receipt(
                _load_json_object(provenance_path, "class acquisition provenance"),
                expected_type=class_acquisition.PROVENANCE_TYPE,
            )
            foundation_binding = provenance.get(
                "acquisition_authority", provenance.get("foundation_attestation")
            )
            if (
                not isinstance(foundation_binding, Mapping)
                or set(foundation_binding) != {"path", "sha256"}
                or not isinstance(foundation_binding.get("path"), str)
                or not isinstance(foundation_binding.get("sha256"), str)
            ):
                raise ValueError("class acquisition provenance has no exact foundation binding")
            bound_foundation = _regular_file(
                Path(foundation_binding["path"]),
                "class acquisition foundation",
            )
            if (
                str(bound_foundation) != acquisition_gate.get("path")
                or foundation_binding["sha256"] != acquisition_gate.get("sha256")
                or sha256_file(bound_foundation) != foundation_binding["sha256"]
            ):
                raise ValueError(
                    "class acquisition runner uses another foundation attestation"
                )
            acquisition_stage.update(
                {
                    "state": "verified",
                    "gate_verification": {
                        (
                            "acquisition_authority_path"
                            if "acquisition_authority" in provenance
                            else "foundation_path"
                        ): str(bound_foundation),
                        (
                            "acquisition_authority_sha256"
                            if "acquisition_authority" in provenance
                            else "foundation_sha256"
                        ): foundation_binding["sha256"],
                        "browser_egress_vectors": acquisition_gate["summary"][
                            "browser_egress_vectors"
                        ],
                        "informational_only": True,
                    },
                }
            )
        stages["acquisition_runner"] = acquisition_stage

    if acquisition_completion_path is None:
        stages["acquisition_completion"] = {"state": "absent"}
    elif candidate_catalogue_path is None:
        stages["acquisition_completion"] = {
            "state": "unverified",
            "reason": "acquisition completion verification requires the candidate catalogue",
        }
    else:
        from . import class_acquisition as acquisition_module

        completion_path = _regular_file(acquisition_completion_path, "acquisition completion")
        completion_value = _load_json_object(completion_path, "acquisition completion")
        completion_payload = acquisition_module.validate_acquisition_completion(
            completion_value,
            candidate_catalogue_path=candidate_catalogue_path,
            runner_root=completion_path.parent,
        )
        current_completion = all(
            type(completion_payload.get(field)) is int and completion_payload[field] == expected
            for field, expected in (
                ("acquisition_schema_version", acquisition_module.SCHEMA_VERSION),
                (
                    "completion_schema_version",
                    acquisition_module.COMPLETION_SCHEMA_VERSION,
                ),
                (
                    "checkpoint_schema_version",
                    acquisition_module.CHECKPOINT_SCHEMA_VERSION,
                ),
            )
        )
        if current_completion:
            validate_current_acquisition_completion_authority(
                completion_payload,
                runner_root=completion_path.parent,
            )
        stages["acquisition_completion"] = {
            "state": "verified" if current_completion else "historical-verify-only",
            "path": str(completion_path),
            "sha256": sha256_file(completion_path),
            "payload_sha256": completion_value["payload_sha256"],
            "terminal_candidates": len(completion_payload["terminal_receipts"]),
            **({} if current_completion else {"verification_status": "historical-verify-only"}),
        }

    pilot_admission = _optional_admission(
        pilot_cohort_receipt_path,
        pilot_cohort_assembly_path,
        candidate_catalogue_path=candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        final_selection_receipt_path=None,
    )
    final_admission = _optional_admission(
        final_cohort_receipt_path,
        final_cohort_assembly_path,
        candidate_catalogue_path=candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        final_selection_receipt_path=final_selection_path,
    )
    stages["pilot_cohort"] = (
        {"state": "verified", **pilot_admission.as_dict()}
        if pilot_admission is not None
        else {"state": "absent"}
    )
    stages["final_cohort"] = (
        {"state": "verified", **final_admission.as_dict()}
        if final_admission is not None
        else {"state": "absent"}
    )

    if campaign_root is not None:
        if pilot_admission is None:
            stages["campaigns"] = {
                "state": "unverified",
                "reason": "campaign verification requires pilot cohort admission",
            }
        else:
            observed_files = len(tuple(Path(campaign_root).iterdir()))
            campaign_stage = PILOT_STAGE if observed_files == 2 else AUTHORITATIVE_STAGE
            stages["campaigns"] = {
                "state": "verified",
                **verify_campaign_set(
                    campaign_root,
                    pilot_admission=pilot_admission,
                    final_admission=final_admission,
                    expected_stage=campaign_stage,
                ),
            }
    else:
        stages["campaigns"] = {"state": "absent"}

    result_records: list[dict[str, Any]] = []
    if result_roots:
        result_records = _result_index(
            result_roots,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
        )
    stages["results"] = _result_status_summary(result_records)

    numeric: list[dict[str, Any]] = []
    verified_numeric_roots: dict[Path, VerifiedNumericFittingBundle] = {}
    for path in numeric_bundle_roots:
        staged = verify_numeric_fitting_bundle(path)
        role = "pilot-fitting" if staged.stage == PILOT_STAGE else "authoritative-fitting"
        matches = [record for record in result_records if record["evidence_role"] == role]
        if len(matches) != 1:
            numeric.append(
                {
                    "state": "unverified",
                    "root": str(Path(path).resolve()),
                    "reason": f"numeric fitting verification requires one {role} result",
                }
            )
            continue
        verified = verify_numeric_fitting_bundle(
            path,
            source_result_root=Path(matches[0]["root"]),
        )
        numeric.append(verified.as_dict())
        verified_numeric_roots[Path(path).resolve()] = verified
    stages["numeric_fitting"] = {
        "state": (
            "verified"
            if numeric and all(item.get("valid") is True for item in numeric)
            else "absent"
            if not numeric
            else "unverified"
        ),
        "bundles": numeric,
    }

    if final_selection_path is None:
        stages["final_selection"] = {"state": "absent"}
    elif pilot_admission is None:
        stages["final_selection"] = {
            "state": "unverified",
            "reason": "final selection requires pilot cohort admission",
        }
    else:
        pilot_numeric = [
            path
            for path in numeric_bundle_roots
            if (verified := verified_numeric_roots.get(Path(path).resolve())) is not None
            and verified.stage == PILOT_STAGE
        ]
        pilot_fitting = [
            record for record in result_records if record["evidence_role"] == "pilot-fitting"
        ]
        compatibility = [
            record for record in result_records if record["evidence_role"] == "pilot-compatibility"
        ]
        if len(pilot_numeric) != 1 or len(pilot_fitting) != 1 or len(compatibility) != 1:
            stages["final_selection"] = {
                "state": "unverified",
                "reason": (
                    "final selection requires one pilot fitting result, one pilot "
                    "numeric bundle, and one pilot-compatibility result"
                ),
            }
        else:
            value = _load_json_object(final_selection_path, "final-selection input")
            pairs = validate_final_selection_input(
                value,
                pilot_admission=pilot_admission,
                pilot_fitting_result_root=Path(pilot_fitting[0]["root"]),
                pilot_numeric_bundle_root=pilot_numeric[0],
                pilot_compatibility_result_root=Path(compatibility[0]["root"]),
                qualification_authority=qualification_authority,
            )
            stages["final_selection"] = {
                "state": "verified",
                "path": str(Path(final_selection_path).resolve()),
                "sha256": sha256_file(final_selection_path),
                "feasible_pairs": len(pairs),
            }

    prefixes: list[dict[str, Any]] = []
    for path in prefix_spec_roots:
        matches = [
            item
            for item in numeric_bundle_roots
            if Path(item).resolve() in verified_numeric_roots
            and _stage_from_name(item.name) == _stage_from_name(path.name)
        ]
        if workload_root is None or len(matches) != 1:
            prefixes.append(
                {
                    "state": "unverified",
                    "root": str(Path(path).resolve()),
                    "reason": (
                        "prefix verification requires one matching numeric bundle and workload root"
                    ),
                }
            )
        else:
            prefixes.append(
                _verify_prefix_spec_root(
                    path,
                    numeric_bundle_root=matches[0],
                    workload_root=workload_root,
                )
            )
    stages["prefix_specs"] = {
        "state": "verified"
        if prefixes and all(item.get("valid") for item in prefixes)
        else "absent"
        if not prefixes
        else "unverified",
        "roots": prefixes,
    }

    qualifications: list[dict[str, Any]] = []
    if qualification_manifests:
        if workload_root is None:
            raise ValueError("qualification status requires a workload root")
        prefix_by_stage = {_stage_from_name(path.name): path for path in prefix_spec_roots}
        for manifest_path in qualification_manifests:
            stage = _stage_from_qualification_path(manifest_path)
            prefix_root = prefix_by_stage.get(stage)
            if prefix_root is None:
                raise ValueError("qualification status requires its matching prefix-spec root")
            output = load_named_qualification_set(
                manifest_path,
                workload_root=workload_root,
                sidecar_root=manifest_path.parent,
                prefix_spec_root=prefix_root,
                expected_qualification_set=_qualification_set(stage),
                expected_qualification_scope=FULL_QUALIFICATION_SCOPE,
                expected_workload_ids=_stage_workloads(
                    _admission_for_stage(stage, pilot_admission, final_admission), stage
                ),
                expected_qualification_authority=qualification_authority,
            )
            _validate_qualification_sidecars(
                manifest_path.parent,
                _stage_workloads(
                    _admission_for_stage(stage, pilot_admission, final_admission), stage
                ),
                qualification_authority,
            )
            qualifications.append(
                {
                    "valid": True,
                    "stage": stage,
                    "root": str(output.path),
                    "manifest_sha256": output.manifest_sha256,
                    "workloads": len(output.workload_ids),
                }
            )
    stages["qualification"] = {
        "state": "verified" if qualifications else "absent",
        "sets": qualifications,
    }

    finals: list[dict[str, Any]] = []
    for root in final_bundle_roots:
        stage = _stage_from_name(root.name)
        role = "pilot-fitting" if stage == PILOT_STAGE else "authoritative-fitting"
        matching_results = [record for record in result_records if record["evidence_role"] == role]
        matching_qualification = [
            path
            for path in qualification_manifests
            if _stage_from_qualification_path(path) == stage
        ]
        matching_prefix = [
            path for path in prefix_spec_roots if _stage_from_name(path.name) == stage
        ]
        if (
            workload_root is None
            or len(matching_results) != 1
            or len(matching_qualification) != 1
            or len(matching_prefix) != 1
        ):
            finals.append(
                {
                    "state": "unverified",
                    "root": str(Path(root).resolve()),
                    "reason": (
                        "final verification requires one matching fitting result plus "
                        "workload, qualification, and prefix evidence"
                    ),
                }
            )
            continue
        context = QualificationContext(
            workload_root=workload_root,
            sidecar_root=matching_qualification[0].parent,
            prefix_spec_root=matching_prefix[0],
            qualification_authority=qualification_authority,
        )
        finals.append(
            verify_class_fitting_bundle(
                root,
                qualification_context=context,
                source_result_root=Path(matching_results[0]["root"]),
            ).as_dict()
        )
    stages["final_fitting"] = {
        "state": "verified"
        if finals and all(item.get("valid") for item in finals)
        else "absent"
        if not finals
        else "unverified",
        "bundles": finals,
    }

    if handoff is not None:
        verified_handoff = verify_class_handoff(handoff, deep=deep)
        stages["handoff"] = {"state": "verified", "root": str(verified_handoff)}
    else:
        stages["handoff"] = {"state": "absent"}
    if evaluation_receipt is not None:
        if handoff is None:
            stages["evaluation"] = {
                "state": "unverified",
                "reason": "evaluation verification requires its formal handoff",
            }
        else:
            from .class_evaluation import verify_class_evaluation_receipt

            evaluation = verify_class_evaluation_receipt(
                evaluation_receipt,
                handoff_root=handoff,
                deep_verify_handoff=deep,
            )
            stages["evaluation"] = {"state": "verified", **evaluation}
    else:
        stages["evaluation"] = {"state": "absent"}

    stages["readiness"] = (
        {
            "state": "verified",
            **validate_class_readiness_attestation(
                readiness_attestation,
                deep_code_gate=deep,
            ),
        }
        if readiness_attestation is not None
        else {"state": "absent"}
    )
    stages["historical_pre_snapshot"] = (
        {
            "state": "verified",
            **validate_class_historical_snapshot(
                historical_pre_snapshot,
                expected_phase="pre-formal",
            ),
        }
        if historical_pre_snapshot is not None
        else {"state": "absent"}
    )
    stages["historical_post_snapshot"] = (
        {
            "state": "verified",
            **validate_class_historical_snapshot(
                historical_post_snapshot,
                expected_phase="post-formal",
            ),
        }
        if historical_post_snapshot is not None
        else {"state": "absent"}
    )
    stages["comparison_review"] = (
        {
            "state": "verified",
            **validate_class_comparison_review(comparison_review),
        }
        if comparison_review is not None
        else {"state": "absent"}
    )
    stages["validation_attestation"] = (
        {
            "state": "verified",
            **validate_class_validation_attestation(
                validation_attestation,
                deep_code_gate=deep,
            ),
        }
        if validation_attestation is not None
        else {"state": "absent"}
    )

    return {
        "study_id": STUDY_ID,
        "claim": "prospective-100-class-eight-mode-study",
        "stages": stages,
        "certification_contract": {
            "classes": FINAL_CLASS_COUNT,
            "modes": list(COMPATIBILITY_MODES),
            "expected_unique_class_mode_pairs": CERTIFICATION_PAIR_COUNT,
            "first_launch_only": True,
            "accepted_and_eligible_required": True,
        },
        "next_required_stage": _next_required_stage(stages, result_records),
        "attestation_generated": stages["validation_attestation"]["state"] == "verified",
    }


def run_class_study_action(
    action: str,
    *,
    stage: str | None = None,
    candidate_catalogue_path: Path | None = None,
    stability_root: Path | None = None,
    stability_input: Path | None = None,
    workload_root: Path | None = None,
    acquisition_completion_path: Path | None = None,
    acquisition_root: Path | None = None,
    acquisition_started_at: str | None = None,
    acquisition_browser_tool: str = "playwright-chromium",
    acquisition_max_candidates: int = MAX_CANDIDATES_PER_ACTION,
    acquisition_timeout_ms: int = 60_000,
    pilot_cohort_receipt_path: Path | None = None,
    pilot_cohort_assembly_path: Path | None = None,
    final_cohort_receipt_path: Path | None = None,
    final_cohort_assembly_path: Path | None = None,
    cohort_receipt_path: Path | None = None,
    cohort_assembly_path: Path | None = None,
    final_selection_path: Path | None = None,
    campaign_root: Path | None = None,
    campaign: Path | None = None,
    results_root: Path | None = None,
    capture_result: Path | None = None,
    result_roots: Sequence[Path] = (),
    regression_result_roots: Sequence[Path] = (),
    controlled_result_roots: Sequence[Path] = (),
    canary_result_roots: Sequence[Path] = (),
    formal_result_roots: Sequence[Path] = (),
    artifacts_root: Path | None = None,
    numeric_bundle_root: Path | None = None,
    numeric_bundle_roots: Sequence[Path] = (),
    prefix_spec_root: Path | None = None,
    prefix_spec_roots: Sequence[Path] = (),
    qualification_checkpoint: Path | None = None,
    qualification_sidecar_root: Path | None = None,
    qualification_publication_root: Path | None = None,
    qualification_manifest: Path | None = None,
    qualification_manifests: Sequence[Path] = (),
    qualification_workload: str | None = None,
    qualify_all_pending: bool = False,
    final_bundle_root: Path | None = None,
    final_bundle_roots: Sequence[Path] = (),
    handoff: Path | None = None,
    evaluation_receipt: Path | None = None,
    cohort_version: int | None = None,
    build_execution_receipt: Path | None = None,
    pinned_cdp_receipt: Path | None = None,
    browser_egress_qualification_root: Path | None = None,
    reference_receipt: Path | None = None,
    code_gate_receipt: Path | None = None,
    controlled_qualification_receipt: Path | None = None,
    pilot_fitting_result: Path | None = None,
    pilot_compatibility_result: Path | None = None,
    authoritative_fitting_result: Path | None = None,
    certification_result: Path | None = None,
    foundation_attestation: Path | None = None,
    acquisition_authority: Path | None = None,
    readiness_attestation: Path | None = None,
    historical_pre_snapshot: Path | None = None,
    historical_post_snapshot: Path | None = None,
    snapshot_phase: str | None = None,
    comparison_review: Path | None = None,
    validation_attestation: Path | None = None,
    successor_policy: Path | None = None,
    successor_decision: Path | None = None,
    successor_restart: Path | None = None,
    comparison_review_input: Path | None = None,
    reviewer: str | None = None,
    reviewed_at: str | None = None,
    destination: Path | None = None,
    target: Path | None = None,
    execute: bool = False,
    deep: bool = True,
    dlsvm_cache_directory: Path | None = None,
) -> ClassStudyActionResult:
    """Execute one explicit class-study boundary.

    Every mutation is create-only or delegated to the existing resumable
    campaign/qualification implementation.  A capture is launched only when
    ``execute=True``; otherwise the same validation path returns safe guidance.
    """

    if action not in STUDY_ACTIONS:
        raise ValueError(f"class-study action must be one of: {', '.join(STUDY_ACTIONS)}")
    status_numeric_bundle_roots = _status_artifact_inputs(
        action,
        numeric_bundle_roots,
        numeric_bundle_root,
        option="--numeric-bundle",
    )
    status_prefix_spec_roots = _status_artifact_inputs(
        action,
        prefix_spec_roots,
        prefix_spec_root,
        option="--prefix-spec-root",
    )
    status_qualification_manifests = _status_artifact_inputs(
        action,
        qualification_manifests,
        qualification_manifest,
        option="--qualification-manifest",
    )
    status_final_bundle_roots = _status_artifact_inputs(
        action,
        final_bundle_roots,
        final_bundle_root,
        option="--final-bundle",
    )
    successor_context = _successor_action_context(
        action,
        successor_restart=successor_restart,
        foundation_attestation=foundation_attestation,
        campaign=campaign,
        workload_root=workload_root,
        artifacts_root=artifacts_root,
        numeric_bundle_root=numeric_bundle_root,
        prefix_spec_root=prefix_spec_root,
        qualification_checkpoint=qualification_checkpoint,
        qualification_sidecar_root=qualification_sidecar_root,
        qualification_publication_root=qualification_publication_root,
        qualification_manifest=qualification_manifest,
        final_bundle_root=final_bundle_root,
        snapshot_phase=snapshot_phase,
        destination=destination,
    )
    if successor_context is not None:
        artifacts_root = successor_context["artifacts_root"]
        numeric_bundle_root = successor_context["numeric_bundle_root"]
        prefix_spec_root = successor_context["prefix_spec_root"]
        qualification_checkpoint = successor_context["qualification_checkpoint"]
        qualification_sidecar_root = successor_context["qualification_sidecar_root"]
        qualification_publication_root = successor_context["qualification_publication_root"]
        qualification_manifest = successor_context["qualification_manifest"]
        final_bundle_root = successor_context["final_bundle_root"]
    else:
        _validate_fresh_layout_arguments(
            action=action,
            stage=stage,
            candidate_catalogue_path=candidate_catalogue_path,
            acquisition_root=acquisition_root,
            stability_root=stability_root,
            workload_root=workload_root,
            pilot_cohort_receipt_path=pilot_cohort_receipt_path,
            pilot_cohort_assembly_path=pilot_cohort_assembly_path,
            final_cohort_receipt_path=final_cohort_receipt_path,
            final_cohort_assembly_path=final_cohort_assembly_path,
            cohort_receipt_path=cohort_receipt_path,
            cohort_assembly_path=cohort_assembly_path,
            final_selection_path=final_selection_path,
            campaign_root=campaign_root,
            campaign=campaign,
            artifacts_root=artifacts_root,
            numeric_bundle_root=numeric_bundle_root,
            prefix_spec_root=prefix_spec_root,
            qualification_sidecar_root=qualification_sidecar_root,
            qualification_publication_root=qualification_publication_root,
            qualification_manifest=qualification_manifest,
            final_bundle_root=final_bundle_root,
            destination=destination,
        )
    if action in {
        "acquisition-init",
        "acquisition-run",
        "acquisition-status",
        "acquisition-complete",
    }:
        from . import class_acquisition
        from .class_acquisition import (
            ExistingAcquisitionBackend,
            acquisition_status,
            initialise_runner,
            run_due_acquisition,
            validate_acquisition_completion,
            write_acquisition_completion,
        )

        catalogue = _required(candidate_catalogue_path, "--candidate-catalogue")
        runner = _required(acquisition_root, "--acquisition-root")
        if action == "acquisition-init":
            if not isinstance(acquisition_started_at, str) or not acquisition_started_at:
                raise ValueError("acquisition initialisation requires --acquisition-started-at")
            from .class_attestation import (
                validate_class_acquisition_authority,
                validate_class_foundation_attestation,
            )

            if acquisition_authority is not None and foundation_attestation is not None:
                raise ValueError("acquisition initialisation accepts one authority, not both")
            if acquisition_authority is not None:
                foundation_path = acquisition_authority
                foundation = validate_class_acquisition_authority(
                    foundation_path, runtime_role="prepare"
                )
            else:
                foundation_path = _required(
                    foundation_attestation,
                    "--acquisition-authority or --foundation-attestation",
                )
                foundation = validate_class_foundation_attestation(
                    foundation_path, deep_code_gate=True, runtime_role="prepare"
                )
            if _class_aware_timestamp(
                foundation.get("recorded_at"), label="foundation attestation"
            ) > _class_aware_timestamp(acquisition_started_at, label="acquisition start"):
                raise ValueError("class acquisition starts before its foundation gate")
            authority_argument = (
                {"acquisition_authority": foundation_path}
                if acquisition_authority is not None
                else {"foundation_attestation": foundation_path}
            )
            output = initialise_runner(
                runner,
                candidate_catalogue_path=catalogue,
                **authority_argument,
                started_at=acquisition_started_at,
                browser_tool=acquisition_browser_tool,
            )
            details = acquisition_status(output, candidate_catalogue_path=catalogue)
            details.update({"valid": True, "runner_root": str(output.resolve())})
            return ClassStudyActionResult(action, "complete", details)
        if action == "acquisition-status":
            provenance_path = _regular_file(
                Path(runner) / "provenance.json",
                "class acquisition provenance",
            )
            provenance = validate_hash_bound_receipt(
                _load_json_object(provenance_path, "class acquisition provenance"),
                expected_type=class_acquisition.PROVENANCE_TYPE,
            )
            # A status snapshot is operational guidance, not promotion
            # authority.  It nevertheless runs under the exact same current
            # prepare-image, source, and deeply reconstructed foundation
            # contract as a mutating acquisition action.
            class_acquisition._validate_runner_runtime(provenance)
            foundation_binding = provenance.get(
                "acquisition_authority", provenance.get("foundation_attestation")
            )
            if (
                not isinstance(foundation_binding, Mapping)
                or set(foundation_binding) != {"path", "sha256"}
                or not isinstance(foundation_binding.get("path"), str)
                or not isinstance(foundation_binding.get("sha256"), str)
                or _SHA256.fullmatch(foundation_binding["sha256"]) is None
            ):
                raise ValueError("class acquisition provenance has no exact foundation binding")
            details = acquisition_status(runner, candidate_catalogue_path=catalogue)
            details.update(
                {
                    "valid": True,
                    "runner_root": str(Path(runner).resolve()),
                    "gate": stability_gate(),
                    "authoritative": False,
                    "gate_verification": {
                        (
                            "acquisition_authority_path"
                            if "acquisition_authority" in provenance
                            else "foundation_path"
                        ): foundation_binding["path"],
                        (
                            "acquisition_authority_sha256"
                            if "acquisition_authority" in provenance
                            else "foundation_sha256"
                        ): foundation_binding["sha256"],
                        "informational_only": True,
                    },
                }
            )
            return ClassStudyActionResult(action, "complete", details)
        if action == "acquisition-run":
            # This is a production evidence boundary, not an unbounded batching
            # interface. Keep the coordinator fail-closed so invoking the
            # in-image CLI cannot exceed the immutable two-candidate/global-page
            # bounds or substitute another browser timeout.
            if (
                type(acquisition_max_candidates) is not int
                or not 1 <= acquisition_max_candidates <= MAX_CANDIDATES_PER_ACTION
                or acquisition_timeout_ms != 60_000
            ):
                raise ValueError(
                    "acquisition-run requires --acquisition-max-candidates 1 or 2 "
                    "and --acquisition-timeout-ms 60000"
                )
            details = run_due_acquisition(
                runner,
                candidate_catalogue_path=catalogue,
                stability_root=_required(stability_root, "--stability-root"),
                workload_root=_required(workload_root, "--workload-root"),
                backend=ExistingAcquisitionBackend(timeout_ms=acquisition_timeout_ms),
                max_candidates=acquisition_max_candidates,
            )
            if (
                details.get("maximum_candidates_per_action")
                != MAX_CANDIDATES_PER_ACTION
                or details.get("global_live_page_cap") != GLOBAL_LIVE_PAGE_CAP
            ):
                raise ValueError("acquisition-run returned another immutable batch contract")
            details.update(
                {
                    "valid": True,
                    "runner_root": str(Path(runner).resolve()),
                    "bounded_candidates": acquisition_max_candidates,
                    "runner_wait_policy": dict(ACQUISITION_RUN_WAIT_POLICY),
                }
            )
            return ClassStudyActionResult(
                action,
                "ready" if details["complete"] else "pending",
                details,
                ()
                if details["complete"]
                else (
                    (
                        "rerun now; bounded acquisition work is due: interrupted recovery, "
                        "deterministic finalisation, missed-window terminalisation, a live "
                        "probe, or an unblocked navigation/baseline batch"
                    )
                    if details.get("work_due_now") is True
                    else (
                        "rerun when next_due is reached; the host watcher waits between "
                        "the t+24h and t+72h probe actions"
                    ),
                ),
            )
        completion = write_acquisition_completion(
            runner,
            candidate_catalogue_path=catalogue,
        )
        value = _load_json_object(completion, "acquisition completion")
        payload = validate_acquisition_completion(
            value,
            candidate_catalogue_path=catalogue,
            runner_root=Path(runner),
        )
        return ClassStudyActionResult(
            action,
            "complete",
            {
                "valid": True,
                "path": str(completion.resolve()),
                "sha256": sha256_file(completion),
                "payload_sha256": value["payload_sha256"],
                "terminal_candidates": len(payload["terminal_receipts"]),
            },
        )

    if action == "status":
        if successor_context is not None:
            details = _successor_study_status(
                successor_context,
                result_roots=result_roots,
                workload_root=workload_root,
                foundation_attestation=foundation_attestation,
                readiness_attestation=readiness_attestation,
                historical_pre_snapshot=historical_pre_snapshot,
                historical_post_snapshot=historical_post_snapshot,
                handoff=handoff,
                evaluation_receipt=evaluation_receipt,
                comparison_review=comparison_review,
                validation_attestation=validation_attestation,
                deep=deep,
            )
            return ClassStudyActionResult(action, "complete", details)
        details = class_study_status(
            candidate_catalogue_path=candidate_catalogue_path,
            stability_root=stability_root,
            workload_root=workload_root,
            acquisition_completion_path=acquisition_completion_path,
            acquisition_root=acquisition_root,
            pilot_cohort_receipt_path=pilot_cohort_receipt_path,
            pilot_cohort_assembly_path=pilot_cohort_assembly_path,
            final_cohort_receipt_path=final_cohort_receipt_path,
            final_cohort_assembly_path=final_cohort_assembly_path,
            final_selection_path=final_selection_path,
            campaign_root=campaign_root,
            result_roots=result_roots,
            numeric_bundle_roots=status_numeric_bundle_roots,
            prefix_spec_roots=status_prefix_spec_roots,
            qualification_manifests=status_qualification_manifests,
            final_bundle_roots=status_final_bundle_roots,
            handoff=handoff,
            evaluation_receipt=evaluation_receipt,
            foundation_attestation=foundation_attestation,
            acquisition_authority=acquisition_authority,
            readiness_attestation=readiness_attestation,
            historical_pre_snapshot=historical_pre_snapshot,
            historical_post_snapshot=historical_post_snapshot,
            comparison_review=comparison_review,
            validation_attestation=validation_attestation,
            deep=deep,
        )
        return ClassStudyActionResult(action, "complete", details)

    if action == "stability":
        catalogue = _required(candidate_catalogue_path, "--candidate-catalogue")
        stability = _required(stability_root, "--stability-root")
        output: Path | None = None
        if stability_input is not None:
            output = admit_stability_observation_batch(catalogue, stability, stability_input)
        details = stability_status(catalogue, stability)
        if output is not None:
            details["admitted_receipt"] = str(output)
            details["admitted_receipt_sha256"] = sha256_file(output)
        return ClassStudyActionResult(
            action,
            "complete" if output is not None else "pending",
            details,
            () if output is not None else ("supply --stability-input from an acquisition runner",),
        )

    if action == "cohort":
        # Cohort outputs do not exist yet, so validate their source inputs via
        # the publisher and then independently rebuild the published bridge.
        catalogue = _required(candidate_catalogue_path, "--candidate-catalogue")
        stability = _required(stability_root, "--stability-root")
        workloads = _required(workload_root, "--workload-root")
        cohort = _required(cohort_receipt_path, "--cohort")
        assembly = _required(cohort_assembly_path, "--cohort-assembly")
        completion = _required(acquisition_completion_path, "--acquisition-completion")
        cohort_stage = _required_stage(stage)
        feasible_pairs: tuple[tuple[str, str], ...] | None = None
        if cohort_stage == AUTHORITATIVE_STAGE:
            qualification_authority = _qualification_authority_for_action(
                _required(foundation_attestation, "--foundation-attestation"),
                deep_code_gate=deep,
                runtime_role="collection",
                successor_context=successor_context,
            )
            pilot_admission = _required_admission(
                pilot_cohort_receipt_path,
                pilot_cohort_assembly_path,
                candidate_catalogue_path=catalogue,
                stability_root=stability,
                workload_root=workloads,
                acquisition_completion_path=completion,
                final_selection_receipt_path=None,
                label="pilot",
            )
            records = _result_index(
                result_roots,
                pilot_admission=pilot_admission,
                final_admission=None,
            )
            pilot_fitting = _require_role(records, "pilot-fitting")
            compatibility = _require_role(records, "pilot-compatibility")
            selection_path = write_final_selection_input(
                _required(final_selection_path, "--final-selection"),
                pilot_admission=pilot_admission,
                pilot_fitting_result_root=Path(pilot_fitting["root"]),
                pilot_numeric_bundle_root=_required(numeric_bundle_root, "--numeric-bundle"),
                pilot_compatibility_result_root=Path(compatibility["root"]),
                qualification_authority=qualification_authority,
            )
            feasible_pairs = validate_final_selection_input(
                _load_json_object(selection_path, "final-selection input"),
                pilot_admission=pilot_admission,
                pilot_fitting_result_root=Path(pilot_fitting["root"]),
                pilot_numeric_bundle_root=_required(numeric_bundle_root, "--numeric-bundle"),
                pilot_compatibility_result_root=Path(compatibility["root"]),
                qualification_authority=qualification_authority,
            )
        paths = publish_evidenced_cohort(
            cohort,
            assembly,
            candidate_catalogue_path=catalogue,
            stability_root=stability,
            workload_root=workloads,
            acquisition_completion_path=completion,
            feasible_pairs=feasible_pairs,
            final_selection_receipt_path=(
                selection_path if cohort_stage == AUTHORITATIVE_STAGE else None
            ),
        )
        verified = verify_cohort_admission(
            paths[0],
            paths[1],
            candidate_catalogue_path=catalogue,
            stability_root=stability,
            workload_root=workloads,
            acquisition_completion_path=completion,
            final_selection_receipt_path=(
                selection_path if cohort_stage == AUTHORITATIVE_STAGE else None
            ),
        )
        if cohort_stage == PILOT_STAGE and verified.selection.feasible_pairs is not None:
            raise ValueError("pilot cohort freeze must precede feasible-pair selection")
        if cohort_stage == AUTHORITATIVE_STAGE:
            if verified.selection.feasible_pairs != feasible_pairs:
                raise ValueError("final cohort differs from the pilot-bound feasible-pair graph")
            if tuple(item.candidate_id for item in verified.selection.pilot) != tuple(
                item.candidate_id for item in pilot_admission.selection.pilot
            ):
                raise ValueError("final cohort changed the frozen pilot class inventory")
            if verified.selection.matching is None:
                raise ValueError("final cohort has no verified perfect matching")
        return ClassStudyActionResult(action, "complete", verified.as_dict())

    if action in {
        "successor-policy",
        "successor-decision",
        "successor-restart",
        "successor-verify",
    }:
        from .class_successor import (
            DECISION_RECEIPT_TYPE,
            POLICY_RECEIPT_TYPE,
            RESTART_RECEIPT_TYPE,
            create_successor_decision,
            create_successor_policy,
            create_successor_restart,
            validate_successor_decision,
            validate_successor_policy,
            validate_successor_restart,
        )

        if action == "successor-policy":
            output = create_successor_policy(_required(destination, "--destination"))
            return ClassStudyActionResult(action, "complete", validate_successor_policy(output))
        if action == "successor-decision":
            output = create_successor_decision(
                _required(destination, "--destination"),
                policy_receipt=_required(successor_policy, "--successor-policy"),
                certification_result_root=_required(certification_result, "--certification-result"),
                predecessor_cohort_receipt=_required(final_cohort_receipt_path, "--final-cohort"),
                predecessor_cohort_assembly=_required(
                    final_cohort_assembly_path, "--final-cohort-assembly"
                ),
                predecessor_final_selection=_required(final_selection_path, "--final-selection"),
                predecessor_foundation_attestation=_required(
                    foundation_attestation, "--foundation-attestation"
                ),
            )
            return ClassStudyActionResult(action, "complete", validate_successor_decision(output))
        if action == "successor-restart":
            output = create_successor_restart(
                _required(destination, "--destination"),
                decision_receipt=_required(successor_decision, "--successor-decision"),
            )
            return ClassStudyActionResult(action, "complete", validate_successor_restart(output))

        verification_target = _required(target, "--target")
        value = _load_json_object(verification_target, "successor verification target")
        receipt_type = value.get("receipt_type")
        validators = {
            POLICY_RECEIPT_TYPE: validate_successor_policy,
            DECISION_RECEIPT_TYPE: validate_successor_decision,
            RESTART_RECEIPT_TYPE: validate_successor_restart,
        }
        validator = validators.get(receipt_type)
        if validator is None:
            raise ValueError("successor verification target has an unsupported receipt type")
        return ClassStudyActionResult(
            action,
            "complete",
            validator(verification_target),
        )

    if action in {"foundation", "acquisition-authority"}:
        from .class_attestation import (
            create_class_acquisition_authority,
            create_class_foundation_attestation,
            validate_class_acquisition_authority,
            validate_class_foundation_attestation,
        )

        if type(cohort_version) is not int or cohort_version < 1:
            raise ValueError("class-study foundation requires --cohort-version")
        build_path = _required(build_execution_receipt, "--build-execution-receipt")
        pinned_path = _required(pinned_cdp_receipt, "--pinned-cdp-receipt")
        browser_egress_root = _required(
            browser_egress_qualification_root,
            "--browser-egress-qualification-root",
        )
        expected_pinned_path = (
            Path(build_path).absolute().parent
            / f"pinned-cdp-execution-v{cohort_version}.json"
        )
        if Path(pinned_path).absolute() != expected_pinned_path:
            raise ValueError(
                "class-study foundation pinned CDP receipt has the wrong canonical filename"
            )
        expected_browser_egress_root = (
            Path(build_path).absolute().parent
            / f"browser-egress-qualification-v{cohort_version}"
        )
        if Path(browser_egress_root).absolute() != expected_browser_egress_root:
            raise ValueError(
                "class-study foundation browser-egress qualification root has the "
                "wrong canonical path"
            )
        foundation_destination = _required(destination, "--destination")
        expected_foundation_destination = (
            Path(build_path).absolute().parent.parent
            / f"class-study-{action}-v{cohort_version}.json"
        )
        if Path(foundation_destination).absolute() != expected_foundation_destination:
            raise ValueError(
                "class-study foundation destination has the wrong canonical filename"
            )
        common_inputs = dict(
            cohort_version=cohort_version,
            build_execution_receipt=build_path,
            pinned_cdp_receipt=pinned_path,
            browser_egress_qualification_root=browser_egress_root,
        )
        if action == "acquisition-authority":
            output = create_class_acquisition_authority(
                foundation_destination, **common_inputs
            )
            return ClassStudyActionResult(
                action, "complete", validate_class_acquisition_authority(output)
            )
        output = create_class_foundation_attestation(
            foundation_destination,
            **common_inputs,
            reference_receipt=_required(reference_receipt, "--reference-receipt"),
            code_gate_receipt=_required(code_gate_receipt, "--code-gate-receipt"),
            controlled_qualification_receipt=_required(
                controlled_qualification_receipt,
                "--controlled-qualification-receipt",
            ),
            regression_result_roots=regression_result_roots,
            controlled_result_roots=controlled_result_roots,
        )
        details = validate_class_foundation_attestation(output, deep_code_gate=False)
        return ClassStudyActionResult(action, "complete", details)

    if action == "readiness" and successor_context is not None:
        from .class_successor import (
            create_successor_readiness,
            validate_successor_readiness,
        )

        output = create_successor_readiness(
            _required(destination, "--destination"),
            restart_receipt=successor_context["restart_path"],
            foundation_attestation=_required(foundation_attestation, "--foundation-attestation"),
            authoritative_fitting_result_root=_required(
                authoritative_fitting_result, "--authoritative-fitting-result"
            ),
            authoritative_fitting_bundle_root=_required(final_bundle_root, "--final-bundle"),
            qualification_workload_root=_required(workload_root, "--workload-root"),
            qualification_sidecar_root=_required(
                qualification_sidecar_root, "--qualification-sidecar-root"
            ),
            qualification_prefix_root=_required(prefix_spec_root, "--prefix-spec-root"),
            certification_result_root=_required(certification_result, "--certification-result"),
        )
        return ClassStudyActionResult(
            action,
            "complete",
            validate_successor_readiness(output, deep_code_gate=False),
        )

    if action == "readiness":
        from .class_attestation import (
            create_class_readiness_attestation,
            validate_class_readiness_attestation,
        )

        if type(cohort_version) is not int or cohort_version < 1:
            raise ValueError("class-study readiness requires --cohort-version")
        output = create_class_readiness_attestation(
            _required(destination, "--destination"),
            foundation_attestation=_required(foundation_attestation, "--foundation-attestation"),
            cohort_version=cohort_version,
            build_execution_receipt=_required(build_execution_receipt, "--build-execution-receipt"),
            reference_receipt=_required(reference_receipt, "--reference-receipt"),
            code_gate_receipt=_required(code_gate_receipt, "--code-gate-receipt"),
            controlled_qualification_receipt=_required(
                controlled_qualification_receipt,
                "--controlled-qualification-receipt",
            ),
            regression_result_roots=regression_result_roots,
            controlled_result_roots=controlled_result_roots,
            candidate_catalogue=_required(candidate_catalogue_path, "--candidate-catalogue"),
            stability_root=_required(stability_root, "--stability-root"),
            workload_root=_required(workload_root, "--workload-root"),
            acquisition_completion=_required(
                acquisition_completion_path, "--acquisition-completion"
            ),
            pilot_cohort_receipt=_required(pilot_cohort_receipt_path, "--pilot-cohort"),
            pilot_cohort_assembly=_required(pilot_cohort_assembly_path, "--pilot-cohort-assembly"),
            pilot_fitting_result_root=_required(pilot_fitting_result, "--pilot-fitting-result"),
            pilot_numeric_bundle_root=_required(numeric_bundle_root, "--numeric-bundle"),
            pilot_compatibility_result_root=_required(
                pilot_compatibility_result, "--pilot-compatibility-result"
            ),
            final_selection_receipt=_required(final_selection_path, "--final-selection"),
            final_cohort_receipt=_required(final_cohort_receipt_path, "--final-cohort"),
            final_cohort_assembly=_required(final_cohort_assembly_path, "--final-cohort-assembly"),
            authoritative_fitting_result_root=_required(
                authoritative_fitting_result, "--authoritative-fitting-result"
            ),
            authoritative_fitting_bundle_root=_required(final_bundle_root, "--final-bundle"),
            qualification_workload_root=_required(workload_root, "--workload-root"),
            qualification_sidecar_root=_required(
                qualification_sidecar_root, "--qualification-sidecar-root"
            ),
            qualification_prefix_root=_required(prefix_spec_root, "--prefix-spec-root"),
            certification_result_root=_required(certification_result, "--certification-result"),
        )
        details = validate_class_readiness_attestation(output, deep_code_gate=False)
        return ClassStudyActionResult(action, "complete", details)

    if action == "historical-snapshot":
        from .class_attestation import (
            create_class_historical_snapshot,
            validate_class_historical_snapshot,
        )

        if snapshot_phase not in {"pre-formal", "post-formal"}:
            raise ValueError(
                "class historical snapshot requires --snapshot-phase pre-formal or post-formal"
            )
        readiness_path = _required(readiness_attestation, "--readiness-attestation")
        if successor_context is not None:
            from .class_attestation import validate_class_readiness_attestation

            _require_successor_receipt_lineage(
                validate_class_readiness_attestation(readiness_path, deep_code_gate=deep),
                successor_context,
                label="readiness attestation",
                require_restart=True,
            )
            if snapshot_phase == "post-formal":
                admission = verify_successor_cohort_admission(successor_context["restart_path"])
                if len(formal_result_roots) != FORMAL_BLOCK_COUNT:
                    raise ValueError("successor post-formal snapshot requires ten formal blocks")
                records = tuple(
                    verify_class_study_result(
                        root,
                        admission=admission,
                        expected_role="formal",
                        expected_block=block,
                    )
                    for block, root in enumerate(formal_result_roots, start=1)
                )
                _require_successor_result_records(
                    records,
                    restart_sha256=sha256_file(successor_context["restart_path"]),
                    study_id=successor_context["study_id"],
                )
        output = create_class_historical_snapshot(
            _required(destination, "--destination"),
            phase=snapshot_phase,
            readiness_attestation=readiness_path,
            formal_result_roots=formal_result_roots,
            pre_snapshot=historical_pre_snapshot,
        )
        details = validate_class_historical_snapshot(output, expected_phase=snapshot_phase)
        return ClassStudyActionResult(action, "complete", details)

    if action == "comparison-review":
        from .class_attestation import (
            build_class_comparison_review_template,
            create_class_comparison_review,
            validate_class_comparison_review,
        )

        comparison_handoff = _required(handoff, "--handoff")
        comparison_evaluation = _required(evaluation_receipt, "--evaluation-receipt")
        if successor_context is not None:
            _require_successor_handoff_lineage(comparison_handoff, successor_context)
            from .class_evaluation import verify_class_evaluation_receipt

            _require_successor_receipt_lineage(
                verify_class_evaluation_receipt(
                    comparison_evaluation,
                    handoff_root=comparison_handoff,
                    deep_verify_handoff=deep,
                    replay_attacks=deep,
                ),
                successor_context,
                label="evaluation receipt",
                require_restart=False,
            )
        if comparison_review_input is None:
            template = build_class_comparison_review_template(
                handoff=comparison_handoff,
                evaluation_receipt=comparison_evaluation,
            )
            return ClassStudyActionResult(
                action,
                "ready",
                template,
                (
                    "complete every review entry, save only the reviews array under "
                    "a top-level reviews key, then rerun with --comparison-review-input, "
                    "--reviewer, --reviewed-at, and --destination",
                ),
            )
        review_input = _load_json_object(
            comparison_review_input,
            "class comparison review input",
        )
        if set(review_input) != {"reviews"} or not isinstance(review_input.get("reviews"), list):
            raise ValueError("class comparison review input must contain only a reviews array")
        if not isinstance(reviewer, str) or not reviewer.strip():
            raise ValueError("class comparison review requires --reviewer")
        if not isinstance(reviewed_at, str) or not reviewed_at:
            raise ValueError("class comparison review requires --reviewed-at")
        output = create_class_comparison_review(
            _required(destination, "--destination"),
            handoff=comparison_handoff,
            evaluation_receipt=comparison_evaluation,
            reviewer=reviewer,
            reviewed_at=reviewed_at,
            reviews=review_input["reviews"],
            _post_write_validate=False,
        )
        details = validate_class_comparison_review(output)
        return ClassStudyActionResult(action, "complete", details)

    if action == "attest":
        from .class_attestation import (
            create_class_validation_attestation,
            validate_class_validation_attestation,
        )

        attest_readiness = _required(readiness_attestation, "--readiness-attestation")
        if successor_context is not None:
            from .class_attestation import validate_class_readiness_attestation

            _require_successor_receipt_lineage(
                validate_class_readiness_attestation(attest_readiness, deep_code_gate=deep),
                successor_context,
                label="readiness attestation",
                require_restart=True,
            )
        output = create_class_validation_attestation(
            _required(destination, "--destination"),
            _post_write_validate=False,
            readiness_attestation=attest_readiness,
            canary_result_roots=canary_result_roots,
            formal_result_roots=formal_result_roots,
            historical_pre_snapshot=_required(historical_pre_snapshot, "--historical-pre-snapshot"),
            historical_post_snapshot=_required(
                historical_post_snapshot, "--historical-post-snapshot"
            ),
            handoff=_required(handoff, "--handoff"),
            evaluation_receipt=_required(evaluation_receipt, "--evaluation-receipt"),
            comparison_review=_required(comparison_review, "--comparison-review"),
        )
        details = validate_class_validation_attestation(output, deep_code_gate=False)
        return ClassStudyActionResult(action, "complete", details)

    if action == "verify" and target is not None:
        promotion = _verify_class_promotion_target(target, deep=deep)
        if promotion is not None:
            if successor_context is not None:
                _require_successor_receipt_lineage(
                    promotion,
                    successor_context,
                    label="promotion target",
                    require_restart=True,
                )
            return ClassStudyActionResult(action, "complete", promotion)

    if successor_context is not None:
        # A successor is admitted only through the immutable restart receipt.
        # Never fall back to caller-supplied predecessor cohort paths: that
        # would allow predecessor downstream evidence to satisfy successor
        # fitting or capture gates.
        pilot_admission = None
        final_admission = verify_successor_cohort_admission(successor_context["restart_path"])
    else:
        pilot_admission = _optional_admission(
            pilot_cohort_receipt_path,
            pilot_cohort_assembly_path,
            candidate_catalogue_path=candidate_catalogue_path,
            stability_root=stability_root,
            workload_root=workload_root,
            acquisition_completion_path=acquisition_completion_path,
            final_selection_receipt_path=None,
        )
        final_admission = _optional_admission(
            final_cohort_receipt_path,
            final_cohort_assembly_path,
            candidate_catalogue_path=candidate_catalogue_path,
            stability_root=stability_root,
            workload_root=workload_root,
            acquisition_completion_path=acquisition_completion_path,
            final_selection_receipt_path=final_selection_path,
        )

    if action == "campaigns":
        campaign_stage = _required_stage(stage)
        if pilot_admission is None:
            raise ValueError("campaign generation requires the pilot cohort admission")
        if campaign_stage == AUTHORITATIVE_STAGE:
            qualification_authority = _qualification_authority_for_action(
                _required(foundation_attestation, "--foundation-attestation"),
                deep_code_gate=deep,
                runtime_role="collection",
                successor_context=successor_context,
            )
            if final_admission is None:
                raise ValueError(
                    "authoritative campaign generation requires final cohort admission"
                )
            records = _result_index(
                result_roots,
                pilot_admission=pilot_admission,
                final_admission=final_admission,
            )
            pilot_fitting = _require_role(records, "pilot-fitting")
            compatibility = _require_role(records, "pilot-compatibility")
            pairs = validate_final_selection_input(
                _load_json_object(
                    _required(final_selection_path, "--final-selection"),
                    "final-selection input",
                ),
                pilot_admission=pilot_admission,
                pilot_fitting_result_root=Path(pilot_fitting["root"]),
                pilot_numeric_bundle_root=_required(numeric_bundle_root, "--numeric-bundle"),
                pilot_compatibility_result_root=Path(compatibility["root"]),
                qualification_authority=qualification_authority,
            )
            if final_admission.selection.feasible_pairs != pairs:
                raise ValueError("final cohort is not bound to the verified final-selection input")
            if final_admission.selection.matching is None:
                raise ValueError("authoritative campaigns require a matched final cohort")
        root = _required(campaign_root, "--campaign-root")
        paths = publish_campaign_set(
            campaign_stage,
            pilot_admission,
            root,
            final_admission=final_admission,
            pilot_cohort_reference=_relative_reference(root, pilot_admission.cohort_path),
            pilot_cohort_assembly_reference=_relative_reference(
                root, pilot_admission.assembly_path
            ),
            final_cohort_reference=(
                _relative_reference(root, final_admission.cohort_path)
                if final_admission is not None
                else DEFAULT_COHORT_REFERENCE
            ),
            final_cohort_assembly_reference=(
                _relative_reference(root, final_admission.assembly_path)
                if final_admission is not None
                else DEFAULT_COHORT_ASSEMBLY_REFERENCE
            ),
        )
        details = verify_campaign_set(
            root,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
            expected_stage=campaign_stage,
        )
        details["created_or_verified"] = [str(path) for path in paths]
        return ClassStudyActionResult(action, "complete", details)

    if action == "fit-numeric":
        fitted_stage = _required_stage(stage)
        admission = _admission_for_stage(fitted_stage, pilot_admission, final_admission)
        source = _required(capture_result, "--capture-result")
        source_record = _require_fitting_source(source, fitted_stage, admission)
        if successor_context is not None:
            _require_successor_result_records(
                (source_record,),
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        records = _result_index(
            result_roots,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
        )
        if successor_context is not None:
            _require_successor_result_records(
                records,
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        if fitted_stage == AUTHORITATIVE_STAGE and successor_context is None:
            _require_role(records, "pilot-compatibility")
        output = create_numeric_fitting_bundle(
            source,
            artifacts_root=_required(artifacts_root, "--artifacts-root"),
            stage=fitted_stage,
            expected_cohort_receipt_path=admission.cohort_path,
            expected_cohort_assembly_receipt_path=admission.assembly_path,
        )
        verified = verify_numeric_fitting_bundle(output, source_result_root=source)
        return ClassStudyActionResult(action, "complete", verified.as_dict())

    if action == "prefix-specs":
        fitted_stage = _required_stage(stage)
        admission = _admission_for_stage(fitted_stage, pilot_admission, final_admission)
        source = _required(capture_result, "--capture-result")
        source_record = _require_fitting_source(source, fitted_stage, admission)
        if successor_context is not None:
            _require_successor_result_records(
                (source_record,),
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        numeric = _required(numeric_bundle_root, "--numeric-bundle")
        verified_numeric = verify_numeric_fitting_bundle(
            numeric,
            source_result_root=source,
        )
        if verified_numeric.stage != fitted_stage:
            raise ValueError("numeric fitting bundle has the wrong requested stage")
        _require_numeric_admission(verified_numeric, admission)
        if successor_context is not None:
            _require_successor_fitting_artifact(
                verified_numeric,
                successor_context,
            )
        output = derive_schema_six_prefix_specs(
            numeric,
            source_result_root=source,
            workload_root=_required(workload_root, "--workload-root"),
            artifacts_root=_required(artifacts_root, "--artifacts-root"),
        )
        details = _verify_prefix_spec_root(
            output,
            numeric_bundle_root=numeric,
            workload_root=_required(workload_root, "--workload-root"),
        )
        return ClassStudyActionResult(action, "complete", details)

    if action == "qualify-prefix":
        fitted_stage = _required_stage(stage)
        admission = _admission_for_stage(fitted_stage, pilot_admission, final_admission)
        source = _required(capture_result, "--capture-result")
        source_record = _require_fitting_source(source, fitted_stage, admission)
        if successor_context is not None:
            _require_successor_result_records(
                (source_record,),
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        numeric = _required(numeric_bundle_root, "--numeric-bundle")
        return _coordinate_qualification(
            fitted_stage,
            admission=admission,
            source_result_root=source,
            numeric_bundle_root=numeric,
            prefix_spec_root=_required(prefix_spec_root, "--prefix-spec-root"),
            workload_root=_required(workload_root, "--workload-root"),
            checkpoint_path=_required(qualification_checkpoint, "--qualification-checkpoint"),
            sidecar_root=_required(qualification_sidecar_root, "--qualification-sidecar-root"),
            publication_root=_required(
                qualification_publication_root, "--qualification-publication-root"
            ),
            workload_id=qualification_workload,
            qualify_all_pending=qualify_all_pending,
            qualification_authority=_qualification_authority_for_action(
                _required(foundation_attestation, "--foundation-attestation"),
                deep_code_gate=deep,
                runtime_role="prepare",
                successor_context=successor_context,
            ),
            qualification_set_name=(
                f"{successor_context['study_id']}-final-full"
                if successor_context is not None
                else None
            ),
            expected_successor_study_id=(
                successor_context["study_id"] if successor_context is not None else None
            ),
            expected_successor_restart_sha256=(
                sha256_file(successor_context["restart_path"])
                if successor_context is not None
                else None
            ),
        )

    if action == "finalize-fitting":
        fitted_stage = _required_stage(stage)
        admission = _admission_for_stage(fitted_stage, pilot_admission, final_admission)
        records = _result_index(
            result_roots,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
        )
        if successor_context is not None:
            _require_successor_result_records(
                records,
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        required_role = "pilot-fitting" if fitted_stage == PILOT_STAGE else "authoritative-fitting"
        fitting_record = _require_role(records, required_role)
        fitting_result_root = Path(fitting_record["root"])
        numeric = _required(numeric_bundle_root, "--numeric-bundle")
        verified_numeric = verify_numeric_fitting_bundle(
            numeric,
            source_result_root=fitting_result_root,
        )
        if verified_numeric.stage != fitted_stage:
            raise ValueError("numeric fitting bundle has the wrong finalisation stage")
        _require_numeric_admission(verified_numeric, admission)
        if successor_context is not None:
            _require_successor_fitting_artifact(
                verified_numeric,
                successor_context,
            )
        qualification = _required(qualification_manifest, "--qualification-manifest")
        prefix = _required(prefix_spec_root, "--prefix-spec-root")
        workloads = _required(workload_root, "--workload-root")
        context = QualificationContext(
            workload_root=workloads,
            sidecar_root=qualification.parent,
            prefix_spec_root=prefix,
            qualification_authority=_qualification_authority_for_action(
                _required(foundation_attestation, "--foundation-attestation"),
                deep_code_gate=deep,
                runtime_role="collection",
                successor_context=successor_context,
            ),
            expected_qualification_set=(
                f"{successor_context['study_id']}-final-full"
                if successor_context is not None
                else None
            ),
        )
        output = finalize_fitting_bundle(
            numeric,
            source_result_root=fitting_result_root,
            qualification_manifest_path=qualification,
            qualification_context=context,
            artifacts_root=_required(artifacts_root, "--artifacts-root"),
        )
        verified = verify_class_fitting_bundle(
            output,
            qualification_context=context,
            source_result_root=fitting_result_root,
        )
        return ClassStudyActionResult(action, "complete", verified.as_dict())

    if action in {"capture", "resume"}:
        return _coordinate_capture(
            action,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
            campaign=campaign,
            results_root=results_root,
            capture_result=capture_result,
            prerequisite_roots=result_roots,
            foundation_attestation=foundation_attestation,
            readiness_attestation=readiness_attestation,
            historical_pre_snapshot=historical_pre_snapshot,
            execute=execute,
            successor_restart_sha256=(
                sha256_file(successor_context["restart_path"])
                if successor_context is not None
                else None
            ),
            successor_study_id=(
                successor_context["study_id"] if successor_context is not None else None
            ),
        )

    if action == "export":
        if final_admission is None:
            raise ValueError("formal export requires final cohort admission")
        records = _result_index(
            result_roots,
            pilot_admission=pilot_admission,
            final_admission=final_admission,
        )
        if successor_context is not None:
            _require_successor_result_records(
                records,
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        _require_role(records, "certification")
        formal_roots: list[Path] = []
        for block in range(1, FORMAL_BLOCK_COUNT + 1):
            _require_block(records, "canary", block)
            formal = _require_block(records, "formal", block)
            formal_roots.append(Path(formal["root"]))
        output = export_class_handoff(
            formal_roots,
            _required(destination, "--destination"),
            historical_post_snapshot=_required(
                historical_post_snapshot, "--historical-post-snapshot"
            ),
        )
        verified = verify_class_handoff(output, deep=deep)
        return ClassStudyActionResult(
            action,
            "complete",
            {
                "valid": True,
                "root": str(verified),
                "formal_blocks": FORMAL_BLOCK_COUNT,
                "samples": FINAL_CLASS_COUNT * len(FORMAL_MODES) * 2 * FORMAL_BLOCK_COUNT,
            },
        )

    if action == "evaluate":
        source = _required(handoff, "--handoff")
        verify_class_handoff(source, deep=deep)
        if successor_context is not None:
            _require_successor_handoff_lineage(source, successor_context)
        from .class_evaluation import (
            verify_class_evaluation_receipt,
            write_class_evaluation_receipt,
        )

        output = write_class_evaluation_receipt(
            _required(destination, "--destination"),
            handoff_root=source,
            dlsvm_cache_directory=_required(
                dlsvm_cache_directory,
                "--dlsvm-cache-directory",
            ),
            deep_verify_handoff=deep,
        )
        verified = verify_class_evaluation_receipt(
            output,
            handoff_root=source,
            deep_verify_handoff=deep,
        )
        if successor_context is not None:
            _require_successor_receipt_lineage(
                verified,
                successor_context,
                label="evaluation receipt",
                require_restart=False,
            )
        return ClassStudyActionResult(action, "complete", verified)

    if action == "verify":
        verification_stage = _required_stage(stage)
        admission = _admission_for_stage(verification_stage, pilot_admission, final_admission)
        details = _verify_target(
            _required(target, "--target"),
            admission=admission,
            fitting_stage=verification_stage,
            fitting_source_result_root=capture_result,
            workload_root=_required(workload_root, "--workload-root"),
            numeric_bundle_root=numeric_bundle_root,
            prefix_spec_root=prefix_spec_root,
            qualification_manifest=qualification_manifest,
            foundation_attestation=foundation_attestation,
            handoff=handoff,
            deep=deep,
            successor_context=successor_context,
        )
        return ClassStudyActionResult(action, "complete", details)
    raise AssertionError(f"unhandled class-study action: {action}")


def _coordinate_qualification(
    stage: str,
    *,
    admission: CohortAdmission,
    source_result_root: Path,
    numeric_bundle_root: Path,
    prefix_spec_root: Path,
    workload_root: Path,
    checkpoint_path: Path,
    sidecar_root: Path,
    publication_root: Path,
    workload_id: str | None,
    qualify_all_pending: bool,
    qualification_authority: Mapping[str, Any],
    qualification_set_name: str | None = None,
    expected_successor_study_id: str | None = None,
    expected_successor_restart_sha256: str | None = None,
) -> ClassStudyActionResult:
    numeric = verify_numeric_fitting_bundle(
        numeric_bundle_root,
        source_result_root=source_result_root,
    )
    if numeric.stage != stage:
        raise ValueError("numeric fitting bundle has the wrong qualification stage")
    _require_numeric_admission(numeric, admission)
    if (expected_successor_study_id is None) != (expected_successor_restart_sha256 is None):
        raise ValueError("successor qualification identity requires study and restart")
    if expected_successor_study_id is not None:
        assert expected_successor_restart_sha256 is not None
        require_successor_fitting_identity(
            numeric.provenance,
            expected_study_id=expected_successor_study_id,
            expected_restart_sha256=expected_successor_restart_sha256,
        )
    _verify_prefix_spec_root(
        prefix_spec_root,
        numeric_bundle_root=numeric_bundle_root,
        workload_root=workload_root,
    )
    workloads = _stage_workloads(admission, stage)
    name = qualification_set_name or _qualification_set(stage)
    sidecars = _regular_directory(sidecar_root, "qualification sidecar root")
    publications = _regular_directory(publication_root, "qualification publication root")
    authority = _validated_qualification_authority(qualification_authority)
    # Validate both the installed prepare implementation and every resumable
    # sidecar before the first checkpoint/publication mutation.
    execution_context = _qualification_execution_context()
    if (
        execution_context[1] != authority["prepare_source"]
        or execution_context[2] != authority["prepare_image_digest"]
    ):
        raise ValueError("live qualification runtime differs from the foundation prepare build")
    _validate_qualification_sidecars(sidecars, workloads, authority)
    published_manifest = publications / name / NAMED_QUALIFICATION_SET_MANIFEST
    if published_manifest.exists() or published_manifest.is_symlink():
        published_prefix_root = published_manifest.parent / NAMED_QUALIFICATION_PREFIX_DIRECTORY
        selected_prefix_root = (
            published_prefix_root
            if published_prefix_root.exists() or published_prefix_root.is_symlink()
            else prefix_spec_root
        )
        output = load_named_qualification_set(
            published_manifest,
            workload_root=workload_root,
            sidecar_root=published_manifest.parent,
            prefix_spec_root=selected_prefix_root,
            expected_qualification_set=name,
            expected_qualification_scope=FULL_QUALIFICATION_SCOPE,
            expected_workload_ids=workloads,
            expected_qualification_authority=authority,
        )
        _validate_qualification_sidecars(published_manifest.parent, workloads, authority)
        return ClassStudyActionResult(
            "qualify-prefix",
            "complete",
            {
                "valid": True,
                "qualification_set": output.qualification_set,
                "manifest": str(output.manifest_path),
                "manifest_sha256": output.manifest_sha256,
                "workloads": len(output.workload_ids),
                "prefix_spec_root": str(Path(selected_prefix_root).resolve()),
            },
        )
    checkpoint = Path(os.path.abspath(checkpoint_path))
    if not checkpoint.exists() and not checkpoint.is_symlink():
        initialize_named_qualification_checkpoint(
            checkpoint,
            workloads,
            qualification_set=name,
            qualification_scope=FULL_QUALIFICATION_SCOPE,
            workload_root=workload_root,
            prefix_spec_root=prefix_spec_root,
            qualification_authority=authority,
        )
    reconcile_named_qualification_checkpoint(
        checkpoint,
        workload_root=workload_root,
        sidecar_root=sidecars,
        prefix_spec_root=prefix_spec_root,
        expected_qualification_authority=authority,
    )
    pending = pending_named_qualification_workloads(
        checkpoint,
        workload_root=workload_root,
        sidecar_root=sidecars,
        prefix_spec_root=prefix_spec_root,
        expected_qualification_authority=authority,
    )
    requested: tuple[str, ...]
    if workload_id is not None:
        if workload_id not in workloads:
            raise ValueError("requested qualification workload is outside the stage cohort")
        requested = (workload_id,) if workload_id in pending else ()
    elif qualify_all_pending:
        requested = pending
    else:
        requested = ()
    for current in requested:
        qualify_chaff(
            current,
            qualification_root=sidecars,
            workload_root=workload_root,
            prefix_spec_root=prefix_spec_root,
            _execution_context=execution_context,
            qualification_authority=authority,
        )
        _validate_qualification_sidecars(sidecars, (current,), authority)
        record_named_qualification_checkpoint(
            checkpoint,
            current,
            workload_root=workload_root,
            sidecar_root=sidecars,
            prefix_spec_root=prefix_spec_root,
            expected_qualification_authority=authority,
        )
    pending = pending_named_qualification_workloads(
        checkpoint,
        workload_root=workload_root,
        sidecar_root=sidecars,
        prefix_spec_root=prefix_spec_root,
        expected_qualification_authority=authority,
    )
    if not pending:
        _validate_qualification_sidecars(sidecars, workloads, authority)
        output = publish_named_qualification_set_from_checkpoint(
            checkpoint,
            workload_root=workload_root,
            sidecar_root=sidecars,
            publication_root=publications,
            prefix_spec_root=prefix_spec_root,
            qualification_authority=authority,
        )
        return ClassStudyActionResult(
            "qualify-prefix",
            "complete",
            {
                "valid": True,
                "qualification_set": output.qualification_set,
                "manifest": str(output.manifest_path),
                "manifest_sha256": output.manifest_sha256,
                "workloads": len(output.workload_ids),
                "prefix_spec_root": str(
                    (output.path / NAMED_QUALIFICATION_PREFIX_DIRECTORY).resolve()
                ),
            },
        )
    return ClassStudyActionResult(
        "qualify-prefix",
        "pending",
        {
            "qualification_set": name,
            "checkpoint": str(checkpoint.resolve()),
            "qualified": len(workloads) - len(pending),
            "pending": len(pending),
            "next_workload": pending[0],
            "pending_workloads": list(pending),
        },
        (
            "run one pending workload with --qualification-workload, or explicitly "
            "use --qualify-all-pending",
        ),
    )


def _validated_qualification_authority(value: object) -> dict[str, Any]:
    from .class_attestation import validate_class_qualification_authority

    return validate_class_qualification_authority(value)


def _validate_qualification_sidecars(
    sidecar_root: Path,
    workload_ids: Sequence[str],
    authority: Mapping[str, Any],
) -> None:
    """Require each present sidecar to carry the exact foundation authority."""

    root = _regular_directory(sidecar_root, "qualification sidecar root")
    expected = _validated_qualification_authority(authority)
    for workload_id in workload_ids:
        path = root / f"{workload_id}.json"
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"qualification sidecar is not a regular file: {path}")
        value = _load_json_object(path, f"qualification sidecar {workload_id}")
        if (
            value.get("schema_version") != CLASS_STUDY_QUALIFICATION_SCHEMA_VERSION
            or value.get("qualification_source") != expected["prepare_source"]
            or value.get("qualification_image_digest") != expected["prepare_image_digest"]
            or value.get("qualification_authority") != expected
            or value.get("qualification_authority_sha256")
            != canonical_json_sha256(expected)
        ):
            raise ValueError(
                f"qualification sidecar {workload_id} differs from the foundation authority"
            )


def _verify_class_promotion_target(
    target: Path,
    *,
    deep: bool,
) -> dict[str, Any] | None:
    """Route promotion receipts before cohort-specific generic verification."""

    path = Path(os.path.abspath(target))
    if path.is_symlink() or not path.is_file():
        return None
    value = _load_json_object(path, "class-study verification target")
    receipt_type = value.get("receipt_type")
    from .class_attestation import (
        ACQUISITION_AUTHORITY_RECEIPT_TYPE,
        COMPARISON_REVIEW_RECEIPT_TYPE,
        FOUNDATION_RECEIPT_TYPE,
        HISTORICAL_SNAPSHOT_RECEIPT_TYPE,
        READINESS_RECEIPT_TYPE,
        VALIDATION_RECEIPT_TYPE,
        validate_class_acquisition_authority,
        validate_class_comparison_review,
        validate_class_foundation_attestation,
        validate_class_historical_snapshot,
        validate_class_readiness_attestation,
        validate_class_validation_attestation,
    )

    if receipt_type == ACQUISITION_AUTHORITY_RECEIPT_TYPE:
        return validate_class_acquisition_authority(
            path,
            runtime_role="collection",
            allow_historical=True,
        )
    if receipt_type == FOUNDATION_RECEIPT_TYPE:
        return validate_class_foundation_attestation(
            path,
            deep_code_gate=deep,
            runtime_role="collection",
        )
    if receipt_type == READINESS_RECEIPT_TYPE:
        return validate_class_readiness_attestation(path, deep_code_gate=deep)
    if receipt_type == HISTORICAL_SNAPSHOT_RECEIPT_TYPE:
        return validate_class_historical_snapshot(path)
    if receipt_type == COMPARISON_REVIEW_RECEIPT_TYPE:
        return validate_class_comparison_review(path)
    if receipt_type == VALIDATION_RECEIPT_TYPE:
        return validate_class_validation_attestation(path, deep_code_gate=deep)
    return None


def _coordinate_capture(
    action: str,
    *,
    pilot_admission: CohortAdmission | None,
    final_admission: CohortAdmission | None,
    campaign: Path | None,
    results_root: Path | None,
    capture_result: Path | None,
    prerequisite_roots: Sequence[Path],
    foundation_attestation: Path | None,
    readiness_attestation: Path | None,
    historical_pre_snapshot: Path | None,
    execute: bool,
    successor_restart_sha256: str | None = None,
    successor_study_id: str | None = None,
) -> ClassStudyActionResult:
    records = _result_index(
        prerequisite_roots,
        pilot_admission=pilot_admission,
        final_admission=final_admission,
    )
    if successor_restart_sha256 is not None:
        _require_successor_result_records(
            records,
            restart_sha256=successor_restart_sha256,
            study_id=str(successor_study_id),
        )
    if action == "capture":
        campaign_path = _required(campaign, "--campaign")
        preflight_foundation = None
        if foundation_attestation is not None:
            preflight_foundation = {
                "required_environment": {
                    "QCSD_CLASS_FOUNDATION_ATTESTATION": str(
                        _regular_file(
                            foundation_attestation,
                            "class foundation attestation",
                        )
                    )
                }
            }
        with _capture_authority_environment(preflight_foundation):
            preflight = preflight_campaign(campaign_path)
        role = _campaign_role(preflight)
        block = _campaign_block(preflight)
        if successor_restart_sha256 is not None and (
            preflight.get(CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY) != successor_restart_sha256
            or preflight.get("class_study_id") != successor_study_id
        ):
            raise ValueError("successor campaign uses another restart authority")
        admission = _admission_for_role(role, pilot_admission, final_admission)
        _require_capture_admission_binding(preflight, admission=admission, role=role)
        prerequisite_ledger: tuple[Mapping[str, Any], ...] = ()
        if not (successor_restart_sha256 is not None and role == "authoritative-fitting"):
            prerequisite_ledger = _validate_capture_prerequisites(role, block, records)
        foundation_authority = _validate_capture_foundation(
            role,
            foundation_attestation=foundation_attestation,
            capture_started_at=None,
            expected_sha256=None,
            prerequisite_records=records,
        )
        fitting_generation = _validate_capture_fitting_generation(
            role,
            prerequisite_records=prerequisite_ledger,
            campaign_path=campaign_path,
            frozen_result_root=None,
            qualification_authority=(
                foundation_authority.get("qualification_authority")
                if isinstance(foundation_authority, Mapping)
                else None
            ),
        )
        authority = _validate_formal_capture_authority(
            role,
            readiness_attestation=readiness_attestation,
            historical_pre_snapshot=historical_pre_snapshot,
            admission=admission,
            prerequisite_records=records,
            capture_started_at=None,
            foundation_authority=foundation_authority,
            capture_configuration=preflight,
        )
        capacity = _formal_capacity_preflight(
            role,
            authority=authority,
            prerequisite_records=records,
            storage_root=results_root,
            current_experiment=None,
        )
        if not execute:
            details: dict[str, Any] = {
                "preflight": preflight,
                "delegation": "qcsd_lab.orchestrator.run_campaign",
                "will_create_result": False,
            }
            if authority is not None:
                details["formal_capture_authority"] = authority
            if foundation_authority is not None:
                details["foundation_authority"] = foundation_authority
            if capacity is not None:
                details["capacity_preflight"] = capacity
            if fitting_generation is not None:
                details["fitting_generation_authority"] = fitting_generation
            return ClassStudyActionResult(
                action,
                "ready",
                details,
                ("repeat with --execute after reviewing the preflight",),
            )
        with (
            _class_study_coordinator_capture_authority(
                {
                    **preflight,
                    "campaign_sha256": sha256_file(campaign_path),
                },
                prerequisite_ledger,
                fitting_generation,
            ),
            _capture_authority_environment(foundation_authority),
            _capture_authority_environment(authority),
        ):
            output = run_campaign(
                campaign_path,
                _required(results_root, "--results-root"),
            )
    else:
        source = _required(capture_result, "--capture-result")
        experiment = _load_json_object(source / "experiment.json", "resume experiment")
        configuration = experiment.get("configuration")
        if not isinstance(configuration, Mapping):
            raise ValueError("resume experiment has no frozen configuration")
        role = configuration.get("evidence_role")
        if not isinstance(role, str):
            raise ValueError("resume experiment is not class-study evidence")
        if successor_restart_sha256 is not None and (
            configuration.get(CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY) != successor_restart_sha256
            or configuration.get("class_study_id") != successor_study_id
        ):
            raise ValueError("successor resume uses another restart authority")
        block = _result_block(
            str(experiment.get("name")),
            role,
            study_id=str(configuration.get("class_study_id", STUDY_ID)),
        )
        admission = _admission_for_role(role, pilot_admission, final_admission)
        _require_capture_admission_binding(
            configuration,
            admission=admission,
            role=role,
        )
        prerequisite_ledger = ()
        if not (successor_restart_sha256 is not None and role == "authoritative-fitting"):
            prerequisite_ledger = _validate_capture_prerequisites(role, block, records)
        foundation_authority = _validate_capture_foundation(
            role,
            foundation_attestation=foundation_attestation,
            capture_started_at=experiment.get("started_at"),
            expected_sha256=configuration.get(CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY),
            prerequisite_records=records,
        )
        fitting_generation = _validate_capture_fitting_generation(
            role,
            prerequisite_records=prerequisite_ledger,
            campaign_path=None,
            frozen_result_root=source,
            qualification_authority=(
                foundation_authority.get("qualification_authority")
                if isinstance(foundation_authority, Mapping)
                else None
            ),
        )
        authority = _validate_formal_capture_authority(
            role,
            readiness_attestation=readiness_attestation,
            historical_pre_snapshot=historical_pre_snapshot,
            admission=admission,
            prerequisite_records=records,
            capture_started_at=experiment.get("started_at"),
            foundation_authority=foundation_authority,
            capture_configuration=configuration,
        )
        capacity = _formal_capacity_preflight(
            role,
            authority=authority,
            prerequisite_records=records,
            storage_root=source,
            current_experiment=experiment,
        )
        if not execute:
            details = {
                "result": str(source.resolve()),
                "declared_status": experiment.get("status"),
                "delegation": "qcsd_lab.orchestrator.resume_campaign",
                "will_resume": False,
            }
            if authority is not None:
                details["formal_capture_authority"] = authority
            if foundation_authority is not None:
                details["foundation_authority"] = foundation_authority
            if capacity is not None:
                details["capacity_preflight"] = capacity
            if fitting_generation is not None:
                details["fitting_generation_authority"] = fitting_generation
            return ClassStudyActionResult(
                action,
                "ready",
                details,
                ("repeat with --execute after reviewing the checkpoint",),
            )
        with (
            _class_study_coordinator_capture_authority(
                {**dict(configuration), "name": experiment.get("name")},
                prerequisite_ledger,
                fitting_generation,
            ),
            _capture_authority_environment(foundation_authority),
            _capture_authority_environment(authority),
        ):
            output = resume_campaign(source)
    record = verify_class_study_result(
        output,
        admission=admission,
        expected_role=role,
        expected_block=block,
    )
    if capacity is not None:
        record["capacity_preflight"] = capacity
    return ClassStudyActionResult(action, "complete", record)


def _validate_capture_foundation(
    role: str,
    *,
    foundation_attestation: Path | None,
    capture_started_at: object,
    expected_sha256: object,
    prerequisite_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if role not in {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }:
        raise ValueError("capture campaign has an unsupported class-study evidence role")
    path = _required(foundation_attestation, "--foundation-attestation")
    from .class_attestation import (
        class_qualification_authority,
        validate_class_foundation_attestation,
    )

    foundation = validate_class_foundation_attestation(
        path,
        deep_code_gate=True,
        runtime_role="collection",
    )
    if capture_started_at is not None and _class_aware_timestamp(
        foundation.get("recorded_at"), label="foundation attestation"
    ) > _class_aware_timestamp(capture_started_at, label=f"{role} start"):
        raise ValueError(f"{role} started before its foundation gate")
    binding = {
        "path": str(_regular_file(path, "class foundation attestation")),
        "sha256": sha256_file(path),
    }
    if capture_started_at is not None and (
        not isinstance(expected_sha256, str) or _SHA256.fullmatch(expected_sha256) is None
    ):
        raise ValueError("resumed class capture has no frozen foundation binding")
    if expected_sha256 is not None and expected_sha256 != binding["sha256"]:
        raise ValueError("resumed class capture uses a different foundation attestation")
    if any(
        record.get("class_study_foundation_sha256") != binding["sha256"]
        for record in prerequisite_records
    ):
        raise ValueError("class capture prerequisites use a different foundation")
    qualification_authority = class_qualification_authority(
        path,
        deep_code_gate=True,
        runtime_role="collection",
    )
    if qualification_authority["foundation_attestation"]["sha256"] != binding["sha256"]:
        raise ValueError("class qualification authority uses a different foundation")
    return {
        "foundation_attestation": binding,
        "source_sha256": canonical_json_sha256(foundation["source"]),
        "qualification_authority": qualification_authority,
        "qualification_authority_sha256": canonical_json_sha256(qualification_authority),
        "required_environment": {
            "QCSD_CLASS_FOUNDATION_ATTESTATION": binding["path"],
        },
    }


def _validate_formal_capture_authority(
    role: str,
    *,
    readiness_attestation: Path | None,
    historical_pre_snapshot: Path | None,
    admission: CohortAdmission,
    prerequisite_records: Sequence[Mapping[str, Any]],
    capture_started_at: object,
    foundation_authority: Mapping[str, Any] | None = None,
    capture_configuration: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Require hash-bound readiness and pre-history before canary/formal work."""

    if role not in {"canary", "formal"}:
        if readiness_attestation is not None or historical_pre_snapshot is not None:
            raise ValueError(f"{role} capture forbids readiness and historical-pre authority")
        if isinstance(capture_configuration, Mapping) and any(
            key in capture_configuration
            for key in (
                CLASS_STUDY_READINESS_CONFIGURATION_KEY,
                CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY,
            )
        ):
            raise ValueError(f"{role} capture has unexpected frozen promotion authority")
        return None
    readiness_path = _required(readiness_attestation, "--readiness-attestation")
    snapshot_path = _required(historical_pre_snapshot, "--historical-pre-snapshot")
    from .class_attestation import (
        validate_class_historical_snapshot,
        validate_class_readiness_attestation,
    )

    readiness = validate_class_readiness_attestation(
        readiness_path,
        deep_code_gate=True,
    )
    snapshot = validate_class_historical_snapshot(
        snapshot_path,
        expected_phase="pre-formal",
    )
    readiness_binding = {
        "path": str(_regular_file(readiness_path, "class readiness attestation")),
        "sha256": sha256_file(readiness_path),
    }
    snapshot_binding = {
        "path": str(_regular_file(snapshot_path, "historical pre snapshot")),
        "sha256": sha256_file(snapshot_path),
    }
    evidence = readiness.get("evidence")
    final_cohort = evidence.get("final_cohort") if isinstance(evidence, Mapping) else None
    final_assembly = (
        evidence.get("final_cohort_assembly") if isinstance(evidence, Mapping) else None
    )
    readiness_foundation = evidence.get("foundation") if isinstance(evidence, Mapping) else None
    foundation_binding = (
        foundation_authority.get("foundation_attestation")
        if isinstance(foundation_authority, Mapping)
        else None
    )
    readiness_successor = (
        evidence.get("successor_restart") if isinstance(evidence, Mapping) else None
    )
    capture_successor_sha256 = (
        capture_configuration.get(CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY)
        if isinstance(capture_configuration, Mapping)
        else None
    )
    if (
        snapshot.get("readiness") != readiness_binding
        or snapshot.get("source") != readiness.get("source")
        or not isinstance(foundation_binding, Mapping)
        or not isinstance(readiness_foundation, Mapping)
        or readiness_foundation.get("sha256") != foundation_binding.get("sha256")
        or not isinstance(final_cohort, Mapping)
        or final_cohort.get("sha256") != admission.cohort_sha256
        or not isinstance(final_assembly, Mapping)
        or final_assembly.get("sha256") != admission.assembly_sha256
        or (
            capture_successor_sha256 is not None
            and (
                not isinstance(readiness_successor, Mapping)
                or readiness_successor.get("sha256") != capture_successor_sha256
                or readiness.get("study_id") != capture_configuration.get("class_study_id")
            )
        )
    ):
        raise ValueError("formal capture authority differs from its readiness/cohort admission")

    summary = readiness.get("summary")
    certification_runtime_inputs = (
        summary.get("certification_defense_runtime_inputs")
        if isinstance(summary, Mapping)
        else None
    )
    final_qualification_manifest_sha256 = (
        summary.get("final_qualification_set_manifest_sha256")
        if isinstance(summary, Mapping)
        else None
    )
    if (
        not isinstance(certification_runtime_inputs, Mapping)
        or set(certification_runtime_inputs) != set(COMPATIBILITY_MODES)
        or not isinstance(final_qualification_manifest_sha256, str)
        or _SHA256.fullmatch(final_qualification_manifest_sha256) is None
    ):
        raise ValueError("formal capture readiness lacks certified runtime/qualification identity")
    if not isinstance(capture_configuration, Mapping):
        raise ValueError("formal capture has no prospective frozen configuration")
    raw_capture_runtime_inputs = capture_configuration.get("defense_runtime_inputs")
    capture_runtime_inputs = (
        dict(raw_capture_runtime_inputs)
        if isinstance(raw_capture_runtime_inputs, Mapping)
        else _defense_runtime_input_identities(capture_configuration)
    )
    expected_modes = ("undefended",) if role == "canary" else FORMAL_MODES
    expected_runtime_inputs = {mode: certification_runtime_inputs[mode] for mode in expected_modes}
    if capture_runtime_inputs != expected_runtime_inputs:
        raise ValueError("formal capture runtime inputs differ from certification/readiness")
    observed_manifest = capture_configuration.get("chaff_qualification_set_manifest_sha256")
    observed_set = capture_configuration.get("chaff_qualification_set")
    if role == "formal":
        expected_set = (
            f"{readiness['study_id']}-final-full"
            if is_successor_study_id(readiness.get("study_id"))
            else AUTHORITATIVE_QUALIFICATION_SET
        )
        if observed_manifest != final_qualification_manifest_sha256 or observed_set != expected_set:
            raise ValueError("formal capture qualification manifest differs from readiness")
    elif observed_manifest is not None or observed_set is not None:
        raise ValueError("class canary unexpectedly uses a qualification set")

    foundation_sha256 = str(foundation_binding["sha256"])
    _require_prior_capture_runtime_bindings(
        prerequisite_records,
        foundation_sha256=foundation_sha256,
        readiness_sha256=readiness_binding["sha256"],
        historical_pre_sha256=snapshot_binding["sha256"],
        certification_runtime_inputs=certification_runtime_inputs,
        final_qualification_manifest_sha256=final_qualification_manifest_sha256,
    )
    if capture_started_at is not None and (
        capture_configuration.get(CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY) != foundation_sha256
        or capture_configuration.get(CLASS_STUDY_READINESS_CONFIGURATION_KEY)
        != readiness_binding["sha256"]
        or capture_configuration.get(CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY)
        != snapshot_binding["sha256"]
    ):
        raise ValueError("resumed class capture uses different promotion authority")

    certification = evidence.get("certification_result")
    if not isinstance(certification, Mapping) or not isinstance(certification.get("root"), str):
        raise ValueError("formal capture readiness has no certification binding")
    certification_verified = verify_result(Path(certification["root"]))
    certification_record = _require_role(prerequisite_records, "certification")
    if Path(
        str(certification_record.get("root"))
    ).resolve() != certification_verified.root.resolve() or certification_record.get(
        "evidence_sha256"
    ) != certification.get("evidence_sha256"):
        raise ValueError("formal capture certification prerequisite differs from readiness")
    certification_time = _class_aware_timestamp(
        certification_verified.experiment.get("completed_at"),
        label="certification completion",
    )
    snapshot_time = _class_aware_timestamp(
        snapshot.get("recorded_at"),
        label="historical pre snapshot",
    )
    if snapshot_time < certification_time:
        raise ValueError("historical pre snapshot predates class certification")
    starts: list[datetime] = []
    for record in prerequisite_records:
        if record.get("evidence_role") not in {"canary", "formal"}:
            continue
        root = record.get("root")
        if not isinstance(root, str):
            raise ValueError("formal prerequisite has no result root")
        starts.append(
            _class_aware_timestamp(
                verify_result(Path(root)).experiment.get("started_at"),
                label="formal prerequisite start",
            )
        )
    if capture_started_at is not None:
        starts.append(
            _class_aware_timestamp(
                capture_started_at,
                label="resumed capture start",
            )
        )
    if any(snapshot_time > started for started in starts):
        raise ValueError("historical pre snapshot does not precede class capture")
    return {
        "readiness_attestation": readiness_binding,
        "historical_pre_snapshot": snapshot_binding,
        "source_sha256": canonical_json_sha256(readiness["source"]),
        "cohort_sha256": admission.cohort_sha256,
        "cohort_assembly_sha256": admission.assembly_sha256,
        "certification_result_root": str(certification_verified.root),
        "certification_defense_runtime_inputs": dict(certification_runtime_inputs),
        "final_qualification_set_manifest_sha256": (final_qualification_manifest_sha256),
        "required_environment": {
            "QCSD_CLASS_READINESS_ATTESTATION": readiness_binding["path"],
            "QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT": snapshot_binding["path"],
        },
    }


def _require_prior_capture_runtime_bindings(
    prerequisite_records: Sequence[Mapping[str, Any]],
    *,
    foundation_sha256: str,
    readiness_sha256: str,
    historical_pre_sha256: str,
    certification_runtime_inputs: Mapping[str, Any],
    final_qualification_manifest_sha256: str,
) -> None:
    """Require every prior canary/formal record to retain one frozen authority."""

    for record in prerequisite_records:
        if record.get("class_study_foundation_sha256") != foundation_sha256:
            raise ValueError("class capture prerequisites use different foundations")
        prior_role = record.get("evidence_role")
        if prior_role not in {"canary", "formal"}:
            continue
        prior_modes = ("undefended",) if prior_role == "canary" else FORMAL_MODES
        if record.get("defense_runtime_inputs") != {
            mode: certification_runtime_inputs[mode] for mode in prior_modes
        }:
            raise ValueError(
                "prior class capture runtime inputs differ from certification/readiness"
            )
        prior_manifest = record.get("chaff_qualification_set_manifest_sha256")
        if (prior_role == "formal" and prior_manifest != final_qualification_manifest_sha256) or (
            prior_role == "canary" and prior_manifest is not None
        ):
            raise ValueError("prior class capture qualification manifest differs from readiness")
        if (
            record.get("class_study_readiness_sha256") != readiness_sha256
            or record.get("class_study_historical_pre_snapshot_sha256") != historical_pre_sha256
        ):
            raise ValueError("prior class capture uses different readiness/pre-formal authority")


def _formal_capacity_preflight(
    role: str,
    *,
    authority: Mapping[str, Any] | None,
    prerequisite_records: Sequence[Mapping[str, Any]],
    storage_root: Path | None,
    current_experiment: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Project formal storage/time from the exact 900-sample certification.

    This check runs before every canary/formal launch or resume.  It deliberately
    uses only sealed certification evidence and fails if the target filesystem
    does not retain three times the projected bytes for all remaining samples.
    """

    if role not in {"canary", "formal"}:
        return None
    if not isinstance(authority, Mapping):
        raise ValueError("formal capacity preflight has no validated capture authority")
    certification_raw = authority.get("certification_result_root")
    if not isinstance(certification_raw, str):
        raise ValueError("formal capacity preflight has no certification result")
    certification = verify_result(Path(certification_raw))
    if len(certification.accepted_samples) != 900:
        raise ValueError("formal capacity projection requires exactly 900 certification samples")
    started = _class_aware_timestamp(
        certification.experiment.get("started_at"),
        label="certification start",
    )
    completed = _class_aware_timestamp(
        certification.experiment.get("completed_at"),
        label="certification completion",
    )
    observed_seconds = (completed - started).total_seconds()
    if observed_seconds <= 0:
        raise ValueError("formal certification duration is not positive")
    evidence_bytes = (
        sum((certification.root / relative).stat().st_size for relative in certification.checksums)
        + (certification.root / "evidence.sha256").stat().st_size
    )
    if evidence_bytes <= 0:
        raise ValueError("formal certification has no measurable evidence bytes")

    completed_roots: set[str] = set()
    completed_samples = 0
    for record in prerequisite_records:
        if record.get("evidence_role") not in {"canary", "formal"}:
            continue
        root = record.get("root")
        samples = record.get("samples")
        if not isinstance(root, str) or type(samples) is not int or samples < 0:
            raise ValueError("formal capacity prerequisite record is malformed")
        resolved = str(Path(root).resolve())
        if resolved in completed_roots:
            raise ValueError("formal capacity prerequisite results are duplicated")
        completed_roots.add(resolved)
        completed_samples += samples
    in_progress_samples = 0
    if current_experiment is not None:
        samples = current_experiment.get("samples")
        if not isinstance(samples, list):
            raise TypeError("formal resume experiment sample inventory is malformed")
        in_progress_samples = sum(
            isinstance(sample, Mapping)
            and sample.get("state") == "accepted"
            and sample.get("eligible") is True
            for sample in samples
        )
    total_samples = CANARY_SAMPLE_COUNT + FORMAL_SAMPLE_COUNT
    if completed_samples + in_progress_samples > total_samples:
        raise ValueError("formal capacity evidence exceeds the registered study matrix")
    remaining_samples = total_samples - completed_samples - in_progress_samples
    bytes_per_sample = evidence_bytes / 900
    projected_remaining_bytes = math.ceil(bytes_per_sample * remaining_samples)
    required_free_bytes = 3 * projected_remaining_bytes
    target = _regular_directory(
        _required(storage_root, "formal storage root"),
        "formal storage root",
    )
    free_bytes = shutil.disk_usage(target).free
    if free_bytes < required_free_bytes:
        raise ValueError(
            "formal storage preflight requires at least three times projected "
            f"remaining evidence ({required_free_bytes} bytes required; "
            f"{free_bytes} bytes free)"
        )
    observed_seconds_per_sample = observed_seconds / 900
    expected_seconds = observed_seconds_per_sample * remaining_samples
    conservative_seconds = max(
        expected_seconds * 1.5,
        remaining_samples
        * (
            CAPTURE_LIMITS["timeout_seconds"]
            + CAPTURE_LIMITS["per_origin_cooldown_seconds"]
            + CAPTURE_LIMITS["settle_seconds"]
        ),
    )
    return {
        "schema_version": 1,
        "basis": {
            "certification_result_root": str(certification.root),
            "certification_evidence_sha256": sha256_file(certification.root / "evidence.sha256"),
            "accepted_samples": 900,
            "authoritative_bytes": evidence_bytes,
            "observed_wall_seconds": observed_seconds,
        },
        "progress": {
            "planned_canary_and_formal_samples": total_samples,
            "completed_samples": completed_samples,
            "current_result_eligible_samples": in_progress_samples,
            "remaining_samples": remaining_samples,
        },
        "storage": {
            "root": str(target),
            "bytes_per_certification_sample": bytes_per_sample,
            "projected_remaining_bytes": projected_remaining_bytes,
            "required_free_bytes_three_times_projection": required_free_bytes,
            "observed_free_bytes": free_bytes,
            "passed": True,
        },
        "wall_time": {
            "basis_seconds_per_sample": observed_seconds_per_sample,
            "expected_remaining_seconds": expected_seconds,
            "expected_remaining_hours": expected_seconds / 3600,
            "conservative_remaining_seconds": conservative_seconds,
            "conservative_remaining_hours": conservative_seconds / 3600,
            "conservative_rule": (
                "max(1.5*certification-rate projection, remaining samples * "
                "(120s timeout + 30s origin cooldown + 1s settle))"
            ),
        },
    }


@contextmanager
def _capture_authority_environment(
    authority: Mapping[str, Any] | None,
) -> Iterator[None]:
    if authority is None:
        yield
        return
    required = authority.get("required_environment")
    allowed = {
        "QCSD_CLASS_FOUNDATION_ATTESTATION",
        "QCSD_CLASS_READINESS_ATTESTATION",
        "QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT",
    }
    if not isinstance(required, Mapping) or not required or not set(required) <= allowed:
        raise ValueError("formal capture authority environment is malformed")
    previous: dict[str, str | None] = {}
    for name, raw in required.items():
        if not isinstance(raw, str):
            raise TypeError("formal capture authority path is malformed")
        existing = os.environ.get(name)
        if existing is not None and Path(existing).resolve() != Path(raw).resolve():
            raise ValueError(f"{name} differs from validated class capture authority")
        previous[name] = existing
        os.environ[name] = raw
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _class_aware_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"class {label} timestamp is missing")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"class {label} timestamp is invalid") from error
    if timestamp.tzinfo is None:
        raise ValueError(f"class {label} timestamp has no timezone")
    return timestamp


def _validate_capture_prerequisites(
    role: str,
    block: int | None,
    records: Sequence[Mapping[str, Any]],
) -> tuple[Mapping[str, Any], ...]:
    if role == "pilot-fitting":
        return ()
    if role == "pilot-compatibility":
        return (_require_role(records, "pilot-fitting"),)
    if role == "authoritative-fitting":
        return (_require_role(records, "pilot-compatibility"),)
    if role == "certification":
        return (_require_role(records, "authoritative-fitting"),)
    if role not in {"canary", "formal"} or block is None:
        raise ValueError("capture campaign has an unsupported class-study evidence role")
    required = [_require_role(records, "certification")]
    for prior in range(1, block):
        required.append(_require_block(records, "canary", prior))
        required.append(_require_block(records, "formal", prior))
    if role == "formal":
        required.append(_require_block(records, "canary", block))
    return tuple(required)


def _validate_capture_fitting_generation(
    role: str,
    *,
    prerequisite_records: Sequence[Mapping[str, Any]],
    campaign_path: Path | None,
    frozen_result_root: Path | None,
    qualification_authority: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Bind a fitted capture to the exact fitting result that precedes it."""

    source_role = {
        "pilot-compatibility": "pilot-fitting",
        "certification": "authoritative-fitting",
    }.get(role)
    if source_role is None:
        return None
    source_record = _require_role(prerequisite_records, source_role)
    source_root = source_record.get("root")
    source_evidence_sha256 = source_record.get("evidence_sha256")
    if (
        not isinstance(source_root, str)
        or not isinstance(source_evidence_sha256, str)
        or _SHA256.fullmatch(source_evidence_sha256) is None
    ):
        raise ValueError("fitting-generation prerequisite result identity is incomplete")
    generation = verify_class_study_fitting_generation(
        source_result_root=Path(source_root),
        campaign_path=campaign_path,
        frozen_result_root=frozen_result_root,
        expected_qualification_authority=_validated_qualification_authority(
            qualification_authority
        ),
    )
    source = generation.get("source_result")
    if (
        not isinstance(source, Mapping)
        or Path(str(source.get("root"))).resolve() != Path(source_root).resolve()
        or source.get("evidence_sha256") != source_evidence_sha256
    ):
        raise ValueError("fitting-generation verification used another prerequisite result")
    return generation


def _require_capture_admission_binding(
    value: Mapping[str, Any],
    *,
    admission: CohortAdmission,
    role: str,
) -> None:
    if (
        value.get("class_study_cohort_sha256") != admission.cohort_sha256
        or value.get("class_study_cohort_assembly_sha256") != admission.assembly_sha256
    ):
        raise ValueError("capture input is bound to a different cohort admission")
    selected = (
        admission.selection.pilot
        if role in {"pilot-fitting", "pilot-compatibility"}
        else admission.selection.final
    )
    expected_ids = tuple(item.candidate_id for item in selected)
    workloads = value.get("workloads")
    if not isinstance(workloads, list):
        raise TypeError("capture input workload inventory is malformed")
    observed_ids = tuple(record.get("id") for record in workloads if isinstance(record, Mapping))
    if observed_ids != expected_ids or len(workloads) != len(expected_ids):
        raise ValueError("capture input workload order differs from cohort admission")
    for record in workloads:
        if not isinstance(record, Mapping) or record.get(
            "sha256"
        ) != admission.prepared_workload_sha256.get(str(record.get("id"))):
            raise ValueError("capture input prepared workload differs from cohort admission")


def _sealed_configuration_input(
    verified: VerifiedResult,
    *,
    relative: str,
    configuration_key: str,
    label: str,
) -> str:
    configuration = verified.experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise TypeError(f"{label} has no frozen configuration")
    path = verified.root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a sealed regular file")
    digest = sha256_file(path)
    if verified.checksums.get(relative) != digest or configuration.get(configuration_key) != digest:
        raise ValueError(f"{label} is not checksum/configuration bound")
    return digest


def _forbid_sealed_configuration_input(
    verified: VerifiedResult,
    *,
    relative: str,
    configuration_key: str,
    label: str,
) -> None:
    configuration = verified.experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise TypeError(f"{label} has no frozen configuration")
    path = verified.root / relative
    if configuration_key in configuration or path.exists() or path.is_symlink():
        raise ValueError(f"{label} is forbidden for this class-study role")


def _defense_runtime_input_identities(
    configuration: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Recover every mode's typed runtime input from frozen configuration.

    External parameter files are only one kind of runtime input.  Static is
    driven by its frozen schedule, while undefended, FRONT, and Tamaraw are
    source-bound built-ins.  Keeping those cases typed prevents an absent
    ``parameters_sha256`` field from being mistaken for an unbound mode.
    """

    records = configuration.get("defenses")
    if not isinstance(records, list) or not records:
        raise TypeError("class-study result defense inventory is malformed")
    identities: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise TypeError("class-study result defense record is malformed")
        name = record.get("name")
        kind = record.get("kind")
        if (
            not isinstance(name, str)
            or name not in _RUNTIME_KIND_BY_MODE
            or kind != _RUNTIME_KIND_BY_MODE[name]
            or name in identities
        ):
            raise ValueError("class-study result defense runtime identity is invalid")
        has_parameter_fields = any(
            key in record
            for key in (
                "parameters",
                "parameters_sha256",
                "provenance",
                "provenance_sha256",
                "input_policy",
            )
        )
        has_schedule_fields = any(key in record for key in ("schedule", "schedule_sha256", "mode"))
        if name in _EXTERNAL_PARAMETER_MODES:
            parameters_sha256 = record.get("parameters_sha256")
            provenance_sha256 = record.get("provenance_sha256")
            input_policy = record.get("input_policy")
            if (
                not has_parameter_fields
                or has_schedule_fields
                or not isinstance(parameters_sha256, str)
                or _SHA256.fullmatch(parameters_sha256) is None
                or not isinstance(provenance_sha256, str)
                or _SHA256.fullmatch(provenance_sha256) is None
                or not isinstance(input_policy, str)
                or not input_policy
            ):
                raise ValueError(f"class-study {name} runtime parameter binding is incomplete")
            identity = {
                "identity_type": "hash-bound-parameter-artifact",
                "runtime_kind": kind,
                "parameters_sha256": parameters_sha256,
                "provenance_sha256": provenance_sha256,
                "input_policy": input_policy,
            }
        elif name == "static":
            schedule_sha256 = record.get("schedule_sha256")
            mode = record.get("mode")
            if (
                has_parameter_fields
                or not has_schedule_fields
                or not isinstance(schedule_sha256, str)
                or _SHA256.fullmatch(schedule_sha256) is None
                or mode not in {"chaff-only", "chaff-and-shape"}
            ):
                raise ValueError("class-study static runtime schedule binding is incomplete")
            identity = {
                "identity_type": "hash-bound-static-schedule",
                "runtime_kind": kind,
                "schedule_sha256": schedule_sha256,
                "mode": mode,
            }
        else:
            if has_parameter_fields or has_schedule_fields:
                raise ValueError(f"class-study source-bound {name} has unexpected external input")
            identity = {
                "identity_type": (
                    "source-bound-no-defense" if name == "undefended" else "source-bound-built-in"
                ),
                "runtime_kind": kind,
            }
        identities[name] = identity
    return identities


def _validate_verified_class_result(
    verified: VerifiedResult,
    *,
    admission: CohortAdmission,
    expected_role: str | None,
    expected_block: int | None,
) -> dict[str, Any]:
    experiment = verified.experiment
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise TypeError("class-study result has no frozen configuration")
    role = configuration.get("evidence_role")
    if not isinstance(role, str) or role not in {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }:
        raise ValueError("sealed result is not a class-study evidence role")
    if expected_role is not None and role != expected_role:
        raise ValueError("class-study result has the wrong expected evidence role")
    name = experiment.get("name")
    if not isinstance(name, str):
        raise TypeError("class-study result has no canonical name")
    study_id = configuration.get("class_study_id", STUDY_ID)
    successor_sha256: str | None = None
    if CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY in configuration:
        successor_sha256 = _sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_SUCCESSOR_INPUT,
            configuration_key=CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY,
            label="class-study successor restart",
        )
        if (
            not is_successor_study_id(study_id)
            or role not in {"authoritative-fitting", "certification", "canary", "formal"}
        ):
            raise ValueError("class-study result successor identity is invalid")
    else:
        _forbid_sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_SUCCESSOR_INPUT,
            configuration_key=CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY,
            label="class-study successor restart",
        )
        if study_id != STUDY_ID:
            raise ValueError("class-study result has an unbound alternate study identity")
    block = _result_block(name, role, study_id=str(study_id))
    if expected_block is not None and block != expected_block:
        raise ValueError("class-study result has the wrong acquisition block")
    expected_name = _CANONICAL_NAMES.get(role)
    if successor_sha256 is not None:
        expected_name = {
            "authoritative-fitting": f"{study_id}-authoritative-fitting-2000-1200",
            "certification": f"{study_id}-certification-900-1200",
        }.get(role)
    if expected_name is not None and name != expected_name:
        raise ValueError("class-study result name is not canonical")
    if (
        experiment.get("status") != "complete"
        or not isinstance(experiment.get("summary"), Mapping)
        or experiment["summary"].get("passed") is not True
    ):
        raise ValueError("class-study evidence result is not complete and passed")
    cohort_input = _regular_file(
        verified.root / "inputs/class-study-cohort.json",
        "frozen class-study cohort",
    )
    if sha256_file(cohort_input) != admission.cohort_sha256:
        raise ValueError("class-study result is bound to a different cohort receipt")
    assembly_input = _regular_file(
        verified.root / "inputs/class-study-cohort-assembly.json",
        "frozen class-study cohort assembly",
    )
    if sha256_file(assembly_input) != admission.assembly_sha256:
        raise ValueError("class-study result is bound to a different cohort assembly")
    launch_sha256 = _sealed_configuration_input(
        verified,
        relative=CLASS_STUDY_LAUNCH_INPUT,
        configuration_key="class_study_launch_sha256",
        label="class-study first-launch claim",
    )
    readiness_sha256: str | None = None
    historical_pre_sha256: str | None = None
    foundation_sha256 = _sealed_configuration_input(
        verified,
        relative=CLASS_STUDY_FOUNDATION_INPUT,
        configuration_key=CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY,
        label="class-study foundation attestation",
    )
    if role in {"canary", "formal"}:
        readiness_sha256 = _sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_READINESS_INPUT,
            configuration_key=CLASS_STUDY_READINESS_CONFIGURATION_KEY,
            label="class-study readiness attestation",
        )
        historical_pre_sha256 = _sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_HISTORICAL_PRE_INPUT,
            configuration_key=CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY,
            label="class-study historical pre snapshot",
        )
    else:
        _forbid_sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_READINESS_INPUT,
            configuration_key=CLASS_STUDY_READINESS_CONFIGURATION_KEY,
            label="class-study readiness attestation",
        )
        _forbid_sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_HISTORICAL_PRE_INPUT,
            configuration_key=CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY,
            label="class-study historical pre snapshot",
        )

    expected_qualification_set = {
        "pilot-compatibility": PILOT_QUALIFICATION_SET,
        "certification": AUTHORITATIVE_QUALIFICATION_SET,
        "formal": AUTHORITATIVE_QUALIFICATION_SET,
    }.get(role)
    if successor_sha256 is not None and role in {"certification", "formal"}:
        expected_qualification_set = f"{study_id}-final-full"
    qualification_set = configuration.get("chaff_qualification_set")
    qualification_manifest_sha256 = configuration.get("chaff_qualification_set_manifest_sha256")
    if expected_qualification_set is None:
        if (
            "chaff_qualification_set" in configuration
            or "chaff_qualification_set_manifest_sha256" in configuration
        ):
            raise ValueError(f"{role} result unexpectedly uses a named qualification set")
        qualification_manifest_sha256 = None
    elif (
        qualification_set != expected_qualification_set
        or not isinstance(qualification_manifest_sha256, str)
        or _SHA256.fullmatch(qualification_manifest_sha256) is None
    ):
        raise ValueError(f"{role} result has no exact named qualification-set manifest binding")

    selected = (
        admission.selection.pilot
        if role in {"pilot-fitting", "pilot-compatibility"}
        else admission.selection.final
    )
    selected_ids = tuple(item.candidate_id for item in selected)
    workload_records = configuration.get("workloads")
    if not isinstance(workload_records, list):
        raise TypeError("class-study result workload inventory is malformed")
    if (
        tuple(record.get("id") for record in workload_records if isinstance(record, Mapping))
        != selected_ids
    ):
        raise ValueError("class-study result workload order differs from cohort admission")
    for record in workload_records:
        if not isinstance(record, Mapping):
            raise TypeError("class-study result workload record is malformed")
        workload_id = record["id"]
        if record.get("sha256") != admission.prepared_workload_sha256[workload_id]:
            raise ValueError("class-study result prepared workload differs from cohort assembly")

    if role in {"pilot-fitting", "authoritative-fitting"}:
        fitted_stage = PILOT_STAGE if role == "pilot-fitting" else AUTHORITATIVE_STAGE
        fitting = validate_class_fitting_result(
            verified.root,
            expected_stage=fitted_stage,
            expected_cohort_receipt_path=admission.cohort_path,
            expected_cohort_assembly_receipt_path=admission.assembly_path,
        )
        sample_count = len(fitting.verified.experiment["samples"])
        unique_class_mode_pairs = None
    else:
        sample_count, unique_class_mode_pairs = _validate_non_fitting_result(
            verified,
            role=role,
            selected_ids=selected_ids,
        )
    evidence_path = _regular_file(verified.root / "evidence.sha256", "class-study evidence seal")
    experiment_sha256 = verified.checksums.get("experiment.json")
    if not isinstance(experiment_sha256, str):
        raise TypeError("class-study evidence seal does not bind experiment.json")
    defense_runtime_inputs = _defense_runtime_input_identities(configuration)
    defense_parameter_sha256 = {
        name: str(identity["parameters_sha256"])
        for name, identity in defense_runtime_inputs.items()
        if identity["identity_type"] == "hash-bound-parameter-artifact"
    }
    return {
        "valid": True,
        "root": str(verified.root),
        "name": name,
        "evidence_role": role,
        "block": block,
        "samples": sample_count,
        "accepted": len(verified.accepted_samples),
        "cohort_sha256": admission.cohort_sha256,
        "cohort_assembly_sha256": admission.assembly_sha256,
        "evidence_sha256": sha256_file(evidence_path),
        "class_study_launch_sha256": launch_sha256,
        "class_study_foundation_sha256": foundation_sha256,
        "class_study_readiness_sha256": readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": historical_pre_sha256,
        "class_study_id": study_id,
        "class_study_successor_sha256": successor_sha256,
        "experiment_sha256": experiment_sha256,
        "unique_class_mode_pairs": unique_class_mode_pairs,
        "first_launch_unique_class_mode_pairs": (
            unique_class_mode_pairs if role == "certification" else None
        ),
        "defense_parameter_sha256": defense_parameter_sha256,
        "defense_runtime_inputs": defense_runtime_inputs,
        "chaff_qualification_set": qualification_set,
        "chaff_qualification_set_manifest_sha256": (qualification_manifest_sha256),
    }


def _validate_current_candidate_sample_receipt(
    verified: VerifiedResult,
    sample: Mapping[str, Any],
    *,
    role: str,
) -> None:
    """Reopen one sealed candidate run and require the current terminal schema.

    ``verify_result`` proves checksum closure, while this boundary proves that
    a class-study certification/formal result still contains the current
    candidate semantics.  In particular, a historical schema-2/3 receipt must
    never be promoted merely because its experiment checkpoint says
    ``accepted`` and ``eligible``.
    """

    mode = sample.get("defense")
    runtime_kind = _CURRENT_CANDIDATE_RUNTIME_KINDS.get(str(mode))
    if runtime_kind is None:
        return
    sample_id = sample.get("sample_id")
    sample_path = sample.get("path")
    artifacts = sample.get("artifacts")
    accepted = verified.accepted_samples.get(str(sample_id))
    if (
        not isinstance(sample_id, str)
        or not isinstance(sample_path, str)
        or sample.get("runtime_kind") != runtime_kind
        or not isinstance(artifacts, Mapping)
        or not isinstance(accepted, Mapping)
    ):
        raise ValueError(f"{role} candidate sample has an invalid accepted-evidence identity")
    expected_artifacts = {f"{sample_path}/{relative}" for relative in ACCEPTED_ARTIFACTS}
    if set(artifacts) != expected_artifacts or dict(artifacts) != dict(accepted):
        raise ValueError(f"{role} candidate sample differs from its sealed five-file inventory")
    sample_root = resolved_sample_directory(verified.root, sample, require_directory=True)
    run_path = sample_root / "neqo/run.json"
    run_relative = run_path.relative_to(verified.root).as_posix()
    run_digest = artifacts.get(run_relative)
    if (
        run_path.is_symlink()
        or not run_path.is_file()
        or not isinstance(run_digest, str)
        or verified.checksums.get(run_relative) != run_digest
        or sha256_file(run_path) != run_digest
    ):
        raise ValueError(f"{role} candidate run is not bound to its sealed accepted evidence")
    try:
        run = load_json(run_path)
    except (OSError, ValueError) as error:
        raise ValueError(f"{role} candidate run receipt is invalid") from error
    if not isinstance(run, Mapping) or not new_defense_terminal_receipts_valid(
        run,
        runtime_kind,
        require_application_complete=True,
        require_current_schema=True,
    ):
        summary_key = "buflo_summary" if runtime_kind == "buflo" else "cs_buflo_summary"
        summary = run.get(summary_key) if isinstance(run, Mapping) else None
        schema = summary.get("schema_version") if isinstance(summary, Mapping) else None
        raise ValueError(
            f"{role} {mode} sample {sample_id} lacks a valid current "
            f"schema-4 terminal receipt and runner-wakeup "
            f"schema-{'12 with kernel-TX evidence' if runtime_kind == 'buflo' else '10'} "
            f"(observed terminal schema {schema!r})"
        )
    # Import lazily so the coordinator's core/result metadata import graph stays
    # independent of the heavier handoff parsers while reusing their exact
    # schedule, event, and packet chronology validator at this evidence boundary.
    from .buflo_handoff import _algorithm_diagnostics

    try:
        algorithm = _algorithm_diagnostics(
            run,
            defense=str(mode),
            runtime_kind=runtime_kind,
            schedule_path=sample_root / "neqo/schedule.csv",
            events_path=sample_root / "neqo/events.csv",
            packets_path=sample_root / "neqo/packets.csv",
            require_current=True,
            require_latest_cs=True,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(
            f"{role} {mode} sample {sample_id} has invalid current terminal/schedule chronology"
        ) from error
    if algorithm.get("schema_version") != 4:
        raise ValueError(
            f"{role} {mode} sample {sample_id} did not derive schema-4 algorithm evidence"
        )


def _validate_class_sample_run_receipt(
    verified: VerifiedResult,
    sample: Mapping[str, Any],
    *,
    role: str,
) -> None:
    """Reopen one accepted run and bind it to the full admitted workload graph."""

    sample_id = sample.get("sample_id")
    sample_path = sample.get("path")
    artifacts = sample.get("artifacts")
    accepted = verified.accepted_samples.get(str(sample_id))
    if (
        not isinstance(sample_id, str)
        or not isinstance(sample_path, str)
        or not isinstance(artifacts, Mapping)
        or not isinstance(accepted, Mapping)
    ):
        raise ValueError(f"{role} sample has an invalid accepted-evidence identity")
    expected_artifacts = {f"{sample_path}/{relative}" for relative in ACCEPTED_ARTIFACTS}
    if set(artifacts) != expected_artifacts or dict(artifacts) != dict(accepted):
        raise ValueError(f"{role} sample differs from its sealed five-file inventory")
    sample_root = resolved_sample_directory(
        verified.root,
        sample,
        require_directory=True,
    )
    run_path = sample_root / "neqo/run.json"
    run_relative = run_path.relative_to(verified.root).as_posix()
    run_digest = artifacts.get(run_relative)
    if (
        run_path.is_symlink()
        or not run_path.is_file()
        or not isinstance(run_digest, str)
        or verified.checksums.get(run_relative) != run_digest
        or sha256_file(run_path) != run_digest
    ):
        raise ValueError(f"{role} run is not bound to its sealed accepted evidence")
    run = load_json(run_path)
    configuration = verified.experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError(f"{role} result has no frozen configuration")
    binding = resolve_class_sample_run_binding(
        verified.root,
        configuration,
        sample,
        allow_derived_runtime_without_frozen_copy=role == "canary",
    )
    validate_class_sample_run_binding(run, sample, binding)
    diagnostics = run.get("defense_diagnostics") if isinstance(run, Mapping) else None
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    schedule = _schedule_realization_metrics_from_path(sample_root / "neqo/schedule.csv")
    defense = defense_from_runtime_identity(
        str(sample.get("defense")),
        str(sample.get("runtime_kind")),
    )
    if not fidelity_eligible(
        defense,
        diagnostics,
        sample_eligible=True,
        missed_events=schedule.get("missed_events"),
        outgoing_size_mismatches=schedule.get("outgoing_size_mismatch_events"),
        schedule_metrics=schedule,
        resolved_configuration=(
            run.get("resolved_configuration") if isinstance(run, Mapping) else None
        ),
        require_defense_activation=True,
    ):
        raise ValueError(f"{role} sample has no independently valid defence activation evidence")


def _validate_non_fitting_result(
    verified: VerifiedResult,
    *,
    role: str,
    selected_ids: tuple[str, ...],
) -> tuple[int, int | None]:
    expected_count = _NON_FITTING_COUNTS[role]
    samples = verified.experiment.get("samples")
    if (
        not isinstance(samples, list)
        or len(samples) != expected_count
        or len(verified.accepted_samples) != expected_count
    ):
        raise ValueError(f"{role} result does not contain exactly {expected_count} samples")
    configuration = verified.experiment["configuration"]
    raw_defenses = configuration.get("defenses")
    if not isinstance(raw_defenses, list):
        raise TypeError("class-study result defenses are malformed")
    defense_names = tuple(
        defense.get("name") for defense in raw_defenses if isinstance(defense, Mapping)
    )
    expected_modes = (
        ("undefended",)
        if role == "canary"
        else FORMAL_MODES
        if role == "formal"
        else COMPATIBILITY_MODES
    )
    if defense_names != expected_modes:
        raise ValueError(f"{role} result defense order differs from its contract")
    visits = 2 if role == "formal" else 1
    expected = {
        (workload_id, mode, visit)
        for workload_id in selected_ids
        for mode in expected_modes
        for visit in range(visits)
    }
    observed: set[tuple[str, str, int]] = set()
    class_mode_pairs: set[tuple[str, str]] = set()
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise TypeError("class-study result sample is malformed")
        identity = (sample.get("workload_id"), sample.get("defense"), sample.get("visit"))
        if identity not in expected or identity in observed:
            raise ValueError(f"{role} result is not the exact class/mode/visit cross-product")
        if (
            sample.get("state") != "accepted"
            or sample.get("eligible") is not True
            or sample.get("request_policy") != "as-defined"
            or type(sample.get("attempts")) is not int
            or not 1 <= sample["attempts"] <= (1 if role == "certification" else 3)
        ):
            raise ValueError(f"{role} result contains an ineligible or invalid attempt")
        if role == "certification" and sample["attempts"] != 1:
            raise ValueError("certification evidence must succeed on its first launch")
        _validate_class_sample_run_receipt(
            verified,
            sample,
            role=role,
        )
        if identity[1] in _CURRENT_CANDIDATE_RUNTIME_KINDS:
            _validate_current_candidate_sample_receipt(
                verified,
                sample,
                role=role,
            )
        observed.add(identity)  # type: ignore[arg-type]
        class_mode_pairs.add((identity[0], identity[1]))  # type: ignore[arg-type]
    if observed != expected:
        raise ValueError(f"{role} result is missing required cross-product samples")
    pair_count = len(class_mode_pairs) if role in {"pilot-compatibility", "certification"} else None
    if role == "certification" and pair_count != CERTIFICATION_PAIR_COUNT:
        raise ValueError("certification does not cover exactly 900 unique class/mode pairs")
    if role == "pilot-compatibility" and pair_count != _NON_FITTING_COUNTS[role]:
        raise ValueError("pilot compatibility does not cover exactly 1,080 class/mode pairs")
    return len(samples), pair_count


def _result_index(
    roots: Sequence[Path],
    *,
    pilot_admission: CohortAdmission | None,
    final_admission: CohortAdmission | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for root in roots:
        verified = verify_result(root)
        configuration = verified.experiment.get("configuration")
        if not isinstance(configuration, Mapping):
            raise TypeError("class-study prerequisite has no frozen configuration")
        role = configuration.get("evidence_role")
        if not isinstance(role, str):
            raise TypeError("class-study prerequisite has no evidence role")
        admission = _admission_for_role(role, pilot_admission, final_admission)
        records.append(
            _validate_verified_class_result(
                verified,
                admission=admission,
                expected_role=role,
                expected_block=None,
            )
        )
    names = [record["name"] for record in records]
    if len(names) != len(set(names)):
        raise ValueError("class-study prerequisite results contain duplicate campaign identities")
    return sorted(records, key=_result_sort_key)


def _result_sort_key(record: Mapping[str, Any]) -> tuple[int, int, str]:
    order = {
        "pilot-fitting": 0,
        "pilot-compatibility": 1,
        "authoritative-fitting": 2,
        "certification": 3,
        "canary": 4,
        "formal": 5,
    }
    return order[str(record["evidence_role"])], int(record.get("block") or 0), str(record["name"])


def _result_status_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    roles: dict[str, int] = {}
    for record in records:
        role = str(record["evidence_role"])
        roles[role] = roles.get(role, 0) + 1
    certification = next(
        (record for record in records if record["evidence_role"] == "certification"), None
    )
    return {
        "state": "verified" if records else "absent",
        "verified_results": len(records),
        "by_evidence_role": roles,
        "certification": {
            "expected_samples": CERTIFICATION_PAIR_COUNT,
            "expected_unique_class_mode_pairs": CERTIFICATION_PAIR_COUNT,
            "first_launch_only": True,
            "verified": certification is not None,
            "observed_unique_class_mode_pairs": (
                certification["first_launch_unique_class_mode_pairs"]
                if certification is not None
                else 0
            ),
        },
        "records": list(records),
    }


def _require_role(records: Sequence[Mapping[str, Any]], role: str) -> Mapping[str, Any]:
    matches = [record for record in records if record["evidence_role"] == role]
    if len(matches) != 1:
        raise ValueError(f"class-study stage requires exactly one verified {role} result")
    return matches[0]


def _require_successor_result_records(
    records: Sequence[Mapping[str, Any]],
    *,
    restart_sha256: str,
    study_id: str,
) -> None:
    """Reject predecessor or mixed-successor downstream evidence."""

    if _SHA256.fullmatch(restart_sha256) is None or not is_successor_study_id(study_id):
        raise ValueError("successor result authority is malformed")
    if any(
        record.get("class_study_successor_sha256") != restart_sha256
        or record.get("class_study_id") != study_id
        for record in records
    ):
        raise ValueError("successor stage includes predecessor or mixed restart evidence")


def _require_block(
    records: Sequence[Mapping[str, Any]], role: str, block: int
) -> Mapping[str, Any]:
    matches = [
        record for record in records if record["evidence_role"] == role and record["block"] == block
    ]
    if len(matches) != 1:
        raise ValueError(f"class-study stage requires verified {role} block {block:02d} evidence")
    return matches[0]


def _require_fitting_source(
    source: Path,
    stage: str,
    admission: CohortAdmission,
) -> dict[str, Any]:
    role = "pilot-fitting" if stage == PILOT_STAGE else "authoritative-fitting"
    record = verify_class_study_result(source, admission=admission, expected_role=role)
    validate_class_fitting_result(
        source,
        expected_stage=stage,
        expected_cohort_receipt_path=admission.cohort_path,
        expected_cohort_assembly_receipt_path=admission.assembly_path,
    )
    return record


def _require_numeric_admission(numeric: Any, admission: CohortAdmission) -> None:
    cohort = numeric.provenance.get("cohort")
    if (
        not isinstance(cohort, Mapping)
        or cohort.get("receipt_sha256") != admission.cohort_sha256
        or cohort.get("assembly_receipt_sha256") != admission.assembly_sha256
    ):
        raise ValueError("numeric fitting bundle is bound to a different cohort admission")
    expected = tuple(
        item.candidate_id
        for item in (
            admission.selection.pilot if numeric.stage == PILOT_STAGE else admission.selection.final
        )
    )
    if tuple(numeric.provenance["fitting_contract"]["workload_order"]) != expected:
        raise ValueError("numeric fitting workload order differs from cohort admission")


def _require_successor_fitting_artifact(
    artifact: VerifiedNumericFittingBundle | VerifiedClassFittingBundle,
    successor_context: Mapping[str, Any],
) -> None:
    """Bind a verified fitting artifact to the exact active successor restart."""

    require_successor_fitting_identity(
        artifact.provenance,
        expected_study_id=str(successor_context["study_id"]),
        expected_restart_sha256=sha256_file(successor_context["restart_path"]),
    )


def _require_successor_foundation_sha256(
    observed_sha256: object,
    successor_context: Mapping[str, Any],
) -> None:
    """Reject any foundation except the predecessor authority frozen by restart."""

    expected_sha256 = successor_context["restart"].get("predecessor_foundation_sha256")
    if observed_sha256 != expected_sha256:
        raise ValueError("successor action uses another foundation authority")


def _qualification_authority_for_action(
    foundation_attestation: Path,
    *,
    deep_code_gate: bool,
    runtime_role: str,
    successor_context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Derive qualification authority and retain the exact successor foundation."""

    from .class_attestation import class_qualification_authority

    authority = class_qualification_authority(
        foundation_attestation,
        deep_code_gate=deep_code_gate,
        runtime_role=runtime_role,
    )
    if successor_context is not None:
        foundation = authority.get("foundation_attestation")
        observed_sha256 = foundation.get("sha256") if isinstance(foundation, Mapping) else None
        _require_successor_foundation_sha256(
            observed_sha256,
            successor_context,
        )
    return authority


def _verify_prefix_spec_root(
    root: Path,
    *,
    numeric_bundle_root: Path,
    workload_root: Path,
) -> dict[str, Any]:
    numeric = verify_numeric_fitting_bundle(numeric_bundle_root)
    directory = _regular_directory(root, "class-study prefix-spec root")
    workloads = tuple(numeric.provenance["fitting_contract"]["workload_order"])
    expected_names = {f"{workload_id}.json" for workload_id in workloads}
    observed_names = {path.name for path in directory.iterdir()}
    if observed_names != expected_names:
        raise ValueError("prefix-spec root does not contain the exact fitting cohort")
    walkie_path = numeric.root / "walkie-talkie.json"
    walkie = load_json(walkie_path)
    for workload_id in workloads:
        manifest = load_json(
            _regular_file(workload_root / f"{workload_id}.json", "prepared workload")
        )
        validate_schema_six_prefix_spec(
            load_json(directory / f"{workload_id}.json"),
            workload_id=workload_id,
            walkie_talkie=walkie,
            source_walkie_talkie_artifact_sha256=sha256_file(walkie_path),
            application_manifest=manifest,
        )
    return {
        "valid": True,
        "root": str(directory),
        "stage": numeric.stage,
        "workloads": len(workloads),
        "source_walkie_talkie_sha256": sha256_file(walkie_path),
    }


def _verify_target(
    target: Path,
    *,
    admission: CohortAdmission,
    fitting_stage: str,
    fitting_source_result_root: Path | None,
    workload_root: Path,
    numeric_bundle_root: Path | None,
    prefix_spec_root: Path | None,
    qualification_manifest: Path | None,
    foundation_attestation: Path | None,
    handoff: Path | None,
    deep: bool,
    successor_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    path = Path(os.path.abspath(target))
    if path.is_dir() and (path / "experiment.json").is_file():
        result = verify_class_study_result(path, admission=admission)
        if successor_context is not None:
            _require_successor_result_records(
                (result,),
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        return result
    if path.is_dir() and (path / "dataset.json").is_file():
        root = verify_class_handoff(path, deep=deep)
        if successor_context is not None:
            _require_successor_handoff_lineage(root, successor_context)
        return {"valid": True, "root": str(root)}
    if path.is_dir() and (path / NAMED_QUALIFICATION_SET_MANIFEST).is_file():
        authority = _qualification_authority_for_action(
            _required(foundation_attestation, "--foundation-attestation"),
            deep_code_gate=deep,
            runtime_role="collection",
            successor_context=successor_context,
        )
        stage = (
            AUTHORITATIVE_STAGE
            if successor_context is not None
            else _stage_from_qualification_path(path / NAMED_QUALIFICATION_SET_MANIFEST)
        )
        expected_set = (
            f"{successor_context['study_id']}-final-full"
            if successor_context is not None
            else _qualification_set(stage)
        )
        if successor_context is not None and path != Path(
            successor_context["qualification_sidecar_root"]
        ):
            raise ValueError("successor qualification verification target is not canonical")
        prefix = _required(prefix_spec_root, "--prefix-spec-root")
        output = load_named_qualification_set(
            path / NAMED_QUALIFICATION_SET_MANIFEST,
            workload_root=workload_root,
            sidecar_root=path,
            prefix_spec_root=prefix,
            expected_qualification_set=expected_set,
            expected_qualification_scope=FULL_QUALIFICATION_SCOPE,
            expected_workload_ids=_stage_workloads(admission, stage),
            expected_qualification_authority=authority,
        )
        _validate_qualification_sidecars(path, _stage_workloads(admission, stage), authority)
        return {
            "valid": True,
            "root": str(output.path),
            "qualification_set": output.qualification_set,
            "manifest_sha256": output.manifest_sha256,
        }
    if path.is_dir():
        source = _required(fitting_source_result_root, "--capture-result")
        source_record = _require_fitting_source(source, fitting_stage, admission)
        if successor_context is not None:
            _require_successor_result_records(
                (source_record,),
                restart_sha256=sha256_file(successor_context["restart_path"]),
                study_id=successor_context["study_id"],
            )
        context: QualificationContext | None = None
        if qualification_manifest is not None and prefix_spec_root is not None:
            context = QualificationContext(
                workload_root=workload_root,
                sidecar_root=qualification_manifest.parent,
                prefix_spec_root=prefix_spec_root,
                qualification_authority=_qualification_authority_for_action(
                    _required(foundation_attestation, "--foundation-attestation"),
                    deep_code_gate=deep,
                    runtime_role="collection",
                    successor_context=successor_context,
                ),
                expected_qualification_set=(
                    f"{successor_context['study_id']}-final-full"
                    if successor_context is not None
                    else None
                ),
            )
        verified = verify_class_fitting_artifact_root(
            path,
            qualification_context=context,
            source_result_root=source,
        )
        if verified.stage != fitting_stage:
            raise ValueError("fitting artifact has the wrong requested stage")
        _require_numeric_admission(verified, admission)
        if successor_context is not None:
            _require_successor_fitting_artifact(verified, successor_context)
        return verified.as_dict()
    value = _load_json_object(path, "class-study verification target")
    if value.get("receipt_type") == COHORT_RECEIPT_TYPE:
        if path != admission.cohort_path:
            raise ValueError("verification target is not the admitted cohort receipt")
        return admission.as_dict()
    if value.get("receipt_type") == STABILITY_RECEIPT_TYPE:
        _receipt, decision = load_stability_receipt(path)
        return {"valid": True, "path": str(path), **decision.as_dict()}
    if (
        value.get("artifact_type") == "qcsd-class-study-evaluation"
        or value.get("receipt_type") == "qcsd-class-study-evaluation"
    ):
        if handoff is None:
            raise ValueError("evaluation verification requires --handoff")
        from .class_evaluation import verify_class_evaluation_receipt

        verified = verify_class_evaluation_receipt(
            path,
            handoff_root=handoff,
            deep_verify_handoff=deep,
        )
        if successor_context is not None:
            _require_successor_handoff_lineage(handoff, successor_context)
            _require_successor_receipt_lineage(
                verified,
                successor_context,
                label="evaluation receipt",
                require_restart=False,
            )
        return verified
    raise ValueError("target is not a recognised class-study artifact")


def _campaign_documents_with_assembly(
    cohort_path: Path,
    assembly_path: Path,
    *,
    enforce_fresh_layout: bool = True,
    **references: str,
) -> dict[str, dict[str, Any]]:
    """Call the schema-two generator while enforcing its assembly-aware API."""

    try:
        documents = campaign_documents(
            cohort_path,
            cohort_assembly_receipt=assembly_path,
            _enforce_fresh_layout=enforce_fresh_layout,
            **references,
        )
    except TypeError as error:
        if "cohort_assembly_receipt" not in str(error):
            raise
        raise RuntimeError(
            "class campaign generator lacks intrinsic class_study_cohort_assembly support"
        ) from error
    if any(
        document.get("class_study_cohort_assembly") != references["cohort_assembly_reference"]
        for document in documents.values()
    ):
        raise ValueError("generated campaigns do not carry the exact cohort assembly reference")
    return documents


def _validate_pilot_campaign_documents(
    documents: Mapping[str, Mapping[str, Any]],
    admission: CohortAdmission,
) -> None:
    by_role = {str(document.get("evidence_role")): document for document in documents.values()}
    fitting = by_role["pilot-fitting"]
    compatibility = by_role["pilot-compatibility"]
    cohort_reference = fitting.get("class_study_cohort")
    assembly_reference = fitting.get("class_study_cohort_assembly")
    if (
        not isinstance(cohort_reference, str)
        or not isinstance(assembly_reference, str)
        or compatibility.get("class_study_cohort") != cohort_reference
        or compatibility.get("class_study_cohort_assembly") != assembly_reference
    ):
        raise ValueError("pilot campaigns do not share their exact admission references")
    bundle = _fitted_bundle_reference(compatibility)
    expected = _campaign_documents_with_assembly(
        admission.cohort_path,
        admission.assembly_path,
        enforce_fresh_layout=False,
        cohort_reference=cohort_reference,
        cohort_assembly_reference=assembly_reference,
        pilot_bundle_reference=bundle,
        authoritative_bundle_reference="unused-by-pilot-stage",
    )
    expected = {
        name: value
        for name, value in expected.items()
        if value["evidence_role"] in {"pilot-fitting", "pilot-compatibility"}
    }
    if canonical_json_bytes(documents) != canonical_json_bytes(expected):
        raise ValueError("pilot campaign files differ from the deterministic stage contract")


def _validate_full_campaign_documents(
    documents: Mapping[str, Mapping[str, Any]],
    *,
    pilot_admission: CohortAdmission,
    final_admission: CohortAdmission,
) -> None:
    by_role: dict[str, list[Mapping[str, Any]]] = {}
    for document in documents.values():
        by_role.setdefault(str(document.get("evidence_role")), []).append(document)
    pilot_fitting = by_role["pilot-fitting"][0]
    pilot_compatibility = by_role["pilot-compatibility"][0]
    authoritative_fitting = by_role["authoritative-fitting"][0]
    certification = by_role["certification"][0]
    pilot_bundle = _fitted_bundle_reference(pilot_compatibility)
    authoritative_bundle = _fitted_bundle_reference(certification)
    pilot_expected = _campaign_documents_with_assembly(
        pilot_admission.cohort_path,
        pilot_admission.assembly_path,
        enforce_fresh_layout=False,
        cohort_reference=str(pilot_fitting["class_study_cohort"]),
        cohort_assembly_reference=str(pilot_fitting["class_study_cohort_assembly"]),
        pilot_bundle_reference=pilot_bundle,
        authoritative_bundle_reference=authoritative_bundle,
    )
    final_expected = _campaign_documents_with_assembly(
        final_admission.cohort_path,
        final_admission.assembly_path,
        enforce_fresh_layout=False,
        cohort_reference=str(authoritative_fitting["class_study_cohort"]),
        cohort_assembly_reference=str(authoritative_fitting["class_study_cohort_assembly"]),
        pilot_bundle_reference=pilot_bundle,
        authoritative_bundle_reference=authoritative_bundle,
    )
    expected = {
        name: value
        for name, value in pilot_expected.items()
        if value["evidence_role"] in {"pilot-fitting", "pilot-compatibility"}
    }
    expected.update(
        {
            name: value
            for name, value in final_expected.items()
            if value["evidence_role"] not in {"pilot-fitting", "pilot-compatibility"}
        }
    )
    if canonical_json_bytes(documents) != canonical_json_bytes(expected):
        raise ValueError("campaign set differs from the deterministic two-freeze contract")


def _fitted_bundle_reference(document: Mapping[str, Any]) -> str:
    defenses = document.get("defenses")
    traffic = (
        next(
            (
                item
                for item in defenses
                if isinstance(item, Mapping) and item.get("name") == "traffic-morphing"
            ),
            None,
        )
        if isinstance(defenses, list)
        else None
    )
    parameters = traffic.get("parameters") if isinstance(traffic, Mapping) else None
    suffix = "/traffic-morphing.json"
    if not isinstance(parameters, str) or not parameters.endswith(suffix):
        raise ValueError("campaign has no canonical fitted-bundle reference")
    return parameters.removesuffix(suffix)


def _campaign_role(preflight: Mapping[str, Any]) -> str:
    role = preflight.get("evidence_role")
    if not isinstance(role, str):
        raise TypeError("campaign is not class-study evidence")
    return role


def _campaign_block(preflight: Mapping[str, Any]) -> int | None:
    return _result_block(
        str(preflight.get("name")),
        _campaign_role(preflight),
        study_id=str(preflight.get("class_study_id", STUDY_ID)),
    )


def _result_block(name: str, role: str, *, study_id: str = STUDY_ID) -> int | None:
    if role not in {"canary", "formal"}:
        return None
    try:
        identity = parse_class_study_campaign_name(name)
    except ValueError as error:
        raise ValueError(f"{role} result name is not canonical") from error
    if (
        identity.study_id != study_id
        or identity.evidence_role != role
        or identity.block is None
    ):
        raise ValueError(f"{role} result name is not canonical")
    block = identity.block
    if not 1 <= block <= FORMAL_BLOCK_COUNT:
        raise ValueError(f"{role} block is outside 01..{FORMAL_BLOCK_COUNT:02d}")
    return block


def _stage_workloads(admission: CohortAdmission | None, stage: str) -> tuple[str, ...]:
    if admission is None:
        raise ValueError("stage workload resolution requires cohort admission")
    selected = admission.selection.pilot if stage == PILOT_STAGE else admission.selection.final
    return tuple(item.candidate_id for item in selected)


def _stage_from_name(name: str) -> str:
    if "-pilot-fitting" in name:
        return PILOT_STAGE
    if "-authoritative-fitting" in name:
        return AUTHORITATIVE_STAGE
    raise ValueError(f"cannot determine class fitting stage from canonical name: {name}")


def _stage_from_qualification_path(path: Path) -> str:
    names = {path.name, path.parent.name}
    if PILOT_QUALIFICATION_SET in names:
        return PILOT_STAGE
    if AUTHORITATIVE_QUALIFICATION_SET in names:
        return AUTHORITATIVE_STAGE
    raise ValueError("qualification path does not identify a canonical class-study set")


def _qualification_set(stage: str) -> str:
    return PILOT_QUALIFICATION_SET if stage == PILOT_STAGE else AUTHORITATIVE_QUALIFICATION_SET


def _validate_fresh_layout_arguments(
    *,
    action: str,
    stage: str | None,
    candidate_catalogue_path: Path | None,
    acquisition_root: Path | None,
    stability_root: Path | None,
    workload_root: Path | None,
    pilot_cohort_receipt_path: Path | None,
    pilot_cohort_assembly_path: Path | None,
    final_cohort_receipt_path: Path | None,
    final_cohort_assembly_path: Path | None,
    cohort_receipt_path: Path | None,
    cohort_assembly_path: Path | None,
    final_selection_path: Path | None,
    campaign_root: Path | None,
    campaign: Path | None,
    artifacts_root: Path | None,
    numeric_bundle_root: Path | None,
    prefix_spec_root: Path | None,
    qualification_sidecar_root: Path | None,
    qualification_publication_root: Path | None,
    qualification_manifest: Path | None,
    final_bundle_root: Path | None,
    destination: Path | None,
) -> None:
    """Fail closed on alternate prospective paths before an action mutates.

    ``status``, ``resume``, and ``verify`` deliberately bypass this boundary:
    they may inspect immutable result-local inputs from an older cohort.  The
    fresh capture path remains constrained here and again in ``orchestrator``.
    """

    if action not in _FRESH_LAYOUT_ACTIONS:
        return
    if candidate_catalogue_path is not None:
        require_canonical_fresh_child(
            candidate_catalogue_path,
            field="study_config_root",
            filename=f"{STUDY_ID}-candidates.json",
            label="candidate catalogue",
        )
    if acquisition_root is not None:
        require_canonical_fresh_path(
            acquisition_root,
            field="acquisition_root",
            label="acquisition root",
        )
    if stability_root is not None:
        require_canonical_fresh_path(
            stability_root,
            field="stability_root",
            label="stability root",
        )
    if workload_root is not None:
        require_canonical_fresh_path(
            workload_root,
            field="workload_root",
            label="workload root",
        )
    for path, filename, label in (
        (
            pilot_cohort_receipt_path,
            PILOT_COHORT_FILENAME,
            "pilot cohort receipt",
        ),
        (
            pilot_cohort_assembly_path,
            PILOT_COHORT_ASSEMBLY_FILENAME,
            "pilot cohort assembly",
        ),
        (
            final_cohort_receipt_path,
            AUTHORITATIVE_COHORT_FILENAME,
            "final cohort receipt",
        ),
        (
            final_cohort_assembly_path,
            AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
            "final cohort assembly",
        ),
        (final_selection_path, FINAL_SELECTION_FILENAME, "final-selection receipt"),
    ):
        if path is not None:
            require_canonical_fresh_child(
                path,
                field="study_config_root",
                filename=filename,
                label=label,
            )
    cohort_filenames = {
        PILOT_STAGE: (PILOT_COHORT_FILENAME, PILOT_COHORT_ASSEMBLY_FILENAME),
        AUTHORITATIVE_STAGE: (
            AUTHORITATIVE_COHORT_FILENAME,
            AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
        ),
    }
    if cohort_receipt_path is not None or cohort_assembly_path is not None:
        if stage not in cohort_filenames:
            raise ValueError("fresh cohort receipt paths require --stage pilot or authoritative")
        cohort_filename, assembly_filename = cohort_filenames[stage]
        if cohort_receipt_path is not None:
            require_canonical_fresh_child(
                cohort_receipt_path,
                field="study_config_root",
                filename=cohort_filename,
                label="cohort receipt",
            )
        if cohort_assembly_path is not None:
            require_canonical_fresh_child(
                cohort_assembly_path,
                field="study_config_root",
                filename=assembly_filename,
                label="cohort assembly",
            )
    if campaign_root is not None:
        require_canonical_fresh_path(
            campaign_root,
            field="campaign_root",
            label="campaign root",
        )
    if campaign is not None:
        campaign_path = require_canonical_fresh_child(
            campaign,
            field="campaign_root",
            label="campaign",
        )
        if campaign_path.suffix != ".yml":
            raise ValueError("fresh class-study campaign must use a .yml filename")
    if artifacts_root is not None:
        require_canonical_fresh_path(
            artifacts_root,
            field="artifacts_root",
            label="artifact root",
        )
    _require_layout_choice(
        numeric_bundle_root,
        pilot_field="pilot_numeric_root",
        authoritative_field="authoritative_numeric_root",
        label="numeric bundle",
    )
    _require_layout_choice(
        prefix_spec_root,
        pilot_field="pilot_prefix_root",
        authoritative_field="authoritative_prefix_root",
        label="prefix-spec root",
    )
    _require_layout_choice(
        final_bundle_root,
        pilot_field="pilot_final_root",
        authoritative_field="authoritative_final_root",
        label="final bundle",
    )
    if qualification_publication_root is not None:
        require_canonical_fresh_path(
            qualification_publication_root,
            field="qualification_sets_root",
            label="qualification publication root",
        )
    if qualification_manifest is not None:
        qualification_field = _stage_layout_field(
            qualification_manifest.parent,
            stage=None,
            pilot_field="pilot_qualification_set_root",
            authoritative_field="final_qualification_set_root",
            label="qualification manifest",
        )
        require_canonical_fresh_child(
            qualification_manifest,
            field=qualification_field,
            filename=NAMED_QUALIFICATION_SET_MANIFEST,
            label="qualification manifest",
        )
    if action in {"cohort", "campaigns"} and stage == AUTHORITATIVE_STAGE:
        _require_exact_layout_path(
            numeric_bundle_root,
            field="pilot_numeric_root",
            label="numeric bundle",
        )
    if action in {"prefix-specs", "qualify-prefix", "finalize-fitting"}:
        if stage == PILOT_STAGE:
            stage_fields = (
                (numeric_bundle_root, "pilot_numeric_root", "numeric bundle"),
                (prefix_spec_root, "pilot_prefix_root", "prefix-spec root"),
                (final_bundle_root, "pilot_final_root", "final bundle"),
            )
            manifest_field = "pilot_qualification_set_root"
        elif stage == AUTHORITATIVE_STAGE:
            stage_fields = (
                (
                    numeric_bundle_root,
                    "authoritative_numeric_root",
                    "numeric bundle",
                ),
                (
                    prefix_spec_root,
                    "authoritative_prefix_root",
                    "prefix-spec root",
                ),
                (
                    final_bundle_root,
                    "authoritative_final_root",
                    "final bundle",
                ),
            )
            manifest_field = "final_qualification_set_root"
        else:
            stage_fields = ()
            manifest_field = None
        for path, field, label in stage_fields:
            _require_exact_layout_path(path, field=field, label=label)
        if action == "qualify-prefix" and manifest_field is not None:
            layout = class_study_layout()
            require_canonical_fresh_path(
                getattr(layout, manifest_field),
                field=manifest_field,
                label="named qualification-set publication root",
            )
        if qualification_manifest is not None and manifest_field is not None:
            require_canonical_fresh_child(
                qualification_manifest,
                field=manifest_field,
                filename=NAMED_QUALIFICATION_SET_MANIFEST,
                label="qualification manifest",
            )
    if action == "readiness":
        for path, field, label in (
            (numeric_bundle_root, "pilot_numeric_root", "numeric bundle"),
            (
                prefix_spec_root,
                "authoritative_prefix_root",
                "prefix-spec root",
            ),
            (final_bundle_root, "authoritative_final_root", "final bundle"),
            (
                qualification_sidecar_root,
                "final_qualification_set_root",
                "qualification sidecar root",
            ),
        ):
            _require_exact_layout_path(path, field=field, label=label)
        if qualification_manifest is not None:
            require_canonical_fresh_child(
                qualification_manifest,
                field="final_qualification_set_root",
                filename=NAMED_QUALIFICATION_SET_MANIFEST,
                label="qualification manifest",
            )
    if (
        action
        in {
            "acquisition-authority",
            "foundation",
            "readiness",
            "historical-snapshot",
            "comparison-review",
            "attest",
        }
        and destination is not None
    ):
        require_canonical_fresh_child(
            destination,
            field="artifacts_root",
            label=f"{action} destination",
        )


def _successor_action_context(
    action: str,
    *,
    successor_restart: Path | None,
    campaign: Path | None,
    workload_root: Path | None,
    artifacts_root: Path | None,
    numeric_bundle_root: Path | None,
    prefix_spec_root: Path | None,
    qualification_checkpoint: Path | None,
    qualification_sidecar_root: Path | None,
    qualification_publication_root: Path | None,
    qualification_manifest: Path | None,
    final_bundle_root: Path | None,
    snapshot_phase: str | None,
    destination: Path | None,
    foundation_attestation: Path | None = None,
) -> dict[str, Any] | None:
    """Resolve every mutable successor path beneath its immutable namespace."""

    if successor_restart is None:
        return None
    allowed = {
        "status",
        "fit-numeric",
        "prefix-specs",
        "qualify-prefix",
        "finalize-fitting",
        "capture",
        "resume",
        "readiness",
        "historical-snapshot",
        "export",
        "evaluate",
        "comparison-review",
        "attest",
        "verify",
    }
    if action not in allowed:
        raise ValueError(f"class-study {action} does not accept --successor-restart")
    from .class_successor import validate_successor_restart

    restart_path = _regular_file(successor_restart, "successor restart receipt")
    restart = validate_successor_restart(restart_path)
    root = restart_path.parent.parent
    study_id = str(restart["study_id"])
    if foundation_attestation is not None:
        foundation_path = _regular_file(
            foundation_attestation,
            "successor foundation attestation",
        )
        _require_successor_foundation_sha256(
            sha256_file(foundation_path),
            {
                "restart": restart,
            },
        )
    canonical_workloads = class_study_layout().workload_root
    if workload_root is not None and Path(os.path.abspath(workload_root)) != canonical_workloads:
        raise ValueError(
            "successor workload root must use the canonical prepared workload directory "
            f"{canonical_workloads}"
        )
    artifacts = root / "artifacts"
    qualification = root / "qualification"
    final_set = qualification / f"{study_id}-final-full"
    expected = {
        "artifacts_root": artifacts,
        "numeric_bundle_root": (artifacts / f"{STUDY_ID}-authoritative-fitting-numeric"),
        "prefix_spec_root": (artifacts / f"{STUDY_ID}-authoritative-fitting-prefix-specs"),
        "qualification_checkpoint": qualification / "checkpoint.json",
        "qualification_sidecar_root": (
            final_set
            if action in {"readiness", "finalize-fitting", "verify"}
            else qualification / "work"
        ),
        "qualification_publication_root": qualification,
        "qualification_manifest": final_set / NAMED_QUALIFICATION_SET_MANIFEST,
        "final_bundle_root": artifacts / f"{STUDY_ID}-authoritative-fitting",
    }
    supplied = {
        "artifacts_root": artifacts_root,
        "numeric_bundle_root": numeric_bundle_root,
        "prefix_spec_root": prefix_spec_root,
        "qualification_checkpoint": qualification_checkpoint,
        "qualification_sidecar_root": qualification_sidecar_root,
        "qualification_publication_root": qualification_publication_root,
        "qualification_manifest": qualification_manifest,
        "final_bundle_root": final_bundle_root,
    }
    for label, path in supplied.items():
        if path is not None and Path(os.path.abspath(path)) != expected[label]:
            raise ValueError(f"successor {label.replace('_', ' ')} must use {expected[label]}")
    if campaign is not None:
        candidate = Path(os.path.abspath(campaign))
        campaign_root = root / "plan/campaigns"
        if candidate.parent != campaign_root:
            raise ValueError("successor campaign must come from its immutable plan")
    destination_by_action = {
        "readiness": root / "attestations/successor-readiness.json",
        "export": root / "handoff",
        "evaluate": root / "attestations/evaluation.json",
        "comparison-review": root / "attestations/comparison-review.json",
        "attest": root / "attestations/validation-attestation.json",
    }
    if action == "historical-snapshot":
        if snapshot_phase not in {"pre-formal", "post-formal"}:
            raise ValueError(
                "successor historical snapshot requires a pre-formal/post-formal phase"
            )
        destination_by_action[action] = (
            root / "attestations" / f"historical-{snapshot_phase}-snapshot.json"
        )
    expected_destination = destination_by_action.get(action)
    if destination is not None and expected_destination is not None:
        if Path(os.path.abspath(destination)) != expected_destination:
            raise ValueError(
                f"successor {action} must use its hash-namespaced destination "
                f"{expected_destination}"
            )
    return {
        "restart_path": restart_path,
        "restart": restart,
        "root": root,
        "study_id": study_id,
        **expected,
    }


def _require_successor_handoff_lineage(
    handoff: Path,
    successor_context: Mapping[str, Any],
) -> None:
    """Bind a closed handoff to the exact restart, not just a v2-looking ID."""

    root = _regular_directory(handoff, "successor class handoff")
    dataset = _load_json_object(root / "dataset.json", "successor class dataset")
    expected_sha256 = sha256_file(successor_context["restart_path"])
    if dataset.get("study_id") != successor_context["study_id"] or dataset.get(
        "class_study_successor"
    ) != {
        "path": "inputs/class-study-successor.json",
        "sha256": expected_sha256,
    }:
        raise ValueError("successor handoff uses another study/restart authority")
    frozen = root / "inputs/class-study-successor.json"
    if frozen.is_symlink() or not frozen.is_file() or sha256_file(frozen) != expected_sha256:
        raise ValueError("successor handoff has no exact frozen restart authority")


def _require_successor_receipt_lineage(
    value: Mapping[str, Any],
    successor_context: Mapping[str, Any],
    *,
    label: str,
    require_restart: bool,
) -> None:
    """Reject v1, another v2, or a same-ID receipt with another restart hash."""

    if value.get("study_id") != successor_context["study_id"]:
        raise ValueError(f"successor {label} uses another study identity")
    expected_sha256 = sha256_file(successor_context["restart_path"])
    evidence = value.get("evidence")
    restart = evidence.get("successor_restart") if isinstance(evidence, Mapping) else None
    if isinstance(restart, Mapping):
        if restart.get("sha256") != expected_sha256:
            raise ValueError(f"successor {label} uses another restart authority")
        return
    readiness = value.get("readiness")
    if isinstance(readiness, Mapping) and isinstance(readiness.get("path"), str):
        from .class_attestation import validate_class_readiness_attestation

        nested = validate_class_readiness_attestation(Path(readiness["path"]), deep_code_gate=True)
        _require_successor_receipt_lineage(
            nested,
            successor_context,
            label=f"{label} readiness",
            require_restart=True,
        )
        return
    handoff = value.get("handoff")
    if isinstance(handoff, Mapping) and isinstance(handoff.get("root"), str):
        _require_successor_handoff_lineage(Path(handoff["root"]), successor_context)
        return
    if require_restart:
        raise ValueError(f"successor {label} has no restart lineage")


def _successor_study_status(
    successor_context: Mapping[str, Any],
    *,
    result_roots: Sequence[Path],
    workload_root: Path | None,
    foundation_attestation: Path | None,
    readiness_attestation: Path | None,
    historical_pre_snapshot: Path | None,
    historical_post_snapshot: Path | None,
    handoff: Path | None,
    evaluation_receipt: Path | None,
    comparison_review: Path | None,
    validation_attestation: Path | None,
    deep: bool,
) -> dict[str, Any]:
    """Report only deeply verified evidence in one successor namespace."""

    restart_path = Path(successor_context["restart_path"])
    restart_sha256 = sha256_file(restart_path)
    study_id = str(successor_context["study_id"])
    admission = verify_successor_cohort_admission(restart_path)
    records = _result_index(
        result_roots,
        pilot_admission=None,
        final_admission=admission,
    )
    _require_successor_result_records(
        records,
        restart_sha256=restart_sha256,
        study_id=study_id,
    )
    stages: dict[str, Any] = {
        "successor_restart": {
            "state": "verified",
            "path": str(restart_path),
            "sha256": restart_sha256,
        },
        "successor_cohort": {"state": "verified", **admission.as_dict()},
        "campaigns": {
            "state": "verified",
            "root": str(Path(successor_context["root"]) / "plan/campaigns"),
            "count": 22,
        },
        "results": _result_status_summary(records),
    }

    from .class_attestation import (
        validate_class_comparison_review,
        validate_class_foundation_attestation,
        validate_class_historical_snapshot,
        validate_class_readiness_attestation,
        validate_class_validation_attestation,
    )

    stages["foundation"] = {"state": "absent"}
    if foundation_attestation is not None:
        foundation = validate_class_foundation_attestation(
            foundation_attestation,
            deep_code_gate=deep,
            runtime_role="collection",
        )
        if sha256_file(foundation_attestation) != successor_context["restart"].get(
            "predecessor_foundation_sha256"
        ):
            raise ValueError("successor status foundation differs from restart authority")
        stages["foundation"] = {"state": "verified", **foundation}

    readiness: dict[str, Any] | None = None
    stages["readiness"] = {"state": "absent"}
    if readiness_attestation is not None:
        readiness = validate_class_readiness_attestation(readiness_attestation, deep_code_gate=deep)
        _require_successor_receipt_lineage(
            readiness,
            successor_context,
            label="readiness attestation",
            require_restart=True,
        )
        stages["readiness"] = {"state": "verified", **readiness}

    for key, path, phase in (
        ("historical_pre_snapshot", historical_pre_snapshot, "pre-formal"),
        ("historical_post_snapshot", historical_post_snapshot, "post-formal"),
    ):
        stages[key] = {"state": "absent"}
        if path is not None:
            snapshot = validate_class_historical_snapshot(path, expected_phase=phase)
            _require_successor_receipt_lineage(
                snapshot,
                successor_context,
                label=key.replace("_", " "),
                require_restart=True,
            )
            stages[key] = {"state": "verified", **snapshot}

    stages["handoff"] = {"state": "absent"}
    if handoff is not None:
        verified_handoff = verify_class_handoff(handoff, deep=deep)
        _require_successor_handoff_lineage(verified_handoff, successor_context)
        stages["handoff"] = {"state": "verified", "root": str(verified_handoff)}

    stages["evaluation"] = {"state": "absent"}
    if evaluation_receipt is not None:
        if handoff is None:
            raise ValueError("successor evaluation status requires its handoff")
        from .class_evaluation import verify_class_evaluation_receipt

        evaluation = verify_class_evaluation_receipt(
            evaluation_receipt,
            handoff_root=handoff,
            deep_verify_handoff=deep,
            replay_attacks=deep,
        )
        _require_successor_receipt_lineage(
            evaluation,
            successor_context,
            label="evaluation receipt",
            require_restart=False,
        )
        stages["evaluation"] = {"state": "verified", **evaluation}

    stages["comparison_review"] = {"state": "absent"}
    if comparison_review is not None:
        review = validate_class_comparison_review(comparison_review)
        _require_successor_receipt_lineage(
            review,
            successor_context,
            label="comparison review",
            require_restart=True,
        )
        stages["comparison_review"] = {"state": "verified", **review}

    stages["validation_attestation"] = {"state": "absent"}
    if validation_attestation is not None:
        attestation = validate_class_validation_attestation(
            validation_attestation, deep_code_gate=deep
        )
        _require_successor_receipt_lineage(
            attestation,
            successor_context,
            label="validation attestation",
            require_restart=True,
        )
        stages["validation_attestation"] = {
            "state": "verified",
            **attestation,
        }

    next_stage = _successor_next_required_stage(stages, records)
    return {
        "study_id": study_id,
        "claim": "hash-namespaced-successor-restart",
        "workload_root": (
            str(Path(workload_root).resolve()) if workload_root is not None else None
        ),
        "stages": stages,
        "next_required_stage": next_stage,
        "attestation_generated": next_stage == "complete",
    }


def _successor_next_required_stage(
    stages: Mapping[str, Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> str:
    """Report successor progress without implying absent capture authority."""

    if stages["readiness"]["state"] != "verified":
        return "successor-readiness"
    if stages["historical_pre_snapshot"]["state"] != "verified":
        return "historical-pre-formal-snapshot"
    expected_roles = {
        "authoritative-fitting": 1,
        "certification": 1,
        "canary": FORMAL_BLOCK_COUNT,
        "formal": FORMAL_BLOCK_COUNT,
    }
    observed_roles = Counter(record["evidence_role"] for record in records)
    if not all(observed_roles[role] == count for role, count in expected_roles.items()):
        return "canary/formal-capture"
    if stages["historical_post_snapshot"]["state"] != "verified":
        return "historical-post-formal-snapshot"
    if stages["handoff"]["state"] != "verified":
        return "formal-handoff"
    if stages["evaluation"]["state"] != "verified":
        return "attack-evaluation"
    if stages["comparison_review"]["state"] != "verified":
        return "original-study-comparison-review"
    if stages["validation_attestation"]["state"] != "verified":
        return "final-validation-attestation"
    return "complete"


def _require_fresh_admission_paths(
    admission: CohortAdmission,
    *,
    stage: str,
) -> None:
    if stage == PILOT_STAGE:
        cohort_filename = PILOT_COHORT_FILENAME
        assembly_filename = PILOT_COHORT_ASSEMBLY_FILENAME
        label = "pilot"
    elif stage == AUTHORITATIVE_STAGE:
        cohort_filename = AUTHORITATIVE_COHORT_FILENAME
        assembly_filename = AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
        label = "authoritative"
    else:  # pragma: no cover - internal stage contract.
        raise AssertionError(f"unknown fresh admission stage: {stage}")
    require_canonical_fresh_child(
        admission.cohort_path,
        field="study_config_root",
        filename=cohort_filename,
        label=f"{label} cohort receipt",
    )
    require_canonical_fresh_child(
        admission.assembly_path,
        field="study_config_root",
        filename=assembly_filename,
        label=f"{label} cohort assembly",
    )


def _require_layout_choice(
    path: Path | None,
    *,
    pilot_field: str,
    authoritative_field: str,
    label: str,
) -> None:
    if path is None:
        return
    field = _stage_layout_field(
        path,
        stage=None,
        pilot_field=pilot_field,
        authoritative_field=authoritative_field,
        label=label,
    )
    require_canonical_fresh_path(path, field=field, label=label)


def _require_exact_layout_path(
    path: Path | None,
    *,
    field: str,
    label: str,
) -> None:
    if path is not None:
        require_canonical_fresh_path(path, field=field, label=label)


def _stage_layout_field(
    path: Path,
    *,
    stage: str | None,
    pilot_field: str,
    authoritative_field: str,
    label: str,
) -> str:
    if stage == PILOT_STAGE:
        return pilot_field
    if stage == AUTHORITATIVE_STAGE:
        return authoritative_field
    layout = class_study_layout()
    candidate = Path(os.path.abspath(path))
    if candidate == getattr(layout, pilot_field):
        return pilot_field
    if candidate == getattr(layout, authoritative_field):
        return authoritative_field
    raise ValueError(f"{label} must use one canonical class-study path")


def _required_stage(stage: str | None) -> str:
    if stage not in {PILOT_STAGE, AUTHORITATIVE_STAGE}:
        raise ValueError("class-study action requires --stage pilot or authoritative")
    return stage


def _optional_admission(
    cohort_receipt_path: Path | None,
    cohort_assembly_path: Path | None,
    *,
    candidate_catalogue_path: Path | None,
    stability_root: Path | None,
    workload_root: Path | None,
    acquisition_completion_path: Path | None,
    final_selection_receipt_path: Path | None,
) -> CohortAdmission | None:
    if cohort_receipt_path is None and cohort_assembly_path is None:
        return None
    if (
        cohort_receipt_path is None
        or cohort_assembly_path is None
        or not all(
            value is not None
            for value in (
                candidate_catalogue_path,
                stability_root,
                workload_root,
                acquisition_completion_path,
            )
        )
    ):
        raise ValueError(
            "cohort admission requires selection, assembly, catalogue, stability, "
            "workload, and acquisition-completion inputs together"
        )
    return verify_cohort_admission(
        cohort_receipt_path,  # type: ignore[arg-type]
        cohort_assembly_path,  # type: ignore[arg-type]
        candidate_catalogue_path=candidate_catalogue_path,  # type: ignore[arg-type]
        stability_root=stability_root,  # type: ignore[arg-type]
        workload_root=workload_root,  # type: ignore[arg-type]
        acquisition_completion_path=acquisition_completion_path,  # type: ignore[arg-type]
        final_selection_receipt_path=final_selection_receipt_path,
    )


def _required_admission(
    cohort_receipt_path: Path | None,
    cohort_assembly_path: Path | None,
    *,
    candidate_catalogue_path: Path | None,
    stability_root: Path | None,
    workload_root: Path | None,
    acquisition_completion_path: Path | None,
    final_selection_receipt_path: Path | None,
    label: str,
) -> CohortAdmission:
    admission = _optional_admission(
        cohort_receipt_path,
        cohort_assembly_path,
        candidate_catalogue_path=candidate_catalogue_path,
        stability_root=stability_root,
        workload_root=workload_root,
        acquisition_completion_path=acquisition_completion_path,
        final_selection_receipt_path=final_selection_receipt_path,
    )
    if admission is None:
        raise ValueError(f"class-study action requires the {label} cohort admission")
    return admission


def _admission_for_stage(
    stage: str,
    pilot_admission: CohortAdmission | None,
    final_admission: CohortAdmission | None,
) -> CohortAdmission:
    value = pilot_admission if _required_stage(stage) == PILOT_STAGE else final_admission
    if value is None:
        raise ValueError(f"class-study {stage} action requires its cohort admission")
    return value


def _admission_for_role(
    role: str,
    pilot_admission: CohortAdmission | None,
    final_admission: CohortAdmission | None,
) -> CohortAdmission:
    stage = PILOT_STAGE if role in {"pilot-fitting", "pilot-compatibility"} else AUTHORITATIVE_STAGE
    return _admission_for_stage(stage, pilot_admission, final_admission)


def _require_campaign_reference_binding(
    campaign_root: Path,
    reference: object,
    *,
    expected_path: Path,
    expected_sha256: str,
    label: str,
) -> None:
    if not isinstance(reference, str) or not reference:
        raise ValueError(f"class-study campaign has no {label} reference")
    path = Path(reference)
    resolved = path.resolve() if path.is_absolute() else (campaign_root / path).resolve()
    expected = expected_path.resolve()
    if resolved != expected:
        raise ValueError(f"class-study campaign references a different {label}")
    source = _regular_file(resolved, f"campaign {label}")
    if sha256_file(source) != expected_sha256:
        raise ValueError(f"class-study campaign {label} hash differs from admission")


def _relative_reference(root: Path, target: Path) -> str:
    directory = _regular_directory(root, "class-study campaign root")
    return Path(os.path.relpath(target.resolve(), directory)).as_posix()


def _status_artifact_inputs(
    action: str,
    repeated: Sequence[Path],
    legacy: Path | None,
    *,
    option: str,
) -> tuple[Path, ...]:
    """Preserve repeatable status inputs while retaining the singular API.

    The four fitting artefact options remain singular for every producing or
    consuming action.  ``status`` alone needs one pilot and one authoritative
    instance at the same time.  Deduplicate the singular compatibility value
    against the repeatable form without allowing a non-status caller to smuggle
    a second artefact into an otherwise singular action.
    """

    values = tuple(Path(path) for path in repeated)
    legacy_identity = Path(os.path.abspath(legacy)) if legacy is not None else None
    if action != "status" and values:
        if legacy_identity is None or any(
            Path(os.path.abspath(path)) != legacy_identity for path in values
        ):
            raise ValueError(f"{option} is repeatable only for class-study status")

    ordered: list[Path] = []
    identities: set[Path] = set()
    for path in (*values, *((legacy,) if legacy is not None else ())):
        identity = Path(os.path.abspath(path))
        if identity in identities:
            continue
        identities.add(identity)
        ordered.append(path)
    return tuple(ordered)


def _next_required_stage(
    stages: Mapping[str, Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> str:
    if stages["catalogue"]["state"] != "verified":
        return "prospective-catalogue"
    if (
        stages["foundation"]["state"] != "verified"
        and stages.get("acquisition_authority", {}).get("state") != "verified"
    ):
        return "source-browser-preparation-acquisition-authority"
    if stages["acquisition_completion"]["state"] != "verified":
        return "complete-30s-24h-72h-acquisition"
    if stages["pilot_cohort"]["state"] != "verified":
        return "pilot-selection-and-assembly-freeze"
    if stages["foundation"]["state"] != "verified":
        return "source-reference-code-regression-controlled-foundation"
    if stages["campaigns"]["state"] != "verified" or stages["campaigns"].get("stage") not in {
        PILOT_STAGE,
        AUTHORITATIVE_STAGE,
    }:
        return "pilot-campaign-generation"
    roles = {str(record["evidence_role"]) for record in records}
    if "pilot-fitting" not in roles:
        return "pilot-fitting"
    if not any(
        bundle.get("stage") == PILOT_STAGE
        for bundle in stages["numeric_fitting"].get("bundles", [])
    ):
        return "pilot-numeric-fitting"
    if not any(
        root.get("stage") == PILOT_STAGE for root in stages["prefix_specs"].get("roots", [])
    ):
        return "pilot-prefix-specification"
    if not any(
        item.get("stage") == PILOT_STAGE for item in stages["qualification"].get("sets", [])
    ):
        return "pilot-full-prefix-qualification"
    if not any(
        bundle.get("stage") == PILOT_STAGE for bundle in stages["final_fitting"].get("bundles", [])
    ):
        return "pilot-fitting-finalisation"
    if "pilot-compatibility" not in roles:
        return "pilot-compatibility"
    if stages["final_selection"]["state"] != "verified":
        return "pilot-bound-final-selection-input"
    if stages["final_cohort"]["state"] != "verified":
        return "final-and-reserve-selection-and-assembly-freeze"
    if stages["campaigns"].get("stage") != AUTHORITATIVE_STAGE:
        return "authoritative-campaign-generation"
    if "authoritative-fitting" not in roles:
        return "authoritative-fitting"
    if not any(
        bundle.get("stage") == AUTHORITATIVE_STAGE
        for bundle in stages["numeric_fitting"].get("bundles", [])
    ):
        return "authoritative-numeric-fitting"
    if not any(
        root.get("stage") == AUTHORITATIVE_STAGE for root in stages["prefix_specs"].get("roots", [])
    ):
        return "authoritative-prefix-specification"
    if not any(
        item.get("stage") == AUTHORITATIVE_STAGE for item in stages["qualification"].get("sets", [])
    ):
        return "authoritative-full-prefix-qualification"
    if not any(
        bundle.get("stage") == AUTHORITATIVE_STAGE
        for bundle in stages["final_fitting"].get("bundles", [])
    ):
        return "authoritative-fitting-finalisation"
    if "certification" not in roles:
        return "certification"
    if stages["readiness"]["state"] != "verified":
        return "class-readiness-attestation"
    if stages["historical_pre_snapshot"]["state"] != "verified":
        return "historical-pre-formal-snapshot"
    for block in range(1, FORMAL_BLOCK_COUNT + 1):
        if not any(
            record["evidence_role"] == "canary" and record["block"] == block for record in records
        ):
            return f"canary-{block:02d}"
        if not any(
            record["evidence_role"] == "formal" and record["block"] == block for record in records
        ):
            return f"formal-{block:02d}"
    if stages["historical_post_snapshot"]["state"] != "verified":
        return "historical-post-formal-snapshot"
    if stages["handoff"]["state"] != "verified":
        return "formal-handoff"
    if stages["evaluation"]["state"] != "verified":
        return "attack-evaluation"
    if stages["comparison_review"]["state"] != "verified":
        return "original-study-comparison-review"
    if stages["validation_attestation"]["state"] != "verified":
        return "final-validation-attestation"
    return "study-complete"


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    source = _regular_file(path, label)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON: {source}") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object")
    return value


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


def _required(value: Path | None, option: str) -> Path:
    if value is None:
        raise ValueError(f"class-study action requires {option}")
    return value


def _write_or_verify_bytes(path: Path, encoded: bytes, *, label: str) -> Path:
    destination = Path(os.path.abspath(path))
    parent = _regular_directory(destination.parent, f"{label} publication root")
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != encoded
        ):
            raise FileExistsError(f"immutable {label} output already differs: {destination}")
        return destination
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
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise FileExistsError(f"immutable {label} output raced: {destination}") from error
        _fsync_directory(parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
