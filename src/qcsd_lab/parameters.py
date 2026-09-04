"""Validation for immutable smoke fixtures and sealed research parameters."""

from __future__ import annotations

import math
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fidelity import (
    BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT,
    BUFLO_TERMINAL_SUBCELL_POLICY,
)
from .fitting_walkie_talkie import receiver_continuation_contract as _current_wt_contract
from .profiles import UDP_PAYLOAD_CEILING_BY_PROFILE
from .util import LAB_ROOT, load_json, sha256_file

PROVENANCE_SCHEMA_VERSION = 1
REVIEWED_PARAMETER_INPUT_POLICY = "reviewed-engineering-fixture"
REVIEWED_FIXTURE_STATUS = "reviewed-smoke-fixture"
BUFLO_STUDY_PARAMETER_INPUT_POLICY = "reviewed-buflo-study-candidate-v1"
BUFLO_STUDY_ARTIFACT_TYPE = "qcsd-buflo-study-parameters"
BUFLO_STUDY_CANDIDATE_STATUS = "candidate-validation-required"
BUFLO_STUDY_ID = "buflo-csbuflo-qcsd-v1"
CONTROLLED_REGRESSION_ARTIFACT_TYPE = "qcsd-controlled-regression-parameters"
CONTROLLED_REGRESSION_INPUT_POLICY = "controlled-regression-test-only-v1"
TIMING_STRESS_ARTIFACT_TYPE = "qcsd-buflo-timing-stress-parameters"
PREVIOUS_TIMING_STRESS_INPUT_POLICY = "controlled-test-only-timing-stress-v1"
PREVIOUS_TIMING_STRESS_V2_INPUT_POLICY = "controlled-test-only-timing-stress-v2"
TIMING_STRESS_INPUT_POLICY = "controlled-test-only-timing-stress-v3"
PARAMETER_ARTIFACT_NAME = "defense-parameters.json"
PARAMETER_PROVENANCE_ARTIFACT_NAME = "defense-parameters.provenance.json"

_PROVENANCE_KEYS = {
    "schema_version",
    "artifact_type",
    "status",
    "production_ready",
    "defense_kind",
    "qcsd_profile",
    "udp_payload_ceiling",
    "parameter_file",
}
_WALKIE_TALKIE_PROVENANCE_KEYS = _PROVENANCE_KEYS | {"workload_sha256"}
_BUFLO_STUDY_PROVENANCE_KEYS = _PROVENANCE_KEYS | {
    "study_id",
    "implementation_status",
    "implementation_scope",
    "paper_variant",
    "paper_equivalent",
    "parameter_semantics",
    "reference_artifact",
    "reference_receipt",
    "validation_requirements",
}
_LEGACY_CS_BUFLO_SEMANTICS_V1_KEYS = {
    "source_semantics",
    "live_semantics",
    "rate_boundary_translation_version",
    "rate_boundary_counter_semantics",
    "author_rate_boundary_counter_semantics",
    "translation_classification",
    "early_termination_semantics",
    "expected_difference",
}
_CS_BUFLO_SEMANTICS_V2_KEYS = {
    *_LEGACY_CS_BUFLO_SEMANTICS_V1_KEYS,
    "early_termination_translation_version",
    "paper_early_termination_semantics",
    "pinned_author_source_early_termination_semantics",
    "pinned_author_padding_done_active_consumers",
    "paper_source_early_termination_discrepancy",
    "live_early_termination_semantics",
    "early_termination_translation_classification",
    "early_termination_expected_difference",
}
_BUFLO_TERMINAL_SEMANTICS_KEYS = {
    "terminal_translation_version",
    "paper_termination_semantics",
    "live_terminal_semantics",
    "terminal_subcell_policy",
    "terminal_subcell_observer_effect",
    "terminal_parser_safety",
    "translation_classification",
    "expected_difference",
}
_PARAMETER_FILE_KEYS = {"path", "sha256"}
SEALED_RESEARCH_PARAMETER_KINDS = frozenset({"traffic_morphing", "wtf_pad", "walkie_talkie"})
BUFLO_STUDY_PARAMETER_KINDS = frozenset({"buflo", "cs_buflo"})
_PARAMETERIZED_KINDS = set(SEALED_RESEARCH_PARAMETER_KINDS)
_BUFLO_STUDY_VALIDATION_REQUIREMENTS = (
    "reference-oracle-comparison",
    "deterministic-unit-and-property-tests",
    "docker-netem-controlled-capture",
    "public-smoke-and-rehearsal",
    "formal-paired-capture",
    "client-correctness-and-fidelity",
    "paper-overhead-comparison",
)
_BUFLO_STUDY_REFERENCE_FILES = {
    "buflo": (
        "config/reference/buflo-csbuflo/buflo-ieee-sp-2012-v1.json",
        "config/reference/buflo-csbuflo/buflo-ieee-sp-2012-v1.receipt.json",
    ),
    "cs_buflo": (
        "config/reference/buflo-csbuflo/csbuflo-wpes-2014-v1.json",
        "config/reference/buflo-csbuflo/csbuflo-wpes-2014-v1.receipt.json",
    ),
}
_WTF_PAD_INFINITY_TOKEN_FORMULAS = {
    "burst": "k_inf = (1 - p_fake) / p_fake * K",
    "gap": "k_inf = (K - mean_burst_length + 1) / (mean_burst_length - 1)",
}
_WALKIE_TALKIE_RECEIVER_CONTINUATION_SCHEMA_FIVE = {
    "allocation_policy": (
        "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell"
    ),
    "application_order": "after-symmetric-elementwise-mold",
    "batch_end_release_policy": (
        "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate"
    ),
    "base_allocation_policy": (
        "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;"
        "exact-capacity-before-bounded-framing-claims"
    ),
    "causal_capacity_precondition": (
        "first-molded-component-outgoing>0;max_chaff_streams>=maximum-receiver-continuation-"
        "reserve-horizon+1;required-preprovisioned-chaff-request-stream-frames-through-fin-fit-"
        "within-residual-normal-priority-stream-data-budget-after-higher-priority-due-"
        "application-stream-frames-at-each-positive-outgoing-horizon-start"
    ),
    "cells_per_nonzero_incoming_component": 1,
    "formula": "adapted_incoming=symmetric_incoming+1-if-symmetric_incoming>0-else-0",
    "parser_allowance_ceiling_bytes": 1_000,
    "post_outgoing_loss_liveness_limitation": (
        "insufficient-peer-acknowledged-survivors-after-positive-outgoing-targets-resolve-hold-"
        "base-and-continuation-allocation;no-targetless-chaff-stream-retransmission-or-generic-"
        "loss-liveness-guarantee"
    ),
    "prefix_consumability_precondition": (
        "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable"
    ),
    "provisioning_policy": "fill-configured-chaff-stream-limit-before-due-molded-outgoing-actions",
    "raw_headroom_bytes_per_nonzero_incoming_component": 1_200,
    "release_policy": (
        "after-all-base-events-controller-requested-and-request-signals-observed;reserve-"
        "deterministic-peer-acknowledged-pristine-candidates-for-current-zero-outgoing-"
        "continuation-horizon-before-first-base-allocation-and-retain-each-until-corresponding-"
        "continuation-release-or-session-end;recompute-live-unconsumed-base-each-retry;extend-"
        "single-coalesced-positive-outstanding-header-blocked-stream-else-reserved-peer-"
        "acknowledged-stream;outstanding-at-or-below-parser-ceiling"
    ),
    "request_activation_policy": (
        "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-"
        "contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-"
        "molded-outgoing-cells"
    ),
    "request_prefix_delivery_precondition": (
        "before-each-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-"
        "chaff-request-survivors>=current-receiver-continuation-reserve-horizon+1"
    ),
    "resource_precondition": (
        "initial-chaff-selection-yields-known-valid-dependency-free-same-origin-resource-with-"
        "effective-length>=raw-headroom-bytes-per-nonzero-incoming-component"
    ),
    "reserve_policy": (
        "reserve-deterministic-acknowledged-pristine-candidates-for-current-zero-outgoing-"
        "continuation-horizon-before-first-base-allocation-of-each-nonzero-incoming-component"
    ),
    "reserve_lifecycle_policy": (
        "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-allocation-"
        "even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-for-defense-"
        "pending-continuation-or-tagged-continuation-still-queued-for-allocation;retryable-"
        "unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-corresponding-"
        "horizon-reserve-before-further-base-allocation"
    ),
}
# Keep the runnable schema-six validator byte-for-byte coupled to the fitter's
# current contract while retaining the literal schema-five oracle above.
_WALKIE_TALKIE_RECEIVER_CONTINUATION = _current_wt_contract()


@dataclass(frozen=True)
class ParameterArtifact:
    """One validated runtime JSON file and its adjacent receipt."""

    path: Path
    sha256: str
    provenance_path: Path
    provenance_sha256: str
    input_policy: str = REVIEWED_PARAMETER_INPUT_POLICY


def parameter_provenance_path(parameter: Path) -> Path:
    """Return a fitted bundle's common receipt or a smoke fixture's adjacent receipt."""

    common = parameter.parent / "provenance.json"
    if (
        parameter.name
        in {
            "traffic-morphing.json",
            "wtf-pad.json",
            "walkie-talkie.json",
        }
        and common.is_file()
    ):
        return common
    return parameter.with_suffix(parameter.suffix + ".provenance.json")


def validate_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path | None = None,
    expected_kind: str | None = None,
    allow_reviewed_fixture: bool = False,
    allow_study_candidate: bool = False,
    allow_timing_stress: bool = False,
    expected_qcsd_profile: str | None = None,
    expected_udp_payload_ceiling: int | None = None,
    expected_workloads: Mapping[str, object] | Collection[str] | None = None,
    qualification_inputs_root: Path | None = None,
    qualification_context: object | None = None,
    expected_qualification_set: str | None = None,
    campaign_evidence_role: str | None = None,
    expected_successor_study_id: str | None = None,
    expected_successor_restart_sha256: str | None = None,
) -> ParameterArtifact:
    """Validate one runtime parameter file and its concise smoke receipt.

    ``allow_reviewed_fixture`` is deliberately explicit.  The orchestrator
    enables it only for smoke campaigns, so fitting and evaluation campaigns
    cannot accidentally treat the acceptance fixtures as research artifacts.
    """

    return _validate_parameter_artifact(
        parameter_path,
        provenance_path=provenance_path,
        expected_kind=expected_kind,
        allow_reviewed_fixture=allow_reviewed_fixture,
        allow_study_candidate=allow_study_candidate,
        allow_timing_stress=allow_timing_stress,
        expected_qcsd_profile=expected_qcsd_profile,
        expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        expected_workloads=expected_workloads,
        receipt_parameter_name=None,
        require_checked_in_fixture=True,
        allow_historical_research_bundle=False,
        qualification_inputs_root=qualification_inputs_root,
        qualification_context=qualification_context,
        expected_qualification_set=expected_qualification_set,
        frozen_qualification_inputs=False,
        campaign_evidence_role=campaign_evidence_role,
        expected_successor_study_id=expected_successor_study_id,
        expected_successor_restart_sha256=expected_successor_restart_sha256,
    )


def validate_frozen_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path,
    original_parameter_name: str,
    expected_kind: str,
    allow_reviewed_fixture: bool,
    allow_study_candidate: bool = False,
    expected_qcsd_profile: str,
    expected_udp_payload_ceiling: int,
    expected_workloads: Mapping[str, object] | Collection[str],
    allow_historical_research_bundle: bool = False,
    qualification_inputs_root: Path | None = None,
    qualification_context: object | None = None,
    expected_qualification_set: str | None = None,
    campaign_evidence_role: str | None = None,
    expected_successor_study_id: str | None = None,
    expected_successor_restart_sha256: str | None = None,
) -> ParameterArtifact:
    """Revalidate a copied artifact using its frozen campaign binding.

    Frozen files deliberately have canonical result names (``parameters.json``
    and ``provenance.json``), while the receipt names the checked-in source
    artifact.  This entry point preserves that filename binding without
    pretending the result copy itself is a checked-in fixture.  Historical
    research bundles are accepted only for explicit read-only evidence
    verification; they can never become inputs to a current runtime.
    """

    if not original_parameter_name or Path(original_parameter_name).name != original_parameter_name:
        raise ValueError("frozen parameter source name must be a filename")
    return _validate_parameter_artifact(
        parameter_path,
        provenance_path=provenance_path,
        expected_kind=expected_kind,
        allow_reviewed_fixture=allow_reviewed_fixture,
        allow_study_candidate=allow_study_candidate,
        allow_timing_stress=False,
        expected_qcsd_profile=expected_qcsd_profile,
        expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        expected_workloads=expected_workloads,
        receipt_parameter_name=original_parameter_name,
        require_checked_in_fixture=False,
        allow_historical_research_bundle=allow_historical_research_bundle,
        qualification_inputs_root=qualification_inputs_root,
        qualification_context=qualification_context,
        expected_qualification_set=expected_qualification_set,
        frozen_qualification_inputs=True,
        campaign_evidence_role=campaign_evidence_role,
        expected_successor_study_id=expected_successor_study_id,
        expected_successor_restart_sha256=expected_successor_restart_sha256,
    )


def _validate_parameter_artifact(
    parameter_path: Path,
    *,
    provenance_path: Path | None,
    expected_kind: str | None,
    allow_reviewed_fixture: bool,
    allow_study_candidate: bool,
    allow_timing_stress: bool,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
    receipt_parameter_name: str | None,
    require_checked_in_fixture: bool,
    allow_historical_research_bundle: bool,
    qualification_inputs_root: Path | None,
    qualification_context: object | None,
    expected_qualification_set: str | None,
    frozen_qualification_inputs: bool,
    campaign_evidence_role: str | None,
    expected_successor_study_id: str | None,
    expected_successor_restart_sha256: str | None,
) -> ParameterArtifact:
    receipt_path = (
        provenance_path
        if provenance_path is not None
        else parameter_provenance_path(parameter_path)
    )
    if parameter_path.is_symlink() or receipt_path.is_symlink():
        raise ValueError("defense parameter files must not be symbolic links")
    parameter_path = parameter_path.resolve()
    receipt_path = receipt_path.resolve()
    if not parameter_path.is_file():
        raise ValueError(f"defense parameter file does not exist: {parameter_path}")
    if not receipt_path.is_file():
        raise ValueError(
            f"defense parameter file requires an adjacent provenance receipt: {receipt_path}"
        )

    parameter = _mapping(load_json(parameter_path), "defense parameters")
    receipt = _mapping(load_json(receipt_path), "parameter provenance")
    if receipt.get("artifact_type") == TIMING_STRESS_ARTIFACT_TYPE:
        return _validate_timing_stress_parameter_artifact(
            parameter,
            receipt,
            parameter_path=parameter_path,
            receipt_path=receipt_path,
            receipt_parameter_name=receipt_parameter_name,
            require_checked_in_fixture=require_checked_in_fixture,
            allow_timing_stress=allow_timing_stress,
            expected_kind=expected_kind,
            expected_qcsd_profile=expected_qcsd_profile,
            expected_udp_payload_ceiling=expected_udp_payload_ceiling,
            expected_workloads=expected_workloads,
        )
    if receipt.get("artifact_type") == "qcsd-class-study-research-defense-bundle":
        from .class_fitting import (
            BUNDLE_FILES as CLASS_BUNDLE_FILES,
            QualificationContext,
            class_research_parameter_record,
        )

        if campaign_evidence_role is None:
            raise ValueError("class-study parameters require an explicit campaign evidence role")
        if qualification_inputs_root is None and qualification_context is None:
            raise ValueError("class-study parameters require qualification evidence")
        expected_parameter_name = receipt_parameter_name or parameter_path.name
        inferred = {filename: kind for kind, filename in CLASS_BUNDLE_FILES.items()}.get(
            expected_parameter_name
        )
        kind = expected_kind or inferred
        if kind not in SEALED_RESEARCH_PARAMETER_KINDS or inferred != kind:
            raise ValueError("class-study parameter defense kind cannot be inferred")
        if expected_qcsd_profile not in {None, "research-1200"}:
            raise ValueError("class-study parameter QCSD profile does not match campaign")
        if expected_udp_payload_ceiling not in {None, 1_200}:
            raise ValueError("class-study parameter UDP ceiling does not match campaign")
        qualification = receipt.get("qualification_inputs")
        qualification_set = (
            qualification.get("qualification_set") if isinstance(qualification, Mapping) else None
        )
        if not isinstance(qualification_set, str) or not qualification_set:
            raise ValueError("class-study provenance has no qualification-set binding")
        if qualification_context is not None:
            if frozen_qualification_inputs:
                raise ValueError(
                    "frozen class-study parameters require their result-local qualification root"
                )
            if qualification_inputs_root is not None:
                raise ValueError(
                    "class-study qualification root and explicit context are mutually exclusive"
                )
            if not isinstance(qualification_context, QualificationContext):
                raise TypeError("class-study qualification context must be a QualificationContext")
            context = qualification_context
            if (
                expected_qualification_set is not None
                and context.expected_qualification_set != expected_qualification_set
            ):
                raise ValueError("class-study qualification context has another named set")
        elif frozen_qualification_inputs:
            root = Path(qualification_inputs_root).resolve()
            context = QualificationContext(
                workload_root=root / "workloads",
                sidecar_root=root / "chaff-qualifications",
                prefix_spec_root=root / "chaff-prefix-specs",
                require_current_implementation=False,
                expected_qualification_set=expected_qualification_set,
            )
        else:
            root = Path(qualification_inputs_root).resolve()
            context = QualificationContext(
                workload_root=root / "workloads",
                sidecar_root=root / "chaff-qualification-store" / "sets" / qualification_set,
                prefix_spec_root=root / "chaff-prefix-specs" / "sets" / qualification_set,
                require_current_implementation=True,
                expected_qualification_set=expected_qualification_set,
            )
        expected_ids = tuple(expected_workloads or ())
        parameter_sha256, provenance_sha256, input_policy = class_research_parameter_record(
            parameter_path,
            receipt_path,
            expected_kind=kind,
            expected_workloads=expected_ids,
            campaign_evidence_role=campaign_evidence_role,
            qualification_context=context,
            expected_successor_study_id=expected_successor_study_id,
            expected_successor_restart_sha256=expected_successor_restart_sha256,
        )
        return ParameterArtifact(
            path=parameter_path,
            sha256=parameter_sha256,
            provenance_path=receipt_path,
            provenance_sha256=provenance_sha256,
            input_policy=input_policy,
        )
    if receipt.get("artifact_type") == "qcsd-research-defense-bundle":
        from .fitting import BUNDLE_FILES, research_parameter_record

        expected_parameter_name = receipt_parameter_name or parameter_path.name
        inferred = {filename: kind for kind, filename in BUNDLE_FILES.items()}.get(
            expected_parameter_name
        )
        kind = expected_kind or inferred
        if kind not in _PARAMETERIZED_KINDS:
            raise ValueError("research parameter defense kind cannot be inferred")
        if expected_qcsd_profile not in {None, "research-1200"}:
            raise ValueError("research parameter QCSD profile does not match campaign")
        if expected_udp_payload_ceiling not in {None, 1_200}:
            raise ValueError("research parameter UDP ceiling does not match campaign")
        parameter_sha256, provenance_sha256, input_policy = research_parameter_record(
            parameter_path,
            receipt_path,
            expected_kind=kind,
            expected_workloads=expected_workloads,
            parameter_name=expected_parameter_name,
            allow_historical=allow_historical_research_bundle,
            qualification_inputs_root=qualification_inputs_root,
            frozen_qualification_inputs=frozen_qualification_inputs,
        )
        return ParameterArtifact(
            path=parameter_path,
            sha256=parameter_sha256,
            provenance_path=receipt_path,
            provenance_sha256=provenance_sha256,
            input_policy=input_policy,
        )
    if receipt.get("artifact_type") == BUFLO_STUDY_ARTIFACT_TYPE:
        return _validate_buflo_study_parameter_artifact(
            parameter,
            receipt,
            parameter_path=parameter_path,
            receipt_path=receipt_path,
            receipt_parameter_name=receipt_parameter_name,
            require_checked_in_fixture=require_checked_in_fixture,
            allow_study_candidate=allow_study_candidate,
            expected_kind=expected_kind,
            expected_qcsd_profile=expected_qcsd_profile,
            expected_udp_payload_ceiling=expected_udp_payload_ceiling,
        )
    if receipt.get("artifact_type") == CONTROLLED_REGRESSION_ARTIFACT_TYPE:
        return _validate_controlled_regression_parameter(
            parameter,
            receipt,
            parameter_path=parameter_path,
            receipt_path=receipt_path,
            receipt_parameter_name=receipt_parameter_name,
            allow_reviewed_fixture=allow_reviewed_fixture,
            expected_kind=expected_kind,
            expected_qcsd_profile=expected_qcsd_profile,
            expected_udp_payload_ceiling=expected_udp_payload_ceiling,
            expected_workloads=expected_workloads,
        )
    reviewed_kind = receipt.get("defense_kind")
    if reviewed_kind == "walkie_talkie" and "workload_sha256" not in receipt:
        raise ValueError(
            "obsolete walkie_talkie smoke fixture is not bound to workload SHA-256 values; "
            "use a sealed fitted bundle or a controlled workload-bound fixture"
        )
    receipt_keys = (
        _WALKIE_TALKIE_PROVENANCE_KEYS if reviewed_kind == "walkie_talkie" else _PROVENANCE_KEYS
    )
    _require_exact_keys(receipt, receipt_keys, "parameter provenance")
    if receipt.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported parameter provenance schema_version in {receipt_path}; "
            f"expected {PROVENANCE_SCHEMA_VERSION}"
        )
    if receipt.get("artifact_type") != "qcsd-defense-parameters":
        raise ValueError(f"parameter provenance has the wrong artifact type: {receipt_path}")
    if (
        receipt.get("status") != REVIEWED_FIXTURE_STATUS
        or receipt.get("production_ready") is not False
    ):
        raise ValueError(
            f"parameter provenance must explicitly declare a non-production smoke fixture: "
            f"{receipt_path}"
        )
    if not allow_reviewed_fixture:
        raise ValueError("reviewed smoke parameter fixtures are accepted only by smoke campaigns")
    if reviewed_kind == "walkie_talkie":
        raise ValueError(
            "reviewed walkie_talkie schema-five fixtures are historical test oracles only; "
            "current runtime campaigns require a sealed schema-six bundle"
        )
    if require_checked_in_fixture:
        _require_checked_in_fixture(parameter_path, receipt_path)

    parameter_sha256 = sha256_file(parameter_path)
    recorded_file = _mapping(receipt.get("parameter_file"), "parameter_file metadata")
    _require_exact_keys(recorded_file, _PARAMETER_FILE_KEYS, "parameter_file metadata")
    expected_parameter_name = receipt_parameter_name or parameter_path.name
    if recorded_file.get("path") != expected_parameter_name:
        raise ValueError(f"parameter provenance filename mismatch: {receipt_path}")
    if recorded_file.get("sha256") != parameter_sha256:
        raise ValueError(f"parameter provenance SHA-256 mismatch: {receipt_path}")

    kind = receipt.get("defense_kind")
    if kind not in _PARAMETERIZED_KINDS:
        raise ValueError(f"parameter provenance has an unsupported defense kind: {receipt_path}")
    if expected_kind is not None and kind != expected_kind:
        raise ValueError(f"parameter defense kind does not match campaign: {receipt_path}")

    profile = receipt.get("qcsd_profile")
    if profile not in UDP_PAYLOAD_CEILING_BY_PROFILE:
        raise ValueError(f"parameter provenance has an unsupported QCSD profile: {receipt_path}")
    ceiling = receipt.get("udp_payload_ceiling")
    if type(ceiling) is not int or ceiling != UDP_PAYLOAD_CEILING_BY_PROFILE[profile]:
        raise ValueError(f"parameter provenance profile and UDP ceiling disagree: {receipt_path}")
    if expected_qcsd_profile is not None and profile != expected_qcsd_profile:
        raise ValueError(f"parameter QCSD profile does not match campaign: {receipt_path}")
    if expected_udp_payload_ceiling is not None and ceiling != expected_udp_payload_ceiling:
        raise ValueError(f"parameter UDP ceiling does not match campaign: {receipt_path}")
    if (
        expected_qcsd_profile is not None
        and expected_udp_payload_ceiling is not None
        and UDP_PAYLOAD_CEILING_BY_PROFILE.get(expected_qcsd_profile)
        != expected_udp_payload_ceiling
    ):
        raise ValueError("expected QCSD profile and UDP ceiling disagree")

    _validate_reviewed_workload_binding(receipt, str(kind), expected_workloads, receipt_path)
    expected_schema_version = 2
    _validate_runtime_shape(
        parameter,
        str(kind),
        int(ceiling),
        receipt_path,
        expected_schema_version=expected_schema_version,
    )
    _validate_workload_coverage(parameter, str(kind), expected_workloads, receipt_path)
    return ParameterArtifact(
        path=parameter_path,
        sha256=parameter_sha256,
        provenance_path=receipt_path,
        provenance_sha256=sha256_file(receipt_path),
    )


def _validate_buflo_study_parameter_artifact(
    parameter: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    parameter_path: Path,
    receipt_path: Path,
    receipt_parameter_name: str | None,
    require_checked_in_fixture: bool,
    allow_study_candidate: bool,
    expected_kind: str | None,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
) -> ParameterArtifact:
    """Validate a paper-bound but deliberately non-promoted BuFLO study input."""

    receipt_kind = receipt.get("defense_kind")
    receipt_schema = receipt.get("schema_version")
    cs_semantics_keys = (
        _LEGACY_CS_BUFLO_SEMANTICS_V1_KEYS
        if receipt_schema == 1
        else _CS_BUFLO_SEMANTICS_V2_KEYS
        if receipt_schema == 2
        else set()
    )
    expected_receipt_keys = _BUFLO_STUDY_PROVENANCE_KEYS | (
        cs_semantics_keys
        if receipt_kind == "cs_buflo"
        else _BUFLO_TERMINAL_SEMANTICS_KEYS
        if receipt_kind == "buflo"
        else set()
    )
    _require_exact_keys(receipt, expected_receipt_keys, "BuFLO study provenance")
    if type(receipt_schema) is not int or not (
        receipt_kind == "cs_buflo"
        and receipt_schema in {1, 2}
        or receipt_kind == "buflo"
        and receipt_schema == PROVENANCE_SCHEMA_VERSION
    ):
        raise ValueError(f"unsupported BuFLO study provenance schema: {receipt_path}")
    if (
        receipt.get("artifact_type") != BUFLO_STUDY_ARTIFACT_TYPE
        or receipt.get("status") != BUFLO_STUDY_CANDIDATE_STATUS
        or receipt.get("production_ready") is not False
        or receipt.get("implementation_status") != "candidate"
        or receipt.get("implementation_scope") != "client_only_quic"
        or receipt.get("paper_equivalent") is not False
        or receipt.get("study_id") != BUFLO_STUDY_ID
    ):
        raise ValueError(
            f"BuFLO study provenance must remain an explicit non-production candidate: "
            f"{receipt_path}"
        )
    if not allow_study_candidate:
        raise ValueError(
            "BuFLO study candidate parameters require an explicit study-campaign admission"
        )
    if list(receipt.get("validation_requirements", ())) != list(
        _BUFLO_STUDY_VALIDATION_REQUIREMENTS
    ):
        raise ValueError(f"BuFLO study validation requirements are incomplete: {receipt_path}")
    if require_checked_in_fixture:
        _require_checked_in_fixture(parameter_path, receipt_path)

    parameter_sha256 = sha256_file(parameter_path)
    recorded_file = _mapping(receipt.get("parameter_file"), "parameter_file metadata")
    _require_exact_keys(recorded_file, _PARAMETER_FILE_KEYS, "parameter_file metadata")
    expected_parameter_name = receipt_parameter_name or parameter_path.name
    if recorded_file.get("path") != expected_parameter_name:
        raise ValueError(f"BuFLO study provenance filename mismatch: {receipt_path}")
    if recorded_file.get("sha256") != parameter_sha256:
        raise ValueError(f"BuFLO study provenance SHA-256 mismatch: {receipt_path}")

    kind = receipt.get("defense_kind")
    if kind not in BUFLO_STUDY_PARAMETER_KINDS:
        raise ValueError(f"unsupported BuFLO study defense kind: {receipt_path}")
    if expected_kind is not None and kind != expected_kind:
        raise ValueError(f"BuFLO study defense kind does not match campaign: {receipt_path}")
    profile = receipt.get("qcsd_profile")
    ceiling = receipt.get("udp_payload_ceiling")
    if profile != "research-1200" or ceiling != UDP_PAYLOAD_CEILING_BY_PROFILE["research-1200"]:
        raise ValueError(f"BuFLO study parameters require research-1200: {receipt_path}")
    if expected_qcsd_profile not in {None, profile}:
        raise ValueError(f"BuFLO study QCSD profile does not match campaign: {receipt_path}")
    if expected_udp_payload_ceiling not in {None, ceiling}:
        raise ValueError(f"BuFLO study UDP ceiling does not match campaign: {receipt_path}")

    reference_artifact, reference_receipt = _BUFLO_STUDY_REFERENCE_FILES[str(kind)]
    if (
        receipt.get("reference_artifact") != reference_artifact
        or receipt.get("reference_receipt") != reference_receipt
    ):
        raise ValueError(f"BuFLO study provenance references the wrong oracle: {receipt_path}")

    if kind == "buflo":
        _validate_buflo(parameter, int(ceiling), receipt_path)
        if (
            type(receipt.get("terminal_translation_version")) is not int
            or receipt.get("terminal_translation_version") != 2
            or receipt.get("paper_termination_semantics")
            != "minimum-duration-then-continue-only-while-real-data-remains"
            or receipt.get("live_terminal_semantics")
            != (
                "inclusive-tau-drain-whole-reviewed-chaff-cells-then-client-local-"
                "http3-cancel-unallocatable-subcell-tail"
            )
            or receipt.get("terminal_subcell_policy") != BUFLO_TERMINAL_SUBCELL_POLICY
            or receipt.get("terminal_subcell_observer_effect")
            != BUFLO_TERMINAL_SUBCELL_OBSERVER_EFFECT
            or receipt.get("terminal_parser_safety")
            != (
                "latch-requires-zero-live-parser-lease-bytes-and-zero-pending-"
                "application-parser-boundaries;pending-reviewed-chaff-parser-"
                "boundaries-are-counted-and-cancelled-with-their-streams"
            )
            or receipt.get("translation_classification")
            != "expected-client-only-qcsd-adaptation-difference"
            or receipt.get("expected_difference")
            != "typed-http3-defense-control-may-follow-the-last-exact-buflo-cell"
        ):
            raise ValueError(f"BuFLO terminal-subcell translation is not explicit: {receipt_path}")
        expected_variant = "QCSD-BuFLO-udp1200-rho20-tau10"
        expected_semantics = (
            "qcsd-udp1200-adaptation-with-120-second-event-guard-and-versioned-"
            "terminal-subcell-policy"
        )
    else:
        _validate_cs_buflo(parameter, int(ceiling), receipt_path)
        common_invalid = (
            receipt.get("source_semantics")
            != (
                "author-oracle-advances-16KiB-boundaries-on-actually-transmitted-"
                "real-plus-junk-bytes-per-endpoint-and-direction"
            )
            or receipt.get("live_semantics")
            != (
                "qcsd-live-advances-16KiB-boundaries-on-exact-fresh-application-"
                "stream-bytes-outgoing-excludes-retransmission-and-defense-added-"
                "bytes-and-uses-consumed-application-offsets-incoming"
            )
            or type(receipt.get("rate_boundary_translation_version")) is not int
            or receipt.get("rate_boundary_translation_version") != 2
            or receipt.get("rate_boundary_counter_semantics")
            != (
                "client_only_quic_fresh_application_stream_bytes_outgoing_"
                "retransmission_excluded_and_consumed_application_offsets_incoming"
            )
            or receipt.get("author_rate_boundary_counter_semantics")
            != "per_direction_actually_transmitted_real_plus_junk_bytes"
            or receipt.get("translation_classification")
            != "expected-client-only-qcsd-adaptation-difference"
            or receipt.get("expected_difference")
            != (
                "adaptation-boundary-crossings-and-rate-transition-times-may-differ-"
                "from-the-author-artifact"
            )
        )
        legacy_invalid = receipt_schema == 1 and (
            receipt.get("early_termination_semantics")
            != "udp_client_only_observed_udp_power_of_two_crossing"
        )
        current_invalid = receipt_schema == 2 and (
            receipt.get("early_termination_semantics")
            != (
                "client_only_outgoing_observed_udp_and_incoming_consumed_credit_"
                "power_of_two_crossing"
            )
            or type(receipt.get("early_termination_translation_version")) is not int
            or receipt.get("early_termination_translation_version") != 2
            or receipt.get("paper_early_termination_semantics")
            != (
                "server-done-xmitting-requires-empty-output-buffer-and-onload-or-"
                "strict-quiet-time-and-either-client-padding-done-or-current-write-"
                "real-plus-junk-power-of-two-crossing"
            )
            or receipt.get("pinned_author_source_early_termination_semantics")
            != (
                "transcript-end-and-zero-w2w-state-machine-with-onload-or-inclusive-"
                "two-second-local-quiet-exit;client-padding-done-is-dispatched-and-"
                "stored-but-has-zero-active-consumers;paper-algorithm-4-power-"
                "crossing-is-not-an-active-source-stop-predicate"
            )
            or type(receipt.get("pinned_author_padding_done_active_consumers")) is not int
            or receipt.get("pinned_author_padding_done_active_consumers") != 0
            or receipt.get("paper_source_early_termination_discrepancy")
            != (
                "paper Algorithm 4 makes padding-done or a current-write power-of-two "
                "crossing an active bilateral server stop input; the pinned runtime "
                "dispatches and stores padding-done but no active loop consumes it, and "
                "active termination instead uses transcript-end/zero-w2w state with "
                "onLoad or an inclusive two-second local quiet exit"
            )
            or receipt.get("live_early_termination_semantics")
            != (
                "stop-new-client-opportunities-at-first-eligible-frozen-padding-target-"
                "or-directional-power-of-two-crossing-outgoing-by-observed-udp-and-"
                "incoming-by-fully-consumed-scheduled-credit-then-drain-advertised-"
                "credit-exactly-once"
            )
            or receipt.get("early_termination_translation_classification")
            != "expected-client-only-qcsd-adaptation-difference"
            or receipt.get("early_termination_expected_difference")
            != (
                "client-only-qcsd-has-no-peer-padding-done-signal-or-server-packet-"
                "composition;outgoing-crossings-use-observed-udp-payload-while-incoming-"
                "crossings-use-fully-consumed-scheduled-receive-credit-and-advertised-"
                "credit-drains-exactly-once-before-local-termination"
            )
        )
        if common_invalid or legacy_invalid or current_invalid:
            raise ValueError(
                f"CS-BuFLO source/live translation divergence is not explicit: {receipt_path}"
            )
        expected_variant = "CTSP" if parameter["outgoing_padding_mode"] == "total" else "CPSP"
        expected_semantics = "paper-source-values-mapped-to-quic-udp-payload"
    if (
        receipt.get("paper_variant") != expected_variant
        or receipt.get("parameter_semantics") != expected_semantics
    ):
        raise ValueError(f"BuFLO study paper-variant binding is invalid: {receipt_path}")

    return ParameterArtifact(
        path=parameter_path,
        sha256=parameter_sha256,
        provenance_path=receipt_path,
        provenance_sha256=sha256_file(receipt_path),
        input_policy=BUFLO_STUDY_PARAMETER_INPUT_POLICY,
    )


def _validate_timing_stress_parameter_artifact(
    parameter: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    parameter_path: Path,
    receipt_path: Path,
    receipt_parameter_name: str | None,
    require_checked_in_fixture: bool,
    allow_timing_stress: bool,
    expected_kind: str | None,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
) -> ParameterArtifact:
    """Admit only a checked-in, excluded 100-second BuFLO stress derivative."""

    timing_root = (LAB_ROOT / "config/buflo-study/v1").resolve()
    v1_parameter_path = timing_root / "buflo-timing-stress-v1.json"
    v2_parameter_path = timing_root / "buflo-timing-stress-v2.json"
    v3_parameter_path = timing_root / "buflo-timing-stress-v3.json"
    if parameter_path == v1_parameter_path:
        provenance_schema_version = 1
        input_policy = PREVIOUS_TIMING_STRESS_INPUT_POLICY
        expected_capture_contract = {
            "visits": 12,
            "max_attempts": 1,
            "authoritative_checkpoint": "experiment.json",
            "outgoing_opportunities_per_visit": 5_001,
            "incoming_opportunities_per_visit": 5_001,
            "guarded_outgoing_releases_per_visit": 5_000,
            "full_outgoing_cells_per_visit": 5_001,
            "incoming_bytes_per_visit": 6_001_200,
            "strict_half_open_window_us": 5_000,
            "catch_up": False,
        }
    elif parameter_path == v2_parameter_path:
        provenance_schema_version = 2
        input_policy = PREVIOUS_TIMING_STRESS_V2_INPUT_POLICY
        expected_capture_contract = {
            "schema_version": 2,
            "visits": 12,
            "max_attempts": 1,
            "authoritative_checkpoint": "experiment.json",
            "mandatory_prefix_opportunities_per_direction": 5_001,
            "maximum_opportunities_per_direction": 6_000,
            "minimum_guarded_outgoing_releases_per_visit": 5_000,
            "maximum_guarded_outgoing_releases_per_visit": 5_999,
            "minimum_incoming_bytes_per_visit": 6_001_200,
            "maximum_incoming_bytes_per_visit": 7_200_000,
            "cadence_semantics": (
                "inclusive-minimum-prefix-plus-bounded-terminal-whole-cell-drain"
            ),
            "terminal_drain_suffix": "contiguous-exact-paired-whole-cell-opportunities",
            "logical_order_evidence": "direction-target-slot-identity",
            "physical_row_order": "terminal-resolution-order-not-dispatch-order",
            "terminal_schedule_stop_policy": (
                "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
                "then_drain_already_advertised_incoming_credit"
            ),
            "strict_half_open_window_us": 5_000,
            "catch_up": False,
        }
    elif parameter_path == v3_parameter_path:
        provenance_schema_version = 3
        input_policy = TIMING_STRESS_INPUT_POLICY
        expected_capture_contract = {
            "schema_version": 3,
            "visits": 12,
            "max_attempts": 1,
            "authoritative_checkpoint": "experiment.json",
            "mandatory_prefix_opportunities_per_direction": 5_001,
            "maximum_opportunities_per_direction": 6_000,
            "minimum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": 5_000,
            "maximum_kernel_timed_outgoing_releases_after_tick_zero_per_visit": 5_999,
            "minimum_incoming_bytes_per_visit": 6_001_200,
            "maximum_incoming_bytes_per_visit": 7_200_000,
            "cadence_semantics": (
                "inclusive-minimum-prefix-plus-bounded-terminal-whole-cell-drain"
            ),
            "terminal_drain_suffix": "contiguous-exact-paired-whole-cell-opportunities",
            "logical_order_evidence": "direction-target-slot-identity",
            "physical_row_order": "terminal-resolution-order-not-dispatch-order",
            "terminal_schedule_stop_policy": (
                "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_"
                "then_drain_already_advertised_incoming_credit"
            ),
            "strict_half_open_window_us": 5_000,
            "catch_up": False,
            "realization_backend": "linux-etf-so-txtime-post-veth-v1",
            "runner_wakeup_schema_version": 11,
            "legacy_userspace_exact_release_projection": (
                "schema-10-compatibility-fields-retained-and-neutral"
            ),
            "kernel_tx_runner_receipt_schema_version": 1,
            "kernel_tx_evidence_schema_version": 1,
            "observer_topology_receipt_schema_version": 1,
            "physical_outgoing_observer": "router-ingress-post-client-veth-pre-netem",
            "tick_zero_physical_observation_required": True,
        }
    else:
        raise ValueError(
            "BuFLO timing-stress parameters are valid only at a checked-in "
            "excluded-campaign identity"
        )
    expected_parameter_path = parameter_path
    expected_receipt_path = expected_parameter_path.with_suffix(
        expected_parameter_path.suffix + ".provenance.json"
    )
    if not allow_timing_stress:
        raise ValueError(
            "BuFLO timing-stress parameters require an explicit timing-stress admission"
        )
    if (
        not require_checked_in_fixture
        or receipt_parameter_name is not None
        or receipt_path != expected_receipt_path
        or expected_workloads is not None
    ):
        raise ValueError(
            "BuFLO timing-stress parameters are valid only at their checked-in "
            "excluded-campaign identity"
        )

    receipt_keys = {
        "schema_version",
        "artifact_type",
        "status",
        "production_ready",
        "evidence_class",
        "study_id",
        "defense_kind",
        "qcsd_profile",
        "udp_payload_ceiling",
        "implementation_scope",
        "paper_equivalent",
        "canonical_parameter",
        "parameter_file",
        "derivation",
        "capture_contract",
    }
    _require_exact_keys(receipt, receipt_keys, "BuFLO timing-stress provenance")
    if (
        receipt.get("schema_version") != provenance_schema_version
        or receipt.get("artifact_type") != TIMING_STRESS_ARTIFACT_TYPE
        or receipt.get("status") != "controlled-test-only"
        or receipt.get("production_ready") is not False
        or receipt.get("evidence_class") != "timing-stress-nonformal-excluded"
        or receipt.get("study_id") != BUFLO_STUDY_ID
        or receipt.get("defense_kind") != "buflo"
        or receipt.get("qcsd_profile") != "research-1200"
        or receipt.get("udp_payload_ceiling") != 1_200
        or receipt.get("implementation_scope") != "client_only_quic"
        or receipt.get("paper_equivalent") is not False
        or expected_kind not in {None, "buflo"}
        or expected_qcsd_profile not in {None, "research-1200"}
        or expected_udp_payload_ceiling not in {None, 1_200}
    ):
        raise ValueError(f"BuFLO timing-stress provenance is invalid: {receipt_path}")

    canonical_path = (LAB_ROOT / "config/defense-params/buflo-live.json").resolve()
    canonical = _mapping(load_json(canonical_path), "canonical BuFLO parameters")
    expected_parameter = dict(canonical)
    expected_parameter["minimum_duration_us"] = 100_000_000
    if parameter != expected_parameter:
        raise ValueError("BuFLO timing-stress parameters may change only minimum_duration_us")
    parameter_sha256 = sha256_file(parameter_path)
    if receipt.get("canonical_parameter") != {
        "path": "../../defense-params/buflo-live.json",
        "sha256": sha256_file(canonical_path),
    } or receipt.get("parameter_file") != {
        "path": expected_parameter_path.name,
        "sha256": parameter_sha256,
    }:
        raise ValueError("BuFLO timing-stress parameter file binding is invalid")
    if receipt.get("derivation") != {
        "policy": (
            "canonical-live-buflo-with-only-minimum-duration-extended-for-"
            "excluded-captured-timing-stress"
        ),
        "changed_field": "minimum_duration_us",
        "canonical_value": 10_000_000,
        "stress_value": 100_000_000,
    }:
        raise ValueError("BuFLO timing-stress derivation is invalid")
    if receipt.get("capture_contract") != expected_capture_contract:
        raise ValueError("BuFLO timing-stress capture contract is invalid")
    _validate_buflo(parameter, 1_200, receipt_path)
    return ParameterArtifact(
        path=parameter_path,
        sha256=parameter_sha256,
        provenance_path=receipt_path,
        provenance_sha256=sha256_file(receipt_path),
        input_policy=input_policy,
    )


def _validate_controlled_regression_parameter(
    parameter: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    parameter_path: Path,
    receipt_path: Path,
    receipt_parameter_name: str | None,
    allow_reviewed_fixture: bool,
    expected_kind: str | None,
    expected_qcsd_profile: str | None,
    expected_udp_payload_ceiling: int | None,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
) -> ParameterArtifact:
    """Admit one workload-bound, explicitly non-formal local regression fixture."""

    keys = _PROVENANCE_KEYS | {"evidence_class", "workload_sha256"}
    _require_exact_keys(receipt, keys, "controlled regression provenance")
    if (
        receipt.get("schema_version") != PROVENANCE_SCHEMA_VERSION
        or receipt.get("artifact_type") != CONTROLLED_REGRESSION_ARTIFACT_TYPE
        or receipt.get("status") != "controlled-test-only"
        or receipt.get("production_ready") is not False
        or receipt.get("evidence_class") != "nonformal-regression"
        or receipt.get("defense_kind") != "walkie_talkie"
        or receipt.get("qcsd_profile") != "live"
        or receipt.get("udp_payload_ceiling") != 1_200
        or not allow_reviewed_fixture
        or expected_kind not in {None, "walkie_talkie"}
        or expected_qcsd_profile not in {None, "live"}
        or expected_udp_payload_ceiling not in {None, 1_200}
    ):
        raise ValueError(f"controlled regression provenance is invalid: {receipt_path}")
    recorded = _mapping(receipt.get("parameter_file"), "parameter_file metadata")
    _require_exact_keys(recorded, _PARAMETER_FILE_KEYS, "parameter_file metadata")
    expected_name = receipt_parameter_name or parameter_path.name
    parameter_sha256 = sha256_file(parameter_path)
    if recorded != {"path": expected_name, "sha256": parameter_sha256}:
        raise ValueError(f"controlled regression parameter binding is invalid: {receipt_path}")
    bindings = receipt.get("workload_sha256")
    if not isinstance(bindings, Mapping) or not bindings:
        raise ValueError(f"controlled regression workload binding is missing: {receipt_path}")
    if expected_workloads is not None:
        if not isinstance(expected_workloads, Mapping) or dict(bindings) != dict(
            expected_workloads
        ):
            raise ValueError(
                f"controlled regression parameter does not bind exact workloads: {receipt_path}"
            )
    _validate_runtime_shape(
        parameter,
        "walkie_talkie",
        1_200,
        receipt_path,
        expected_schema_version=6,
    )
    _validate_workload_coverage(
        parameter,
        "walkie_talkie",
        expected_workloads,
        receipt_path,
    )
    return ParameterArtifact(
        path=parameter_path,
        sha256=parameter_sha256,
        provenance_path=receipt_path,
        provenance_sha256=sha256_file(receipt_path),
        input_policy=CONTROLLED_REGRESSION_INPUT_POLICY,
    )


def _validate_reviewed_workload_binding(
    receipt: Mapping[str, Any],
    kind: str,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
    receipt_path: Path,
) -> None:
    if kind != "walkie_talkie":
        return
    bindings = receipt.get("workload_sha256")
    if (
        not isinstance(bindings, Mapping)
        or not bindings
        or any(
            not isinstance(workload_id, str)
            or not workload_id
            or not isinstance(digest, str)
            or not _lower_hex_digest(digest)
            for workload_id, digest in bindings.items()
        )
    ):
        raise ValueError(
            f"walkie_talkie smoke provenance requires workload SHA-256 bindings: {receipt_path}"
        )
    if expected_workloads is None:
        return
    if not isinstance(expected_workloads, Mapping):
        raise ValueError(
            "reviewed walkie_talkie fixtures require campaign workload SHA-256 bindings"
        )
    expected = dict(expected_workloads)
    if not expected or any(
        not isinstance(workload_id, str)
        or not workload_id
        or not isinstance(digest, str)
        or not _lower_hex_digest(digest)
        for workload_id, digest in expected.items()
    ):
        raise ValueError(
            "expected walkie_talkie workloads must map non-empty IDs to SHA-256 digests"
        )
    mismatched = sorted(
        workload_id
        for workload_id, digest in expected.items()
        if bindings.get(workload_id) != digest
    )
    if mismatched:
        raise ValueError(
            "walkie_talkie smoke provenance does not bind the exact campaign workload "
            f"SHA-256 for: {', '.join(mismatched)}"
        )


def validate_run_parameter_binding(
    run_data: Mapping[str, Any],
    *,
    kind: str,
    sha256: str,
    expected_path: Path | None = None,
    expected_workload_id: str | None = None,
) -> None:
    """Check the runner's kind/hash/path receipt for an external parameter."""

    parameter = run_data.get("defense_parameters")
    if (
        not isinstance(parameter, Mapping)
        or parameter.get("kind") != kind
        or parameter.get("sha256") != sha256
        or (expected_path is not None and parameter.get("path") != str(expected_path))
    ):
        raise ValueError("sample defense parameter run binding mismatch")
    if expected_workload_id is None:
        return
    resolved = run_data.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    if not isinstance(defense, Mapping) or defense.get("workload_id") != expected_workload_id:
        raise ValueError("sample defense workload run binding mismatch")


def _require_checked_in_fixture(parameter_path: Path, receipt_path: Path) -> None:
    fixture_root = (LAB_ROOT / "config/defense-params").resolve()
    if not parameter_path.is_relative_to(fixture_root) or not receipt_path.is_relative_to(
        fixture_root
    ):
        raise ValueError(f"reviewed parameter fixtures must be checked in under {fixture_root}")
    if receipt_path != parameter_provenance_path(parameter_path):
        raise ValueError("parameter provenance receipt must be adjacent to its parameter file")


def _validate_runtime_shape(
    parameter: Mapping[str, Any],
    kind: str,
    ceiling: int,
    receipt_path: Path,
    *,
    expected_schema_version: int,
) -> None:
    if (
        parameter.get("schema_version") != expected_schema_version
        or parameter.get("adaptation") != "qcsd-client-only"
        or parameter.get("paper_equivalent") is not False
    ):
        raise ValueError(
            f"{kind} parameter file lacks the versioned client-only runtime contract: "
            f"{receipt_path}"
        )
    if kind == "traffic_morphing":
        _validate_traffic_morphing(parameter, ceiling, receipt_path)
    elif kind == "wtf_pad":
        _validate_wtf_pad(parameter, receipt_path)
    else:
        _validate_walkie_talkie(
            parameter,
            ceiling,
            receipt_path,
            expected_schema_version=expected_schema_version,
        )


def _validate_buflo(parameter: Mapping[str, Any], ceiling: int, receipt_path: Path) -> None:
    fields = {
        "schema_version",
        "interval_us",
        "minimum_duration_us",
        "packet_size",
        "max_events",
        "implementation_scope",
        "paper_equivalent",
    }
    _require_exact_keys(parameter, fields, "BuFLO runtime parameters")
    integer_fields = fields - {"schema_version", "implementation_scope", "paper_equivalent"}
    values = {field: parameter.get(field) for field in integer_fields}
    if (
        parameter.get("schema_version") != 1
        or parameter.get("implementation_scope") != "client_only_quic"
        or parameter.get("paper_equivalent") is not False
        or any(type(value) is not int or value <= 0 for value in values.values())
        or int(values["packet_size"]) > ceiling
        or int(values["minimum_duration_us"]) < int(values["interval_us"])
        or int(values["max_events"])
        < int(values["minimum_duration_us"]) // int(values["interval_us"]) + 1
        # The runtime counter is per direction.  Ten thousand therefore proves
        # a hard combined ceiling of twenty thousand scheduled opportunities.
        or int(values["max_events"]) > 10_000
        or int(values["max_events"]) * int(values["interval_us"]) > 120_000_000
    ):
        raise ValueError(f"buflo parameter runtime shape is invalid: {receipt_path}")


def _validate_cs_buflo(parameter: Mapping[str, Any], ceiling: int, receipt_path: Path) -> None:
    fields = {
        "schema_version",
        "packet_size",
        "initial_interval_us",
        "minimum_interval_us",
        "maximum_interval_us",
        "initial_adaptation_boundary_bytes",
        "quiet_time_us",
        "outgoing_padding_mode",
        "incoming_padding_mode",
        "timing_sample_limit",
        "jitter_denominator",
        "jitter_max_numerator",
        "early_termination",
        "max_events",
        "implementation_scope",
        "paper_equivalent",
    }
    _require_exact_keys(parameter, fields, "CS-BuFLO runtime parameters")
    integer_fields = fields - {
        "schema_version",
        "outgoing_padding_mode",
        "incoming_padding_mode",
        "early_termination",
        "implementation_scope",
        "paper_equivalent",
    }
    values = {field: parameter.get(field) for field in integer_fields}
    if (
        parameter.get("schema_version") != 1
        or parameter.get("implementation_scope") != "client_only_quic"
        or parameter.get("paper_equivalent") is not False
        or any(type(value) is not int or value <= 0 for value in values.values())
        or int(values["packet_size"]) > ceiling
        or not int(values["minimum_interval_us"])
        <= int(values["initial_interval_us"])
        <= int(values["maximum_interval_us"])
        or parameter.get("outgoing_padding_mode") not in {"payload", "total"}
        or parameter.get("incoming_padding_mode") != "payload"
        or parameter.get("early_termination") != "local"
        or values["timing_sample_limit"] != 1_000
        or values["jitter_denominator"] != 100
        or values["jitter_max_numerator"] != 200
        or int(values["quiet_time_us"]) < int(values["maximum_interval_us"])
    ):
        raise ValueError(f"cs_buflo parameter runtime shape is invalid: {receipt_path}")
    for field in (
        "initial_interval_us",
        "minimum_interval_us",
        "maximum_interval_us",
        "initial_adaptation_boundary_bytes",
    ):
        value = int(values[field])
        if value & (value - 1):
            raise ValueError(f"cs_buflo {field} must be a power of two: {receipt_path}")


def _validate_traffic_morphing(
    parameter: Mapping[str, Any], ceiling: int, receipt_path: Path
) -> None:
    buckets = parameter.get("buckets")
    profiles = parameter.get("profiles")
    if (
        parameter.get("udp_payload_ceiling") != ceiling
        or not isinstance(buckets, list)
        or not buckets
        or any(type(value) is not int or value <= 0 for value in buckets)
        or buckets != sorted(set(buckets))
        or buckets[-1] > ceiling
        or not isinstance(profiles, list)
        or not profiles
    ):
        raise ValueError(f"traffic_morphing parameter runtime shape is invalid: {receipt_path}")
    sources: list[str] = []
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise ValueError(f"traffic_morphing profile is malformed: {receipt_path}")
        source = profile.get("source")
        target = profile.get("target")
        if not isinstance(source, str) or not source or not isinstance(target, str) or not target:
            raise ValueError(f"traffic_morphing profile identity is invalid: {receipt_path}")
        sources.append(source)
        for direction in ("outgoing", "incoming"):
            _validate_morphing_direction(profile.get(direction), len(buckets), receipt_path)
    if len(sources) != len(set(sources)):
        raise ValueError(f"traffic_morphing source profiles are duplicated: {receipt_path}")


def _validate_morphing_direction(value: Any, width: int, receipt_path: Path) -> None:
    direction = _mapping(value, "traffic_morphing direction")
    for name in ("source_distribution", "target_distribution", "realized_distribution"):
        distribution = direction.get(name)
        if not _probability_row(distribution, width):
            raise ValueError(f"traffic_morphing {name} is invalid: {receipt_path}")
    rows = direction.get("rows")
    if (
        not isinstance(rows, list)
        or len(rows) != width
        or any(not _probability_row(row, width) for row in rows)
    ):
        raise ValueError(f"traffic_morphing matrix is invalid: {receipt_path}")


def _validate_wtf_pad(parameter: Mapping[str, Any], receipt_path: Path) -> None:
    fitting = parameter.get("fitting")
    if (
        not isinstance(fitting, Mapping)
        or fitting.get("infinity_token_formulas") != _WTF_PAD_INFINITY_TOKEN_FORMULAS
    ):
        raise ValueError(f"wtf_pad fitting metadata is invalid: {receipt_path}")
    for direction_name in ("outgoing", "incoming"):
        direction = _mapping(parameter.get(direction_name), f"wtf_pad {direction_name}")
        for state in ("burst", "gap"):
            histogram = _mapping(direction.get(state), f"wtf_pad {direction_name} {state}")
            edges = histogram.get("edges_us")
            tokens = histogram.get("tokens")
            infinity = histogram.get("infinity_tokens")
            if (
                not isinstance(edges, list)
                or not edges
                or any(type(value) is not int or value <= 0 for value in edges)
                or edges != sorted(set(edges))
                or not isinstance(tokens, list)
                or len(tokens) != len(edges)
                or any(type(value) is not int or value < 0 for value in tokens)
                or sum(tokens) < 1
                or type(infinity) is not int
                or infinity < 1
            ):
                raise ValueError(
                    f"wtf_pad {direction_name} {state} histogram is invalid: {receipt_path}"
                )


def _validate_walkie_talkie(
    parameter: Mapping[str, Any],
    ceiling: int,
    receipt_path: Path,
    *,
    expected_schema_version: int,
) -> None:
    profiles = parameter.get("profiles")
    expected_matching_algorithm = (
        "minimum-base-symmetric-mold-padding-cost-one-to-one"
        if expected_schema_version in {5, 6}
        else "minimum-cost-one-to-one"
    )
    receiver_continuation = parameter.get("receiver_continuation")
    if (
        parameter.get("packet_size") != ceiling
        or parameter.get("matching_algorithm") != expected_matching_algorithm
        or (
            expected_schema_version in {5, 6}
            and receiver_continuation
            != (
                _WALKIE_TALKIE_RECEIVER_CONTINUATION_SCHEMA_FIVE
                if expected_schema_version == 5
                else _WALKIE_TALKIE_RECEIVER_CONTINUATION
            )
        )
        or (expected_schema_version == 2 and "receiver_continuation" in parameter)
        or not isinstance(profiles, list)
        or not profiles
    ):
        raise ValueError(f"walkie_talkie parameter runtime shape is invalid: {receipt_path}")
    bindings = parameter.get("qualification_bindings")
    if expected_schema_version == 6:
        if not isinstance(bindings, list) or not bindings:
            raise ValueError(
                f"walkie_talkie schema-six qualification bindings are missing: {receipt_path}"
            )
        binding_ids: list[str] = []
        for value in bindings:
            if not isinstance(value, Mapping) or set(value) != {
                "workload_id",
                "chaff_qualification_sidecar_sha256",
                "prefix_pack_spec_sha256",
                "qualified_chaff_manifest_sha256",
                "application_resource_id",
                "selected_chaff_resource_id",
                "qualified_parallel_chaff_streams",
                "walkie_talkie_required_chaff_streams",
            }:
                raise ValueError(
                    f"walkie_talkie qualification binding is malformed: {receipt_path}"
                )
            workload_id = value["workload_id"]
            if (
                not isinstance(workload_id, str)
                or not workload_id
                or any(
                    not isinstance(value[field], str) or not _lower_hex_digest(value[field])
                    for field in (
                        "chaff_qualification_sidecar_sha256",
                        "prefix_pack_spec_sha256",
                        "qualified_chaff_manifest_sha256",
                    )
                )
                or type(value["application_resource_id"]) is not int
                or value["application_resource_id"] != 0
                or type(value["selected_chaff_resource_id"]) is not int
                or value["selected_chaff_resource_id"] < 0
                or type(value["walkie_talkie_required_chaff_streams"]) is not int
                or not 1 <= value["walkie_talkie_required_chaff_streams"] <= 20
                or type(value["qualified_parallel_chaff_streams"]) is not int
                or value["qualified_parallel_chaff_streams"]
                != max(5, value["walkie_talkie_required_chaff_streams"])
            ):
                raise ValueError(f"walkie_talkie qualification binding is invalid: {receipt_path}")
            binding_ids.append(workload_id)
        if len(binding_ids) != len(set(binding_ids)):
            raise ValueError(f"walkie_talkie qualification bindings are duplicated: {receipt_path}")
    elif "qualification_bindings" in parameter:
        raise ValueError(
            f"historical walkie_talkie artifact contains schema-six bindings: {receipt_path}"
        )
    real_ids: list[str] = []
    decoy_ids: list[str] = []
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise ValueError(f"walkie_talkie profile is malformed: {receipt_path}")
        real = profile.get("real")
        decoy = profile.get("decoy")
        bursts = profile.get("bursts")
        if (
            not isinstance(real, str)
            or not real
            or not isinstance(decoy, str)
            or not decoy
            or not isinstance(bursts, list)
            or not bursts
        ):
            raise ValueError(f"walkie_talkie profile identity is invalid: {receipt_path}")
        real_ids.append(real)
        decoy_ids.append(decoy)
        if expected_schema_version in {5, 6}:
            first = bursts[0]
            first_outgoing = first.get("outgoing") if isinstance(first, Mapping) else None
            if type(first_outgoing) is not int or first_outgoing <= 0:
                raise ValueError(
                    f"walkie_talkie first molded component must contain outgoing cells: "
                    f"{receipt_path}"
                )
        for burst in bursts:
            if not isinstance(burst, Mapping):
                raise ValueError(f"walkie_talkie burst is malformed: {receipt_path}")
            outgoing = burst.get("outgoing")
            incoming = burst.get("incoming")
            if (
                type(outgoing) is not int
                or outgoing < 0
                or type(incoming) is not int
                or incoming < 0
                or outgoing + incoming < 1
            ):
                raise ValueError(f"walkie_talkie burst is invalid: {receipt_path}")
    identities = [*real_ids, *decoy_ids]
    if len(identities) != len(set(identities)):
        raise ValueError(f"walkie_talkie profiles are duplicated: {receipt_path}")


def _validate_workload_coverage(
    parameter: Mapping[str, Any],
    kind: str,
    expected_workloads: Mapping[str, object] | Collection[str] | None,
    receipt_path: Path,
) -> None:
    if expected_workloads is None or kind == "wtf_pad":
        return
    expected = set(expected_workloads)
    if not expected or any(not isinstance(value, str) or not value for value in expected):
        raise ValueError("expected workloads must contain non-empty workload IDs")
    profiles = parameter.get("profiles")
    assert isinstance(profiles, list)  # validated by the kind-specific parser
    if kind == "traffic_morphing":
        observed = {
            str(profile["source"])
            for profile in profiles
            if isinstance(profile, Mapping) and isinstance(profile.get("source"), str)
        }
    else:
        observed = {
            str(profile[identity])
            for profile in profiles
            if isinstance(profile, Mapping)
            for identity in ("real", "decoy")
            if isinstance(profile.get(identity), str)
        }
    if not expected <= observed:
        raise ValueError(
            f"{kind} parameter profiles do not cover all campaign workloads: {receipt_path}"
        )


def _probability_row(value: Any, width: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) == width
        and all(_finite_number(item) and 0 <= float(item) <= 1 for item in value)
        and math.isclose(sum(float(item) for item in value), 1.0, abs_tol=1e-6)
    )


def _finite_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def _lower_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = ", ".join(sorted(expected - set(value))) or "none"
        extra = ", ".join(sorted(set(value) - expected)) or "none"
        raise ValueError(f"{label} has the wrong fields (missing: {missing}; extra: {extra})")
