"""Independent fitting artifacts for ``classifier-multiorigin100-v1``.

The historical six-workload ``research-1200`` fitter is intentionally not
extended here.  This module owns a separate, hash-bound contract for the 120
class pilot and the 100 class authoritative cohort.  Numeric fitting evidence,
prefix-capacity evidence, live qualification evidence, and runtime parameters
are separate stages; bytes from the latter two stages can never enter a fit.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from .class_acquisition import validate_class_study_preparation
from .class_cohort import (
    cohort_workload_hashes,
    validate_cohort_assembly_receipt,
)
from .class_run_binding import (
    ClassSampleRunBinding,
    resolve_class_sample_run_binding,
)
from .class_study import (
    FINAL_CLASS_COUNT,
    PILOT_COUNT,
    STUDY_ID,
    canonical_json_bytes,
    canonical_json_sha256,
    validate_study_receipt,
)
from .experiment import resolved_sample_directory
from .fitting_morphing import fit_traffic_morphing, minimum_cost_derangement
from .fitting_trace import FittingTrace, load_fitting_trace
from .fitting_walkie_talkie import (
    fit_walkie_talkie,
    minimum_weight_perfect_matching_from_costs,
)
from .fitting_wtfpad import fit_wtf_pad
from .util import SOURCE_METADATA_KEYS, load_json, sha256_bytes, sha256_file
from .verification import VerifiedResult, verify_result

SCHEMA_VERSION = 1
FITTER_VERSION = "qcsd_lab.class_fitting 1.0.0"
NUMERIC_ARTIFACT_TYPE = "qcsd-class-study-numeric-fitting-bundle"
FINAL_ARTIFACT_TYPE = "qcsd-class-study-research-defense-bundle"
PREFIX_ARTIFACT_TYPE = "qcsd-class-study-walkie-talkie-prefix-pack-spec"
NUMERIC_PROVENANCE_FILE = "numeric-provenance.json"
PROVENANCE_FILE = "provenance.json"
BUNDLE_FILES = {
    "traffic_morphing": "traffic-morphing.json",
    "wtf_pad": "wtf-pad.json",
    "walkie_talkie": "walkie-talkie.json",
}
NUMERIC_FILES = frozenset((*BUNDLE_FILES.values(), NUMERIC_PROVENANCE_FILE))
FINAL_FILES = frozenset((*BUNDLE_FILES.values(), PROVENANCE_FILE))

PILOT_STAGE = "pilot"
AUTHORITATIVE_STAGE = "authoritative"
STAGES = frozenset({PILOT_STAGE, AUTHORITATIVE_STAGE})
PILOT_BUNDLE_DIRECTORY = f"{STUDY_ID}-pilot-fitting"
AUTHORITATIVE_BUNDLE_DIRECTORY = f"{STUDY_ID}-authoritative-fitting"
PILOT_NUMERIC_DIRECTORY = f"{PILOT_BUNDLE_DIRECTORY}-numeric"
AUTHORITATIVE_NUMERIC_DIRECTORY = f"{AUTHORITATIVE_BUNDLE_DIRECTORY}-numeric"
PILOT_PREFIX_DIRECTORY = f"{PILOT_BUNDLE_DIRECTORY}-prefix-specs"
AUTHORITATIVE_PREFIX_DIRECTORY = f"{AUTHORITATIVE_BUNDLE_DIRECTORY}-prefix-specs"
PILOT_QUALIFICATION_SET = f"{STUDY_ID}-pilot120-full-v1"
AUTHORITATIVE_QUALIFICATION_SET = f"{STUDY_ID}-final100-full-v1"
PILOT_PARAMETER_INPUT_POLICY = "sealed-class-study-pilot-fitting-v1"
AUTHORITATIVE_PARAMETER_INPUT_POLICY = "sealed-class-study-fitting-v1"

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_EXPECTED_LIMITS = {
    "timeout_seconds": 120,
    "max_response_bytes": 1024 * 1024,
    "capture_seconds": 180,
    "capture_megabytes": 64,
    "max_attempts": 3,
    "per_origin_cooldown_seconds": 30.0,
    "settle_seconds": 1.0,
}
_UNDEFENDED = [{"name": "undefended", "kind": "none", "baseline": True}]
_NAMED_SET_KEYS = {
    "schema_version",
    "artifact_type",
    "qualification_set",
    "qualification_scope",
    "qualification_sidecar_schema_version",
    "workload_count",
    "workload_ids",
    "workloads",
    "bindings_sha256",
    "qualification_authority",
}
_NAMED_ENTRY_KEYS = {
    "index",
    "workload_id",
    "workload_manifest",
    "qualification_sidecar",
    "runtime_manifest_sha256",
    "prefix_pack_spec",
}
_RUNTIME_BINDING_KEYS = {
    "workload_id",
    "chaff_qualification_sidecar_sha256",
    "prefix_pack_spec_sha256",
    "qualified_chaff_manifest_sha256",
    "application_resource_id",
    "selected_chaff_resource_id",
    "qualified_parallel_chaff_streams",
    "walkie_talkie_required_chaff_streams",
}


class ResultVerifier(Protocol):
    def __call__(self, root: Path) -> VerifiedResult: ...


class TraceLoader(Protocol):
    def __call__(self, sample_root: Path, **kwargs: Any) -> FittingTrace: ...


class QualificationLoader(Protocol):
    def __call__(self, sidecar_path: Path, **kwargs: Any) -> Any: ...


class PrefixValidator(Protocol):
    def __call__(
        self,
        value: object,
        *,
        workload_id: str,
        walkie_talkie: Mapping[str, Any],
        source_walkie_talkie_artifact_sha256: str,
        application_manifest: Mapping[str, Any],
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ClassFitters:
    """Injectable fitting boundary used by deterministic unit tests."""

    traffic_morphing: Callable[
        [Mapping[str, Sequence[FittingTrace]]], tuple[dict[str, object], dict[str, object]]
    ] = fit_traffic_morphing
    wtf_pad: Callable[..., tuple[dict[str, object], dict[str, object]]] = fit_wtf_pad
    walkie_talkie: Callable[
        [Mapping[str, Sequence[FittingTrace]]], tuple[dict[str, object], dict[str, object]]
    ] = fit_walkie_talkie


DEFAULT_FITTERS = ClassFitters()


@dataclass(frozen=True)
class ClassFittingInputs:
    verified: VerifiedResult
    stage: str
    workload_ids: tuple[str, ...]
    visits_per_policy: int
    as_defined: Mapping[str, tuple[FittingTrace, ...]]
    half_duplex: Mapping[str, tuple[FittingTrace, ...]]
    cohort_receipt: dict[str, Any]
    cohort_receipt_sha256: str
    cohort_assembly_receipt: dict[str, Any]
    cohort_assembly_receipt_sha256: str
    source_result: dict[str, Any]


@dataclass(frozen=True)
class QualificationContext:
    """File-backed evidence needed to verify a finalized fitting bundle."""

    workload_root: Path
    sidecar_root: Path
    prefix_spec_root: Path
    loader: QualificationLoader | None = None
    prefix_validator: PrefixValidator | None = None
    preparation_validator: Callable[..., None] = validate_class_study_preparation
    require_current_implementation: bool = True
    qualification_authority: Mapping[str, Any] | None = None
    expected_qualification_set: str | None = None


@dataclass(frozen=True)
class VerifiedClassFittingBundle:
    root: Path
    provenance: dict[str, Any]
    artifact_hashes: dict[str, str]
    stage: str
    parameter_input_policy: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": True,
            "root": str(self.root),
            "stage": self.stage,
            "parameter_input_policy": self.parameter_input_policy,
            "provenance_sha256": sha256_file(self.root / PROVENANCE_FILE),
            "artifacts": self.artifact_hashes,
        }


@dataclass(frozen=True)
class VerifiedNumericFittingBundle:
    root: Path
    provenance: dict[str, Any]
    artifact_hashes: dict[str, str]
    stage: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": True,
            "authoritative": False,
            "root": str(self.root),
            "stage": self.stage,
            "artifacts": self.artifact_hashes,
        }


@dataclass(frozen=True)
class _RecordedMorphingCost:
    fidelity_cost: float
    byte_cost: float


def validate_class_fitting_result(
    root: Path,
    *,
    expected_stage: str | None = None,
    expected_cohort_receipt_path: Path | None = None,
    expected_cohort_assembly_receipt_path: Path | None = None,
    result_verifier: ResultVerifier = verify_result,
    trace_loader: TraceLoader = load_fitting_trace,
    preparation_validator: Callable[..., None] = validate_class_study_preparation,
    run_binding_resolver: Callable[..., ClassSampleRunBinding] = (resolve_class_sample_run_binding),
) -> ClassFittingInputs:
    """Validate the exact sealed schema-two class-study fitting cross-product."""

    verified = result_verifier(root)
    experiment = verified.experiment
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise TypeError("class-study fitting result has no frozen configuration")
    role = configuration.get("evidence_role")
    stage = {
        "pilot-fitting": PILOT_STAGE,
        "authoritative-fitting": AUTHORITATIVE_STAGE,
    }.get(role)
    if stage is None or (expected_stage is not None and stage != _stage(expected_stage)):
        raise ValueError("class-study fitting result has the wrong evidence role")
    count, visits, campaign = _stage_contract(stage)
    study_id = configuration.get("class_study_id", STUDY_ID)
    successor_sha256 = configuration.get("class_study_successor_sha256")
    if successor_sha256 is not None:
        if (
            stage != AUTHORITATIVE_STAGE
            or not isinstance(study_id, str)
            or not study_id.startswith("classifier-multiorigin100-v2-")
            or not _digest(successor_sha256)
        ):
            raise ValueError("class-study fitting successor identity is invalid")
        successor_input = verified.root / "inputs/class-study-successor.json"
        if (
            successor_input.is_symlink()
            or not successor_input.is_file()
            or sha256_file(successor_input) != successor_sha256
            or verified.checksums.get("inputs/class-study-successor.json") != successor_sha256
        ):
            raise ValueError("class-study fitting successor authority is not sealed")
        campaign = f"{study_id}-authoritative-fitting-2000-1200"
    elif study_id != STUDY_ID:
        raise ValueError("class-study fitting has an unbound alternate study identity")
    if (
        experiment.get("name") != campaign
        or experiment.get("purpose") != "fitting"
        or experiment.get("status") != "complete"
        or not isinstance(experiment.get("summary"), Mapping)
        or experiment["summary"].get("passed") is not True
    ):
        raise ValueError("class-study fitting requires a complete fully eligible result")
    if configuration.get("profile") != "research-1200":
        raise ValueError("class-study fitting requires profile research-1200")
    if configuration.get("request_policies") != ["as-defined", "half-duplex"]:
        raise ValueError("class-study fitting request-policy order is invalid")
    if configuration.get("defenses") != _UNDEFENDED:
        raise ValueError("class-study fitting requires the exact undefended baseline")
    if configuration.get("limits") != _EXPECTED_LIMITS:
        raise ValueError("class-study fitting capture limits differ from the contract")
    _validate_clean_source(experiment.get("source"))

    frozen_receipt_path = verified.root / "inputs/class-study-cohort.json"
    frozen_receipt = _load_regular_json(frozen_receipt_path, "frozen class-study cohort")
    selection = validate_study_receipt(frozen_receipt)
    cohort_sha256 = sha256_file(frozen_receipt_path)
    if configuration.get("class_study_cohort_sha256") != cohort_sha256:
        raise ValueError("class-study fitting cohort hash differs from its frozen input")
    frozen_assembly_path = verified.root / "inputs/class-study-cohort-assembly.json"
    frozen_assembly = _load_regular_json(
        frozen_assembly_path,
        "frozen class-study cohort assembly",
    )
    validate_cohort_assembly_receipt(frozen_assembly, cohort=frozen_receipt)
    assembly_sha256 = sha256_file(frozen_assembly_path)
    if configuration.get("class_study_cohort_assembly_sha256") != assembly_sha256:
        raise ValueError("class-study fitting cohort-assembly hash differs from its frozen input")
    if expected_cohort_receipt_path is not None:
        expected_path = _regular_file(expected_cohort_receipt_path, "expected cohort receipt")
        if sha256_file(expected_path) != cohort_sha256:
            raise ValueError("class-study fitting uses an unexpected cohort receipt")
        validate_study_receipt(load_json(expected_path))
    if expected_cohort_assembly_receipt_path is not None:
        expected_assembly_path = _regular_file(
            expected_cohort_assembly_receipt_path,
            "expected cohort-assembly receipt",
        )
        if sha256_file(expected_assembly_path) != assembly_sha256:
            raise ValueError("class-study fitting uses an unexpected cohort-assembly receipt")
        validate_cohort_assembly_receipt(
            load_json(expected_assembly_path),
            cohort=frozen_receipt,
        )
    selected = selection.pilot if stage == PILOT_STAGE else selection.final
    cohort_ids = tuple(candidate.candidate_id for candidate in selected)
    if len(cohort_ids) != count:
        raise ValueError("class-study fitting cohort cardinality is invalid")

    workload_records = configuration.get("workloads")
    if not isinstance(workload_records, list) or len(workload_records) != count:
        raise ValueError("class-study fitting workload inventory has the wrong cardinality")
    workload_ids: list[str] = []
    run_bindings: dict[str, ClassSampleRunBinding] = {}
    admitted_hashes = cohort_workload_hashes(
        frozen_assembly,
        cohort=frozen_receipt,
        workload_ids=cohort_ids,
    )
    for expected_id, raw_record in zip(cohort_ids, workload_records, strict=True):
        if not isinstance(raw_record, Mapping):
            raise TypeError("class-study fitting workload record is not an object")
        workload_id = raw_record.get("id")
        if workload_id != expected_id or raw_record.get("visits") != visits:
            raise ValueError("class-study fitting workload order or visit count is invalid")
        manifest_path = _safe_result_file(
            verified.root,
            raw_record.get("manifest"),
            f"frozen workload {expected_id}",
        )
        if (
            raw_record.get("sha256") != sha256_file(manifest_path)
            or raw_record.get("sha256") != admitted_hashes[expected_id]
        ):
            raise ValueError("class-study fitting workload manifest hash is invalid")
        manifest = load_json(manifest_path)
        preparation_validator(manifest, workload_id=expected_id)
        run_bindings[expected_id] = run_binding_resolver(
            verified.root,
            configuration,
            {
                "workload_id": expected_id,
                "defense": "undefended",
                "runtime_kind": "none",
                "baseline": True,
            },
            allow_derived_runtime_without_frozen_copy=True,
        )
        workload_ids.append(expected_id)
    if tuple(workload_ids) != cohort_ids or len(set(workload_ids)) != count:
        raise ValueError("class-study fitting workload identities are invalid")

    samples = experiment.get("samples")
    sample_count = count * visits * 2
    if not isinstance(samples, list) or len(samples) != sample_count:
        raise ValueError(f"class-study fitting requires exactly {sample_count} samples")
    expected = {
        (workload_id, policy, visit)
        for workload_id in cohort_ids
        for policy in ("as-defined", "half-duplex")
        for visit in range(visits)
    }
    observed: set[tuple[str, str, int]] = set()
    by_policy: dict[str, dict[str, list[FittingTrace]]] = {
        policy: {workload_id: [] for workload_id in cohort_ids}
        for policy in ("as-defined", "half-duplex")
    }
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise TypeError("class-study fitting sample is not an object")
        identity = (
            sample.get("workload_id"),
            sample.get("request_policy"),
            sample.get("visit"),
        )
        if identity not in expected or identity in observed:
            raise ValueError("class-study fitting samples are not the exact cross-product")
        if (
            sample.get("state") != "accepted"
            or sample.get("eligible") is not True
            or sample.get("defense") != "undefended"
            or sample.get("runtime_kind") != "none"
            or sample.get("baseline") is not True
            or type(sample.get("attempts")) is not int
            or not 1 <= sample["attempts"] <= 3
        ):
            raise ValueError("every class-study fitting sample must be eligible and undefended")
        observed.add(identity)  # type: ignore[arg-type]
        sample_root = resolved_sample_directory(verified.root, sample, require_directory=True)
        trace = trace_loader(
            sample_root,
            sample_id=sample["sample_id"],
            workload_id=sample["workload_id"],
            request_policy=sample["request_policy"],
            visit=sample["visit"],
            require_observations=sample["request_policy"] == "half-duplex",
            accepted_artifacts=sample["artifacts"],
            seed=sample.get("seed"),
            run_binding=run_bindings.get(str(sample["workload_id"])),
        )
        by_policy[sample["request_policy"]][sample["workload_id"]].append(trace)
    if observed != expected:
        raise ValueError("class-study fitting result is missing required samples")
    frozen = {
        policy: {
            workload_id: tuple(sorted(values, key=lambda trace: (trace.visit, trace.sample_id)))
            for workload_id, values in mapping.items()
        }
        for policy, mapping in by_policy.items()
    }
    source_result = _source_result_receipt(verified)
    return ClassFittingInputs(
        verified=verified,
        stage=stage,
        workload_ids=cohort_ids,
        visits_per_policy=visits,
        as_defined=frozen["as-defined"],
        half_duplex=frozen["half-duplex"],
        cohort_receipt=dict(frozen_receipt),
        cohort_receipt_sha256=cohort_sha256,
        cohort_assembly_receipt=dict(frozen_assembly),
        cohort_assembly_receipt_sha256=assembly_sha256,
        source_result=source_result,
    )


def create_numeric_fitting_bundle(
    result_root: Path,
    *,
    artifacts_root: Path,
    stage: str,
    expected_cohort_receipt_path: Path | None = None,
    expected_cohort_assembly_receipt_path: Path | None = None,
    fitting_inputs_loader: Callable[..., ClassFittingInputs] = validate_class_fitting_result,
    fitters: ClassFitters = DEFAULT_FITTERS,
) -> Path:
    """Fit and create the non-runnable numeric staging bundle exactly once."""

    stage = _stage(stage)
    fitting = fitting_inputs_loader(
        result_root,
        expected_stage=stage,
        expected_cohort_receipt_path=expected_cohort_receipt_path,
        expected_cohort_assembly_receipt_path=expected_cohort_assembly_receipt_path,
    )
    _validate_injected_inputs(fitting, stage)
    traffic, traffic_receipt = fitters.traffic_morphing(fitting.as_defined)
    ordered_as_defined = tuple(
        trace for workload_id in fitting.workload_ids for trace in fitting.as_defined[workload_id]
    )
    wtf, wtf_receipt = fitters.wtf_pad(
        ordered_as_defined,
        fitted_from=_consumed_corpus_digest(fitting.as_defined, fitting.workload_ids),
    )
    walkie, walkie_receipt = fitters.walkie_talkie(fitting.half_duplex)
    artifacts = {
        "traffic_morphing": traffic,
        "wtf_pad": wtf,
        "walkie_talkie": walkie,
    }
    diagnostics = {
        "traffic_morphing": traffic_receipt,
        "wtf_pad": wtf_receipt,
        "walkie_talkie": walkie_receipt,
    }
    _validate_numeric_parameters(artifacts, fitting.workload_ids)
    _validate_selected_optima(diagnostics, fitting.workload_ids)
    _validate_artifact_algorithm_bindings(
        artifacts,
        diagnostics,
        _sample_contributions(fitting),
        fitting.workload_ids,
    )

    parent = _regular_directory(artifacts_root, "class fitting artifact root")
    destination = parent / _numeric_directory(stage)
    candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.qcsd-tmp-", dir=parent))
    try:
        for kind, filename in BUNDLE_FILES.items():
            _write_new_json(candidate / filename, artifacts[kind])
        hashes = {kind: sha256_file(candidate / name) for kind, name in BUNDLE_FILES.items()}
        provenance = _numeric_provenance(fitting, diagnostics, hashes)
        _write_new_json(candidate / NUMERIC_PROVENANCE_FILE, provenance)
        _verify_numeric_files(candidate)
        _publish_directory(candidate, destination)
        return verify_numeric_fitting_bundle(destination).root
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)


def verify_numeric_fitting_bundle(
    root: Path,
    *,
    source_result_root: Path | None = None,
    fitting_inputs_loader: Callable[..., ClassFittingInputs] = validate_class_fitting_result,
    fitters: ClassFitters = DEFAULT_FITTERS,
) -> VerifiedNumericFittingBundle:
    """Verify numeric staging bytes and optionally refit every value from evidence."""

    root = _bundle_root(root, NUMERIC_FILES, "numeric fitting bundle")
    provenance = _verify_numeric_files(root)
    stage = _stage(provenance["stage"])
    hashes = _verify_artifact_hashes(root, provenance)
    workload_ids = tuple(provenance["fitting_contract"]["workload_order"])
    artifacts = {kind: load_json(root / filename) for kind, filename in BUNDLE_FILES.items()}
    _validate_numeric_parameters(artifacts, workload_ids)
    _validate_selected_optima(provenance["algorithms"], workload_ids)
    _validate_artifact_algorithm_bindings(
        artifacts,
        provenance["algorithms"],
        provenance["sample_contributions"],
        workload_ids,
    )
    if source_result_root is not None:
        fitting = fitting_inputs_loader(source_result_root, expected_stage=stage)
        _validate_injected_inputs(fitting, stage)
        _require_embedded_fitting_identity(provenance, fitting)
        recomputed = _run_fitters(fitting, fitters)
        for kind, (parameter, receipt) in recomputed.items():
            if canonical_json_bytes(parameter) != canonical_json_bytes(artifacts[kind]):
                raise ValueError(f"numeric {kind} differs from independently refitted evidence")
            if canonical_json_bytes(receipt) != canonical_json_bytes(
                provenance["algorithms"][kind]
            ):
                raise ValueError(f"numeric {kind} algorithm receipt differs from refitting")
    return VerifiedNumericFittingBundle(root, provenance, hashes, stage)


def build_schema_six_prefix_spec(
    workload_id: str,
    walkie_talkie: Mapping[str, Any],
    *,
    source_walkie_talkie_artifact_sha256: str,
    application_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Project one schema-six runtime mould without adding framing a second time."""

    from .chaff_qualification import (
        MAX_STREAM_DATA_EXCESS,
        UDP_PAYLOAD_CEILING,
        _capacity_plan,
        _maximum_receiver_continuation_reserve_horizon,
        selected_chaff_resource,
        selected_navigation_root,
    )
    from .chaff_qualification import (
        SCHEMA_VERSION as LEGACY_PREFIX_SCHEMA_VERSION,
    )

    if walkie_talkie.get("schema_version") != 6 or walkie_talkie.get("packet_size") != 1_200:
        raise ValueError("class-study prefix specs require a schema-six Walkie-Talkie artifact")
    if not _digest(source_walkie_talkie_artifact_sha256):
        raise ValueError("class-study prefix source SHA-256 is invalid")
    profiles = walkie_talkie.get("profiles")
    matches = (
        [
            profile
            for profile in profiles
            if isinstance(profile, Mapping)
            and workload_id in {profile.get("real"), profile.get("decoy")}
        ]
        if isinstance(profiles, list)
        else []
    )
    if len(matches) != 1:
        raise ValueError(f"Walkie-Talkie does not uniquely cover {workload_id!r}")
    raw_bursts = matches[0].get("bursts")
    if not isinstance(raw_bursts, list) or not raw_bursts:
        raise ValueError("schema-six Walkie-Talkie profile has no runtime bursts")
    bursts: list[dict[str, int]] = []
    for raw in raw_bursts:
        if not isinstance(raw, Mapping) or set(raw) != {"outgoing", "incoming"}:
            raise ValueError("schema-six Walkie-Talkie burst has an invalid schema")
        outgoing, incoming = raw["outgoing"], raw["incoming"]
        if type(outgoing) is not int or type(incoming) is not int or outgoing <= 0 or incoming < 0:
            raise ValueError("schema-six Walkie-Talkie burst has invalid cell counts")
        # Schema six's fitter already applied both the sender-framing and
        # receiver-continuation cells in mold().  These values are deliberately
        # copied verbatim; the legacy schema-five projector must not be called.
        bursts.append({"outgoing": outgoing, "incoming": incoming})
    numeric = {"packet_size": 1_200, "bursts": bursts}
    numeric_sha256 = sha256_bytes(
        b"qcsd-class-study-walkie-talkie-numeric-profile-v1\0"
        + json.dumps(numeric, sort_keys=True, separators=(",", ":")).encode()
    )
    application = selected_navigation_root(application_manifest, workload_id)
    selected, selected_response = selected_chaff_resource(application_manifest, workload_id)
    required, stages = _capacity_plan(
        bursts=bursts,
        manifest=application_manifest,
        selected_chaff_body_bytes=selected_response["bytes"],
    )
    horizon = _maximum_receiver_continuation_reserve_horizon(bursts)
    return {
        "schema_version": LEGACY_PREFIX_SCHEMA_VERSION + 1,
        "artifact_type": PREFIX_ARTIFACT_TYPE,
        "workload_id": workload_id,
        "packet_size": UDP_PAYLOAD_CEILING,
        "source_walkie_talkie_schema_version": 6,
        "numeric_profile_derivation": (
            "schema-six-runtime-bursts-verbatim-no-additional-sender-framing"
        ),
        "max_stream_data_excess": MAX_STREAM_DATA_EXCESS,
        "maximum_receiver_continuation_reserve_horizon": horizon,
        "required_chaff_survivors": horizon + 1,
        "numeric_profile_sha256": numeric_sha256,
        "source_walkie_talkie_artifact_sha256": source_walkie_talkie_artifact_sha256,
        "application_resource_id": application["id"],
        "selected_chaff_resource_id": selected["id"],
        "selected_chaff_body_bytes": selected_response["bytes"],
        "required_chaff_streams": required,
        "stream_activation_stages": stages,
        "numeric_profile": numeric,
    }


def validate_schema_six_prefix_spec(
    value: object,
    *,
    workload_id: str,
    walkie_talkie: Mapping[str, Any],
    source_walkie_talkie_artifact_sha256: str,
    application_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute a class-study prefix specification from its exact WT6 source."""

    observed = validate_schema_six_prefix_spec_shape(
        value,
        workload_id=workload_id,
        application_manifest=application_manifest,
    )
    expected = build_schema_six_prefix_spec(
        workload_id,
        walkie_talkie,
        source_walkie_talkie_artifact_sha256=source_walkie_talkie_artifact_sha256,
        application_manifest=application_manifest,
    )
    if canonical_json_bytes(observed) != canonical_json_bytes(expected):
        raise ValueError("class-study prefix specification differs from its WT6 source")
    return observed


def validate_schema_six_prefix_spec_shape(
    value: object,
    *,
    workload_id: str,
    application_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a WT6 prefix spec intrinsically, without reopening its bundle.

    Qualification uses this boundary while producing/loading its per-workload
    sidecar.  Final bundle verification adds :func:`validate_schema_six_prefix_spec`
    to bind the same bytes back to the exact numeric Walkie-Talkie artifact.
    """

    from .chaff_qualification import (
        MAX_QUALIFIED_CHAFF_STREAMS,
        MAX_STREAM_DATA_EXCESS,
        UDP_PAYLOAD_CEILING,
        _capacity_plan,
        _maximum_receiver_continuation_reserve_horizon,
        selected_chaff_resource,
        selected_navigation_root,
    )
    from .chaff_qualification import (
        SCHEMA_VERSION as LEGACY_PREFIX_SCHEMA_VERSION,
    )

    keys = {
        "schema_version",
        "artifact_type",
        "workload_id",
        "packet_size",
        "source_walkie_talkie_schema_version",
        "numeric_profile_derivation",
        "max_stream_data_excess",
        "maximum_receiver_continuation_reserve_horizon",
        "required_chaff_survivors",
        "numeric_profile_sha256",
        "source_walkie_talkie_artifact_sha256",
        "application_resource_id",
        "selected_chaff_resource_id",
        "selected_chaff_body_bytes",
        "required_chaff_streams",
        "stream_activation_stages",
        "numeric_profile",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError("class-study prefix specification has an invalid exact schema")
    spec = dict(value)
    if (
        spec["schema_version"] != LEGACY_PREFIX_SCHEMA_VERSION + 1
        or spec["artifact_type"] != PREFIX_ARTIFACT_TYPE
        or spec["workload_id"] != workload_id
        or spec["packet_size"] != UDP_PAYLOAD_CEILING
        or spec["source_walkie_talkie_schema_version"] != 6
        or spec["numeric_profile_derivation"]
        != "schema-six-runtime-bursts-verbatim-no-additional-sender-framing"
        or spec["max_stream_data_excess"] != MAX_STREAM_DATA_EXCESS
        or not _digest(spec["numeric_profile_sha256"])
        or not _digest(spec["source_walkie_talkie_artifact_sha256"])
    ):
        raise ValueError("class-study prefix specification binding is invalid")
    numeric = spec["numeric_profile"]
    if not isinstance(numeric, Mapping) or set(numeric) != {"packet_size", "bursts"}:
        raise ValueError("class-study prefix numeric profile has an invalid schema")
    bursts_raw = numeric["bursts"]
    if (
        numeric["packet_size"] != UDP_PAYLOAD_CEILING
        or not isinstance(bursts_raw, list)
        or not bursts_raw
    ):
        raise ValueError("class-study prefix numeric profile is invalid")
    bursts: list[dict[str, int]] = []
    for raw in bursts_raw:
        if not isinstance(raw, Mapping) or set(raw) != {"outgoing", "incoming"}:
            raise ValueError("class-study prefix burst has an invalid schema")
        outgoing, incoming = raw["outgoing"], raw["incoming"]
        if type(outgoing) is not int or type(incoming) is not int or outgoing <= 0 or incoming < 0:
            raise ValueError("class-study prefix burst has invalid cell counts")
        bursts.append({"outgoing": outgoing, "incoming": incoming})
    expected_numeric_hash = sha256_bytes(
        b"qcsd-class-study-walkie-talkie-numeric-profile-v1\0"
        + json.dumps(
            {"packet_size": UDP_PAYLOAD_CEILING, "bursts": bursts},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    horizon = _maximum_receiver_continuation_reserve_horizon(bursts)
    if (
        spec["numeric_profile_sha256"] != expected_numeric_hash
        or type(spec["maximum_receiver_continuation_reserve_horizon"]) is not int
        or spec["maximum_receiver_continuation_reserve_horizon"] != horizon
        or type(spec["required_chaff_survivors"]) is not int
        or spec["required_chaff_survivors"] != horizon + 1
        or not 1 <= spec["required_chaff_survivors"] <= MAX_QUALIFIED_CHAFF_STREAMS
        or type(spec["required_chaff_streams"]) is not int
        or not spec["required_chaff_survivors"]
        <= spec["required_chaff_streams"]
        <= MAX_QUALIFIED_CHAFF_STREAMS
    ):
        raise ValueError("class-study prefix numeric derivation is invalid")
    application = selected_navigation_root(application_manifest, workload_id)
    selected, selected_response = selected_chaff_resource(application_manifest, workload_id)
    if (
        spec["application_resource_id"] != application["id"]
        or spec["selected_chaff_resource_id"] != selected["id"]
        or spec["selected_chaff_body_bytes"] != selected_response["bytes"]
    ):
        raise ValueError("class-study prefix prepared-resource identity is invalid")
    required, stages = _capacity_plan(
        bursts=bursts,
        manifest=application_manifest,
        selected_chaff_body_bytes=selected_response["bytes"],
    )
    if spec["required_chaff_streams"] != required or spec["stream_activation_stages"] != stages:
        raise ValueError("class-study prefix capacity-plan recurrence is invalid")
    return spec


def derive_schema_six_prefix_specs(
    numeric_bundle_root: Path,
    *,
    workload_root: Path,
    artifacts_root: Path,
) -> Path:
    """Create the exact per-workload WT6 prefix-spec directory."""

    verified = verify_numeric_fitting_bundle(numeric_bundle_root)
    workloads = _regular_directory(workload_root, "class-study workload root")
    parent = _regular_directory(artifacts_root, "class fitting artifact root")
    destination = parent / _prefix_directory(verified.stage)
    candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.qcsd-tmp-", dir=parent))
    walkie_path = verified.root / BUNDLE_FILES["walkie_talkie"]
    walkie = load_json(walkie_path)
    try:
        for workload_id in verified.provenance["fitting_contract"]["workload_order"]:
            manifest_path = _regular_file(
                workloads / f"{workload_id}.json", f"workload {workload_id}"
            )
            manifest = load_json(manifest_path)
            validate_class_study_preparation(manifest, workload_id=workload_id)
            spec = build_schema_six_prefix_spec(
                workload_id,
                walkie,
                source_walkie_talkie_artifact_sha256=sha256_file(walkie_path),
                application_manifest=manifest,
            )
            _write_new_json(candidate / f"{workload_id}.json", spec)
        _require_exact_named_files(
            candidate,
            tuple(verified.provenance["fitting_contract"]["workload_order"]),
        )
        _publish_directory(candidate, destination)
        return destination.resolve()
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)


def finalize_fitting_bundle(
    numeric_bundle_root: Path,
    *,
    qualification_manifest_path: Path,
    qualification_context: QualificationContext,
    artifacts_root: Path,
) -> Path:
    """Bind live full qualification and publish the exact four-file runtime bundle."""

    numeric = verify_numeric_fitting_bundle(numeric_bundle_root)
    context = _normalise_qualification_context(qualification_context)
    qualification, bindings = _verify_qualification(
        qualification_manifest_path,
        stage=numeric.stage,
        workload_ids=tuple(numeric.provenance["fitting_contract"]["workload_order"]),
        walkie_talkie_path=numeric.root / BUNDLE_FILES["walkie_talkie"],
        context=context,
    )
    parent = _regular_directory(artifacts_root, "class fitting artifact root")
    destination = parent / _final_directory(numeric.stage)
    candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.qcsd-tmp-", dir=parent))
    try:
        for kind in ("traffic_morphing", "wtf_pad"):
            shutil.copyfile(numeric.root / BUNDLE_FILES[kind], candidate / BUNDLE_FILES[kind])
        walkie = load_json(numeric.root / BUNDLE_FILES["walkie_talkie"])
        if "qualification_bindings" in walkie:
            raise ValueError("numeric Walkie-Talkie artifact already contains qualification bytes")
        walkie["qualification_bindings"] = bindings
        _write_new_json(candidate / BUNDLE_FILES["walkie_talkie"], walkie)
        hashes = {kind: sha256_file(candidate / name) for kind, name in BUNDLE_FILES.items()}
        provenance = _final_provenance(numeric.provenance, qualification, bindings, hashes)
        _write_new_json(candidate / PROVENANCE_FILE, provenance)
        _publish_directory(candidate, destination)
        return verify_class_fitting_bundle(
            destination,
            qualification_context=context,
        ).root
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)


def verify_class_fitting_bundle(
    root: Path,
    *,
    qualification_context: QualificationContext,
    source_result_root: Path | None = None,
    fitting_inputs_loader: Callable[..., ClassFittingInputs] = validate_class_fitting_result,
    fitters: ClassFitters = DEFAULT_FITTERS,
) -> VerifiedClassFittingBundle:
    """Strictly verify a finalized bundle, qualification evidence, and optima."""

    root = _bundle_root(root, FINAL_FILES, "class-study fitting bundle")
    provenance = _load_regular_json(root / PROVENANCE_FILE, "fitting provenance")
    stage = _validate_final_provenance(provenance)
    hashes = _verify_artifact_hashes(root, provenance)
    workload_ids = tuple(provenance["fitting_contract"]["workload_order"])
    artifacts = {kind: load_json(root / filename) for kind, filename in BUNDLE_FILES.items()}
    bindings = artifacts["walkie_talkie"].get("qualification_bindings")
    if bindings != provenance["qualification_inputs"]["qualification_bindings"]:
        raise ValueError("Walkie-Talkie qualification bindings differ from provenance")
    numeric_artifacts = {kind: dict(value) for kind, value in artifacts.items()}
    numeric_artifacts["walkie_talkie"].pop("qualification_bindings")
    _validate_numeric_parameters(numeric_artifacts, workload_ids)
    _validate_runtime_bindings(bindings, workload_ids)
    _validate_selected_optima(provenance["algorithms"], workload_ids)
    _validate_artifact_algorithm_bindings(
        numeric_artifacts,
        provenance["algorithms"],
        provenance["sample_contributions"],
        workload_ids,
    )

    context = _normalise_qualification_context(qualification_context)
    manifest_path = _regular_file(
        context.sidecar_root / "_qualification-set.json",
        "named qualification-set manifest",
    )
    qualification, observed_bindings = _verify_qualification(
        manifest_path,
        stage=stage,
        workload_ids=workload_ids,
        walkie_talkie_path=root / BUNDLE_FILES["walkie_talkie"],
        context=context,
    )
    observed_qualification = {
        **qualification,
        "qualification_bindings": observed_bindings,
    }
    if (
        observed_qualification != provenance["qualification_inputs"]
        or observed_bindings != bindings
    ):
        raise ValueError("finalized bundle differs from current qualification evidence")

    if source_result_root is not None:
        fitting = fitting_inputs_loader(source_result_root, expected_stage=stage)
        _validate_injected_inputs(fitting, stage)
        _require_embedded_fitting_identity(provenance, fitting)
        recomputed = _run_fitters(fitting, fitters)
        for kind, (parameter, receipt) in recomputed.items():
            if canonical_json_bytes(parameter) != canonical_json_bytes(numeric_artifacts[kind]):
                raise ValueError(f"final {kind} differs from independently refitted evidence")
            if canonical_json_bytes(receipt) != canonical_json_bytes(
                provenance["algorithms"][kind]
            ):
                raise ValueError(
                    f"final {kind} receipt differs from independently refitted evidence"
                )
    return VerifiedClassFittingBundle(
        root=root,
        provenance=provenance,
        artifact_hashes=hashes,
        stage=stage,
        parameter_input_policy=_parameter_policy(stage),
    )


def is_class_fitting_artifact_candidate(path: Path) -> bool:
    """Recognise class-study staging/final directories without accepting them."""

    if path.name in {
        PILOT_NUMERIC_DIRECTORY,
        AUTHORITATIVE_NUMERIC_DIRECTORY,
        PILOT_BUNDLE_DIRECTORY,
        AUTHORITATIVE_BUNDLE_DIRECTORY,
    }:
        return True
    if not path.is_dir():
        return False
    names = {entry.name for entry in path.iterdir()}
    return bool(names & (NUMERIC_FILES | FINAL_FILES))


def verify_class_fitting_artifact_root(
    root: Path,
    *,
    qualification_context: QualificationContext | None = None,
    source_result_root: Path | None = None,
) -> VerifiedNumericFittingBundle | VerifiedClassFittingBundle:
    """Dispatch a class-study artifact root by its collision-resistant inventory."""

    names = {entry.name for entry in root.iterdir()} if root.is_dir() else set()
    if names == NUMERIC_FILES:
        return verify_numeric_fitting_bundle(root, source_result_root=source_result_root)
    if names == FINAL_FILES:
        if qualification_context is None:
            raise ValueError(
                "final class-study bundle verification requires qualification evidence"
            )
        return verify_class_fitting_bundle(
            root,
            qualification_context=qualification_context,
            source_result_root=source_result_root,
        )
    raise ValueError("path is not an exact class-study fitting artifact inventory")


def require_successor_fitting_identity(
    provenance: Mapping[str, Any],
    *,
    expected_study_id: str,
    expected_restart_sha256: str,
) -> None:
    """Require one fitting artifact to originate from the exact successor restart."""

    if (
        not isinstance(expected_study_id, str)
        or not expected_study_id.startswith("classifier-multiorigin100-v2-")
        or not _digest(expected_restart_sha256)
    ):
        raise ValueError("expected successor fitting authority is invalid")
    source_result = provenance.get("source_result")
    if (
        not isinstance(source_result, Mapping)
        or source_result.get("study_id") != expected_study_id
        or source_result.get("class_study_successor_sha256") != expected_restart_sha256
    ):
        raise ValueError("class fitting artifact uses predecessor or another successor restart")


def class_research_parameter_record(
    parameter_path: Path,
    provenance_path: Path,
    *,
    expected_kind: str,
    expected_workloads: Sequence[str],
    campaign_evidence_role: str,
    qualification_context: QualificationContext,
    expected_successor_study_id: str | None = None,
    expected_successor_restart_sha256: str | None = None,
) -> tuple[str, str, str]:
    """Return the strict parameter/provenance/policy tuple used by campaign loading."""

    if expected_kind not in BUNDLE_FILES:
        raise ValueError(f"unsupported class-study parameter kind: {expected_kind}")
    parameter = _regular_file(parameter_path, "class-study parameter")
    provenance = _regular_file(provenance_path, "class-study provenance")
    if parameter.parent != provenance.parent or parameter.name != BUNDLE_FILES[expected_kind]:
        raise ValueError("class-study parameters require their complete sibling bundle")
    if provenance.name != PROVENANCE_FILE:
        raise ValueError("class-study provenance filename is not canonical")
    verified = verify_class_fitting_bundle(
        parameter.parent,
        qualification_context=qualification_context,
    )
    if (expected_successor_study_id is None) != (expected_successor_restart_sha256 is None):
        raise ValueError("successor fitting identity requires both study and restart")
    if expected_successor_study_id is not None:
        assert expected_successor_restart_sha256 is not None
        require_successor_fitting_identity(
            verified.provenance,
            expected_study_id=expected_successor_study_id,
            expected_restart_sha256=expected_successor_restart_sha256,
        )
    expected_order = tuple(expected_workloads)
    sealed_order = tuple(verified.provenance["fitting_contract"]["workload_order"])
    if expected_order != sealed_order:
        raise ValueError("campaign workload order differs from the sealed fitting cohort")
    if verified.stage == PILOT_STAGE:
        if campaign_evidence_role != "pilot-compatibility":
            raise ValueError(
                "pilot fitting artifacts are test-only and limited to pilot compatibility"
            )
    elif campaign_evidence_role not in {"certification", "canary", "formal"}:
        raise ValueError("authoritative fitting artifact is not valid for this campaign role")
    return (
        verified.artifact_hashes[expected_kind],
        sha256_file(provenance),
        verified.parameter_input_policy,
    )


def class_fitting_artifact_type(value: object) -> str | None:
    """Return the recognised artifact type for parameter-dispatch code."""

    if not isinstance(value, Mapping):
        return None
    artifact_type = value.get("artifact_type")
    return artifact_type if artifact_type in {NUMERIC_ARTIFACT_TYPE, FINAL_ARTIFACT_TYPE} else None


def _run_fitters(
    fitting: ClassFittingInputs,
    fitters: ClassFitters,
) -> dict[str, tuple[dict[str, object], dict[str, object]]]:
    ordered = tuple(
        trace for workload_id in fitting.workload_ids for trace in fitting.as_defined[workload_id]
    )
    return {
        "traffic_morphing": fitters.traffic_morphing(fitting.as_defined),
        "wtf_pad": fitters.wtf_pad(
            ordered,
            fitted_from=_consumed_corpus_digest(fitting.as_defined, fitting.workload_ids),
        ),
        "walkie_talkie": fitters.walkie_talkie(fitting.half_duplex),
    }


def _numeric_provenance(
    fitting: ClassFittingInputs,
    algorithms: Mapping[str, object],
    artifact_hashes: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": NUMERIC_ARTIFACT_TYPE,
        "status": "numeric-staging-only",
        "runtime_authorized": False,
        "stage": fitting.stage,
        "bundle_name": _numeric_directory(fitting.stage),
        "qcsd_profile": "research-1200",
        "udp_payload_ceiling": 1_200,
        "parameter_input_policy": None,
        "source_result": fitting.source_result,
        "cohort": {
            "role": fitting.stage,
            "receipt_sha256": fitting.cohort_receipt_sha256,
            "receipt": fitting.cohort_receipt,
            "assembly_receipt_sha256": fitting.cohort_assembly_receipt_sha256,
            "assembly_receipt": fitting.cohort_assembly_receipt,
        },
        "fitting_contract": _fitting_contract(fitting),
        "sample_contributions": _sample_contributions(fitting),
        "nontraining_inputs": {
            "qualification_bytes_excluded": True,
            "prefix_specification_bytes_excluded": True,
            "status": "pending",
        },
        "algorithms": dict(algorithms),
        "artifacts": _artifact_receipts(artifact_hashes),
    }


def _final_provenance(
    numeric: Mapping[str, Any],
    qualification: Mapping[str, Any],
    bindings: Sequence[Mapping[str, Any]],
    artifact_hashes: Mapping[str, str],
) -> dict[str, Any]:
    stage = _stage(numeric["stage"])
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": FINAL_ARTIFACT_TYPE,
        "status": ("pilot-test-only" if stage == PILOT_STAGE else "authoritative-fitted-artifact"),
        "runtime_authorized": stage == AUTHORITATIVE_STAGE,
        "stage": stage,
        "bundle_name": _final_directory(stage),
        "qcsd_profile": "research-1200",
        "udp_payload_ceiling": 1_200,
        "parameter_input_policy": _parameter_policy(stage),
        "source_result": numeric["source_result"],
        "cohort": numeric["cohort"],
        "fitting_contract": numeric["fitting_contract"],
        "sample_contributions": numeric["sample_contributions"],
        "qualification_inputs": {**qualification, "qualification_bindings": list(bindings)},
        "algorithms": numeric["algorithms"],
        "artifacts": _artifact_receipts(artifact_hashes),
    }


def _verify_numeric_files(root: Path) -> dict[str, Any]:
    provenance = _load_regular_json(root / NUMERIC_PROVENANCE_FILE, "numeric provenance")
    expected = {
        "schema_version",
        "artifact_type",
        "status",
        "runtime_authorized",
        "stage",
        "bundle_name",
        "qcsd_profile",
        "udp_payload_ceiling",
        "parameter_input_policy",
        "source_result",
        "cohort",
        "fitting_contract",
        "sample_contributions",
        "nontraining_inputs",
        "algorithms",
        "artifacts",
    }
    if set(provenance) != expected:
        raise ValueError("numeric fitting provenance has an invalid exact schema")
    stage = _stage(provenance["stage"])
    if (
        provenance["schema_version"] != SCHEMA_VERSION
        or provenance["artifact_type"] != NUMERIC_ARTIFACT_TYPE
        or provenance["status"] != "numeric-staging-only"
        or provenance["runtime_authorized"] is not False
        or provenance["bundle_name"] != _numeric_directory(stage)
        or provenance["qcsd_profile"] != "research-1200"
        or provenance["udp_payload_ceiling"] != 1_200
        or provenance["parameter_input_policy"] is not None
        or provenance["nontraining_inputs"]
        != {
            "qualification_bytes_excluded": True,
            "prefix_specification_bytes_excluded": True,
            "status": "pending",
        }
    ):
        raise ValueError("numeric fitting provenance makes an invalid authority claim")
    _validate_common_provenance(provenance, stage)
    _verify_artifact_hashes(root, provenance)
    return provenance


def _validate_final_provenance(provenance: Mapping[str, Any]) -> str:
    expected = {
        "schema_version",
        "artifact_type",
        "status",
        "runtime_authorized",
        "stage",
        "bundle_name",
        "qcsd_profile",
        "udp_payload_ceiling",
        "parameter_input_policy",
        "source_result",
        "cohort",
        "fitting_contract",
        "sample_contributions",
        "qualification_inputs",
        "algorithms",
        "artifacts",
    }
    if set(provenance) != expected:
        raise ValueError("final fitting provenance has an invalid exact schema")
    stage = _stage(provenance["stage"])
    if (
        provenance["schema_version"] != SCHEMA_VERSION
        or provenance["artifact_type"] != FINAL_ARTIFACT_TYPE
        or provenance["status"]
        != ("pilot-test-only" if stage == PILOT_STAGE else "authoritative-fitted-artifact")
        or provenance["runtime_authorized"] is not (stage == AUTHORITATIVE_STAGE)
        or provenance["bundle_name"] != _final_directory(stage)
        or provenance["qcsd_profile"] != "research-1200"
        or provenance["udp_payload_ceiling"] != 1_200
        or provenance["parameter_input_policy"] != _parameter_policy(stage)
    ):
        raise ValueError("final fitting provenance authority binding is invalid")
    _validate_common_provenance(provenance, stage)
    qualification = provenance["qualification_inputs"]
    if not isinstance(qualification, Mapping):
        raise TypeError("final fitting provenance has no qualification receipt")
    authority = qualification.get("qualification_authority")
    manifest = qualification.get("qualification_manifest")
    if not isinstance(manifest, Mapping) or manifest.get("qualification_authority") != authority:
        raise ValueError("final fitting provenance qualification authority is inconsistent")
    _validate_qualification_authority(authority)
    _validate_runtime_bindings(
        qualification.get("qualification_bindings"),
        tuple(provenance["fitting_contract"]["workload_order"]),
    )
    return stage


def _validate_common_provenance(provenance: Mapping[str, Any], stage: str) -> None:
    _validate_source_result(provenance.get("source_result"), stage)
    cohort = provenance.get("cohort")
    if not isinstance(cohort, Mapping) or set(cohort) != {
        "role",
        "receipt_sha256",
        "receipt",
        "assembly_receipt_sha256",
        "assembly_receipt",
    }:
        raise ValueError("class fitting cohort receipt has an invalid schema")
    if (
        cohort.get("role") != stage
        or not _digest(cohort.get("receipt_sha256"))
        or not _digest(cohort.get("assembly_receipt_sha256"))
    ):
        raise ValueError("class fitting cohort binding is invalid")
    receipt = cohort.get("receipt")
    if not isinstance(receipt, Mapping):
        raise TypeError("class fitting cohort receipt is missing")
    selection = validate_study_receipt(receipt)
    if sha256_bytes(canonical_json_bytes(receipt)) != cohort["receipt_sha256"]:
        raise ValueError("embedded class fitting cohort hash is invalid")
    assembly = cohort.get("assembly_receipt")
    if not isinstance(assembly, Mapping):
        raise TypeError("class fitting cohort-assembly receipt is missing")
    validate_cohort_assembly_receipt(assembly, cohort=receipt)
    if sha256_bytes(canonical_json_bytes(assembly)) != cohort["assembly_receipt_sha256"]:
        raise ValueError("embedded class fitting cohort-assembly hash is invalid")
    expected_ids = tuple(
        item.candidate_id for item in (selection.pilot if stage == PILOT_STAGE else selection.final)
    )
    contract = provenance.get("fitting_contract")
    if not isinstance(contract, Mapping) or contract != _contract_from_values(stage, expected_ids):
        raise ValueError("class fitting contract differs from the cohort contract")
    contributions = provenance.get("sample_contributions")
    _validate_sample_contributions(contributions, stage, expected_ids)
    algorithms = provenance.get("algorithms")
    if not isinstance(algorithms, Mapping) or set(algorithms) != set(BUNDLE_FILES):
        raise ValueError("class fitting algorithm receipts are incomplete")


def _fitting_contract(fitting: ClassFittingInputs) -> dict[str, Any]:
    return _contract_from_values(fitting.stage, fitting.workload_ids)


def _contract_from_values(stage: str, workload_ids: Sequence[str]) -> dict[str, Any]:
    count, visits, _campaign = _stage_contract(stage)
    if len(workload_ids) != count:
        raise ValueError("class fitting workload count differs from its stage")
    return {
        "contract_version": SCHEMA_VERSION,
        "fitter_version": FITTER_VERSION,
        "study_id": STUDY_ID,
        "stage": stage,
        "profile": "research-1200",
        "request_policies": ["as-defined", "half-duplex"],
        "visits_per_policy": visits,
        "samples_consumed": count * visits * 2,
        "workload_order": list(workload_ids),
        "parameter_schema_versions": {
            "traffic_morphing": 2,
            "wtf_pad": 2,
            "walkie_talkie": 6,
        },
        "numeric_input_policy": "undefended-accepted-eligible-fitting-traces-only",
        "qualification_bytes_excluded": True,
        "prefix_specification_bytes_excluded": True,
    }


def _sample_contributions(fitting: ClassFittingInputs) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for workload_id in fitting.workload_ids:
        policies: dict[str, Any] = {}
        for policy, traces in (
            ("as-defined", fitting.as_defined),
            ("half-duplex", fitting.half_duplex),
        ):
            policies[policy] = [
                {
                    "sample_id": trace.sample_id,
                    "visit": trace.visit,
                    "training_input_sha256": trace.training_input_sha256,
                    "consumed_evidence": dict(trace.consumed_evidence),
                }
                for trace in traces[workload_id]
            ]
        result.append({"workload_id": workload_id, "policies": policies})
    return result


def _validate_sample_contributions(
    value: object,
    stage: str,
    workload_ids: Sequence[str],
) -> None:
    _count, visits, _campaign = _stage_contract(stage)
    if not isinstance(value, list) or len(value) != len(workload_ids):
        raise ValueError("class fitting sample contributions have the wrong count")
    training_hashes: set[str] = set()
    sample_ids: set[str] = set()
    for workload_id, raw in zip(workload_ids, value, strict=True):
        if not isinstance(raw, Mapping) or set(raw) != {"workload_id", "policies"}:
            raise ValueError("class fitting sample contribution schema is invalid")
        if raw["workload_id"] != workload_id or not isinstance(raw["policies"], Mapping):
            raise ValueError("class fitting sample contribution order is invalid")
        if set(raw["policies"]) != {"as-defined", "half-duplex"}:
            raise ValueError("class fitting contribution policies are invalid")
        for policy in ("as-defined", "half-duplex"):
            rows = raw["policies"][policy]
            if not isinstance(rows, list) or len(rows) != visits:
                raise ValueError("class fitting contribution visits are incomplete")
            for visit, row in enumerate(rows):
                if not isinstance(row, Mapping) or set(row) != {
                    "sample_id",
                    "visit",
                    "training_input_sha256",
                    "consumed_evidence",
                }:
                    raise ValueError("class fitting contribution entry schema is invalid")
                if (
                    row["visit"] != visit
                    or not isinstance(row["sample_id"], str)
                    or not _digest(row["training_input_sha256"])
                    or not isinstance(row["consumed_evidence"], Mapping)
                    or any(
                        not isinstance(name, str) or not _digest(digest)
                        for name, digest in row["consumed_evidence"].items()
                    )
                    or row["sample_id"] in sample_ids
                    or row["training_input_sha256"] in training_hashes
                ):
                    raise ValueError("class fitting contribution identity is invalid")
                sample_ids.add(row["sample_id"])
                training_hashes.add(row["training_input_sha256"])


def _validate_numeric_parameters(
    artifacts: Mapping[str, Mapping[str, Any]], workload_ids: Sequence[str]
) -> None:
    if set(artifacts) != set(BUNDLE_FILES):
        raise ValueError("numeric fitting artifacts are incomplete")
    traffic = artifacts["traffic_morphing"]
    wtf = artifacts["wtf_pad"]
    walkie = artifacts["walkie_talkie"]
    if traffic.get("schema_version") != 2 or wtf.get("schema_version") != 2:
        raise ValueError("TM/WTF-PAD runtime parameter schemas must both be two")
    if walkie.get("schema_version") != 6:
        raise ValueError("Walkie-Talkie runtime parameter schema must be six")
    if "qualification_bindings" in walkie:
        raise ValueError("numeric fitting artifact contains live qualification bindings")
    expected = set(workload_ids)
    traffic_profiles = traffic.get("profiles")
    walkie_profiles = walkie.get("profiles")
    if (
        not isinstance(traffic_profiles, list)
        or {profile.get("source") for profile in traffic_profiles if isinstance(profile, Mapping)}
        != expected
    ):
        raise ValueError("Traffic Morphing profiles do not exactly cover the cohort")
    if not isinstance(walkie_profiles, list):
        raise TypeError("Walkie-Talkie profiles are missing")
    covered = [
        identity
        for profile in walkie_profiles
        if isinstance(profile, Mapping)
        for identity in (profile.get("real"), profile.get("decoy"))
    ]
    if len(covered) != len(expected) or set(covered) != expected:
        raise ValueError("Walkie-Talkie profiles do not exactly cover the cohort")
    if wtf.get("adaptation") != "qcsd-client-only" or wtf.get("paper_equivalent") is not False:
        raise ValueError("WTF-PAD runtime parameter adaptation binding is invalid")


def _validate_selected_optima(value: object, workload_ids: Sequence[str]) -> None:
    if not isinstance(value, Mapping):
        raise TypeError("class fitting algorithm receipt must be an object")
    morphing = value.get("traffic_morphing")
    walkie = value.get("walkie_talkie")
    if not isinstance(morphing, Mapping) or not isinstance(walkie, Mapping):
        raise TypeError("class fitting optimizer receipts are missing")
    candidates = morphing.get("candidate_costs")
    selected = morphing.get("selected_mapping")
    expected_edges = len(workload_ids) * (len(workload_ids) - 1)
    if not isinstance(candidates, list) or len(candidates) != expected_edges:
        raise ValueError("Traffic Morphing candidate receipt is incomplete")
    costs: dict[tuple[str, str], _RecordedMorphingCost] = {}
    for row in candidates:
        if not isinstance(row, Mapping) or set(row) != {
            "source",
            "target",
            "l1_cost",
            "estimated_added_bytes",
        }:
            raise ValueError("Traffic Morphing candidate cost schema is invalid")
        edge = (row["source"], row["target"])
        if edge in costs or edge[0] == edge[1]:
            raise ValueError("Traffic Morphing candidate edge is duplicated or self-targeting")
        costs[edge] = _RecordedMorphingCost(
            float(row["l1_cost"]), float(row["estimated_added_bytes"])
        )
    optimum = minimum_cost_derangement(workload_ids, costs)  # type: ignore[arg-type]
    if not isinstance(selected, list) or len(selected) != len(workload_ids):
        raise ValueError("Traffic Morphing selected mapping is incomplete")
    observed_rows: list[Mapping[str, Any]] = []
    candidate_by_edge = {
        (row["source"], row["target"]): row for row in candidates if isinstance(row, Mapping)
    }
    for row in selected:
        if not isinstance(row, Mapping) or set(row) != {
            "source",
            "target",
            "l1_cost",
            "estimated_added_bytes",
        }:
            raise ValueError("Traffic Morphing selected mapping schema is invalid")
        if row != candidate_by_edge.get((row["source"], row["target"])):
            raise ValueError("Traffic Morphing selected costs differ from candidate costs")
        observed_rows.append(row)
    observed = tuple((row["source"], row["target"]) for row in observed_rows)
    if observed != optimum:
        raise ValueError("Traffic Morphing selected mapping is not the exact scalable optimum")

    pair_costs_raw = walkie.get("candidate_pair_costs")
    selected_pairs_raw = walkie.get("selected_pairs")
    expected_pairs = len(workload_ids) * (len(workload_ids) - 1) // 2
    if not isinstance(pair_costs_raw, list) or len(pair_costs_raw) != expected_pairs:
        raise ValueError("Walkie-Talkie candidate-pair receipt is incomplete")
    pair_costs: dict[tuple[str, str], int] = {}
    for row in pair_costs_raw:
        if not isinstance(row, Mapping) or set(row) != {
            "left",
            "right",
            "base_matching_cost_packets",
            "matching_cost_packets",
        }:
            raise ValueError("Walkie-Talkie candidate-pair schema is invalid")
        pair = tuple(sorted((row["left"], row["right"])))
        cost = row["base_matching_cost_packets"]
        if pair in pair_costs or type(cost) is not int or cost < 0:
            raise ValueError("Walkie-Talkie candidate-pair cost is invalid")
        pair_costs[pair] = cost
    optimum_pairs = minimum_weight_perfect_matching_from_costs(workload_ids, pair_costs)
    if not isinstance(selected_pairs_raw, list) or len(selected_pairs_raw) != (
        len(workload_ids) // 2
    ):
        raise ValueError("Walkie-Talkie selected-pair receipt is incomplete")
    candidate_by_pair = {
        (row["left"], row["right"]): row for row in pair_costs_raw if isinstance(row, Mapping)
    }
    observed_pairs_list: list[tuple[str, str, int]] = []
    for row in selected_pairs_raw:
        if not isinstance(row, Mapping) or set(row) != {
            "real",
            "decoy",
            "base_matching_cost_packets",
            "matching_cost_packets",
        }:
            raise ValueError("Walkie-Talkie selected-pair schema is invalid")
        candidate = candidate_by_pair.get((row["real"], row["decoy"]))
        if candidate is None or any(
            row[key] != candidate[key]
            for key in ("base_matching_cost_packets", "matching_cost_packets")
        ):
            raise ValueError("Walkie-Talkie selected costs differ from candidate costs")
        observed_pairs_list.append((row["real"], row["decoy"], row["base_matching_cost_packets"]))
    observed_pairs = tuple(observed_pairs_list)
    if observed_pairs != optimum_pairs:
        raise ValueError("Walkie-Talkie selected pairs are not the exact scalable optimum")


def _validate_artifact_algorithm_bindings(
    artifacts: Mapping[str, Mapping[str, Any]],
    algorithms: Mapping[str, Any],
    contributions: object,
    workload_ids: Sequence[str],
) -> None:
    traffic_profiles = artifacts["traffic_morphing"]["profiles"]
    selected_mapping = algorithms["traffic_morphing"]["selected_mapping"]
    artifact_mapping = tuple((row["source"], row["target"]) for row in traffic_profiles)
    receipt_mapping = tuple((row["source"], row["target"]) for row in selected_mapping)
    if artifact_mapping != receipt_mapping:
        raise ValueError("Traffic Morphing profiles differ from the selected optimum")

    walkie_profiles = artifacts["walkie_talkie"]["profiles"]
    selected_pairs = algorithms["walkie_talkie"]["selected_pairs"]
    artifact_pairs = tuple((row["real"], row["decoy"]) for row in walkie_profiles)
    receipt_pairs = tuple((row["real"], row["decoy"]) for row in selected_pairs)
    if artifact_pairs != receipt_pairs:
        raise ValueError("Walkie-Talkie profiles differ from the selected optimum")

    if not isinstance(contributions, list):
        raise TypeError("class fitting contributions must be a list")
    identity = [
        {
            "workload_id": workload_id,
            "samples": [
                row["training_input_sha256"] for row in contribution["policies"]["as-defined"]
            ],
        }
        for workload_id, contribution in zip(workload_ids, contributions, strict=True)
    ]
    expected_wtf_source = sha256_bytes(
        b"qcsd-class-study-consumed-fitting-corpus-v1\0"
        + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    if artifacts["wtf_pad"].get("fitted_from") != expected_wtf_source:
        raise ValueError("WTF-PAD fitted_from differs from exact as-defined contributions")


def _verify_qualification(
    manifest_path: Path,
    *,
    stage: str,
    workload_ids: tuple[str, ...],
    walkie_talkie_path: Path,
    context: QualificationContext,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = _regular_file(manifest_path, "named qualification-set manifest")
    manifest = load_json(manifest_path)
    if not isinstance(manifest, Mapping) or set(manifest) != _NAMED_SET_KEYS:
        raise ValueError("named qualification-set manifest has an invalid exact schema")
    expected_set = context.expected_qualification_set or (
        PILOT_QUALIFICATION_SET if stage == PILOT_STAGE else AUTHORITATIVE_QUALIFICATION_SET
    )
    if (
        manifest.get("schema_version") != 2
        or manifest.get("artifact_type") != "qcsd-named-chaff-qualification-set"
        or manifest.get("qualification_set") != expected_set
        or manifest.get("qualification_scope") != "full"
        or manifest.get("qualification_sidecar_schema_version") != 2
        or manifest.get("workload_count") != len(workload_ids)
        or manifest.get("workload_ids") != list(workload_ids)
    ):
        raise ValueError("named qualification set differs from the fitting cohort")
    authority = _validate_qualification_authority(manifest.get("qualification_authority"))
    if (
        context.qualification_authority is not None
        and authority != _validate_qualification_authority(context.qualification_authority)
    ):
        raise ValueError("named qualification authority differs from the expected foundation")
    expected_bindings_digest = _named_set_bindings_digest(manifest)
    if manifest.get("bindings_sha256") != expected_bindings_digest:
        raise ValueError("named qualification-set bindings hash is invalid")
    entries = manifest.get("workloads")
    if not isinstance(entries, list) or len(entries) != len(workload_ids):
        raise ValueError("named qualification-set entries are incomplete")

    walkie_path = _regular_file(walkie_talkie_path, "Walkie-Talkie fitting artifact")
    walkie = load_json(walkie_path)
    numeric_walkie = dict(walkie)
    numeric_walkie.pop("qualification_bindings", None)
    source_hash = sha256_bytes(canonical_json_bytes(numeric_walkie))
    bindings: list[dict[str, Any]] = []
    loader = context.loader or _default_qualification_loader
    validator = context.prefix_validator or validate_schema_six_prefix_spec
    for index, (workload_id, raw_entry) in enumerate(zip(workload_ids, entries, strict=True)):
        if not isinstance(raw_entry, Mapping) or set(raw_entry) != _NAMED_ENTRY_KEYS:
            raise ValueError("named qualification-set entry has an invalid schema")
        if raw_entry.get("index") != index or raw_entry.get("workload_id") != workload_id:
            raise ValueError("named qualification-set workload order is invalid")
        workload_path = _bound_file(
            context.workload_root,
            raw_entry.get("workload_manifest"),
            f"qualified workload {workload_id}",
        )
        sidecar_path = _bound_file(
            context.sidecar_root,
            raw_entry.get("qualification_sidecar"),
            f"qualification sidecar {workload_id}",
        )
        sidecar = load_json(sidecar_path)
        if (
            not isinstance(sidecar, Mapping)
            or sidecar.get("qualification_source") != authority["prepare_source"]
            or sidecar.get("qualification_image_digest") != authority["prepare_image_digest"]
        ):
            raise ValueError(
                f"qualification sidecar {workload_id} differs from the authorised prepare build"
            )
        prefix_path = _bound_file(
            context.prefix_spec_root,
            raw_entry.get("prefix_pack_spec"),
            f"prefix specification {workload_id}",
        )
        manifest_value = load_json(workload_path)
        context.preparation_validator(manifest_value, workload_id=workload_id)
        validator(
            load_json(prefix_path),
            workload_id=workload_id,
            walkie_talkie=numeric_walkie,
            source_walkie_talkie_artifact_sha256=source_hash,
            application_manifest=manifest_value,
        )
        qualified = loader(
            sidecar_path,
            workload_id=workload_id,
            base_manifest_path=workload_path,
            prefix_spec_path=prefix_path,
            require_current_implementation=context.require_current_implementation,
        )
        if getattr(qualified, "manifest_sha256", None) != raw_entry["runtime_manifest_sha256"]:
            raise ValueError("qualified runtime manifest hash differs from the named set")
        binding = {
            "workload_id": workload_id,
            "chaff_qualification_sidecar_sha256": qualified.sidecar_sha256,
            "prefix_pack_spec_sha256": sha256_file(prefix_path),
            "qualified_chaff_manifest_sha256": qualified.manifest_sha256,
            "application_resource_id": qualified.application_resource_id,
            "selected_chaff_resource_id": qualified.selected_chaff_resource_id,
            "qualified_parallel_chaff_streams": qualified.qualified_parallel_chaff_streams,
            "walkie_talkie_required_chaff_streams": qualified.walkie_talkie_required_chaff_streams,
        }
        bindings.append(binding)
    _validate_runtime_bindings(bindings, workload_ids)
    return (
        {
            "role": "runtime-qualification-only-excluded-from-numeric-fitting",
            "qualification_bytes_excluded": True,
            "prefix_specification_bytes_excluded": True,
            "qualification_set": expected_set,
            "qualification_manifest_sha256": sha256_file(manifest_path),
            "qualification_manifest": dict(manifest),
            "qualification_authority": authority,
            "qualification_bindings_sha256": canonical_json_sha256(bindings),
        },
        bindings,
    )


def _validate_runtime_bindings(value: object, workload_ids: Sequence[str]) -> None:
    if not isinstance(value, list) or len(value) != len(workload_ids):
        raise ValueError("qualification bindings do not cover the fitting cohort")
    for workload_id, raw in zip(workload_ids, value, strict=True):
        if not isinstance(raw, Mapping) or set(raw) != _RUNTIME_BINDING_KEYS:
            raise ValueError("qualification binding has an invalid exact schema")
        if (
            raw["workload_id"] != workload_id
            or any(
                not _digest(raw[key])
                for key in (
                    "chaff_qualification_sidecar_sha256",
                    "prefix_pack_spec_sha256",
                    "qualified_chaff_manifest_sha256",
                )
            )
            or raw["application_resource_id"] != 0
            or type(raw["selected_chaff_resource_id"]) is not int
            or raw["selected_chaff_resource_id"] < 0
            or type(raw["walkie_talkie_required_chaff_streams"]) is not int
            or not 1 <= raw["walkie_talkie_required_chaff_streams"] <= 20
            or raw["qualified_parallel_chaff_streams"]
            != max(5, raw["walkie_talkie_required_chaff_streams"])
        ):
            raise ValueError("qualification binding values are invalid")


def _default_qualification_loader(sidecar_path: Path, **kwargs: Any) -> Any:
    # The generic qualification layer owns execution-side validation.  Its
    # loader accepts class-study schema-three prefix specs once that stage is
    # wired; keeping the import lazy prevents any dependency cycle.
    from .chaff_qualification import load_qualified_chaff

    return load_qualified_chaff(sidecar_path, **kwargs)


def _normalise_qualification_context(value: QualificationContext) -> QualificationContext:
    if not isinstance(value, QualificationContext):
        raise TypeError("qualification context must be a QualificationContext")
    return replace(
        value,
        workload_root=_regular_directory(value.workload_root, "qualification workload root"),
        sidecar_root=_regular_directory(value.sidecar_root, "qualification sidecar root"),
        prefix_spec_root=_regular_directory(
            value.prefix_spec_root, "qualification prefix-spec root"
        ),
        qualification_authority=(
            _validate_qualification_authority(value.qualification_authority)
            if value.qualification_authority is not None
            else None
        ),
        expected_qualification_set=(
            _qualification_set_identity(value.expected_qualification_set)
            if value.expected_qualification_set is not None
            else None
        ),
    )


def _qualification_set_identity(value: object) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value or value in {".", ".."}:
        raise ValueError("qualification-set identity must be a safe filename")
    return value


def _validate_qualification_authority(value: object) -> dict[str, Any]:
    # Kept lazy because the attestation module imports this fitting verifier.
    from .class_attestation import validate_class_qualification_authority

    return validate_class_qualification_authority(value)


def _source_result_receipt(verified: VerifiedResult) -> dict[str, Any]:
    evidence = _regular_file(verified.root / "evidence.sha256", "fitting evidence seal")
    experiment_sha = verified.checksums.get("experiment.json")
    configuration = verified.experiment["configuration"]
    if not _digest(experiment_sha) or not _digest(configuration.get("campaign_sha256")):
        raise ValueError("verified fitting result lacks source receipt hashes")
    receipt = {
        "campaign": verified.experiment["name"],
        "evidence_sha256": sha256_file(evidence),
        "experiment_sha256": experiment_sha,
        "input_digest": verified.experiment["input_digest"],
        "campaign_sha256": configuration["campaign_sha256"],
        "source_fingerprints": dict(verified.experiment["source"]),
    }
    successor_sha256 = configuration.get("class_study_successor_sha256")
    if successor_sha256 is not None:
        receipt.update(
            study_id=configuration.get("class_study_id"),
            class_study_successor_sha256=successor_sha256,
        )
    return receipt


def _validate_source_result(value: object, stage: str) -> None:
    expected_keys = {
        "campaign",
        "evidence_sha256",
        "experiment_sha256",
        "input_digest",
        "campaign_sha256",
        "source_fingerprints",
    }
    _count, _visits, campaign = _stage_contract(stage)
    if not isinstance(value, Mapping):
        raise ValueError("class fitting source-result receipt has an invalid schema")
    successor_keys = {
        *expected_keys,
        "study_id",
        "class_study_successor_sha256",
    }
    if set(value) == successor_keys:
        study_id = value.get("study_id")
        successor_sha256 = value.get("class_study_successor_sha256")
        if (
            stage != AUTHORITATIVE_STAGE
            or not isinstance(study_id, str)
            or not study_id.startswith("classifier-multiorigin100-v2-")
            or not _digest(successor_sha256)
        ):
            raise ValueError("class fitting source-result successor identity is invalid")
        campaign = f"{study_id}-authoritative-fitting-2000-1200"
    elif set(value) != expected_keys:
        raise ValueError("class fitting source-result receipt has an invalid schema")
    if value["campaign"] != campaign or any(
        not _digest(value[key])
        for key in ("evidence_sha256", "experiment_sha256", "input_digest", "campaign_sha256")
    ):
        raise ValueError("class fitting source-result receipt is invalid")
    _validate_clean_source(value["source_fingerprints"])


def _validate_clean_source(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != SOURCE_METADATA_KEYS:
        raise ValueError("class fitting requires complete source/image provenance")
    image = value.get("image_digest")
    if (
        not isinstance(image, str)
        or not image.startswith("sha256:")
        or not _digest(image.removeprefix("sha256:"))
        or value.get("lab_dirty") is not False
        or value.get("neqo_dirty") is not False
        or value.get("lab_patch_sha256") != EMPTY_SHA256
        or value.get("neqo_patch_sha256") != EMPTY_SHA256
    ):
        raise ValueError("class fitting requires a clean immutable source image")
    for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"):
        if not isinstance(value.get(key), str) or _COMMIT.fullmatch(value[key]) is None:
            raise ValueError(f"class fitting source {key} is invalid")
    if value["neqo_commit"] != value["neqo_pinned_commit"]:
        raise ValueError("class fitting Neqo checkout differs from its pinned submodule")


def _validate_injected_inputs(fitting: ClassFittingInputs, stage: str) -> None:
    if not isinstance(fitting, ClassFittingInputs) or fitting.stage != stage:
        raise ValueError("fitting input loader returned the wrong class-study stage")
    count, visits, _campaign = _stage_contract(stage)
    if len(fitting.workload_ids) != count or fitting.visits_per_policy != visits:
        raise ValueError("fitting input loader returned the wrong cohort dimensions")
    if set(fitting.as_defined) != set(fitting.workload_ids) or set(fitting.half_duplex) != set(
        fitting.workload_ids
    ):
        raise ValueError("fitting input loader returned incomplete policy coverage")
    if any(
        len(mapping[workload_id]) != visits
        for mapping in (fitting.as_defined, fitting.half_duplex)
        for workload_id in fitting.workload_ids
    ):
        raise ValueError("fitting input loader returned incomplete visits")
    validate_study_receipt(fitting.cohort_receipt)
    if sha256_bytes(canonical_json_bytes(fitting.cohort_receipt)) != fitting.cohort_receipt_sha256:
        raise ValueError("fitting input loader returned a mismatched cohort receipt hash")
    validate_cohort_assembly_receipt(
        fitting.cohort_assembly_receipt,
        cohort=fitting.cohort_receipt,
    )
    if (
        sha256_bytes(canonical_json_bytes(fitting.cohort_assembly_receipt))
        != fitting.cohort_assembly_receipt_sha256
    ):
        raise ValueError("fitting input loader returned a mismatched cohort-assembly hash")
    _validate_source_result(fitting.source_result, stage)


def _require_embedded_fitting_identity(
    provenance: Mapping[str, Any], fitting: ClassFittingInputs
) -> None:
    if (
        provenance["source_result"] != fitting.source_result
        or provenance["cohort"]
        != {
            "role": fitting.stage,
            "receipt_sha256": fitting.cohort_receipt_sha256,
            "receipt": fitting.cohort_receipt,
            "assembly_receipt_sha256": fitting.cohort_assembly_receipt_sha256,
            "assembly_receipt": fitting.cohort_assembly_receipt,
        }
        or provenance["fitting_contract"] != _fitting_contract(fitting)
        or provenance["sample_contributions"] != _sample_contributions(fitting)
    ):
        raise ValueError("fitting bundle identity differs from the sealed source result")


def _consumed_corpus_digest(
    traces: Mapping[str, Sequence[FittingTrace]], workload_ids: Sequence[str]
) -> str:
    identity = [
        {
            "workload_id": workload_id,
            "samples": [trace.training_input_sha256 for trace in traces[workload_id]],
        }
        for workload_id in workload_ids
    ]
    return sha256_bytes(
        b"qcsd-class-study-consumed-fitting-corpus-v1\0"
        + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )


def _artifact_receipts(hashes: Mapping[str, str]) -> dict[str, dict[str, str]]:
    if set(hashes) != set(BUNDLE_FILES) or any(not _digest(value) for value in hashes.values()):
        raise ValueError("class fitting artifact hash inventory is invalid")
    return {
        kind: {"path": BUNDLE_FILES[kind], "sha256": hashes[kind]} for kind in sorted(BUNDLE_FILES)
    }


def _verify_artifact_hashes(root: Path, provenance: Mapping[str, Any]) -> dict[str, str]:
    records = provenance.get("artifacts")
    if not isinstance(records, Mapping) or set(records) != set(BUNDLE_FILES):
        raise ValueError("class fitting artifact receipts are incomplete")
    result: dict[str, str] = {}
    for kind, filename in BUNDLE_FILES.items():
        path = _regular_file(root / filename, f"{kind} parameter")
        record = records[kind]
        observed = sha256_file(path)
        if record != {"path": filename, "sha256": observed}:
            raise ValueError(f"class fitting artifact hash mismatch: {filename}")
        result[kind] = observed
    return result


def _named_set_bindings_digest(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "bindings_sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(
        f"qcsd-named-chaff-qualification-set-v{value.get('schema_version')}\0".encode() + encoded
    )


def _bound_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise ValueError(f"{label} receipt has an invalid schema")
    name, digest = value["path"], value["sha256"]
    if not isinstance(name, str) or Path(name).name != name or not _digest(digest):
        raise ValueError(f"{label} receipt is invalid")
    path = _regular_file(root / name, label)
    if sha256_file(path) != digest:
        raise ValueError(f"{label} SHA-256 mismatch")
    return path


def _safe_result_file(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError(f"{label} path is invalid")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"{label} escapes the fitting result")
    return _regular_file(path, label)


def _bundle_root(path: Path, inventory: frozenset[str], label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    root = path.resolve()
    if not root.is_dir() or {entry.name for entry in root.iterdir()} != inventory:
        raise ValueError(f"{label} does not have the exact required inventory")
    if any(entry.is_symlink() or not entry.is_file() for entry in root.iterdir()):
        raise ValueError(f"{label} may contain only regular files")
    return root


def _regular_file(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink() or not absolute.is_file():
        raise ValueError(f"{label} is not a regular file: {absolute}")
    return absolute.resolve()


def _regular_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symbolic link: {current}")
    if not absolute.is_dir():
        raise ValueError(f"{label} must be an existing directory: {absolute}")
    return absolute.resolve()


def _load_regular_json(path: Path, label: str) -> dict[str, Any]:
    value = load_json(_regular_file(path, label))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must contain a JSON object")
    return value


def _write_new_json(path: Path, value: object) -> None:
    encoded = canonical_json_bytes(value)
    with path.open("xb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def _publish_directory(candidate: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"class fitting destination already exists: {destination}")
    _fsync_directory(candidate)
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for create-only publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(candidate), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(f"class fitting destination already exists: {destination}")
        raise OSError(error, os.strerror(error), destination)
    _fsync_directory(destination.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_exact_named_files(root: Path, workload_ids: Sequence[str]) -> None:
    expected = {f"{workload_id}.json" for workload_id in workload_ids}
    if {path.name for path in root.iterdir()} != expected or any(
        path.is_symlink() or not path.is_file() for path in root.iterdir()
    ):
        raise ValueError("prefix-spec directory does not exactly cover the cohort")


def _stage(value: object) -> str:
    if not isinstance(value, str) or value not in STAGES:
        raise ValueError(f"class fitting stage must be one of: {', '.join(sorted(STAGES))}")
    return value


def _stage_contract(stage: str) -> tuple[int, int, str]:
    stage = _stage(stage)
    if stage == PILOT_STAGE:
        return PILOT_COUNT, 2, f"{STUDY_ID}-pilot-fitting-1200"
    return FINAL_CLASS_COUNT, 10, f"{STUDY_ID}-authoritative-fitting-1200"


def _numeric_directory(stage: str) -> str:
    return (
        PILOT_NUMERIC_DIRECTORY if _stage(stage) == PILOT_STAGE else AUTHORITATIVE_NUMERIC_DIRECTORY
    )


def _final_directory(stage: str) -> str:
    return (
        PILOT_BUNDLE_DIRECTORY if _stage(stage) == PILOT_STAGE else AUTHORITATIVE_BUNDLE_DIRECTORY
    )


def _prefix_directory(stage: str) -> str:
    return (
        PILOT_PREFIX_DIRECTORY if _stage(stage) == PILOT_STAGE else AUTHORITATIVE_PREFIX_DIRECTORY
    )


def _parameter_policy(stage: str) -> str:
    return (
        PILOT_PARAMETER_INPUT_POLICY
        if _stage(stage) == PILOT_STAGE
        else AUTHORITATIVE_PARAMETER_INPUT_POLICY
    )


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None
