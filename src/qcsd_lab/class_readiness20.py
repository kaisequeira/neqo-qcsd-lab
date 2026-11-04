"""Prospective 20-site readiness authority, separate from frozen v1 readiness.

The receipt is published only after its final cohort, fitting, qualification,
and certification can be independently reconstructed.  Its verifier repeats
those checks from the bound inputs; a caller-supplied count or digest alone is
never promotion evidence.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import class_attestation, class_fitting
from .class_acquisition import (
    PROVENANCE_TYPE,
    validate_acquisition_completion,
)
from .class_cohort20 import load_validated_profile_cohort
from .class_layout import class_study_layout
from .class_study import (
    CLASS20_STUDY_ID,
    COMPATIBILITY_MODES,
    ClassStudyProfile,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    load_class20_profile_contract,
    validate_hash_bound_receipt,
    write_create_only_json,
)
from .chaff_qualification import QUALIFICATION_RUNS
from .util import LAB_ROOT, load_json, require_disjoint_path, sha256_file, source_metadata
from .verification import verify_result


SCHEMA_VERSION = class_attestation.CLASS20_READINESS_SCHEMA_VERSION
RECEIPT_TYPE = class_attestation.READINESS_RECEIPT_TYPE
IMPLEMENTATION_STATUS = class_attestation.READINESS_IMPLEMENTATION_STATUS
_GATES = (
    "source-pinned-20-site-foundation",
    "deep-qualified-20-site-final-cohort",
    "authoritative-fitting-400-of-400",
    "full-live-final-qualification-120-of-120",
    "first-launch-certification-180-of-180",
)
_EVIDENCE_KEYS = frozenset(
    {
        "foundation",
        "study_profile",
        "candidate_catalogue",
        "stability_root",
        "workload_root",
        "acquisition_completion",
        "pilot_cohort",
        "pilot_cohort_assembly",
        "final_selection",
        "final_cohort",
        "final_cohort_assembly",
        "authoritative_fitting_result",
        "authoritative_numeric_bundle",
        "authoritative_fitting_bundle",
        "qualification_workload_root",
        "qualification_sidecar_root",
        "qualification_prefix_root",
        "qualification_manifest",
        "certification_result",
    }
)


def create_profile_readiness_attestation(
    destination: Path,
    *,
    foundation_attestation: Path,
    cohort_version: int,
    candidate_catalogue: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion: Path,
    pilot_cohort_receipt: Path,
    pilot_cohort_assembly: Path,
    final_selection_receipt: Path,
    final_cohort_receipt: Path,
    final_cohort_assembly: Path,
    authoritative_fitting_result_root: Path,
    authoritative_numeric_bundle_root: Path,
    authoritative_fitting_bundle_root: Path,
    qualification_workload_root: Path,
    qualification_sidecar_root: Path,
    qualification_prefix_root: Path,
    certification_result_root: Path,
) -> Path:
    """Create the source-bound v2 readiness receipt exactly once."""

    inputs = locals().copy()
    destination = require_disjoint_path(
        destination,
        tuple(Path(value) for key, value in inputs.items() if key not in {"destination", "cohort_version"}),
        label="20-site readiness destination",
    )
    payload = _readiness_value(**{key: value for key, value in inputs.items() if key != "destination"})
    output = write_create_only_json(destination, bind_receipt(payload, receipt_type=RECEIPT_TYPE))
    validate_profile_readiness_attestation(output, deep_code_gate=False)
    return output


def validate_profile_readiness_attestation(
    path: Path, *, deep_code_gate: bool = True
) -> dict[str, Any]:
    """Rebuild every prospective readiness field from its original evidence."""

    receipt_path = _regular_file(path, "20-site readiness receipt")
    raw = receipt_path.read_bytes()
    value = _json_object(raw, "20-site readiness receipt")
    if raw != canonical_json_bytes(value):
        raise ValueError("20-site readiness receipt is not canonically encoded")
    payload = validate_hash_bound_receipt(value, expected_type=RECEIPT_TYPE)
    _validate_envelope(payload)
    evidence = payload["evidence"]
    expected = _readiness_value(
        foundation_attestation=_bound_file(evidence["foundation"], "foundation"),
        cohort_version=payload["cohort_version"],
        candidate_catalogue=_bound_file(evidence["candidate_catalogue"], "catalogue"),
        stability_root=_bound_root(evidence["stability_root"], "stability"),
        workload_root=_bound_root(evidence["workload_root"], "workload"),
        acquisition_completion=_bound_file(evidence["acquisition_completion"], "acquisition completion"),
        pilot_cohort_receipt=_bound_file(evidence["pilot_cohort"], "pilot cohort"),
        pilot_cohort_assembly=_bound_file(evidence["pilot_cohort_assembly"], "pilot cohort assembly"),
        final_selection_receipt=_bound_file(evidence["final_selection"], "final selection"),
        final_cohort_receipt=_bound_file(evidence["final_cohort"], "final cohort"),
        final_cohort_assembly=_bound_file(evidence["final_cohort_assembly"], "final cohort assembly"),
        authoritative_fitting_result_root=_bound_result(evidence["authoritative_fitting_result"], "fitting result"),
        authoritative_numeric_bundle_root=_bound_bundle(evidence["authoritative_numeric_bundle"], "numeric bundle"),
        authoritative_fitting_bundle_root=_bound_bundle(evidence["authoritative_fitting_bundle"], "final bundle"),
        qualification_workload_root=_bound_root(evidence["qualification_workload_root"], "qualification workloads"),
        qualification_sidecar_root=_bound_root(evidence["qualification_sidecar_root"], "qualification sidecars"),
        qualification_prefix_root=_bound_root(evidence["qualification_prefix_root"], "qualification prefixes"),
        certification_result_root=_bound_result(evidence["certification_result"], "certification result"),
        deep_code_gate=deep_code_gate,
    )
    if payload != expected:
        raise ValueError("20-site readiness differs from independently reconstructed evidence")
    return {
        "path": str(receipt_path),
        "sha256": sha256_file(receipt_path),
        "payload_sha256": value["payload_sha256"],
        **expected,
    }


def _readiness_value(
    *,
    foundation_attestation: Path,
    cohort_version: int,
    candidate_catalogue: Path,
    stability_root: Path,
    workload_root: Path,
    acquisition_completion: Path,
    pilot_cohort_receipt: Path,
    pilot_cohort_assembly: Path,
    final_selection_receipt: Path,
    final_cohort_receipt: Path,
    final_cohort_assembly: Path,
    authoritative_fitting_result_root: Path,
    authoritative_numeric_bundle_root: Path,
    authoritative_fitting_bundle_root: Path,
    qualification_workload_root: Path,
    qualification_sidecar_root: Path,
    qualification_prefix_root: Path,
    certification_result_root: Path,
    deep_code_gate: bool = True,
) -> dict[str, Any]:
    if type(cohort_version) is not int or cohort_version < 1 or type(deep_code_gate) is not bool:
        raise ValueError("20-site readiness cohort version or deep-code flag is invalid")
    profile = load_class20_profile_contract()
    layout = class_study_layout(profile=profile)
    profile_path = _regular_file(layout.study_config_root / "study.json", "20-site profile")
    profile_sha256 = sha256_file(profile_path)
    catalogue = _regular_file(candidate_catalogue, "candidate catalogue")
    expected_catalogue = _regular_file(
        LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json",
        "registered candidate catalogue",
    )
    if catalogue != expected_catalogue:
        raise ValueError("20-site readiness uses another candidate catalogue")
    source = source_metadata()
    class_attestation._validate_immutable_source(source, label="20-site readiness source")
    foundation_path = _regular_file(foundation_attestation, "foundation")
    foundation = class_attestation.validate_class_foundation_attestation(
        foundation_path, deep_code_gate=deep_code_gate, runtime_role="collection"
    )
    if (
        foundation.get("study_id") != profile.study_id
        or foundation.get("attestation_schema_version")
        != class_attestation.CLASS20_FOUNDATION_SCHEMA_VERSION
        or foundation.get("study_profile_sha256") != profile_sha256
        or foundation.get("cohort_version") != cohort_version
        or foundation.get("source") != source
    ):
        raise ValueError("20-site readiness foundation uses another source or study profile")

    completion_path = _regular_file(acquisition_completion, "acquisition completion")
    completion_value = _json_object(completion_path.read_bytes(), "acquisition completion")
    completion = validate_acquisition_completion(
        completion_value, candidate_catalogue_path=catalogue,
        runner_root=completion_path.parent,
    )
    class_attestation._require_current_acquisition_completion(completion)
    foundation_evidence = foundation.get("evidence")
    build_binding = (
        foundation_evidence.get("build_execution")
        if isinstance(foundation_evidence, Mapping) else None
    )
    build_path = _bound_file(build_binding, "foundation build execution")
    build = class_attestation.validate_build_execution_receipt(
        build_path, expected_collection_image=source["image_digest"],
        expected_cohort_version=cohort_version,
    )
    class_attestation._require_acquisition_toolchain(
        completion.get("observed_toolchain"), source=source, build_receipt=build,
    )
    provenance_path = _regular_file(completion_path.parent / "provenance.json", "acquisition provenance")
    provenance_value = _json_object(provenance_path.read_bytes(), "acquisition provenance")
    provenance = validate_hash_bound_receipt(provenance_value, expected_type=PROVENANCE_TYPE)
    if completion.get("provenance_sha256") != sha256_file(provenance_path):
        raise ValueError("20-site readiness acquisition provenance differs from completion")
    class_attestation._validate_acquisition_foundation_join(
        provenance, foundation=foundation, foundation_attestation=foundation_path
    )

    pilot_path = _regular_file(pilot_cohort_receipt, "pilot cohort")
    pilot_assembly_path = _regular_file(pilot_cohort_assembly, "pilot cohort assembly")
    final_path = _regular_file(final_cohort_receipt, "final cohort")
    final_assembly_path = _regular_file(final_cohort_assembly, "final cohort assembly")
    pilot_ids, premature_final = load_validated_profile_cohort(
        pilot_path, pilot_assembly_path, profile=profile, require_deep=True
    )
    final_pilot_ids, final_ids = load_validated_profile_cohort(
        final_path, final_assembly_path, profile=profile, require_deep=True
    )
    if (
        len(pilot_ids) != profile.pilot_count
        or premature_final
        or final_pilot_ids != pilot_ids
        or len(final_ids) != profile.final_count
        or len(set(final_ids)) != profile.final_count
    ):
        raise ValueError("20-site readiness lacks an exact 30-pilot/20-final cohort")
    final_selection_path = _regular_file(final_selection_receipt, "final selection")
    final_payload = validate_hash_bound_receipt(
        _json_object(final_path.read_bytes(), "final cohort"),
        expected_type="qcsd-class-study-profile-cohort",
    )
    selection_binding = final_payload.get("final_selection")
    if (
        not isinstance(selection_binding, Mapping)
        or selection_binding.get("path") != final_selection_path.relative_to(LAB_ROOT).as_posix()
        or selection_binding.get("sha256") != sha256_file(final_selection_path)
    ):
        raise ValueError("20-site readiness final selection differs from the deep cohort")
    _require_acquisition_cohort_bindings(
        pilot_assembly_path, candidate_catalogue=catalogue,
        stability_root=stability_root, workload_root=workload_root,
        acquisition_completion=completion_path, profile=profile,
    )
    _require_acquisition_cohort_bindings(
        final_assembly_path, candidate_catalogue=catalogue,
        stability_root=stability_root, workload_root=workload_root,
        acquisition_completion=completion_path, profile=profile,
    )

    fit_root = _regular_directory(authoritative_fitting_result_root, "authoritative fitting result")
    numeric_root = _regular_directory(authoritative_numeric_bundle_root, "authoritative numeric bundle")
    final_bundle_root = _regular_directory(authoritative_fitting_bundle_root, "authoritative fitting bundle")
    fitting = class_fitting.validate_class_fitting_result(
        fit_root, expected_stage=class_fitting.AUTHORITATIVE_STAGE,
        study_profile=profile, expected_cohort_receipt_path=final_path,
        expected_cohort_assembly_receipt_path=final_assembly_path,
    )
    fit_samples = fitting.verified.experiment.get("samples")
    if (
        tuple(fitting.workload_ids) != final_ids
        or not isinstance(fit_samples, list)
        or len(fit_samples) != profile.final_count * 10 * 2
    ):
        raise ValueError("20-site authoritative fitting is not exact 400-visit evidence")
    numeric = class_fitting.verify_numeric_fitting_bundle(
        numeric_root, source_result_root=fit_root
    )
    if (
        numeric.stage != class_fitting.AUTHORITATIVE_STAGE
        or numeric.provenance.get("study_id") != profile.study_id
        or numeric.provenance.get("study_profile_sha256") != profile_sha256
        or tuple(numeric.provenance["fitting_contract"]["workload_order"]) != final_ids
    ):
        raise ValueError("20-site numeric fitting uses another study or final cohort")
    qualification_authority = class_attestation.class_qualification_authority(
        foundation_path, deep_code_gate=deep_code_gate, runtime_role="collection"
    )
    context = class_fitting.QualificationContext(
        workload_root=_regular_directory(qualification_workload_root, "qualification workload root"),
        sidecar_root=_regular_directory(qualification_sidecar_root, "qualification sidecar root"),
        prefix_spec_root=_regular_directory(qualification_prefix_root, "qualification prefix root"),
        qualification_authority=qualification_authority,
        expected_qualification_set=layout.final_qualification_set_root.name,
    )
    final_bundle = class_fitting.verify_class_fitting_bundle(
        final_bundle_root, qualification_context=context, source_result_root=fit_root
    )
    qualification = final_bundle.provenance.get("qualification_inputs")
    manifest = qualification.get("qualification_manifest") if isinstance(qualification, Mapping) else None
    bindings = qualification.get("qualification_bindings") if isinstance(qualification, Mapping) else None
    if (
        final_bundle.stage != class_fitting.AUTHORITATIVE_STAGE
        or final_bundle.provenance.get("study_id") != profile.study_id
        or final_bundle.provenance.get("study_profile_sha256") != profile_sha256
        or not isinstance(manifest, Mapping)
        or manifest.get("workload_count") != profile.final_count
        or manifest.get("workload_ids") != list(final_ids)
        or not isinstance(bindings, list)
        or len(bindings) != profile.final_count
        or QUALIFICATION_RUNS != 3
        # The deep sidecar loader verifies three response runs and three
        # prefix-pack runs for every final site.
        or len(bindings) * 2 * QUALIFICATION_RUNS != 120
    ):
        raise ValueError("20-site final fitting lacks 120 full qualification checks")
    manifest_path = _regular_file(context.sidecar_root / "_qualification-set.json", "qualification manifest")
    if qualification.get("qualification_manifest_sha256") != sha256_file(manifest_path):
        raise ValueError("20-site final fitting qualification manifest changed")

    fit_record = _verify_profile_result(
        fit_root, profile=profile, cohort_receipt=final_path,
        cohort_assembly=final_assembly_path, expected_role="authoritative-fitting",
    )
    certification_root = _regular_directory(certification_result_root, "certification result")
    certification = _verify_profile_result(
        certification_root, profile=profile, cohort_receipt=final_path,
        cohort_assembly=final_assembly_path, expected_role="certification",
    )
    _require_result_lineage(
        fit_record, profile=profile, foundation_sha256=sha256_file(foundation_path),
        cohort_sha256=sha256_file(final_path), assembly_sha256=sha256_file(final_assembly_path),
    )
    _require_result_lineage(
        certification, profile=profile, foundation_sha256=sha256_file(foundation_path),
        cohort_sha256=sha256_file(final_path), assembly_sha256=sha256_file(final_assembly_path),
    )
    if fit_record.get("samples") != 400 or fit_record.get("accepted") != 400:
        raise ValueError("20-site authoritative fitting result is not 400/400")
    expected_parameters = {
        "traffic-morphing": final_bundle.artifact_hashes["traffic_morphing"],
        "wtf-pad": final_bundle.artifact_hashes["wtf_pad"],
        "walkie-talkie": final_bundle.artifact_hashes["walkie_talkie"],
    }
    parameters = certification.get("defense_parameter_sha256")
    if (
        certification.get("samples") != profile.final_count * len(COMPATIBILITY_MODES)
        or certification.get("accepted") != profile.final_count * len(COMPATIBILITY_MODES)
        or certification.get("first_launch_unique_class_mode_pairs")
        != profile.final_count * len(COMPATIBILITY_MODES)
        or not isinstance(parameters, Mapping)
        or set(parameters) != {
            "traffic-morphing", "wtf-pad", "walkie-talkie", "buflo", "cs-buflo"
        }
        or any(parameters.get(mode) != digest for mode, digest in expected_parameters.items())
        or certification.get("chaff_qualification_set_manifest_sha256")
        != sha256_file(manifest_path)
        or certification.get("chaff_qualification_set")
        != layout.final_qualification_set_root.name
    ):
        raise ValueError("20-site certification is not exact 180 first-launch visits")
    runtime_inputs = class_attestation._validated_runtime_inputs(
        certification.get("defense_runtime_inputs"),
        expected_modes=COMPATIBILITY_MODES,
        label="20-site certification",
    )
    if any(
        runtime_inputs[mode]["parameters_sha256"] != parameters[mode]
        for mode in expected_parameters
    ):
        raise ValueError("20-site certification runtime and fitted parameters differ")
    verified_results = (verify_result(fit_root), verify_result(certification_root))
    foundation_time = class_attestation._aware_timestamp(
        foundation.get("recorded_at"), label="20-site foundation"
    )
    fitting_start = class_attestation._aware_timestamp(
        verified_results[0].experiment.get("started_at"), label="20-site fitting start"
    )
    fitting_finish = class_attestation._aware_timestamp(
        verified_results[0].experiment.get("completed_at"), label="20-site fitting finish"
    )
    certification_start = class_attestation._aware_timestamp(
        verified_results[1].experiment.get("started_at"), label="20-site certification start"
    )
    certification_finish = class_attestation._aware_timestamp(
        verified_results[1].experiment.get("completed_at"), label="20-site certification finish"
    )
    if not foundation_time <= fitting_start <= fitting_finish <= certification_start <= certification_finish:
        raise ValueError("20-site readiness evidence chronology is invalid")
    environments = []
    from .buflo_study import _validate_result_environment

    for verified in verified_results:
        if verified.experiment.get("source") != source:
            raise ValueError("20-site readiness result uses another source")
        environments.append(_validate_result_environment(verified, source))
    if class_attestation._one_class_build_execution_identity(
        environments, include_completion=True
    ) != foundation.get("build_execution_identity"):
        raise ValueError("20-site readiness results use another no-cache build")

    evidence = {
        "foundation": _file_binding(foundation_path),
        "study_profile": _file_binding(profile_path),
        "candidate_catalogue": _file_binding(catalogue),
        "stability_root": _root_binding(stability_root),
        "workload_root": _root_binding(workload_root),
        "acquisition_completion": _file_binding(completion_path),
        "pilot_cohort": _file_binding(pilot_path),
        "pilot_cohort_assembly": _file_binding(pilot_assembly_path),
        "final_selection": _file_binding(final_selection_path),
        "final_cohort": _file_binding(final_path),
        "final_cohort_assembly": _file_binding(final_assembly_path),
        "authoritative_fitting_result": _result_binding(fit_root),
        "authoritative_numeric_bundle": _bundle_binding(numeric_root, class_fitting.NUMERIC_PROVENANCE_FILE),
        "authoritative_fitting_bundle": _bundle_binding(final_bundle_root, class_fitting.PROVENANCE_FILE),
        "qualification_workload_root": _root_binding(context.workload_root),
        "qualification_sidecar_root": _root_binding(context.sidecar_root),
        "qualification_prefix_root": _root_binding(context.prefix_spec_root),
        "qualification_manifest": _file_binding(manifest_path),
        "certification_result": _result_binding(certification_root),
    }
    gate_evidence = {
        _GATES[0]: [evidence["foundation"]["sha256"], profile_sha256],
        _GATES[1]: [evidence["final_selection"]["sha256"], evidence["final_cohort"]["sha256"], evidence["final_cohort_assembly"]["sha256"]],
        _GATES[2]: [evidence["authoritative_fitting_result"]["evidence_sha256"], evidence["authoritative_numeric_bundle"]["provenance_sha256"]],
        _GATES[3]: [evidence["authoritative_fitting_bundle"]["provenance_sha256"], evidence["qualification_manifest"]["sha256"]],
        _GATES[4]: [evidence["certification_result"]["evidence_sha256"]],
    }
    return {
        "attestation_schema_version": SCHEMA_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "study_id": profile.study_id,
        "study_profile_sha256": profile_sha256,
        "cohort_version": cohort_version,
        "implementation_status": IMPLEMENTATION_STATUS,
        "promotion_authority": False,
        "implementation_scope": class_attestation.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "source": dict(source),
        "build_execution_identity": dict(foundation["build_execution_identity"]),
        "evidence": evidence,
        "summary": {
            "pilot_classes": len(pilot_ids),
            "final_classes": len(final_ids),
            "reserve_classes": profile.reserve_count,
            "authoritative_fitting_samples": 400,
            "final_qualification_executions": 120,
            "certification_samples": 180,
            "certification_unique_first_launch_pairs": 180,
            "fitted_parameter_sha256": expected_parameters,
            "certification_defense_parameter_sha256": dict(parameters),
            "certification_defense_runtime_inputs": runtime_inputs,
            "final_qualification_set_manifest_sha256": sha256_file(manifest_path),
            "qualification_authority_sha256": canonical_json_sha256(qualification_authority),
            "formal_expected_samples": profile.formal_sample_count,
            "canary_expected_samples": profile.final_count * profile.formal_block_count,
        },
        "hard_gates": class_attestation._hard_gate_records(_GATES, gate_evidence),
        "all_readiness_gates_passed": True,
    }


def _verify_profile_result(root: Path, **kwargs: Any) -> Mapping[str, Any]:
    try:
        from .class_profile_result import verify_profile_class_result
    except ImportError as error:
        raise ValueError("20-site readiness awaits deep sealed-result verification") from error
    result = verify_profile_class_result(root, **kwargs)
    if not isinstance(result, Mapping) or result.get("valid") is not True:
        raise ValueError("20-site sealed-result verifier did not admit evidence")
    return result


def _require_result_lineage(
    record: Mapping[str, Any], *, profile: ClassStudyProfile,
    foundation_sha256: str, cohort_sha256: str, assembly_sha256: str,
) -> None:
    if (
        record.get("class_study_id") != profile.study_id
        or record.get("class_study_profile_sha256")
        != sha256_file(class_study_layout(profile=profile).study_config_root / "study.json")
        or record.get("class_study_foundation_sha256") != foundation_sha256
        or record.get("cohort_sha256") != cohort_sha256
        or record.get("cohort_assembly_sha256") != assembly_sha256
    ):
        raise ValueError("20-site result uses another profile, foundation, or cohort")


def _require_acquisition_cohort_bindings(
    assembly_path: Path, *, candidate_catalogue: Path,
    stability_root: Path, workload_root: Path,
    acquisition_completion: Path, profile: ClassStudyProfile,
) -> None:
    payload = validate_hash_bound_receipt(
        _json_object(assembly_path.read_bytes(), "final cohort assembly"),
        expected_type="qcsd-class-study-profile-cohort-assembly",
    )
    expected = {
        "candidate_catalogue": candidate_catalogue,
        "acquisition_completion": acquisition_completion,
    }
    for key, path in expected.items():
        binding = payload.get(key)
        if not isinstance(binding, Mapping) or binding.get("path") != _relative_to_lab(path):
            raise ValueError(f"20-site final cohort {key} uses another input")
        if binding.get("sha256") != sha256_file(path):
            raise ValueError(f"20-site final cohort {key} hash differs")
    for key, path in (("stability_root", stability_root), ("workload_root", workload_root)):
        if payload.get(key) != _relative_to_lab(_regular_directory(path, key)):
            raise ValueError(f"20-site final cohort {key} uses another publication root")
    if payload.get("study_id") != profile.study_id:
        raise ValueError("20-site final cohort assembly has another study identity")


def _validate_envelope(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != {
            "attestation_schema_version", "artifact_type", "study_id",
            "study_profile_sha256", "cohort_version", "implementation_status",
            "promotion_authority", "implementation_scope", "paper_equivalent",
            "no_waivers", "source", "build_execution_identity", "evidence",
            "summary", "hard_gates", "all_readiness_gates_passed",
        }
        or payload.get("attestation_schema_version") != SCHEMA_VERSION
        or payload.get("artifact_type") != RECEIPT_TYPE
        or payload.get("study_id") != CLASS20_STUDY_ID
        or payload.get("implementation_status") != IMPLEMENTATION_STATUS
        or payload.get("promotion_authority") is not False
        or payload.get("implementation_scope") != class_attestation.IMPLEMENTATION_SCOPE
        or payload.get("paper_equivalent") is not False
        or payload.get("no_waivers") is not True
        or payload.get("all_readiness_gates_passed") is not True
        or not isinstance(payload.get("evidence"), Mapping)
        or set(payload["evidence"]) != _EVIDENCE_KEYS
        or payload.get("study_profile_sha256")
        != sha256_file(class_study_layout(profile=load_class20_profile_contract()).study_config_root / "study.json")
    ):
        raise ValueError("20-site readiness envelope is invalid")
    class_attestation._validate_hard_gates(payload.get("hard_gates"), _GATES)


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} is not an object")
    return value


def _regular_file(path: Path, label: str) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{label} is not a regular file: {candidate}")
    return candidate.resolve()


def _regular_directory(path: Path, label: str) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError(f"{label} is not a regular directory: {candidate}")
    return candidate.resolve()


def _relative_to_lab(path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(LAB_ROOT).resolve()).as_posix()
    except ValueError as error:
        raise ValueError("20-site readiness evidence is outside the Lab") from error


def _file_binding(path: Path) -> dict[str, str]:
    source = _regular_file(path, "evidence file")
    return {"path": str(source), "sha256": sha256_file(source)}


def _root_binding(path: Path) -> dict[str, str]:
    return {"root": str(_regular_directory(path, "evidence directory"))}


def _result_binding(path: Path) -> dict[str, str]:
    root = _regular_directory(path, "result")
    return {"root": str(root), "evidence_sha256": sha256_file(_regular_file(root / "evidence.sha256", "result seal"))}


def _bundle_binding(path: Path, provenance_name: str) -> dict[str, str]:
    root = _regular_directory(path, "fitting bundle")
    return {
        "root": str(root),
        "provenance": provenance_name,
        "provenance_sha256": sha256_file(_regular_file(root / provenance_name, "fitting provenance")),
    }


def _bound_file(value: object, label: str) -> Path:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise ValueError(f"20-site readiness {label} binding is invalid")
    path = _regular_file(Path(value["path"]), label)
    if value["sha256"] != sha256_file(path):
        raise ValueError(f"20-site readiness {label} hash changed")
    return path


def _bound_root(value: object, label: str) -> Path:
    if not isinstance(value, Mapping) or set(value) != {"root"}:
        raise ValueError(f"20-site readiness {label} root binding is invalid")
    return _regular_directory(Path(value["root"]), label)


def _bound_result(value: object, label: str) -> Path:
    if not isinstance(value, Mapping) or set(value) != {"root", "evidence_sha256"}:
        raise ValueError(f"20-site readiness {label} result binding is invalid")
    root = _regular_directory(Path(value["root"]), label)
    if value["evidence_sha256"] != sha256_file(_regular_file(root / "evidence.sha256", label)):
        raise ValueError(f"20-site readiness {label} result seal changed")
    return root


def _bound_bundle(value: object, label: str) -> Path:
    if not isinstance(value, Mapping) or set(value) != {"root", "provenance", "provenance_sha256"}:
        raise ValueError(f"20-site readiness {label} bundle binding is invalid")
    if value["provenance"] not in {
        class_fitting.PROVENANCE_FILE, class_fitting.NUMERIC_PROVENANCE_FILE
    }:
        raise ValueError(f"20-site readiness {label} provenance is invalid")
    root = _regular_directory(Path(value["root"]), label)
    if value["provenance_sha256"] != sha256_file(_regular_file(root / value["provenance"], label)):
        raise ValueError(f"20-site readiness {label} provenance changed")
    return root
