"""Deep sealed-result verification for the prospective 20-site class study.

The 100-site result contract remains in :mod:`class_pipeline`.  This boundary
uses the ordinary sealed/frozen-campaign verifier, then reapplies the 20-site
cohort and per-run scientific checks before returning a readiness record.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .chaff_qualification import NAMED_QUALIFICATION_SET_MANIFEST
from .class_layout import class_study_layout
from .class_study import (
    CLASS20_PROFILE,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    ClassStudyProfile,
    _CLASS20_OVERLAY_SHA256,
    load_class20_profile_contract,
    parse_class_study_campaign_name,
)
from .util import load_json, sha256_file
from .verification import VerifiedResult, verify_result


_PROFILE_ROLES = frozenset(
    {"pilot-fitting", "authoritative-fitting", "certification", "canary", "formal"}
)
_CURRENT_CANDIDATE_MODES = frozenset({"buflo", "cs-buflo"})


def verify_profile_class_result(
    root: Path,
    *,
    profile: ClassStudyProfile,
    cohort_receipt: Path,
    cohort_assembly: Path,
    expected_role: str,
    expected_block: int | None = None,
) -> dict[str, Any]:
    """Verify a complete v2 result and every accepted run before granting credit.

    ``verify_result`` reconstructs the frozen campaign and all planned sample
    identities, validates the sealed file inventory, and checks accepted and
    durable attempt evidence.  Fitting additionally replays all fitting
    traces.  Every other role reopens each accepted run, checks its admitted
    workload graph and defence fidelity, and applies the current BuFLO receipt
    chronology checks where relevant.
    """

    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("20-site result requires the exact registered study profile")
    if expected_role not in _PROFILE_ROLES:
        raise ValueError("20-site result evidence role is not registered")
    if expected_block is not None and (
        expected_role not in {"canary", "formal"}
        or type(expected_block) is not int
        or not 1 <= expected_block <= profile.formal_block_count
    ):
        raise ValueError("20-site result expected block is invalid")

    # This is deliberately the first result read; hashes or experiment fields
    # alone cannot establish that the individual captures are valid.
    verified = verify_result(root)
    experiment = verified.experiment
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("20-site result has no frozen configuration")
    name = experiment.get("name")
    if not isinstance(name, str):
        raise ValueError("20-site result has no canonical campaign name")
    identity = parse_class_study_campaign_name(name)
    if (
        identity.study_id != profile.study_id
        or identity.evidence_role != expected_role
        or configuration.get("class_study_id") != profile.study_id
        or configuration.get("class_study_profile_sha256") != _CLASS20_OVERLAY_SHA256
        or configuration.get("evidence_role") != expected_role
    ):
        raise ValueError("20-site result identity or source profile differs")
    block = identity.block
    if block != expected_block and expected_block is not None:
        raise ValueError("20-site result has the wrong formal block")
    if expected_role not in {"canary", "formal"} and block is not None:
        raise ValueError("20-site non-block result has a block number")
    if (
        experiment.get("status") != "complete"
        or not isinstance(experiment.get("summary"), Mapping)
        or experiment["summary"].get("passed") is not True
    ):
        raise ValueError("20-site result is not complete and passed")

    from .class_cohort20 import load_validated_profile_cohort
    from .class_fitting import _profile_cohort_workload_hashes
    from .class_pipeline import (
        CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY,
        CLASS_STUDY_FOUNDATION_INPUT,
        CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY,
        CLASS_STUDY_HISTORICAL_PRE_INPUT,
        CLASS_STUDY_LAUNCH_INPUT,
        CLASS_STUDY_READINESS_CONFIGURATION_KEY,
        CLASS_STUDY_READINESS_INPUT,
        _defense_runtime_input_identities,
        _forbid_sealed_configuration_input,
        _sealed_configuration_input,
    )

    cohort_path = _regular_file(cohort_receipt, "20-site cohort receipt")
    assembly_path = _regular_file(cohort_assembly, "20-site cohort assembly")
    pilot_ids, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=False
    )
    pilot_role = expected_role == "pilot-fitting"
    selected_ids = pilot_ids if pilot_role else final_ids
    expected_site_count = profile.pilot_count if pilot_role else profile.final_count
    if len(selected_ids) != expected_site_count:
        raise ValueError("20-site result cohort has the wrong stage or site count")
    cohort_sha256 = sha256_file(cohort_path)
    assembly_sha256 = sha256_file(assembly_path)
    for label, filename, digest in (
        ("cohort", "class-study-cohort.json", cohort_sha256),
        ("cohort assembly", "class-study-cohort-assembly.json", assembly_sha256),
    ):
        frozen = _regular_file(verified.root / "inputs" / filename, f"frozen {label}")
        if sha256_file(frozen) != digest or verified.checksums.get(f"inputs/{filename}") != digest:
            raise ValueError(f"20-site result is bound to another {label}")
    if (
        configuration.get("class_study_cohort_sha256") != cohort_sha256
        or configuration.get("class_study_cohort_assembly_sha256") != assembly_sha256
    ):
        raise ValueError("20-site result cohort configuration differs")

    workload_records = configuration.get("workloads")
    if (
        not isinstance(workload_records, list)
        or len(workload_records) != expected_site_count
        or any(not isinstance(record, Mapping) for record in workload_records)
        or tuple(record.get("id") for record in workload_records) != selected_ids
    ):
        raise ValueError("20-site result workload order differs from its cohort")
    admitted_hashes = _profile_cohort_workload_hashes(load_json(assembly_path), selected_ids)
    if any(
        record.get("sha256") != admitted_hashes[record["id"]]
        for record in workload_records
    ):
        raise ValueError("20-site result prepared workloads differ from cohort evidence")

    launch_sha256 = _sealed_configuration_input(
        verified,
        relative=CLASS_STUDY_LAUNCH_INPUT,
        configuration_key="class_study_launch_sha256",
        label="20-site first-launch claim",
    )
    foundation_sha256 = _sealed_configuration_input(
        verified,
        relative=CLASS_STUDY_FOUNDATION_INPUT,
        configuration_key=CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY,
        label="20-site foundation",
    )
    if expected_role in {"canary", "formal"}:
        readiness_sha256 = _sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_READINESS_INPUT,
            configuration_key=CLASS_STUDY_READINESS_CONFIGURATION_KEY,
            label="20-site readiness",
        )
        historical_pre_sha256 = _sealed_configuration_input(
            verified,
            relative=CLASS_STUDY_HISTORICAL_PRE_INPUT,
            configuration_key=CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY,
            label="20-site historical pre snapshot",
        )
    else:
        for relative, key, label in (
            (CLASS_STUDY_READINESS_INPUT, CLASS_STUDY_READINESS_CONFIGURATION_KEY, "readiness"),
            (CLASS_STUDY_HISTORICAL_PRE_INPUT, CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY, "historical pre snapshot"),
        ):
            _forbid_sealed_configuration_input(
                verified, relative=relative, configuration_key=key,
                label=f"20-site {label}",
            )
        readiness_sha256 = historical_pre_sha256 = None

    if expected_role in {"pilot-fitting", "authoritative-fitting"}:
        from .class_fitting import validate_class_fitting_result

        stage = "pilot" if pilot_role else "authoritative"
        fitting = validate_class_fitting_result(
            verified.root,
            expected_stage=stage,
            study_profile=profile,
            expected_cohort_receipt_path=cohort_path,
            expected_cohort_assembly_receipt_path=assembly_path,
            result_verifier=lambda _root: verified,
        )
        sample_count = len(fitting.verified.experiment["samples"])
        required_count = expected_site_count * (2 if pilot_role else 10) * 2
        if sample_count != required_count or len(verified.accepted_samples) != required_count:
            raise ValueError("20-site fitting result has the wrong accepted cross-product")
        unique_class_mode_pairs = None
    else:
        sample_count, unique_class_mode_pairs = _validate_profile_non_fitting_samples(
            verified, role=expected_role, selected_ids=selected_ids,
            visits_per_formal_block=profile.formal_visits_per_block,
        )

    expected_set = (
        class_study_layout(profile=profile).final_qualification_set_root.name
        if expected_role in {"certification", "formal"} else None
    )
    qualification_manifest_sha256: str | None = None
    if expected_set is None:
        if (
            "chaff_qualification_set" in configuration
            or "chaff_qualification_set_manifest_sha256" in configuration
        ):
            raise ValueError("20-site result unexpectedly uses a qualification set")
    else:
        if configuration.get("chaff_qualification_set") != expected_set:
            raise ValueError("20-site result uses another qualification set")
        qualification_manifest_sha256 = _sealed_configuration_input(
            verified,
            relative=f"inputs/chaff-qualifications/{NAMED_QUALIFICATION_SET_MANIFEST}",
            configuration_key="chaff_qualification_set_manifest_sha256",
            label="20-site final qualification set",
        )

    evidence_path = _regular_file(verified.root / "evidence.sha256", "20-site evidence seal")
    experiment_sha256 = verified.checksums.get("experiment.json")
    if not isinstance(experiment_sha256, str):
        raise ValueError("20-site evidence seal does not bind experiment.json")
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
        "evidence_role": expected_role,
        "block": block,
        "samples": sample_count,
        "accepted": len(verified.accepted_samples),
        "cohort_sha256": cohort_sha256,
        "cohort_assembly_sha256": assembly_sha256,
        "evidence_sha256": sha256_file(evidence_path),
        "experiment_sha256": experiment_sha256,
        "class_study_id": profile.study_id,
        "class_study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "class_study_launch_sha256": launch_sha256,
        "class_study_foundation_sha256": foundation_sha256,
        "class_study_readiness_sha256": readiness_sha256,
        "class_study_historical_pre_snapshot_sha256": historical_pre_sha256,
        "class_study_successor_sha256": None,
        "unique_class_mode_pairs": unique_class_mode_pairs,
        "first_launch_unique_class_mode_pairs": (
            unique_class_mode_pairs if expected_role == "certification" else None
        ),
        "defense_parameter_sha256": defense_parameter_sha256,
        "defense_runtime_inputs": defense_runtime_inputs,
        "chaff_qualification_set": expected_set,
        "chaff_qualification_set_manifest_sha256": qualification_manifest_sha256,
    }


def _validate_profile_non_fitting_samples(
    verified: VerifiedResult,
    *,
    role: str,
    selected_ids: Sequence[str],
    visits_per_formal_block: int,
) -> tuple[int, int | None]:
    """Replay the exact v2 cross-product and existing deep per-run validators."""

    if role not in {"certification", "canary", "formal"}:
        raise ValueError("20-site non-fitting result role is invalid")
    from .class_pipeline import (
        _validate_class_sample_run_receipt,
        _validate_current_candidate_sample_receipt,
    )

    configuration = verified.experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("20-site result has no frozen configuration")
    modes = (
        ("undefended",) if role == "canary"
        else FORMAL_MODES if role == "formal" else COMPATIBILITY_MODES
    )
    defenses = configuration.get("defenses")
    if (
        not isinstance(defenses, list)
        or any(not isinstance(defense, Mapping) for defense in defenses)
        or tuple(defense.get("name") for defense in defenses) != modes
        or configuration.get("request_policies") != ["as-defined"]
    ):
        raise ValueError("20-site result defense or request-policy matrix differs")
    visits = visits_per_formal_block if role == "formal" else 1
    expected = {
        (site, mode, visit)
        for site in selected_ids for mode in modes for visit in range(visits)
    }
    samples = verified.experiment.get("samples")
    if (
        not isinstance(samples, list)
        or len(samples) != len(expected)
        or len(verified.accepted_samples) != len(expected)
    ):
        raise ValueError("20-site result has the wrong accepted sample count")
    observed: set[tuple[str, str, int]] = set()
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise ValueError("20-site result sample is malformed")
        site, mode, visit = (
            sample.get("workload_id"), sample.get("defense"), sample.get("visit")
        )
        if not isinstance(site, str) or not isinstance(mode, str) or type(visit) is not int:
            raise ValueError("20-site result sample identity is malformed")
        identity = (site, mode, visit)
        if identity not in expected or identity in observed:
            raise ValueError("20-site result is not the exact site/mode/visit cross-product")
        if (
            sample.get("state") != "accepted"
            or sample.get("eligible") is not True
            or sample.get("request_policy") != "as-defined"
            or type(sample.get("attempts")) is not int
            or not 1 <= sample["attempts"] <= (1 if role == "certification" else 3)
        ):
            raise ValueError("20-site result has an ineligible or invalid attempt")
        _validate_class_sample_run_receipt(verified, sample, role=role)
        if sample["defense"] in _CURRENT_CANDIDATE_MODES:
            _validate_current_candidate_sample_receipt(verified, sample, role=role)
        observed.add(identity)
    if observed != expected:
        raise ValueError("20-site result has a missing site/mode/visit sample")
    unique_pairs = len({(site, mode) for site, mode, _visit in observed})
    return len(samples), unique_pairs if role == "certification" else None


def _regular_file(path: Path, label: str) -> Path:
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file: {path}")
    return path
