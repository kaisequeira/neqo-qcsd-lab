"""Deep, read-only launch prerequisites for 20-site canary/formal capture."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from . import class_attestation, class_fitting
from .buflo_study import _validate_result_environment
from .class_campaigns import validate_campaign_document
from .class_cohort20 import load_validated_profile_cohort
from .class_layout import class_study_layout, require_canonical_fresh_child
from .class_profile_result import verify_profile_class_result
from .class_study import (
    CLASS20_PROFILE,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    ClassStudyProfile,
    load_class20_profile_contract,
    parse_class_study_campaign_name,
)
from .util import load_json, sha256_file, source_metadata
from .verification import verify_result


def verify_profile_initial_capture_prerequisites(
    *,
    campaign_path: Path,
    cohort_receipt: Path,
    cohort_assembly: Path,
    prerequisite_roots: Sequence[Path],
    foundation_attestation: Path,
    pilot_cohort_receipt: Path | None = None,
    pilot_cohort_assembly: Path | None = None,
    numeric_bundle_root: Path | None = None,
    final_bundle_root: Path | None = None,
    qualification_workload_root: Path | None = None,
    qualification_sidecar_root: Path | None = None,
    qualification_prefix_root: Path | None = None,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> dict[str, Any]:
    """Deeply admit one v2 fitting or certification launch without promotion receipts."""

    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("20-site capture requires its source-pinned profile")
    layout = class_study_layout(profile=profile)
    campaign = _regular_file(campaign_path, "20-site campaign")
    if campaign.parent != layout.campaign_root or campaign.suffix != ".yml":
        raise ValueError("20-site capture campaign path is not canonical")
    document = yaml.safe_load(campaign.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("20-site capture campaign is not an object")
    identity = parse_class_study_campaign_name(document.get("name"))
    role = identity.evidence_role
    if (
        identity.study_id != profile.study_id
        or role not in {"pilot-fitting", "authoritative-fitting", "certification"}
        or identity.block is not None
        or campaign.name != f"{identity.name}.yml"
        or document.get("evidence_role") != role
    ):
        raise ValueError("20-site initial capture role or campaign identity is invalid")
    require_canonical_fresh_child(
        campaign, field="campaign_root", filename=campaign.name, profile=profile,
    )
    pilot_role = role == "pilot-fitting"
    cohort = _regular_file(require_canonical_fresh_child(
        cohort_receipt, field="study_config_root",
        filename=(f"{profile.study_id}-pilot-cohort.json" if pilot_role
                  else f"{profile.study_id}-cohort.json"), profile=profile,
    ), "20-site capture cohort")
    assembly = _regular_file(require_canonical_fresh_child(
        cohort_assembly, field="study_config_root",
        filename=(f"{profile.study_id}-pilot-cohort-assembly.json" if pilot_role
                  else f"{profile.study_id}-cohort-assembly.json"), profile=profile,
    ), "20-site capture assembly")
    pilot_ids, final_ids = load_validated_profile_cohort(
        cohort, assembly, profile=profile, require_deep=True,
    )
    if (
        len(pilot_ids) != profile.pilot_count
        or len(final_ids) != (0 if pilot_role else profile.final_count)
    ):
        raise ValueError("20-site initial capture uses another cohort stage")
    validate_campaign_document(
        document, cohort_receipt=cohort,
        cohort_assembly_receipt=assembly, profile=profile,
    )
    foundation_path = _regular_file(foundation_attestation, "20-site foundation")
    foundation = class_attestation.validate_class_foundation_attestation(
        foundation_path, deep_code_gate=True, runtime_role="collection",
    )
    source = source_metadata()
    class_attestation._validate_immutable_source(source, label="20-site capture source")
    profile_sha = sha256_file(layout.study_config_root / "study.json")
    foundation_sha = sha256_file(foundation_path)
    if (
        foundation.get("study_id") != profile.study_id
        or foundation.get("attestation_schema_version")
        != class_attestation.CLASS20_FOUNDATION_SCHEMA_VERSION
        or foundation.get("study_profile_sha256") != profile_sha
        or foundation.get("source") != source
    ):
        raise ValueError("20-site initial capture uses another foundation source or profile")

    expected_prior = () if pilot_role else (
        (("pilot-fitting", pilot_cohort_receipt, pilot_cohort_assembly, 120),)
        if role == "authoritative-fitting" else
        (("authoritative-fitting", cohort, assembly, 400),)
    )
    if len(prerequisite_roots) != len(expected_prior):
        raise ValueError("20-site initial capture has the wrong preceding result ledger")
    ledger: list[dict[str, Any]] = []
    prior_finish = _aware_time(foundation.get("recorded_at"), "foundation")
    prior_root: Path | None = None
    for raw, (prior_role, prior_cohort, prior_assembly, expected_samples) in zip(
        prerequisite_roots, expected_prior, strict=True,
    ):
        prior_root = _regular_directory(raw, "20-site preceding result")
        if prior_cohort is None or prior_assembly is None:
            raise ValueError("20-site authoritative fitting requires its pilot cohort")
        if prior_role == "pilot-fitting":
            prior_cohort = _regular_file(require_canonical_fresh_child(
                prior_cohort, field="study_config_root",
                filename=f"{profile.study_id}-pilot-cohort.json", profile=profile,
            ), "20-site pilot cohort")
            prior_assembly = _regular_file(require_canonical_fresh_child(
                prior_assembly, field="study_config_root",
                filename=f"{profile.study_id}-pilot-cohort-assembly.json", profile=profile,
            ), "20-site pilot assembly")
            old_pilot, old_final = load_validated_profile_cohort(
                prior_cohort, prior_assembly, profile=profile, require_deep=True,
            )
            if old_pilot != pilot_ids or old_final:
                raise ValueError("20-site selected final cohort changed its pilot inventory")
        record = verify_profile_class_result(
            prior_root, profile=profile, cohort_receipt=prior_cohort,
            cohort_assembly=prior_assembly, expected_role=prior_role,
        )
        if (
            record.get("valid") is not True
            or record.get("class_study_id") != profile.study_id
            or record.get("class_study_profile_sha256") != profile_sha
            or record.get("class_study_foundation_sha256") != foundation_sha
            or record.get("cohort_sha256") != sha256_file(prior_cohort)
            or record.get("cohort_assembly_sha256") != sha256_file(prior_assembly)
            or record.get("samples") != expected_samples
            or record.get("accepted") != expected_samples
        ):
            raise ValueError("20-site initial capture predecessor differs from its authorities")
        experiment = load_json(_regular_file(prior_root / "experiment.json", "preceding experiment"))
        if not isinstance(experiment, Mapping) or experiment.get("source") != source:
            raise ValueError("20-site initial capture predecessor uses another source")
        environment = _validate_result_environment(verify_result(prior_root), source)
        if class_attestation._one_class_build_execution_identity(
            [environment], include_completion=True
        ) != foundation.get("build_execution_identity"):
            raise ValueError("20-site initial capture predecessor uses another no-cache build")
        started = _aware_time(experiment.get("started_at"), "preceding start")
        finished = _aware_time(experiment.get("completed_at"), "preceding completion")
        if started < prior_finish or finished <= started:
            raise ValueError("20-site initial capture predecessor chronology is invalid")
        prior_finish = finished
        ledger.append(dict(record))

    generation = None
    expected_runtime = {
        "undefended": {"identity_type": "source-bound-no-defense", "runtime_kind": "none"}
    }
    qualification_sha: str | None = None
    if role == "certification":
        assert prior_root is not None
        from .orchestrator import verify_class_study_fitting_generation
        from .class_attestation import class_qualification_authority
        from .chaff_qualification import QUALIFICATION_RUNS

        numeric_root = _regular_directory(numeric_bundle_root, "20-site numeric bundle")
        final_root = _regular_directory(final_bundle_root, "20-site final fitting bundle")
        workload_root = _regular_directory(
            qualification_workload_root, "20-site qualification workloads"
        )
        sidecar_root = _regular_directory(
            qualification_sidecar_root, "20-site qualification sidecars"
        )
        prefix_root = _regular_directory(
            qualification_prefix_root, "20-site qualification prefixes"
        )
        if (
            numeric_root != layout.authoritative_numeric_root
            or final_root != layout.authoritative_final_root
            or workload_root != layout.workload_root
            or sidecar_root != layout.final_qualification_set_root
            or prefix_root != layout.final_qualification_set_root / "_prefix-specs"
        ):
            raise ValueError("20-site certification uses noncanonical fitting or qualification roots")
        numeric = class_fitting.verify_numeric_fitting_bundle(
            numeric_root, source_result_root=prior_root,
        )
        if (
            numeric.stage != class_fitting.AUTHORITATIVE_STAGE
            or numeric.provenance.get("study_id") != profile.study_id
            or numeric.provenance.get("study_profile_sha256") != profile_sha
            or tuple(numeric.provenance["fitting_contract"]["workload_order"]) != final_ids
        ):
            raise ValueError("20-site certification numeric fitting differs from final cohort")
        qualification_authority = class_qualification_authority(
            foundation_path, deep_code_gate=True, runtime_role="collection",
        )
        context = class_fitting.QualificationContext(
            workload_root=workload_root, sidecar_root=sidecar_root,
            prefix_spec_root=prefix_root,
            qualification_authority=qualification_authority,
            expected_qualification_set=layout.final_qualification_set_root.name,
        )
        fitted = class_fitting.verify_class_fitting_bundle(
            final_root, qualification_context=context, source_result_root=prior_root,
        )
        qualification = fitted.provenance.get("qualification_inputs")
        manifest = qualification.get("qualification_manifest") if isinstance(qualification, Mapping) else None
        bindings = qualification.get("qualification_bindings") if isinstance(qualification, Mapping) else None
        manifest_path = _regular_file(sidecar_root / "_qualification-set.json", "qualification manifest")
        qualification_sha = sha256_file(manifest_path)
        if (
            fitted.stage != class_fitting.AUTHORITATIVE_STAGE
            or fitted.provenance.get("study_id") != profile.study_id
            or fitted.provenance.get("study_profile_sha256") != profile_sha
            or not isinstance(manifest, Mapping)
            or manifest.get("workload_count") != profile.final_count
            or manifest.get("workload_ids") != list(final_ids)
            or not isinstance(bindings, list)
            or len(bindings) != profile.final_count
            or QUALIFICATION_RUNS != 3
            or len(bindings) * 2 * QUALIFICATION_RUNS != 120
            or qualification.get("qualification_manifest_sha256") != qualification_sha
        ):
            raise ValueError("20-site certification lacks exact 120 full qualification checks")
        generation = verify_class_study_fitting_generation(
            source_result_root=prior_root,
            campaign_path=campaign,
            expected_qualification_authority=qualification_authority,
        )
        if (
            generation.get("evidence_role") != "certification"
            or generation.get("source_result", {}).get("root") != str(prior_root)
            or generation.get("source_result", {}).get("evidence_sha256")
            != ledger[0].get("evidence_sha256")
        ):
            raise ValueError("20-site certification fitting generation uses another result")
        expected_runtime = generation["capture_runtime"]["defense_runtime_inputs"]
        if set(expected_runtime) != set(COMPATIBILITY_MODES):
            raise ValueError("20-site certification runtime does not cover nine modes")

    planned = (
        profile.pilot_count * 2 * 2 if pilot_role
        else profile.final_count * 10 * 2 if role == "authoritative-fitting"
        else profile.final_count * len(COMPATIBILITY_MODES)
    )
    return {
        "valid": True,
        "campaign_path": str(campaign),
        "campaign_sha256": sha256_file(campaign),
        "campaign_name": identity.name,
        "evidence_role": role,
        "block": None,
        "planned_samples": planned,
        "cohort_sha256": sha256_file(cohort),
        "cohort_assembly_sha256": sha256_file(assembly),
        "foundation_sha256": foundation_sha,
        "foundation_recorded_at": foundation["recorded_at"],
        "readiness_sha256": None,
        "historical_pre_snapshot_sha256": None,
        "source": dict(source),
        "expected_defense_runtime_inputs": expected_runtime,
        "qualification_manifest_sha256": qualification_sha,
        "prerequisite_ledger": tuple(ledger),
        "fitting_generation": generation,
        "required_environment": {
            "QCSD_CLASS_FOUNDATION_ATTESTATION": str(foundation_path),
        },
    }


def verify_profile_capture_prerequisites(
    *,
    campaign_path: Path,
    final_cohort_receipt: Path,
    final_cohort_assembly: Path,
    prerequisite_roots: Sequence[Path],
    foundation_attestation: Path,
    readiness_attestation: Path,
    historical_pre_snapshot: Path,
    profile: ClassStudyProfile = CLASS20_PROFILE,
) -> dict[str, Any]:
    """Return a verified launch ledger for one v2 canary or formal block.

    Results must be supplied in the exact historical order: authoritative
    fitting, certification, then each completed canary/formal block.  A formal
    block additionally requires its own canary.  The v2 pre snapshot must pass
    its own deep dispatcher; an absent or unsupported validator blocks launch.
    """

    if profile != CLASS20_PROFILE or load_class20_profile_contract() != profile:
        raise ValueError("20-site capture requires its source-pinned profile")
    layout = class_study_layout(profile=profile)
    campaign = _regular_file(campaign_path, "20-site campaign")
    if campaign.parent != layout.campaign_root or campaign.suffix != ".yml":
        raise ValueError("20-site capture campaign path is not canonical")
    document = yaml.safe_load(campaign.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("20-site capture campaign is not an object")
    identity = parse_class_study_campaign_name(document.get("name"))
    role, block = identity.evidence_role, identity.block
    if (
        identity.study_id != profile.study_id
        or role not in {"canary", "formal"}
        or type(block) is not int
        or not 1 <= block <= profile.formal_block_count
        or document.get("evidence_role") != role
        or campaign.name != f"{identity.name}.yml"
    ):
        raise ValueError("20-site capture campaign role, block, or name is invalid")
    campaign = require_canonical_fresh_child(
        campaign, field="campaign_root", filename=campaign.name, profile=profile,
    )
    required = _required_stages(role, block)
    if not isinstance(prerequisite_roots, Sequence) or isinstance(prerequisite_roots, (str, bytes)):
        raise ValueError("20-site capture prerequisite roots are malformed")
    if len(prerequisite_roots) != len(required):
        raise ValueError("20-site capture requires the exact preceding result ledger")
    # The v2 pre snapshot is an independent promotion boundary.  Check it
    # before the more expensive final-cohort, foundation, and readiness replays.
    snapshot_path = _regular_file(historical_pre_snapshot, "20-site pre snapshot")
    snapshot = class_attestation.validate_class_historical_snapshot(
        snapshot_path, expected_phase="pre-formal",
    )
    cohort_path = _regular_file(require_canonical_fresh_child(
        final_cohort_receipt, field="study_config_root",
        filename=f"{profile.study_id}-cohort.json", profile=profile,
    ), "20-site final cohort")
    assembly_path = _regular_file(require_canonical_fresh_child(
        final_cohort_assembly, field="study_config_root",
        filename=f"{profile.study_id}-cohort-assembly.json", profile=profile,
    ), "20-site final cohort assembly")
    pilot_ids, final_ids = load_validated_profile_cohort(
        cohort_path, assembly_path, profile=profile, require_deep=True,
    )
    if len(pilot_ids) != profile.pilot_count or len(final_ids) != profile.final_count:
        raise ValueError("20-site capture lacks its complete deep final cohort")
    validate_campaign_document(
        document, cohort_receipt=cohort_path,
        cohort_assembly_receipt=assembly_path, profile=profile,
    )

    foundation_path = _regular_file(foundation_attestation, "20-site foundation")
    readiness_path = _regular_file(readiness_attestation, "20-site readiness")
    foundation = class_attestation.validate_class_foundation_attestation(
        foundation_path, deep_code_gate=True, runtime_role="collection",
    )
    readiness = class_attestation.validate_class_readiness_attestation(
        readiness_path, deep_code_gate=True,
    )
    profile_sha = sha256_file(layout.study_config_root / "study.json")
    cohort_sha, assembly_sha = sha256_file(cohort_path), sha256_file(assembly_path)
    foundation_sha, readiness_sha, snapshot_sha = (
        sha256_file(foundation_path), sha256_file(readiness_path), sha256_file(snapshot_path)
    )
    evidence = readiness.get("evidence")
    summary = readiness.get("summary")
    if (
        foundation.get("study_id") != profile.study_id
        or foundation.get("study_profile_sha256") != profile_sha
        or readiness.get("study_id") != profile.study_id
        or readiness.get("study_profile_sha256") != profile_sha
        or not isinstance(evidence, Mapping)
        or not isinstance(summary, Mapping)
        or evidence.get("foundation") != {"path": str(foundation_path), "sha256": foundation_sha}
        or evidence.get("final_cohort") != {"path": str(cohort_path), "sha256": cohort_sha}
        or evidence.get("final_cohort_assembly")
        != {"path": str(assembly_path), "sha256": assembly_sha}
        or readiness.get("source") != foundation.get("source")
        or snapshot.get("study_id") != profile.study_id
        or snapshot.get("study_profile_sha256") != profile_sha
        or snapshot.get("phase") != "pre-formal"
        or snapshot.get("source") != readiness.get("source")
        or snapshot.get("readiness") != {"path": str(readiness_path), "sha256": readiness_sha}
    ):
        raise ValueError("20-site capture foundation, readiness, snapshot, or cohort differs")
    snapshot_time = _aware_time(snapshot.get("recorded_at"), "pre snapshot")
    certified_runtime = summary.get("certification_defense_runtime_inputs")
    if not isinstance(certified_runtime, Mapping) or not all(
        mode in certified_runtime for mode in ("undefended", *FORMAL_MODES)
    ):
        raise ValueError("20-site readiness has incomplete certified runtime inputs")
    ledger: list[dict[str, Any]] = []
    roots_seen: set[Path] = set()
    preceding_finish: datetime | None = None
    for root, (prior_role, prior_block) in zip(prerequisite_roots, required, strict=True):
        result_root = _regular_directory(Path(root), "20-site prerequisite result")
        if result_root in roots_seen:
            raise ValueError("20-site capture prerequisite result is repeated")
        roots_seen.add(result_root)
        record = verify_profile_class_result(
            result_root, profile=profile, cohort_receipt=cohort_path,
            cohort_assembly=assembly_path, expected_role=prior_role,
            expected_block=prior_block,
        )
        if not isinstance(record, Mapping) or record.get("valid") is not True:
            raise ValueError("20-site capture prerequisite did not deep verify")
        if (
            record.get("root") != str(result_root)
            or record.get("evidence_role") != prior_role
            or record.get("block") != prior_block
            or record.get("class_study_id") != profile.study_id
            or record.get("class_study_profile_sha256") != profile_sha
            or record.get("class_study_foundation_sha256") != foundation_sha
            or record.get("cohort_sha256") != cohort_sha
            or record.get("cohort_assembly_sha256") != assembly_sha
        ):
            raise ValueError("20-site capture prerequisite has another identity or authority")
        if prior_role in {"authoritative-fitting", "certification"}:
            binding_name = (
                "authoritative_fitting_result"
                if prior_role == "authoritative-fitting" else "certification_result"
            )
            if (
                evidence.get(binding_name) != {
                    "root": str(result_root),
                    "evidence_sha256": record.get("evidence_sha256"),
                }
                or record.get("class_study_readiness_sha256") is not None
                or record.get("class_study_historical_pre_snapshot_sha256") is not None
            ):
                raise ValueError("20-site capture fitting/certification differs from readiness")
        else:
            expected_modes = ("undefended",) if prior_role == "canary" else FORMAL_MODES
            if (
                record.get("class_study_readiness_sha256") != readiness_sha
                or record.get("class_study_historical_pre_snapshot_sha256") != snapshot_sha
                or record.get("defense_runtime_inputs")
                != {mode: certified_runtime[mode] for mode in expected_modes}
                or (
                    record.get("chaff_qualification_set_manifest_sha256")
                    != summary.get("final_qualification_set_manifest_sha256")
                    if prior_role == "formal" else
                    record.get("chaff_qualification_set_manifest_sha256") is not None
                )
            ):
                raise ValueError("20-site prior capture uses another readiness or runtime")
        sealed = load_json(_regular_file(result_root / "experiment.json", "prerequisite experiment"))
        if not isinstance(sealed, Mapping) or sealed.get("source") != readiness.get("source"):
            raise ValueError("20-site prerequisite uses another source")
        start = _aware_time(sealed.get("started_at"), "prerequisite start")
        finish = _aware_time(sealed.get("completed_at"), "prerequisite completion")
        if finish < start or (preceding_finish is not None and start < preceding_finish):
            raise ValueError("20-site prerequisite chronology is invalid")
        if prior_role == "certification" and snapshot_time < finish:
            raise ValueError("20-site pre snapshot predates certification completion")
        if prior_role in {"canary", "formal"} and start < snapshot_time:
            raise ValueError("20-site prior capture predates the pre snapshot")
        preceding_finish = finish
        ledger.append(dict(record))

    return {
        "valid": True,
        "campaign_path": str(campaign),
        "campaign_sha256": sha256_file(campaign),
        "campaign_name": identity.name,
        "evidence_role": role,
        "block": block,
        "planned_samples": profile.final_count * (
            1 if role == "canary" else profile.formal_visits_per_block * len(FORMAL_MODES)
        ),
        "cohort_sha256": cohort_sha,
        "cohort_assembly_sha256": assembly_sha,
        "foundation_sha256": foundation_sha,
        "readiness_sha256": readiness_sha,
        "historical_pre_snapshot_sha256": snapshot_sha,
        "historical_pre_recorded_at": snapshot["recorded_at"],
        "source": dict(readiness["source"]),
        "expected_defense_runtime_inputs": {
            mode: certified_runtime[mode]
            for mode in (("undefended",) if role == "canary" else FORMAL_MODES)
        },
        "prerequisite_ledger": tuple(ledger),
        "required_environment": {
            "QCSD_CLASS_FOUNDATION_ATTESTATION": str(foundation_path),
            "QCSD_CLASS_READINESS_ATTESTATION": str(readiness_path),
            "QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT": str(snapshot_path),
        },
    }


def _required_stages(role: str, block: int) -> tuple[tuple[str, int | None], ...]:
    stages: list[tuple[str, int | None]] = [
        ("authoritative-fitting", None), ("certification", None),
    ]
    for prior in range(1, block):
        stages.extend((("canary", prior), ("formal", prior)))
    if role == "formal":
        stages.append(("canary", block))
    return tuple(stages)


def _aware_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"20-site {label} timestamp is missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"20-site {label} timestamp is invalid") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"20-site {label} timestamp has no timezone")
    return result


def _regular_file(path: Path, label: str) -> Path:
    value = Path(path).absolute()
    if value.is_symlink() or not value.is_file():
        raise ValueError(f"{label} is not a regular file")
    return value


def _regular_directory(path: Path, label: str) -> Path:
    value = Path(path).absolute()
    if value.is_symlink() or not value.is_dir():
        raise ValueError(f"{label} is not a regular directory")
    return value
