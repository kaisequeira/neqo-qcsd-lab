"""Deterministic campaign generation for ``classifier-multiorigin100-v1``."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .class_layout import (
    AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
    AUTHORITATIVE_COHORT_FILENAME,
    DEFAULT_AUTHORITATIVE_FINAL_REFERENCE,
    DEFAULT_COHORT_ASSEMBLY_REFERENCE,
    DEFAULT_COHORT_REFERENCE,
    DEFAULT_PILOT_FINAL_REFERENCE,
    FINAL_QUALIFICATION_SET,
    PILOT_QUALIFICATION_SET,
    PILOT_COHORT_ASSEMBLY_FILENAME,
    PILOT_COHORT_FILENAME,
    class_study_layout,
    canonical_campaign_reference,
    require_canonical_campaign_reference,
    require_canonical_fresh_child,
    require_canonical_fresh_path,
    require_safe_campaign_reference,
)
from .class_cohort import validate_cohort_assembly_receipt
from .class_study import (
    CLASS20_PROFILE,
    FINAL_CLASS_COUNT,
    FORMAL_BLOCK_COUNT,
    FORMAL_MODES,
    FORMAL_VISITS_PER_BLOCK,
    PILOT_COUNT,
    STUDY_ID,
    ClassStudyProfile,
    canonical_json_bytes,
    load_class20_profile_contract,
    load_study_receipt,
)
from .util import load_json

SCHEMA_VERSION = 1
ARTIFACT_TYPE = "qcsd-class-study-campaign-set"
ORIGIN_AWARE_WINDOW = 16

CAPTURE_LIMITS = {
    "timeout_seconds": 120,
    "max_response_bytes": 1_048_576,
    "capture_seconds": 180,
    "capture_megabytes": 64,
    "max_attempts": 3,
    "per_origin_cooldown_seconds": 30,
    "settle_seconds": 1,
}


def campaign_documents(
    cohort_receipt: Path,
    *,
    cohort_assembly_receipt: Path,
    cohort_reference: str = DEFAULT_COHORT_REFERENCE,
    cohort_assembly_reference: str = DEFAULT_COHORT_ASSEMBLY_REFERENCE,
    pilot_bundle_reference: str = DEFAULT_PILOT_FINAL_REFERENCE,
    authoritative_bundle_reference: str = DEFAULT_AUTHORITATIVE_FINAL_REFERENCE,
    profile: ClassStudyProfile | None = None,
    _enforce_fresh_layout: bool = True,
) -> dict[str, dict[str, Any]]:
    """Return the complete excluded/fitting/canary/formal campaign inventory."""

    contract = _campaign_contract(profile)
    layout = class_study_layout(profile=profile)
    stage: str | None = None
    if profile is not None:
        stage = {
            f"{profile.study_id}-pilot-cohort.json": "pilot",
            f"{profile.study_id}-cohort.json": "final",
        }.get(cohort_receipt.name)
        if stage is None and _enforce_fresh_layout:
            raise ValueError("20-site campaign cohort filename is not canonical")
        cohort_name = (
            f"{contract.study_id}-pilot-cohort.json"
            if stage == "pilot"
            else f"{contract.study_id}-cohort.json"
        )
        assembly_name = (
            f"{contract.study_id}-pilot-cohort-assembly.json"
            if stage == "pilot"
            else f"{contract.study_id}-cohort-assembly.json"
        )
        if cohort_reference == DEFAULT_COHORT_REFERENCE:
            cohort_reference = f"../class-study/v2/{cohort_name}"
        if cohort_assembly_reference == DEFAULT_COHORT_ASSEMBLY_REFERENCE:
            cohort_assembly_reference = f"../class-study/v2/{assembly_name}"
        if pilot_bundle_reference == DEFAULT_PILOT_FINAL_REFERENCE:
            pilot_bundle_reference = _bundle_default_reference("pilot", profile)
        if authoritative_bundle_reference == DEFAULT_AUTHORITATIVE_FINAL_REFERENCE:
            authoritative_bundle_reference = _bundle_default_reference(
                "authoritative", profile
            )
    if profile is None:
        receipt, selection = load_study_receipt(cohort_receipt)
        if receipt.get("payload", {}).get("study_id") != contract.study_id:
            raise ValueError("class-study campaign cohort uses another study profile")
        assembly_path = Path(os.path.abspath(cohort_assembly_receipt))
        if assembly_path.is_symlink() or not assembly_path.is_file():
            raise ValueError(f"cohort assembly receipt is not a regular file: {assembly_path}")
        validate_cohort_assembly_receipt(load_json(assembly_path), cohort=receipt)
        pilot_ids = tuple(candidate.candidate_id for candidate in selection.pilot)
        final_ids = tuple(candidate.candidate_id for candidate in selection.final)
    else:
        if load_class20_profile_contract() != profile:
            raise ValueError("class-study campaign profile differs from the registered contract")
        from .class_cohort20 import load_validated_profile_cohort

        pilot_ids, final_ids = load_validated_profile_cohort(
            cohort_receipt,
            cohort_assembly_receipt,
            profile=profile,
            require_deep=_enforce_fresh_layout,
        )
        verified_stage = "final" if final_ids else "pilot"
        if stage is not None and stage != verified_stage:
            raise ValueError("20-site campaign cohort stage differs from its filename")
        stage = verified_stage
    return _campaign_documents_for_ids(
        pilot_ids=pilot_ids,
        final_ids=final_ids,
        cohort_reference=cohort_reference,
        cohort_assembly_reference=cohort_assembly_reference,
        pilot_bundle_reference=pilot_bundle_reference,
        authoritative_bundle_reference=authoritative_bundle_reference,
        profile=profile,
        enforce_fresh_layout=_enforce_fresh_layout,
        stage=stage,
    )


def _campaign_documents_for_ids(
    *,
    pilot_ids: Sequence[str],
    final_ids: Sequence[str],
    cohort_reference: str,
    cohort_assembly_reference: str,
    pilot_bundle_reference: str,
    authoritative_bundle_reference: str,
    profile: ClassStudyProfile | None,
    enforce_fresh_layout: bool,
    stage: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build documents after the caller has validated cohort and assembly authority."""

    contract = _campaign_contract(profile)
    if (profile is None and stage is not None) or (
        profile is not None and stage not in {"pilot", "final"}
    ):
        raise ValueError("class-study campaign generation stage is invalid")
    if profile is not None and (
        len(pilot_ids) != contract.pilot_count
        or (stage == "pilot" and final_ids)
        or (stage == "final" and len(final_ids) != contract.final_count)
    ):
        raise ValueError("class-study campaign cohort cardinality differs from its stage")
    layout = class_study_layout(profile=profile)
    documents: dict[str, dict[str, Any]] = {}

    if stage != "final":
        _add(
            documents,
            _campaign(
                name=_campaign_name("pilot-fitting", profile=profile),
                role="pilot-fitting",
                workloads=pilot_ids,
                visits=2,
                policies=("as-defined", "half-duplex"),
                defenses=("undefended",),
                cohort_reference=cohort_reference,
                cohort_assembly_reference=cohort_assembly_reference,
                max_attempts=3,
                study_id=contract.study_id,
            ),
        )
        if profile is None:
            _add(
                documents,
                _campaign(
                    name=_campaign_name("pilot-compatibility", profile=profile),
                    role="pilot-compatibility",
                    workloads=pilot_ids,
                    visits=1,
                    policies=("as-defined",),
                    defenses=_compatibility_defenses(pilot_bundle_reference),
                    cohort_reference=cohort_reference,
                    cohort_assembly_reference=cohort_assembly_reference,
                    qualification_set=layout.pilot_qualification_set_root.name,
                    defense_order_block=0,
                    max_attempts=3,
                    study_id=contract.study_id,
                ),
            )
    if stage != "pilot":
        _add(
            documents,
            _campaign(
                name=_campaign_name("authoritative-fitting", profile=profile),
                role="authoritative-fitting",
                workloads=final_ids,
                visits=10,
                policies=("as-defined", "half-duplex"),
                defenses=("undefended",),
                cohort_reference=cohort_reference,
                cohort_assembly_reference=cohort_assembly_reference,
                max_attempts=3,
                study_id=contract.study_id,
            ),
        )
        _add(
            documents,
            _campaign(
                name=_campaign_name("certification", profile=profile),
                role="certification",
                workloads=final_ids,
                visits=1,
                policies=("as-defined",),
                defenses=_compatibility_defenses(authoritative_bundle_reference),
                cohort_reference=cohort_reference,
                cohort_assembly_reference=cohort_assembly_reference,
                qualification_set=layout.final_qualification_set_root.name,
                defense_order_block=0,
                max_attempts=1,
                study_id=contract.study_id,
            ),
        )
    blocks = range(1, contract.formal_block_count + 1) if stage != "pilot" else ()
    for block in blocks:
        _add(
            documents,
            _campaign(
                name=_campaign_name("canary", profile=profile, block=block),
                role="canary",
                workloads=final_ids,
                visits=1,
                policies=("as-defined",),
                defenses=("undefended",),
                cohort_reference=cohort_reference,
                cohort_assembly_reference=cohort_assembly_reference,
                defense_order_block=block - 1,
                # The canary is an excluded pre-block health gate.  Preserve
                # transient failures and permit bounded retries; any terminal
                # failure still prevents the formal block from starting.
                max_attempts=3,
                study_id=contract.study_id,
            ),
        )
        _add(
            documents,
            _campaign(
                name=_campaign_name("formal", profile=profile, block=block),
                role="formal",
                workloads=final_ids,
                visits=contract.formal_visits_per_block,
                policies=("as-defined",),
                defenses=_formal_defenses(authoritative_bundle_reference),
                cohort_reference=cohort_reference,
                cohort_assembly_reference=cohort_assembly_reference,
                qualification_set=layout.final_qualification_set_root.name,
                defense_order_block=block - 1,
                # Certification is deliberately strict, but a 16,000-sample
                # acquisition must tolerate bounded transient collection
                # failures.  Every failed attempt remains sealed; only an
                # exactly accepted sample enters the classifier handoff.
                max_attempts=3,
                study_id=contract.study_id,
            ),
        )
    _validate_generated_layout_references(
        documents,
        cohort_reference=cohort_reference,
        cohort_assembly_reference=cohort_assembly_reference,
        pilot_bundle_reference=pilot_bundle_reference,
        authoritative_bundle_reference=authoritative_bundle_reference,
        enforce_fresh_layout=enforce_fresh_layout,
        profile=profile,
    )
    validate_campaign_documents(
        documents, pilot_ids=pilot_ids, final_ids=final_ids, profile=profile, stage=stage
    )
    return documents


def write_campaign_documents(
    cohort_receipt: Path,
    destination: Path,
    *,
    cohort_assembly_receipt: Path,
    profile: ClassStudyProfile | None = None,
    **references: str,
) -> tuple[Path, ...]:
    """Create all campaign YAML files without replacing any existing file."""

    contract = _campaign_contract(profile)
    layout = class_study_layout(profile=profile)
    final_cohort_name = f"{contract.study_id}-cohort.json"
    final_assembly_name = f"{contract.study_id}-cohort-assembly.json"
    pilot_cohort_name = f"{contract.study_id}-pilot-cohort.json"
    pilot_assembly_name = f"{contract.study_id}-pilot-cohort-assembly.json"
    root = require_canonical_fresh_path(
        destination,
        field="campaign_root",
        label="class-study campaign destination",
        profile=profile,
    )
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"campaign destination must be a regular directory: {root}")
    cohort_path = require_canonical_fresh_child(
        cohort_receipt,
        field="study_config_root",
        filename=final_cohort_name,
        label="class-study cohort receipt",
        profile=profile,
    )
    assembly_path = require_canonical_fresh_child(
        cohort_assembly_receipt,
        field="study_config_root",
        filename=final_assembly_name,
        label="class-study cohort-assembly receipt",
        profile=profile,
    )
    references = dict(references)
    if "_enforce_fresh_layout" in references:
        raise ValueError("campaign publication cannot disable canonical fresh-layout validation")
    references.setdefault(
        "cohort_reference",
        canonical_campaign_reference(
            field="study_config_root",
            filename=cohort_path.name,
            profile=profile,
        ),
    )
    references.setdefault(
        "cohort_assembly_reference",
        canonical_campaign_reference(
            field="study_config_root",
            filename=assembly_path.name,
            profile=profile,
        ),
    )
    require_canonical_campaign_reference(
        references["cohort_reference"],
        field="study_config_root",
        filename=cohort_path.name,
        label="class-study cohort reference",
        profile=profile,
    )
    require_canonical_campaign_reference(
        references["cohort_assembly_reference"],
        field="study_config_root",
        filename=assembly_path.name,
        label="class-study cohort-assembly reference",
        profile=profile,
    )
    authoritative_documents = campaign_documents(
        cohort_path,
        cohort_assembly_receipt=assembly_path,
        profile=profile,
        **references,
    )
    pilot_cohort_path = require_canonical_fresh_child(
        layout.study_config_root / pilot_cohort_name,
        field="study_config_root",
        filename=pilot_cohort_name,
        label="pilot cohort receipt",
        profile=profile,
    )
    pilot_assembly_path = require_canonical_fresh_child(
        layout.study_config_root / pilot_assembly_name,
        field="study_config_root",
        filename=pilot_assembly_name,
        label="pilot cohort-assembly receipt",
        profile=profile,
    )
    if pilot_cohort_path.is_symlink() or not pilot_cohort_path.is_file():
        raise ValueError(f"pilot cohort receipt is not a regular file: {pilot_cohort_path}")
    if pilot_assembly_path.is_symlink() or not pilot_assembly_path.is_file():
        raise ValueError(
            f"pilot cohort-assembly receipt is not a regular file: {pilot_assembly_path}"
        )
    pilot_documents = campaign_documents(
        pilot_cohort_path,
        cohort_assembly_receipt=pilot_assembly_path,
        cohort_reference=canonical_campaign_reference(
            field="study_config_root",
            filename=pilot_cohort_name,
            profile=profile,
        ),
        cohort_assembly_reference=canonical_campaign_reference(
            field="study_config_root",
            filename=pilot_assembly_name,
            profile=profile,
        ),
        pilot_bundle_reference=references.get(
            "pilot_bundle_reference",
            _bundle_default_reference("pilot", profile),
        ),
        authoritative_bundle_reference=references.get(
            "authoritative_bundle_reference",
            _bundle_default_reference("authoritative", profile),
        ),
        profile=profile,
    )
    pilot_entries = {
        filename: document
        for filename, document in pilot_documents.items()
        if document["evidence_role"] in {"pilot-fitting", "pilot-compatibility"}
    }
    documents = {**pilot_entries, **authoritative_documents}
    documents.update(pilot_entries)
    if profile is not None:
        pilot_ids = tuple(
            pilot_documents[_campaign_name("pilot-fitting", profile=profile) + ".yml"][
                "workloads"
            ]
        )
        final_ids = tuple(
            authoritative_documents[
                _campaign_name("authoritative-fitting", profile=profile) + ".yml"
            ]["workloads"]
        )
        validate_campaign_documents(
            documents, pilot_ids=pilot_ids, final_ids=final_ids, profile=profile
        )
    paths: list[Path] = []
    for filename, value in documents.items():
        path = root / filename
        encoded = yaml.safe_dump(value, sort_keys=False, width=100).encode("utf-8")
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "xb",
                dir=root,
                prefix=f".{filename}.",
                suffix=".qcsd-tmp",
                delete=False,
            ) as output:
                temporary = Path(output.name)
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                raise FileExistsError(f"campaign already exists: {path}") from error
            paths.append(path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return tuple(paths)


def _validate_generated_layout_references(
    documents: Mapping[str, Mapping[str, Any]],
    *,
    cohort_reference: str,
    cohort_assembly_reference: str,
    pilot_bundle_reference: str,
    authoritative_bundle_reference: str,
    enforce_fresh_layout: bool,
    profile: ClassStudyProfile | None,
) -> None:
    """Prove every statically knowable reference against the canonical graph.

    Fresh publications require the exact versioned graph.  The sole relaxed
    mode is used internally while reconstructing an already sealed result;
    even there, references remain normalised and confined to the Lab root.
    """

    references = (
        (cohort_reference, "class-study cohort reference"),
        (cohort_assembly_reference, "class-study cohort-assembly reference"),
        (pilot_bundle_reference, "pilot fitted-bundle reference"),
        (authoritative_bundle_reference, "authoritative fitted-bundle reference"),
    )
    for reference, label in references:
        require_safe_campaign_reference(reference, label=label, profile=profile)

    if enforce_fresh_layout:
        study_id = _campaign_contract(profile).study_id
        canonical_admissions = {
            (
                canonical_campaign_reference(
                    field="study_config_root",
                    filename=f"{study_id}-pilot-cohort.json",
                    profile=profile,
                ),
                canonical_campaign_reference(
                    field="study_config_root",
                    filename=f"{study_id}-pilot-cohort-assembly.json",
                    profile=profile,
                ),
            ),
            (
                canonical_campaign_reference(
                    field="study_config_root",
                    filename=f"{study_id}-cohort.json",
                    profile=profile,
                ),
                canonical_campaign_reference(
                    field="study_config_root",
                    filename=f"{study_id}-cohort-assembly.json",
                    profile=profile,
                ),
            ),
        }
        if (cohort_reference, cohort_assembly_reference) not in canonical_admissions:
            raise ValueError(
                "class-study cohort references use an alternate class-study path; "
                "expected one exact canonical admission pair"
            )

    canonical = (
        (
            pilot_bundle_reference,
            _bundle_default_reference("pilot", profile),
            "pilot_final_root",
            None,
            "pilot fitted-bundle reference",
        ),
        (
            authoritative_bundle_reference,
            _bundle_default_reference("authoritative", profile),
            "authoritative_final_root",
            None,
            "authoritative fitted-bundle reference",
        ),
    )
    for observed, default, field, filename, label in canonical:
        if enforce_fresh_layout and observed != default:
            raise ValueError(
                f"{label} must use the canonical class-study reference {default}"
            )
        if enforce_fresh_layout or observed == default:
            require_canonical_campaign_reference(
                observed,
                field=field,
                filename=filename,
                label=label,
                profile=profile,
            )

    fixed_defense_inputs = {
        "static": ("schedule", "static-control-1200.csv"),
        "buflo": ("parameters", "buflo-live.json"),
        "cs-buflo": ("parameters", "cs-buflo-ctsp-live.json"),
    }
    for document in documents.values():
        defenses = document.get("defenses")
        if not isinstance(defenses, list):
            raise ValueError("generated class-study defense inventory is malformed")
        for defense in defenses:
            if not isinstance(defense, Mapping):
                continue
            name = defense.get("name")
            fixed = fixed_defense_inputs.get(str(name))
            if fixed is None:
                continue
            key, filename = fixed
            reference = defense.get(key)
            if not isinstance(reference, str):
                raise ValueError(f"generated {name} defense has no {key} reference")
            require_canonical_campaign_reference(
                reference,
                field="defense_params_root",
                filename=filename,
                label=f"generated {name} {key} reference",
                profile=profile,
            )


def validate_campaign_documents(
    documents: Mapping[str, Mapping[str, Any]],
    *,
    pilot_ids: Sequence[str],
    final_ids: Sequence[str],
    profile: ClassStudyProfile | None = None,
    stage: str | None = None,
) -> None:
    """Validate the complete or prospective partial campaign matrix."""

    contract = _campaign_contract(profile)
    if stage not in {None, "pilot", "final"} or (profile is None and stage is not None):
        raise ValueError("class-study campaign validation stage is invalid")
    if stage == "pilot":
        expected_file_count = 1 if profile is not None else 2
    elif stage == "final":
        expected_file_count = 2 + 2 * contract.formal_block_count
    else:
        expected_file_count = (3 if profile is not None else 4) + 2 * contract.formal_block_count
    if len(documents) != expected_file_count or len(set(documents)) != expected_file_count:
        raise ValueError("class-study campaign set has the wrong file count")
    if profile is not None and (
        len(pilot_ids) != contract.pilot_count
        or (stage == "pilot" and final_ids)
        or (stage != "pilot" and len(final_ids) != contract.final_count)
    ):
        raise ValueError("class-study campaign cohort cardinality differs from its profile")
    role_counts: dict[str, int] = {}
    sample_counts: dict[str, int] = {}
    for filename, document in documents.items():
        if filename != f"{document.get('name')}.yml":
            raise ValueError("class-study campaign filename differs from its name")
        if document.get("schema") != 2 or document.get("profile") != "research-1200":
            raise ValueError("class-study campaign has the wrong schema or profile")
        role = document.get("evidence_role")
        if not isinstance(role, str):
            raise ValueError("class-study campaign has no evidence role")
        role_counts[role] = role_counts.get(role, 0) + 1
        workloads = document.get("workloads")
        defenses = document.get("defenses")
        policies = document.get("request_policies")
        if not isinstance(workloads, Mapping) or not isinstance(defenses, list):
            raise ValueError("class-study campaign matrix is malformed")
        if not isinstance(policies, list):
            raise ValueError("class-study campaign policies are malformed")
        expected_ids = tuple(pilot_ids if role.startswith("pilot-") else final_ids)
        if tuple(workloads) != expected_ids:
            raise ValueError("class-study campaign workload order is not cohort-bound")
        sample_counts[role] = sample_counts.get(role, 0) + (
            sum(int(visits) for visits in workloads.values()) * len(defenses) * len(policies)
        )
    expected_role_counts = {
        "pilot-fitting": 1,
        "pilot-compatibility": 1,
        "authoritative-fitting": 1,
        "certification": 1,
        "canary": contract.formal_block_count,
        "formal": contract.formal_block_count,
    }
    if profile is not None:
        del expected_role_counts["pilot-compatibility"]
    if stage == "pilot":
        expected_role_counts = {
            role: count
            for role, count in expected_role_counts.items()
            if role.startswith("pilot-")
        }
    elif stage == "final":
        expected_role_counts = {
            role: count
            for role, count in expected_role_counts.items()
            if not role.startswith("pilot-")
        }
    if role_counts != expected_role_counts:
        raise ValueError("class-study campaign role inventory is invalid")
    expected_sample_counts = {
        "pilot-fitting": contract.pilot_count * 2 * 2,
        "pilot-compatibility": contract.pilot_count * 9,
        "authoritative-fitting": contract.final_count * 10 * 2,
        "certification": contract.final_count * 9,
        "canary": contract.formal_block_count * contract.final_count,
        "formal": (
            contract.formal_block_count
            * contract.final_count
            * contract.formal_visits_per_block
            * len(FORMAL_MODES)
        ),
    }
    if profile is not None:
        del expected_sample_counts["pilot-compatibility"]
    if stage == "pilot":
        expected_sample_counts = {
            role: count
            for role, count in expected_sample_counts.items()
            if role.startswith("pilot-")
        }
    elif stage == "final":
        expected_sample_counts = {
            role: count
            for role, count in expected_sample_counts.items()
            if not role.startswith("pilot-")
        }
    if sample_counts != expected_sample_counts:
        raise ValueError("class-study campaign sample arithmetic is invalid")


def validate_campaign_document(
    document: Mapping[str, Any],
    *,
    cohort_receipt: Path,
    cohort_assembly_receipt: Path,
    enforce_fresh_layout: bool = True,
    profile: ClassStudyProfile | None = None,
) -> str:
    """Reconstruct one canonical campaign from its exact cohort admission.

    This closes the direct-run boundary as well as campaign-set publication:
    limits, seed, mode order, fixed CTSP/BuFLO inputs, fitted-bundle references,
    qualification identity, and block ordering must all equal the generator.
    """

    role = document.get("evidence_role")
    name = document.get("name")
    cohort_reference = document.get("class_study_cohort")
    assembly_reference = document.get("class_study_cohort_assembly")
    if (
        not isinstance(role, str)
        or not isinstance(name, str)
        or not isinstance(cohort_reference, str)
        or not isinstance(assembly_reference, str)
    ):
        raise ValueError("class-study campaign lacks its canonical identity fields")
    if enforce_fresh_layout:
        study_id = _campaign_contract(profile).study_id
        pilot_role = role in {"pilot-fitting", "pilot-compatibility"}
        expected_cohort = canonical_campaign_reference(
            field="study_config_root",
            filename=(
                f"{study_id}-pilot-cohort.json" if pilot_role else f"{study_id}-cohort.json"
            ),
            profile=profile,
        )
        expected_assembly = canonical_campaign_reference(
            field="study_config_root",
            filename=(
                f"{study_id}-pilot-cohort-assembly.json"
                if pilot_role
                else f"{study_id}-cohort-assembly.json"
            ),
            profile=profile,
        )
        if (
            cohort_reference != expected_cohort
            or assembly_reference != expected_assembly
        ):
            raise ValueError(
                f"{role} campaign does not use its exact canonical cohort admission"
            )
    pilot_bundle = (
        _document_fitted_bundle_reference(document)
        if role == "pilot-compatibility"
        else _bundle_default_reference("pilot", profile)
    )
    authoritative_bundle = (
        _document_fitted_bundle_reference(document)
        if role in {"certification", "formal"}
        else _bundle_default_reference("authoritative", profile)
    )
    expected = campaign_documents(
        cohort_receipt,
        cohort_assembly_receipt=cohort_assembly_receipt,
        cohort_reference=cohort_reference,
        cohort_assembly_reference=assembly_reference,
        pilot_bundle_reference=pilot_bundle,
        authoritative_bundle_reference=authoritative_bundle,
        profile=profile,
        _enforce_fresh_layout=enforce_fresh_layout,
    )
    filename = f"{name}.yml"
    selected = expected.get(filename)
    if selected is None or selected.get("evidence_role") != role:
        raise ValueError("class-study campaign name and evidence role are not canonical")
    if canonical_json_bytes(document) != canonical_json_bytes(selected):
        raise ValueError("class-study campaign differs from its deterministic generator")
    return filename


def _document_fitted_bundle_reference(document: Mapping[str, Any]) -> str:
    defenses = document.get("defenses")
    traffic = (
        next(
            (
                item
                for item in defenses
                if isinstance(item, Mapping)
                and item.get("name") == "traffic-morphing"
            ),
            None,
        )
        if isinstance(defenses, list)
        else None
    )
    parameters = traffic.get("parameters") if isinstance(traffic, Mapping) else None
    suffix = "/traffic-morphing.json"
    if not isinstance(parameters, str) or not parameters.endswith(suffix):
        raise ValueError("class-study campaign has no canonical fitted-bundle reference")
    return parameters.removesuffix(suffix)


def _campaign(
    *,
    name: str,
    role: str,
    workloads: Sequence[str],
    visits: int,
    policies: Sequence[str],
    defenses: Sequence[str | Mapping[str, Any]],
    cohort_reference: str,
    cohort_assembly_reference: str,
    max_attempts: int,
    study_id: str = STUDY_ID,
    qualification_set: str | None = None,
    defense_order_block: int | None = None,
) -> dict[str, Any]:
    purpose = "fitting" if role.endswith("fitting") else "evaluation" if role == "formal" else "smoke"
    value: dict[str, Any] = {
        "schema": 2,
        "name": name,
        "purpose": purpose,
        "evidence_role": role,
        "seed": _seed(name, study_id=study_id),
        "profile": "research-1200",
        "class_study_cohort": cohort_reference,
        "class_study_cohort_assembly": cohort_assembly_reference,
        "sample_order": {
            "scheme": "origin-aware-windowed",
            "window_size": ORIGIN_AWARE_WINDOW,
        },
        "workloads": {workload_id: visits for workload_id in workloads},
        "request_policies": list(policies),
        "defenses": list(defenses),
        "limits": {**CAPTURE_LIMITS, "max_attempts": max_attempts},
    }
    if qualification_set is not None:
        value["chaff_qualification_set"] = qualification_set
    if defense_order_block is not None:
        value["defense_order"] = {
            "scheme": "cyclic-latin-square",
            "block": defense_order_block,
        }
    return value


def _compatibility_defenses(bundle: str) -> tuple[str | Mapping[str, Any], ...]:
    return (
        "undefended",
        {
            "name": "static",
            "kind": "static",
            "schedule": "../defense-params/static-control-1200.csv",
            "mode": "chaff-only",
        },
        "front",
        "tamaraw",
        *_fitted_defenses(bundle),
        {
            "name": "buflo",
            "kind": "buflo",
            "parameters": "../defense-params/buflo-live.json",
        },
        {
            "name": "cs-buflo",
            "kind": "cs_buflo",
            "parameters": "../defense-params/cs-buflo-ctsp-live.json",
        },
    )


def _formal_defenses(bundle: str) -> tuple[str | Mapping[str, Any], ...]:
    compatibility = _compatibility_defenses(bundle)
    result = tuple(item for item in compatibility if not (isinstance(item, Mapping) and item.get("name") == "static"))
    names = tuple(item if isinstance(item, str) else item["name"] for item in result)
    if names != FORMAL_MODES:
        raise AssertionError("formal defense encoding differs from the class-study contract")
    return result


def _fitted_defenses(bundle: str) -> tuple[Mapping[str, Any], ...]:
    return (
        {
            "name": "traffic-morphing",
            "kind": "traffic_morphing",
            "parameters": f"{bundle}/traffic-morphing.json",
        },
        {
            "name": "wtf-pad",
            "kind": "wtf_pad",
            "parameters": f"{bundle}/wtf-pad.json",
        },
        {
            "name": "walkie-talkie",
            "kind": "walkie_talkie",
            "parameters": f"{bundle}/walkie-talkie.json",
        },
    )


def _seed(name: str, *, study_id: str = STUDY_ID) -> int:
    return int.from_bytes(hashlib.sha256(f"{study_id}\0{name}".encode()).digest()[:4], "big")


@dataclass(frozen=True)
class _CampaignContract:
    study_id: str
    pilot_count: int
    final_count: int
    formal_block_count: int
    formal_visits_per_block: int


def _campaign_contract(profile: ClassStudyProfile | None) -> _CampaignContract:
    if profile is None:
        return _CampaignContract(
            STUDY_ID,
            PILOT_COUNT,
            FINAL_CLASS_COUNT,
            FORMAL_BLOCK_COUNT,
            FORMAL_VISITS_PER_BLOCK,
        )
    if profile != CLASS20_PROFILE:
        raise ValueError("unsupported class-study campaign profile")
    return _CampaignContract(
        profile.study_id,
        profile.pilot_count,
        profile.final_count,
        profile.formal_block_count,
        profile.formal_visits_per_block,
    )


def _bundle_default_reference(
    stage: str, profile: ClassStudyProfile | None
) -> str:
    if stage not in {"pilot", "authoritative"}:
        raise ValueError("class-study fitting stage is invalid")
    if profile is None:
        return (
            DEFAULT_PILOT_FINAL_REFERENCE
            if stage == "pilot"
            else DEFAULT_AUTHORITATIVE_FINAL_REFERENCE
        )
    _campaign_contract(profile)
    return f"../../artifacts/{profile.study_id}-{stage}-fitting"


def _campaign_name(
    role: str, *, profile: ClassStudyProfile | None, block: int | None = None
) -> str:
    study_id = _campaign_contract(profile).study_id
    if role in {"canary", "formal"}:
        if block is None:
            raise ValueError("block campaign requires a block number")
        return f"{study_id}-{role}-{block:02d}-1200"
    suffix = (
        {
            "pilot-fitting": "pilot-fitting-1200",
            "pilot-compatibility": "pilot-compatibility-1080-1200",
            "authoritative-fitting": "authoritative-fitting-1200",
            "certification": "certification-900-1200",
        }
        if profile is None
        else {
            "pilot-fitting": "pilot-fitting-120-1200",
            "authoritative-fitting": "authoritative-fitting-400-1200",
            "certification": "certification-180-1200",
        }
    )[role]
    return f"{study_id}-{suffix}"


def _add(documents: dict[str, dict[str, Any]], value: dict[str, Any]) -> None:
    filename = f"{value['name']}.yml"
    if filename in documents:
        raise AssertionError(f"duplicate generated campaign: {filename}")
    documents[filename] = value
