"""Deterministic campaign generation for ``classifier-multiorigin100-v1``."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Mapping, Sequence
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
    FORMAL_MODES,
    STUDY_ID,
    canonical_json_bytes,
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
    _enforce_fresh_layout: bool = True,
) -> dict[str, dict[str, Any]]:
    """Return the complete excluded/fitting/canary/formal campaign inventory."""

    receipt, selection = load_study_receipt(cohort_receipt)
    assembly_path = Path(os.path.abspath(cohort_assembly_receipt))
    if assembly_path.is_symlink() or not assembly_path.is_file():
        raise ValueError(f"cohort assembly receipt is not a regular file: {assembly_path}")
    validate_cohort_assembly_receipt(load_json(assembly_path), cohort=receipt)
    pilot_ids = tuple(candidate.candidate_id for candidate in selection.pilot)
    final_ids = tuple(candidate.candidate_id for candidate in selection.final)
    documents: dict[str, dict[str, Any]] = {}

    _add(
        documents,
        _campaign(
            name=f"{STUDY_ID}-pilot-fitting-1200",
            role="pilot-fitting",
            workloads=pilot_ids,
            visits=2,
            policies=("as-defined", "half-duplex"),
            defenses=("undefended",),
            cohort_reference=cohort_reference,
            cohort_assembly_reference=cohort_assembly_reference,
            max_attempts=3,
        ),
    )
    _add(
        documents,
        _campaign(
            name=f"{STUDY_ID}-pilot-compatibility-1080-1200",
            role="pilot-compatibility",
            workloads=pilot_ids,
            visits=1,
            policies=("as-defined",),
            defenses=_compatibility_defenses(pilot_bundle_reference),
            cohort_reference=cohort_reference,
            cohort_assembly_reference=cohort_assembly_reference,
            qualification_set=PILOT_QUALIFICATION_SET,
            defense_order_block=0,
            max_attempts=3,
        ),
    )
    _add(
        documents,
        _campaign(
            name=f"{STUDY_ID}-authoritative-fitting-1200",
            role="authoritative-fitting",
            workloads=final_ids,
            visits=10,
            policies=("as-defined", "half-duplex"),
            defenses=("undefended",),
            cohort_reference=cohort_reference,
            cohort_assembly_reference=cohort_assembly_reference,
            max_attempts=3,
        ),
    )
    _add(
        documents,
        _campaign(
            name=f"{STUDY_ID}-certification-900-1200",
            role="certification",
            workloads=final_ids,
            visits=1,
            policies=("as-defined",),
            defenses=_compatibility_defenses(authoritative_bundle_reference),
            cohort_reference=cohort_reference,
            cohort_assembly_reference=cohort_assembly_reference,
            qualification_set=FINAL_QUALIFICATION_SET,
            defense_order_block=0,
            max_attempts=1,
        ),
    )
    for block in range(1, 11):
        _add(
            documents,
            _campaign(
                name=f"{STUDY_ID}-canary-{block:02d}-1200",
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
            ),
        )
        _add(
            documents,
            _campaign(
                name=f"{STUDY_ID}-formal-{block:02d}-1200",
                role="formal",
                workloads=final_ids,
                visits=2,
                policies=("as-defined",),
                defenses=_formal_defenses(authoritative_bundle_reference),
                cohort_reference=cohort_reference,
                cohort_assembly_reference=cohort_assembly_reference,
                qualification_set=FINAL_QUALIFICATION_SET,
                defense_order_block=block - 1,
                # Certification is deliberately strict, but a 16,000-sample
                # acquisition must tolerate bounded transient collection
                # failures.  Every failed attempt remains sealed; only an
                # exactly accepted sample enters the classifier handoff.
                max_attempts=3,
            ),
        )
    _validate_generated_layout_references(
        documents,
        cohort_reference=cohort_reference,
        cohort_assembly_reference=cohort_assembly_reference,
        pilot_bundle_reference=pilot_bundle_reference,
        authoritative_bundle_reference=authoritative_bundle_reference,
        enforce_fresh_layout=_enforce_fresh_layout,
    )
    validate_campaign_documents(documents, pilot_ids=pilot_ids, final_ids=final_ids)
    return documents


def write_campaign_documents(
    cohort_receipt: Path,
    destination: Path,
    *,
    cohort_assembly_receipt: Path,
    **references: str,
) -> tuple[Path, ...]:
    """Create all campaign YAML files without replacing any existing file."""

    root = require_canonical_fresh_path(
        destination,
        field="campaign_root",
        label="class-study campaign destination",
    )
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"campaign destination must be a regular directory: {root}")
    cohort_path = require_canonical_fresh_child(
        cohort_receipt,
        field="study_config_root",
        filename=AUTHORITATIVE_COHORT_FILENAME,
        label="class-study cohort receipt",
    )
    assembly_path = require_canonical_fresh_child(
        cohort_assembly_receipt,
        field="study_config_root",
        filename=AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
        label="class-study cohort-assembly receipt",
    )
    references = dict(references)
    if "_enforce_fresh_layout" in references:
        raise ValueError("campaign publication cannot disable canonical fresh-layout validation")
    references.setdefault(
        "cohort_reference",
        canonical_campaign_reference(
            field="study_config_root",
            filename=cohort_path.name,
        ),
    )
    references.setdefault(
        "cohort_assembly_reference",
        canonical_campaign_reference(
            field="study_config_root",
            filename=assembly_path.name,
        ),
    )
    require_canonical_campaign_reference(
        references["cohort_reference"],
        field="study_config_root",
        filename=cohort_path.name,
        label="class-study cohort reference",
    )
    require_canonical_campaign_reference(
        references["cohort_assembly_reference"],
        field="study_config_root",
        filename=assembly_path.name,
        label="class-study cohort-assembly reference",
    )
    authoritative_documents = campaign_documents(
        cohort_path,
        cohort_assembly_receipt=assembly_path,
        **references,
    )
    layout = class_study_layout()
    pilot_cohort_path = require_canonical_fresh_child(
        layout.study_config_root / PILOT_COHORT_FILENAME,
        field="study_config_root",
        filename=PILOT_COHORT_FILENAME,
        label="pilot cohort receipt",
    )
    pilot_assembly_path = require_canonical_fresh_child(
        layout.study_config_root / PILOT_COHORT_ASSEMBLY_FILENAME,
        field="study_config_root",
        filename=PILOT_COHORT_ASSEMBLY_FILENAME,
        label="pilot cohort-assembly receipt",
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
            filename=PILOT_COHORT_FILENAME,
        ),
        cohort_assembly_reference=canonical_campaign_reference(
            field="study_config_root",
            filename=PILOT_COHORT_ASSEMBLY_FILENAME,
        ),
        pilot_bundle_reference=references.get(
            "pilot_bundle_reference", DEFAULT_PILOT_FINAL_REFERENCE
        ),
        authoritative_bundle_reference=references.get(
            "authoritative_bundle_reference", DEFAULT_AUTHORITATIVE_FINAL_REFERENCE
        ),
    )
    documents = {
        filename: (
            pilot_documents[filename]
            if document["evidence_role"] in {"pilot-fitting", "pilot-compatibility"}
            else document
        )
        for filename, document in authoritative_documents.items()
    }
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
        require_safe_campaign_reference(reference, label=label)

    if enforce_fresh_layout:
        canonical_admissions = {
            (
                canonical_campaign_reference(
                    field="study_config_root",
                    filename=PILOT_COHORT_FILENAME,
                ),
                canonical_campaign_reference(
                    field="study_config_root",
                    filename=PILOT_COHORT_ASSEMBLY_FILENAME,
                ),
            ),
            (DEFAULT_COHORT_REFERENCE, DEFAULT_COHORT_ASSEMBLY_REFERENCE),
        }
        if (cohort_reference, cohort_assembly_reference) not in canonical_admissions:
            raise ValueError(
                "class-study cohort references use an alternate class-study path; "
                "expected one exact canonical admission pair"
            )

    canonical = (
        (
            pilot_bundle_reference,
            DEFAULT_PILOT_FINAL_REFERENCE,
            "pilot_final_root",
            None,
            "pilot fitted-bundle reference",
        ),
        (
            authoritative_bundle_reference,
            DEFAULT_AUTHORITATIVE_FINAL_REFERENCE,
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
            )


def validate_campaign_documents(
    documents: Mapping[str, Mapping[str, Any]],
    *,
    pilot_ids: Sequence[str],
    final_ids: Sequence[str],
) -> None:
    """Validate the generated 24-file matrix and its exact sample arithmetic."""

    if len(documents) != 24 or len(set(documents)) != 24:
        raise ValueError("class-study campaign set must contain exactly 24 files")
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
    if role_counts != {
        "pilot-fitting": 1,
        "pilot-compatibility": 1,
        "authoritative-fitting": 1,
        "certification": 1,
        "canary": 10,
        "formal": 10,
    }:
        raise ValueError("class-study campaign role inventory is invalid")
    if sample_counts != {
        "pilot-fitting": 480,
        "pilot-compatibility": 1_080,
        "authoritative-fitting": 2_000,
        "certification": 900,
        "canary": 1_000,
        "formal": 16_000,
    }:
        raise ValueError("class-study campaign sample arithmetic is invalid")


def validate_campaign_document(
    document: Mapping[str, Any],
    *,
    cohort_receipt: Path,
    cohort_assembly_receipt: Path,
    enforce_fresh_layout: bool = True,
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
        pilot_role = role in {"pilot-fitting", "pilot-compatibility"}
        expected_cohort = canonical_campaign_reference(
            field="study_config_root",
            filename=(
                PILOT_COHORT_FILENAME if pilot_role else AUTHORITATIVE_COHORT_FILENAME
            ),
        )
        expected_assembly = canonical_campaign_reference(
            field="study_config_root",
            filename=(
                PILOT_COHORT_ASSEMBLY_FILENAME
                if pilot_role
                else AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
            ),
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
        else DEFAULT_PILOT_FINAL_REFERENCE
    )
    authoritative_bundle = (
        _document_fitted_bundle_reference(document)
        if role in {"certification", "formal"}
        else DEFAULT_AUTHORITATIVE_FINAL_REFERENCE
    )
    expected = campaign_documents(
        cohort_receipt,
        cohort_assembly_receipt=cohort_assembly_receipt,
        cohort_reference=cohort_reference,
        cohort_assembly_reference=assembly_reference,
        pilot_bundle_reference=pilot_bundle,
        authoritative_bundle_reference=authoritative_bundle,
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
    qualification_set: str | None = None,
    defense_order_block: int | None = None,
) -> dict[str, Any]:
    purpose = "fitting" if role.endswith("fitting") else "evaluation" if role == "formal" else "smoke"
    value: dict[str, Any] = {
        "schema": 2,
        "name": name,
        "purpose": purpose,
        "evidence_role": role,
        "seed": _seed(name),
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


def _seed(name: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{STUDY_ID}\0{name}".encode()).digest()[:4], "big")


def _add(documents: dict[str, dict[str, Any]], value: dict[str, Any]) -> None:
    filename = f"{value['name']}.yml"
    if filename in documents:
        raise AssertionError(f"duplicate generated campaign: {filename}")
    documents[filename] = value
