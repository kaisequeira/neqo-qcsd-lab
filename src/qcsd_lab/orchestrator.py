from __future__ import annotations

import base64
import csv
import fcntl
import json
import math
import os
import random
import re
import shutil
import stat
import tempfile
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import capture_session as capture_engine
from .defenses import defense_from_runtime_identity
from .experiment import (
    accepted_sample_hashes,
    resolved_attempt_directory,
    resolved_sample_directory,
    validate_planned_sample_identity,
)
from .fidelity import (
    BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US,
    _schedule_realization_metrics,
    fidelity_eligible,
    validate_primary_capture_clock_integrity,
)
from .manifest import (
    canonical_bytes,
    https_origin,
    runtime_manifest,
    validate_manifest,
    validate_research_preparation,
)
from .parameters import (
    BUFLO_STUDY_PARAMETER_KINDS,
    CONTROLLED_REGRESSION_ARTIFACT_TYPE,
    SEALED_RESEARCH_PARAMETER_KINDS,
    parameter_provenance_path,
    validate_frozen_parameter_artifact,
    validate_parameter_artifact,
)
from .profiles import UDP_PAYLOAD_CEILING_BY_PROFILE
from .util import (
    LAB_ROOT,
    SOURCE_METADATA_KEYS,
    atomic_json,
    discard_atomic_write_temps,
    load_json,
    response_signature,
    sha256_bytes,
    sha256_file,
    source_metadata,
)

SCHEMA_VERSION = 1
PURPOSES = {"smoke", "fitting", "evaluation"}
REQUEST_POLICIES = {"as-defined", "half-duplex"}
CAMPAIGN_KEYS = {
    "schema",
    "name",
    "purpose",
    "seed",
    "profile",
    "chaff_qualification_set",
    "defense_order",
    "workloads",
    "request_policies",
    "defenses",
    "limits",
    "study_controlled",
}
LIMIT_KEYS = {
    "timeout_seconds",
    "max_response_bytes",
    "capture_seconds",
    "capture_megabytes",
    "max_attempts",
    "per_origin_cooldown_seconds",
    "settle_seconds",
}
DEFENSE_KEYS = {"name", "kind", "schedule", "mode", "parameters"}
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
WALKIE_TALKIE_RECEIVER_RAW_HEADROOM_BYTES = 1_200
RESPONSE_ONLY_CHAFF_DEFENSE_KINDS = frozenset(
    {"front", "tamaraw", *BUFLO_STUDY_PARAMETER_KINDS}
)
RESPONSE_ONLY_CHAFF_SCOPE = "response-only"
FULL_CHAFF_SCOPE = "full"
RESPONSE_ONLY_MANIFEST_TO_SIDECAR_SCHEMA = {3: 1, 4: 2}
FITTING_LIMITS = capture_engine.Limits(
    timeout_seconds=120,
    max_response_bytes=1024 * 1024,
    capture_seconds=180,
    capture_megabytes=64,
    max_attempts=3,
    per_origin_cooldown_seconds=30.0,
    settle_seconds=1.0,
)


class CampaignIncomplete(RuntimeError):
    """A completed run that did not produce every required eligible sample."""

    def __init__(self, root: Path):
        self.root = root
        super().__init__(f"campaign incomplete; evidence retained at {root}")


@dataclass(frozen=True)
class Workload:
    id: str
    visits: int
    path: Path
    source_bytes: bytes
    sha256: str
    data: dict[str, Any]
    resource_count: int
    origin_count: int
    runtime_path: Path | None = None
    runtime_sha256: str | None = None
    chaff_qualification_path: Path | None = None
    chaff_qualification_sha256: str | None = None
    chaff_qualification_scope: str | None = None
    chaff_prefix_spec_path: Path | None = None
    chaff_prefix_spec_sha256: str | None = None
    chaff_manifest_path: Path | None = None
    chaff_manifest_sha256: str | None = None
    chaff_manifest_data: dict[str, Any] | None = None


@dataclass(frozen=True)
class Campaign:
    path: Path
    source_bytes: bytes
    name: str
    purpose: str
    seed: int
    profile: str
    workloads: tuple[Workload, ...]
    request_policies: tuple[str, ...]
    defenses: tuple[capture_engine.Defense, ...]
    limits: capture_engine.Limits
    chaff_qualification_set: str | None = None
    defense_order_scheme: str = "seeded-shuffle"
    defense_order_block: int | None = None
    study_controlled: Mapping[str, Any] | None = None

    @property
    def udp_payload_ceiling(self) -> int:
        return UDP_PAYLOAD_CEILING_BY_PROFILE[self.profile]


@dataclass(frozen=True)
class _RunContext:
    qcsd_profile: str
    request_policy: str
    limits: capture_engine.Limits
    udp_payload_ceiling: int


def _slug(value: str) -> str:
    return capture_engine.slug(value)


def _stable_digest(*parts: object) -> str:
    return capture_engine.stable_digest(*parts)


def _stable_seed(*parts: object) -> int:
    return int(_stable_digest(*parts)[:16], 16)


def _reject_unknown(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{location} contains unsupported fields: {', '.join(sorted(unknown))}")


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be an object")
    return dict(value)


def load_campaign(path: Path) -> Campaign:
    """Load the single consolidated campaign schema."""

    return _load_campaign(
        path,
        frozen_inputs=None,
        allow_historical_research_bundle=False,
    )


def _load_campaign(
    path: Path,
    *,
    frozen_inputs: Path | None,
    allow_historical_research_bundle: bool = False,
) -> Campaign:
    path = path.resolve()
    try:
        source_bytes = path.read_bytes()
        source = yaml.safe_load(source_bytes.decode("utf-8"))
    except UnicodeError as error:
        raise ValueError("campaign YAML is not valid UTF-8") from error
    except yaml.YAMLError as error:
        raise ValueError(f"campaign YAML is invalid: {error}") from error
    value = _object(source, "campaign")
    _reject_unknown(value, CAMPAIGN_KEYS, "campaign")
    required = {
        "schema",
        "name",
        "purpose",
        "seed",
        "profile",
        "workloads",
        "request_policies",
        "defenses",
    }
    missing = required - set(value)
    if missing:
        raise ValueError(f"campaign is missing: {', '.join(sorted(missing))}")
    if value["schema"] != SCHEMA_VERSION:
        raise ValueError(f"campaign schema must be {SCHEMA_VERSION}")
    if "chaff_qualification_set" not in value:
        qualification_set = None
    else:
        from .chaff_qualification import validate_qualification_set

        qualification_set = validate_qualification_set(value["chaff_qualification_set"])
    purpose = value["purpose"]
    if not isinstance(purpose, str):
        raise ValueError("campaign purpose must be a string")
    if purpose not in PURPOSES:
        raise ValueError("campaign purpose must be smoke, fitting, or evaluation")
    profile = value["profile"]
    if not isinstance(profile, str):
        raise ValueError("campaign profile must be a string")
    if profile not in UDP_PAYLOAD_CEILING_BY_PROFILE:
        choices = ", ".join(sorted(UDP_PAYLOAD_CEILING_BY_PROFILE))
        raise ValueError(f"campaign profile must be one of: {choices}")
    seed = value["seed"]
    if type(seed) is not int or seed < 0:
        raise ValueError("campaign seed must be a non-negative integer")
    policies = value["request_policies"]
    if (
        not isinstance(policies, list)
        or not policies
        or len(policies) != len(set(policies))
        or any(policy not in REQUEST_POLICIES for policy in policies)
    ):
        raise ValueError("request_policies must contain unique as-defined/half-duplex values")
    defense_order_scheme, defense_order_block = _load_defense_order(value.get("defense_order"))
    study_controlled = None
    if "study_controlled" in value:
        from .buflo_study import validate_controlled_campaign_receipt

        study_controlled = validate_controlled_campaign_receipt(value["study_controlled"])
        if purpose != "smoke":
            raise ValueError("controlled study metadata is valid only for smoke campaigns")
    config_root = _campaign_config_root(path, frozen_inputs=frozen_inputs)
    workloads = _load_workloads(
        path,
        value["workloads"],
        purpose=purpose,
        frozen_inputs=frozen_inputs,
        config_root=config_root,
    )
    defenses = _load_defenses(
        config_root / "campaigns",
        value["defenses"],
        purpose,
        profile,
        {workload.id: workload.sha256 for workload in workloads},
        frozen_inputs=frozen_inputs,
        allow_historical_research_bundle=allow_historical_research_bundle,
    )
    has_defended_run = any(not defense.baseline for defense in defenses)
    qualification_scope = _required_chaff_qualification_scope(defenses)
    if qualification_set is not None and qualification_scope != RESPONSE_ONLY_CHAFF_SCOPE:
        raise ValueError("chaff_qualification_set requires a response-only defended runtime")
    current_prepared_inputs = all(
        isinstance(workload.data.get("preparation"), Mapping) for workload in workloads
    )
    historical_research_inputs = (
        frozen_inputs is not None
        and any(
            defense.parameters_input_policy == "sealed-fitting-result-v1"
            and defense.kind == "walkie_talkie"
            and defense.parameters_path is not None
            and load_json(defense.parameters_path).get("schema_version") in {2, 5}
            for defense in defenses
        )
        and not (frozen_inputs / "chaff-qualifications").is_dir()
    )
    # Fitting is definitionally undefended and its contract validator below
    # rejects any defense mutation.  Qualification evidence is an excluded
    # runtime input and must never be consulted while resolving fitting data.
    if has_defended_run and purpose != "fitting" and not historical_research_inputs:
        if not current_prepared_inputs:
            raise ValueError(
                "every defended campaign requires research-prepared workloads and qualified chaff"
            )
        if qualification_scope is None:
            raise AssertionError("defended campaign has no chaff qualification scope")
        workloads = _load_qualified_chaff_inputs(
            path,
            workloads,
            frozen_inputs=frozen_inputs,
            qualification_scope=qualification_scope,
            qualification_set=qualification_set,
            config_root=config_root,
        )
    _validate_loaded_qualification_bindings(defenses, workloads)
    if any(_uses_schema_six_walkie_talkie(defense) for defense in defenses):
        if not all(workload.chaff_manifest_data is not None for workload in workloads):
            raise ValueError("schema-six Walkie-Talkie requires qualified chaff for every workload")
        _validate_walkie_talkie_resource_preconditions(workloads)
    raw_limits = value.get("limits", {})
    limits = _load_limits(raw_limits)
    name = value["name"]
    if not isinstance(name, str) or _slug(name) != name:
        raise ValueError("campaign name must be a filesystem-safe identifier")
    campaign = Campaign(
        path=path,
        source_bytes=source_bytes,
        name=name,
        purpose=purpose,
        seed=seed,
        profile=profile,
        workloads=workloads,
        request_policies=tuple(policies),
        defenses=defenses,
        limits=limits,
        chaff_qualification_set=qualification_set,
        defense_order_scheme=defense_order_scheme,
        defense_order_block=defense_order_block,
        study_controlled=study_controlled,
    )
    if purpose == "fitting":
        _validate_fitting_campaign(campaign, raw_limits=raw_limits)
    return campaign


def _uses_schema_six_walkie_talkie(defense: capture_engine.Defense) -> bool:
    """Identify the only current runtime contract that requires qualified chaff."""

    if defense.kind != "walkie_talkie":
        return False
    if defense.parameters_path is None:
        raise ValueError("walkie_talkie defense has no resolved parameter artifact")
    parameter = load_json(defense.parameters_path)
    return isinstance(parameter, Mapping) and parameter.get("schema_version") == 6


def _required_chaff_qualification_scope(
    defenses: tuple[capture_engine.Defense, ...],
) -> str | None:
    """Select one qualification contract from the resolved runtime defense kinds."""

    defended_kinds = {defense.kind for defense in defenses if not defense.baseline}
    if not defended_kinds:
        return None
    if defended_kinds <= RESPONSE_ONLY_CHAFF_DEFENSE_KINDS:
        return RESPONSE_ONLY_CHAFF_SCOPE
    return FULL_CHAFF_SCOPE


def _load_qualified_chaff_inputs(
    campaign_path: Path,
    workloads: tuple[Workload, ...],
    *,
    frozen_inputs: Path | None,
    qualification_scope: str = FULL_CHAFF_SCOPE,
    qualification_set: str | None = None,
    config_root: Path | None = None,
) -> tuple[Workload, ...]:
    """Bind the selected immutable sidecar contract and derived manifest."""

    from .chaff_qualification import load_qualified_chaff, load_response_qualified_chaff

    if frozen_inputs is not None:
        qualification_scope = _frozen_chaff_qualification_scope(
            frozen_inputs,
            workloads,
            defense_derived_scope=qualification_scope,
        )
    if frozen_inputs is None:
        config_root = campaign_path.parent.parent if config_root is None else config_root
        if qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE:
            if qualification_set is None:
                qualification_root = config_root / "chaff-response-qualification-store/v2"
            else:
                from .chaff_qualification import validate_qualification_set

                qualification_set = validate_qualification_set(qualification_set)
                qualification_root = _trusted_regular_directory(
                    config_root / "chaff-response-qualification-store" / "sets" / qualification_set,
                    root=config_root,
                    label="selected response qualification set",
                )
                expected_names = {f"{workload.id}.json" for workload in workloads}
                entries = list(qualification_root.iterdir())
                if {entry.name for entry in entries} != expected_names or any(
                    entry.is_symlink() or not entry.is_file() for entry in entries
                ):
                    raise ValueError(
                        "selected response qualification set does not contain the exact "
                        "campaign workload cohort"
                    )
            prefix_root: Path | None = None
        elif qualification_scope == FULL_CHAFF_SCOPE:
            qualification_root = config_root / "chaff-qualification-store/v2"
            prefix_root = config_root / "chaff-prefix-specs/v2"
        else:
            raise ValueError(f"unsupported chaff qualification scope: {qualification_scope}")
        manifest_root: Path | None = None
    else:
        config_root = frozen_inputs
        qualification_root = frozen_inputs / "chaff-qualifications"
        prefix_root = (
            None
            if qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE
            else frozen_inputs / "chaff-prefix-specs"
        )
        manifest_root = frozen_inputs / "chaff-manifests"
    qualified: list[Workload] = []
    for workload in workloads:
        if manifest_root is None:
            manifest_path = None
        else:
            manifest_path = _trusted_regular_input(
                manifest_root / f"{workload.id}.json",
                root=config_root,
                label="frozen qualified chaff manifest",
            )
        sidecar_path = _trusted_regular_input(
            qualification_root / f"{workload.id}.json",
            root=config_root,
            label="chaff qualification sidecar",
        )
        if qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE:
            spec_path = None
            expected_sidecar_schema_version = (
                2
                if manifest_path is None
                else _response_only_sidecar_schema_for_manifest(load_json(manifest_path))
            )
            receipt = load_response_qualified_chaff(
                sidecar_path,
                workload_id=workload.id,
                base_manifest_path=workload.path,
                expected_sidecar_schema_version=expected_sidecar_schema_version,
                require_current_implementation=frozen_inputs is None,
            )
        else:
            if prefix_root is None:
                raise AssertionError("full chaff qualification has no prefix-spec root")
            spec_path = _trusted_regular_input(
                prefix_root / f"{workload.id}.json",
                root=config_root,
                label="chaff prefix-pack specification",
            )
            receipt = load_qualified_chaff(
                sidecar_path,
                workload_id=workload.id,
                base_manifest_path=workload.path,
                prefix_spec_path=spec_path,
                require_current_implementation=frozen_inputs is None,
            )
        if manifest_path is not None:
            if sha256_file(manifest_path) != receipt.manifest_sha256:
                raise ValueError(f"frozen qualified chaff manifest SHA-256 mismatch: {workload.id}")
        qualified.append(
            replace(
                workload,
                chaff_qualification_path=sidecar_path,
                chaff_qualification_sha256=receipt.sidecar_sha256,
                chaff_qualification_scope=qualification_scope,
                chaff_prefix_spec_path=spec_path,
                chaff_prefix_spec_sha256=(sha256_file(spec_path) if spec_path else None),
                chaff_manifest_path=manifest_path,
                chaff_manifest_sha256=receipt.manifest_sha256,
                chaff_manifest_data=receipt.manifest,
            )
        )
    return tuple(qualified)


def _frozen_chaff_qualification_scope(
    frozen_inputs: Path,
    workloads: tuple[Workload, ...],
    *,
    defense_derived_scope: str,
) -> str:
    """Select the contract recorded by frozen evidence, never today's routing policy."""

    prefix_root = frozen_inputs / "chaff-prefix-specs"
    prefix_present = prefix_root.exists() or prefix_root.is_symlink()
    if prefix_present and (prefix_root.is_symlink() or not prefix_root.is_dir()):
        raise ValueError("frozen chaff prefix-spec root is not a regular directory")
    response_versions: list[int | None] = []
    for workload in workloads:
        manifest_path = _trusted_regular_input(
            frozen_inputs / "chaff-manifests" / f"{workload.id}.json",
            root=frozen_inputs,
            label="frozen qualified chaff manifest",
        )
        manifest = load_json(manifest_path)
        response_versions.append(
            manifest.get("schema_version")
            if isinstance(manifest, Mapping)
            and type(manifest.get("schema_version")) is int
            and manifest.get("schema_version") in {3, 4}
            and manifest.get("qualification_scope") == RESPONSE_ONLY_CHAFF_SCOPE
            else None
        )
    if prefix_present:
        if any(version is not None for version in response_versions):
            raise ValueError(
                "frozen chaff evidence ambiguously contains response-only manifests and prefix specs"
            )
        return FULL_CHAFF_SCOPE
    if any(version is None for version in response_versions):
        raise ValueError(
            "frozen response-only chaff evidence requires explicit schema-three scope markers "
            "or explicit schema-four scope markers"
        )
    if len(set(response_versions)) != 1:
        raise ValueError("frozen response-only chaff evidence mixes schema-three and schema-four")
    if defense_derived_scope != RESPONSE_ONLY_CHAFF_SCOPE:
        raise ValueError("response-only frozen chaff is incompatible with the campaign defenses")
    return RESPONSE_ONLY_CHAFF_SCOPE


def _response_only_sidecar_schema_for_manifest(value: object) -> int:
    """Map an exact response-only runtime schema to its immutable sidecar schema."""

    if (
        not isinstance(value, Mapping)
        or value.get("qualification_scope") != RESPONSE_ONLY_CHAFF_SCOPE
    ):
        raise ValueError("response-only chaff manifest scope marker is invalid")
    schema_version = value.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version not in RESPONSE_ONLY_MANIFEST_TO_SIDECAR_SCHEMA
    ):
        raise ValueError("response-only chaff manifest schema version is invalid")
    return RESPONSE_ONLY_MANIFEST_TO_SIDECAR_SCHEMA[schema_version]


def _trusted_regular_input(path: Path, *, root: Path, label: str) -> Path:
    """Reject a symlink or escape before resolving a trusted campaign input."""

    candidate = Path(path)
    boundary = Path(root)
    if boundary.is_symlink() or not boundary.is_dir():
        raise ValueError(f"trusted campaign input root is not a regular directory: {boundary}")
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{label} is not a regular file: {candidate}")
    cursor = candidate.parent
    while cursor != boundary and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError(f"{label} contains a symbolic-link component: {cursor}")
        cursor = cursor.parent
    if cursor != boundary:
        raise ValueError(f"{label} escapes the trusted campaign input root: {candidate}")
    resolved_root = boundary.resolve()
    resolved = candidate.resolve()
    if resolved_root not in resolved.parents:
        raise ValueError(f"{label} escapes the trusted campaign input root: {candidate}")
    return resolved


def _trusted_regular_directory(path: Path, *, root: Path, label: str) -> Path:
    """Reject a symlink or escape before resolving a trusted campaign directory."""

    candidate = Path(path)
    boundary = Path(root)
    if boundary.is_symlink() or not boundary.is_dir():
        raise ValueError(f"trusted campaign input root is not a regular directory: {boundary}")
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError(f"{label} is not a regular directory: {candidate}")
    cursor = candidate.parent
    while cursor != boundary and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError(f"{label} contains a symbolic-link component: {cursor}")
        cursor = cursor.parent
    if cursor != boundary:
        raise ValueError(f"{label} escapes the trusted campaign input root: {candidate}")
    resolved_root = boundary.resolve()
    resolved = candidate.resolve()
    if resolved_root not in resolved.parents:
        raise ValueError(f"{label} escapes the trusted campaign input root: {candidate}")
    return resolved


def _validate_loaded_qualification_bindings(
    defenses: tuple[capture_engine.Defense, ...],
    workloads: tuple[Workload, ...],
) -> None:
    """Cross-link actual qualified inputs to every loaded schema-six bundle."""

    expected = {
        workload.id: {
            "workload_id": workload.id,
            "chaff_qualification_sidecar_sha256": workload.chaff_qualification_sha256,
            "prefix_pack_spec_sha256": workload.chaff_prefix_spec_sha256,
            "qualified_chaff_manifest_sha256": workload.chaff_manifest_sha256,
            "application_resource_id": (
                workload.chaff_manifest_data.get("application_resource_id")
                if isinstance(workload.chaff_manifest_data, Mapping)
                else None
            ),
            "selected_chaff_resource_id": (
                workload.chaff_manifest_data.get("selected_chaff_resource_id")
                if isinstance(workload.chaff_manifest_data, Mapping)
                else None
            ),
            "qualified_parallel_chaff_streams": (
                workload.chaff_manifest_data.get("qualified_parallel_chaff_streams")
                if isinstance(workload.chaff_manifest_data, Mapping)
                else None
            ),
            "walkie_talkie_required_chaff_streams": (
                workload.chaff_manifest_data.get("walkie_talkie_required_chaff_streams")
                if isinstance(workload.chaff_manifest_data, Mapping)
                else None
            ),
        }
        for workload in workloads
    }
    for defense in defenses:
        if defense.parameters_provenance_path is None:
            continue
        provenance = load_json(defense.parameters_provenance_path)
        if provenance.get("artifact_type") == CONTROLLED_REGRESSION_ARTIFACT_TYPE:
            if defense.parameters_path is None:
                raise ValueError("controlled regression defense has no parameter file")
            parameter = load_json(defense.parameters_path)
            raw_bindings = parameter.get("qualification_bindings")
            if not isinstance(raw_bindings, list):
                raise ValueError("controlled regression lacks qualification bindings")
            bindings = {
                record.get("workload_id"): dict(record)
                for record in raw_bindings
                if isinstance(record, Mapping)
                and isinstance(record.get("workload_id"), str)
            }
            if any(
                bindings.get(workload_id) != record
                for workload_id, record in expected.items()
            ):
                raise ValueError(
                    "controlled regression parameters do not match loaded chaff qualifications"
                )
            continue
        contract = provenance.get("fitting_contract")
        if not isinstance(contract, Mapping) or contract.get("contract_version") != 6:
            continue
        from .fitting import _qualification_bindings_from_provenance

        if any(value is None for record in expected.values() for value in record.values()):
            raise ValueError("schema-six bundle requires qualified chaff for every workload")
        bindings = {
            record["workload_id"]: record
            for record in _qualification_bindings_from_provenance(provenance)
        }
        if any(bindings.get(workload_id) != record for workload_id, record in expected.items()):
            raise ValueError(
                "loaded chaff qualifications do not match schema-six Walkie-Talkie bindings"
            )


def _validate_walkie_talkie_resource_preconditions(
    workloads: tuple[Workload, ...],
) -> None:
    """Reject manifests that cannot provision the schema-five reserve horizon."""

    for workload in workloads:
        if workload.chaff_manifest_data is None:
            raise ValueError(f"{workload.id} qualified chaff manifest is missing")
        manifest = workload.chaff_manifest_data
        _validate_walkie_talkie_resource_precondition(
            manifest,
            workload_id=workload.id,
            endpoint_origins=set(capture_engine._manifest_origins(manifest)),
        )


def _validate_walkie_talkie_resource_precondition(
    manifest: Mapping[str, Any],
    *,
    workload_id: str,
    endpoint_origins: set[str],
) -> None:
    """Mirror the initial chaff selector and require one full continuation cell."""

    resources = manifest.get("resources")
    eligible: list[Mapping[str, Any]] = (
        [
            resource
            for resource in resources
            if isinstance(resource, Mapping)
            and resource.get("known_valid") is True
            and resource.get("depends_on", []) == []
            and _manifest_resource_effective_length(resource) > 0
            and https_origin(str(resource.get("url", ""))) in endpoint_origins
        ]
        if isinstance(resources, list)
        else []
    )
    priority_only = any(resource.get("chaff_priority") is True for resource in eligible)
    candidates = [
        resource
        for resource in eligible
        if not priority_only or resource.get("chaff_priority") is True
    ]
    selected = (
        max(
            candidates,
            key=lambda resource: (
                _manifest_resource_effective_length(resource),
                _manifest_resource_type_rank(resource),
                int(resource.get("id", 0)),
            ),
        )
        if candidates
        else None
    )
    if (
        selected is None
        or _manifest_resource_effective_length(selected) < WALKIE_TALKIE_RECEIVER_RAW_HEADROOM_BYTES
    ):
        raise ValueError(
            f"walkie_talkie workload {workload_id!r} initial chaff selection must yield a "
            "known-valid, dependency-free resource matching a request endpoint origin with "
            f"effective length at least {WALKIE_TALKIE_RECEIVER_RAW_HEADROOM_BYTES} bytes"
        )


def _manifest_resource_effective_length(resource: Mapping[str, Any]) -> int:
    """Mirror Neqo's Resource::effective_length for a validated manifest resource."""

    content_length = resource.get("content_length")
    content = 1 if content_length is None else int(content_length)
    return max(content, int(resource.get("data_length", 0)))


def _manifest_resource_type_rank(resource: Mapping[str, Any]) -> int:
    """Mirror Neqo's final deterministic tie-break after effective length."""

    kind = resource.get("type")
    if kind == "Image":
        return 4
    if kind in {"Font", "Stylesheet", "Script"}:
        return 3
    return 2 if kind == "Document" else 1


def _validate_fitting_campaign(campaign: Campaign, *, raw_limits: Any) -> None:
    """Reject an underspecified fitting capture before any traffic can run."""

    prefix = "research fitting campaigns require"
    if campaign.name != "research-fitting-1200":
        raise ValueError(f"{prefix} the exact name research-fitting-1200")
    if campaign.seed != 2_026_081_201:
        raise ValueError(f"{prefix} the fixed seed 2026081201")
    if campaign.profile != "research-1200":
        raise ValueError(f"{prefix} profile research-1200")
    if len(campaign.workloads) != 6:
        raise ValueError(f"{prefix} exactly six unique workloads")
    if any(workload.visits != 10 for workload in campaign.workloads):
        raise ValueError(f"{prefix} exactly ten visits per workload")
    if campaign.request_policies != ("as-defined", "half-duplex"):
        raise ValueError(f"{prefix} request policies in exact order: as-defined, then half-duplex")
    if len(campaign.defenses) != 1:
        raise ValueError(f"{prefix} exactly one undefended baseline")
    defense = campaign.defenses[0]
    if defense.name != "undefended" or defense.kind != "none" or defense.baseline is not True:
        raise ValueError(f"{prefix} the canonical undefended baseline with runtime kind none")
    if not isinstance(raw_limits, dict) or set(raw_limits) != LIMIT_KEYS:
        raise ValueError(f"{prefix} every explicit capture, retry, cooldown, and settle limit")
    if campaign.limits != FITTING_LIMITS:
        raise ValueError(
            f"{prefix} the fixed 120-second/1-MiB/180-second/64-MiB/"
            "3-attempt/30-second/1-second limits"
        )


def _validate_fitting_capture_source(source: object) -> None:
    """Require concrete, clean and submodule-pinned runtime image provenance."""

    prefix = "research fitting capture requires"
    if not isinstance(source, dict) or set(source) != SOURCE_METADATA_KEYS:
        raise ValueError(f"{prefix} complete source/image provenance")
    image = source.get("image_digest")
    if not (
        isinstance(image, str)
        and image.startswith("sha256:")
        and _lower_hex_digest(image.removeprefix("sha256:"), length=64)
    ):
        raise ValueError(f"{prefix} a concrete image SHA-256 digest")
    if source.get("lab_dirty") is not False or source.get("neqo_dirty") is not False:
        raise ValueError(f"{prefix} clean lab and Neqo sources")
    if (
        source.get("lab_patch_sha256") != EMPTY_SHA256
        or source.get("neqo_patch_sha256") != EMPTY_SHA256
    ):
        raise ValueError(f"{prefix} empty source patch hashes")
    for key in ("lab_commit", "neqo_commit", "neqo_pinned_commit"):
        if not _lower_hex_digest(source.get(key), length=40):
            raise ValueError(f"{prefix} a valid {key}")
    if source["neqo_commit"] != source["neqo_pinned_commit"]:
        raise ValueError(f"{prefix} a runtime Neqo commit equal to the pinned submodule")


def _lower_hex_digest(value: object, *, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _workload_root(campaign_path: Path) -> Path:
    # Campaigns conventionally live under config/campaigns and workloads under
    # config/workloads. Keeping this one convention removes another path knob.
    return campaign_path.parent.parent / "workloads"


def _campaign_config_root(path: Path, *, frozen_inputs: Path | None) -> Path:
    if frozen_inputs is not None:
        return frozen_inputs
    generated = (LAB_ROOT / "artifacts/buflo-study/cohort-inputs").resolve()
    if path.is_relative_to(generated):
        relative = path.relative_to(generated)
        if (
            len(relative.parts) != 3
            or re.fullmatch(r"v[1-9][0-9]*", relative.parts[0]) is None
            or relative.parts[1] != "campaigns"
            or re.fullmatch(
                r"buflo-study-v1-(?:smoke|rehearsal|formal-[0-9]{2})[.]yml",
                relative.parts[2],
            )
            is None
        ):
            raise ValueError("resolved cohort campaign path is invalid")
        return (LAB_ROOT / "config").resolve()
    return path.parent.parent


def _load_workloads(
    path: Path,
    raw: Any,
    *,
    purpose: str,
    frozen_inputs: Path | None = None,
    config_root: Path | None = None,
) -> tuple[Workload, ...]:
    value = _object(raw, "workloads")
    if not value:
        raise ValueError("campaign requires at least one workload")
    root = (
        frozen_inputs / "workloads"
        if frozen_inputs is not None
        else (config_root or path.parent.parent) / "workloads"
    )
    result: list[Workload] = []
    seen: set[str] = set()
    for identifier, raw_visits in value.items():
        if not isinstance(identifier, str) or _slug(identifier) != identifier:
            raise ValueError("workload IDs must be filesystem-safe strings")
        workload_id = identifier
        if workload_id in seen:
            raise ValueError(f"duplicate workload {workload_id}")
        seen.add(workload_id)
        if type(raw_visits) is not int or raw_visits < 1:
            raise ValueError("workload visit counts must be positive integers")
        manifest_path = _trusted_regular_input(
            root / f"{workload_id}.json",
            root=(frozen_inputs if frozen_inputs is not None else (config_root or path.parent.parent)),
            label="workload manifest",
        )
        try:
            source_bytes = manifest_path.read_bytes()
            manifest = json.loads(source_bytes.decode("utf-8"))
        except UnicodeError as error:
            raise ValueError(f"workload manifest is not valid UTF-8: {manifest_path}") from error
        validate_manifest(manifest)
        if purpose in {"fitting", "evaluation"}:
            validate_research_preparation(manifest, workload_id=workload_id)
        runtime = runtime_manifest(manifest)
        runtime_bytes = canonical_bytes(runtime)
        runtime_candidate = (
            frozen_inputs / "runtime-workloads" / f"{workload_id}.json"
            if frozen_inputs is not None
            else None
        )
        runtime_path = (
            _trusted_regular_input(
                runtime_candidate,
                root=frozen_inputs,
                label="frozen runtime workload",
            )
            if runtime_candidate is not None
            and (runtime_candidate.exists() or runtime_candidate.is_symlink())
            else None
        )
        if runtime_path is not None and runtime_path.read_bytes() != runtime_bytes:
            raise ValueError(f"frozen runtime workload differs from prepared source: {workload_id}")
        origins = capture_engine._manifest_origins(runtime)
        result.append(
            Workload(
                id=workload_id,
                visits=raw_visits,
                path=manifest_path,
                source_bytes=source_bytes,
                sha256=sha256_bytes(source_bytes),
                data=manifest,
                resource_count=len(runtime["resources"]),
                origin_count=len(origins),
                runtime_path=runtime_path,
                runtime_sha256=sha256_bytes(runtime_bytes),
            )
        )
    return tuple(result)


def _load_limits(raw: Any) -> capture_engine.Limits:
    value = _object(raw, "limits")
    _reject_unknown(value, LIMIT_KEYS, "limits")
    limits = capture_engine.Limits(
        timeout_seconds=_integer_limit(value, "timeout_seconds", 45),
        max_response_bytes=_integer_limit(value, "max_response_bytes", 512 * 1024),
        capture_seconds=_integer_limit(value, "capture_seconds", 60),
        capture_megabytes=_integer_limit(value, "capture_megabytes", 64),
        max_attempts=_integer_limit(value, "max_attempts", 3),
        per_origin_cooldown_seconds=_numeric_limit(value, "per_origin_cooldown_seconds", 30),
        settle_seconds=_numeric_limit(value, "settle_seconds", 1),
    )
    if (
        min(
            limits.timeout_seconds,
            limits.max_response_bytes,
            limits.capture_seconds,
            limits.capture_megabytes,
        )
        < 1
    ):
        raise ValueError("timeout, response, and capture limits must be positive")
    if not 1 <= limits.max_attempts <= 3:
        raise ValueError("max_attempts must be between one and three")
    if min(limits.per_origin_cooldown_seconds, limits.settle_seconds) < 0:
        raise ValueError("cooldown and settle limits cannot be negative")
    if limits.settle_seconds > 5:
        raise ValueError("settle_seconds must not exceed five")
    if limits.capture_seconds < limits.timeout_seconds + limits.settle_seconds + 1:
        raise ValueError("capture_seconds must cover timeout, settle, and collector startup")
    return limits


def _load_defense_order(raw: Any) -> tuple[str, int | None]:
    if raw is None:
        return "seeded-shuffle", None
    value = _object(raw, "defense_order")
    _reject_unknown(value, {"scheme", "block"}, "defense_order")
    if set(value) != {"scheme", "block"}:
        raise ValueError("defense_order requires scheme and block")
    block = value.get("block")
    if value.get("scheme") != "cyclic-latin-square" or type(block) is not int or block < 0:
        raise ValueError("defense_order must select a non-negative cyclic-latin-square block")
    return "cyclic-latin-square", block


def _integer_limit(value: dict[str, Any], name: str, default: int) -> int:
    candidate = value.get(name, default)
    if type(candidate) is not int:
        raise ValueError(f"limits.{name} must be an integer")
    return candidate


def _numeric_limit(value: dict[str, Any], name: str, default: int) -> float:
    candidate = value.get(name, default)
    if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
        raise ValueError(f"limits.{name} must be a number")
    result = float(candidate)
    if not math.isfinite(result):
        raise ValueError(f"limits.{name} must be finite")
    return result


def _load_defenses(
    base: Path,
    raw: Any,
    purpose: str,
    profile: str,
    workloads: Mapping[str, str],
    *,
    frozen_inputs: Path | None = None,
    allow_historical_research_bundle: bool = False,
) -> tuple[capture_engine.Defense, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("defenses must be a non-empty list")
    defenses: list[capture_engine.Defense] = []
    names: set[str] = set()
    evaluation_bundle_root: Path | None = None
    for item in raw:
        if not isinstance(item, (str, dict)):
            raise ValueError("each defense must be a name or object")
        value = {"name": item} if isinstance(item, str) else dict(item)
        _reject_unknown(value, DEFENSE_KEYS, "defense")
        raw_name = value.get("name", value.get("kind", ""))
        if not isinstance(raw_name, str) or _slug(raw_name) != raw_name:
            raise ValueError("defense name must be a filesystem-safe string")
        name = raw_name
        if name in names:
            raise ValueError(f"duplicate defense {name}")
        names.add(name)
        raw_kind = value.get("kind", "none" if name == "undefended" else name)
        if not isinstance(raw_kind, str):
            raise ValueError("defense kind must be a string")
        kind = raw_kind
        kind = kind.lower().replace("-", "_")
        if kind not in capture_engine.SUPPORTED_DEFENSE_KINDS:
            raise ValueError(f"unsupported defense kind: {kind}")
        # A custom experiment label may alias any supported runtime kind, but a
        # canonical scientific identity must never silently select a different
        # implementation (for example, ``front`` bound to ``tamaraw``).
        defense_from_runtime_identity(name, kind)
        baseline = name == "undefended" or kind == "none"
        if kind == "static":
            schedule = value.get("schedule")
            mode = value.get("mode", "")
            if (
                not isinstance(schedule, str)
                or not schedule
                or not isinstance(mode, str)
                or mode not in capture_engine.STATIC_MODES
            ):
                raise ValueError("Static requires schedule and mode")
            schedule_path = (
                (frozen_inputs / "defense-parameters" / name / "schedule.csv").resolve()
                if frozen_inputs is not None
                else (base / str(schedule)).resolve()
            )
            if not schedule_path.is_file():
                raise ValueError(f"Static schedule does not exist: {schedule}")
            _validate_static_schedule(
                schedule_path,
                udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
            )
            defenses.append(
                capture_engine.Defense(
                    name=name,
                    kind=kind,
                    baseline=baseline,
                    schedule=str(schedule),
                    schedule_path=schedule_path,
                    schedule_sha256=sha256_file(schedule_path),
                    mode=mode,
                )
            )
            continue
        if "schedule" in value or "mode" in value:
            raise ValueError("schedule and mode are valid only for Static")
        if kind in capture_engine.PARAMETER_FLAG_BY_KIND:
            parameters = value.get("parameters")
            if not isinstance(parameters, str) or not parameters:
                raise ValueError(f"{kind} requires a parameter file")
            original_name = Path(parameters).name
            if frozen_inputs is None:
                parameters_path = (base / str(parameters)).resolve()
                provenance_path = parameter_provenance_path(parameters_path)
            else:
                research_dir = frozen_inputs / "defense-parameters" / "research-1200"
                if kind in SEALED_RESEARCH_PARAMETER_KINDS and (
                    purpose == "evaluation" or (research_dir / original_name).is_file()
                ):
                    parameters_path = (research_dir / original_name).resolve()
                    provenance_path = (research_dir / "provenance.json").resolve()
                else:
                    artifact_dir = frozen_inputs / "defense-parameters" / name
                    parameters_path = (artifact_dir / "parameters.json").resolve()
                    provenance_path = (artifact_dir / "provenance.json").resolve()

            if purpose == "evaluation" and kind in SEALED_RESEARCH_PARAMETER_KINDS:
                from .fitting import (
                    BUNDLE_FILES,
                    _verify_current_artifact_bundle_at,
                    verify_frozen_artifact_bundle,
                )

                bundle_root = parameters_path.parent
                if evaluation_bundle_root is not None and bundle_root != evaluation_bundle_root:
                    raise ValueError(
                        "evaluation data-driven defenses must reference one common sealed "
                        "research bundle"
                    )
                if evaluation_bundle_root is None:
                    if not bundle_root.is_dir() or bundle_root.is_symlink():
                        raise ValueError(
                            f"evaluation campaign requires a sealed research bundle at "
                            f"{bundle_root}; run ./qcsd-lab fit <fitting-result> first"
                        )
                    try:
                        if frozen_inputs is None:
                            _verify_current_artifact_bundle_at(
                                bundle_root,
                                qualification_inputs_root=base.parent,
                            )
                        else:
                            verify_frozen_artifact_bundle(
                                bundle_root,
                                qualification_inputs_root=frozen_inputs,
                            )
                    except (OSError, TypeError, ValueError) as error:
                        raise ValueError(
                            f"evaluation campaign research bundle is invalid at "
                            f"{bundle_root}: {error}"
                        ) from error
                    evaluation_bundle_root = bundle_root
                expected_name = BUNDLE_FILES[kind]
                if original_name != expected_name or parameters_path.name != expected_name:
                    raise ValueError(
                        f"evaluation {kind} must reference {expected_name} from the common "
                        "sealed research bundle"
                    )

            if frozen_inputs is None:
                artifact = validate_parameter_artifact(
                    parameters_path,
                    provenance_path=provenance_path,
                    expected_kind=kind,
                    allow_reviewed_fixture=purpose == "smoke",
                    allow_study_candidate=(
                        purpose in {"smoke", "evaluation"}
                        and kind in BUFLO_STUDY_PARAMETER_KINDS
                    ),
                    expected_qcsd_profile=profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
                    expected_workloads=workloads,
                    qualification_inputs_root=base.parent,
                )
            else:
                artifact = validate_frozen_parameter_artifact(
                    parameters_path,
                    provenance_path=provenance_path,
                    original_parameter_name=Path(parameters).name,
                    expected_kind=kind,
                    allow_reviewed_fixture=purpose == "smoke",
                    allow_study_candidate=(
                        purpose in {"smoke", "evaluation"}
                        and kind in BUFLO_STUDY_PARAMETER_KINDS
                    ),
                    expected_qcsd_profile=profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
                    expected_workloads=workloads,
                    allow_historical_research_bundle=allow_historical_research_bundle,
                    qualification_inputs_root=frozen_inputs,
                )
            defenses.append(
                capture_engine.Defense(
                    name=name,
                    kind=kind,
                    baseline=baseline,
                    parameters=str(parameters),
                    parameters_path=artifact.path,
                    parameters_sha256=artifact.sha256,
                    parameters_provenance=str(parameter_provenance_path(Path(str(parameters)))),
                    parameters_provenance_path=artifact.provenance_path,
                    parameters_provenance_sha256=artifact.provenance_sha256,
                    parameters_input_policy=artifact.input_policy,
                )
            )
            continue
        if "parameters" in value:
            raise ValueError("parameters are valid only for data-driven defenses")
        defenses.append(capture_engine.Defense(name=name, kind=kind, baseline=baseline))
    baseline_count = sum(defense.baseline for defense in defenses)
    if baseline_count > 1:
        raise ValueError("campaign can contain at most one undefended baseline")
    if len(defenses) > 1 and baseline_count != 1:
        raise ValueError("a multi-defence campaign requires one undefended baseline")
    return tuple(defenses)


def _validate_static_schedule(path: Path, *, udp_payload_ceiling: int) -> None:
    """Validate the exact ``seconds,signed_size`` format consumed by Neqo."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Static schedule cannot be read as UTF-8: {path}") from error
    records = 0
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        records += 1
        fields = line.split(",")
        if len(fields) != 2:
            raise ValueError(f"Static schedule line {line_number} must be seconds,signed_size")
        raw_seconds = fields[0].strip()
        if not re.fullmatch(
            r"[+-]?(?:(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+))(?:[eE][+-]?[0-9]+)?|nan|inf(?:inity)?)",
            raw_seconds,
            flags=re.IGNORECASE,
        ):
            raise ValueError(f"Static schedule line {line_number} timestamp is not a number")
        try:
            seconds = float(raw_seconds)
        except ValueError as error:
            raise ValueError(
                f"Static schedule line {line_number} timestamp is not a number"
            ) from error
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError(
                f"Static schedule line {line_number} timestamp must be finite and non-negative"
            )
        if seconds * 1_000_000 > (2**64 - 1):
            raise ValueError(f"Static schedule line {line_number} timestamp is too large")
        raw_size = fields[1].strip()
        if not re.fullmatch(r"[+-]?[0-9]+", raw_size):
            raise ValueError(f"Static schedule line {line_number} signed_size is not an integer")
        try:
            signed_size = int(raw_size)
        except ValueError as error:
            raise ValueError(
                f"Static schedule line {line_number} signed_size is not an integer"
            ) from error
        if signed_size == 0:
            raise ValueError(f"Static schedule line {line_number} signed_size must not be zero")
        if not -(2**31) <= signed_size < 2**31:
            raise ValueError(
                f"Static schedule line {line_number} signed_size exceeds the 32-bit domain"
            )
        if abs(signed_size) > udp_payload_ceiling:
            raise ValueError(
                f"Static schedule line {line_number} exceeds the {udp_payload_ceiling}-byte "
                "QCSD profile ceiling"
            )
    if records == 0:
        raise ValueError("Static schedule must contain at least one packet")


def plan_campaign(campaign: Campaign) -> list[dict[str, Any]]:
    """Expand the deterministic sequential sample plan."""

    samples: list[dict[str, Any]] = []
    workload_ranks = {
        workload_id: index for index, workload_id in enumerate(sorted(w.id for w in campaign.workloads))
    }
    for workload in campaign.workloads:
        for policy in campaign.request_policies:
            for visit in range(workload.visits):
                defenses = list(campaign.defenses)
                if campaign.defense_order_scheme == "cyclic-latin-square":
                    if campaign.defense_order_block is None:
                        raise ValueError("Latin-square campaign has no acquisition block")
                    phase = (
                        campaign.defense_order_block + workload_ranks[workload.id] + visit
                    ) % len(defenses)
                    defenses = defenses[phase:] + defenses[:phase]
                else:
                    random.Random(
                        _stable_seed("defense-order", campaign.seed, workload.id, policy, visit)
                    ).shuffle(defenses)
                for defense in defenses:
                    seed = _stable_seed(
                        "sample-seed",
                        campaign.seed,
                        workload.id,
                        policy,
                        visit,
                        defense.name,
                    )
                    sample_id = _stable_digest(
                        "sample", campaign.name, workload.id, policy, visit, defense.name, seed
                    )
                    samples.append(
                        {
                            "sample_id": sample_id,
                            "workload_id": workload.id,
                            "request_policy": policy,
                            "visit": visit,
                            "defense": defense.name,
                            "runtime_kind": defense.kind,
                            "baseline": defense.baseline,
                            "seed": seed,
                            "path": (
                                f"samples/{workload.id}/{policy}/visit-{visit:03d}/{defense.name}"
                            ),
                            "state": "planned",
                            "attempts": 0,
                            "eligible": False,
                            "failure": None,
                            "diagnostics": {},
                            "artifacts": {},
                        }
                    )
    return samples


def preflight_campaign(path: Path) -> dict[str, Any]:
    campaign = load_campaign(path)
    if campaign.purpose == "fitting":
        _validate_fitting_capture_source(source_metadata())
    samples = plan_campaign(campaign)
    result = {
        "valid": True,
        "name": campaign.name,
        "purpose": campaign.purpose,
        "profile": campaign.profile,
        "workloads": [
            {
                "id": workload.id,
                "visits": workload.visits,
                "resources": workload.resource_count,
                "origins": workload.origin_count,
                "sha256": workload.sha256,
            }
            for workload in campaign.workloads
        ],
        "request_policies": list(campaign.request_policies),
        "defenses": [defense.name for defense in campaign.defenses],
        "sample_count": len(samples),
        "execution_order": [sample["sample_id"] for sample in samples],
        "samples": [
            {
                key: sample[key]
                for key in (
                    "sample_id",
                    "workload_id",
                    "request_policy",
                    "visit",
                    "defense",
                    "path",
                )
            }
            for sample in samples
        ],
    }
    if campaign.chaff_qualification_set is not None:
        result["chaff_qualification_set"] = campaign.chaff_qualification_set
    if campaign.defense_order_scheme != "seeded-shuffle":
        result["defense_order"] = {
            "scheme": campaign.defense_order_scheme,
            "block": campaign.defense_order_block,
        }
    return result


@contextmanager
def _study_capture_lock(results_root: Path):
    """Hold one non-blocking cross-process lock for all study acquisition."""

    root_value = results_root.absolute()
    if root_value.is_symlink():
        raise ValueError("study results root cannot be a symlink")
    root = root_value.resolve()
    if not root.is_dir():
        raise ValueError("study results root must already exist")
    path = root / ".buflo-study-v1.capture.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("study capture lock is not a regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another BuFLO-study capture or resume holds the global lock") from error
        payload = f"pid={os.getpid()}\n"
        os.ftruncate(descriptor, 0)
        os.write(descriptor, payload.encode("ascii"))
        os.fsync(descriptor)
        yield path
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _public_buflo_campaign(name: str) -> bool:
    return (
        re.fullmatch(
            r"buflo-study-v1-(?:public-(?:smoke|rehearsal)|formal-[0-9]{2})-1200",
            name,
        )
        is not None
    )


def run_campaign(path: Path, results_root: Path = Path("/lab/results")) -> Path:
    campaign = load_campaign(path)
    if campaign.name.startswith("buflo-study-v1-") and os.environ.get(
        "QCSD_BUFLO_CAPTURE_LOCK_HELD"
    ) != "1":
        with _study_capture_lock(results_root):
            return _run_loaded_campaign(campaign, results_root)
    return _run_loaded_campaign(campaign, results_root)


def _run_loaded_campaign(campaign: Campaign, results_root: Path) -> Path:
    from .experiment import initialize_experiment, result_path

    source = source_metadata()
    if campaign.purpose == "fitting":
        _validate_fitting_capture_source(source)
    started = datetime.now(timezone.utc)
    if _public_buflo_campaign(campaign.name):
        admission_value = os.environ.get("QCSD_BUFLO_CAPTURE_ADMISSION")
        if not admission_value:
            raise ValueError("public BuFLO-study run requires a typed capture admission")
        from .buflo_study import admitted_result_root

        root = admitted_result_root(
            Path(admission_value), campaign.path, require_sequence=True
        )
        expected_results_root = root.parents[1]
        if expected_results_root != results_root.resolve():
            raise ValueError("capture admission selected a different results root")
        run_id = root.name
        if result_path(results_root, campaign.name, run_id) != root.resolve():
            raise ValueError("capture admission result root is not canonical")
    else:
        run_id = started.strftime("%Y%m%dT%H%M%S.%fZ")
        root = result_path(results_root, campaign.name, run_id)
    root.mkdir(parents=True, exist_ok=False)
    runtime_campaign, configuration = _materialize_inputs(root, campaign, source)
    samples = plan_campaign(runtime_campaign)
    experiment = initialize_experiment(
        root,
        name=campaign.name,
        purpose=campaign.purpose,
        run_id=run_id,
        source=source,
        configuration=configuration,
        samples=samples,
        started_at=started.isoformat(),
    )
    return _execute(root, runtime_campaign, experiment)


def _materialize_inputs(
    root: Path,
    campaign: Campaign,
    source: dict[str, Any],
) -> tuple[Campaign, dict[str, Any]]:
    required_scope = _required_chaff_qualification_scope(campaign.defenses)
    if required_scope is not None and any(
        workload.chaff_qualification_path is None
        or workload.chaff_qualification_scope != required_scope
        or workload.chaff_manifest_data is None
        or workload.chaff_manifest_sha256 is None
        or (required_scope == FULL_CHAFF_SCOPE and workload.chaff_prefix_spec_path is None)
        for workload in campaign.workloads
    ):
        raise ValueError("defended materialization requires prepared source and qualified chaff")
    inputs = root / "inputs"
    workloads_dir = inputs / "workloads"
    runtime_workloads_dir = inputs / "runtime-workloads"
    chaff_qualifications_dir = inputs / "chaff-qualifications"
    chaff_prefix_specs_dir = inputs / "chaff-prefix-specs"
    chaff_manifests_dir = inputs / "chaff-manifests"
    parameters_dir = inputs / "defense-parameters"
    workloads_dir.mkdir(parents=True)
    parameters_dir.mkdir(parents=True)
    if any(workload.chaff_qualification_path is not None for workload in campaign.workloads):
        runtime_workloads_dir.mkdir()
        chaff_qualifications_dir.mkdir()
        chaff_manifests_dir.mkdir()
        if any(workload.chaff_prefix_spec_path is not None for workload in campaign.workloads):
            chaff_prefix_specs_dir.mkdir()
    _materialize_study_environment(inputs, campaign, source)
    _materialize_capture_admission(root, inputs, campaign, source)
    # ``load_campaign`` parsed these exact bytes.  Writing the snapshot instead
    # of reopening the mutable source closes the campaign resolution/copy race.
    frozen_campaign = inputs / "campaign.yml"
    frozen_campaign.write_bytes(campaign.source_bytes)
    if frozen_campaign.read_bytes() != campaign.source_bytes:
        raise ValueError("campaign changed during input materialization")
    atomic_json(inputs / "source.json", source)
    runtime_workloads: list[Workload] = []
    for workload in campaign.workloads:
        destination = workloads_dir / f"{workload.id}.json"
        destination.write_bytes(workload.source_bytes)
        if sha256_file(destination) != workload.sha256:
            raise ValueError(f"{workload.id} workload changed during input materialization")
        validate_manifest(load_json(destination))
        runtime = replace(workload, path=destination, sha256=sha256_file(destination))
        if workload.chaff_qualification_path is not None:
            from .chaff_qualification import (
                load_qualified_chaff,
                load_response_qualified_chaff,
            )

            sidecar_destination = chaff_qualifications_dir / f"{workload.id}.json"
            shutil.copy2(workload.chaff_qualification_path, sidecar_destination)
            if sha256_file(sidecar_destination) != workload.chaff_qualification_sha256:
                raise ValueError(
                    f"{workload.id} chaff qualification changed during input materialization"
                )
            if workload.chaff_qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE:
                spec_destination = None
                if workload.chaff_prefix_spec_path is not None:
                    raise ValueError(
                        f"{workload.id} response-only qualification unexpectedly has a prefix spec"
                    )
                qualified = load_response_qualified_chaff(
                    sidecar_destination,
                    workload_id=workload.id,
                    base_manifest_path=destination,
                    expected_sidecar_schema_version=_response_only_sidecar_schema_for_manifest(
                        workload.chaff_manifest_data
                    ),
                )
            elif workload.chaff_qualification_scope == FULL_CHAFF_SCOPE:
                if workload.chaff_prefix_spec_path is None:
                    raise ValueError(f"{workload.id} chaff prefix-pack specification is missing")
                spec_destination = chaff_prefix_specs_dir / f"{workload.id}.json"
                shutil.copy2(workload.chaff_prefix_spec_path, spec_destination)
                if sha256_file(spec_destination) != workload.chaff_prefix_spec_sha256:
                    raise ValueError(
                        f"{workload.id} chaff qualification changed during input materialization"
                    )
                qualified = load_qualified_chaff(
                    sidecar_destination,
                    workload_id=workload.id,
                    base_manifest_path=destination,
                    prefix_spec_path=spec_destination,
                )
            else:
                raise ValueError(f"{workload.id} chaff qualification scope is invalid")
            runtime_destination = runtime_workloads_dir / f"{workload.id}.json"
            runtime_destination.write_bytes(canonical_bytes(runtime_manifest(workload.data)))
            if sha256_file(runtime_destination) != workload.runtime_sha256:
                raise ValueError(f"{workload.id} runtime workload changed during materialization")
            manifest_destination = chaff_manifests_dir / f"{workload.id}.json"
            manifest_destination.write_bytes(canonical_bytes(qualified.manifest))
            if sha256_file(manifest_destination) != workload.chaff_manifest_sha256:
                raise ValueError(
                    f"{workload.id} derived chaff manifest changed during materialization"
                )
            runtime = replace(
                runtime,
                chaff_qualification_path=sidecar_destination,
                chaff_qualification_sha256=sha256_file(sidecar_destination),
                chaff_qualification_scope=workload.chaff_qualification_scope,
                chaff_prefix_spec_path=spec_destination,
                chaff_prefix_spec_sha256=(
                    sha256_file(spec_destination) if spec_destination is not None else None
                ),
                chaff_manifest_path=manifest_destination,
                chaff_manifest_sha256=sha256_file(manifest_destination),
                chaff_manifest_data=qualified.manifest,
                runtime_path=runtime_destination,
                runtime_sha256=sha256_file(runtime_destination),
            )
        runtime_workloads.append(runtime)
    runtime_defenses: list[capture_engine.Defense] = []
    for defense in campaign.defenses:
        runtime = defense
        destination_dir = parameters_dir / defense.name
        if defense.schedule_path is not None:
            destination_dir.mkdir()
            destination = destination_dir / "schedule.csv"
            shutil.copy2(defense.schedule_path, destination)
            if sha256_file(destination) != defense.schedule_sha256:
                raise ValueError(
                    f"{defense.name} Static schedule changed during input materialization"
                )
            _validate_static_schedule(
                destination,
                udp_payload_ceiling=campaign.udp_payload_ceiling,
            )
            runtime = replace(
                runtime,
                schedule_path=destination,
                schedule_sha256=sha256_file(destination),
            )
        if defense.parameters_path is not None:
            if defense.parameters_provenance_path is None:
                raise ValueError(f"{defense.name} parameter provenance is missing")
            if defense.parameters_input_policy == "sealed-fitting-result-v1":
                from .fitting import (
                    _verify_current_artifact_bundle_at,
                    verify_frozen_artifact_bundle,
                )

                source_bundle = _verify_current_artifact_bundle_at(
                    defense.parameters_path.parent,
                    qualification_inputs_root=campaign.path.parent.parent,
                )
                research_dir = parameters_dir / "research-1200"
                if not research_dir.exists():
                    if source_bundle.provenance["fitting_contract"]["contract_version"] == 6:
                        _materialize_schema_six_qualification_evidence(
                            inputs,
                            qualification_inputs_root=campaign.path.parent.parent,
                            provenance=source_bundle.provenance,
                        )
                    shutil.copytree(source_bundle.root, research_dir)
                frozen_bundle = verify_frozen_artifact_bundle(
                    research_dir,
                    qualification_inputs_root=inputs,
                )
                if source_bundle.artifact_hashes != frozen_bundle.artifact_hashes:
                    raise ValueError("research parameter bundle changed during materialization")
                if defense.parameters is None:
                    raise ValueError(f"{defense.name} parameter source binding is missing")
                destination = research_dir / Path(defense.parameters).name
                provenance = research_dir / "provenance.json"
            else:
                destination_dir.mkdir(exist_ok=True)
                destination = destination_dir / "parameters.json"
                provenance = destination_dir / "provenance.json"
                shutil.copy2(defense.parameters_path, destination)
                shutil.copy2(defense.parameters_provenance_path, provenance)
            if (
                sha256_file(destination) != defense.parameters_sha256
                or sha256_file(provenance) != defense.parameters_provenance_sha256
            ):
                raise ValueError(
                    f"{defense.name} parameter artifact changed during input materialization"
                )
            if defense.parameters is None:
                raise ValueError(f"{defense.name} parameter source binding is missing")
            frozen_artifact = validate_frozen_parameter_artifact(
                destination,
                provenance_path=provenance,
                original_parameter_name=Path(defense.parameters).name,
                expected_kind=defense.kind,
                allow_reviewed_fixture=campaign.purpose == "smoke",
                allow_study_candidate=(
                    campaign.purpose in {"smoke", "evaluation"}
                    and defense.kind in BUFLO_STUDY_PARAMETER_KINDS
                ),
                expected_qcsd_profile=campaign.profile,
                expected_udp_payload_ceiling=campaign.udp_payload_ceiling,
                expected_workloads={
                    workload.id: workload.sha256 for workload in campaign.workloads
                },
                qualification_inputs_root=inputs,
            )
            if (
                frozen_artifact.sha256 != defense.parameters_sha256
                or frozen_artifact.provenance_sha256 != defense.parameters_provenance_sha256
                or frozen_artifact.input_policy != defense.parameters_input_policy
            ):
                raise ValueError(f"{defense.name} frozen parameter validation changed its binding")
            runtime = replace(
                runtime,
                parameters_path=destination,
                parameters_sha256=sha256_file(destination),
                parameters_provenance_path=provenance,
                parameters_provenance_sha256=sha256_file(provenance),
            )
        runtime_defenses.append(runtime)
    runtime_campaign = replace(
        campaign,
        path=inputs / "campaign.yml",
        workloads=tuple(runtime_workloads),
        defenses=tuple(runtime_defenses),
    )
    return runtime_campaign, _frozen_configuration(root, runtime_campaign)


def _materialize_study_environment(
    inputs: Path, campaign: Campaign, source: Mapping[str, Any]
) -> None:
    encoded = os.environ.get("QCSD_STUDY_ENVIRONMENT_B64")
    is_study = campaign.name.startswith("buflo-study-v1-")
    if not is_study:
        if encoded is not None:
            raise ValueError("study environment receipt cannot be applied to a non-study campaign")
        return
    if not encoded:
        raise ValueError("BuFLO study campaign requires a host Docker environment receipt")
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("BuFLO study Docker environment receipt is malformed") from error
    from .buflo_study import validate_study_environment_receipt

    validate_study_environment_receipt(
        value,
        expected_image_digest=source.get("image_digest"),
    )
    destination = inputs / "study-environment.json"
    destination.write_bytes(raw)
    if load_json(destination) != value:
        raise ValueError("BuFLO study Docker environment changed during materialization")


def _materialize_capture_admission(
    root: Path,
    inputs: Path,
    campaign: Campaign,
    source: Mapping[str, Any],
) -> None:
    admission_value = os.environ.get("QCSD_BUFLO_CAPTURE_ADMISSION")
    is_public = _public_buflo_campaign(campaign.name)
    if not is_public:
        if admission_value is not None:
            raise ValueError("capture admission cannot be applied to a non-public study campaign")
        return
    if not admission_value:
        raise ValueError("public BuFLO-study campaign requires a capture admission")
    from .buflo_study import admitted_result_root, validate_capture_admission

    admission_path = Path(admission_value).resolve()
    admission = validate_capture_admission(admission_path)
    if admission["source"] != source or admitted_result_root(admission_path, campaign.path) != root:
        raise ValueError("capture admission source or selected result root is invalid")
    destination = inputs / "capture-admission.json"
    destination.write_bytes(admission_path.read_bytes())
    if sha256_file(destination) != sha256_file(admission_path):
        raise ValueError("capture admission changed during frozen input materialization")
    cohort = admission.get("formal_cohort")
    if cohort is not None:
        cohort_path = Path(cohort["path"]).resolve()
        cohort_destination = inputs / "formal-cohort.json"
        cohort_destination.write_bytes(cohort_path.read_bytes())
        if sha256_file(cohort_destination) != cohort["sha256"]:
            raise ValueError("formal cohort changed during frozen input materialization")


def _materialize_schema_six_qualification_evidence(
    inputs: Path,
    *,
    qualification_inputs_root: Path,
    provenance: Mapping[str, Any],
) -> None:
    """Freeze the sealed cohort needed to reverify one schema-six bundle."""

    from .chaff_qualification import SEALED_WORKLOAD_IDS, load_qualified_chaff

    root = qualification_inputs_root
    records = provenance["runtime_qualification_inputs"]["workloads"]
    if (
        not isinstance(records, list)
        or len(records) != len(SEALED_WORKLOAD_IDS)
        or tuple(record["workload_id"] for record in records) != SEALED_WORKLOAD_IDS
    ):
        raise ValueError("schema-six qualification evidence order changed during materialization")
    records_by_id = {record["workload_id"]: record for record in records}

    source_directories = {
        "workload": root / "workloads",
        "chaff qualification": root / "chaff-qualification-store/v2",
        "chaff prefix specification": root / "chaff-prefix-specs/v2",
    }
    frozen_directories = {
        "workload": inputs / "workloads",
        "chaff qualification": inputs / "chaff-qualifications",
        "chaff prefix specification": inputs / "chaff-prefix-specs",
        "qualified chaff manifest": inputs / "chaff-manifests",
    }
    expected_names = {f"{workload_id}.json" for workload_id in SEALED_WORKLOAD_IDS}
    if inputs.is_symlink() or not inputs.is_dir():
        raise ValueError("frozen qualification input root is not a regular directory")
    for directory in frozen_directories.values():
        if directory.exists() or directory.is_symlink():
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError(
                    f"frozen qualification input directory is not regular: {directory}"
                )
        else:
            directory.mkdir()
        entries = list(directory.iterdir())
        if not {path.name for path in entries} <= expected_names or any(
            path.is_symlink() or not path.is_file() for path in entries
        ):
            raise ValueError(
                f"frozen qualification input directory has an unsafe file set: {directory}"
            )

    def materialize_file(destination: Path, data: bytes, *, label: str) -> Path:
        try:
            with destination.open("xb") as output:
                output.write(data)
        except FileExistsError:
            pass
        frozen = _trusted_regular_input(
            destination,
            root=inputs,
            label=label,
        )
        if frozen.read_bytes() != data:
            raise ValueError(f"{label} changed during input materialization")
        return frozen

    for workload_id in SEALED_WORKLOAD_IDS:
        record = records_by_id[workload_id]
        expected = {
            "workload": record["application_workload_sha256"],
            "chaff qualification": record["chaff_qualification_sidecar"]["sha256"],
            "chaff prefix specification": record["prefix_pack_spec"]["sha256"],
        }
        frozen: dict[str, Path] = {}
        for label, source_directory in source_directories.items():
            source_path = _trusted_regular_input(
                source_directory / f"{workload_id}.json",
                root=root,
                label=label,
            )
            if sha256_file(source_path) != expected[label]:
                raise ValueError(f"{workload_id} {label} changed during input materialization")
            destination = frozen_directories[label] / f"{workload_id}.json"
            frozen[label] = materialize_file(
                destination,
                source_path.read_bytes(),
                label=f"{workload_id} frozen {label}",
            )
            if sha256_file(frozen[label]) != expected[label]:
                raise ValueError(
                    f"{workload_id} frozen {label} changed during input materialization"
                )

        qualified = load_qualified_chaff(
            frozen["chaff qualification"],
            workload_id=workload_id,
            base_manifest_path=frozen["workload"],
            prefix_spec_path=frozen["chaff prefix specification"],
            require_current_implementation=True,
        )
        if (
            qualified.application_manifest_sha256 != expected["workload"]
            or qualified.sidecar_sha256 != expected["chaff qualification"]
            or qualified.manifest_sha256 != record["qualified_chaff_manifest_sha256"]
        ):
            raise ValueError(
                f"{workload_id} qualification binding changed during input materialization"
            )
        manifest = frozen_directories["qualified chaff manifest"] / f"{workload_id}.json"
        manifest_bytes = canonical_bytes(qualified.manifest)
        manifest = materialize_file(
            manifest,
            manifest_bytes,
            label=f"{workload_id} frozen qualified chaff manifest",
        )
        if (
            manifest.read_bytes() != manifest_bytes
            or sha256_file(manifest) != record["qualified_chaff_manifest_sha256"]
        ):
            raise ValueError(
                f"{workload_id} frozen qualified chaff manifest changed during "
                "input materialization"
            )
    for directory in frozen_directories.values():
        entries = list(directory.iterdir())
        if {path.name for path in entries} != expected_names or any(
            path.is_symlink() or not path.is_file() for path in entries
        ):
            raise ValueError(
                f"frozen qualification input directory has an inexact file set: {directory}"
            )


def _checkpoint(root: Path, experiment: dict[str, Any]) -> None:
    from .experiment import checkpoint_experiment

    experiment["summary"] = _summary(
        experiment["samples"], passed=experiment.get("status") == "complete"
    )
    checkpoint_experiment(root, experiment)


def _execute(root: Path, campaign: Campaign, experiment: dict[str, Any]) -> Path:
    from .experiment import accept_sample, finalize_experiment, transition_sample

    samples_by_id = {sample["sample_id"]: sample for sample in experiment["samples"]}
    workload_by_id = {workload.id: workload for workload in campaign.workloads}
    defense_by_name = {defense.name: defense for defense in campaign.defenses}
    origin_last_run = _prior_origin_completion(campaign, experiment)
    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for sample_id in experiment["execution_order"]:
        sample = samples_by_id[sample_id]
        group = (sample["workload_id"], sample["request_policy"], sample["visit"])
        groups.setdefault(group, []).append(sample)
    for members in groups.values():
        for sample in members:
            if sample["state"] == "accepted":
                _validate_accepted(root, sample)
                continue
            workload = workload_by_id[sample["workload_id"]]
            defense = defense_by_name[sample["defense"]]
            attempts_this_execution = 0
            # BuFLO-study ``sample["attempts"]`` is the durable, cross-resume
            # budget.  Preserve the historical generic campaign contract while
            # preventing a resumed study cell from acquiring another three
            # traces after already exhausting its prospective total cap.
            while attempts_this_execution < campaign.limits.max_attempts and (
                not campaign.name.startswith("buflo-study-v1-")
                or sample["attempts"] < campaign.limits.max_attempts
            ):
                attempts_this_execution += 1
                runtime_workload = runtime_manifest(workload.data)
                capture_engine._respect_origin_cooldown(
                    runtime_workload,
                    _RunContext(
                        campaign.profile,
                        sample["request_policy"],
                        campaign.limits,
                        campaign.udp_payload_ceiling,
                    ),
                    origin_last_run,
                )
                transition_sample(
                    experiment,
                    sample["sample_id"],
                    "running",
                    increment_attempt=True,
                    failure=None,
                )
                _checkpoint(root, experiment)
                attempt = resolved_attempt_directory(root, sample)
                try:
                    if workload.runtime_path is not None:
                        runtime_path = workload.runtime_path
                        if sha256_file(runtime_path) != workload.runtime_sha256:
                            raise ValueError("frozen runtime workload changed before capture")
                    else:
                        temporary = tempfile.TemporaryDirectory(prefix="qcsd-runtime-workload-")
                        runtime_path = Path(temporary.name) / f"{workload.id}.json"
                        runtime_path.write_bytes(canonical_bytes(runtime_workload))
                    try:
                        context = _RunContext(
                            campaign.profile,
                            sample["request_policy"],
                            campaign.limits,
                            campaign.udp_payload_ceiling,
                        )
                        # Preserve the established collector seam for campaigns
                        # without qualified inputs.  Current defended campaigns
                        # take the explicit seventh argument below.
                        if not defense.baseline and workload.chaff_manifest_path is not None:
                            result = capture_engine._collect_attempt(
                                attempt,
                                runtime_path,
                                workload.chaff_manifest_path,
                                workload.id,
                                defense,
                                sample["seed"],
                                context,
                                application_workload_source=workload.path,
                            )
                        else:
                            if not defense.baseline:
                                raise ValueError(
                                    "defended execution lacks frozen prepared source and qualified chaff"
                                )
                            result = capture_engine._collect_attempt(
                                attempt,
                                runtime_path,
                                workload.id,
                                defense,
                                sample["seed"],
                                context,
                            )
                    finally:
                        if workload.runtime_path is None:
                            temporary.cleanup()
                except Exception as error:
                    attempt.mkdir(parents=True, exist_ok=True)
                    result = {
                        "success": False,
                        "failure": {
                            "stage": "collection",
                            "type": type(error).__name__,
                            "message": str(error),
                        },
                    }
                    atomic_json(attempt / "failure.json", result["failure"])
                capture_engine._mark_origin_completed(runtime_workload, origin_last_run)
                if result.get("success") is True:
                    fidelity_failure = _intrinsic_fidelity_failure(sample, result, attempt)
                    if fidelity_failure is None:
                        fidelity_failure = _prepared_response_identity_failure(workload, attempt)
                    if fidelity_failure is None:
                        diagnostics = _success_diagnostics(result)
                        controlled_cell = _controlled_study_cell(campaign, sample)
                        if controlled_cell is not None:
                            diagnostics["buflo_study_controlled_cell"] = controlled_cell
                        diagnostics["promotion"] = _promotion_receipt(root, sample, attempt)
                        transition_sample(
                            experiment,
                            sample["sample_id"],
                            "running",
                            diagnostics=diagnostics,
                        )
                        _checkpoint(root, experiment)
                        _promote_attempt(root, sample, attempt)
                        diagnostics.pop("promotion")
                        accept_sample(
                            root,
                            experiment,
                            sample["sample_id"],
                            diagnostics=diagnostics,
                        )
                        break
                    result = _record_fidelity_failure(attempt, result, fidelity_failure)
                _sanitize_failed_attempt(attempt)
                transition_sample(
                    experiment,
                    sample["sample_id"],
                    "failed",
                    failure=result.get("failure"),
                    eligible=False,
                )
                _checkpoint(root, experiment)
            _checkpoint(root, experiment)
        _compare_group(root, members, workload_by_id[members[0]["workload_id"]])
        _checkpoint(root, experiment)
    passed = all(
        sample["state"] == "accepted" and sample["eligible"] is True
        for sample in experiment["samples"]
    )
    finalize_experiment(root, experiment, status="complete" if passed else "incomplete")
    _seal(root)
    if experiment["status"] != "complete":
        raise CampaignIncomplete(root)
    return root


def _prior_origin_completion(campaign: Campaign, experiment: dict[str, Any]) -> dict[str, float]:
    """Start a manual resume with one conservative full cooldown epoch."""

    attempted_workloads = {
        sample["workload_id"] for sample in experiment["samples"] if sample["attempts"] > 0
    }
    if not attempted_workloads:
        return {}
    now = time.monotonic()
    return {
        origin: now
        for workload in campaign.workloads
        if workload.id in attempted_workloads
        for origin in capture_engine._manifest_origins(runtime_manifest(workload.data))
    }


def _sanitize_failed_attempt(attempt: Path) -> None:
    """Keep diagnostics while excluding duplicated frozen parameter inputs."""

    neqo = attempt / "neqo"
    for name in ("defense-parameters.json", "defense-parameters.provenance.json"):
        path = neqo / name
        if path.exists():
            path.unlink()


def _success_diagnostics(result: dict[str, Any]) -> dict[str, Any]:
    capture = dict(_primary_capture_view(result))
    capture["capture_path"] = "capture.pcapng"
    capture.pop("trace_path", None)
    capture.pop("trace_sha256", None)
    return {
        "capture": capture,
        "offloads": result.get("offloads", []),
        "network_condition": result.get("network_condition"),
        "endpoint_count": result.get("endpoint_count"),
        "endpoint_count_valid": result.get("endpoint_count_valid"),
        "runner_binding_valid": result.get("runner_binding_valid", True),
        "operationally_valid": result.get("operationally_valid", True),
        "defense": result.get("defense_diagnostics") or {},
    }


def _controlled_study_cell(
    campaign: Campaign, sample: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Bind one exact prospective local-study cell into accepted diagnostics."""

    receipt = campaign.study_controlled
    if receipt is None:
        return None
    stage = receipt["stage"]
    treatment = str(sample["defense"])
    treatments = tuple(receipt["treatment_order"])
    workload_ids = sorted(workload.id for workload in campaign.workloads)
    workload_rank = workload_ids.index(str(sample["workload_id"]))
    if stage == "controlled":
        phase = (int(receipt["netem_rank"]) + workload_rank + int(sample["visit"])) % len(
            treatments
        )
        position = (treatments.index(treatment) - phase) % len(treatments)
    elif stage == "regression":
        position = (treatments.index(treatment) - workload_rank) % len(treatments)
    else:
        raise ValueError("controlled campaign has an unsupported study stage")
    workload_aliases = receipt["workload_aliases"]
    return {
        "workload": workload_aliases[str(sample["workload_id"])],
        "visit": int(sample["visit"]),
        "treatment": treatment,
        "treatment_position": position,
        "netem_profile": receipt["netem_profile"],
        "client_qdisc": receipt["client_qdisc"],
        "server_qdisc": receipt["server_qdisc"],
    }


def _primary_capture_view(result: Mapping[str, Any]) -> Mapping[str, Any]:
    views = result.get("views")
    if not isinstance(views, list):
        raise ValueError("collection result lacks capture views")
    primaries = [
        view for view in views if isinstance(view, Mapping) and view.get("primary") is True
    ]
    if len(primaries) != 1:
        raise ValueError("collection result must contain exactly one primary capture view")
    return primaries[0]


def _buflo_incoming_credit_delay_failure(
    attempt: Path, schedule: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Describe the exact late incoming-credit slots behind the BuFLO gate."""

    observed_max = schedule.get("incoming_credit_advertisement_delay_us_max")
    if (
        type(observed_max) is not int
        or observed_max < BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US
    ):
        return None

    violations: list[dict[str, int]] = []
    path = attempt / "neqo/schedule.csv"
    try:
        with path.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
    except (OSError, UnicodeError, csv.Error):
        rows = []
    for row in rows:
        if row.get("direction") != "incoming":
            continue
        try:
            delay_us = int(row["credit_advertisement_delay_us"])
            action_time_us = int(row["action_time_us"])
            advertised_at_us = int(row["credit_advertised_at_us"])
            violation = {
                "slot_id": int(row["slot_id"]),
                "connection": int(row["connection"]),
                "target_time_us": int(row["target_time_us"]),
                "action_time_us": action_time_us,
                "credit_advertised_at_us": advertised_at_us,
                "credit_advertisement_delay_us": delay_us,
            }
        except (KeyError, TypeError, ValueError):
            continue
        if (
            delay_us >= BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US
            and advertised_at_us - action_time_us == delay_us
        ):
            violations.append(violation)

    return {
        "name": "buflo_incoming_credit_advertisement_delay_window",
        "predicate": (
            "incoming_credit_advertisement_delay_us_max "
            f"< {BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US}"
        ),
        "limit_us": BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US,
        "observed_max_us": observed_max,
        "violating_slots": violations,
    }


def _intrinsic_fidelity_failure(
    sample: dict[str, Any],
    result: dict[str, Any],
    attempt: Path,
) -> dict[str, Any] | None:
    """Reject a collected defense realization before it becomes immutable evidence."""

    try:
        primary = _primary_capture_view(result)
        validate_primary_capture_clock_integrity(
            primary,
            label=f"sample {sample.get('sample_id')}",
            require_pairing_uncertainty=True,
            require_timestamp_type=True,
        )
    except ValueError as error:
        return {
            "stage": "fidelity",
            "type": "StrictCaptureClockIntegrityFailure",
            "message": "collection artifacts failed Linux capture-clock integrity gates",
            "details": [{"error": str(error)}],
        }

    schedule = _schedule_realization_metrics(attempt)
    defense_metrics = result.get("defense_diagnostics")
    if not isinstance(defense_metrics, dict):
        defense_metrics = {}
    defense = defense_from_runtime_identity(sample["defense"], sample["runtime_kind"])
    eligible = fidelity_eligible(
        defense,
        defense_metrics,
        sample_eligible=True,
        missed_events=schedule.get("missed_events"),
        outgoing_size_mismatches=schedule.get("outgoing_size_mismatch_events"),
        schedule_metrics=schedule,
    )
    if eligible:
        return None
    details: dict[str, Any] = {
        "defense": defense,
        "schedule": schedule,
        "defense_diagnostics": defense_metrics,
    }
    if defense == "buflo":
        credit_delay_failure = _buflo_incoming_credit_delay_failure(attempt, schedule)
        if credit_delay_failure is not None:
            details["failed_predicates"] = [credit_delay_failure]
    return {
        "stage": "fidelity",
        "type": "StrictDefenseFidelityFailure",
        "message": "collection artifacts failed strict defense fidelity gates",
        "details": [details],
    }


def _prepared_response_identity_failure(
    workload: Workload,
    attempt: Path,
) -> dict[str, Any] | None:
    """Reject prepared-response drift before an attempt becomes immutable evidence."""

    expected = _prepared_response_signature(workload.data)
    if expected is None:
        return None
    observed = response_signature(attempt)
    if observed == expected:
        return None

    expected_by_id: dict[Any, list[tuple[Any, ...]]] = {}
    observed_by_id: dict[Any, list[tuple[Any, ...]]] = {}
    for entry in expected:
        expected_by_id.setdefault(entry[0], []).append(entry)
    for entry in observed or []:
        observed_by_id.setdefault(entry[0], []).append(entry)
    differing_resource_ids = sorted(
        (
            resource_id
            for resource_id in expected_by_id.keys() | observed_by_id.keys()
            if expected_by_id.get(resource_id) != observed_by_id.get(resource_id)
        ),
        key=str,
    )
    return {
        "stage": "fidelity",
        "type": "StrictPreparedResponseIdentityFailure",
        "message": "application responses differ from the frozen prepared identity",
        "details": [
            {
                "workload_id": workload.id,
                "expected_response_count": len(expected),
                "observed_response_count": len(observed or []),
                "expected_response_signature_sha256": sha256_bytes(
                    json.dumps(expected, sort_keys=True).encode()
                ),
                "observed_response_signature_sha256": (
                    sha256_bytes(json.dumps(observed, sort_keys=True).encode())
                    if observed is not None
                    else None
                ),
                "differing_resource_ids": differing_resource_ids,
            }
        ],
    }


def _record_fidelity_failure(
    attempt: Path,
    result: dict[str, Any],
    failure: dict[str, Any],
) -> dict[str, Any]:
    """Atomically turn a successful collection receipt into a retryable failure."""

    failed = dict(result)
    failed["success"] = False
    failed["failure"] = failure
    atomic_json(attempt / "attempt.json", failed)
    return failed


def _promotion_sources(attempt: Path) -> dict[str, Path]:
    return {
        "capture.pcapng": attempt / "captures/direct-quic.pcapng",
        "neqo/run.json": attempt / "neqo/run.json",
        "neqo/packets.csv": attempt / "neqo/packets.csv",
        "neqo/events.csv": attempt / "neqo/events.csv",
        "neqo/schedule.csv": attempt / "neqo/schedule.csv",
    }


def _promotion_receipt(root: Path, sample: dict[str, Any], attempt: Path) -> dict[str, Any]:
    expected_attempt = resolved_attempt_directory(root, sample)
    if attempt.resolve() != expected_attempt:
        raise ValueError("attempt path does not match the planned sample")
    attempt = expected_attempt
    sample_path = resolved_sample_directory(root, sample)
    sources = _promotion_sources(attempt)
    missing = [relative for relative, path in sources.items() if not path.is_file()]
    if missing:
        raise ValueError("successful attempt lacks required artifacts: " + ", ".join(missing))
    return {
        "attempt": attempt.relative_to(root).as_posix(),
        "artifacts": {
            (sample_path / relative).relative_to(root).as_posix(): sha256_file(path)
            for relative, path in sources.items()
        },
    }


def _promote_attempt(root: Path, sample: dict[str, Any], attempt: Path) -> None:
    expected_attempt = resolved_attempt_directory(root, sample)
    if attempt.resolve() != expected_attempt:
        raise ValueError("attempt path does not match the planned sample")
    attempt = expected_attempt
    sample_path = resolved_sample_directory(root, sample)
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    if sample_path.exists() or sample_path.is_symlink():
        raise FileExistsError(f"sample promotion target already exists: {sample['path']}")
    sources = _promotion_sources(attempt)
    missing = [relative for relative, path in sources.items() if not path.is_file()]
    if missing:
        raise ValueError("accepted attempt lacks required artifacts: " + ", ".join(missing))
    staging = attempt / ".promotion"
    if staging.exists() or staging.is_symlink():
        if staging.is_symlink() or not staging.is_dir():
            raise ValueError(f"unsafe interrupted promotion staging path: {staging}")
        shutil.rmtree(staging)
    (staging / "neqo").mkdir(parents=True)
    for relative, source in sources.items():
        shutil.copy2(source, staging / relative)
    # Attempts and samples share one result filesystem, so this installs the
    # five-file accepted directory atomically. A crash cannot expose a partial
    # canonical sample.
    staging.replace(sample_path)
    shutil.rmtree(attempt)
    try:
        attempt.parent.rmdir()
    except OSError:
        pass


def _artifact_hashes(root: Path, sample: dict[str, Any]) -> dict[str, str]:
    return accepted_sample_hashes(root, sample)


def _validate_accepted(root: Path, sample: dict[str, Any]) -> None:
    if sample.get("state") != "accepted" or not sample.get("artifacts"):
        raise ValueError(f"accepted sample receipt is invalid: {sample.get('sample_id')}")
    expected = sample["artifacts"]
    actual = _artifact_hashes(root, sample)
    if actual != expected:
        raise ValueError(f"accepted sample artifact set changed: {sample['sample_id']}")


def _compare_group(
    root: Path,
    samples: list[dict[str, Any]],
    workload: Workload,
) -> None:
    accepted = [sample for sample in samples if sample["state"] == "accepted"]
    baseline = next((sample for sample in accepted if sample["baseline"]), None)
    baseline_signature = (
        response_signature(resolved_sample_directory(root, baseline, require_directory=True))
        if baseline
        else None
    )
    prepared_signature = _prepared_response_signature(workload.data)
    reference = prepared_signature if prepared_signature is not None else baseline_signature
    for sample in accepted:
        sample_path = resolved_sample_directory(root, sample, require_directory=True)
        signature = response_signature(sample_path)
        response_match = signature is not None and (reference is None or signature == reference)
        diagnostics = sample["diagnostics"]
        if (root / "inputs/study-environment.json").is_file():
            diagnostics["redirect_attestation"] = _redirect_attestation(
                workload,
                sample_path,
            )
        capture_valid = diagnostics.get("capture", {}).get("valid") is True
        operational = diagnostics.get("operationally_valid") is True
        schedule = _schedule_realization_metrics(sample_path)
        defense_metrics = diagnostics.get("defense")
        if not isinstance(defense_metrics, dict):
            defense_metrics = {}
        defense = defense_from_runtime_identity(sample["defense"], sample["runtime_kind"])
        base_eligible = bool(capture_valid and operational and response_match)
        eligible = fidelity_eligible(
            defense,
            defense_metrics,
            sample_eligible=base_eligible,
            missed_events=schedule.get("missed_events"),
            outgoing_size_mismatches=schedule.get("outgoing_size_mismatch_events"),
            schedule_metrics=schedule,
        )
        diagnostics.update(
            response_match=response_match,
            paired_baseline_response_match=(
                signature == baseline_signature if baseline_signature is not None else None
            ),
            prepared_response_match=(
                signature == prepared_signature if prepared_signature is not None else None
            ),
            response_signature_sha256=(
                sha256_bytes(json.dumps(signature, sort_keys=True).encode())
                if signature is not None
                else None
            ),
            schedule=schedule,
            fidelity_eligible=eligible,
        )
        sample["eligible"] = eligible


def _redirect_attestation(workload: Workload, sample_path: Path) -> dict[str, Any]:
    """Prove that prepared and final application resources contain no redirects."""

    preparation = workload.data.get("preparation")
    resources = workload.data.get("resources")
    run_data = load_json(sample_path / "neqo/run.json")
    responses = run_data.get("responses") if isinstance(run_data, Mapping) else None
    expected_responses = (
        preparation.get("expected_responses") if isinstance(preparation, Mapping) else None
    )
    if (
        not isinstance(preparation, Mapping)
        or preparation.get("source_url") != preparation.get("final_url")
        or not isinstance(resources, list)
        or not isinstance(expected_responses, list)
        or not isinstance(responses, list)
    ):
        raise ValueError("prepared/final redirect evidence is unavailable")
    expected = {
        item.get("resource_id"): item
        for item in expected_responses
        if isinstance(item, Mapping)
    }
    observed = {
        item.get("resource_id"): item for item in responses if isinstance(item, Mapping)
    }
    prepared_resources = {
        item.get("id"): item for item in resources if isinstance(item, Mapping)
    }
    if (
        len(expected) != len(expected_responses)
        or len(observed) != len(responses)
        or len(prepared_resources) != len(resources)
        or set(expected) != set(observed)
        or set(expected) != set(prepared_resources)
    ):
        raise ValueError("prepared/final resource identities cannot prove empty redirects")
    records = []
    for identifier in sorted(expected):
        prepared = prepared_resources[identifier]
        expected_response = expected[identifier]
        response = observed[identifier]
        prepared_status = expected_response.get("status")
        final_status = response.get("status")
        prepared_url = prepared.get("url")
        if (
            type(identifier) is not int
            or not isinstance(prepared_url, str)
            or response.get("url") != prepared_url
            or type(prepared_status) is not int
            or type(final_status) is not int
            or 300 <= prepared_status < 400
            or 300 <= final_status < 400
            or response.get("complete") is not True
            or response.get("outcome") != "succeeded"
        ):
            raise ValueError("prepared/final resource contains redirect evidence")
        records.append(
            {
                "resource_id": identifier,
                "prepared_url": prepared_url,
                "prepared_status": prepared_status,
                "prepared_redirect_sequence": [],
                "final_url": response["url"],
                "final_status": final_status,
                "final_redirect_sequence": [],
            }
        )
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-empty-redirect-attestation",
        "workload_id": workload.id,
        "navigation": {
            "source_url": preparation["source_url"],
            "final_url": preparation["final_url"],
            "redirect_sequence": [],
        },
        "resources": records,
        "all_redirect_sequences_empty": True,
    }


def _prepared_response_signature(manifest: dict[str, Any]) -> list[tuple[Any, ...]] | None:
    preparation = manifest.get("preparation")
    if not isinstance(preparation, dict):
        return None
    responses = preparation.get("expected_responses")
    if not isinstance(responses, list):
        return None
    return sorted(
        (
            response.get("resource_id"),
            response.get("status"),
            response.get("bytes"),
            response.get("body_sha256"),
            "succeeded",
        )
        for response in responses
    )


def _summary(samples: list[dict[str, Any]], *, passed: bool = False) -> dict[str, Any]:
    accepted = sum(sample["state"] == "accepted" for sample in samples)
    failed = sum(sample["state"] == "failed" for sample in samples)
    eligible = sum(sample.get("eligible") is True for sample in samples)
    return {
        "planned": len(samples),
        "accepted": accepted,
        "failed": failed,
        "eligible": eligible,
        "passed": bool(passed and samples and accepted == eligible == len(samples)),
    }


def _seal(root: Path) -> None:
    from .verification import seal_result

    seal_result(root)


def _recover_pending_promotion(root: Path, experiment: dict[str, Any]) -> bool:
    """Finish a validated two-phase promotion without another network run."""

    from .experiment import accept_sample

    running = [sample for sample in experiment["samples"] if sample["state"] == "running"]
    if len(running) > 1:
        raise ValueError("sequential experiment has multiple running samples")
    if not running:
        return False
    sample = running[0]
    diagnostics = sample.get("diagnostics")
    promotion = diagnostics.get("promotion") if isinstance(diagnostics, dict) else None
    if not isinstance(promotion, dict) or set(promotion) != {"attempt", "artifacts"}:
        return False
    capture = diagnostics.get("capture")
    try:
        validate_primary_capture_clock_integrity(
            capture,
            label=f"pending promotion {sample.get('sample_id')}",
            require_pairing_uncertainty=True,
            require_timestamp_type=True,
        )
    except ValueError as error:
        raise ValueError("pending promotion capture clock integrity is invalid") from error
    expected_attempt = resolved_attempt_directory(root, sample)
    if promotion["attempt"] != expected_attempt.relative_to(root).as_posix():
        raise ValueError("pending promotion attempt binding is invalid")
    expected_artifacts = promotion["artifacts"]
    expected_paths = {
        (Path(sample["path"]) / relative).as_posix()
        for relative in _promotion_sources(expected_attempt)
    }
    if not isinstance(expected_artifacts, dict) or set(expected_artifacts) != expected_paths:
        raise ValueError("pending promotion artifact binding is invalid")
    sample_path = resolved_sample_directory(root, sample)
    if sample_path.exists() or sample_path.is_symlink():
        if sample_path.is_symlink() or not sample_path.is_dir():
            raise ValueError("pending promotion target is unsafe")
    else:
        if not expected_attempt.is_dir() or expected_attempt.is_symlink():
            raise ValueError("validated pending promotion artifacts are missing")
        current = _promotion_receipt(root, sample, expected_attempt)["artifacts"]
        if current != expected_artifacts:
            raise ValueError("pending promotion source hash mismatch")
        _promote_attempt(root, sample, expected_attempt)
    actual = _artifact_hashes(root, sample)
    if actual != expected_artifacts:
        raise ValueError("pending promoted sample hash mismatch")
    if expected_attempt.exists():
        if expected_attempt.is_symlink() or not expected_attempt.is_dir():
            raise ValueError("pending promotion attempt path is unsafe")
        shutil.rmtree(expected_attempt)
        try:
            expected_attempt.parent.rmdir()
        except OSError:
            pass
    diagnostics = dict(diagnostics)
    diagnostics.pop("promotion")
    accept_sample(
        root,
        experiment,
        sample["sample_id"],
        diagnostics=diagnostics,
    )
    _checkpoint(root, experiment)
    return True


def _recover_completed_attempt(
    root: Path,
    experiment: dict[str, Any],
    campaign: Campaign,
) -> bool:
    """Checkpoint a terminal attempt receipt left before its state checkpoint."""

    from .experiment import transition_sample

    running = [sample for sample in experiment["samples"] if sample["state"] == "running"]
    if not running:
        return False
    if len(running) != 1:
        raise ValueError("sequential experiment has multiple running samples")
    sample = running[0]
    attempt = resolved_attempt_directory(root, sample)
    if not attempt.exists():
        return False
    if attempt.is_symlink() or not attempt.is_dir():
        raise ValueError(f"running attempt path is unsafe: {attempt}")
    attempt_receipt = attempt / "attempt.json"
    exception_receipt = attempt / "failure.json"
    if attempt_receipt.is_file():
        result = load_json(attempt_receipt)
        if not isinstance(result, dict) or type(result.get("success")) is not bool:
            raise ValueError("running attempt has an invalid terminal receipt")
        if result["success"] is True:
            fidelity_failure = _intrinsic_fidelity_failure(sample, result, attempt)
            if fidelity_failure is None:
                workload = next(
                    item for item in campaign.workloads if item.id == sample["workload_id"]
                )
                fidelity_failure = _prepared_response_identity_failure(workload, attempt)
            if fidelity_failure is None:
                diagnostics = _success_diagnostics(result)
                controlled_cell = _controlled_study_cell(campaign, sample)
                if controlled_cell is not None:
                    diagnostics["buflo_study_controlled_cell"] = controlled_cell
                diagnostics["promotion"] = _promotion_receipt(root, sample, attempt)
                transition_sample(
                    experiment,
                    sample["sample_id"],
                    "running",
                    diagnostics=diagnostics,
                )
                _checkpoint(root, experiment)
                return _recover_pending_promotion(root, experiment)
            result = _record_fidelity_failure(attempt, result, fidelity_failure)
        failure = result.get("failure")
    elif exception_receipt.is_file():
        failure = load_json(exception_receipt)
    else:
        return False
    if not isinstance(failure, dict) or not failure:
        raise ValueError("running attempt has an invalid failure receipt")
    _sanitize_failed_attempt(attempt)
    transition_sample(
        experiment,
        sample["sample_id"],
        "failed",
        failure=failure,
        eligible=False,
    )
    _checkpoint(root, experiment)
    return True


def resume_campaign(root: Path) -> Path:
    root = root.resolve()
    experiment_path = root / "experiment.json"
    value = load_json(experiment_path)
    name = value.get("name") if isinstance(value, Mapping) else None
    if (
        isinstance(name, str)
        and name.startswith("buflo-study-v1-")
        and os.environ.get("QCSD_BUFLO_CAPTURE_LOCK_HELD") != "1"
    ):
        if len(root.parents) < 2:
            raise ValueError("study result root has no canonical results ancestor")
        with _study_capture_lock(root.parents[1]):
            return _resume_campaign_locked(root)
    return _resume_campaign_locked(root)


def _resume_campaign_locked(root: Path) -> Path:
    root = root.resolve()
    from .experiment import (
        load_experiment,
        transition_sample,
        validate_accepted_samples,
        validate_resume_fingerprints,
    )
    from .verification import prepare_resume, seal_result, verify_result

    # A hard stop can leave only a recognizably named, uncommitted sibling of
    # an otherwise intact atomic checkpoint. It is never authoritative and is
    # safe to discard before reading an unsealed result.
    if not (root / "evidence.sha256").exists():
        discard_atomic_write_temps(root)

    # Finalization and sealing are deliberately separate durable operations.
    # If the process stopped between them, the terminal checkpoint already owns
    # the complete accepted state; validate it against the current source and
    # seal it without launching or repeating any sample.
    if not (root / "evidence.sha256").exists():
        terminal = load_experiment(root)
        if terminal["status"] == "running":
            validate_resume_fingerprints(
                root,
                expected_source=source_metadata(),
                experiment=terminal,
            )
            campaign = validate_frozen_experiment_contract(root, terminal)
            validate_accepted_samples(root, terminal, allow_running_artifacts=True)
            _recover_pending_promotion(root, terminal)
            _recover_completed_attempt(root, terminal, campaign)
        elif terminal["status"] in {"complete", "incomplete"}:
            validate_resume_fingerprints(
                root,
                expected_source=source_metadata(),
                experiment=terminal,
            )
            validate_frozen_experiment_contract(root, terminal)
            validate_accepted_samples(root, terminal)
            seal_result(root)
            if terminal["status"] == "complete":
                return root
    else:
        validate_frozen_experiment_contract(root, verify_result(root).experiment)

    experiment = prepare_resume(root, expected_source=source_metadata())
    # A running checkpoint means the process stopped before promotion.  The
    # established generic campaign contract discards that partial attempt and
    # reuses its number.  Prospective BuFLO-study campaigns instead count every
    # physical collector launch against the durable three-attempt ceiling: a
    # hard interruption becomes a small immutable failure tombstone before a
    # later launch receives the next attempt number.
    study_attempt_budget = experiment["name"].startswith("buflo-study-v1-")
    for sample in experiment["samples"]:
        if sample["state"] != "interrupted":
            continue
        attempt = resolved_attempt_directory(root, sample)
        if attempt.exists():
            if attempt.is_symlink() or not attempt.is_dir():
                raise ValueError(f"interrupted attempt path is unsafe: {attempt}")
            shutil.rmtree(attempt)
        if study_attempt_budget:
            attempt.mkdir(parents=True)
            failure = {
                "stage": "interruption",
                "type": "HardInterruption",
                "message": "collector process stopped after the physical launch checkpoint",
                "physical_attempt": sample["attempts"],
            }
            atomic_json(attempt / "failure.json", failure)
            transition_sample(
                experiment,
                sample["sample_id"],
                "failed",
                failure=failure,
                eligible=False,
            )
        else:
            try:
                attempt.parent.rmdir()
            except OSError:
                pass
            sample["attempts"] -= 1
    _checkpoint(root, experiment)
    campaign = validate_frozen_experiment_contract(root, experiment)
    for sample in experiment["samples"]:
        if sample["state"] == "accepted":
            _validate_accepted(root, sample)
    return _execute(root, campaign, experiment)


def validate_frozen_experiment_contract(
    root: Path,
    experiment: dict[str, Any],
    *,
    allow_historical_research_bundle: bool = False,
) -> Campaign:
    """Re-derive every immutable execution field from frozen input bytes."""

    campaign = _campaign_from_frozen_inputs(
        root,
        allow_historical_research_bundle=allow_historical_research_bundle,
    )
    if experiment["name"] != campaign.name:
        raise ValueError("experiment name does not match frozen campaign")
    if experiment["purpose"] != campaign.purpose:
        raise ValueError("experiment purpose does not match frozen campaign")
    expected_configuration = _frozen_configuration(root, campaign)
    if experiment["configuration"] != expected_configuration:
        raise ValueError("experiment configuration does not match frozen campaign inputs")
    # The seed is intentionally stored only once, in campaign.yml.  Replanning
    # from it binds every per-sample seed and the exact execution order without
    # adding another redundant seed field to experiment.json.
    validate_planned_sample_identity(experiment, plan_campaign(campaign))
    for sample in experiment["samples"]:
        resolved_sample_directory(root, sample)
        if (
            campaign.name.startswith("buflo-study-v1-")
            and sample["attempts"] > campaign.limits.max_attempts
        ):
            raise ValueError("sample exceeds the campaign's total persisted attempt cap")
        if sample["attempts"] > 0:
            resolved_attempt_directory(root, sample)
    return campaign


def _campaign_from_frozen_inputs(
    root: Path,
    *,
    allow_historical_research_bundle: bool = False,
) -> Campaign:
    inputs = (root / "inputs").resolve()
    if inputs.is_symlink() or not inputs.is_dir():
        raise ValueError(f"result has no regular inputs directory: {root}")
    return _load_campaign(
        inputs / "campaign.yml",
        frozen_inputs=inputs,
        allow_historical_research_bundle=allow_historical_research_bundle,
    )


def _frozen_configuration(root: Path, campaign: Campaign) -> dict[str, Any]:
    """Derive the experiment configuration without consulting experiment.json."""

    root = root.resolve()
    workload_records = [_frozen_workload_record(root, workload) for workload in campaign.workloads]
    defense_records: list[dict[str, Any]] = []
    for defense in campaign.defenses:
        record: dict[str, Any] = {
            "name": defense.name,
            "kind": defense.kind,
            "baseline": defense.baseline,
        }
        if defense.schedule_path is not None:
            record.update(
                schedule=defense.schedule_path.relative_to(root).as_posix(),
                schedule_sha256=defense.schedule_sha256,
                mode=defense.mode,
            )
        if defense.parameters_path is not None:
            if defense.parameters_provenance_path is None:
                raise ValueError(f"{defense.name} frozen parameter provenance is missing")
            record.update(
                parameters=defense.parameters_path.relative_to(root).as_posix(),
                parameters_sha256=defense.parameters_sha256,
                provenance=defense.parameters_provenance_path.relative_to(root).as_posix(),
                provenance_sha256=defense.parameters_provenance_sha256,
                input_policy=defense.parameters_input_policy,
            )
        defense_records.append(record)
    configuration = {
        "campaign_sha256": sha256_file(campaign.path),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": defense_records,
        "limits": campaign.limits.as_dict(),
    }
    if campaign.chaff_qualification_set is not None:
        configuration["chaff_qualification_set"] = campaign.chaff_qualification_set
    if campaign.defense_order_scheme != "seeded-shuffle":
        configuration["defense_order"] = {
            "scheme": campaign.defense_order_scheme,
            "block": campaign.defense_order_block,
        }
    study_environment = root / "inputs/study-environment.json"
    if campaign.name.startswith("buflo-study-v1-"):
        from .buflo_study import validate_study_environment_receipt

        if study_environment.is_symlink() or not study_environment.is_file():
            raise ValueError("BuFLO study campaign has no frozen environment receipt")
        validate_study_environment_receipt(
            load_json(study_environment),
            expected_image_digest=load_json(root / "inputs/source.json")["image_digest"],
        )
        configuration["study_environment_sha256"] = sha256_file(study_environment)
        admission = root / "inputs/capture-admission.json"
        if _public_buflo_campaign(campaign.name):
            from .buflo_study import validate_capture_admission

            if admission.is_symlink() or not admission.is_file():
                raise ValueError("public BuFLO study campaign has no frozen capture admission")
            admitted = validate_capture_admission(admission)
            selected = [
                row
                for row in admitted["allowed_campaigns"]
                if row["campaign_name"] == campaign.name
                and row["campaign_sha256"] == sha256_file(campaign.path)
            ]
            if len(selected) != 1 or Path(selected[0]["result_root"]) != root:
                raise ValueError("frozen capture admission does not select this result root")
            configuration["capture_admission_sha256"] = sha256_file(admission)
            cohort = root / "inputs/formal-cohort.json"
            if campaign.name.startswith("buflo-study-v1-formal-"):
                from .buflo_study import validate_formal_cohort_manifest

                if cohort.is_symlink() or not cohort.is_file():
                    raise ValueError("formal BuFLO study campaign has no frozen cohort manifest")
                validate_formal_cohort_manifest(cohort)
                configuration["formal_cohort_sha256"] = sha256_file(cohort)
            elif cohort.exists() or cohort.is_symlink():
                raise ValueError("non-formal public campaign has an unexpected cohort manifest")
        elif admission.exists() or admission.is_symlink():
            raise ValueError("local study campaign has an unexpected capture admission")
    elif study_environment.exists() or study_environment.is_symlink():
        raise ValueError("non-study campaign has an unexpected study environment receipt")
    return configuration


def _frozen_workload_record(root: Path, workload: Workload) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": workload.id,
        "visits": workload.visits,
        "manifest": workload.path.relative_to(root).as_posix(),
        "sha256": workload.sha256,
        "resource_count": workload.resource_count,
        "origin_count": workload.origin_count,
    }
    if workload.chaff_qualification_path is not None:
        if (
            workload.chaff_manifest_path is None
            or workload.runtime_path is None
            or workload.chaff_qualification_scope
            not in {
                RESPONSE_ONLY_CHAFF_SCOPE,
                FULL_CHAFF_SCOPE,
            }
            or (
                workload.chaff_qualification_scope == FULL_CHAFF_SCOPE
                and workload.chaff_prefix_spec_path is None
            )
        ):
            raise ValueError(f"{workload.id} qualified chaff frozen inputs are incomplete")
        record.update(
            chaff_qualification=workload.chaff_qualification_path.relative_to(root).as_posix(),
            chaff_qualification_sha256=workload.chaff_qualification_sha256,
            chaff_manifest=workload.chaff_manifest_path.relative_to(root).as_posix(),
            chaff_manifest_sha256=workload.chaff_manifest_sha256,
            runtime_manifest=workload.runtime_path.relative_to(root).as_posix(),
            runtime_manifest_sha256=workload.runtime_sha256,
        )
        if workload.chaff_qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE:
            record["chaff_qualification_scope"] = RESPONSE_ONLY_CHAFF_SCOPE
        else:
            assert workload.chaff_prefix_spec_path is not None
            record.update(
                chaff_prefix_spec=workload.chaff_prefix_spec_path.relative_to(root).as_posix(),
                chaff_prefix_spec_sha256=workload.chaff_prefix_spec_sha256,
            )
    return record
