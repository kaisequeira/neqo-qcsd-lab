from __future__ import annotations

import base64
import csv
import fcntl
import hashlib
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
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import capture_session as capture_engine
from .class_acquisition import validate_class_study_preparation
from .class_study import (
    STUDY_ID,
    is_class_study_campaign_name,
    is_successor_study_id,
    parse_class_study_campaign_name,
)
from .defenses import defense_from_runtime_identity
from .experiment import (
    KERNEL_TX_EVIDENCE_DIRECTORY,
    KERNEL_TX_EVIDENCE_FILES,
    KERNEL_TX_EVIDENCE_RECEIPT_KEY,
    KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
    OBSERVER_TOPOLOGY_RECEIPT_KEY,
    SCHEDULER_RUNTIME_EVIDENCE_PATH,
    SCHEDULER_RUNTIME_RECEIPT_KEY,
    TERMINAL_DEFENSE_FAILURE_TYPES,
    accepted_sample_hashes,
    resolved_attempt_directory,
    resolved_sample_directory,
    scheduler_runtime_receipt,
    validate_accepted_kernel_tx_evidence,
    validate_accepted_observer_topology_receipt,
    validate_accepted_scheduler_runtime_receipt,
    validate_planned_sample_identity,
)
from .fidelity import (
    BUFLO_INCOMING_CREDIT_ADVERTISEMENT_DELAY_LIMIT_US,
    _runner_csv_u64,
    _schedule_realization_metrics,
    fidelity_eligible,
    terminal_evidence_render_receipt_valid,
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
    durable_create,
    fsync_directory,
    load_json,
    response_signature,
    sha256_bytes,
    sha256_file,
    source_metadata,
)

SCHEMA_VERSION = 1
CLASS_STUDY_SCHEMA_VERSION = 2
CLASS_STUDY_PUBLIC_ORIGIN_ENV = "QCSD_PUBLIC_ORIGIN_ONLY"
SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION, CLASS_STUDY_SCHEMA_VERSION})
PURPOSES = {"smoke", "fitting", "evaluation"}
EVIDENCE_ROLES = frozenset(
    {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }
)
COORDINATOR_ONLY_CAPTURE_ROLES = frozenset(
    {
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }
)
CLASS_STUDY_LAUNCH_ARTIFACT_TYPE = "qcsd-class-study-first-launch-claim"
CLASS_STUDY_LAUNCH_SCHEMA_VERSION = 1
CLASS_STUDY_LAUNCH_INPUT = "inputs/class-study-launch.json"
CLASS_STUDY_FOUNDATION_INPUT = "inputs/class-study-foundation.json"
CLASS_STUDY_READINESS_INPUT = "inputs/class-study-readiness.json"
CLASS_STUDY_HISTORICAL_PRE_INPUT = "inputs/class-study-historical-pre-snapshot.json"
CLASS_STUDY_SUCCESSOR_INPUT = "inputs/class-study-successor.json"
CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY = "class_study_foundation_sha256"
CLASS_STUDY_READINESS_CONFIGURATION_KEY = "class_study_readiness_sha256"
CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY = "class_study_historical_pre_snapshot_sha256"
CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY = "class_study_successor_sha256"
CLASS_STUDY_FOUNDATION_ENV = "QCSD_CLASS_FOUNDATION_ATTESTATION"
CLASS_STUDY_READINESS_ENV = "QCSD_CLASS_READINESS_ATTESTATION"
CLASS_STUDY_HISTORICAL_PRE_ENV = "QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT"
REQUEST_POLICIES = {"as-defined", "half-duplex"}
LEGACY_CAMPAIGN_KEYS = {
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
CAMPAIGN_KEYS = LEGACY_CAMPAIGN_KEYS | {
    "evidence_role",
    "sample_order",
    "class_study_cohort",
    "class_study_cohort_assembly",
    "class_study_successor",
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
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
WALKIE_TALKIE_RECEIVER_RAW_HEADROOM_BYTES = 1_200
RESPONSE_ONLY_CHAFF_DEFENSE_KINDS = frozenset({"front", "tamaraw", *BUFLO_STUDY_PARAMETER_KINDS})
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
    qualification_set_manifest_path: Path | None = None
    qualification_set_manifest_sha256: str | None = None


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
    schema_version: int = SCHEMA_VERSION
    evidence_role: str | None = None
    sample_order_scheme: str = "grouped"
    sample_order_window: int | None = None
    class_study_cohort_path: Path | None = None
    class_study_cohort_sha256: str | None = None
    class_study_cohort_assembly_path: Path | None = None
    class_study_cohort_assembly_sha256: str | None = None
    class_study_id: str | None = None
    class_study_successor_path: Path | None = None
    class_study_successor_sha256: str | None = None
    class_study_launch_namespace: str | None = None

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


def _load_successor_campaign_context(
    campaign_path: Path,
    *,
    source_bytes: bytes,
    raw_reference: object,
    schema_version: int,
    frozen_inputs: Path | None,
) -> dict[str, Any] | None:
    """Resolve one exact hash-namespaced successor plan before path admission."""

    if raw_reference is None:
        return None
    if schema_version != CLASS_STUDY_SCHEMA_VERSION:
        raise ValueError("class_study_successor is valid only for schema-two campaigns")
    if (
        not isinstance(raw_reference, str)
        or not raw_reference
        or Path(raw_reference).is_absolute()
        or Path(raw_reference).as_posix() != raw_reference
    ):
        raise ValueError("class_study_successor must be a normalised relative path")
    if frozen_inputs is None:
        restart_path = (campaign_path.parent / raw_reference).resolve()
        from .class_successor import validate_successor_restart

        restart = validate_successor_restart(restart_path)
        restart_root = restart_path.parent.parent
        expected_campaign = restart_root / "plan/campaigns" / campaign_path.name
        if campaign_path.resolve() != expected_campaign.resolve():
            raise ValueError("successor campaign is outside its hash-namespaced plan")
    else:
        restart_path = frozen_inputs / "class-study-successor.json"
        if restart_path.is_symlink() or not restart_path.is_file():
            raise ValueError("frozen successor campaign lacks its restart authority")
        from .class_study import validate_hash_bound_receipt
        from .class_successor import RESTART_RECEIPT_TYPE

        restart_value = load_json(restart_path)
        restart = validate_hash_bound_receipt(restart_value, expected_type=RESTART_RECEIPT_TYPE)
        restart_root = restart_path.parent
    artifacts = restart.get("immutable_plan_artifacts")
    if isinstance(artifacts, Mapping) and frozen_inputs is not None:
        matches = [
            binding
            for relative, binding in artifacts.items()
            if isinstance(relative, str)
            and relative.startswith("campaigns/")
            and isinstance(binding, Mapping)
            and binding.get("sha256") == sha256_bytes(source_bytes)
        ]
        campaign_binding = matches[0] if len(matches) == 1 else None
    else:
        campaign_binding = (
            artifacts.get(f"campaigns/{campaign_path.name}")
            if isinstance(artifacts, Mapping)
            else None
        )
    if not isinstance(campaign_binding, Mapping) or campaign_binding.get("sha256") != sha256_bytes(
        source_bytes
    ):
        raise ValueError("successor campaign bytes differ from the immutable restart plan")
    study_id = restart.get("study_id")
    namespace = restart.get("namespace")
    launch_namespace = namespace.get("launch_namespace") if isinstance(namespace, Mapping) else None
    if (
        not is_successor_study_id(study_id)
        or launch_namespace != f".{study_id}-launches"
    ):
        raise ValueError("successor restart has an invalid study/launch namespace")
    return {
        "study_id": study_id,
        "launch_namespace": launch_namespace,
        "restart_path": str(restart_path.resolve()),
        "restart_sha256": sha256_file(restart_path),
        "restart_root": str(restart_root.resolve()),
        "qualification_set_root": str(
            (restart_root / "qualification" / f"{study_id}-final-full").resolve()
        ),
    }


_CLASS_FITTED_EVIDENCE_ROLES = frozenset(
    {"pilot-compatibility", "certification", "formal"}
)


def _manifest_qualification_authority(path: Path, *, trust_root: Path) -> dict[str, Any]:
    """Read the authority carried by one trusted named qualification manifest."""

    from .class_attestation import validate_class_qualification_authority
    from .class_study import canonical_json_sha256

    manifest_path = _trusted_regular_input(
        path,
        root=trust_root,
        label="class-study named qualification-set manifest",
    )
    manifest = load_json(manifest_path)
    if not isinstance(manifest, Mapping):
        raise TypeError("class-study named qualification-set manifest is malformed")
    authority = validate_class_qualification_authority(
        manifest.get("qualification_authority")
    )
    if manifest.get("qualification_authority_sha256") != canonical_json_sha256(authority):
        raise ValueError("class-study named qualification authority digest is invalid")
    return authority


def _frozen_qualification_authority(
    frozen_inputs: Path,
    *,
    manifest_authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a manifest authority against its result-local foundation copy.

    A captured manifest intentionally preserves the original canonical
    foundation path.  The frozen copy has a result-local path, so reconstruct
    the authority from that fully validated copy and permit only that one path
    field to differ.  Every hash, payload hash, build identity and source field
    must remain byte-for-byte identical.

    This relocation allowance is deliberately limited to the foundation
    receipt itself.  That receipt's hash-bound build, gate and result paths are
    canonical external evidence prerequisites and must remain available for
    every deep revalidation.  A copied result directory is therefore not a
    standalone evidence archive; portability is provided by the separately
    verified handoff product.
    """

    from .class_attestation import (
        class_qualification_authority,
        validate_class_qualification_authority,
    )

    candidate = validate_class_qualification_authority(manifest_authority)
    foundation_path = _trusted_regular_input(
        frozen_inputs / "class-study-foundation.json",
        root=frozen_inputs,
        label="frozen class-study foundation attestation",
    )
    local = class_qualification_authority(
        foundation_path,
        deep_code_gate=True,
        runtime_role="collection",
    )
    relocated = {
        **candidate,
        "foundation_attestation": {
            **candidate["foundation_attestation"],
            "path": local["foundation_attestation"]["path"],
        },
    }
    if relocated != local:
        raise ValueError(
            "frozen class qualification authority differs from its foundation/build/source"
        )
    return candidate


def _class_fitted_qualification_authority(
    *,
    evidence_role: str | None,
    qualification_set: str | None,
    config_root: Path,
    successor_context: Mapping[str, Any] | None,
    frozen_inputs: Path | None,
    expected_authority: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Resolve the mandatory external authority for fitted class defenses."""

    if evidence_role not in _CLASS_FITTED_EVIDENCE_ROLES:
        return None
    if qualification_set is None:
        raise ValueError("fitted class-study campaign has no qualification set")
    from .chaff_qualification import NAMED_QUALIFICATION_SET_MANIFEST

    if frozen_inputs is not None:
        qualification_root = frozen_inputs / "chaff-qualifications"
        trust_root = frozen_inputs
    elif successor_context is not None:
        qualification_root = Path(str(successor_context["qualification_set_root"]))
        trust_root = Path(str(successor_context["restart_root"]))
    else:
        qualification_root = (
            config_root / "chaff-qualification-store" / "sets" / qualification_set
        )
        trust_root = config_root
    manifest_authority = _manifest_qualification_authority(
        qualification_root / NAMED_QUALIFICATION_SET_MANIFEST,
        trust_root=trust_root,
    )

    if frozen_inputs is not None:
        manifest_authority = _frozen_qualification_authority(
            frozen_inputs,
            manifest_authority=manifest_authority,
        )
    if frozen_inputs is None:
        from .class_attestation import class_qualification_authority

        if expected_authority is None:
            foundation_raw = os.environ.get(CLASS_STUDY_FOUNDATION_ENV)
            if not foundation_raw:
                raise ValueError(
                    "fitted class-study campaign requires its foundation qualification authority"
                )
        else:
            foundation = expected_authority.get("foundation_attestation")
            foundation_raw = (
                foundation.get("path") if isinstance(foundation, Mapping) else None
            )
            if not isinstance(foundation_raw, str) or not foundation_raw:
                raise ValueError("expected class qualification authority has no foundation path")
        reconstructed = class_qualification_authority(
            Path(foundation_raw),
            deep_code_gate=True,
            runtime_role="collection",
        )
        if expected_authority is not None and reconstructed != expected_authority:
            raise ValueError(
                "expected class qualification authority differs from its foundation"
            )
        expected_authority = reconstructed
    if expected_authority is not None:
        from .class_attestation import validate_class_qualification_authority

        expected = validate_class_qualification_authority(expected_authority)
        if manifest_authority != expected:
            raise ValueError(
                "class fitting qualification authority differs from the expected foundation"
            )
    return manifest_authority


def load_campaign(
    path: Path,
    *,
    expected_qualification_authority: Mapping[str, Any] | None = None,
) -> Campaign:
    """Load the single consolidated campaign schema."""

    return _load_campaign(
        path,
        frozen_inputs=None,
        allow_historical_research_bundle=False,
        expected_qualification_authority=expected_qualification_authority,
    )


def _load_campaign(
    path: Path,
    *,
    frozen_inputs: Path | None,
    allow_historical_research_bundle: bool = False,
    expected_qualification_authority: Mapping[str, Any] | None = None,
) -> Campaign:
    path = Path(os.path.abspath(path))
    try:
        source_bytes = path.read_bytes()
        source = yaml.safe_load(source_bytes.decode("utf-8"))
    except UnicodeError as error:
        raise ValueError("campaign YAML is not valid UTF-8") from error
    except yaml.YAMLError as error:
        raise ValueError(f"campaign YAML is invalid: {error}") from error
    value = _object(source, "campaign")
    schema_version = value.get("schema")
    if type(schema_version) is not int or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        choices = ", ".join(str(item) for item in sorted(SUPPORTED_SCHEMA_VERSIONS))
        raise ValueError(f"campaign schema must be one of: {choices}")
    successor_context = _load_successor_campaign_context(
        path,
        source_bytes=source_bytes,
        raw_reference=value.get("class_study_successor"),
        schema_version=schema_version,
        frozen_inputs=frozen_inputs,
    )
    if (
        schema_version == CLASS_STUDY_SCHEMA_VERSION
        and frozen_inputs is None
        and successor_context is None
    ):
        from .class_layout import require_canonical_fresh_child

        path = require_canonical_fresh_child(
            path,
            field="campaign_root",
            label="fresh schema-two class-study campaign",
        )
        if path.suffix != ".yml":
            raise ValueError("fresh schema-two class-study campaign must use a .yml filename")
    else:
        # Historical schema-one and frozen result-local loaders retain their
        # established resolution semantics.  Sealed-result verification owns
        # the trust boundary for the latter.
        path = path.resolve()
    _reject_unknown(
        value,
        LEGACY_CAMPAIGN_KEYS if schema_version == SCHEMA_VERSION else CAMPAIGN_KEYS,
        "campaign",
    )
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
    evidence_role, sample_order_scheme, sample_order_window = _load_class_study_execution(
        schema_version,
        evidence_role=value.get("evidence_role"),
        sample_order=value.get("sample_order"),
    )
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
    if successor_context is not None and frozen_inputs is None:
        config_root = (LAB_ROOT / "config").resolve()
    cohort_trust_root = (
        Path(successor_context["restart_root"]) / "plan"
        if successor_context is not None and frozen_inputs is None
        else config_root
    )
    workloads = _load_workloads(
        path,
        value["workloads"],
        purpose=purpose,
        schema_version=schema_version,
        frozen_inputs=frozen_inputs,
        config_root=config_root,
    )
    (
        class_study_cohort_path,
        class_study_cohort_sha256,
        class_study_cohort_assembly_path,
        class_study_cohort_assembly_sha256,
    ) = _load_class_study_cohort_binding(
        schema_version=schema_version,
        evidence_role=evidence_role,
        raw_path=value.get("class_study_cohort"),
        raw_assembly_path=value.get("class_study_cohort_assembly"),
        campaign_path=path,
        config_root=config_root,
        cohort_trust_root=cohort_trust_root,
        frozen_inputs=frozen_inputs,
        workload_ids=tuple(workload.id for workload in workloads),
        workload_hashes={workload.id: workload.sha256 for workload in workloads},
    )
    qualification_authority = _class_fitted_qualification_authority(
        evidence_role=evidence_role,
        qualification_set=qualification_set,
        config_root=config_root,
        successor_context=successor_context,
        frozen_inputs=frozen_inputs,
        expected_authority=expected_qualification_authority,
    )
    class_qualification_context = None
    if successor_context is not None and frozen_inputs is None and qualification_set is not None:
        from .class_fitting import QualificationContext

        restart_root = Path(successor_context["restart_root"])
        class_qualification_context = QualificationContext(
            workload_root=config_root / "workloads",
            sidecar_root=Path(successor_context["qualification_set_root"]),
            prefix_spec_root=(
                restart_root / "artifacts" / f"{STUDY_ID}-authoritative-fitting-prefix-specs"
            ),
            qualification_authority=qualification_authority,
            expected_qualification_set=qualification_set,
        )
    defenses = _load_defenses(
        (
            path.parent
            if successor_context is not None and frozen_inputs is None
            else config_root / "campaigns"
        ),
        value["defenses"],
        purpose,
        profile,
        {workload.id: workload.sha256 for workload in workloads},
        frozen_inputs=frozen_inputs,
        allow_historical_research_bundle=allow_historical_research_bundle,
        evidence_role=evidence_role,
        class_qualification_context=class_qualification_context,
        class_qualification_authority=qualification_authority,
        qualification_set=qualification_set,
        expected_successor_study_id=(
            str(successor_context["study_id"]) if successor_context is not None else None
        ),
        expected_successor_restart_sha256=(
            str(successor_context["restart_sha256"]) if successor_context is not None else None
        ),
    )
    has_defended_run = any(not defense.baseline for defense in defenses)
    qualification_scope = _required_chaff_qualification_scope(defenses)
    if (
        schema_version == SCHEMA_VERSION
        and qualification_set is not None
        and qualification_scope != RESPONSE_ONLY_CHAFF_SCOPE
    ):
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
            qualification_set_root_override=(
                Path(successor_context["qualification_set_root"])
                if successor_context is not None and frozen_inputs is None
                else None
            ),
        )
        if schema_version == CLASS_STUDY_SCHEMA_VERSION:
            if qualification_set is None:
                raise ValueError("schema-two defended campaigns require a named qualification set")
            if any(workload.qualification_set_manifest_path is None for workload in workloads):
                raise ValueError(
                    "schema-two defended campaigns require a manifest-bound qualification set"
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
    if (
        schema_version == CLASS_STUDY_SCHEMA_VERSION
        and frozen_inputs is None
        and successor_context is None
    ):
        from .class_layout import require_canonical_fresh_child

        path = require_canonical_fresh_child(
            path,
            field="campaign_root",
            filename=f"{name}.yml",
            label="fresh schema-two class-study campaign",
        )
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
        schema_version=schema_version,
        evidence_role=evidence_role,
        sample_order_scheme=sample_order_scheme,
        sample_order_window=sample_order_window,
        class_study_cohort_path=class_study_cohort_path,
        class_study_cohort_sha256=class_study_cohort_sha256,
        class_study_cohort_assembly_path=class_study_cohort_assembly_path,
        class_study_cohort_assembly_sha256=class_study_cohort_assembly_sha256,
        class_study_id=(
            str(successor_context["study_id"])
            if successor_context is not None
            else STUDY_ID
            if schema_version == CLASS_STUDY_SCHEMA_VERSION
            else None
        ),
        class_study_successor_path=(
            Path(successor_context["restart_path"]) if successor_context is not None else None
        ),
        class_study_successor_sha256=(
            str(successor_context["restart_sha256"]) if successor_context is not None else None
        ),
        class_study_launch_namespace=(
            str(successor_context["launch_namespace"])
            if successor_context is not None
            else f".{STUDY_ID}-launches"
            if schema_version == CLASS_STUDY_SCHEMA_VERSION
            else None
        ),
    )
    if purpose == "fitting":
        _validate_fitting_campaign(campaign, raw_limits=raw_limits)
    _validate_evidence_role(campaign)
    if schema_version == CLASS_STUDY_SCHEMA_VERSION:
        if class_study_cohort_path is None or class_study_cohort_assembly_path is None:
            raise AssertionError("class-study campaign lost its admission receipts")
        if successor_context is None:
            from .class_campaigns import validate_campaign_document

            validate_campaign_document(
                value,
                cohort_receipt=class_study_cohort_path,
                cohort_assembly_receipt=class_study_cohort_assembly_path,
                enforce_fresh_layout=frozen_inputs is None,
            )
    return campaign


def _load_class_study_cohort_binding(
    *,
    schema_version: int,
    evidence_role: str | None,
    raw_path: object,
    raw_assembly_path: object,
    campaign_path: Path,
    config_root: Path,
    frozen_inputs: Path | None,
    workload_ids: tuple[str, ...],
    workload_hashes: Mapping[str, str],
    cohort_trust_root: Path | None = None,
) -> tuple[Path | None, str | None, Path | None, str | None]:
    """Resolve the final cohort receipt without affecting historical campaigns."""

    if schema_version == SCHEMA_VERSION:
        if raw_path is not None or raw_assembly_path is not None:
            raise ValueError("campaign schema one cannot declare class-study cohort evidence")
        return None, None, None, None
    requires_final = evidence_role in {
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    }
    if raw_path is None or raw_assembly_path is None:
        raise ValueError(f"{evidence_role} evidence requires cohort and cohort-assembly receipts")
    for field, raw in (
        ("class_study_cohort", raw_path),
        ("class_study_cohort_assembly", raw_assembly_path),
    ):
        if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
            raise ValueError(f"{field} must be a nonempty relative path")
    cohort_candidate = (
        frozen_inputs / "class-study-cohort.json"
        if frozen_inputs is not None
        else campaign_path.parent / raw_path
    )
    assembly_candidate = (
        frozen_inputs / "class-study-cohort-assembly.json"
        if frozen_inputs is not None
        else campaign_path.parent / raw_assembly_path
    )
    receipt_path = _trusted_regular_input(
        cohort_candidate,
        root=(frozen_inputs if frozen_inputs is not None else (cohort_trust_root or config_root)),
        label="class-study cohort receipt",
    )
    assembly_path = _trusted_regular_input(
        assembly_candidate,
        root=(frozen_inputs if frozen_inputs is not None else (cohort_trust_root or config_root)),
        label="class-study cohort-assembly receipt",
    )
    from .class_cohort import cohort_workload_hashes, validate_cohort_assembly_receipt
    from .class_study import load_study_receipt

    receipt, selection = load_study_receipt(receipt_path)
    assembly = load_json(assembly_path)
    validate_cohort_assembly_receipt(assembly, cohort=receipt)
    expected = selection.final if requires_final else selection.pilot
    expected_ids = tuple(candidate.candidate_id for candidate in expected)
    if workload_ids != expected_ids:
        cohort = "final" if requires_final else "pilot"
        raise ValueError(f"{evidence_role} workload order differs from the {cohort} cohort")
    expected_hashes = cohort_workload_hashes(
        assembly,
        cohort=receipt,
        workload_ids=expected_ids,
    )
    if dict(workload_hashes) != expected_hashes:
        raise ValueError(f"{evidence_role} prepared workload bytes differ from cohort admission")
    return (
        receipt_path,
        sha256_file(receipt_path),
        assembly_path,
        sha256_file(assembly_path),
    )


def _load_class_study_execution(
    schema_version: int,
    *,
    evidence_role: object,
    sample_order: object,
) -> tuple[str | None, str, int | None]:
    """Parse the schema-two evidence and execution controls without changing v1."""

    if schema_version == SCHEMA_VERSION:
        if evidence_role is not None or sample_order is not None:
            raise ValueError("campaign schema one cannot declare class-study execution fields")
        return None, "grouped", None
    if not isinstance(evidence_role, str) or evidence_role not in EVIDENCE_ROLES:
        choices = ", ".join(sorted(EVIDENCE_ROLES))
        raise ValueError(f"schema-two campaign evidence_role must be one of: {choices}")
    if sample_order is None:
        return evidence_role, "grouped", None
    value = _object(sample_order, "sample_order")
    _reject_unknown(value, {"scheme", "window_size"}, "sample_order")
    if value.get("scheme") != "origin-aware-windowed":
        raise ValueError("sample_order scheme must be origin-aware-windowed")
    window = value.get("window_size")
    if type(window) is not int or not 2 <= window <= 100:
        raise ValueError("sample_order window_size must be an integer in [2, 100]")
    return evidence_role, "origin-aware-windowed", window


def _validate_evidence_role(campaign: Campaign) -> None:
    """Keep excluded fitting/qualification traffic out of formal result roles."""

    if campaign.schema_version == SCHEMA_VERSION:
        return
    expected_purpose = {
        "pilot-fitting": "fitting",
        "authoritative-fitting": "fitting",
        "pilot-compatibility": "smoke",
        "certification": "smoke",
        "canary": "smoke",
        "formal": "evaluation",
    }[str(campaign.evidence_role)]
    if campaign.purpose != expected_purpose:
        raise ValueError(f"{campaign.evidence_role} evidence requires purpose {expected_purpose}")
    expected_attempts = 1 if campaign.evidence_role == "certification" else 3
    if campaign.limits.max_attempts != expected_attempts:
        raise ValueError(
            f"{campaign.evidence_role} evidence requires max_attempts {expected_attempts}"
        )
    _validate_class_study_campaign_contract(campaign)


def _validate_class_study_campaign_contract(campaign: Campaign) -> None:
    """Enforce the preregistered matrices independently of generated YAML."""

    from .class_campaigns import (
        CAPTURE_LIMITS,
        FINAL_QUALIFICATION_SET,
        ORIGIN_AWARE_WINDOW,
        PILOT_QUALIFICATION_SET,
    )
    from .class_study import (
        COMPATIBILITY_MODES,
        FINAL_CLASS_COUNT,
        FORMAL_MODES,
        PILOT_COUNT,
        STUDY_ID,
    )

    role = str(campaign.evidence_role)
    study_id = campaign.class_study_id or STUDY_ID
    successor = campaign.class_study_successor_sha256 is not None
    expected_workloads = (
        PILOT_COUNT if role in {"pilot-fitting", "pilot-compatibility"} else FINAL_CLASS_COUNT
    )
    expected_visits = {
        "pilot-fitting": 2,
        "pilot-compatibility": 1,
        "authoritative-fitting": 10,
        "certification": 1,
        "canary": 1,
        "formal": 2,
    }[role]
    if len(campaign.workloads) != expected_workloads or any(
        workload.visits != expected_visits for workload in campaign.workloads
    ):
        raise ValueError(
            f"{role} evidence requires {expected_workloads} workloads with "
            f"{expected_visits} visit(s) each"
        )
    expected_policies = (
        ("as-defined", "half-duplex")
        if role in {"pilot-fitting", "authoritative-fitting"}
        else ("as-defined",)
    )
    if campaign.request_policies != expected_policies:
        raise ValueError(f"{role} evidence has the wrong request-policy matrix")
    expected_modes = (
        ("undefended",)
        if role in {"pilot-fitting", "authoritative-fitting", "canary"}
        else FORMAL_MODES
        if role == "formal"
        else COMPATIBILITY_MODES
    )
    observed_modes = tuple(defense.name for defense in campaign.defenses)
    if observed_modes != expected_modes:
        raise ValueError(f"{role} defenses differ from the fixed class-study mode order")
    expected_kinds = {
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
    if any(defense.kind != expected_kinds[defense.name] for defense in campaign.defenses):
        raise ValueError(f"{role} runtime kinds differ from the fixed class-study identities")
    if (
        campaign.sample_order_scheme != "origin-aware-windowed"
        or campaign.sample_order_window != ORIGIN_AWARE_WINDOW
    ):
        raise ValueError(f"{role} evidence requires the fixed origin-aware sample window")
    expected_name = {
        "pilot-fitting": f"{STUDY_ID}-pilot-fitting-1200",
        "pilot-compatibility": "classifier-multiorigin100-v1-pilot-compatibility-1080-1200",
        "authoritative-fitting": f"{STUDY_ID}-authoritative-fitting-1200",
        "certification": "classifier-multiorigin100-v1-certification-900-1200",
    }.get(role)
    if successor:
        expected_name = {
            "authoritative-fitting": f"{study_id}-authoritative-fitting-2000-1200",
            "certification": f"{study_id}-certification-900-1200",
        }.get(role)
    if role in {"canary", "formal"}:
        try:
            campaign_identity = parse_class_study_campaign_name(campaign.name)
        except ValueError as error:
            raise ValueError(f"{role} campaign name is not canonical") from error
        if (
            campaign_identity.study_id != study_id
            or campaign_identity.evidence_role != role
            or campaign_identity.block is None
        ):
            raise ValueError(f"{role} campaign name is not canonical")
    elif expected_name is not None and campaign.name != expected_name:
        raise ValueError(f"{role} campaign name is not canonical")
    expected_seed = int.from_bytes(
        hashlib.sha256(f"{study_id}\0{campaign.name}".encode()).digest()[:4],
        "big",
    )
    if campaign.seed != expected_seed:
        raise ValueError(f"{role} campaign seed differs from its canonical name")
    expected_attempts = 1 if role == "certification" else 3
    expected_limits = {**CAPTURE_LIMITS, "max_attempts": expected_attempts}
    if campaign.limits.as_dict() != expected_limits:
        raise ValueError(f"{role} capture limits differ from the fixed study contract")
    expected_qualification = {
        "pilot-compatibility": PILOT_QUALIFICATION_SET,
        "certification": FINAL_QUALIFICATION_SET,
        "formal": FINAL_QUALIFICATION_SET,
    }.get(role)
    if successor and role in {"certification", "formal"}:
        expected_qualification = f"{study_id}-final-full"
    if campaign.chaff_qualification_set != expected_qualification:
        raise ValueError(f"{role} qualification-set identity is not canonical")
    if role in {"pilot-compatibility", "certification", "canary", "formal"}:
        if campaign.defense_order_scheme != "cyclic-latin-square":
            raise ValueError(f"{role} evidence requires cyclic Latin defense ordering")
    elif (
        campaign.defense_order_scheme != "seeded-shuffle"
        or campaign.defense_order_block is not None
    ):
        raise ValueError(f"{role} fitting order differs from the fixed study contract")
    if role in {"canary", "formal"}:
        match = re.search(r"-([0-9]{2})-1200$", campaign.name)
        if match is None:
            raise ValueError(f"{role} campaign has no acquisition block")
        block = int(match.group(1))
        if not 1 <= block <= 10 or campaign.defense_order_block != block - 1:
            raise ValueError(f"{role} defense-order block differs from its campaign name")
    elif role in {"pilot-compatibility", "certification"} and (campaign.defense_order_block != 0):
        raise ValueError(f"{role} defense-order block must be zero")


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
    qualification_set_root_override: Path | None = None,
) -> tuple[Workload, ...]:
    """Bind the selected immutable sidecar contract and derived manifest."""

    from .chaff_qualification import (
        NAMED_QUALIFICATION_PREFIX_DIRECTORY,
        NAMED_QUALIFICATION_SET_MANIFEST,
        load_named_qualification_set,
        load_qualified_chaff,
        load_response_qualified_chaff,
    )

    if frozen_inputs is not None:
        qualification_scope = _frozen_chaff_qualification_scope(
            frozen_inputs,
            workloads,
            defense_derived_scope=qualification_scope,
        )
    set_manifest_path: Path | None = None
    set_manifest_sha256: str | None = None
    if frozen_inputs is None:
        config_root = campaign_path.parent.parent if config_root is None else config_root
        qualification_trust_root = config_root
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
            prefix_root: Path | None = None
        elif qualification_scope == FULL_CHAFF_SCOPE:
            if qualification_set is None:
                qualification_root = config_root / "chaff-qualification-store/v2"
                prefix_root = config_root / "chaff-prefix-specs/v2"
            else:
                from .chaff_qualification import validate_qualification_set

                qualification_set = validate_qualification_set(qualification_set)
                selected_root = (
                    qualification_set_root_override
                    if qualification_set_root_override is not None
                    else config_root / "chaff-qualification-store" / "sets" / qualification_set
                )
                trust_root = (
                    qualification_set_root_override.parent
                    if qualification_set_root_override is not None
                    else config_root
                )
                qualification_trust_root = trust_root
                qualification_root = _trusted_regular_directory(
                    selected_root,
                    root=trust_root,
                    label="selected full qualification set",
                )
                published_prefix_root = qualification_root / NAMED_QUALIFICATION_PREFIX_DIRECTORY
                prefix_root = _trusted_regular_directory(
                    (
                        published_prefix_root
                        if published_prefix_root.exists() or published_prefix_root.is_symlink()
                        else config_root / "chaff-prefix-specs" / "sets" / qualification_set
                    ),
                    root=qualification_trust_root,
                    label="selected full qualification prefix specifications",
                )
        else:
            raise ValueError(f"unsupported chaff qualification scope: {qualification_scope}")
        manifest_root: Path | None = None
    else:
        config_root = frozen_inputs
        qualification_trust_root = frozen_inputs
        qualification_root = frozen_inputs / "chaff-qualifications"
        prefix_root = (
            None
            if qualification_scope == RESPONSE_ONLY_CHAFF_SCOPE
            else frozen_inputs / "chaff-prefix-specs"
        )
        manifest_root = frozen_inputs / "chaff-manifests"
    candidate_set_manifest = qualification_root / NAMED_QUALIFICATION_SET_MANIFEST
    if candidate_set_manifest.exists() or candidate_set_manifest.is_symlink():
        named = load_named_qualification_set(
            candidate_set_manifest,
            workload_root=config_root / "workloads",
            sidecar_root=qualification_root,
            prefix_spec_root=prefix_root,
            expected_qualification_set=qualification_set,
            expected_qualification_scope=qualification_scope,
            expected_workload_ids=tuple(workload.id for workload in workloads),
            require_current_implementation=frozen_inputs is None,
        )
        set_manifest_path = named.manifest_path
        set_manifest_sha256 = named.manifest_sha256
    elif qualification_set is not None:
        expected_names = {f"{workload.id}.json" for workload in workloads}
        entries = list(qualification_root.iterdir())
        if {entry.name for entry in entries} != expected_names or any(
            entry.is_symlink() or not entry.is_file() for entry in entries
        ):
            raise ValueError(
                "selected response qualification set does not contain the exact "
                "campaign workload cohort"
            )
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
            root=qualification_trust_root,
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
                root=qualification_trust_root,
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
                qualification_set_manifest_path=set_manifest_path,
                qualification_set_manifest_sha256=set_manifest_sha256,
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
                "frozen chaff evidence ambiguously contains response-only manifests "
                "and prefix specs"
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
                if isinstance(record, Mapping) and isinstance(record.get("workload_id"), str)
            }
            if any(bindings.get(workload_id) != record for workload_id, record in expected.items()):
                raise ValueError(
                    "controlled regression parameters do not match loaded chaff qualifications"
                )
            continue
        if provenance.get("artifact_type") == "qcsd-class-study-research-defense-bundle":
            qualification = provenance.get("qualification_inputs")
            raw_bindings = (
                qualification.get("qualification_bindings")
                if isinstance(qualification, Mapping)
                else None
            )
            if not isinstance(raw_bindings, list):
                raise ValueError("class-study fitting bundle lacks qualification bindings")
            if any(value is None for record in expected.values() for value in record.values()):
                raise ValueError("class-study bundle requires qualified chaff for every workload")
            bindings = {
                record.get("workload_id"): dict(record)
                for record in raw_bindings
                if isinstance(record, Mapping) and isinstance(record.get("workload_id"), str)
            }
            if any(bindings.get(workload_id) != record for workload_id, record in expected.items()):
                raise ValueError(
                    "loaded chaff qualifications do not match class-study WT6 bindings"
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

    if campaign.schema_version == CLASS_STUDY_SCHEMA_VERSION:
        prefix = "class-study fitting campaigns require"
        expected_count = 120 if campaign.evidence_role == "pilot-fitting" else 100
        expected_visits = 2 if campaign.evidence_role == "pilot-fitting" else 10
        expected_stage = "pilot" if campaign.evidence_role == "pilot-fitting" else "authoritative"
        expected_name = (
            f"{campaign.class_study_id}-authoritative-fitting-2000-1200"
            if campaign.class_study_successor_sha256 is not None
            else f"{STUDY_ID}-{expected_stage}-fitting-1200"
        )
        if campaign.name != expected_name:
            raise ValueError(f"{prefix} the canonical {expected_stage} name")
        if campaign.profile != "research-1200":
            raise ValueError(f"{prefix} profile research-1200")
        if len(campaign.workloads) != expected_count or expected_count % 2:
            raise ValueError(f"{prefix} exactly {expected_count} unique workloads")
        if any(workload.visits != expected_visits for workload in campaign.workloads):
            raise ValueError(f"{prefix} exactly {expected_visits} visits per workload")
        if campaign.request_policies != ("as-defined", "half-duplex"):
            raise ValueError(
                f"{prefix} request policies in exact order: as-defined, then half-duplex"
            )
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
        return

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
    # Campaign directories live directly below config/ and workloads below
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
    schema_version: int,
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
            root=(
                frozen_inputs if frozen_inputs is not None else (config_root or path.parent.parent)
            ),
            label="workload manifest",
        )
        try:
            source_bytes = manifest_path.read_bytes()
            manifest = json.loads(source_bytes.decode("utf-8"))
        except UnicodeError as error:
            raise ValueError(f"workload manifest is not valid UTF-8: {manifest_path}") from error
        validate_manifest(manifest)
        if schema_version == CLASS_STUDY_SCHEMA_VERSION:
            validate_class_study_preparation(manifest, workload_id=workload_id)
        elif purpose in {"fitting", "evaluation"}:
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
    evidence_role: str | None = None,
    class_qualification_context: object | None = None,
    class_qualification_authority: Mapping[str, Any] | None = None,
    qualification_set: str | None = None,
    expected_successor_study_id: str | None = None,
    expected_successor_restart_sha256: str | None = None,
) -> tuple[capture_engine.Defense, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("defenses must be a non-empty list")
    if (expected_successor_study_id is None) != (expected_successor_restart_sha256 is None):
        raise ValueError("successor defense loading requires study and restart identity")
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
                class_research_dir = frozen_inputs / "defense-parameters" / "class-study"
                if (
                    kind in SEALED_RESEARCH_PARAMETER_KINDS
                    and (class_research_dir / original_name).is_file()
                ):
                    parameters_path = (class_research_dir / original_name).resolve()
                    provenance_path = (class_research_dir / "provenance.json").resolve()
                elif kind in SEALED_RESEARCH_PARAMETER_KINDS and (
                    purpose == "evaluation" or (research_dir / original_name).is_file()
                ):
                    parameters_path = (research_dir / original_name).resolve()
                    provenance_path = (research_dir / "provenance.json").resolve()
                else:
                    artifact_dir = frozen_inputs / "defense-parameters" / name
                    parameters_path = (artifact_dir / "parameters.json").resolve()
                    provenance_path = (artifact_dir / "provenance.json").resolve()

            # Provenance identifies the new common class-study bundle, but its
            # absence must still flow through the established bundle verifier.
            # In particular, an entirely absent legacy evaluation bundle has a
            # stable actionable error below rather than leaking FileNotFoundError
            # while merely probing its prospective provenance path.
            provenance_value = (
                load_json(provenance_path)
                if provenance_path.is_file() and not provenance_path.is_symlink()
                else None
            )
            is_class_bundle = (
                isinstance(provenance_value, Mapping)
                and provenance_value.get("artifact_type")
                == "qcsd-class-study-research-defense-bundle"
            )
            if (
                expected_successor_study_id is not None
                and kind in SEALED_RESEARCH_PARAMETER_KINDS
                and not is_class_bundle
            ):
                raise ValueError(
                    "successor data-driven defenses require their exact class fitting bundle"
                )
            if is_class_bundle:
                from .class_fitting import BUNDLE_FILES as CLASS_BUNDLE_FILES

                bundle_root = parameters_path.parent
                if evaluation_bundle_root is not None and bundle_root != evaluation_bundle_root:
                    raise ValueError(
                        "class-study data-driven defenses must reference one common bundle"
                    )
                evaluation_bundle_root = bundle_root
                expected_name = CLASS_BUNDLE_FILES[kind]
                if original_name != expected_name or parameters_path.name != expected_name:
                    raise ValueError(
                        f"class-study {kind} must reference {expected_name} from its common bundle"
                    )
            elif purpose == "evaluation" and kind in SEALED_RESEARCH_PARAMETER_KINDS:
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
                        purpose in {"smoke", "evaluation"} and kind in BUFLO_STUDY_PARAMETER_KINDS
                    ),
                    expected_qcsd_profile=profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
                    expected_workloads=workloads,
                    qualification_inputs_root=(
                        None if class_qualification_context is not None else base.parent
                    ),
                    qualification_context=class_qualification_context,
                    qualification_authority=class_qualification_authority,
                    expected_qualification_set=qualification_set,
                    campaign_evidence_role=evidence_role,
                    expected_successor_study_id=expected_successor_study_id,
                    expected_successor_restart_sha256=(expected_successor_restart_sha256),
                )
            else:
                artifact = validate_frozen_parameter_artifact(
                    parameters_path,
                    provenance_path=provenance_path,
                    original_parameter_name=Path(parameters).name,
                    expected_kind=kind,
                    allow_reviewed_fixture=purpose == "smoke",
                    allow_study_candidate=(
                        purpose in {"smoke", "evaluation"} and kind in BUFLO_STUDY_PARAMETER_KINDS
                    ),
                    expected_qcsd_profile=profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
                    expected_workloads=workloads,
                    allow_historical_research_bundle=allow_historical_research_bundle,
                    qualification_inputs_root=frozen_inputs,
                    qualification_context=None,
                    qualification_authority=class_qualification_authority,
                    expected_qualification_set=qualification_set,
                    campaign_evidence_role=evidence_role,
                    expected_successor_study_id=expected_successor_study_id,
                    expected_successor_restart_sha256=(expected_successor_restart_sha256),
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

    groups: list[list[dict[str, Any]]] = []
    workload_ranks = {
        workload_id: index
        for index, workload_id in enumerate(sorted(workload.id for workload in campaign.workloads))
    }
    for workload in campaign.workloads:
        for policy in campaign.request_policies:
            for visit in range(workload.visits):
                group: list[dict[str, Any]] = []
                defenses = list(campaign.defenses)
                if campaign.defense_order_scheme == "cyclic-latin-square":
                    if campaign.defense_order_block is None:
                        raise ValueError("Latin-square campaign has no acquisition block")
                    if campaign.schema_version == CLASS_STUDY_SCHEMA_VERSION:
                        # Schema two balances the complete workload/visit cross product.
                        # With 100 classes and two visits this yields exactly 25 uses of
                        # every one of the eight formal Latin rows in each block.
                        rank = workload_ranks[workload.id] * workload.visits + visit
                    else:
                        rank = workload_ranks[workload.id] + visit
                    phase = (campaign.defense_order_block + rank) % len(defenses)
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
                    group.append(
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
                groups.append(group)
    if campaign.sample_order_scheme == "grouped":
        return [sample for group in groups for sample in group]
    if campaign.sample_order_scheme != "origin-aware-windowed":
        raise AssertionError(f"unsupported sample order: {campaign.sample_order_scheme}")
    if campaign.sample_order_window is None:
        raise AssertionError("origin-aware campaign has no window size")
    ordered = _origin_aware_group_order(campaign, groups)
    samples: list[dict[str, Any]] = []
    for offset in range(0, len(ordered), campaign.sample_order_window):
        window = ordered[offset : offset + campaign.sample_order_window]
        width = max(len(group) for group in window)
        for position in range(width):
            samples.extend(group[position] for group in window if position < len(group))
    return samples


def _origin_aware_group_order(
    campaign: Campaign, groups: list[list[dict[str, Any]]]
) -> list[list[dict[str, Any]]]:
    """Greedily separate groups sharing any prepared endpoint origin."""

    if campaign.sample_order_window is None:
        raise AssertionError("origin-aware group ordering requires a window")
    workload_by_id = {workload.id: workload for workload in campaign.workloads}
    origin_sets = {
        workload.id: frozenset(capture_engine._manifest_origins(runtime_manifest(workload.data)))
        for workload in campaign.workloads
    }
    remaining = list(enumerate(groups))
    selected: list[tuple[int, list[dict[str, Any]]]] = []
    recent: list[frozenset[str]] = []
    while remaining:
        recent_union = frozenset().union(*recent) if recent else frozenset()

        def key(item: tuple[int, list[dict[str, Any]]]) -> tuple[int, int, int, int]:
            original_index, group = item
            workload_id = group[0]["workload_id"]
            if workload_id not in workload_by_id:
                raise AssertionError("planned group names an unknown workload")
            origins = origin_sets[workload_id]
            overlap = len(origins & recent_union)
            return (
                int(overlap > 0),
                overlap,
                _stable_seed("origin-aware-order", campaign.seed, original_index, workload_id),
                original_index,
            )

        chosen = min(remaining, key=key)
        remaining.remove(chosen)
        selected.append(chosen)
        chosen_origins = origin_sets[chosen[1][0]["workload_id"]]
        recent.append(chosen_origins)
        keep = max(campaign.sample_order_window - 1, 1)
        if len(recent) > keep:
            recent = recent[-keep:]
    return [group for _index, group in selected]


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
        if _is_class_study_campaign(campaign):
            result["chaff_qualification_set_manifest_sha256"] = (
                _class_study_campaign_qualification_manifest_sha256(campaign)
            )
        else:
            set_hashes = {
                workload.qualification_set_manifest_sha256
                for workload in campaign.workloads
                if workload.qualification_set_manifest_sha256 is not None
            }
            if len(set_hashes) == 1:
                [result["chaff_qualification_set_manifest_sha256"]] = set_hashes
    if campaign.class_study_cohort_sha256 is not None:
        result["class_study_cohort_sha256"] = campaign.class_study_cohort_sha256
    if campaign.class_study_cohort_assembly_sha256 is not None:
        result["class_study_cohort_assembly_sha256"] = campaign.class_study_cohort_assembly_sha256
    if campaign.class_study_id is not None:
        result["class_study_id"] = campaign.class_study_id
    if campaign.class_study_successor_sha256 is not None:
        result[CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY] = campaign.class_study_successor_sha256
    if campaign.defense_order_scheme != "seeded-shuffle":
        result["defense_order"] = {
            "scheme": campaign.defense_order_scheme,
            "block": campaign.defense_order_block,
        }
    if campaign.evidence_role is not None:
        result["schema"] = campaign.schema_version
        result["evidence_role"] = campaign.evidence_role
        result["defense_runtime_inputs"] = _class_study_campaign_runtime_inputs(campaign)
    if campaign.sample_order_scheme != "grouped":
        result["sample_order"] = {
            "scheme": campaign.sample_order_scheme,
            "window_size": campaign.sample_order_window,
        }
    return result


def _class_study_campaign_runtime_inputs(
    campaign: Campaign,
) -> dict[str, dict[str, Any]]:
    """Derive every loaded class campaign mode's typed runtime identity."""

    if not _is_class_study_campaign(campaign):
        raise ValueError("runtime-input identity requires a class-study campaign")
    identities: dict[str, dict[str, Any]] = {}
    for defense in campaign.defenses:
        if defense.name in identities:
            raise ValueError("class-study runtime-input identity has duplicate modes")
        if defense.kind in capture_engine.PARAMETER_FLAG_BY_KIND:
            if (
                defense.parameters_path is None
                or defense.parameters_provenance_path is None
                or not isinstance(defense.parameters_sha256, str)
                or _SHA256.fullmatch(defense.parameters_sha256) is None
                or not isinstance(defense.parameters_provenance_sha256, str)
                or _SHA256.fullmatch(defense.parameters_provenance_sha256) is None
                or not isinstance(defense.parameters_input_policy, str)
                or not defense.parameters_input_policy
                or defense.schedule_path is not None
            ):
                raise ValueError(
                    f"class-study {defense.name} runtime parameter binding is incomplete"
                )
            identity = {
                "identity_type": "hash-bound-parameter-artifact",
                "runtime_kind": defense.kind,
                "parameters_sha256": defense.parameters_sha256,
                "provenance_sha256": defense.parameters_provenance_sha256,
                "input_policy": defense.parameters_input_policy,
            }
        elif defense.kind == "static":
            if (
                defense.schedule_path is None
                or not isinstance(defense.schedule_sha256, str)
                or _SHA256.fullmatch(defense.schedule_sha256) is None
                or defense.mode not in capture_engine.STATIC_MODES
                or defense.parameters_path is not None
            ):
                raise ValueError("class-study static runtime schedule binding is incomplete")
            identity = {
                "identity_type": "hash-bound-static-schedule",
                "runtime_kind": defense.kind,
                "schedule_sha256": defense.schedule_sha256,
                "mode": defense.mode,
            }
        else:
            if (
                defense.kind not in {"none", "front", "tamaraw"}
                or defense.schedule_path is not None
                or defense.parameters_path is not None
            ):
                raise ValueError(
                    f"class-study {defense.name} source-bound runtime input is invalid"
                )
            identity = {
                "identity_type": (
                    "source-bound-no-defense" if defense.kind == "none" else "source-bound-built-in"
                ),
                "runtime_kind": defense.kind,
            }
        identities[defense.name] = identity
    return identities


def _class_study_campaign_qualification_manifest_sha256(
    campaign: Campaign,
) -> str | None:
    """Return the one loaded named-set manifest identity, or prove its absence."""

    values = {
        workload.qualification_set_manifest_sha256
        for workload in campaign.workloads
        if workload.qualification_set_manifest_sha256 is not None
    }
    if campaign.chaff_qualification_set is None:
        if values or any(
            workload.qualification_set_manifest_path is not None for workload in campaign.workloads
        ):
            raise ValueError(
                "class-study campaign has qualification-set evidence without a named set"
            )
        return None
    if len(values) != 1 or any(
        workload.qualification_set_manifest_path is None
        or workload.qualification_set_manifest_sha256 is None
        for workload in campaign.workloads
    ):
        raise ValueError("class-study named qualification-set binding is inconsistent")
    [digest] = values
    if _SHA256.fullmatch(digest) is None:
        raise ValueError("class-study named qualification-set digest is invalid")
    return digest


_FITTING_GENERATION_STAGES = {
    "pilot-compatibility": "pilot",
    "certification": "authoritative",
}
_FITTED_MODE_TO_KIND = {
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
}


def _class_study_configuration_runtime_inputs(
    configuration: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Recover typed runtime identities before a class-study resume mutates state."""

    raw = configuration.get("defense_runtime_inputs")
    if isinstance(raw, Mapping):
        return {
            str(name): dict(identity)
            for name, identity in raw.items()
            if isinstance(name, str) and isinstance(identity, Mapping)
        }
    records = configuration.get("defenses")
    if not isinstance(records, list) or not records:
        raise ValueError("class-study fitting-generation configuration has no defenses")
    identities: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise TypeError("class-study fitting-generation defense is malformed")
        name = record.get("name")
        kind = record.get("kind")
        if not isinstance(name, str) or not isinstance(kind, str) or name in identities:
            raise ValueError("class-study fitting-generation defense identity is invalid")
        if kind in capture_engine.PARAMETER_FLAG_BY_KIND:
            parameters_sha256 = record.get("parameters_sha256")
            provenance_sha256 = record.get("provenance_sha256")
            input_policy = record.get("input_policy")
            if (
                _SHA256.fullmatch(str(parameters_sha256)) is None
                or _SHA256.fullmatch(str(provenance_sha256)) is None
                or not isinstance(input_policy, str)
                or not input_policy
            ):
                raise ValueError(
                    f"class-study {name} fitting-generation parameter binding is incomplete"
                )
            identity = {
                "identity_type": "hash-bound-parameter-artifact",
                "runtime_kind": kind,
                "parameters_sha256": parameters_sha256,
                "provenance_sha256": provenance_sha256,
                "input_policy": input_policy,
            }
        elif kind == "static":
            schedule_sha256 = record.get("schedule_sha256")
            mode = record.get("mode")
            if (
                _SHA256.fullmatch(str(schedule_sha256)) is None
                or mode not in capture_engine.STATIC_MODES
            ):
                raise ValueError("class-study static fitting-generation binding is incomplete")
            identity = {
                "identity_type": "hash-bound-static-schedule",
                "runtime_kind": kind,
                "schedule_sha256": schedule_sha256,
                "mode": mode,
            }
        elif kind in {"none", "front", "tamaraw"}:
            identity = {
                "identity_type": (
                    "source-bound-no-defense" if kind == "none" else "source-bound-built-in"
                ),
                "runtime_kind": kind,
            }
        else:
            raise ValueError(f"class-study {name} fitting-generation runtime kind is invalid")
        identities[name] = identity
    return identities


def _class_study_fitting_runtime_projection(
    campaign_or_configuration: Campaign | Mapping[str, Any],
) -> dict[str, Any]:
    """Project the runtime bytes that a fitted-generation capability authorises."""

    from .class_study import COMPATIBILITY_MODES

    if isinstance(campaign_or_configuration, Campaign):
        role = campaign_or_configuration.evidence_role
        runtime_inputs = _class_study_campaign_runtime_inputs(campaign_or_configuration)
        qualification_set = campaign_or_configuration.chaff_qualification_set
        manifest_sha256 = _class_study_campaign_qualification_manifest_sha256(
            campaign_or_configuration
        )
    else:
        role = campaign_or_configuration.get("evidence_role")
        runtime_inputs = _class_study_configuration_runtime_inputs(campaign_or_configuration)
        qualification_set = campaign_or_configuration.get("chaff_qualification_set")
        manifest_sha256 = campaign_or_configuration.get(
            "chaff_qualification_set_manifest_sha256"
        )
    if role not in _FITTING_GENERATION_STAGES:
        raise ValueError(
            "fitting-generation authority is valid only for compatibility/certification"
        )
    if tuple(runtime_inputs) != COMPATIBILITY_MODES:
        raise ValueError("fitting-generation runtime map is not the exact nine-mode order")
    if (
        not isinstance(qualification_set, str)
        or not qualification_set
        or not isinstance(manifest_sha256, str)
        or _SHA256.fullmatch(manifest_sha256) is None
    ):
        raise ValueError("fitting-generation qualification manifest identity is incomplete")
    return {
        "defense_runtime_inputs": runtime_inputs,
        "qualification_set": qualification_set,
        "qualification_set_manifest_sha256": manifest_sha256,
    }


def _fitting_generation_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_class_study_fitting_generation(
    *,
    source_result_root: Path,
    expected_qualification_authority: Mapping[str, Any],
    campaign_path: Path | None = None,
    frozen_result_root: Path | None = None,
) -> dict[str, Any]:
    """Refit a compatibility/certification bundle from its exact predecessor.

    The ordinary campaign loader proves that the bundle is internally valid.
    This stronger promotion boundary supplies ``source_result_root`` so all
    fitted values and optimiser receipts are independently regenerated from
    the exact fitting result selected by the coordinator.
    """

    if (campaign_path is None) == (frozen_result_root is None):
        raise ValueError("fitting-generation verification requires one campaign or frozen result")
    frozen = frozen_result_root is not None
    campaign = (
        _campaign_from_frozen_inputs(
            Path(frozen_result_root),
            expected_qualification_authority=expected_qualification_authority,
        )
        if frozen
        else load_campaign(
            Path(campaign_path),
            expected_qualification_authority=expected_qualification_authority,
        )
    )
    role = campaign.evidence_role
    stage = _FITTING_GENERATION_STAGES.get(str(role))
    if stage is None:
        raise ValueError("fitting-generation verification requires compatibility/certification")

    fitted = {
        defense.name: defense
        for defense in campaign.defenses
        if defense.kind in SEALED_RESEARCH_PARAMETER_KINDS
    }
    if set(fitted) != set(_FITTED_MODE_TO_KIND):
        raise ValueError("fitting-generation campaign lacks the exact fitted-defense set")
    bundle_roots = {
        defense.parameters_path.parent.resolve()
        for defense in fitted.values()
        if defense.parameters_path is not None
    }
    provenance_paths = {
        defense.parameters_provenance_path.resolve()
        for defense in fitted.values()
        if defense.parameters_provenance_path is not None
    }
    if len(bundle_roots) != 1 or len(provenance_paths) != 1:
        raise ValueError("fitting-generation defenses do not share one complete bundle")
    [bundle_root] = bundle_roots
    [provenance_path] = provenance_paths
    if provenance_path.parent != bundle_root:
        raise ValueError("fitting-generation provenance is outside its common bundle")

    workload_roots = {workload.path.parent.resolve() for workload in campaign.workloads}
    sidecar_roots = {
        workload.chaff_qualification_path.parent.resolve()
        for workload in campaign.workloads
        if workload.chaff_qualification_path is not None
    }
    prefix_roots = {
        workload.chaff_prefix_spec_path.parent.resolve()
        for workload in campaign.workloads
        if workload.chaff_prefix_spec_path is not None
    }
    if len(workload_roots) != 1 or len(sidecar_roots) != 1 or len(prefix_roots) != 1:
        raise ValueError("fitting-generation qualification roots are not unique and complete")
    [workload_root] = workload_roots
    [sidecar_root] = sidecar_roots
    [prefix_spec_root] = prefix_roots

    from .class_attestation import validate_class_qualification_authority
    from .class_fitting import BUNDLE_FILES as CLASS_BUNDLE_FILES
    from .class_fitting import PROVENANCE_FILE as CLASS_PROVENANCE_FILE
    from .class_fitting import (
        QualificationContext,
        verify_class_fitting_bundle,
    )

    qualification_authority = validate_class_qualification_authority(
        expected_qualification_authority
    )

    source = Path(os.path.abspath(source_result_root))
    if source.is_symlink() or not source.is_dir():
        raise ValueError("fitting-generation source result is not a regular directory")
    source = source.resolve()
    verified = verify_class_fitting_bundle(
        bundle_root,
        qualification_context=QualificationContext(
            workload_root=workload_root,
            sidecar_root=sidecar_root,
            prefix_spec_root=prefix_spec_root,
            require_current_implementation=not frozen,
            expected_qualification_set=campaign.chaff_qualification_set,
            qualification_authority=qualification_authority,
        ),
        source_result_root=source,
    )
    if verified.stage != stage:
        raise ValueError("fitting-generation bundle has the wrong fitting stage")
    runtime = _class_study_fitting_runtime_projection(campaign)
    provenance_sha256 = sha256_file(bundle_root / CLASS_PROVENANCE_FILE)
    for mode, kind in _FITTED_MODE_TO_KIND.items():
        identity = runtime["defense_runtime_inputs"][mode]
        if (
            identity.get("parameters_sha256") != verified.artifact_hashes[kind]
            or identity.get("provenance_sha256") != provenance_sha256
            or fitted[mode].parameters_path.name != CLASS_BUNDLE_FILES[kind]
        ):
            raise ValueError("fitting-generation runtime identity differs from verified bundle")
    evidence_path = source / "evidence.sha256"
    if evidence_path.is_symlink() or not evidence_path.is_file():
        raise ValueError("fitting-generation source result has no regular evidence seal")
    # Close bundle/manifest replacement races after the independent refit.  The
    # coordinator capability performs the same comparison again after the
    # campaign is reloaded by run_campaign/resume_campaign.
    _revalidate_loaded_class_study_runtime_files(campaign)
    return {
        "schema_version": 1,
        "evidence_role": role,
        "source_result": {
            "root": str(source),
            "evidence_sha256": sha256_file(evidence_path),
        },
        "bundle": {
            "root": str(bundle_root),
            "stage": stage,
            "provenance_sha256": provenance_sha256,
            "parameter_sha256": {
                mode: verified.artifact_hashes[kind]
                for mode, kind in _FITTED_MODE_TO_KIND.items()
            },
        },
        "capture_runtime": runtime,
    }


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
            raise RuntimeError(
                "another BuFLO-study capture or resume holds the global lock"
            ) from error
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


def _is_class_study_campaign(campaign: Campaign) -> bool:
    """Return whether a campaign carries the complete schema-two class identity."""

    study_id = campaign.class_study_id or STUDY_ID
    try:
        name_identity = parse_class_study_campaign_name(campaign.name)
    except ValueError:
        return False
    return bool(
        campaign.schema_version == CLASS_STUDY_SCHEMA_VERSION
        and campaign.evidence_role in EVIDENCE_ROLES
        and name_identity.study_id == study_id
        and name_identity.evidence_role == campaign.evidence_role
        and campaign.class_study_cohort_sha256 is not None
        and campaign.class_study_cohort_assembly_sha256 is not None
    )


@dataclass(frozen=True)
class _ClassStudyCoordinatorCaptureAuthority:
    """Process-local proof that the coordinator validated prerequisite evidence."""

    campaign_identity: tuple[str, str, str, str, str, str, str | None]
    prerequisite_ledger: tuple[tuple[str, str, int | None, str, str], ...]
    fitting_generation_sha256: str | None
    fitting_runtime_sha256: str | None


_CLASS_STUDY_COORDINATOR_CAPTURE_AUTHORITY: ContextVar[
    _ClassStudyCoordinatorCaptureAuthority | None
] = ContextVar("qcsd_class_study_coordinator_capture_authority", default=None)


def _class_study_coordinator_campaign_identity(
    campaign_or_configuration: Campaign | Mapping[str, Any],
) -> tuple[str, str, str, str, str, str, str | None] | None:
    """Return the immutable identity for a coordinator-only capture role."""

    if isinstance(campaign_or_configuration, Campaign):
        role = campaign_or_configuration.evidence_role
        if role not in COORDINATOR_ONLY_CAPTURE_ROLES:
            return None
        if not _is_class_study_campaign(campaign_or_configuration):
            raise ValueError("coordinator-only capture is not a complete class-study campaign")
        name = campaign_or_configuration.name
        study_id = campaign_or_configuration.class_study_id or STUDY_ID
        campaign_sha256 = sha256_bytes(campaign_or_configuration.source_bytes)
        cohort_sha256 = campaign_or_configuration.class_study_cohort_sha256
        assembly_sha256 = campaign_or_configuration.class_study_cohort_assembly_sha256
        successor_sha256 = campaign_or_configuration.class_study_successor_sha256
    else:
        role = campaign_or_configuration.get("evidence_role")
        if role not in COORDINATOR_ONLY_CAPTURE_ROLES:
            return None
        name = campaign_or_configuration.get("name")
        study_id = campaign_or_configuration.get("class_study_id", STUDY_ID)
        campaign_sha256 = campaign_or_configuration.get("campaign_sha256")
        cohort_sha256 = campaign_or_configuration.get("class_study_cohort_sha256")
        assembly_sha256 = campaign_or_configuration.get("class_study_cohort_assembly_sha256")
        successor_sha256 = campaign_or_configuration.get(CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY)
    try:
        name_identity = parse_class_study_campaign_name(name)
    except ValueError:
        name_identity = None
    if (
        not isinstance(name, str)
        or not isinstance(role, str)
        or not isinstance(study_id, str)
        or name_identity is None
        or name_identity.study_id != study_id
        or name_identity.evidence_role != role
        or not isinstance(campaign_sha256, str)
        or _SHA256.fullmatch(campaign_sha256) is None
        or not isinstance(cohort_sha256, str)
        or _SHA256.fullmatch(cohort_sha256) is None
        or not isinstance(assembly_sha256, str)
        or _SHA256.fullmatch(assembly_sha256) is None
        or (
            successor_sha256 is not None
            and (
                not isinstance(successor_sha256, str) or _SHA256.fullmatch(successor_sha256) is None
            )
        )
    ):
        raise ValueError("coordinator-only class-study capture identity is malformed")
    return (
        name,
        role,
        study_id,
        campaign_sha256,
        cohort_sha256,
        assembly_sha256,
        successor_sha256,
    )


def _class_study_coordinator_prerequisite_ledger(
    records: tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, str, int | None, str, str], ...]:
    """Reduce verified prerequisite records to a stable, non-empty ledger."""

    ledger: list[tuple[str, str, int | None, str, str]] = []
    for record in records:
        name = record.get("name")
        role = record.get("evidence_role")
        block = record.get("block")
        root = record.get("root")
        evidence_sha256 = record.get("evidence_sha256")
        if (
            not isinstance(name, str)
            or not isinstance(role, str)
            or (block is not None and (not isinstance(block, int) or isinstance(block, bool)))
            or not isinstance(root, str)
            or not isinstance(evidence_sha256, str)
            or _SHA256.fullmatch(evidence_sha256) is None
        ):
            raise ValueError("class-study prerequisite ledger entry is malformed")
        ledger.append((name, role, block, root, evidence_sha256))
    if not ledger or len(set(ledger)) != len(ledger):
        raise ValueError("class-study prerequisite ledger must be non-empty and unique")
    return tuple(
        sorted(
            ledger,
            key=lambda item: (
                item[0],
                item[1],
                -1 if item[2] is None else item[2],
                item[3],
                item[4],
            ),
        )
    )


@contextmanager
def _class_study_coordinator_capture_authority(
    campaign_configuration: Mapping[str, Any],
    prerequisite_records: tuple[Mapping[str, Any], ...],
    fitting_generation: Mapping[str, Any] | None = None,
):
    """Authorise one identity-bound launch after coordinator prerequisite checks."""

    identity = _class_study_coordinator_campaign_identity(campaign_configuration)
    if identity is None:
        yield
        return
    if not prerequisite_records and (
        identity[1] == "pilot-fitting"
        or (identity[1] == "authoritative-fitting" and identity[6] is not None)
    ):
        # Pilot fitting is the initial capture stage. A successor restart
        # deliberately begins with fresh authoritative fitting rather than
        # reusing predecessor results. The latter's immutable restart SHA is
        # part of the exact coordinator capability identity.
        ledger = ()
    else:
        ledger = _class_study_coordinator_prerequisite_ledger(prerequisite_records)
    generation_sha256: str | None = None
    runtime_sha256: str | None = None
    if identity[1] in _FITTING_GENERATION_STAGES:
        if not isinstance(fitting_generation, Mapping):
            raise ValueError(
                "compatibility/certification capture lacks fitting-generation authority"
            )
        source = fitting_generation.get("source_result")
        bundle = fitting_generation.get("bundle")
        runtime = fitting_generation.get("capture_runtime")
        expected_source_role = (
            "pilot-fitting" if identity[1] == "pilot-compatibility" else "authoritative-fitting"
        )
        expected_runtime = _class_study_fitting_runtime_projection(campaign_configuration)
        if (
            set(fitting_generation)
            != {"schema_version", "evidence_role", "source_result", "bundle", "capture_runtime"}
            or fitting_generation.get("schema_version") != 1
            or fitting_generation.get("evidence_role") != identity[1]
            or not isinstance(source, Mapping)
            or set(source) != {"root", "evidence_sha256"}
            or not isinstance(source.get("root"), str)
            or not isinstance(source.get("evidence_sha256"), str)
            or _SHA256.fullmatch(source["evidence_sha256"]) is None
            or not isinstance(bundle, Mapping)
            or set(bundle)
            != {"root", "stage", "provenance_sha256", "parameter_sha256"}
            or not isinstance(bundle.get("root"), str)
            or bundle.get("stage") != _FITTING_GENERATION_STAGES[identity[1]]
            or not isinstance(bundle.get("provenance_sha256"), str)
            or _SHA256.fullmatch(bundle["provenance_sha256"]) is None
            or not isinstance(bundle.get("parameter_sha256"), Mapping)
            or set(bundle["parameter_sha256"]) != set(_FITTED_MODE_TO_KIND)
            or any(
                not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
                for digest in bundle["parameter_sha256"].values()
            )
            or not isinstance(runtime, Mapping)
            or dict(runtime) != expected_runtime
        ):
            raise ValueError("class-study fitting-generation authority is malformed or mismatched")
        runtime_inputs = runtime["defense_runtime_inputs"]
        assert isinstance(runtime_inputs, Mapping)
        parameter_sha256 = bundle["parameter_sha256"]
        assert isinstance(parameter_sha256, Mapping)
        if any(
            runtime_inputs[mode].get("parameters_sha256") != parameter_sha256[mode]
            or runtime_inputs[mode].get("provenance_sha256")
            != bundle["provenance_sha256"]
            for mode in _FITTED_MODE_TO_KIND
        ):
            raise ValueError(
                "class-study fitting-generation bundle differs from its capture runtime"
            )
        matching = [
            item
            for item in ledger
            if item[1] == expected_source_role
            and Path(item[3]).resolve() == Path(source["root"]).resolve()
            and item[4] == source["evidence_sha256"]
        ]
        if len(matching) != 1:
            raise ValueError("fitting-generation authority uses another prerequisite result")
        generation_sha256 = sha256_bytes(_fitting_generation_json_bytes(fitting_generation))
        runtime_sha256 = sha256_bytes(_fitting_generation_json_bytes(runtime))
    elif fitting_generation is not None:
        raise ValueError("non-fitted capture has unexpected fitting-generation authority")
    authority = _ClassStudyCoordinatorCaptureAuthority(
        campaign_identity=identity,
        prerequisite_ledger=ledger,
        fitting_generation_sha256=generation_sha256,
        fitting_runtime_sha256=runtime_sha256,
    )
    token = _CLASS_STUDY_COORDINATOR_CAPTURE_AUTHORITY.set(authority)
    try:
        yield
    finally:
        _CLASS_STUDY_COORDINATOR_CAPTURE_AUTHORITY.reset(token)


def _require_class_study_coordinator_capture_authority(
    campaign_or_configuration: Campaign | Mapping[str, Any],
) -> None:
    """Reject generic launch/resume for every prerequisite-ordered class role."""

    identity = _class_study_coordinator_campaign_identity(campaign_or_configuration)
    if identity is None:
        return
    authority = _CLASS_STUDY_COORDINATOR_CAPTURE_AUTHORITY.get()
    if authority is None or authority.campaign_identity != identity:
        raise ValueError(
            "ordered class-study capture must be launched through the class-study "
            "coordinator with its validated prerequisite ledger or restart authority"
        )
    if identity[1] in _FITTING_GENERATION_STAGES:
        if (
            authority.fitting_generation_sha256 is None
            or authority.fitting_runtime_sha256 is None
        ):
            raise ValueError("compatibility/certification capability lacks fitting generation")
        if isinstance(campaign_or_configuration, Campaign):
            _revalidate_loaded_class_study_runtime_files(campaign_or_configuration)
        runtime = _class_study_fitting_runtime_projection(campaign_or_configuration)
        if (
            sha256_bytes(_fitting_generation_json_bytes(runtime))
            != authority.fitting_runtime_sha256
        ):
            raise ValueError(
                "compatibility/certification runtime differs from fitted-generation authority"
            )
    elif (
        authority.fitting_generation_sha256 is not None
        or authority.fitting_runtime_sha256 is not None
    ):
        raise ValueError("non-fitted capture capability contains fitting-generation authority")


def _has_durable_attempt_budget(campaign: Campaign) -> bool:
    return campaign.name.startswith("buflo-study-v1-") or _is_class_study_campaign(campaign)


def _has_terminal_strict_defense_fidelity_failure(
    experiment: Mapping[str, Any],
) -> bool:
    """Whether a durable study must stop for a client-side defence/QCSD repair."""

    if not _has_durable_attempt_name(experiment.get("name")):
        return False
    samples = experiment.get("samples")
    return isinstance(samples, list) and any(
        isinstance(sample, Mapping)
        and sample.get("state") == "failed"
        and isinstance(sample.get("failure"), Mapping)
        and sample["failure"].get("type") in TERMINAL_DEFENSE_FAILURE_TYPES
        for sample in samples
    )


def _has_durable_attempt_name(name: object) -> bool:
    return isinstance(name, str) and (
        name.startswith("buflo-study-v1-")
        or is_class_study_campaign_name(name)
    )


def _require_class_study_public_origin_policy(campaign_or_name: Campaign | object) -> None:
    is_class_study = (
        _is_class_study_campaign(campaign_or_name)
        if isinstance(campaign_or_name, Campaign)
        else is_class_study_campaign_name(campaign_or_name)
    )
    if is_class_study and os.environ.get(CLASS_STUDY_PUBLIC_ORIGIN_ENV) != "1":
        raise ValueError("class-study capture requires QCSD_PUBLIC_ORIGIN_ONLY=1 before launch")


def run_campaign(path: Path, results_root: Path = Path("/lab/results")) -> Path:
    campaign = load_campaign(path)
    _require_class_study_coordinator_capture_authority(campaign)
    if _is_class_study_campaign(campaign):
        results_root = _canonical_class_study_results_root(results_root)
    lock_held = (
        campaign.name.startswith("buflo-study-v1-")
        and os.environ.get("QCSD_BUFLO_CAPTURE_LOCK_HELD") == "1"
    ) or (
        _is_class_study_campaign(campaign) and os.environ.get("QCSD_CLASS_CAPTURE_LOCK_HELD") == "1"
    )
    if _has_durable_attempt_budget(campaign) and not lock_held:
        with _study_capture_lock(results_root):
            return _run_loaded_campaign(campaign, results_root)
    return _run_loaded_campaign(campaign, results_root)


def _class_study_launch_key(campaign: Campaign) -> str:
    if not _is_class_study_campaign(campaign):
        raise ValueError("first-launch claim requires a class-study campaign")
    from .class_study import class_study_launch_identity, class_study_launch_key

    identity = class_study_launch_identity(
        study_id=str(campaign.class_study_id),
        campaign_name=campaign.name,
        evidence_role=str(campaign.evidence_role),
        cohort_sha256=str(campaign.class_study_cohort_sha256),
        cohort_assembly_sha256=str(campaign.class_study_cohort_assembly_sha256),
    )
    return class_study_launch_key(**identity)


def _class_study_launch_namespace(campaign: Campaign) -> str:
    """Return the sole registry namespace admitted for this study identity."""

    study_id = campaign.class_study_id or STUDY_ID
    expected = f".{study_id}-launches"
    declared = campaign.class_study_launch_namespace
    if declared is not None and declared != expected:
        raise ValueError("class-study launch namespace differs from its study identity")
    return expected


def _class_study_launch_payload(
    campaign: Campaign,
    *,
    result_root: Path,
    source: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    payload = {
        "study_id": campaign.class_study_id or STUDY_ID,
        "launch_key": _class_study_launch_key(campaign),
        "campaign_name": campaign.name,
        "campaign_sha256": sha256_bytes(campaign.source_bytes),
        "evidence_role": campaign.evidence_role,
        "class_study_cohort_sha256": campaign.class_study_cohort_sha256,
        "class_study_cohort_assembly_sha256": (campaign.class_study_cohort_assembly_sha256),
        "result_root": str(result_root.resolve()),
        "created_at": created_at,
        "source": dict(source),
        "policy": "one-result-root-per-campaign-and-cohort-assembly",
    }
    if campaign.class_study_successor_sha256 is not None:
        payload["class_study_successor_sha256"] = campaign.class_study_successor_sha256
        payload["launch_namespace"] = campaign.class_study_launch_namespace
    return payload


def _bind_class_study_launch(payload: Mapping[str, Any]) -> dict[str, Any]:
    detached = json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    digest = sha256_bytes(json.dumps(detached, sort_keys=True, separators=(",", ":")).encode())
    return {
        "schema_version": CLASS_STUDY_LAUNCH_SCHEMA_VERSION,
        "artifact_type": CLASS_STUDY_LAUNCH_ARTIFACT_TYPE,
        "payload_sha256": digest,
        "payload": detached,
    }


def _validate_class_study_launch_value(
    value: Any,
    *,
    campaign: Campaign,
    result_root: Path,
    source: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "artifact_type",
        "payload_sha256",
        "payload",
    }:
        raise ValueError("class-study first-launch claim has an invalid envelope")
    payload = value.get("payload")
    if (
        value.get("schema_version") != CLASS_STUDY_LAUNCH_SCHEMA_VERSION
        or value.get("artifact_type") != CLASS_STUDY_LAUNCH_ARTIFACT_TYPE
        or not isinstance(payload, Mapping)
        or value.get("payload_sha256")
        != sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    ):
        raise ValueError("class-study first-launch claim does not verify")
    expected = _class_study_launch_payload(
        campaign,
        result_root=result_root,
        source=source,
        created_at=str(payload.get("created_at")),
    )
    if dict(payload) != expected:
        raise ValueError("class-study first-launch claim differs from its campaign")
    return dict(payload)


def _class_study_authority_specification(
    campaign: Campaign,
) -> dict[str, tuple[str, str]]:
    """Return the exact authority inputs required by one class-study role."""

    if not _is_class_study_campaign(campaign):
        raise ValueError("class-study authority requires a class-study campaign")
    if campaign.evidence_role not in EVIDENCE_ROLES:
        raise ValueError("class-study campaign has no recognised evidence role")
    required = {
        CLASS_STUDY_FOUNDATION_ENV: (
            CLASS_STUDY_FOUNDATION_INPUT,
            CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY,
        )
    }
    if campaign.evidence_role in {"canary", "formal"}:
        required.update(
            {
                CLASS_STUDY_READINESS_ENV: (
                    CLASS_STUDY_READINESS_INPUT,
                    CLASS_STUDY_READINESS_CONFIGURATION_KEY,
                ),
                CLASS_STUDY_HISTORICAL_PRE_ENV: (
                    CLASS_STUDY_HISTORICAL_PRE_INPUT,
                    CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY,
                ),
            }
        )
    return required


def _class_study_authority_paths(campaign: Campaign) -> dict[str, Path]:
    """Resolve prospective authority without creating any result state."""

    environment = {
        CLASS_STUDY_FOUNDATION_ENV: os.environ.get(CLASS_STUDY_FOUNDATION_ENV),
        CLASS_STUDY_READINESS_ENV: os.environ.get(CLASS_STUDY_READINESS_ENV),
        CLASS_STUDY_HISTORICAL_PRE_ENV: os.environ.get(CLASS_STUDY_HISTORICAL_PRE_ENV),
    }
    required = _class_study_authority_specification(campaign)
    unexpected = sorted(
        name for name, value in environment.items() if value is not None and name not in required
    )
    if unexpected:
        raise ValueError("unexpected class-study authority environment: " + ", ".join(unexpected))

    resolved: dict[str, Path] = {}
    for name, (relative, _configuration_key) in required.items():
        raw_path = environment[name]
        if not raw_path:
            raise ValueError(f"{campaign.evidence_role} campaign requires {name}")
        path = Path(raw_path)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{name} must name a regular non-symlink file")
        resolved[relative] = path.resolve()
    return resolved


def _validate_class_study_authority_files(
    campaign: Campaign,
    *,
    source: Mapping[str, Any],
    paths: Mapping[str, Path],
) -> dict[str, Mapping[str, Any]]:
    """Reconstruct authority and bind it to source, build, and cohort."""

    from .class_attestation import (
        validate_class_foundation_attestation,
        validate_class_historical_snapshot,
        validate_class_readiness_attestation,
    )

    required_relatives = {
        relative
        for relative, _configuration_key in _class_study_authority_specification(campaign).values()
    }
    if set(paths) != required_relatives:
        raise ValueError("class-study authority file set differs from its role")

    foundation_path = paths[CLASS_STUDY_FOUNDATION_INPUT]
    foundation = validate_class_foundation_attestation(
        foundation_path,
        deep_code_gate=True,
        runtime_role="collection",
    )
    if foundation.get("source") != dict(source):
        raise ValueError("class-study foundation uses a different source identity")
    if campaign.class_study_successor_path is not None:
        from .class_study import canonical_json_sha256, validate_hash_bound_receipt
        from .class_successor import RESTART_RECEIPT_TYPE

        successor = validate_hash_bound_receipt(
            load_json(campaign.class_study_successor_path),
            expected_type=RESTART_RECEIPT_TYPE,
        )
        if (
            successor.get("predecessor_foundation_sha256") != sha256_file(foundation_path)
            or successor.get("source_sha256") != canonical_json_sha256(source)
            or successor.get("build_execution_identity_sha256")
            != canonical_json_sha256(foundation.get("build_execution_identity"))
        ):
            raise ValueError("successor campaign foundation/source/build differs from its restart")
    validated: dict[str, Mapping[str, Any]] = {"foundation": foundation}
    if campaign.evidence_role not in {"canary", "formal"}:
        return validated

    readiness_path = paths[CLASS_STUDY_READINESS_INPUT]
    snapshot_path = paths[CLASS_STUDY_HISTORICAL_PRE_INPUT]
    readiness = validate_class_readiness_attestation(
        readiness_path,
        deep_code_gate=True,
    )
    snapshot = validate_class_historical_snapshot(
        snapshot_path,
        expected_phase="pre-formal",
    )
    evidence = readiness.get("evidence")
    final_cohort = evidence.get("final_cohort") if isinstance(evidence, Mapping) else None
    final_assembly = (
        evidence.get("final_cohort_assembly") if isinstance(evidence, Mapping) else None
    )
    readiness_foundation = evidence.get("foundation") if isinstance(evidence, Mapping) else None
    snapshot_readiness = snapshot.get("readiness")
    readiness_successor = (
        evidence.get("successor_restart") if isinstance(evidence, Mapping) else None
    )
    if (
        readiness.get("source") != dict(source)
        or snapshot.get("source") != dict(source)
        or readiness.get("build_execution_identity") != foundation.get("build_execution_identity")
        or not isinstance(readiness_foundation, Mapping)
        or readiness_foundation.get("sha256") != sha256_file(foundation_path)
        or not isinstance(snapshot_readiness, Mapping)
        or snapshot_readiness.get("sha256") != sha256_file(readiness_path)
        or not isinstance(final_cohort, Mapping)
        or final_cohort.get("sha256") != campaign.class_study_cohort_sha256
        or not isinstance(final_assembly, Mapping)
        or final_assembly.get("sha256") != campaign.class_study_cohort_assembly_sha256
        or (
            campaign.class_study_successor_sha256 is not None
            and (
                not isinstance(readiness_successor, Mapping)
                or readiness_successor.get("sha256") != campaign.class_study_successor_sha256
                or readiness.get("study_id") != campaign.class_study_id
                or snapshot.get("study_id") != campaign.class_study_id
            )
        )
    ):
        raise ValueError("class-study capture authority differs from source, build, or cohort")
    validated.update(readiness=readiness, historical_pre_snapshot=snapshot)
    return validated


def _study_environment_from_environment(
    campaign: Campaign,
    source: Mapping[str, Any],
) -> tuple[bytes, Any, Mapping[str, Any]] | None:
    """Decode and validate the prospective host environment without writing it."""

    encoded = os.environ.get("QCSD_STUDY_ENVIRONMENT_B64")
    is_study = campaign.name.startswith("buflo-study-v1-") or _is_class_study_campaign(campaign)
    if not is_study:
        if encoded is not None:
            raise ValueError("study environment receipt cannot be applied to a non-study campaign")
        return None
    if not encoded:
        raise ValueError("research campaign requires a host Docker environment receipt")
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("study Docker environment receipt is malformed") from error
    from .buflo_study import validate_study_environment_receipt

    validated = validate_study_environment_receipt(
        value,
        expected_image_digest=source.get("image_digest"),
    )
    return raw, value, validated


def _validate_class_study_preclaim_authority(
    campaign: Campaign,
    *,
    source: Mapping[str, Any],
    started_at: datetime,
) -> None:
    """Fail closed on authority/build lineage before creating a global claim."""

    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise ValueError("class-study launch timestamp must be timezone-aware")
    authority = _validate_class_study_authority_files(
        campaign,
        source=source,
        paths=_class_study_authority_paths(campaign),
    )
    if (
        campaign.class_study_successor_sha256 is not None
        or campaign.evidence_role in _FITTING_GENERATION_STAGES
    ):
        # Repeat runtime artifact and manifest hashes after campaign loading so
        # no replacement can cross the load-to-claim boundary. Successors also
        # recheck their fitting-provenance lineage inside this helper.
        _revalidate_loaded_class_study_runtime_files(campaign)
    try:
        foundation_recorded_at = datetime.fromisoformat(str(authority["foundation"]["recorded_at"]))
    except (KeyError, ValueError) as error:
        raise ValueError("class-study foundation timestamp is invalid") from error
    if (
        foundation_recorded_at.tzinfo is None
        or foundation_recorded_at.utcoffset() is None
        or foundation_recorded_at > started_at
    ):
        raise ValueError("class-study launch precedes its foundation authority")
    historical_pre = authority.get("historical_pre_snapshot")
    if historical_pre is not None:
        try:
            historical_recorded_at = datetime.fromisoformat(str(historical_pre["recorded_at"]))
        except (KeyError, ValueError) as error:
            raise ValueError("class-study historical pre-snapshot timestamp is invalid") from error
        if (
            historical_recorded_at.tzinfo is None
            or historical_recorded_at.utcoffset() is None
            or historical_recorded_at > started_at
        ):
            raise ValueError("class-study launch precedes its historical pre-snapshot")
    environment_record = _study_environment_from_environment(campaign, source)
    if environment_record is None:  # pragma: no cover - class campaigns are studies.
        raise AssertionError("class-study environment validation was bypassed")
    _raw, _value, environment = environment_record
    foundation_build = authority["foundation"].get("build_execution_identity")
    environment_build = environment.get("build_execution")
    if not isinstance(foundation_build, Mapping) or not isinstance(environment_build, Mapping):
        raise ValueError("class-study authority has no typed no-cache build identity")
    observed_build = {key: environment_build.get(key) for key in foundation_build}
    if observed_build != dict(foundation_build):
        raise ValueError("class-study Docker environment uses a different no-cache build")
    readiness = authority.get("readiness")
    if readiness is not None and readiness.get("build_execution_identity") != foundation_build:
        raise ValueError("class-study readiness and foundation use different builds")
    if readiness is not None:
        _validate_class_study_runtime_authority(campaign, readiness=readiness)


def _validate_class_study_runtime_authority(
    campaign: Campaign,
    *,
    readiness: Mapping[str, Any],
) -> None:
    """Bind a loaded canary/formal campaign to certified runtime inputs."""

    from .class_study import COMPATIBILITY_MODES, FORMAL_MODES

    if campaign.evidence_role not in {"canary", "formal"}:
        raise ValueError("runtime authority is valid only for canary/formal campaigns")
    _revalidate_loaded_class_study_runtime_files(campaign)
    summary = readiness.get("summary")
    certification_inputs = (
        summary.get("certification_defense_runtime_inputs")
        if isinstance(summary, Mapping)
        else None
    )
    if not isinstance(certification_inputs, Mapping) or set(certification_inputs) != set(
        COMPATIBILITY_MODES
    ):
        raise ValueError("class-study readiness has no complete certified runtime map")
    expected_modes = ("undefended",) if campaign.evidence_role == "canary" else FORMAL_MODES
    observed = _class_study_campaign_runtime_inputs(campaign)
    expected = {mode: certification_inputs[mode] for mode in expected_modes}
    if observed != expected:
        raise ValueError("class-study campaign runtime inputs differ from certification/readiness")

    final_manifest_sha256 = (
        summary.get("final_qualification_set_manifest_sha256")
        if isinstance(summary, Mapping)
        else None
    )
    if (
        not isinstance(final_manifest_sha256, str)
        or _SHA256.fullmatch(final_manifest_sha256) is None
    ):
        raise ValueError("class-study readiness has no final qualification-set manifest identity")
    observed_manifest = _class_study_campaign_qualification_manifest_sha256(campaign)
    if campaign.evidence_role == "formal":
        if observed_manifest != final_manifest_sha256:
            raise ValueError("class-study formal qualification manifest differs from readiness")
    elif observed_manifest is not None:
        raise ValueError("class-study canary unexpectedly uses a qualification set")


def _revalidate_loaded_class_study_runtime_files(campaign: Campaign) -> None:
    """Close load-to-claim races for every external runtime input."""

    def require_hash(path: Path | None, digest: str | None, *, label: str) -> None:
        if (
            path is None
            or path.is_symlink()
            or not path.is_file()
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or sha256_file(path) != digest
        ):
            raise ValueError(f"class-study {label} changed after campaign loading")

    successor_study_id = campaign.class_study_id
    successor_restart_sha256 = campaign.class_study_successor_sha256
    if successor_restart_sha256 is None:
        if successor_study_id not in {None, STUDY_ID}:
            raise ValueError("class-study runtime has an unbound alternate study identity")
    elif (
        not is_successor_study_id(successor_study_id)
        or _SHA256.fullmatch(successor_restart_sha256) is None
    ):
        raise ValueError("class-study successor runtime identity is incomplete")
    seen_provenance: set[Path] = set()
    for defense in campaign.defenses:
        if defense.schedule_path is not None:
            require_hash(
                defense.schedule_path,
                defense.schedule_sha256,
                label=f"{defense.name} schedule",
            )
        if defense.parameters_path is not None:
            require_hash(
                defense.parameters_path,
                defense.parameters_sha256,
                label=f"{defense.name} parameters",
            )
            require_hash(
                defense.parameters_provenance_path,
                defense.parameters_provenance_sha256,
                label=f"{defense.name} parameter provenance",
            )
            provenance_path = defense.parameters_provenance_path.resolve()
            if successor_restart_sha256 is not None and provenance_path not in seen_provenance:
                provenance = load_json(provenance_path)
                is_class_bundle = (
                    isinstance(provenance, Mapping)
                    and provenance.get("artifact_type")
                    == "qcsd-class-study-research-defense-bundle"
                )
                if defense.kind in SEALED_RESEARCH_PARAMETER_KINDS and not is_class_bundle:
                    raise ValueError(
                        "successor data-driven defenses require their exact class fitting bundle"
                    )
                if is_class_bundle:
                    from .class_fitting import require_successor_fitting_identity

                    assert successor_study_id is not None
                    require_successor_fitting_identity(
                        provenance,
                        expected_study_id=successor_study_id,
                        expected_restart_sha256=successor_restart_sha256,
                    )
                seen_provenance.add(provenance_path)
    seen_manifests: set[Path] = set()
    for workload in campaign.workloads:
        path = workload.qualification_set_manifest_path
        if path is None:
            continue
        resolved = path.resolve()
        if resolved in seen_manifests:
            continue
        require_hash(
            path,
            workload.qualification_set_manifest_sha256,
            label="named qualification-set manifest",
        )
        seen_manifests.add(resolved)


def _claim_class_study_launch(
    campaign: Campaign,
    *,
    results_root: Path,
    source: Mapping[str, Any],
    started_at: datetime,
) -> tuple[Path, str, Path]:
    """Create/recover the global claim before any class-study result launch."""

    from .experiment import result_path

    if not _is_class_study_campaign(campaign):
        raise ValueError("first-launch claim requires a complete class-study campaign")
    root = _canonical_class_study_results_root(results_root)
    _validate_class_study_preclaim_authority(
        campaign,
        source=source,
        started_at=started_at,
    )
    namespace = _class_study_launch_namespace(campaign)
    registry = _class_study_launch_registry(root, namespace)
    key = _class_study_launch_key(campaign)
    marker = registry / f"{key}.json"
    recovered = _recover_class_study_launch_claim(
        marker,
        root=root,
        campaign=campaign,
        source=source,
    )
    if recovered is not None:
        return recovered

    run_id = started_at.strftime("%Y%m%dT%H%M%S.%fZ")
    result_root = result_path(root, campaign.name, run_id)
    value = _bind_class_study_launch(
        _class_study_launch_payload(
            campaign,
            result_root=result_root,
            source=source,
            created_at=started_at.isoformat(),
        )
    )
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    try:
        durable_create(marker, encoded)
    except FileExistsError:
        # Another direct-API process can win after our absence check.  The
        # create-only link is the linearisation point: load and validate that
        # winner rather than manufacturing another result identity.
        recovered = _recover_class_study_launch_claim(
            marker,
            root=root,
            campaign=campaign,
            source=source,
        )
        if recovered is None:  # pragma: no cover - an unlinking adversary.
            raise ValueError("class-study launch claim disappeared after collision")
        return recovered
    return result_root, run_id, marker


def _canonical_class_study_results_root(results_root: Path) -> Path:
    """Bind every fresh class-study launch to this Lab's one results root.

    Frozen-result resume and verification deliberately do not call this
    helper: their already sealed claim is validated relative to the result's
    own historical results ancestor.
    """

    from .class_layout import require_canonical_fresh_path

    root = require_canonical_fresh_path(
        results_root,
        field="results_root",
        label="class-study results root",
    )
    if not root.is_dir():
        raise ValueError("class-study results root must be a regular directory")
    return root


def _class_study_launch_registry(root: Path, namespace: str) -> Path:
    """Create or admit the single private registry beneath ``root`` safely."""

    registry = root / namespace
    created = False
    try:
        registry.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    try:
        metadata = registry.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        raise ValueError("class-study launch registry disappeared") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError(
            "class-study launch registry must be an owner-owned mode-0700 directory"
        )
    if created:
        fsync_directory(root)
    return registry


def _recover_class_study_launch_claim(
    marker: Path,
    *,
    root: Path,
    campaign: Campaign,
    source: Mapping[str, Any],
) -> tuple[Path, str, Path] | None:
    """Load one complete winner or report that no claim has been published."""

    from .experiment import result_path

    try:
        metadata = marker.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("class-study launch claim must be a regular file")
    value = load_json(marker)
    payload = value.get("payload") if isinstance(value, Mapping) else None
    if not isinstance(payload, Mapping) or not isinstance(payload.get("result_root"), str):
        raise ValueError("class-study launch claim is malformed")
    claimed_root = Path(payload["result_root"])
    _validate_class_study_launch_value(
        value,
        campaign=campaign,
        result_root=claimed_root,
        source=source,
    )
    run_id = claimed_root.name
    if result_path(root, campaign.name, run_id) != claimed_root.resolve():
        raise ValueError("class-study launch claim result path is not canonical")
    if claimed_root.exists() or claimed_root.is_symlink():
        if claimed_root.is_symlink() or not claimed_root.is_dir():
            raise ValueError("class-study claimed result root is unsafe")
        if (claimed_root / "experiment.json").is_file():
            raise FileExistsError(
                "class-study campaign/cohort has already launched; resume its claimed result"
            )
        _discard_unlaunched_class_root(claimed_root)
    return claimed_root, run_id, marker


def _discard_unlaunched_class_root(root: Path) -> None:
    """Recover only our own pre-experiment materialisation after a hard stop."""

    if root.is_symlink() or not root.is_dir() or (root / "experiment.json").exists():
        raise ValueError("class-study pre-launch recovery target is unsafe")
    allowed_root_names = {"inputs"}
    for entry in root.iterdir():
        if entry.name not in allowed_root_names and ".qcsd-tmp-" not in entry.name:
            raise ValueError(
                "class-study claimed root has unknown pre-launch content; manual audit required"
            )
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("class-study pre-launch recovery refuses symlinks")
    # No attempt can exist before experiment.json is durably initialised.  The
    # remaining tree consists solely of reproducible frozen-input copies, so a
    # same-key retry may recreate it at the already claimed path.
    shutil.rmtree(root)


def _validate_class_study_launch(root: Path, campaign: Campaign) -> str:
    """Verify the frozen claim and its global create-only registry copy."""

    if not _is_class_study_campaign(campaign):
        raise ValueError("class-study launch validation received another campaign")
    frozen = root / CLASS_STUDY_LAUNCH_INPUT
    if frozen.is_symlink() or not frozen.is_file():
        raise ValueError("class-study result has no frozen first-launch claim")
    source_path = root / "inputs/source.json"
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("class-study result has no frozen source identity")
    source = load_json(source_path)
    value = load_json(frozen)
    payload = _validate_class_study_launch_value(
        value,
        campaign=campaign,
        result_root=root,
        source=source,
    )
    namespace = _class_study_launch_namespace(campaign)
    registry = root.parents[1] / namespace
    if registry.is_symlink() or not registry.is_dir():
        raise ValueError("class-study launch registry is not a regular directory")
    marker = registry / f"{payload['launch_key']}.json"
    if marker.is_symlink() or not marker.is_file() or sha256_file(marker) != sha256_file(frozen):
        raise ValueError("class-study global first-launch claim differs from the result")
    return sha256_file(frozen)


def _run_loaded_campaign(campaign: Campaign, results_root: Path) -> Path:
    from .experiment import initialize_experiment, result_path

    _require_class_study_public_origin_policy(campaign)
    source = source_metadata()
    if campaign.purpose == "fitting":
        _validate_fitting_capture_source(source)
    started = datetime.now(timezone.utc)
    class_launch: Path | None = None
    if _public_buflo_campaign(campaign.name):
        admission_value = os.environ.get("QCSD_BUFLO_CAPTURE_ADMISSION")
        if not admission_value:
            raise ValueError("public BuFLO-study run requires a typed capture admission")
        from .buflo_study import admitted_result_root

        root = admitted_result_root(Path(admission_value), campaign.path, require_sequence=True)
        expected_results_root = root.parents[1]
        if expected_results_root != results_root.resolve():
            raise ValueError("capture admission selected a different results root")
        run_id = root.name
        if result_path(results_root, campaign.name, run_id) != root.resolve():
            raise ValueError("capture admission result root is not canonical")
    elif _is_class_study_campaign(campaign):
        root, run_id, class_launch = _claim_class_study_launch(
            campaign,
            results_root=results_root,
            source=source,
            started_at=started,
        )
    else:
        run_id = started.strftime("%Y%m%dT%H%M%S.%fZ")
        root = result_path(results_root, campaign.name, run_id)
    root.mkdir(parents=True, exist_ok=False)
    if class_launch is not None:
        inputs = root / "inputs"
        inputs.mkdir()
        frozen_launch = root / CLASS_STUDY_LAUNCH_INPUT
        with class_launch.open("rb") as input_file, frozen_launch.open("xb") as output:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
    runtime_campaign, configuration = _materialize_inputs(root, campaign, source)
    if class_launch is not None:
        configuration["class_study_launch_sha256"] = _validate_class_study_launch(
            root,
            runtime_campaign,
        )
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
    _materialize_class_study_authority(inputs, campaign)
    class_study_successor_destination: Path | None = None
    if campaign.class_study_successor_path is not None:
        if campaign.class_study_successor_sha256 is None:
            raise ValueError("successor campaign has no restart receipt digest")
        class_study_successor_destination = inputs / "class-study-successor.json"
        shutil.copy2(
            campaign.class_study_successor_path,
            class_study_successor_destination,
        )
        if sha256_file(class_study_successor_destination) != campaign.class_study_successor_sha256:
            raise ValueError("successor restart receipt changed during materialization")
    class_study_cohort_destination: Path | None = None
    class_study_cohort_assembly_destination: Path | None = None
    if campaign.class_study_cohort_path is not None:
        if (
            campaign.class_study_cohort_sha256 is None
            or campaign.class_study_cohort_assembly_path is None
            or campaign.class_study_cohort_assembly_sha256 is None
        ):
            raise ValueError("class-study cohort evidence has no complete frozen binding")
        class_study_cohort_destination = inputs / "class-study-cohort.json"
        class_study_cohort_assembly_destination = inputs / "class-study-cohort-assembly.json"
        shutil.copy2(campaign.class_study_cohort_path, class_study_cohort_destination)
        shutil.copy2(
            campaign.class_study_cohort_assembly_path,
            class_study_cohort_assembly_destination,
        )
        if sha256_file(class_study_cohort_destination) != campaign.class_study_cohort_sha256:
            raise ValueError("class-study cohort receipt changed during materialization")
        if (
            sha256_file(class_study_cohort_assembly_destination)
            != campaign.class_study_cohort_assembly_sha256
        ):
            raise ValueError("class-study cohort assembly changed during materialization")
        from .class_cohort import validate_cohort_assembly_receipt
        from .class_study import load_study_receipt

        frozen_cohort, _selection = load_study_receipt(class_study_cohort_destination)
        validate_cohort_assembly_receipt(
            load_json(class_study_cohort_assembly_destination),
            cohort=frozen_cohort,
        )
    qualification_set_manifest_destination: Path | None = None
    qualification_set_manifest_paths = {
        workload.qualification_set_manifest_path
        for workload in campaign.workloads
        if workload.qualification_set_manifest_path is not None
    }
    if qualification_set_manifest_paths:
        if len(qualification_set_manifest_paths) != 1 or any(
            workload.qualification_set_manifest_path is None
            or workload.qualification_set_manifest_sha256 is None
            for workload in campaign.workloads
        ):
            raise ValueError("named qualification-set binding is inconsistent across workloads")
        from .chaff_qualification import NAMED_QUALIFICATION_SET_MANIFEST

        [qualification_set_manifest_source] = qualification_set_manifest_paths
        qualification_set_manifest_destination = (
            chaff_qualifications_dir / NAMED_QUALIFICATION_SET_MANIFEST
        )
        shutil.copy2(
            qualification_set_manifest_source,
            qualification_set_manifest_destination,
        )
        expected_set_hashes = {
            workload.qualification_set_manifest_sha256 for workload in campaign.workloads
        }
        if expected_set_hashes != {sha256_file(qualification_set_manifest_destination)}:
            raise ValueError("named qualification-set manifest changed during materialization")
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
                qualification_set_manifest_path=qualification_set_manifest_destination,
                qualification_set_manifest_sha256=(
                    sha256_file(qualification_set_manifest_destination)
                    if qualification_set_manifest_destination is not None
                    else None
                ),
            )
        runtime_workloads.append(runtime)
    if qualification_set_manifest_destination is not None:
        from .chaff_qualification import load_named_qualification_set

        load_named_qualification_set(
            qualification_set_manifest_destination,
            workload_root=workloads_dir,
            sidecar_root=chaff_qualifications_dir,
            prefix_spec_root=(
                chaff_prefix_specs_dir if required_scope == FULL_CHAFF_SCOPE else None
            ),
            expected_qualification_set=campaign.chaff_qualification_set,
            expected_qualification_scope=required_scope,
            expected_workload_ids=tuple(workload.id for workload in campaign.workloads),
            require_current_implementation=True,
        )
    frozen_class_qualification_authority = _class_fitted_qualification_authority(
        evidence_role=campaign.evidence_role,
        qualification_set=campaign.chaff_qualification_set,
        config_root=inputs,
        successor_context=None,
        frozen_inputs=inputs,
        expected_authority=None,
    )
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
            elif defense.parameters_input_policy in {
                "sealed-class-study-pilot-fitting-v1",
                "sealed-class-study-fitting-v1",
            }:
                class_dir = parameters_dir / "class-study"
                if not class_dir.exists():
                    shutil.copytree(defense.parameters_path.parent, class_dir)
                if defense.parameters is None:
                    raise ValueError(f"{defense.name} parameter source binding is missing")
                destination = class_dir / Path(defense.parameters).name
                provenance = class_dir / "provenance.json"
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
                qualification_authority=frozen_class_qualification_authority,
                expected_qualification_set=campaign.chaff_qualification_set,
                campaign_evidence_role=campaign.evidence_role,
                expected_successor_study_id=(
                    campaign.class_study_id
                    if campaign.class_study_successor_sha256 is not None
                    else None
                ),
                expected_successor_restart_sha256=(campaign.class_study_successor_sha256),
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
        class_study_cohort_path=class_study_cohort_destination,
        class_study_cohort_sha256=(
            sha256_file(class_study_cohort_destination)
            if class_study_cohort_destination is not None
            else None
        ),
        class_study_cohort_assembly_path=class_study_cohort_assembly_destination,
        class_study_cohort_assembly_sha256=(
            sha256_file(class_study_cohort_assembly_destination)
            if class_study_cohort_assembly_destination is not None
            else None
        ),
        class_study_successor_path=class_study_successor_destination,
        class_study_successor_sha256=(
            sha256_file(class_study_successor_destination)
            if class_study_successor_destination is not None
            else None
        ),
    )
    return runtime_campaign, _frozen_configuration(root, runtime_campaign)


def _materialize_class_study_authority(inputs: Path, campaign: Campaign) -> None:
    """Freeze the gate authority required by a prospective class-study run."""

    if not _is_class_study_campaign(campaign):
        if any(
            os.environ.get(name) is not None
            for name in (
                CLASS_STUDY_FOUNDATION_ENV,
                CLASS_STUDY_READINESS_ENV,
                CLASS_STUDY_HISTORICAL_PRE_ENV,
            )
        ):
            raise ValueError("class-study authority cannot be applied to a non-class campaign")
        return

    for relative, source in _class_study_authority_paths(campaign).items():
        destination = inputs.parent / relative
        durable_create(destination, source.read_bytes())
    _validate_frozen_class_study_authority(inputs.parent, campaign)


def _validate_frozen_class_study_authority(root: Path, campaign: Campaign) -> dict[str, str]:
    """Revalidate frozen authority and derive its configuration bindings."""

    required = tuple(_class_study_authority_specification(campaign).values())
    all_relatives = {
        CLASS_STUDY_FOUNDATION_INPUT,
        CLASS_STUDY_READINESS_INPUT,
        CLASS_STUDY_HISTORICAL_PRE_INPUT,
    }
    required_relatives = {relative for relative, _key in required}
    for relative in all_relatives - required_relatives:
        unexpected = root / relative
        if unexpected.exists() or unexpected.is_symlink():
            raise ValueError(f"{campaign.evidence_role} result has unexpected authority {relative}")
    if not required:
        return {}

    frozen: dict[str, Path] = {}
    configuration: dict[str, str] = {}
    for relative, key in required:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{campaign.evidence_role} result lacks frozen authority {relative}")
        frozen[relative] = path
        configuration[key] = sha256_file(path)

    _validate_class_study_authority_files(
        campaign,
        source=load_json(root / "inputs/source.json"),
        paths=frozen,
    )
    return configuration


def _materialize_study_environment(
    inputs: Path, campaign: Campaign, source: Mapping[str, Any]
) -> None:
    receipt = _study_environment_from_environment(campaign, source)
    if receipt is None:
        return
    raw, value, _validated = receipt
    destination = inputs / "study-environment.json"
    durable_create(destination, raw)
    if load_json(destination) != value:
        raise ValueError("study Docker environment changed during materialization")


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
    groups: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    for sample_id in experiment["execution_order"]:
        sample = samples_by_id[sample_id]
        if campaign.sample_order_scheme == "grouped":
            group: tuple[object, ...] = (
                sample["workload_id"],
                sample["request_policy"],
                sample["visit"],
            )
        else:
            # Schema-two plans already interleave modes and origins.  A singleton
            # execution group prevents the legacy regrouping pass from silently
            # undoing that frozen acquisition order.
            group = ("sample", sample_id)
        groups.setdefault(group, []).append(sample)
    for members in groups.values():
        for sample in members:
            if sample["state"] == "accepted":
                _validate_accepted(root, experiment, sample)
                continue
            workload = workload_by_id[sample["workload_id"]]
            defense = defense_by_name[sample["defense"]]
            attempts_this_execution = 0
            # BuFLO-study and schema-two class-study ``sample["attempts"]`` is
            # the durable, cross-resume budget.  Preserve the historical generic
            # campaign contract while preventing a resumed study cell from
            # acquiring another three traces after exhausting its total cap.
            while attempts_this_execution < campaign.limits.max_attempts and (
                not _has_durable_attempt_budget(campaign)
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
                                    "defended execution lacks frozen prepared source and "
                                    "qualified chaff"
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
                        diagnostics = _success_diagnostics(result, attempt)
                        controlled_cell = _controlled_study_cell(campaign, sample)
                        if controlled_cell is not None:
                            diagnostics["buflo_study_controlled_cell"] = controlled_cell
                        promotion = _promotion_receipt(root, sample, attempt)
                        if KERNEL_TX_EVIDENCE_RECEIPT_KEY in promotion:
                            diagnostics[KERNEL_TX_EVIDENCE_RECEIPT_KEY] = promotion[
                                KERNEL_TX_EVIDENCE_RECEIPT_KEY
                            ]
                        diagnostics["promotion"] = promotion
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
                if _has_terminal_strict_defense_fidelity_failure(experiment):
                    # A defence/QCSD fidelity defect is not a stochastic
                    # collection failure. Freeze the partial study exactly at
                    # the first typed defect so a later attempt cannot conceal
                    # it; repair requires a new source/image cohort.
                    finalize_experiment(root, experiment, status="incomplete")
                    _seal(root)
                    raise CampaignIncomplete(root)
            _checkpoint(root, experiment)
        _compare_group(
            root,
            experiment,
            members,
            workload_by_id[members[0]["workload_id"]],
        )
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


def _success_diagnostics(result: dict[str, Any], attempt: Path) -> dict[str, Any]:
    capture = dict(_primary_capture_view(result))
    capture["capture_path"] = "capture.pcapng"
    capture.pop("trace_path", None)
    capture.pop("trace_sha256", None)
    diagnostics = {
        "capture": capture,
        "offloads": result.get("offloads", []),
        "network_condition": result.get("network_condition"),
        "endpoint_count": result.get("endpoint_count"),
        "endpoint_count_valid": result.get("endpoint_count_valid"),
        "runner_binding_valid": result.get("runner_binding_valid", True),
        "operationally_valid": result.get("operationally_valid", True),
        "defense": result.get("defense_diagnostics") or {},
        "resolved_configuration": result.get("resolved_configuration"),
    }
    runtime = _scheduler_runtime_receipt_for_promotion(result, attempt)
    if runtime is not None:
        diagnostics[SCHEDULER_RUNTIME_RECEIPT_KEY] = runtime
    topology = _observer_topology_receipt_for_promotion(result, attempt)
    if topology is not None:
        diagnostics[OBSERVER_TOPOLOGY_RECEIPT_KEY] = topology
    return diagnostics


def _observer_topology_receipt_for_promotion(
    result: Mapping[str, Any], attempt: Path
) -> dict[str, Any] | None:
    """Retain the validated observer topology before attempt deletion."""

    run_path = attempt / "neqo/run.json"
    if run_path.is_symlink() or not run_path.is_file():
        raise ValueError("successful attempt lacks a regular runner receipt")
    run = load_json(run_path)
    scheduler = run.get("process_scheduler") if isinstance(run, Mapping) else None
    matched = bool(
        isinstance(scheduler, Mapping)
        and scheduler.get("contract")
        == "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1"
    )
    retained = result.get("observer_topology_receipt")
    if not matched:
        topology_required = result.get("observer_topology_required")
        if (
            topology_required is not None
            and topology_required is not False
            or retained is not None
            or result.get("observer_topology_valid") is not None
        ):
            raise ValueError("non-matched successful attempt claims observer topology evidence")
        return None
    if (
        result.get("observer_topology_required") is not True
        or result.get("observer_topology_valid") is not True
        or not capture_engine.observer_topology_receipt_valid(retained)
    ):
        raise ValueError("matched successful attempt observer topology evidence is invalid")
    return dict(retained)


def _scheduler_runtime_receipt_for_promotion(
    result: Mapping[str, Any], attempt: Path
) -> dict[str, Any] | None:
    """Validate and retain scheduler evidence before promotion deletes its file."""

    run_path = attempt / "neqo/run.json"
    if run_path.is_symlink() or not run_path.is_file():
        raise ValueError("successful attempt lacks a regular runner receipt")
    run_data = load_json(run_path)
    if result.get("process_scheduler_required") is not True:
        return None

    scheduler_path = attempt / SCHEDULER_RUNTIME_EVIDENCE_PATH
    evidence = result.get("scheduler_runtime_evidence")
    digest = result.get("scheduler_runtime_evidence_sha256")
    if (
        result.get("scheduler_runtime_evidence_path") != SCHEDULER_RUNTIME_EVIDENCE_PATH
        or scheduler_path.is_symlink()
        or not scheduler_path.is_file()
        or not isinstance(evidence, Mapping)
        or load_json(scheduler_path) != evidence
        or not isinstance(digest, str)
        or sha256_file(scheduler_path) != digest
        or result.get("process_scheduler_required") is not True
        or result.get("process_scheduler_valid") is not True
        or result.get("scheduler_runtime_evidence_valid") is not True
        or not capture_engine._capture_scheduler_runtime_evidence_valid(evidence)
        or not capture_engine._process_scheduler_bound_to_run_valid(
            run_data,
            expected_contract=evidence.get("contract"),
        )
    ):
        raise ValueError("successful attempt scheduler runtime evidence is invalid")
    return scheduler_runtime_receipt(
        evidence=evidence,
        evidence_sha256=digest,
        process_scheduler_required=True,
        process_scheduler_valid=True,
        evidence_valid=True,
    )


def _controlled_study_cell(campaign: Campaign, sample: Mapping[str, Any]) -> dict[str, Any] | None:
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
            delay_us = _runner_csv_u64(
                row["credit_advertisement_delay_us"],
                label="credit_advertisement_delay_us",
            )
            action_time_us = _runner_csv_u64(
                row["action_time_us"],
                label="action_time_us",
            )
            advertised_at_us = _runner_csv_u64(
                row["credit_advertised_at_us"],
                label="credit_advertised_at_us",
            )
            violation = {
                "slot_id": _runner_csv_u64(row["slot_id"], label="slot_id"),
                "connection": _runner_csv_u64(row["connection"], label="connection"),
                "target_time_us": _runner_csv_u64(
                    row["target_time_us"],
                    label="target_time_us",
                ),
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
    try:
        run = load_json(attempt / "neqo/run.json")
    except (OSError, ValueError):
        run = {}
    result["resolved_configuration"] = (
        run.get("resolved_configuration") if isinstance(run, Mapping) else None
    )
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
        resolved_configuration=(
            run.get("resolved_configuration") if isinstance(run, Mapping) else None
        ),
        require_defense_activation=True,
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


def _kernel_tx_attempt_sources(attempt: Path) -> dict[str, Path]:
    diagnostics = attempt / "diagnostics"
    return {
        "router-capture.pcapng": diagnostics / "kernel-tx-post-veth-raw.pcapng",
        "router-receipt.json": diagnostics / "kernel-tx-post-veth-receipt.json",
        "kernel-tx-evidence.json": diagnostics / "kernel-tx-evidence.json",
    }


def _kernel_tx_sidecar_directory(root: Path, sample: Mapping[str, Any]) -> Path:
    sample_id = sample.get("sample_id")
    if not isinstance(sample_id, str) or re.fullmatch(r"[0-9a-f]{64}", sample_id) is None:
        raise ValueError("kernel-TX sidecar requires the canonical sample identity")
    root = root.resolve()
    sidecar_root = (root / KERNEL_TX_EVIDENCE_DIRECTORY).resolve()
    target = (sidecar_root / sample_id).resolve()
    if not target.is_relative_to(sidecar_root):
        raise ValueError("kernel-TX sidecar path escapes its result directory")
    return target


def _kernel_tx_promotion_receipt(
    root: Path, sample: Mapping[str, Any], attempt: Path
) -> dict[str, Any] | None:
    sources = _kernel_tx_attempt_sources(attempt)
    present = {name for name, path in sources.items() if path.exists() or path.is_symlink()}
    run_path = attempt / "neqo/run.json"
    run_data = load_json(run_path) if run_path.is_file() and not run_path.is_symlink() else None
    wakeups = run_data.get("runner_wakeup_metrics") if isinstance(run_data, Mapping) else None
    raw = wakeups.get("buflo_kernel_tx") if isinstance(wakeups, Mapping) else None
    if not present and not isinstance(raw, Mapping):
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("non-kernel successful attempt retains a kernel-TX evidence sidecar")
    if not terminal_evidence_render_receipt_valid(
        run_data,
        require_present=True,
        require_empty=True,
    ):
        raise ValueError("successful kernel-TX attempt has terminal rendering failures")
    if present != KERNEL_TX_EVIDENCE_FILES or any(
        path.is_symlink() or not path.is_file() for path in sources.values()
    ):
        raise ValueError("successful attempt has a partial kernel-TX evidence sidecar")
    from .kernel_tx import kernel_tx_evidence_success_valid
    from .kernel_tx_runtime import extract_router_udp_packets

    router_receipt = load_json(sources["router-receipt.json"])
    evidence = load_json(sources["kernel-tx-evidence.json"])
    router_packets = extract_router_udp_packets(sources["router-capture.pcapng"])
    if not kernel_tx_evidence_success_valid(
        evidence,
        runner_receipt=raw,
        expected_run_json_sha256=sha256_file(run_path),
        expected_router_capture_sha256=sha256_file(sources["router-capture.pcapng"]),
        router_capture_receipt=router_receipt,
        router_packets=router_packets,
    ):
        raise ValueError("successful attempt kernel-TX sidecar failed deep validation")
    target = _kernel_tx_sidecar_directory(root, sample)
    return {
        "schema_version": KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
        "source": KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
        "directory": target.relative_to(root.resolve()).as_posix(),
        "artifacts": {name: sha256_file(path) for name, path in sorted(sources.items())},
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
    receipt = {
        "attempt": attempt.relative_to(root).as_posix(),
        "artifacts": {
            (sample_path / relative).relative_to(root).as_posix(): sha256_file(path)
            for relative, path in sources.items()
        },
    }
    kernel_tx = _kernel_tx_promotion_receipt(root, sample, attempt)
    if kernel_tx is not None:
        receipt[KERNEL_TX_EVIDENCE_RECEIPT_KEY] = kernel_tx
    return receipt


def _verify_kernel_tx_sidecar(
    root: Path, sample: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    target = _kernel_tx_sidecar_directory(root, sample)
    expected = {
        "schema_version",
        "source",
        "directory",
        "artifacts",
    }
    artifacts = receipt.get("artifacts")
    if (
        set(receipt) != expected
        or receipt.get("schema_version") != KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION
        or receipt.get("source") != KERNEL_TX_EVIDENCE_RECEIPT_SOURCE
        or receipt.get("directory") != target.relative_to(root.resolve()).as_posix()
        or not isinstance(artifacts, Mapping)
        or set(artifacts) != KERNEL_TX_EVIDENCE_FILES
        or any(
            not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in artifacts.values()
        )
        or target.is_symlink()
        or not target.is_dir()
    ):
        raise ValueError("kernel-TX sidecar promotion receipt is invalid")
    observed = set()
    for path in target.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("kernel-TX sidecar contains a non-regular entry")
        observed.add(path.name)
    if observed != KERNEL_TX_EVIDENCE_FILES or any(
        sha256_file(target / name) != artifacts[name] for name in artifacts
    ):
        raise ValueError("kernel-TX sidecar artifact hashes differ")


def _install_kernel_tx_sidecar(
    root: Path, sample: Mapping[str, Any], attempt: Path
) -> None:
    receipt = _kernel_tx_promotion_receipt(root, sample, attempt)
    if receipt is None:
        return
    target = _kernel_tx_sidecar_directory(root, sample)
    if target.exists() or target.is_symlink():
        _verify_kernel_tx_sidecar(root, sample, receipt)
        return
    parent = target.parent
    if parent.is_symlink():
        raise ValueError("kernel-TX evidence root cannot be a symlink")
    parent.mkdir(parents=True, exist_ok=True)
    staging = attempt / ".kernel-tx-evidence-promotion"
    if staging.exists() or staging.is_symlink():
        if staging.is_symlink() or not staging.is_dir():
            raise ValueError("kernel-TX sidecar staging path is unsafe")
        shutil.rmtree(staging)
    staging.mkdir()
    for name, source in _kernel_tx_attempt_sources(attempt).items():
        shutil.copy2(source, staging / name)
    staging.replace(target)
    _verify_kernel_tx_sidecar(root, sample, receipt)


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
    _install_kernel_tx_sidecar(root, sample, attempt)
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


def _validate_accepted(
    root: Path,
    experiment: Mapping[str, Any],
    sample: dict[str, Any],
) -> None:
    if sample.get("state") != "accepted" or not sample.get("artifacts"):
        raise ValueError(f"accepted sample receipt is invalid: {sample.get('sample_id')}")
    expected = sample["artifacts"]
    actual = _artifact_hashes(root, sample)
    if actual != expected:
        raise ValueError(f"accepted sample artifact set changed: {sample['sample_id']}")
    validate_accepted_scheduler_runtime_receipt(root, experiment, sample)
    validate_accepted_observer_topology_receipt(root, experiment, sample)
    validate_accepted_kernel_tx_evidence(root, sample)


def _compare_group(
    root: Path,
    experiment: Mapping[str, Any],
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
        validate_accepted_scheduler_runtime_receipt(root, experiment, sample)
        validate_accepted_observer_topology_receipt(root, experiment, sample)
        validate_accepted_kernel_tx_evidence(root, sample)
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
            resolved_configuration=diagnostics.get("resolved_configuration"),
            require_defense_activation=True,
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
        item.get("resource_id"): item for item in expected_responses if isinstance(item, Mapping)
    }
    observed = {item.get("resource_id"): item for item in responses if isinstance(item, Mapping)}
    prepared_resources = {item.get("id"): item for item in resources if isinstance(item, Mapping)}
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
    allowed_promotion_keys = {"attempt", "artifacts"}
    if isinstance(promotion, Mapping) and KERNEL_TX_EVIDENCE_RECEIPT_KEY in promotion:
        allowed_promotion_keys.add(KERNEL_TX_EVIDENCE_RECEIPT_KEY)
    if not isinstance(promotion, dict) or set(promotion) != allowed_promotion_keys:
        return False
    kernel_tx_sidecar = promotion.get(KERNEL_TX_EVIDENCE_RECEIPT_KEY)
    if kernel_tx_sidecar is not None and (
        not isinstance(kernel_tx_sidecar, Mapping)
        or diagnostics.get(KERNEL_TX_EVIDENCE_RECEIPT_KEY) != kernel_tx_sidecar
    ):
        raise ValueError("pending promotion kernel-TX sidecar binding is invalid")
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
        if isinstance(kernel_tx_sidecar, Mapping):
            _verify_kernel_tx_sidecar(root, sample, kernel_tx_sidecar)
    else:
        if not expected_attempt.is_dir() or expected_attempt.is_symlink():
            raise ValueError("validated pending promotion artifacts are missing")
        current = _promotion_receipt(root, sample, expected_attempt)
        if current != promotion:
            raise ValueError("pending promotion source hash mismatch")
        _promote_attempt(root, sample, expected_attempt)
    actual = _artifact_hashes(root, sample)
    if actual != expected_artifacts:
        raise ValueError("pending promoted sample hash mismatch")
    if isinstance(kernel_tx_sidecar, Mapping):
        _verify_kernel_tx_sidecar(root, sample, kernel_tx_sidecar)
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
                diagnostics = _success_diagnostics(result, attempt)
                controlled_cell = _controlled_study_cell(campaign, sample)
                if controlled_cell is not None:
                    diagnostics["buflo_study_controlled_cell"] = controlled_cell
                promotion = _promotion_receipt(root, sample, attempt)
                if KERNEL_TX_EVIDENCE_RECEIPT_KEY in promotion:
                    diagnostics[KERNEL_TX_EVIDENCE_RECEIPT_KEY] = promotion[
                        KERNEL_TX_EVIDENCE_RECEIPT_KEY
                    ]
                diagnostics["promotion"] = promotion
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
    configuration = value.get("configuration") if isinstance(value, Mapping) else None
    if isinstance(configuration, Mapping):
        coordinator_configuration = dict(configuration)
        coordinator_configuration["name"] = name
        _require_class_study_coordinator_capture_authority(coordinator_configuration)
    lock_held = (
        isinstance(name, str)
        and name.startswith("buflo-study-v1-")
        and os.environ.get("QCSD_BUFLO_CAPTURE_LOCK_HELD") == "1"
    ) or (
        is_class_study_campaign_name(name)
        and os.environ.get("QCSD_CLASS_CAPTURE_LOCK_HELD") == "1"
    )
    if _has_durable_attempt_name(name) and not lock_held:
        if len(root.parents) < 2:
            raise ValueError("study result root has no canonical results ancestor")
        with _study_capture_lock(root.parents[1]):
            return _resume_campaign_locked(root)
    return _resume_campaign_locked(root)


def _resume_campaign_locked(root: Path) -> Path:
    root = root.resolve()
    from .experiment import (
        finalize_experiment,
        load_experiment,
        transition_sample,
        validate_accepted_samples,
        validate_resume_fingerprints,
    )
    from .verification import prepare_resume, seal_result, verify_result

    initial = load_json(root / "experiment.json")
    _require_class_study_public_origin_policy(
        initial.get("name") if isinstance(initial, Mapping) else None
    )

    successor_input = root / CLASS_STUDY_SUCCESSOR_INPUT
    if not (root / "evidence.sha256").exists() and (
        successor_input.exists() or successor_input.is_symlink()
    ):
        # Validate the frozen campaign and its exact fitting provenance before
        # even deleting non-authoritative atomic-write temporaries.
        _campaign_from_frozen_inputs(root)

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

    terminal_defect = load_experiment(root)
    if _has_terminal_strict_defense_fidelity_failure(terminal_defect):
        if terminal_defect["status"] == "running":
            finalize_experiment(root, terminal_defect, status="incomplete")
            seal_result(root)
        elif terminal_defect["status"] == "incomplete" and not (root / "evidence.sha256").is_file():
            seal_result(root)
        raise CampaignIncomplete(root)

    experiment = prepare_resume(root, expected_source=source_metadata())
    # A running checkpoint means the process stopped before promotion.  The
    # established generic campaign contract discards that partial attempt and
    # reuses its number.  BuFLO-study and schema-two class-study campaigns
    # instead count every physical collector launch against the durable attempt
    # ceiling: a hard interruption becomes a small immutable failure tombstone
    # before a later launch receives the next attempt number.
    study_attempt_budget = _has_durable_attempt_name(experiment["name"])
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
            _validate_accepted(root, experiment, sample)
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
            _has_durable_attempt_budget(campaign)
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
    expected_qualification_authority: Mapping[str, Any] | None = None,
) -> Campaign:
    inputs = (root / "inputs").resolve()
    if inputs.is_symlink() or not inputs.is_dir():
        raise ValueError(f"result has no regular inputs directory: {root}")
    return _load_campaign(
        inputs / "campaign.yml",
        frozen_inputs=inputs,
        allow_historical_research_bundle=allow_historical_research_bundle,
        expected_qualification_authority=expected_qualification_authority,
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
        set_hashes = {
            workload.qualification_set_manifest_sha256
            for workload in campaign.workloads
            if workload.qualification_set_manifest_sha256 is not None
        }
        if set_hashes:
            if len(set_hashes) != 1 or any(
                workload.qualification_set_manifest_sha256 is None
                for workload in campaign.workloads
            ):
                raise ValueError("frozen named qualification-set binding is inconsistent")
            [configuration["chaff_qualification_set_manifest_sha256"]] = set_hashes
    if campaign.defense_order_scheme != "seeded-shuffle":
        configuration["defense_order"] = {
            "scheme": campaign.defense_order_scheme,
            "block": campaign.defense_order_block,
        }
    if campaign.evidence_role is not None:
        configuration["evidence_role"] = campaign.evidence_role
    if campaign.class_study_cohort_path is not None:
        if campaign.class_study_cohort_sha256 is None:
            raise ValueError("frozen class-study cohort has no digest")
        configuration["class_study_cohort_sha256"] = campaign.class_study_cohort_sha256
        if campaign.class_study_cohort_assembly_sha256 is None:
            raise ValueError("frozen class-study cohort assembly has no digest")
        configuration["class_study_cohort_assembly_sha256"] = (
            campaign.class_study_cohort_assembly_sha256
        )
        if campaign.class_study_id is not None:
            configuration["class_study_id"] = campaign.class_study_id
        if campaign.class_study_successor_sha256 is not None:
            configuration[CLASS_STUDY_SUCCESSOR_CONFIGURATION_KEY] = (
                campaign.class_study_successor_sha256
            )
        configuration["class_study_launch_sha256"] = _validate_class_study_launch(
            root,
            campaign,
        )
    if campaign.sample_order_scheme != "grouped":
        configuration["sample_order"] = {
            "scheme": campaign.sample_order_scheme,
            "window_size": campaign.sample_order_window,
        }
    if _is_class_study_campaign(campaign):
        configuration.update(_validate_frozen_class_study_authority(root, campaign))
        configuration["public_origin_policy"] = {
            "environment": CLASS_STUDY_PUBLIC_ORIGIN_ENV,
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        }
    study_environment = root / "inputs/study-environment.json"
    if campaign.name.startswith("buflo-study-v1-") or _is_class_study_campaign(campaign):
        from .buflo_study import validate_study_environment_receipt

        if study_environment.is_symlink() or not study_environment.is_file():
            raise ValueError("BuFLO study campaign has no frozen environment receipt")
        validated_environment = validate_study_environment_receipt(
            load_json(study_environment),
            expected_image_digest=load_json(root / "inputs/source.json")["image_digest"],
        )
        if _is_class_study_campaign(campaign):
            from .class_attestation import validate_class_foundation_attestation

            expected_build: Mapping[str, Any] | None = validate_class_foundation_attestation(
                root / CLASS_STUDY_FOUNDATION_INPUT,
                deep_code_gate=True,
                runtime_role="collection",
            ).get("build_execution_identity")
            if campaign.evidence_role in {"canary", "formal"}:
                from .class_attestation import validate_class_readiness_attestation

                readiness_build = validate_class_readiness_attestation(
                    root / CLASS_STUDY_READINESS_INPUT,
                    deep_code_gate=True,
                ).get("build_execution_identity")
                if readiness_build != expected_build:
                    raise ValueError("class-study readiness and foundation use different builds")
            if expected_build is not None:
                environment_build = validated_environment.get("build_execution")
                observed_build = (
                    {key: environment_build.get(key) for key in expected_build}
                    if isinstance(environment_build, Mapping)
                    else None
                )
                if observed_build != expected_build:
                    raise ValueError(
                        "class-study Docker environment uses a different no-cache build"
                    )
        configuration["study_environment_sha256"] = sha256_file(study_environment)
        admission = root / "inputs/capture-admission.json"
        if campaign.name.startswith("buflo-study-v1-") and _public_buflo_campaign(campaign.name):
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
