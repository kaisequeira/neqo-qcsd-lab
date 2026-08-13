from __future__ import annotations

import json
import math
import random
import re
import shutil
import tempfile
import time
from collections.abc import Mapping
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
from .fidelity import _schedule_realization_metrics, fidelity_eligible
from .manifest import (
    canonical_bytes,
    https_origin,
    runtime_manifest,
    validate_manifest,
    validate_research_preparation,
)
from .parameters import (
    parameter_provenance_path,
    validate_frozen_parameter_artifact,
    validate_parameter_artifact,
)
from .profiles import UDP_PAYLOAD_CEILING_BY_PROFILE
from .util import (
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
    "workloads",
    "request_policies",
    "defenses",
    "limits",
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
    workloads = _load_workloads(
        path,
        value["workloads"],
        purpose=purpose,
        frozen_inputs=frozen_inputs,
    )
    defenses = _load_defenses(
        path.parent,
        value["defenses"],
        purpose,
        profile,
        {workload.id: workload.sha256 for workload in workloads},
        frozen_inputs=frozen_inputs,
        allow_historical_research_bundle=allow_historical_research_bundle,
    )
    if any(_uses_schema_five_walkie_talkie(defense) for defense in defenses):
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
    )
    if purpose == "fitting":
        _validate_fitting_campaign(campaign, raw_limits=raw_limits)
    return campaign


def _uses_schema_five_walkie_talkie(defense: capture_engine.Defense) -> bool:
    """Limit new runtime prerequisites to the current, runnable WT contract."""

    if defense.kind != "walkie_talkie":
        return False
    if defense.parameters_path is None:
        raise ValueError("walkie_talkie defense has no resolved parameter artifact")
    parameter = load_json(defense.parameters_path)
    return isinstance(parameter, Mapping) and parameter.get("schema_version") == 5


def _validate_walkie_talkie_resource_preconditions(
    workloads: tuple[Workload, ...],
) -> None:
    """Reject manifests that cannot provision the schema-five reserve horizon."""

    for workload in workloads:
        manifest = runtime_manifest(workload.data)
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


def _load_workloads(
    path: Path,
    raw: Any,
    *,
    purpose: str,
    frozen_inputs: Path | None = None,
) -> tuple[Workload, ...]:
    value = _object(raw, "workloads")
    if not value:
        raise ValueError("campaign requires at least one workload")
    root = frozen_inputs / "workloads" if frozen_inputs is not None else _workload_root(path)
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
        manifest_path = (root / f"{workload_id}.json").resolve()
        if not manifest_path.is_file():
            raise ValueError(f"workload manifest does not exist: {manifest_path}")
        try:
            source_bytes = manifest_path.read_bytes()
            manifest = json.loads(source_bytes.decode("utf-8"))
        except UnicodeError as error:
            raise ValueError(f"workload manifest is not valid UTF-8: {manifest_path}") from error
        validate_manifest(manifest)
        if purpose in {"fitting", "evaluation"}:
            validate_research_preparation(manifest, workload_id=workload_id)
        runtime = runtime_manifest(manifest)
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
                if purpose == "evaluation" or (research_dir / original_name).is_file():
                    parameters_path = (research_dir / original_name).resolve()
                    provenance_path = (research_dir / "provenance.json").resolve()
                else:
                    artifact_dir = frozen_inputs / "defense-parameters" / name
                    parameters_path = (artifact_dir / "parameters.json").resolve()
                    provenance_path = (artifact_dir / "provenance.json").resolve()

            if purpose == "evaluation":
                from .fitting import BUNDLE_FILES, verify_artifact_bundle

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
                        verify_artifact_bundle(bundle_root)
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
                    expected_qcsd_profile=profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
                    expected_workloads=workloads,
                )
            else:
                artifact = validate_frozen_parameter_artifact(
                    parameters_path,
                    provenance_path=provenance_path,
                    original_parameter_name=Path(parameters).name,
                    expected_kind=kind,
                    allow_reviewed_fixture=purpose == "smoke",
                    expected_qcsd_profile=profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[profile],
                    expected_workloads=workloads,
                    allow_historical_research_bundle=allow_historical_research_bundle,
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
    for workload in campaign.workloads:
        for policy in campaign.request_policies:
            for visit in range(workload.visits):
                defenses = list(campaign.defenses)
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
    return {
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


def run_campaign(path: Path, results_root: Path = Path("/lab/results")) -> Path:
    from .experiment import initialize_experiment, result_path

    campaign = load_campaign(path)
    source = source_metadata()
    if campaign.purpose == "fitting":
        _validate_fitting_capture_source(source)
    started = datetime.now(timezone.utc)
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
    inputs = root / "inputs"
    workloads_dir = inputs / "workloads"
    parameters_dir = inputs / "defense-parameters"
    workloads_dir.mkdir(parents=True)
    parameters_dir.mkdir(parents=True)
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
        runtime_workloads.append(
            replace(workload, path=destination, sha256=sha256_file(destination))
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
                from .fitting import verify_artifact_bundle

                source_bundle = verify_artifact_bundle(defense.parameters_path.parent)
                research_dir = parameters_dir / "research-1200"
                if not research_dir.exists():
                    shutil.copytree(source_bundle.root, research_dir)
                frozen_bundle = verify_artifact_bundle(research_dir)
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
                expected_qcsd_profile=campaign.profile,
                expected_udp_payload_ceiling=campaign.udp_payload_ceiling,
                expected_workloads={
                    workload.id: workload.sha256 for workload in campaign.workloads
                },
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
            while attempts_this_execution < campaign.limits.max_attempts:
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
                    with tempfile.TemporaryDirectory(prefix="qcsd-runtime-workload-") as temporary:
                        runtime_path = Path(temporary) / f"{workload.id}.json"
                        runtime_path.write_bytes(canonical_bytes(runtime_workload))
                        result = capture_engine._collect_attempt(
                            attempt,
                            runtime_path,
                            workload.id,
                            defense,
                            sample["seed"],
                            _RunContext(
                                campaign.profile,
                                sample["request_policy"],
                                campaign.limits,
                                campaign.udp_payload_ceiling,
                            ),
                        )
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
                        diagnostics = _success_diagnostics(result)
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
    capture = dict(result.get("views", [{}])[0])
    capture["capture_path"] = "capture.pcapng"
    capture.pop("trace_path", None)
    capture.pop("trace_sha256", None)
    return {
        "capture": capture,
        "offloads": result.get("offloads", []),
        "endpoint_count": result.get("endpoint_count"),
        "endpoint_count_valid": result.get("endpoint_count_valid"),
        "runner_binding_valid": result.get("runner_binding_valid", True),
        "operationally_valid": result.get("operationally_valid", True),
        "defense": result.get("defense_diagnostics") or {},
    }


def _intrinsic_fidelity_failure(
    sample: dict[str, Any],
    result: dict[str, Any],
    attempt: Path,
) -> dict[str, Any] | None:
    """Reject a collected defense realization before it becomes immutable evidence."""

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
    )
    if eligible:
        return None
    return {
        "stage": "fidelity",
        "type": "StrictDefenseFidelityFailure",
        "message": "collection artifacts failed strict defense fidelity gates",
        "details": [
            {
                "defense": defense,
                "schedule": schedule,
                "defense_diagnostics": defense_metrics,
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


def _recover_completed_attempt(root: Path, experiment: dict[str, Any]) -> bool:
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
                diagnostics = _success_diagnostics(result)
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
    from .experiment import load_experiment, validate_accepted_samples, validate_resume_fingerprints
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
            validate_frozen_experiment_contract(root, terminal)
            validate_accepted_samples(root, terminal, allow_running_artifacts=True)
            _recover_pending_promotion(root, terminal)
            _recover_completed_attempt(root, terminal)
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
    # A running checkpoint means the process stopped before promotion.  That
    # one partial attempt is neither accepted evidence nor a failed attempt, so
    # discard it and let the retry reuse the attempt number.  All completed
    # failed attempts and every accepted sample remain untouched.
    for sample in experiment["samples"]:
        if sample["state"] != "interrupted":
            continue
        attempt = resolved_attempt_directory(root, sample)
        if attempt.exists():
            if attempt.is_symlink() or not attempt.is_dir():
                raise ValueError(f"interrupted attempt path is unsafe: {attempt}")
            shutil.rmtree(attempt)
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
    workload_records = [
        {
            "id": workload.id,
            "visits": workload.visits,
            "manifest": workload.path.relative_to(root).as_posix(),
            "sha256": workload.sha256,
            "resource_count": workload.resource_count,
            "origin_count": workload.origin_count,
        }
        for workload in campaign.workloads
    ]
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
    return {
        "campaign_sha256": sha256_file(campaign.path),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": workload_records,
        "defenses": defense_records,
        "limits": campaign.limits.as_dict(),
    }
