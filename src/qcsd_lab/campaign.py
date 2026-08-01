from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .capture import (
    OFFLOAD_DISABLED,
    REQUIRED_OFFLOAD_FEATURES,
    extract_trace,
    offload_evidence_is_valid,
    parse_offload_state,
    read_normalized_trace,
    recompute_offload_verification,
    tuple_filter,
    udp_ceiling_evidence,
    write_normalized_trace,
)
from .defenses import DEFENSE_ORDER, is_canonical_defense_suite
from .fidelity import (
    reconcile_direct_runner_artifacts,
    validate_fidelity_record,
    write_fidelity_record,
)
from .manifest import canonical_bytes, runtime_manifest, validate_manifest
from .parameters import (
    PARAMETER_ARTIFACT_NAME,
    PARAMETER_PROVENANCE_ARTIFACT_NAME,
    parameter_provenance_path,
    validate_parameter_artifact,
    validate_run_parameter_binding,
    validate_sample_parameter_artifacts,
)
from .profiles import UDP_PAYLOAD_CEILING_BY_PROFILE
from .seal import verify_checksum_seal
from .util import (
    atomic_json,
    atomic_text,
    load_json,
    padding_event_guard_triggered,
    response_signature,
    run,
    sha256_bytes,
    sha256_file,
    source_metadata,
    write_checksums,
)

NEQO_CLIENT = os.environ.get("NEQO_QCSD_CLIENT", "/usr/local/bin/neqo-qcsd-client")
STATIC_MODES = {"chaff-only", "chaff-and-shape"}
PARAMETER_FLAG_BY_KIND = {
    "traffic_morphing": "--morphing-matrix",
    "wtf_pad": "--wtf-pad-histograms",
    "walkie_talkie": "--walkie-talkie-molded",
}
SUPPORTED_DEFENSE_KINDS = {
    "none",
    "static",
    "front",
    "tamaraw",
    *PARAMETER_FLAG_BY_KIND,
}
RUNNER_KIND_BY_KIND = {
    "traffic_morphing": "traffic-morphing",
    "wtf_pad": "wtf-pad",
    "walkie_talkie": "walkie-talkie",
}
CAMPAIGN_KEYS = {"name", "seed", "stage", "qcsd_profile", "workloads", "defenses", "limits"}
CAMPAIGN_STAGES = {"acceptance", "research", "parameter-fitting"}
WORKLOAD_KEYS = {
    "root",
    "scope",
    "source",
    "reviewed",
    "request_policy",
    "monitored",
    "unmonitored",
}
REQUEST_POLICIES = {"as-defined", "half-duplex"}
WORKLOAD_SCOPES = {"as-defined", "primary-origin", "all-reviewed-origins"}
LIMIT_KEYS = {
    "timeout_seconds",
    "max_response_bytes",
    "capture_seconds",
    "capture_megabytes",
    "max_attempts",
    "per_origin_cooldown_seconds",
    "inter_sample_seconds",
    "settle_seconds",
}
DEFENSE_KEYS = {
    "name",
    "kind",
    "baseline",
    "schedule",
    "mode",
    "parameters",
    "allow_reviewed_fixture",
}


class CampaignIncomplete(RuntimeError):
    """A sealed campaign containing one or more ineligible paired visits."""

    def __init__(self, root: Path):
        self.root = root
        super().__init__(f"campaign incomplete; results retained at {root}")


@dataclass(frozen=True)
class Limits:
    timeout_seconds: int = 45
    max_response_bytes: int = 512 * 1024
    capture_seconds: int = 60
    capture_megabytes: int = 64
    max_attempts: int = 3
    per_origin_cooldown_seconds: float = 30.0
    inter_sample_seconds: float = 5.0
    settle_seconds: float = 1.0

    def as_dict(self) -> dict[str, int | float]:
        return asdict(self)


@dataclass(frozen=True)
class CaptureView:
    id: str
    interface: str
    link_type: str
    length_basis: str
    primary: bool

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["kind"] = self.id
        return result


DIRECT_CAPTURE_VIEW = CaptureView(
    id="direct-quic",
    interface="eth0",
    link_type="Ethernet",
    length_basis="frame.len",
    primary=True,
)


@dataclass(frozen=True)
class Defense:
    name: str
    kind: str
    baseline: bool
    schedule: str | None = None
    schedule_path: Path | None = None
    schedule_sha256: str | None = None
    mode: str | None = None
    parameters: str | None = None
    parameters_path: Path | None = None
    parameters_sha256: str | None = None
    parameters_provenance: str | None = None
    parameters_provenance_path: Path | None = None
    parameters_provenance_sha256: str | None = None
    parameters_input_policy: str | None = None

    def as_dict(self, *, internal: bool = False) -> dict[str, Any]:
        result = asdict(self)
        result.pop("schedule_path")
        result.pop("parameters_path")
        result.pop("parameters_provenance_path")
        if internal and self.schedule_path:
            result["schedule_path"] = str(self.schedule_path)
        if internal and self.parameters_path:
            result["parameters_path"] = str(self.parameters_path)
        if internal and self.parameters_provenance_path:
            result["parameters_provenance_path"] = str(self.parameters_provenance_path)
        return {key: value for key, value in result.items() if value is not None}


@dataclass(frozen=True)
class Campaign:
    name: str
    path: Path
    seed: int
    stage: str
    qcsd_profile: str
    source: str
    reviewed: bool
    workload_root: Path
    workload_scope: str
    workload_model: str
    request_policy: str
    workloads: tuple[dict[str, Any], ...]
    defenses: tuple[Defense, ...]
    limits: Limits
    network_condition: str
    study_id: str

    @property
    def purpose(self) -> str:
        return "parameter-fitting" if self.stage == "parameter-fitting" else "classification"

    @property
    def views(self) -> tuple[CaptureView, ...]:
        return (DIRECT_CAPTURE_VIEW,)

    @property
    def primary_view(self) -> CaptureView:
        return DIRECT_CAPTURE_VIEW

    @property
    def udp_payload_ceiling(self) -> int:
        """The single packetization ceiling shared by every sample."""

        return UDP_PAYLOAD_CEILING_BY_PROFILE[self.qcsd_profile]


def slug(value: str) -> str:
    rendered = "".join(
        character if character.isalnum() or character in "-_" else "-" for character in value
    ).strip("-")
    if not rendered:
        raise ValueError(f"identifier has no filesystem-safe characters: {value!r}")
    return rendered


def stable_digest(*parts: object) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def split_group_id_for_workload(source_manifest_sha256: str, repetition: int) -> str:
    """Return the leakage-safe identity shared by every derivative of one visit.

    The source manifest digest and repetition are the entire identity surface.
    In particular, collection cohort, stage, request policy, workload alias,
    replay scope, network condition, and defence selection cannot move a
    derivative to another split.
    """

    if not isinstance(source_manifest_sha256, str) or not source_manifest_sha256:
        raise ValueError("split group requires a source manifest SHA-256")
    if type(repetition) is not int or repetition < 0:
        raise ValueError("split group repetition must be a non-negative integer")
    return stable_digest(
        "qcsd-split-group-v1",
        source_manifest_sha256,
        repetition,
    )


def parameter_workload_contract(
    workloads: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> dict[str, tuple[str, str, int]]:
    """Return workload/source/role/visit bindings for parameter preflight."""

    contract: dict[str, tuple[str, str, int]] = {}
    for workload in workloads:
        workload_id = workload.get("workload_id")
        digest = workload.get("source_manifest_sha256")
        role = workload.get("role")
        visits = workload.get("visits")
        if not isinstance(workload_id, str) or not workload_id or workload_id in contract:
            raise ValueError("parameter workload contract has an invalid workload ID")
        if not isinstance(digest, str) or not digest:
            raise ValueError("workload source identity must be a SHA-256 string")
        if role not in {"monitored", "unmonitored"}:
            raise ValueError("workload parameter role must be monitored or unmonitored")
        if type(visits) is not int or visits < 1:
            raise ValueError("workload visit count must be a positive integer")
        contract[workload_id] = (digest, str(role), visits)
    return contract


def split_assignment_for_group(split_group_id: str, seed: int) -> str:
    """Return the canonical frozen split for one source-derived group."""

    if not isinstance(split_group_id, str) or not split_group_id:
        raise ValueError("split assignment requires a split-group identity")
    if type(seed) is not int:
        raise ValueError("split assignment seed must be an integer")
    digest = stable_digest(
        "qcsd-split-assignment-v3",
        seed,
        split_group_id,
    )
    bucket = int(digest[:16], 16) / 2**64
    return "train" if bucket < 0.70 else "validation" if bucket < 0.85 else "test"


def study_id_for_workloads(
    request_policy: str,
    workloads: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> str:
    """Return the stable study identity shared by planning and validation."""

    study_material = [
        {
            key: workload[key]
            for key in (
                "workload_id",
                "source_manifest_sha256",
                "class_label",
                "role",
            )
        }
        for workload in workloads
    ]
    return stable_digest(
        "study",
        request_policy,
        json.dumps(study_material, sort_keys=True, separators=(",", ":")),
    )


def visit_plan_for_workloads(
    *,
    campaign_seed: int,
    request_policy: str,
    workload_scope: str,
    workload_root: Path | str,
    workloads: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> tuple[str, list[dict[str, Any]]]:
    """Reproduce the immutable visit plan from recorded workload inputs.

    This is intentionally the sole implementation of study IDs, visit IDs,
    split-group IDs, visit seeds, and physical visit paths. Dataset validation
    calls the same function so a coordinated edit and reseal cannot choose a
    different split group or seed while retaining a superficially
    self-consistent index.
    """

    study_id = study_id_for_workloads(request_policy, workloads)
    root = Path(workload_root)
    visits: list[dict[str, Any]] = []
    seen_workloads: set[str] = set()
    for workload in workloads:
        workload_id = workload["workload_id"]
        if not isinstance(workload_id, str) or not workload_id:
            raise ValueError("workload plan has an invalid workload ID")
        if workload_id in seen_workloads:
            raise ValueError(f"workload plan contains duplicate workload {workload_id}")
        seen_workloads.add(workload_id)
        repetitions = workload["visits"]
        if type(repetitions) is not int or repetitions < 1:
            raise ValueError(f"workload plan has invalid visit count for {workload_id}")
        manifest_path = workload.get("manifest_path")
        if not isinstance(manifest_path, str) or not manifest_path:
            manifest_path = str(root / f"{workload_id}.json")
        for repetition in range(repetitions):
            source_manifest_sha256 = workload["source_manifest_sha256"]
            split_group_id = split_group_id_for_workload(
                source_manifest_sha256,
                repetition,
            )
            visit_id = stable_digest(
                "qcsd-physical-visit-v2",
                workload_id,
                source_manifest_sha256,
                repetition,
                request_policy,
                workload_scope,
            )
            visit_seed = int(stable_digest("seed", campaign_seed, visit_id)[:16], 16)
            visits.append(
                {
                    "visit_id": visit_id,
                    "split_group_id": split_group_id,
                    "workload_id": workload_id,
                    "manifest": workload["manifest"],
                    "manifest_path": manifest_path,
                    "manifest_sha256": workload["manifest_sha256"],
                    "source_manifest_sha256": source_manifest_sha256,
                    "resolved_manifest_sha256": workload["resolved_manifest_sha256"],
                    "resolved_manifest": f"resolved-workloads/{workload_id}.json",
                    "workload_scope": workload_scope,
                    "workload_model": workload["workload_model"],
                    "resource_count": workload["resource_count"],
                    "origin_count": workload["origin_count"],
                    "expected_endpoint_count": workload["expected_endpoint_count"],
                    "class_label": workload["class_label"],
                    "role": workload["role"],
                    "repetition": repetition,
                    "seed": visit_seed,
                    "path": (f"{workload['class_label']}/{workload_id}-visit-{repetition:05d}"),
                }
            )
    return study_id, visits


def load_campaign(
    path: Path,
    *,
    network_condition: str | None = None,
) -> Campaign:
    source = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(source, dict):
        raise ValueError("campaign must be a YAML object")
    _reject_unknown(source, CAMPAIGN_KEYS, "campaign")
    missing = {"name", "seed", "qcsd_profile", "workloads", "defenses"} - set(source)
    if missing:
        raise ValueError(f"campaign is missing: {', '.join(sorted(missing))}")
    profile = str(source["qcsd_profile"])
    if profile not in {"published", "live"}:
        raise ValueError("qcsd_profile must be published or live")
    stage = str(source.get("stage", "acceptance"))
    if stage not in CAMPAIGN_STAGES:
        raise ValueError("stage must be acceptance, research, or parameter-fitting")
    workload_spec = _object(source["workloads"], "workloads")
    _reject_unknown(workload_spec, WORKLOAD_KEYS, "workloads")
    workload_source = str(workload_spec.get("source", ""))
    if workload_source not in {"controlled", "live"}:
        raise ValueError("workloads source must be controlled or live")
    reviewed = bool(workload_spec.get("reviewed", False))
    if workload_source == "live" and not reviewed:
        raise ValueError("live workloads must be explicitly reviewed")
    workload_scope = str(workload_spec.get("scope", "as-defined"))
    if workload_scope not in WORKLOAD_SCOPES:
        raise ValueError(
            "workloads scope must be as-defined, primary-origin, or all-reviewed-origins"
        )
    request_policy = str(workload_spec.get("request_policy", "as-defined"))
    if request_policy not in REQUEST_POLICIES:
        raise ValueError("workloads request_policy must be as-defined or half-duplex")
    root_value = Path(str(workload_spec.get("root", "workloads")))
    workload_root = (path.parent / root_value).resolve()
    if not workload_root.is_dir():
        raise ValueError(f"workload root does not exist: {root_value}")
    workload_model = {
        "as-defined": "as-defined",
        "primary-origin": "Dconn",
        "all-reviewed-origins": "Dmc",
    }[workload_scope]
    workloads = _load_workloads(workload_root, root_value, workload_spec, workload_scope)
    if stage == "research":
        workload_ids_by_source: dict[str, list[str]] = {}
        for workload in workloads:
            workload_ids_by_source.setdefault(
                str(workload["source_manifest_sha256"]),
                [],
            ).append(str(workload["workload_id"]))
        aliases = [
            identifiers for identifiers in workload_ids_by_source.values() if len(identifiers) > 1
        ]
        if aliases:
            rendered = "; ".join(", ".join(sorted(items)) for items in aliases)
            raise ValueError(
                "research workloads cannot assign distinct workload IDs/class labels to "
                f"the same source manifest: {rendered}"
            )
    split_seed = int(source["seed"])
    expected_workloads = parameter_workload_contract(workloads)
    defenses = _load_defenses(
        path.parent,
        source["defenses"],
        stage=stage,
        qcsd_profile=profile,
        split_seed=split_seed,
        expected_workloads=expected_workloads,
    )
    if stage == "research" and not is_canonical_defense_suite(defenses):
        raise ValueError(
            "research campaigns must configure the canonical seven defenses with their "
            "fixed runtime kinds, sole undefended baseline, and stable order: "
            + ", ".join(DEFENSE_ORDER)
        )
    limits = _load_limits(source.get("limits", {}), workload_source)
    condition = network_condition or "docker-bridge-local"
    if not condition.strip():
        raise ValueError("network condition must not be empty")
    study_id = study_id_for_workloads(request_policy, workloads)
    return Campaign(
        name=slug(str(source["name"])),
        path=path.resolve(),
        seed=split_seed,
        stage=stage,
        qcsd_profile=profile,
        source=workload_source,
        reviewed=reviewed,
        workload_root=workload_root,
        workload_scope=workload_scope,
        workload_model=workload_model,
        request_policy=request_policy,
        workloads=tuple(workloads),
        defenses=defenses,
        limits=limits,
        network_condition=condition,
        study_id=study_id,
    )


def _load_workloads(
    root: Path,
    root_value: Path,
    spec: dict[str, Any],
    scope: str,
) -> list[dict[str, Any]]:
    workloads: list[dict[str, Any]] = []
    seen: set[str] = set()
    for role in ("monitored", "unmonitored"):
        entries = spec.get(role)
        if not isinstance(entries, dict):
            raise ValueError(f"workloads {role} must be a mapping")
        for identifier, raw_visits in entries.items():
            workload_id = slug(str(identifier))
            if workload_id in seen:
                raise ValueError(f"duplicate workload {workload_id}")
            seen.add(workload_id)
            visits = int(raw_visits)
            if visits < 1:
                raise ValueError("workload visit counts must be positive")
            relative = root_value / f"{workload_id}.json"
            manifest = (root / f"{workload_id}.json").resolve()
            if not manifest.is_file():
                raise ValueError(f"workload manifest does not exist: {relative}")
            source_manifest = load_json(manifest)
            validate_manifest(source_manifest)
            resolved, details = resolve_workload(source_manifest, scope)
            workloads.append(
                {
                    "workload_id": workload_id,
                    "manifest": str(relative),
                    "manifest_path": str(manifest),
                    "manifest_sha256": sha256_file(manifest),
                    "source_manifest_sha256": sha256_file(manifest),
                    "resolved_manifest_sha256": sha256_bytes(canonical_bytes(resolved)),
                    "resolved_manifest_data": resolved,
                    "class_label": workload_id,
                    "role": role,
                    "visits": visits,
                    "replay": source_manifest.get("replay"),
                    **details,
                }
            )
    if not workloads:
        raise ValueError("campaign requires at least one workload")
    return workloads


def resolve_workload(source: dict[str, Any], scope: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve one immutable browser graph to the campaign's replay scope."""

    validate_manifest(source)
    resolved = json.loads(json.dumps(runtime_manifest(source)))
    replay = source.get("replay")
    if scope == "primary-origin":
        if not replay:
            raise ValueError("primary-origin scope requires replay metadata")
        final_origin = _url_origin(str(replay["final_url"]))
        resolved["resources"] = [
            resource
            for resource in resolved["resources"]
            if _url_origin(resource["url"]) == final_origin
        ]
    elif scope == "all-reviewed-origins":
        if not replay:
            raise ValueError("all-reviewed-origins scope requires replay metadata")
        reviewed = set(replay["reviewed_origins"])
        unreviewed = {
            _url_origin(resource["url"])
            for resource in resolved["resources"]
            if _url_origin(resource["url"]) not in reviewed
        }
        if unreviewed:
            raise ValueError(
                "source graph contains origins not approved for replay: "
                + ", ".join(sorted(unreviewed))
            )
        resolved["resources"] = [
            resource
            for resource in resolved["resources"]
            if _url_origin(resource["url"]) in reviewed
        ]
    retained_ids = {resource["id"] for resource in resolved["resources"]}
    for resource in resolved["resources"]:
        resource["depends_on"] = [
            dependency
            for dependency in resource.get("depends_on", [])
            if dependency in retained_ids
        ]
    if scope in {"primary-origin", "all-reviewed-origins"}:
        stability = replay.get("response_stability") if replay else None
        stable_ids = set(stability.get("stable_resource_ids", [])) if stability else set()
        unqualified = retained_ids - stable_ids
        if unqualified:
            raise ValueError(
                "replay workload has not passed repeated response-stability preflight "
                f"for resource IDs: {', '.join(map(str, sorted(unqualified)))}"
            )
    validate_manifest(resolved)
    origins = _manifest_origins(resolved)
    if scope == "primary-origin" and (len(resolved["resources"]) < 2 or len(origins) != 1):
        raise ValueError("Dconn replay requires at least two resources from the final-page origin")
    if scope == "all-reviewed-origins" and (len(resolved["resources"]) < 2 or len(origins) < 2):
        raise ValueError("Dmc replay requires at least two retained HTTP/3 origins")
    return resolved, {
        "workload_model": {
            "as-defined": "as-defined",
            "primary-origin": "Dconn",
            "all-reviewed-origins": "Dmc",
        }[scope],
        "resource_count": len(resolved["resources"]),
        "origin_count": len(origins),
        "expected_endpoint_count": len(origins),
    }


def _url_origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _load_defenses(
    base: Path,
    raw: Any,
    *,
    stage: str,
    qcsd_profile: str,
    split_seed: int,
    expected_workloads: dict[str, tuple[str, str, int]],
) -> tuple[Defense, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("defenses must be a non-empty list")
    defenses: list[Defense] = []
    names: set[str] = set()
    for item in raw:
        if not isinstance(item, (str, dict)):
            raise ValueError("each defense must be a name or object")
        value = {"name": item} if isinstance(item, str) else dict(item)
        _reject_unknown(value, DEFENSE_KEYS, "defense")
        name = slug(str(value.get("name", value.get("kind", ""))))
        if name in names:
            raise ValueError(f"duplicate defense {name}")
        names.add(name)
        kind = (
            str(value.get("kind", "none" if name == "undefended" else name))
            .lower()
            .replace("-", "_")
        )
        if kind not in SUPPORTED_DEFENSE_KINDS:
            raise ValueError(f"unsupported defense kind: {kind}")
        baseline = bool(value.get("baseline", name == "undefended" or kind == "none"))
        if kind != "static":
            if "schedule" in value or "mode" in value:
                raise ValueError("schedule and mode are only valid for Static")
            parameters = value.get("parameters")
            if kind in PARAMETER_FLAG_BY_KIND:
                if not parameters:
                    raise ValueError(f"{kind} requires a parameter file")
                parameters_path = (base / str(parameters)).resolve()
                if not parameters_path.is_file():
                    raise ValueError(f"{kind} parameter file does not exist: {parameters}")
                provenance_path = parameter_provenance_path(parameters_path)
                relative_provenance = parameter_provenance_path(Path(str(parameters)))
                allow_reviewed_fixture = value.get("allow_reviewed_fixture", False)
                if not isinstance(allow_reviewed_fixture, bool):
                    raise ValueError("allow_reviewed_fixture must be a boolean")
                if allow_reviewed_fixture and stage != "acceptance":
                    raise ValueError("allow_reviewed_fixture is restricted to acceptance campaigns")
                artifact = validate_parameter_artifact(
                    parameters_path,
                    provenance_path=provenance_path,
                    expected_kind=kind,
                    allow_reviewed_fixture=allow_reviewed_fixture,
                    expected_qcsd_profile=qcsd_profile,
                    expected_udp_payload_ceiling=UDP_PAYLOAD_CEILING_BY_PROFILE[qcsd_profile],
                    expected_split_seed=split_seed if stage == "research" else None,
                    expected_workloads=(expected_workloads if stage == "research" else None),
                )
                defenses.append(
                    Defense(
                        name=name,
                        kind=kind,
                        baseline=baseline,
                        parameters=str(parameters),
                        parameters_path=artifact.path,
                        parameters_sha256=artifact.sha256,
                        parameters_provenance=str(relative_provenance),
                        parameters_provenance_path=artifact.provenance_path,
                        parameters_provenance_sha256=artifact.provenance_sha256,
                        parameters_input_policy=artifact.input_policy,
                    )
                )
            else:
                if "parameters" in value or "allow_reviewed_fixture" in value:
                    raise ValueError(
                        "parameters and allow_reviewed_fixture are only valid for "
                        "Traffic Morphing, WTF-PAD, or Walkie-Talkie"
                    )
                defenses.append(Defense(name=name, kind=kind, baseline=baseline))
            continue
        if "parameters" in value or "allow_reviewed_fixture" in value:
            raise ValueError("parameters and allow_reviewed_fixture are not valid for Static")
        schedule = value.get("schedule")
        mode = str(value.get("mode", ""))
        if not schedule or mode not in STATIC_MODES:
            raise ValueError("Static requires a schedule and a valid mode")
        schedule_path = (base / str(schedule)).resolve()
        if not schedule_path.is_file():
            raise ValueError(f"Static schedule does not exist: {schedule}")
        defenses.append(
            Defense(
                name=name,
                kind=kind,
                baseline=baseline,
                schedule=str(schedule),
                schedule_path=schedule_path,
                schedule_sha256=sha256_file(schedule_path),
                mode=mode,
            )
        )
    if sum(defense.baseline for defense in defenses) != 1:
        raise ValueError("campaign requires exactly one baseline defense")
    return tuple(defenses)


def _load_limits(raw: Any, source: str) -> Limits:
    value = _object(raw, "limits")
    _reject_unknown(value, LIMIT_KEYS, "limits")
    limits = Limits(
        timeout_seconds=int(value.get("timeout_seconds", 45)),
        max_response_bytes=int(value.get("max_response_bytes", 512 * 1024)),
        capture_seconds=int(value.get("capture_seconds", 60)),
        capture_megabytes=int(value.get("capture_megabytes", 64)),
        max_attempts=int(value.get("max_attempts", 3)),
        per_origin_cooldown_seconds=float(value.get("per_origin_cooldown_seconds", 30)),
        inter_sample_seconds=float(value.get("inter_sample_seconds", 5)),
        settle_seconds=float(value.get("settle_seconds", 1)),
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
    if (
        min(
            limits.per_origin_cooldown_seconds,
            limits.inter_sample_seconds,
            limits.settle_seconds,
        )
        < 0
    ):
        raise ValueError("delay limits cannot be negative")
    if limits.settle_seconds > 5:
        raise ValueError("settle_seconds must not exceed five")
    if limits.capture_seconds < limits.timeout_seconds + limits.settle_seconds + 1:
        raise ValueError(
            "capture_seconds must cover timeout_seconds, settle_seconds, "
            "and one second of collector startup margin"
        )
    if source == "live" and limits.per_origin_cooldown_seconds < 30:
        raise ValueError("live workloads require a 30-second origin cooldown")
    return limits


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be an object")
    return dict(value)


def _reject_unknown(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{location} contains unsupported fields: {', '.join(sorted(unknown))}")


def plan_campaign(
    campaign: Campaign,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    reproduced_study_id, visits = visit_plan_for_workloads(
        campaign_seed=campaign.seed,
        request_policy=campaign.request_policy,
        workload_scope=campaign.workload_scope,
        workload_root=campaign.workload_root,
        workloads=campaign.workloads,
    )
    if reproduced_study_id != campaign.study_id:
        raise ValueError("campaign study identity does not reproduce from its workloads")
    samples: list[dict[str, Any]] = []
    for visit in visits:
        for defense in campaign.defenses:
            samples.append(
                {
                    "sample_id": stable_digest(
                        "sample",
                        visit["visit_id"],
                        campaign.workload_scope,
                        "direct",
                        campaign.network_condition,
                        defense.name,
                    ),
                    "visit_id": visit["visit_id"],
                    "split_group_id": visit["split_group_id"],
                    "workload_id": visit["workload_id"],
                    "source_manifest_sha256": visit["source_manifest_sha256"],
                    "class_label": visit["class_label"],
                    "role": visit["role"],
                    "repetition": visit["repetition"],
                    "defense": defense.name,
                    "runtime_kind": defense.kind,
                    "seed": visit["seed"],
                    "path": f"{visit['path']}/{defense.name}",
                    "state": "planned",
                    "attempts": 0,
                    "eligible": False,
                    "views": {view.id: False for view in campaign.views},
                }
            )
    splits = create_splits(visits, campaign.seed)
    for sample in samples:
        sample["split"] = splits["assignments"][sample["split_group_id"]]
    return visits, samples, splits


def create_splits(visits: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    assignments: dict[str, str] = {}
    for visit in visits:
        split_group_id = visit.get("split_group_id")
        if not isinstance(split_group_id, str) or not split_group_id:
            raise ValueError("visit has no valid split-group identity")
        assignments[split_group_id] = split_assignment_for_group(split_group_id, seed)
    return {
        "seed": seed,
        "unit": "split_group_id",
        "method": "stable hash 70/15/15 source-manifest/repetition group split",
        "ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "assignments": assignments,
        "views": {
            "open-world": {"roles": ["monitored", "unmonitored"]},
            "closed-world": {"roles": ["monitored"]},
        },
    }


def _materialize_resolved_workloads(root: Path, campaign: Campaign) -> None:
    directory = root / "resolved-workloads"
    directory.mkdir(parents=True, exist_ok=True)
    for workload in campaign.workloads:
        path = directory / f"{workload['workload_id']}.json"
        data = canonical_bytes(workload["resolved_manifest_data"])
        if path.exists():
            if sha256_file(path) != workload["resolved_manifest_sha256"]:
                raise ValueError(f"resolved workload provenance mismatch: {path.name}")
            continue
        atomic_text(path, data.decode())


def collect_campaign(
    path: Path,
    results_root: Path,
    *,
    network_condition: str | None = None,
    resume: Path | None = None,
) -> Path:
    """Collect or resume one study through the shared capture pipeline."""

    campaign = load_campaign(
        path,
        network_condition=network_condition,
    )
    started = datetime.now(timezone.utc)
    visits, planned_samples, splits = plan_campaign(campaign)
    desired = _campaign_receipt(campaign, visits, started)
    defenses = {defense.name: defense for defense in campaign.defenses}
    if resume is None:
        root = results_root / started.strftime("%Y%m%dT%H%M%SZ")
        root.mkdir(parents=True, exist_ok=False)
        samples = planned_samples
        atomic_json(root / "splits.json", splits)
    else:
        root = resume.resolve()
        seal = root / "SHA256SUMS"
        sealed_resume = seal.is_file()
        if sealed_resume:
            verify_checksum_seal(root)
        previous = load_json(root / "campaign.json")
        if previous.get("input_digest") != desired["input_digest"]:
            raise ValueError("resume provenance mismatch")
        samples = _resume_samples(planned_samples, _load_sample_index(root))
        for sample in samples:
            if sample["state"] == "captured":
                _accepted_sample_exists(
                    root,
                    sample,
                    defenses[sample["defense"]],
                    campaign,
                )
        desired["campaign"]["started_at"] = previous["campaign"]["started_at"]
        desired["campaign"]["resumed_at"] = started.isoformat()
        desired["environment"] = previous.get("environment", {})
        # Retire a verified seal only after every read-only resume preflight
        # has passed and immediately before the first possible mutation.
        if sealed_resume:
            seal.unlink()
    _materialize_resolved_workloads(root, campaign)
    receipt = desired
    atomic_json(root / "dataset.json", _dataset_card(campaign, receipt, "collecting"))
    _checkpoint(root, receipt, samples)

    samples_by_visit = {
        visit["visit_id"]: [sample for sample in samples if sample["visit_id"] == visit["visit_id"]]
        for visit in visits
    }
    origin_last_run: dict[str, float] = {}
    for visit in visits:
        manifest_path = root / visit["resolved_manifest"]
        manifest = load_json(manifest_path)
        validate_manifest(manifest)
        visit_samples = samples_by_visit[visit["visit_id"]]
        ordered = list(visit_samples)
        random.Random(visit["seed"]).shuffle(ordered)
        for position, sample in enumerate(ordered):
            defense = defenses[sample["defense"]]
            if sample["state"] == "captured" and _accepted_sample_exists(
                root,
                sample,
                defense,
                campaign,
            ):
                continue
            if sample["state"] == "running":
                sample.update(
                    state="interrupted",
                    failure={"stage": "interruption", "message": "stale running state"},
                )
            sample_path = root / sample["path"]
            while sample["attempts"] < campaign.limits.max_attempts:
                _respect_origin_cooldown(manifest, campaign, origin_last_run)
                sample.update(state="running", attempts=sample["attempts"] + 1)
                sample.pop("failure", None)
                _checkpoint(root, receipt, samples)
                attempt = sample_path / "attempts" / f"attempt-{sample['attempts']:03d}"
                try:
                    result = _collect_attempt(
                        attempt,
                        manifest_path,
                        visit["workload_id"],
                        defense,
                        sample["seed"],
                        campaign,
                    )
                except Exception as error:
                    result = {
                        "success": False,
                        "failure": {
                            "stage": "collection",
                            "type": type(error).__name__,
                            "message": str(error),
                        },
                    }
                    attempt.mkdir(parents=True, exist_ok=True)
                    atomic_json(attempt / "attempt.json", result)
                _mark_origin_completed(manifest, origin_last_run)
                if result["success"]:
                    _promote_attempt(attempt, sample_path)
                    sample["state"] = "captured"
                    metadata = _sample_metadata(visit, sample, defense, result, campaign)
                    atomic_json(sample_path / "sample.json", metadata)
                    sample.update(
                        capture_completed_at=metadata["capture_completed_at"],
                        operationally_valid=result.get("operationally_valid", True),
                        defense_diagnostics=result.get("defense_diagnostics"),
                        views={view["id"]: view["valid"] for view in result["views"]},
                    )
                    sample.pop("failure", None)
                    receipt["environment"].setdefault(
                        "capture_interfaces", result.get("offloads", [])
                    )
                    break
                sample.update(
                    state="failed",
                    failure=result.get("failure"),
                    operationally_valid=result.get("operationally_valid", False),
                    defense_diagnostics=result.get("defense_diagnostics"),
                )
                _checkpoint(root, receipt, samples)
            if sample["state"] != "captured":
                _write_failed_sample(sample_path, visit, sample, defense, campaign)
            _checkpoint(root, receipt, samples)
            if campaign.limits.inter_sample_seconds and position + 1 < len(ordered):
                time.sleep(campaign.limits.inter_sample_seconds)
        _compare_visit(root, visit_samples, defenses, campaign)
        _checkpoint(root, receipt, samples)

    operationally_eligible_visits = sum(
        all(sample["eligible"] for sample in members) for members in samples_by_visit.values()
    )
    eligible_visits = sum(
        all(sample["eligible"] and sample.get("fidelity_eligible") is True for sample in members)
        for members in samples_by_visit.values()
    )
    receipt["summary"] = {
        "eligible_visits": eligible_visits,
        "operationally_eligible_visits": operationally_eligible_visits,
        "fidelity_eligible_visits": eligible_visits,
        "required_visits": len(visits),
        "logical_samples": len(samples),
        "passed": eligible_visits == len(visits),
    }
    receipt["campaign"].update(
        status="complete" if receipt["summary"]["passed"] else "incomplete",
        completed_at=datetime.now(timezone.utc).isoformat(),
    )
    _checkpoint(root, receipt, samples)
    atomic_json(
        root / "dataset.json",
        _dataset_card(campaign, receipt, receipt["campaign"]["status"]),
    )

    from .dataset import write_classifier_indexes, write_projection
    from .plotting import plot_run
    from .report import create_report

    write_classifier_indexes(root)
    plot_run(root)
    create_report(root)
    write_projection(root)
    write_checksums(
        root,
        [path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"],
    )
    if not receipt["summary"]["passed"]:
        raise CampaignIncomplete(root)
    return root


def _campaign_receipt(
    campaign: Campaign, visits: list[dict[str, Any]], started: datetime
) -> dict[str, Any]:
    configuration = {
        "campaign_sha256": sha256_file(campaign.path),
        "study_id": campaign.study_id,
        "stage": campaign.stage,
        "seed": campaign.seed,
        "qcsd_profile": campaign.qcsd_profile,
        "capture": {
            "mode": "direct",
            "purpose": campaign.purpose,
            "network_condition": campaign.network_condition,
            "udp_payload_ceiling": campaign.udp_payload_ceiling,
            "primary_view": campaign.primary_view.id,
            "views": [view.as_dict() for view in campaign.views],
        },
        "limits": campaign.limits.as_dict(),
        "workloads": {
            "source": campaign.source,
            "reviewed": campaign.reviewed,
            "root": str(campaign.workload_root),
            "scope": campaign.workload_scope,
            "model": campaign.workload_model,
            "request_policy": campaign.request_policy,
            "entries": [
                {
                    key: item[key]
                    for key in item
                    if key not in {"manifest_path", "resolved_manifest_data"}
                }
                for item in campaign.workloads
            ],
        },
        "defenses": [defense.as_dict() for defense in campaign.defenses],
    }
    software = {
        **source_metadata(),
        "docker_image": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "unknown"),
        "nss_version": os.environ.get("NSS_VERSION", "unknown"),
        "nspr_version": os.environ.get("NSPR_VERSION", "unknown"),
        "nss_bundle_sha256": os.environ.get("NSS_BUNDLE_SHA256", "unknown"),
    }
    digest_capture = dict(configuration["capture"])
    digest_capture["views"] = [view.as_dict() for view in campaign.views]
    digest_configuration = {**configuration, "capture": digest_capture}
    input_digest = stable_digest(
        "campaign-input",
        json.dumps(
            {"configuration": digest_configuration, "software": software},
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return {
        "campaign": {
            "name": campaign.name,
            "stage": campaign.stage,
            "purpose": campaign.purpose,
            "status": "collecting",
            "started_at": started.isoformat(),
        },
        "input_digest": input_digest,
        "configuration": configuration,
        "software": software,
        "environment": {},
        "visits": visits,
        "summary": {
            "eligible_visits": 0,
            "required_visits": len(visits),
            "logical_samples": len(visits) * len(campaign.defenses),
            "passed": False,
        },
    }


def _resume_samples(
    planned: list[dict[str, Any]], previous: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    old = {sample["sample_id"]: sample for sample in previous}
    if set(old) != {sample["sample_id"] for sample in planned}:
        raise ValueError("resume sample plan mismatch")
    lifecycle = {
        "state",
        "attempts",
        "failure",
        "capture_completed_at",
        "eligible",
        "operationally_valid",
        "defense_diagnostics",
        "response_match",
        "content_drift",
        "views",
        "fidelity_eligible",
        "fidelity_path",
    }
    for sample in planned:
        sample.update(
            {
                key: old[sample["sample_id"]][key]
                for key in lifecycle
                if key in old[sample["sample_id"]]
            }
        )
    return planned


def _dataset_card(campaign: Campaign, receipt: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "title": campaign.name,
        "stage": campaign.stage,
        "purpose": campaign.purpose,
        "status": status,
        "data_license": "not-for-release",
        "threat_model": {
            "adversary": "passive observer at the client network edge",
            "visible_features": [
                "Ethernet frame length",
                "relative inter-arrival timing",
                "direction",
                "trace boundary",
            ],
            "excluded_features": [
                "destinations",
                "endpoints",
                "plaintext",
                "keys",
                "qlogs",
                "Neqo events",
                "response hashes",
                "defense schedules",
                "defense names",
                "seeds",
                "application completion",
                "diagnostics",
                "normalized trace duration",
            ],
        },
        "observer_definitions": [view.as_dict() for view in campaign.views],
        "primary_observer": campaign.primary_view.id,
        "workloads": _public_workload_summary(receipt["configuration"]["workloads"]),
        "defenses": [{"name": item.name, "baseline": item.baseline} for item in campaign.defenses],
        "split": ("one stable hash 70/15/15 assignment per source-manifest/repetition split group"),
        "eligibility_rule": (
            "every defense sample has a valid primary view, matches the undefended "
            "response, has no defense termination guard failure, and passes its "
            "declared fidelity realization gates"
        ),
        "limitations": [
            "test-client workloads model QCSD Dconn/Dmc rather than browser Dfull",
            "canonical PCAPNG files retain link and endpoint metadata; classifier-facing "
            "normalized traces expose only timing, direction, and frame length",
        ],
    }


def _public_workload_summary(workloads: dict[str, Any]) -> dict[str, Any]:
    public_fields = {
        "workload_id",
        "class_label",
        "role",
        "visits",
        "workload_model",
        "resource_count",
        "origin_count",
        "expected_endpoint_count",
        "source_manifest_sha256",
        "resolved_manifest_sha256",
    }
    return {
        "source": workloads["source"],
        "reviewed": workloads["reviewed"],
        "scope": workloads["scope"],
        "model": workloads["model"],
        "entries": [
            {key: value for key, value in item.items() if key in public_fields}
            for item in workloads["entries"]
        ],
    }


def _checkpoint(root: Path, receipt: dict[str, Any], samples: list[dict[str, Any]]) -> None:
    atomic_json(root / "campaign.json", receipt)
    atomic_text(
        root / "samples.jsonl",
        "".join(json.dumps(sample, sort_keys=True) + "\n" for sample in samples),
    )


def _load_sample_index(root: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (root / "samples.jsonl").read_text().splitlines()]


def _accepted_sample_exists(
    root: Path,
    sample: dict[str, Any],
    defense: Defense,
    campaign: Campaign,
) -> bool:
    sample_path = root / sample["path"]
    metadata_path = sample_path / "sample.json"
    if not metadata_path.is_file():
        raise ValueError(f"accepted sample metadata is missing: {sample_path}")
    metadata = load_json(metadata_path)
    if (
        metadata.get("sample_id") != sample["sample_id"]
        or metadata.get("state") != "captured"
        or metadata.get("defense") != defense.name
        or metadata.get("runtime_kind") != defense.kind
    ):
        raise ValueError(f"accepted sample metadata binding is invalid: {sample_path}")
    primary_valid = False
    for view in metadata.get("views", []):
        primary_valid |= bool(view.get("primary") and view.get("valid"))
        if not view.get("valid"):
            continue
        offload = view.get("capture_offload_evidence")
        ceiling = view.get("udp_payload_ceiling_evidence")
        if (
            not offload_evidence_is_valid(
                offload,
                interface=str(view.get("interface", "")),
            )
            or metadata.get("capture_offloads") != [offload]
            or metadata.get("udp_payload_ceiling") != campaign.udp_payload_ceiling
            or not isinstance(ceiling, dict)
            or ceiling.get("configured_udp_payload_ceiling") != campaign.udp_payload_ceiling
            or ceiling.get("runner_resolved_udp_payload_ceiling") != campaign.udp_payload_ceiling
            or ceiling.get("runner_binding_valid") is not True
            or ceiling.get("valid") is not True
        ):
            raise ValueError(
                f"accepted sample capture environment binding is invalid: {sample_path}"
            )
        capture = sample_path / view["capture_path"]
        trace = sample_path / view["trace_path"]
        if not capture.is_file() or not trace.is_file():
            raise ValueError(f"accepted sample view artifact is missing: {sample_path}")
        if sha256_file(capture) != view.get("capture_sha256"):
            raise ValueError(f"accepted sample capture hash mismatch: {sample_path}")
        if sha256_file(trace) != view.get("trace_sha256"):
            raise ValueError(f"accepted sample trace hash mismatch: {sample_path}")
    if not primary_valid:
        raise ValueError(f"accepted sample has no valid primary view: {sample_path}")
    run_path = sample_path / "neqo" / "run.json"
    if not run_path.is_file():
        raise ValueError(f"accepted sample run metadata is missing: {sample_path}")
    run_data = load_json(run_path)
    if not isinstance(run_data, dict):
        raise ValueError(f"accepted sample run is incomplete: {sample_path}")
    try:
        validate_sample_run_binding(
            sample_path,
            run_data,
            sample,
            metadata,
            defense_name=defense.name,
            defense_kind=defense.kind,
            expected_udp_payload_ceiling=campaign.udp_payload_ceiling,
        )
    except ValueError as error:
        raise ValueError(f"accepted {error}") from error
    _validate_accepted_parameter_artifacts(
        sample_path,
        defense,
        run_data,
        campaign=campaign,
        expected_workload_id=(
            str(sample["workload_id"])
            if defense.kind in {"traffic_morphing", "walkie_talkie"} and "workload_id" in sample
            else None
        ),
    )
    try:
        validate_fidelity_record(sample_path, sample, metadata)
    except (OSError, ValueError) as error:
        raise ValueError(
            f"accepted sample fidelity record is invalid: {sample_path}: {error}"
        ) from error
    return True


def _validate_accepted_parameter_artifacts(
    sample_path: Path,
    defense: Defense,
    run_data: dict[str, Any],
    *,
    campaign: Campaign,
    expected_workload_id: str | None,
) -> None:
    run_parameter = run_data.get("defense_parameters")
    if defense.parameters_path is None and defense.schedule_path is None:
        if run_parameter is not None:
            raise ValueError(f"accepted sample has unexpected parameter provenance: {sample_path}")
        return

    if defense.parameters_path is not None:
        try:
            validate_sample_parameter_artifacts(
                sample_path,
                defense.as_dict(),
                expected_runtime_path=defense.parameters_path,
                expected_workload_id=expected_workload_id,
                expected_qcsd_profile=campaign.qcsd_profile,
                expected_udp_payload_ceiling=campaign.udp_payload_ceiling,
                expected_split_seed=(campaign.seed if campaign.stage == "research" else None),
                expected_workloads=(
                    parameter_workload_contract(campaign.workloads)
                    if campaign.stage == "research"
                    else None
                ),
            )
        except ValueError as error:
            raise ValueError(f"{error}: {sample_path}") from error
        return
    try:
        validate_run_parameter_binding(
            run_data,
            kind=defense.kind,
            sha256=defense.schedule_sha256,
            expected_path=defense.schedule_path,
        )
    except ValueError as error:
        raise ValueError(f"{error}: {sample_path}") from error


def _respect_origin_cooldown(
    manifest: dict[str, Any], campaign: Campaign, last: dict[str, float]
) -> None:
    origins = _manifest_origins(manifest)
    cooldown = campaign.limits.per_origin_cooldown_seconds
    wait = max(
        (last.get(origin, 0.0) + cooldown - time.monotonic() for origin in origins),
        default=0.0,
    )
    if wait > 0:
        time.sleep(wait)


def _mark_origin_completed(manifest: dict[str, Any], last: dict[str, float]) -> None:
    now = time.monotonic()
    for origin in _manifest_origins(manifest):
        last[origin] = now


def _manifest_origins(manifest: dict[str, Any]) -> list[str]:
    return sorted(
        {
            f"{urlsplit(resource['url']).scheme}://{urlsplit(resource['url']).netloc}"
            for resource in manifest.get("resources", [])
        }
    )


def _offload_metadata(interface: str) -> dict[str, Any]:
    before = run(["ethtool", "-k", interface], check=False)
    changes = {
        short_name: run(
            ["ethtool", "-K", interface, feature, "off"],
            check=False,
        ).returncode
        for short_name, feature in REQUIRED_OFFLOAD_FEATURES.items()
    }
    after = run(["ethtool", "-k", interface], check=False)
    before_state = parse_offload_state(before.stdout)
    after_state = parse_offload_state(after.stdout)
    evidence = {
        "interface": interface,
        "requested": dict(OFFLOAD_DISABLED),
        "query_returncodes": {"before": before.returncode, "after": after.returncode},
        "change_returncodes": changes,
        "before_state": before_state,
        "after_state": after_state,
        "before_sha256": stable_digest(before.stdout),
        "after_sha256": stable_digest(after.stdout),
    }
    evidence["verified"] = recompute_offload_verification(
        evidence,
        interface=interface,
    )
    return evidence


def _collect_attempt(
    attempt: Path,
    manifest: Path,
    workload_id: str,
    defense: Defense,
    seed: int,
    campaign: Campaign,
) -> dict[str, Any]:
    if (
        defense.parameters_path is not None
        and defense.parameters_sha256 is not None
        and sha256_file(defense.parameters_path) != defense.parameters_sha256
    ):
        raise ValueError("defense parameter file changed after campaign resolution")
    if (
        defense.parameters_provenance_path is not None
        and defense.parameters_provenance_sha256 is not None
        and sha256_file(defense.parameters_provenance_path) != defense.parameters_provenance_sha256
    ):
        raise ValueError("defense parameter provenance changed after campaign resolution")
    attempt.mkdir(parents=True, exist_ok=False)
    diagnostics = attempt / "diagnostics"
    captures = attempt / "captures"
    traces = attempt / "traces"
    neqo = attempt / "neqo"
    for directory in (diagnostics, captures, traces):
        directory.mkdir()
    view = DIRECT_CAPTURE_VIEW
    offloads = [_offload_metadata(view.interface)]
    offloads_valid = all(
        offload_evidence_is_valid(item, interface=view.interface) for item in offloads
    )
    raw = diagnostics / f"{view.id}-raw.pcapng"
    capture_log = diagnostics / f"dumpcap-{view.id}.log"
    handle = capture_log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            "dumpcap",
            "-q",
            "-i",
            view.interface,
            "-f",
            "udp",
            "-w",
            str(raw),
            "-a",
            f"duration:{campaign.limits.capture_seconds}",
            "-a",
            f"filesize:{campaign.limits.capture_megabytes * 1024}",
        ],
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    capture_active_through_settle = False
    try:
        _wait_for_capture_start(process, capture_log)
        client = run(
            _client_command(manifest, workload_id, defense, seed, campaign, neqo),
            log=diagnostics / "neqo-client.log",
            check=False,
        )
        if neqo.is_dir():
            _copy_defense_parameter_artifacts(defense, neqo)
        if campaign.limits.settle_seconds:
            time.sleep(campaign.limits.settle_seconds)
        capture_active_through_settle = process.poll() is None
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
        handle.close()

    run_json = neqo / "run.json"
    run_data = load_json(run_json) if run_json.exists() else {}
    endpoints = run_data.get("endpoints", [])
    completion_status = run_data.get("completion_status")
    responses = run_data.get("responses", [])
    runner_complete = _runner_result_complete(run_data)
    guard_triggered = padding_event_guard_triggered(run_data)
    expected_endpoint_count = len(_manifest_origins(load_json(manifest)))
    endpoint_count_valid = len(endpoints) == expected_endpoint_count
    failures: list[dict[str, Any]] = []
    output = captures / f"{view.id}.pcapng"
    display_filter = tuple_filter(endpoints) if endpoints else "udp"
    filtered = run(
        ["tshark", "-r", str(raw), "-Y", display_filter, "-w", str(output)],
        log=diagnostics / f"filter-{view.id}.log",
        check=False,
    )
    capinfos = run(["capinfos", "-E", "-c", "-s", str(output)], check=False)
    limit = campaign.limits.capture_megabytes * 1024 * 1024
    truncated = raw.exists() and raw.stat().st_size >= int(limit * 0.99)
    try:
        trace = extract_trace(output, endpoints)
    except (KeyError, RuntimeError, ValueError) as error:
        trace = []
        failures.append({"view": view.id, "primary": True, "reason": str(error)})
    trace_path = traces / f"{view.id}.csv"
    if trace:
        write_normalized_trace(trace_path, trace)
    direct_runner_reconciliation_valid = False
    if runner_complete and trace_path.is_file():
        try:
            reconciliation = reconcile_direct_runner_artifacts(
                run_json,
                neqo / "packets.csv",
                trace_path,
            )
            direct_runner_reconciliation_valid = reconciliation.evidence_eligible
        except (OSError, ValueError) as error:
            failures.append(
                {
                    "view": view.id,
                    "primary": True,
                    "reason": f"direct/runner reconciliation failed: {error}",
                }
            )
    resolved_configuration = run_data.get("resolved_configuration")
    resolved_udp_payload_ceiling = (
        resolved_configuration.get("max_udp_payload_size")
        if isinstance(resolved_configuration, dict)
        else None
    )
    ceiling_evidence = udp_ceiling_evidence(trace, campaign.udp_payload_ceiling)
    runner_ceiling_valid = resolved_udp_payload_ceiling == campaign.udp_payload_ceiling
    ceiling_evidence.update(
        {
            "runner_resolved_udp_payload_ceiling": resolved_udp_payload_ceiling,
            "runner_binding_valid": runner_ceiling_valid,
            "valid": bool(ceiling_evidence["valid"] and runner_ceiling_valid),
        }
    )
    link_valid = view.link_type.lower() in capinfos.stdout.lower()
    valid = (
        process.returncode in {0, 2}
        and filtered.returncode == 0
        and capinfos.returncode == 0
        and output.is_file()
        and output.stat().st_size > 0
        and bool(trace)
        and not truncated
        and capture_active_through_settle
        and link_valid
        and offloads_valid
        and ceiling_evidence["valid"]
        and direct_runner_reconciliation_valid
    )
    if not valid:
        failures.append(
            {
                "view": view.id,
                "primary": True,
                "reason": "capture validation failed",
                "dumpcap_returncode": process.returncode,
                "filter_returncode": filtered.returncode,
                "capinfos_returncode": capinfos.returncode,
                "truncated": truncated,
                "capture_active_through_settle": capture_active_through_settle,
                "link_type_valid": link_valid,
                "capture_offloads_valid": offloads_valid,
                "udp_payload_ceiling_valid": ceiling_evidence["valid"],
                "direct_runner_reconciliation_valid": direct_runner_reconciliation_valid,
            }
        )
    record = {
        **view.as_dict(),
        "flow_filter": "udp filtered to the exact Neqo endpoint tuples",
        "direction_rule": "Neqo local endpoint tuple is outgoing",
        "capture_boundary": "before Neqo through defense tail and settle interval",
        "packet_count": len(trace),
        "truncated": truncated,
        "capture_active_through_settle": capture_active_through_settle,
        "capture_path": f"captures/{view.id}.pcapng",
        "trace_path": f"traces/{view.id}.csv",
        "capture_sha256": sha256_file(output) if output.exists() else None,
        "trace_sha256": sha256_file(trace_path) if trace_path.exists() else None,
        "pcapng_bytes": output.stat().st_size if output.exists() else 0,
        "udp_payload_ceiling_evidence": ceiling_evidence,
        "capture_offload_evidence": offloads[0],
        "valid": valid,
    }
    success = client.returncode == 0 and runner_complete and endpoint_count_valid and valid
    result = {
        "success": success,
        "runner_returncode": client.returncode,
        "runner_completion_status": completion_status,
        "runner_complete": runner_complete,
        "endpoint_count": len(endpoints),
        "expected_endpoint_count": expected_endpoint_count,
        "endpoint_count_valid": endpoint_count_valid,
        "views": [record],
        "offloads": offloads,
        "defense_diagnostics": run_data.get("defense_diagnostics"),
        "operationally_valid": not guard_triggered,
        "failure": (
            None
            if success
            else {
                "stage": (
                    "capture"
                    if client.returncode == 0 and runner_complete and endpoint_count_valid
                    else "runner"
                ),
                "details": [
                    {
                        "runner_returncode": client.returncode,
                        "completion_status": completion_status,
                        "operational_failure": (
                            "wtf_pad_padding_event_guard_triggered" if guard_triggered else None
                        ),
                        "defense_diagnostics": run_data.get("defense_diagnostics"),
                        "incomplete_resources": [
                            response.get("resource_id")
                            for response in responses
                            if response.get("complete") is not True
                            or response.get("outcome") != "succeeded"
                        ],
                    },
                    *[item for item in failures if item.get("primary")],
                ],
            }
        ),
    }
    atomic_json(attempt / "attempt.json", result)
    return result


def _copy_defense_parameter_artifacts(defense: Defense, neqo: Path) -> None:
    if defense.parameters_path is None:
        return
    if defense.parameters_provenance_path is None:
        raise ValueError("reactive defense parameters lack provenance")
    shutil.copy2(defense.parameters_path, neqo / PARAMETER_ARTIFACT_NAME)
    shutil.copy2(
        defense.parameters_provenance_path,
        neqo / PARAMETER_PROVENANCE_ARTIFACT_NAME,
    )


def _runner_result_complete(run_data: dict[str, Any]) -> bool:
    responses = run_data.get("responses", [])
    return (
        run_data.get("completion_status") == "complete"
        and not padding_event_guard_triggered(run_data)
        and bool(responses)
        and all(
            response.get("complete") is True and response.get("outcome") == "succeeded"
            for response in responses
        )
    )


def validate_sample_run_binding(
    sample_path: Path,
    run_data: dict[str, Any],
    sample: dict[str, Any],
    metadata: dict[str, Any],
    *,
    defense_name: str,
    defense_kind: str,
    expected_udp_payload_ceiling: int,
) -> None:
    """Validate immutable runner inputs against one planned captured sample."""

    resolved = run_data.get("resolved_configuration")
    resolved_defense = resolved.get("defense") if isinstance(resolved, dict) else None
    signature = response_signature(sample_path)
    expected_signature_sha256 = (
        stable_digest("responses", json.dumps(signature, sort_keys=True))
        if signature is not None
        else None
    )
    if (
        not _runner_result_complete(run_data)
        or not isinstance(resolved_defense, dict)
        or resolved_defense.get("kind") != defense_kind
        or (
            defense_kind in {"traffic_morphing", "walkie_talkie"}
            and resolved_defense.get("workload_id") != sample.get("workload_id")
        )
        or metadata.get("defense") != defense_name
        or metadata.get("runtime_kind") != defense_kind
        or metadata.get("resolved_defense") != resolved
        or metadata.get("sample_id") != sample.get("sample_id")
        or metadata.get("visit_id") != sample.get("visit_id")
        or metadata.get("split_group_id") != sample.get("split_group_id")
        or metadata.get("split") != sample.get("split")
        or metadata.get("seed") != sample.get("seed")
        or run_data.get("seed") != sample.get("seed")
        or run_data.get("workload_hash_sha256") != metadata.get("resolved_manifest_sha256")
        or not isinstance(resolved, dict)
        or resolved.get("max_udp_payload_size") != expected_udp_payload_ceiling
        or metadata.get("response_signature_sha256") != expected_signature_sha256
    ):
        raise ValueError(f"sample run binding is invalid: {sample_path}")


def _wait_for_capture_start(
    process: subprocess.Popen[str],
    log: Path,
    *,
    timeout_seconds: float = 5,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("dumpcap exited before capture start")
        if log.is_file() and "File:" in log.read_text(errors="replace"):
            time.sleep(1)
            return
        time.sleep(0.02)
    raise RuntimeError("dumpcap did not become ready")


def _client_command(
    manifest: Path,
    workload_id: str,
    defense: Defense,
    seed: int,
    campaign: Campaign,
    output: Path,
) -> list[str]:
    command = [
        NEQO_CLIENT,
        "run",
        "--workload",
        str(manifest),
        "--seed",
        str(seed),
        "--output-dir",
        str(output),
        "--max-response-bytes",
        str(campaign.limits.max_response_bytes),
        "--timeout-seconds",
        str(campaign.limits.timeout_seconds),
        "--request-policy",
        campaign.request_policy,
    ]
    if not defense.baseline:
        command += ["--chaff-manifest", str(manifest)]
    runner_kind = RUNNER_KIND_BY_KIND.get(defense.kind, defense.kind)
    command += ["--profile", campaign.qcsd_profile, "--defense", runner_kind]
    if defense.kind == "static":
        command += [
            "--schedule",
            str(defense.schedule_path),
            "--static-mode",
            str(defense.mode),
        ]
    elif defense.kind in PARAMETER_FLAG_BY_KIND:
        command += [
            PARAMETER_FLAG_BY_KIND[defense.kind],
            str(defense.parameters_path),
        ]
        if defense.kind in {"traffic_morphing", "walkie_talkie"}:
            command += ["--workload-id", workload_id]
    return command


def _promote_attempt(attempt: Path, sample: Path) -> None:
    for name in ("captures", "traces", "neqo"):
        destination = sample / name
        if destination.exists():
            raise ValueError(f"accepted artifact already exists: {destination}")
        shutil.move(str(attempt / name), str(destination))
    diagnostics = attempt / "diagnostics"
    if diagnostics.exists():
        shutil.rmtree(diagnostics)


def _sample_metadata(
    visit: dict[str, Any],
    sample: dict[str, Any],
    defense: Defense,
    result: dict[str, Any],
    campaign: Campaign,
) -> dict[str, Any]:
    metadata = _base_sample_metadata(visit, sample, defense, campaign)
    metadata.update(
        capture_completed_at=datetime.now(timezone.utc).isoformat(),
        views=result["views"],
        endpoint_count=result.get("endpoint_count"),
        endpoint_count_valid=result.get("endpoint_count_valid"),
        capture_offloads=result.get("offloads", []),
        udp_payload_ceiling=campaign.udp_payload_ceiling,
        defense_diagnostics=result.get("defense_diagnostics"),
        operationally_valid=result.get("operationally_valid", True),
        content_drift=None,
    )
    return metadata


def _write_failed_sample(
    path: Path,
    visit: dict[str, Any],
    sample: dict[str, Any],
    defense: Defense,
    campaign: Campaign,
) -> None:
    path.mkdir(parents=True, exist_ok=True)
    metadata = _base_sample_metadata(visit, sample, defense, campaign)
    metadata.update(
        views=[],
        failure=sample.get("failure"),
        defense_diagnostics=sample.get("defense_diagnostics"),
        operationally_valid=sample.get("operationally_valid", False),
    )
    atomic_json(path / "sample.json", metadata)


def _base_sample_metadata(
    visit: dict[str, Any],
    sample: dict[str, Any],
    defense: Defense,
    campaign: Campaign,
) -> dict[str, Any]:
    return {
        "sample_id": sample["sample_id"],
        "visit_id": visit["visit_id"],
        "split_group_id": visit["split_group_id"],
        "workload_id": visit["workload_id"],
        "workload_scope": visit["workload_scope"],
        "workload_model": visit["workload_model"],
        "source_manifest_sha256": visit["source_manifest_sha256"],
        "resolved_manifest_sha256": visit["resolved_manifest_sha256"],
        "resource_count": visit["resource_count"],
        "origin_count": visit["origin_count"],
        "expected_endpoint_count": visit["expected_endpoint_count"],
        "class_label": visit["class_label"],
        "role": visit["role"],
        "repetition": visit["repetition"],
        "split": sample["split"],
        "stage": campaign.stage,
        "purpose": campaign.purpose,
        "request_policy": campaign.request_policy,
        "defense": defense.name,
        "runtime_kind": defense.kind,
        "baseline": defense.baseline,
        "seed": sample["seed"],
        "state": sample["state"],
        "attempts": sample["attempts"],
        "primary_view": campaign.primary_view.id,
        "udp_payload_ceiling": campaign.udp_payload_ceiling,
        "eligible": False,
    }


def _compare_visit(
    root: Path,
    samples: list[dict[str, Any]],
    defenses: dict[str, Defense],
    campaign: Campaign,
) -> None:
    baseline = next(sample for sample in samples if defenses[sample["defense"]].baseline)
    reference = response_signature(root / baseline["path"])
    baseline_trace = root / baseline["path"] / "traces/direct-quic.csv"
    baseline_wire_bytes = None
    if baseline_trace.is_file():
        baseline_wire_bytes = sum(
            int(row["length_bytes"]) for row in read_normalized_trace(baseline_trace)
        )
    for sample in samples:
        sample_path = root / sample["path"]
        metadata = load_json(sample_path / "sample.json")
        run_json = sample_path / "neqo" / "run.json"
        run_data = load_json(run_json) if run_json.exists() else {}
        operationally_valid = (
            not padding_event_guard_triggered(run_data)
            if run_json.exists()
            else metadata.get("operationally_valid") is True
        )
        defense_diagnostics = (
            run_data.get("defense_diagnostics")
            if run_json.exists()
            else metadata.get("defense_diagnostics")
        )
        signature = response_signature(sample_path)
        drift = reference is not None and signature is not None and signature != reference
        response_match = (
            metadata.get("state") == "captured"
            and reference is not None
            and signature is not None
            and not drift
        )
        views = metadata.get("views", [])
        primary_valid = any(view.get("primary") and view.get("valid") for view in views)
        metadata.update(
            content_drift=drift,
            response_match=response_match,
            operationally_valid=operationally_valid,
            defense_diagnostics=defense_diagnostics,
            eligible=bool(response_match and primary_valid and operationally_valid),
        )
        for view in views:
            view["eligible"] = bool(response_match and view.get("valid") and operationally_valid)
        if run_json.exists():
            metadata["resolved_defense"] = run_data.get("resolved_configuration")
            metadata["response_signature_sha256"] = (
                stable_digest("responses", json.dumps(signature, sort_keys=True))
                if signature is not None
                else None
            )
        atomic_json(sample_path / "sample.json", metadata)
        fidelity_path, fidelity_eligible = write_fidelity_record(
            sample_path,
            baseline_wire_bytes=baseline_wire_bytes,
        )
        metadata.update(
            fidelity_path=str(fidelity_path.relative_to(sample_path)),
            fidelity_eligible=fidelity_eligible,
        )
        atomic_json(sample_path / "sample.json", metadata)
        sample.update(
            content_drift=drift,
            response_match=response_match,
            operationally_valid=operationally_valid,
            eligible=metadata["eligible"],
            fidelity_eligible=fidelity_eligible,
            fidelity_path=str(fidelity_path.relative_to(sample_path)),
            views={view["id"]: bool(view.get("valid")) for view in views},
        )
