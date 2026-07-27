from __future__ import annotations

import hashlib
import json
import math
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

from .capture import extract_trace, tuple_filter, write_normalized_trace
from .manifest import canonical_bytes, runtime_manifest, validate_manifest
from .util import (
    atomic_json,
    atomic_text,
    load_json,
    response_signature,
    run,
    sha256_bytes,
    sha256_file,
    source_metadata,
    write_checksums,
)

NEQO_CLIENT = os.environ.get("NEQO_QCSD_CLIENT", "/usr/local/bin/neqo-qcsd-client")
CAPTURE_MODES = {"direct", "wireguard"}
STATIC_MODES = {"chaff-only", "chaff-and-shape"}
CAMPAIGN_KEYS = {"name", "seed", "qcsd_profile", "workloads", "defenses", "limits"}
WORKLOAD_KEYS = {"root", "scope", "source", "reviewed", "monitored", "unmonitored"}
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
DEFENSE_KEYS = {"name", "kind", "baseline", "schedule", "mode"}


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
    client_port: int | None = None
    gateway_port: int | None = None
    gateway_address_env: str | None = None

    def as_dict(self, *, resolve_environment: bool = False) -> dict[str, Any]:
        result = {key: value for key, value in asdict(self).items() if value is not None}
        result["kind"] = self.id
        if self.gateway_address_env:
            if resolve_environment:
                result["resolved_gateway_address"] = os.environ.get(
                    self.gateway_address_env
                )
        return result


@dataclass(frozen=True)
class Defense:
    name: str
    kind: str
    baseline: bool
    schedule: str | None = None
    schedule_path: Path | None = None
    schedule_sha256: str | None = None
    mode: str | None = None

    def as_dict(self, *, internal: bool = False) -> dict[str, Any]:
        result = asdict(self)
        result.pop("schedule_path")
        if internal and self.schedule_path:
            result["schedule_path"] = str(self.schedule_path)
        return {key: value for key, value in result.items() if value is not None}


@dataclass(frozen=True)
class Campaign:
    name: str
    path: Path
    seed: int
    qcsd_profile: str
    source: str
    reviewed: bool
    workload_root: Path
    workload_scope: str
    workload_model: str
    workloads: tuple[dict[str, Any], ...]
    defenses: tuple[Defense, ...]
    limits: Limits
    capture: str
    network_condition: str
    outer_only: bool
    views: tuple[CaptureView, ...]
    study_id: str

    @property
    def purpose(self) -> str:
        return "classification" if self.capture == "wireguard" else "diagnostics"

    @property
    def primary_view(self) -> CaptureView:
        return next(view for view in self.views if view.primary)


def slug(value: str) -> str:
    rendered = "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in value
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


def load_campaign(
    path: Path,
    *,
    capture: str,
    outer_only: bool = False,
    network_condition: str | None = None,
) -> Campaign:
    if capture not in CAPTURE_MODES:
        raise ValueError("capture must be direct or wireguard")
    if outer_only and capture != "wireguard":
        raise ValueError("--outer-only requires --capture wireguard")
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
    defenses = _load_defenses(path.parent, source["defenses"])
    limits = _load_limits(source.get("limits", {}), workload_source)
    views = _capture_views(capture, outer_only)
    condition = network_condition or (
        "local-wireguard-gateway" if capture == "wireguard" else "docker-bridge-local"
    )
    if not condition.strip():
        raise ValueError("network condition must not be empty")
    study_material = [
        {
            key: workload[key]
            for key in (
                "workload_id",
                "source_manifest_sha256",
                "class_label",
                "role",
                "visits",
            )
        }
        for workload in workloads
    ]
    study_id = stable_digest(
        "study", json.dumps(study_material, sort_keys=True, separators=(",", ":"))
    )
    return Campaign(
        name=slug(str(source["name"])),
        path=path.resolve(),
        seed=int(source["seed"]),
        qcsd_profile=profile,
        source=workload_source,
        reviewed=reviewed,
        workload_root=workload_root,
        workload_scope=workload_scope,
        workload_model=workload_model,
        workloads=tuple(workloads),
        defenses=defenses,
        limits=limits,
        capture=capture,
        network_condition=condition,
        outer_only=outer_only,
        views=views,
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


def resolve_workload(
    source: dict[str, Any], scope: str
) -> tuple[dict[str, Any], dict[str, Any]]:
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
    if scope == "primary-origin" and (
        len(resolved["resources"]) < 2 or len(origins) != 1
    ):
        raise ValueError(
            "Dconn replay requires at least two resources from the final-page origin"
        )
    if scope == "all-reviewed-origins" and (
        len(resolved["resources"]) < 2 or len(origins) < 2
    ):
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


def _load_defenses(base: Path, raw: Any) -> tuple[Defense, ...]:
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
        kind = str(value.get("kind", "none" if name == "undefended" else name))
        baseline = bool(value.get("baseline", name == "undefended" or kind == "none"))
        if kind.lower() != "static":
            if "schedule" in value or "mode" in value:
                raise ValueError("schedule and mode are only valid for Static")
            defenses.append(Defense(name, kind, baseline))
            continue
        schedule = value.get("schedule")
        mode = str(value.get("mode", ""))
        if not schedule or mode not in STATIC_MODES:
            raise ValueError("Static requires a schedule and a valid mode")
        schedule_path = (base / str(schedule)).resolve()
        if not schedule_path.is_file():
            raise ValueError(f"Static schedule does not exist: {schedule}")
        defenses.append(
            Defense(
                name,
                kind,
                baseline,
                str(schedule),
                schedule_path,
                sha256_file(schedule_path),
                mode,
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
        per_origin_cooldown_seconds=float(
            value.get("per_origin_cooldown_seconds", 30)
        ),
        inter_sample_seconds=float(value.get("inter_sample_seconds", 5)),
        settle_seconds=float(value.get("settle_seconds", 1)),
    )
    if min(
        limits.timeout_seconds,
        limits.max_response_bytes,
        limits.capture_seconds,
        limits.capture_megabytes,
    ) < 1:
        raise ValueError("timeout, response, and capture limits must be positive")
    if not 1 <= limits.max_attempts <= 3:
        raise ValueError("max_attempts must be between one and three")
    if min(
        limits.per_origin_cooldown_seconds,
        limits.inter_sample_seconds,
        limits.settle_seconds,
    ) < 0:
        raise ValueError("delay limits cannot be negative")
    if limits.settle_seconds > 5:
        raise ValueError("settle_seconds must not exceed five")
    if source == "live" and limits.per_origin_cooldown_seconds < 30:
        raise ValueError("live workloads require a 30-second origin cooldown")
    return limits


def _capture_views(capture: str, outer_only: bool) -> tuple[CaptureView, ...]:
    if capture == "direct":
        return (CaptureView("direct-quic", "eth0", "Ethernet", "frame.len", True),)
    views = [
        CaptureView(
            "wireguard-outer",
            "eth0",
            "Ethernet",
            "udp.length",
            True,
            int(os.environ.get("QCSD_WG_CLIENT_PORT", "51821")),
            int(os.environ.get("QCSD_WG_GATEWAY_PORT", "51820")),
            "QCSD_WG_GATEWAY_ADDRESS",
        )
    ]
    if not outer_only:
        views.append(CaptureView("direct-quic", "wg0", "Raw IP", "frame.len", False))
    return tuple(views)


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be an object")
    return dict(value)


def _reject_unknown(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{location} contains unsupported fields: {', '.join(sorted(unknown))}")


def plan_campaign(campaign: Campaign) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    visits: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    for workload in campaign.workloads:
        for repetition in range(workload["visits"]):
            visit_id = stable_digest(
                "visit", campaign.study_id, workload["workload_id"], repetition
            )
            visit_seed = int(stable_digest("seed", campaign.seed, visit_id)[:16], 16)
            visit = {
                "visit_id": visit_id,
                "workload_id": workload["workload_id"],
                "manifest": workload["manifest"],
                "manifest_path": workload["manifest_path"],
                "manifest_sha256": workload["manifest_sha256"],
                "source_manifest_sha256": workload["source_manifest_sha256"],
                "resolved_manifest_sha256": workload["resolved_manifest_sha256"],
                "resolved_manifest": f"resolved-workloads/{workload['workload_id']}.json",
                "workload_scope": campaign.workload_scope,
                "workload_model": workload["workload_model"],
                "resource_count": workload["resource_count"],
                "origin_count": workload["origin_count"],
                "expected_endpoint_count": workload["expected_endpoint_count"],
                "class_label": workload["class_label"],
                "role": workload["role"],
                "repetition": repetition,
                "seed": visit_seed,
                "path": f"{workload['class_label']}/{workload['workload_id']}-visit-{repetition:05d}",
            }
            visits.append(visit)
            for defense in campaign.defenses:
                samples.append(
                    {
                        "sample_id": stable_digest(
                            "sample",
                            visit_id,
                            campaign.workload_scope,
                            campaign.capture,
                            campaign.network_condition,
                            defense.name,
                        ),
                        "visit_id": visit_id,
                        "workload_id": workload["workload_id"],
                        "class_label": workload["class_label"],
                        "role": workload["role"],
                        "repetition": repetition,
                        "defense": defense.name,
                        "runtime_kind": defense.kind,
                        "seed": visit_seed,
                        "path": f"{visit['path']}/{defense.name}",
                        "state": "planned",
                        "attempts": 0,
                        "eligible": False,
                        "views": {view.id: False for view in campaign.views},
                    }
                )
    splits = create_splits(visits, campaign.seed)
    for sample in samples:
        sample["split"] = splits["assignments"][sample["visit_id"]]
    return visits, samples, splits


def create_splits(visits: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    assignments: dict[str, str] = {}
    strata: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for visit in visits:
        label = visit["class_label"] if visit["role"] == "monitored" else "__unmonitored__"
        strata.setdefault((visit["role"], label), []).append(visit)
    for members in strata.values():
        ordered = sorted(
            members, key=lambda visit: stable_digest("split", seed, visit["visit_id"])
        )
        held_out = 0 if len(ordered) < 2 else max(1, math.ceil(len(ordered) * 0.2))
        test_ids = {visit["visit_id"] for visit in ordered[:held_out]}
        for visit in members:
            assignments[visit["visit_id"]] = (
                "test" if visit["visit_id"] in test_ids else "train"
            )
    return {
        "seed": seed,
        "unit": "visit_id",
        "method": "deterministic stratified 80/20 paired split",
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
    capture: str,
    outer_only: bool = False,
    network_condition: str | None = None,
    resume: Path | None = None,
) -> Path:
    """Collect or resume one study through the shared capture pipeline."""

    campaign = load_campaign(
        path,
        capture=capture,
        outer_only=outer_only,
        network_condition=network_condition,
    )
    started = datetime.now(timezone.utc)
    visits, planned_samples, splits = plan_campaign(campaign)
    desired = _campaign_receipt(campaign, visits, started)
    if resume is None:
        root = results_root / started.strftime("%Y%m%dT%H%M%SZ")
        root.mkdir(parents=True, exist_ok=False)
        samples = planned_samples
        atomic_json(root / "splits.json", splits)
    else:
        root = resume.resolve()
        previous = load_json(root / "campaign.json")
        if previous.get("input_digest") != desired["input_digest"]:
            raise ValueError("resume provenance mismatch")
        samples = _resume_samples(planned_samples, _load_sample_index(root))
        desired["campaign"]["started_at"] = previous["campaign"]["started_at"]
        desired["campaign"]["resumed_at"] = started.isoformat()
        desired["environment"] = previous.get("environment", {})
    _materialize_resolved_workloads(root, campaign)
    receipt = desired
    atomic_json(root / "dataset.json", _dataset_card(campaign, receipt, "collecting"))
    _checkpoint(root, receipt, samples)

    defenses = {defense.name: defense for defense in campaign.defenses}
    samples_by_visit = {
        visit["visit_id"]: [
            sample for sample in samples if sample["visit_id"] == visit["visit_id"]
        ]
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
            if sample["state"] == "captured" and _accepted_sample_exists(root, sample):
                continue
            if sample["state"] == "running":
                sample.update(
                    state="interrupted",
                    failure={"stage": "interruption", "message": "stale running state"},
                )
            defense = defenses[sample["defense"]]
            sample_path = root / sample["path"]
            while sample["attempts"] < campaign.limits.max_attempts:
                _respect_origin_cooldown(manifest, campaign, origin_last_run)
                sample.update(state="running", attempts=sample["attempts"] + 1)
                sample.pop("failure", None)
                _checkpoint(root, receipt, samples)
                attempt = sample_path / "attempts" / f"attempt-{sample['attempts']:03d}"
                try:
                    result = _collect_attempt(
                        attempt, manifest_path, defense, sample["seed"], campaign
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
                    _promote_attempt(
                        attempt,
                        sample_path,
                        preserve_diagnostics=bool(result.get("auxiliary_failures")),
                    )
                    sample["state"] = "captured"
                    metadata = _sample_metadata(visit, sample, defense, result, campaign)
                    atomic_json(sample_path / "sample.json", metadata)
                    sample.update(
                        capture_completed_at=metadata["capture_completed_at"],
                        views={view["id"]: view["valid"] for view in result["views"]},
                    )
                    sample.pop("failure", None)
                    receipt["environment"].setdefault(
                        "capture_interfaces", result.get("offloads", [])
                    )
                    break
                sample.update(state="failed", failure=result.get("failure"))
                _checkpoint(root, receipt, samples)
            if sample["state"] != "captured":
                _write_failed_sample(sample_path, visit, sample, defense, campaign)
            _checkpoint(root, receipt, samples)
            if campaign.limits.inter_sample_seconds and position + 1 < len(ordered):
                time.sleep(campaign.limits.inter_sample_seconds)
        _compare_visit(root, visit_samples, defenses, campaign)
        _checkpoint(root, receipt, samples)

    eligible_visits = sum(
        all(sample["eligible"] for sample in members)
        for members in samples_by_visit.values()
    )
    receipt["summary"] = {
        "eligible_visits": eligible_visits,
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

    from .dataset import write_projection
    from .plotting import plot_run
    from .report import create_report

    plot_run(root, policy="aggregate-only" if campaign.capture == "wireguard" else "per-visit")
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
        "seed": campaign.seed,
        "qcsd_profile": campaign.qcsd_profile,
        "capture": {
            "mode": campaign.capture,
            "purpose": campaign.purpose,
            "network_condition": campaign.network_condition,
            "outer_only": campaign.outer_only,
            "primary_view": campaign.primary_view.id,
            "views": [view.as_dict(resolve_environment=True) for view in campaign.views],
        },
        "limits": campaign.limits.as_dict(),
        "workloads": {
            "source": campaign.source,
            "reviewed": campaign.reviewed,
            "root": str(campaign.workload_root),
            "scope": campaign.workload_scope,
            "model": campaign.workload_model,
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
        "response_match",
        "content_drift",
        "views",
    }
    for sample in planned:
        sample.update({key: old[sample["sample_id"]][key] for key in lifecycle if key in old[sample["sample_id"]]})
    return planned


def _dataset_card(
    campaign: Campaign, receipt: dict[str, Any], status: str
) -> dict[str, Any]:
    classification = campaign.purpose == "classification"
    adversary = (
        "passive observer between client and WireGuard gateway"
        if classification else "controlled observer at the container network edge"
    )
    return {
        "title": campaign.name,
        "purpose": campaign.purpose,
        "status": status,
        "data_license": "not-for-release",
        "threat_model": {
            "adversary": adversary,
            "visible_features": ["datagram size", "relative timing", "direction", "load boundary"],
            "excluded_features": [
                "destinations",
                "plaintext",
                "keys",
                "qlogs",
                "Neqo events",
                "response hashes",
                "defense schedules",
            ],
        },
        "observer_definitions": [view.as_dict() for view in campaign.views],
        "primary_observer": campaign.primary_view.id,
        "workloads": _public_workload_summary(receipt["configuration"]["workloads"]),
        "defenses": [{"name": item.name, "baseline": item.baseline} for item in campaign.defenses],
        "split": "one deterministic stratified 80/20 assignment per paired visit",
        "eligibility_rule": "every defense sample has a valid primary view and matches the undefended response",
        "limitations": [
            "test-client workloads model QCSD Dconn/Dmc rather than browser Dfull",
            "local gateway results do not substitute for geographic diversity"
            if classification else "direct captures reveal destination endpoints",
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


def _checkpoint(
    root: Path, receipt: dict[str, Any], samples: list[dict[str, Any]]
) -> None:
    atomic_json(root / "campaign.json", receipt)
    atomic_text(
        root / "samples.jsonl",
        "".join(json.dumps(sample, sort_keys=True) + "\n" for sample in samples),
    )


def _load_sample_index(root: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (root / "samples.jsonl").read_text().splitlines()]


def _accepted_sample_exists(root: Path, sample: dict[str, Any]) -> bool:
    sample_path = root / sample["path"]
    metadata_path = sample_path / "sample.json"
    if not metadata_path.is_file():
        return False
    metadata = load_json(metadata_path)
    if metadata.get("sample_id") != sample["sample_id"] or metadata.get("state") != "captured":
        return False
    primary_valid = False
    for view in metadata.get("views", []):
        primary_valid |= bool(view.get("primary") and view.get("valid"))
        if not view.get("valid"):
            continue
        capture = sample_path / view["capture_path"]
        trace = sample_path / view["trace_path"]
        if not capture.is_file() or not trace.is_file():
            return False
        if sha256_file(capture) != view.get("capture_sha256"):
            return False
        if sha256_file(trace) != view.get("trace_sha256"):
            return False
    return primary_valid


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


def _view_bpf(view: CaptureView) -> str:
    if view.id == "direct-quic":
        return "udp"
    address = os.environ.get(view.gateway_address_env or "")
    if not address:
        raise ValueError("missing WireGuard gateway address")
    return (
        f"host {address} and udp and ((src port {view.client_port} and dst port {view.gateway_port}) "
        f"or (src port {view.gateway_port} and dst port {view.client_port}))"
    )


def _offload_metadata(interface: str) -> dict[str, Any]:
    before = run(["ethtool", "-k", interface], check=False)
    changes = {
        feature: run(["ethtool", "-K", interface, feature, "off"], check=False).returncode
        for feature in ("gro", "gso", "tso")
    }
    after = run(["ethtool", "-k", interface], check=False)
    return {
        "interface": interface,
        "requested": {"gro": "off", "gso": "off", "tso": "off"},
        "change_returncodes": changes,
        "before_sha256": stable_digest(before.stdout),
        "after_sha256": stable_digest(after.stdout),
    }


def _collect_attempt(
    attempt: Path,
    manifest: Path,
    defense: Defense,
    seed: int,
    campaign: Campaign,
) -> dict[str, Any]:
    attempt.mkdir(parents=True, exist_ok=False)
    diagnostics = attempt / "diagnostics"
    captures = attempt / "captures"
    traces = attempt / "traces"
    neqo = attempt / "neqo"
    for directory in (diagnostics, captures, traces):
        directory.mkdir()
    offloads = [
        _offload_metadata(interface)
        for interface in sorted({view.interface for view in campaign.views})
    ]
    processes: list[tuple[CaptureView, subprocess.Popen[str], Any, Path]] = []
    try:
        for view in campaign.views:
            raw = diagnostics / f"{view.id}-raw.pcapng"
            handle = (diagnostics / f"dumpcap-{view.id}.log").open("w", encoding="utf-8")
            process = subprocess.Popen(
                [
                    "dumpcap",
                    "-q",
                    "-i",
                    view.interface,
                    "-f",
                    _view_bpf(view),
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
            processes.append((view, process, handle, raw))
        _wait_for_capture_start(processes)
        client = run(
            _client_command(manifest, defense, seed, campaign, neqo),
            log=diagnostics / "neqo-client.log",
            check=False,
        )
        if campaign.limits.settle_seconds:
            time.sleep(campaign.limits.settle_seconds)
    finally:
        for _view, process, _handle, _raw in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
        for _view, process, handle, _raw in processes:
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
    expected_endpoint_count = len(_manifest_origins(load_json(manifest)))
    endpoint_count_valid = len(endpoints) == expected_endpoint_count
    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for view, process, _handle, raw in processes:
        output = captures / f"{view.id}.pcapng"
        display_filter = tuple_filter(endpoints) if view.id == "direct-quic" and endpoints else "udp"
        filtered = run(
            ["tshark", "-r", str(raw), "-Y", display_filter, "-w", str(output)],
            log=diagnostics / f"filter-{view.id}.log",
            check=False,
        )
        capinfos = run(["capinfos", "-E", "-c", "-s", str(output)], check=False)
        limit = campaign.limits.capture_megabytes * 1024 * 1024
        truncated = raw.exists() and raw.stat().st_size >= int(limit * 0.99)
        try:
            trace = extract_trace(
                output,
                endpoints,
                kind=view.id,
                length_basis=view.length_basis,
                client_port=view.client_port,
            )
        except (KeyError, RuntimeError, ValueError) as error:
            trace = []
            failures.append({"view": view.id, "primary": view.primary, "reason": str(error)})
        trace_path = traces / f"{view.id}.csv"
        if trace:
            write_normalized_trace(trace_path, trace)
        link_valid = view.link_type.lower() in capinfos.stdout.lower()
        valid = (
            process.returncode in {0, 2}
            and filtered.returncode == 0
            and capinfos.returncode == 0
            and output.is_file()
            and output.stat().st_size > 0
            and bool(trace)
            and not truncated
            and link_valid
        )
        if view.primary and not valid:
            failures.append(
                {
                    "view": view.id,
                    "primary": True,
                    "reason": "capture validation failed",
                    "dumpcap_returncode": process.returncode,
                    "filter_returncode": filtered.returncode,
                    "capinfos_returncode": capinfos.returncode,
                    "truncated": truncated,
                    "link_type_valid": link_valid,
                }
            )
        records.append(
            {
                **view.as_dict(resolve_environment=True),
                "flow_filter": _view_bpf(view),
                "direction_rule": (
                    f"source UDP port {view.client_port} is outgoing"
                    if view.id == "wireguard-outer"
                    else "Neqo local endpoint tuple is outgoing"
                ),
                "capture_boundary": "before Neqo through defense tail and settle interval",
                "packet_count": len(trace),
                "truncated": truncated,
                "capture_path": f"captures/{view.id}.pcapng",
                "trace_path": f"traces/{view.id}.csv",
                "capture_sha256": sha256_file(output) if output.exists() else None,
                "trace_sha256": sha256_file(trace_path) if trace_path.exists() else None,
                "pcapng_bytes": output.stat().st_size if output.exists() else 0,
                "valid": valid,
            }
        )
    primary = next(record for record in records if record["primary"])
    auxiliary_failures = [
        {
            "view": record["id"],
            "reason": "capture validation failed",
            "details": [item for item in failures if item.get("view") == record["id"]],
        }
        for record in records
        if not record["primary"] and not record["valid"]
    ]
    success = (
        client.returncode == 0
        and runner_complete
        and endpoint_count_valid
        and primary["valid"]
    )
    result = {
        "success": success,
        "runner_returncode": client.returncode,
        "runner_completion_status": completion_status,
        "runner_complete": runner_complete,
        "endpoint_count": len(endpoints),
        "expected_endpoint_count": expected_endpoint_count,
        "endpoint_count_valid": endpoint_count_valid,
        "views": records,
        "offloads": offloads,
        "auxiliary_failures": auxiliary_failures,
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


def _runner_result_complete(run_data: dict[str, Any]) -> bool:
    responses = run_data.get("responses", [])
    return (
        run_data.get("completion_status") == "complete"
        and bool(responses)
        and all(
            response.get("complete") is True
            and response.get("outcome") == "succeeded"
            for response in responses
        )
    )


def _wait_for_capture_start(
    processes: list[tuple[CaptureView, subprocess.Popen[str], Any, Path]],
    *,
    timeout_seconds: float = 5,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    pending = {view.id for view, _process, _handle, _raw in processes}
    while pending and time.monotonic() < deadline:
        for view, process, handle, _raw in processes:
            if view.id not in pending:
                continue
            if process.poll() is not None:
                raise RuntimeError(f"dumpcap for {view.id} exited before capture start")
            log = Path(handle.name)
            if log.is_file() and "File:" in log.read_text(errors="replace"):
                pending.remove(view.id)
        if pending:
            time.sleep(0.02)
    if pending:
        raise RuntimeError(f"dumpcap did not become ready for: {', '.join(sorted(pending))}")
    time.sleep(1)


def _client_command(
    manifest: Path,
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
    ]
    if not defense.baseline:
        command += ["--chaff-manifest", str(manifest)]
    command += ["--profile", campaign.qcsd_profile, "--defense", defense.kind]
    if defense.kind.lower() == "static":
        command += ["--schedule", str(defense.schedule_path), "--static-mode", str(defense.mode)]
    return command


def _promote_attempt(
    attempt: Path, sample: Path, *, preserve_diagnostics: bool = False
) -> None:
    for name in ("captures", "traces", "neqo"):
        destination = sample / name
        if destination.exists():
            raise ValueError(f"accepted artifact already exists: {destination}")
        shutil.move(str(attempt / name), str(destination))
    diagnostics = attempt / "diagnostics"
    if diagnostics.exists() and not preserve_diagnostics:
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
        auxiliary_failures=result.get("auxiliary_failures", []),
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
    metadata.update(views=[], failure=sample.get("failure"))
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
        "purpose": campaign.purpose,
        "defense": defense.name,
        "runtime_kind": defense.kind,
        "baseline": defense.baseline,
        "seed": sample["seed"],
        "state": sample["state"],
        "attempts": sample["attempts"],
        "primary_view": campaign.primary_view.id,
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
    for sample in samples:
        sample_path = root / sample["path"]
        metadata = load_json(sample_path / "sample.json")
        signature = response_signature(sample_path)
        drift = reference is not None and signature is not None and signature != reference
        response_match = (
            metadata.get("state") == "captured"
            and reference is not None
            and signature is not None
            and not drift
        )
        views = metadata.get("views", [])
        primary_valid = any(
            view.get("primary") and view.get("valid") for view in views
        )
        metadata.update(
            content_drift=drift,
            response_match=response_match,
            eligible=bool(response_match and primary_valid),
        )
        for view in views:
            view["eligible"] = bool(response_match and view.get("valid"))
        run_json = sample_path / "neqo" / "run.json"
        if run_json.exists():
            run_data = load_json(run_json)
            metadata["resolved_defense"] = run_data.get("resolved_configuration")
            metadata["response_signature_sha256"] = (
                stable_digest("responses", json.dumps(signature, sort_keys=True))
                if signature is not None
                else None
            )
        atomic_json(sample_path / "sample.json", metadata)
        sample.update(
            content_drift=drift,
            response_match=response_match,
            eligible=metadata["eligible"],
            views={view["id"]: bool(view.get("valid")) for view in views},
        )
