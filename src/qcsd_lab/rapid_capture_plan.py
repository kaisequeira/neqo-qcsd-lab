"""Small, independent capture lanes for the prospective rapid study.

The caller must first validate the rapid profile, candidate terminals, frozen
workloads and response-qualification sets.  A lane result gets credit only
after the ordinary deep verifier and the checks here both pass.  The lane
layout itself grants no site admission or capture authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from .rapid_study_profile import (
    BUFLO_PARAMETERS_SHA256,
    COHORT_RECEIPT_TYPE,
    CS_BUFLO_PARAMETERS_SHA256,
    FALLBACK_CATALOGUE_SHA256,
    FROZEN_V5_PROFILE_SHA256,
    PROFILE_RECEIPT_TYPE,
    RESEARCH_PROFILE_SHA256,
    SOURCE_SHA256,
    V5_COHORT_RECEIPT_TYPE,
    V5_PROFILE_RECEIPT_TYPE,
    validate_cohort_receipt,
    validate_profile_receipt,
    validate_v5_cohort_receipt,
    validate_v5_profile_receipt,
)
from .util import durable_create
from .verification import verify_result

MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
SHARD_SIZE = 5
FINAL_BLOCKS = 16
FINAL_VISITS_PER_BLOCK = 4
FINAL_CLASS_COUNT = 50
FINAL_SAMPLE_TARGET = 16_000
MAX_LANE_GENERATION = 99
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
CORPUS_TYPE = "qcsd-rapid-v4-formal-corpus-manifest"
V5_CORPUS_TYPE = "qcsd-rapid-v5-formal-corpus-manifest"
STUDY_VERSIONS = (4, 5, 6)
CAPTURE_LIMITS = {
    "timeout_seconds": 120,
    "max_response_bytes": 1_048_576,
    "capture_seconds": 180,
    "capture_megabytes": 64,
    "max_attempts": 3,
    "per_origin_cooldown_seconds": 0,
    "settle_seconds": 0,
}
# The fresh v5 baseline diagnostic lost its last burst with zero settling.
# Retain historical v4 rendering while allowing the recorder to flush in v5.
V5_CAPTURE_LIMITS = {**CAPTURE_LIMITS, "settle_seconds": 2}
PARAMETER_REFERENCES = {
    "buflo": "../defense-params/buflo-live.json",
    "cs-buflo": "../defense-params/cs-buflo-ctsp-live.json",
}


@dataclass(frozen=True)
class Site:
    candidate_id: str
    workload_id: str
    workload_sha256: str
    primary_origin: str
    qualification_set: str
    qualification_set_manifest_sha256: str | None = None


@dataclass(frozen=True)
class Lane:
    role: str
    block: int
    shard: int
    mode: str
    campaign_name: str
    workload_ids: tuple[str, ...]
    visits_per_workload: int
    qualification_set: str | None
    generation: int = 1
    study_version: int = 4

    @property
    def sample_count(self) -> int:
        return len(self.workload_ids) * self.visits_per_workload

    @property
    def logical_name(self) -> str:
        return _campaign_name(
            self.role, self.block, self.shard, self.mode, 1, self.study_version
        )


@dataclass(frozen=True)
class FrozenBindings:
    """Study-wide identities; execution source belongs to each lane receipt."""

    profile_receipt: Path
    profile_sha256: str
    cohort_receipt: Path
    cohort_sha256: str
    study_version: int = 4
    selection_amendment_receipt: Path | None = None
    selection_amendment_sha256: str | None = None

    def digests(self) -> dict[str, str]:
        digests = {
            "profile_sha256": self.profile_sha256,
            "cohort_sha256": self.cohort_sha256,
        }
        if self.study_version == 5:
            digests["study_version"] = "v5"
        if self.selection_amendment_sha256 is not None:
            digests["selection_amendment_sha256"] = self.selection_amendment_sha256
        return digests


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _campaign_name(
    role: str, block: int, shard: int, mode: str, generation: int,
    study_version: int = 4,
) -> str:
    if type(generation) is not int or not 1 <= generation <= MAX_LANE_GENERATION:
        raise ValueError("rapid lane generation is outside 1..99")
    if type(study_version) is not int or study_version not in STUDY_VERSIONS:
        raise ValueError("rapid lane study version is unregistered")
    base = (
        f"rapid-curated-tranco50-v{study_version}-{role}-b{block:02d}-"
        f"s{shard:02d}-{mode}-1200"
    )
    return base if generation == 1 else f"{base}-g{generation:02d}"


def successor_lane(lane: Lane, generation: int) -> Lane:
    """Name a new create-only campaign for one repaired logical lane."""
    from .rapid_slot_chunks import ChunkLane, successor
    if isinstance(lane, ChunkLane):
        return successor(lane, generation)

    if type(generation) is not int or generation <= lane.generation:
        raise ValueError("rapid successor generation must advance")
    return replace(
        lane,
        generation=generation,
        campaign_name=_campaign_name(
            lane.role, lane.block, lane.shard, lane.mode, generation,
            lane.study_version,
        ),
    )


def epoch_campaign_name(lane: Lane, epoch: int) -> str:
    """Separate a prospective block epoch from unchanged-input lane retries."""
    if type(epoch) is not int or not 1 <= epoch <= 9999 or lane.study_version != 5:
        raise ValueError("rapid block epoch is outside the registered v5 namespace")
    return _campaign_name(
        lane.role, lane.block, lane.shard, lane.mode, lane.generation, 5,
    ) + f"-e{epoch:04d}"


def _check_sites(sites: Sequence[Site], *, final: bool, study_version: int = 5) -> tuple[Site, ...]:
    from .rapid_undefended_capture import OrdinarySite, check_sites
    if any(isinstance(site, OrdinarySite) for site in sites):
        return check_sites(sites, final=final, study_version=study_version)
    selected = tuple(sites)
    expected = FINAL_CLASS_COUNT if final else 10
    rolling = study_version == 6
    if rolling and (not final or not 1 <= len(selected) <= SHARD_SIZE):
        raise ValueError("rolling formal batches require one to five sites")
    if not rolling and len(selected) != expected:
        raise ValueError(f"rapid {'final' if final else 'shakedown'} plan needs {expected} sites")
    if any(not isinstance(site, Site) for site in selected):
        raise ValueError("rapid plan site identity is invalid")
    for site in selected:
        try:
            origin = urlsplit(site.primary_origin)
            canonical_origin = (
                origin.scheme == "https"
                and origin.hostname is not None
                and origin.netloc == origin.hostname
                and not origin.path
                and not origin.query
                and not origin.fragment
                and origin.username is None
                and origin.password is None
            )
        except (TypeError, ValueError):
            canonical_origin = False
        if (
            not isinstance(site.candidate_id, str)
            or IDENTIFIER_RE.fullmatch(site.candidate_id) is None
            or not isinstance(site.workload_id, str)
            or IDENTIFIER_RE.fullmatch(site.workload_id) is None
            or not isinstance(site.workload_sha256, str)
            or SHA256_RE.fullmatch(site.workload_sha256) is None
            or not canonical_origin
            or not isinstance(site.qualification_set, str)
            or IDENTIFIER_RE.fullmatch(site.qualification_set) is None
            or (
                site.qualification_set_manifest_sha256 is not None
                and (
                    not isinstance(site.qualification_set_manifest_sha256, str)
                    or SHA256_RE.fullmatch(site.qualification_set_manifest_sha256) is None
                )
            )
        ):
            raise ValueError("rapid plan site identity is invalid")
    for field in ("candidate_id", "workload_id", "primary_origin"):
        values = [getattr(site, field) for site in selected]
        if len(values) != len(set(values)):
            raise ValueError(f"rapid plan repeats a {field}")
    for offset in range(0, len(selected), SHARD_SIZE):
        shard = selected[offset:offset + SHARD_SIZE]
        if len({site.qualification_set for site in shard}) != 1:
            raise ValueError("one five-site shard must share one qualification set")
        if len({site.qualification_set_manifest_sha256 for site in shard}) != 1:
            raise ValueError("one five-site shard must share one qualification manifest")
        if len({site.primary_origin for site in shard}) != (len(shard) if rolling else SHARD_SIZE):
            raise ValueError("one qualification shard needs five distinct primary origins")
    return selected


def plan_lanes(
    sites: Sequence[Site], *, final: bool, study_version: int = 4, rolling_batch: int | None = None
) -> tuple[Lane, ...]:
    """Plan 50 diagnostic or 16,000 formal slots with per-defence recovery."""

    from .rapid_undefended_capture import OrdinarySite, plan_lanes as ordinary_lanes
    if any(isinstance(site, OrdinarySite) for site in sites):
        return ordinary_lanes(sites, final=final, study_version=study_version, rolling_batch=rolling_batch)
    selected = _check_sites(sites, final=final, study_version=study_version)
    if type(study_version) is not int or study_version not in STUDY_VERSIONS:
        raise ValueError("rapid lane study version is unregistered")
    if study_version in {5, 6} and any(
        site.qualification_set_manifest_sha256 is None for site in selected
    ):
        raise ValueError("rapid v5 sites require qualification manifest digests")
    if study_version == 6:
        if type(rolling_batch) is not int or not 1 <= rolling_batch <= FINAL_CLASS_COUNT:
            raise ValueError("rolling plan needs its immutable enrollment batch ordinal")
    elif rolling_batch is not None:
        raise ValueError("historical plans cannot carry rolling enrollment")
    blocks = FINAL_BLOCKS if final else 1
    visits = FINAL_VISITS_PER_BLOCK if final else 1
    role = "formal" if final else "diagnostic"
    lanes: list[Lane] = []
    for block in range(1, blocks + 1):
        for offset in range(0, len(selected), SHARD_SIZE):
            shard = selected[offset:offset + SHARD_SIZE]
            shard_number = rolling_batch if study_version == 6 else offset // SHARD_SIZE + 1
            for mode in MODES:
                lanes.append(Lane(
                    role=role,
                    block=block,
                    shard=shard_number,
                    mode=mode,
                    campaign_name=_campaign_name(
                        role, block, shard_number, mode, 1, study_version
                    ),
                    workload_ids=tuple(site.workload_id for site in shard),
                    visits_per_workload=visits,
                    qualification_set=(
                        None if mode == "undefended" else shard[0].qualification_set
                    ),
                    study_version=study_version,
                ))
    expected = len(selected) * len(MODES) * 64 if study_version == 6 else FINAL_SAMPLE_TARGET if final else 50
    if sum(lane.sample_count for lane in lanes) != expected:
        raise AssertionError("rapid lane sample arithmetic changed")
    return tuple(lanes)


def _checked_file(path: Path, digest: str, label: str) -> bytes:
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} SHA-256 is invalid")
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    content = path.read_bytes()
    if _sha(content) != digest:
        raise ValueError(f"{label} bytes differ from their frozen SHA-256")
    return content


def _check_bindings(bindings: FrozenBindings) -> None:
    if not isinstance(bindings, FrozenBindings):
        raise ValueError("rapid plan needs frozen profile and cohort bindings")
    if type(bindings.study_version) is not int or bindings.study_version not in STUDY_VERSIONS:
        raise ValueError("rapid plan study version is unregistered")
    if bindings.study_version == 6:
        raise ValueError("rolling v6 authority uses its immutable enrollment policy, not a historical final cohort")
    if bindings.study_version == 5 and bindings.profile_sha256 != FROZEN_V5_PROFILE_SHA256:
        raise ValueError("rapid v5 profile differs from the frozen receipt")
    amended = bindings.selection_amendment_receipt is not None
    if amended != (bindings.selection_amendment_sha256 is not None) or (
        amended and bindings.study_version != 5
    ):
        raise ValueError("selection amendment needs paired v5 receipt and SHA-256")
    if amended:
        from .rapid_selection_amendment import validate_selection_amendment
        amendment = _receipt_json(
            bindings.selection_amendment_receipt, bindings.selection_amendment_sha256,
            "rapid selection amendment",
        )
        validate_selection_amendment(amendment, parent_profile_sha256=bindings.profile_sha256)
    for path, digest, label in (
        (bindings.profile_receipt, bindings.profile_sha256, "rapid profile receipt"),
        (bindings.cohort_receipt, bindings.cohort_sha256, "rapid cohort receipt"),
    ):
        _checked_file(path, digest, label)
    profile = _receipt_json(
        bindings.profile_receipt, bindings.profile_sha256, "rapid profile receipt"
    )
    cohort = _receipt_json(
        bindings.cohort_receipt, bindings.cohort_sha256, "rapid cohort receipt"
    )
    expected_profile_type = (
        V5_PROFILE_RECEIPT_TYPE if bindings.study_version == 5 else PROFILE_RECEIPT_TYPE
    )
    expected_cohort_type = (
        V5_COHORT_RECEIPT_TYPE if bindings.study_version == 5 else COHORT_RECEIPT_TYPE
    )
    if amended:
        from .rapid_selection_amendment import AMENDED_COHORT_RECEIPT_TYPE
        expected_cohort_type = AMENDED_COHORT_RECEIPT_TYPE
    if (
        type(profile.get("schema_version")) is not int
        or profile["schema_version"] != bindings.study_version
        or profile.get("receipt_type") != expected_profile_type
        or type(cohort.get("schema_version")) is not int
        or cohort["schema_version"] != bindings.study_version
        or cohort.get("receipt_type") != expected_cohort_type
        or not isinstance(cohort.get("payload"), Mapping)
        or cohort["payload"].get("profile_receipt_sha256") != bindings.profile_sha256
        or (amended and cohort["payload"].get("selection_amendment_sha256")
            != bindings.selection_amendment_sha256)
    ):
        raise ValueError("rapid profile and cohort study identities differ")


def _check_workload_files(sites: Sequence[Site], workload_root: Path) -> None:
    root = Path(workload_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("rapid workload root is not a regular directory")
    for site in sites:
        _checked_file(
            root / f"{site.workload_id}.json",
            site.workload_sha256,
            f"rapid workload {site.workload_id}",
        )


def render_lane_campaign(lane: Lane, sites: Sequence[Site], *, static_capture_limits: Mapping[str, Any] | None = None,
                         buflo_duration_policy: str | None = None,
                         application_body_identity_policy: str | None = None,
                         qualification_delivery_compatibility: Mapping[str, str] | None = None,
                         tamaraw_configuration_policy: str | None = None) -> bytes:
    """Render one deterministic schema-one campaign without granting authority."""

    if lane.role not in {"formal", "diagnostic"}:
        raise ValueError("rapid lane role is unregistered")
    from .rapid_slot_chunks import ChunkLane, render
    if isinstance(lane, ChunkLane):
        return render(lane, sites, static_capture_limits=static_capture_limits,
            buflo_duration_policy=buflo_duration_policy,
            application_body_identity_policy=application_body_identity_policy,
            qualification_delivery_compatibility=qualification_delivery_compatibility,
            tamaraw_configuration_policy=tamaraw_configuration_policy)
    from .rapid_undefended_capture import OrdinarySite
    ordinary_only = any(isinstance(site, OrdinarySite) for site in sites)
    if ordinary_only and (lane.mode != "undefended" or lane.qualification_set is not None
            or qualification_delivery_compatibility is not None or buflo_duration_policy is not None):
        raise ValueError("ordinary-only sites cannot authorize padding or amended settings")
    selected = _check_sites(sites, final=lane.role == "formal", study_version=lane.study_version)
    if not ordinary_only and lane.study_version in {5, 6} and any(
        site.qualification_set_manifest_sha256 is None for site in selected
    ):
        raise ValueError("rapid v5 sites require qualification manifest digests")
    if (
        lane.mode not in MODES
        or type(lane.block) is not int
        or not 1 <= lane.block <= (FINAL_BLOCKS if lane.role == "formal" else 1)
        or type(lane.shard) is not int
        or not 1 <= lane.shard <= (FINAL_CLASS_COUNT if lane.study_version == 6 else len(selected) // SHARD_SIZE)
    ):
        raise ValueError("rapid lane is outside the registered grid")
    shard = selected if lane.study_version == 6 else selected[(lane.shard - 1) * SHARD_SIZE:lane.shard * SHARD_SIZE]
    expected = Lane(
        role=lane.role,
        block=lane.block,
        shard=lane.shard,
        mode=lane.mode,
        campaign_name=_campaign_name(
            lane.role, lane.block, lane.shard, lane.mode, lane.generation,
            lane.study_version,
        ),
        workload_ids=tuple(site.workload_id for site in shard),
        visits_per_workload=FINAL_VISITS_PER_BLOCK if lane.role == "formal" else 1,
        qualification_set=(
            None if lane.mode == "undefended" else shard[0].qualification_set
        ),
        generation=lane.generation,
        study_version=lane.study_version,
    )
    if expected != lane:
        raise ValueError("rapid lane differs from the frozen 50-site grid")
    defense: str | dict[str, str]
    if lane.mode in PARAMETER_REFERENCES:
        defense = {
            "name": lane.mode,
            "kind": lane.mode.replace("-", "_"),
            "parameters": PARAMETER_REFERENCES[lane.mode],
        }
    else:
        defense = lane.mode
    document: dict[str, Any] = {
        "schema": 1,
        "name": lane.campaign_name,
        "purpose": "evaluation" if lane.role == "formal" else "smoke",
        "seed": int(_sha(lane.campaign_name.encode("ascii"))[:16], 16),
        "profile": "research-1200",
        "workloads": {item: lane.visits_per_workload for item in lane.workload_ids},
        "request_policies": ["as-defined"],
        "defenses": [defense],
        "limits": dict(V5_CAPTURE_LIMITS if lane.study_version in {5, 6} else CAPTURE_LIMITS),
    }
    if static_capture_limits is not None:
        from .supplied_static_admission import capture_limits
        if (lane.study_version != 6 or lane.role != "formal"
            or not isinstance(static_capture_limits, Mapping)
            or dict(static_capture_limits) != capture_limits(static_capture_limits.get("max_response_bytes"),
                                                             static_capture_limits.get("capture_megabytes"))):
            raise ValueError("static capture may change only its declared response/recording budgets")
        document["limits"] = dict(static_capture_limits)
    if application_body_identity_policy is not None:
        from .application_response_policy import validate_application_body_identity_policy
        if lane.study_version != 6 or lane.role != "formal" or static_capture_limits is None:
            raise ValueError("application body policy requires its prospective full-graph formal setting")
        document["application_body_identity_policy"] = validate_application_body_identity_policy(application_body_identity_policy)
    if qualification_delivery_compatibility is not None:
        from .qualification_control_authority import validate
        validate(qualification_delivery_compatibility, body_policy=application_body_identity_policy)
        document["qualification_delivery_compatibility"] = dict(qualification_delivery_compatibility)
    if tamaraw_configuration_policy is not None:
        from .tamaraw_fixed_configuration import validate_policy, FIELD
        from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
        if (lane.mode != "tamaraw" or lane.study_version != 6 or lane.role != "formal"
            or static_capture_limits is None or qualification_delivery_compatibility is not None
            or application_body_identity_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):
            raise ValueError("fixed Tamaraw configuration requires its own complete-graph serial setting")
        document[FIELD] = validate_policy(tamaraw_configuration_policy)
    if buflo_duration_policy is not None:
        from .buflo_duration_budget import POLICY, PARAMETER_PATH, capture_limits
        if (type(buflo_duration_policy) is not str or buflo_duration_policy != POLICY
            or lane.study_version != 6 or lane.role != "formal" or static_capture_limits is None):
            raise ValueError("BuFLO200 campaign requires its prospective static formal contract")
        if lane.mode == "buflo":
            document["defenses"][0]["parameters"] = "../defense-params/" + Path(PARAMETER_PATH).name
        document["limits"] = capture_limits(lane.mode, document["limits"], policy=buflo_duration_policy)
    if lane.qualification_set is not None:
        document["chaff_qualification_set"] = lane.qualification_set
    return yaml.safe_dump(document, sort_keys=False, width=100).encode("utf-8")


def materialize_lane_campaigns(
    campaign_dir: Path,
    sites: Sequence[Site],
    *,
    final: bool,
    bindings: FrozenBindings,
    workload_root: Path,
) -> dict[str, str]:
    """Publish all lane YAML files create-only after checking frozen input bytes.

    The returned hashes describe campaign documents, not admission or capture
    authority. A later corpus verifier must reopen the cohort and every result.
    """

    _check_bindings(bindings)
    selected = _check_sites(sites, final=final)
    if bindings.study_version == 5 and any(
        site.qualification_set_manifest_sha256 is None for site in selected
    ):
        raise ValueError("rapid v5 sites require qualification manifest digests")
    _check_workload_files(selected, workload_root)
    destination = Path(campaign_dir)
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("rapid campaign directory is not a regular directory")
    rendered = {
        lane.campaign_name: render_lane_campaign(lane, selected)
        for lane in plan_lanes(
            selected, final=final, study_version=bindings.study_version
        )
    }
    for name in rendered:
        path = destination / f"{name}.yml"
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"rapid campaign already exists: {path}")
    for name, content in rendered.items():
        durable_create(destination / f"{name}.yml", content)
    return {name: _sha(content) for name, content in rendered.items()}


def materialize_successor_campaign(
    campaign_dir: Path,
    sites: Sequence[Site],
    lane: Lane,
    *,
    bindings: FrozenBindings,
    workload_root: Path,
) -> str:
    """Publish one repaired lane under a fresh generation, retaining predecessors."""

    if lane.generation <= 1:
        raise ValueError("rapid successor campaign needs generation two or later")
    _check_bindings(bindings)
    if lane.study_version != bindings.study_version:
        raise ValueError("rapid successor campaign differs from frozen study version")
    selected = _check_sites(sites, final=lane.role == "formal")
    _check_workload_files(selected, workload_root)
    destination = Path(campaign_dir)
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("rapid campaign directory is not a regular directory")
    predecessor = replace(
        lane,
        generation=lane.generation - 1,
        campaign_name=_campaign_name(
            lane.role, lane.block, lane.shard, lane.mode, lane.generation - 1,
            lane.study_version,
        ),
    )
    predecessor_bytes = render_lane_campaign(predecessor, selected)
    _checked_file(
        destination / f"{predecessor.campaign_name}.yml",
        _sha(predecessor_bytes), "rapid predecessor campaign",
    )
    content = render_lane_campaign(lane, selected)
    path = destination / f"{lane.campaign_name}.yml"
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"rapid successor campaign already exists: {path}")
    durable_create(path, content)
    return _sha(content)


def verify_lane_result(
    result_root: Path,
    lane: Lane,
    *,
    collection_image_digest: str,
    lab_commit: str,
    campaign_sha256: str,
    workload_sha256s: Mapping[str, str],
    qualification_set_manifest_sha256: str | None = None,
    block_epoch: int | None = None,
    collection_runtime_epoch: int | None = None,
) -> dict[str, Any]:
    """Deep-verify an exact lane result and reject sealed incomplete runs.

    A caller must bind the returned result seal to a prospective plan receipt
    and ensure that its launch-intent/source-overlay record is also verified.
    """

    if collection_runtime_epoch is not None:
        if (type(collection_runtime_epoch) is not int or not 2 <= collection_runtime_epoch <= 9999
            or block_epoch is not None or lane.role != "diagnostic" or lane.study_version != 5
            or lane.generation != 1 or len(lane.workload_ids) != 5 or lane.visits_per_workload != 1
            or type(lane.block) is not int or not 1 <= lane.block <= FINAL_BLOCKS
            or type(lane.shard) is not int or not 1 <= lane.shard <= FINAL_CLASS_COUNT // SHARD_SIZE
            or lane.mode not in MODES or (lane.qualification_set is None) != (lane.mode == "undefended")):
            raise ValueError("runtime canary changes its zero-credit five-site diagnostic contract")
        expected_name = (f"rapid-curated-tranco50-v2-diagnostic-runtime-e{collection_runtime_epoch:04d}"
                         f"-b{lane.block:02d}-s{lane.shard:02d}-{lane.mode}")
    else:
        from .rapid_slot_chunks import ChunkLane, checked_lane, name
        if isinstance(lane, ChunkLane):
            checked_lane(asdict(lane))
            if block_epoch is not None:
                raise ValueError("slot chunks cannot claim historical epoch naming")
            expected_name = name(lane, lane.generation)
        else:
            expected_name = (
            epoch_campaign_name(lane, block_epoch) if block_epoch is not None
            else _campaign_name(lane.role, lane.block, lane.shard, lane.mode,
                                lane.generation, lane.study_version)
            )
    if lane.role not in {"formal", "diagnostic"} or lane.campaign_name != expected_name:
        raise ValueError("rapid lane role and campaign identity differ")

    if IMAGE_RE.fullmatch(collection_image_digest) is None:
        raise ValueError("rapid lane collection image digest is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", lab_commit) is None:
        raise ValueError("rapid lane base Lab commit is invalid")
    if SHA256_RE.fullmatch(campaign_sha256) is None:
        raise ValueError("rapid lane campaign hash is invalid")
    if set(workload_sha256s) != set(lane.workload_ids) or any(
        SHA256_RE.fullmatch(value) is None for value in workload_sha256s.values()
    ):
        raise ValueError("rapid lane workload hash map is incomplete")
    if qualification_set_manifest_sha256 is not None and (
        lane.qualification_set is None
        or not isinstance(qualification_set_manifest_sha256, str)
        or SHA256_RE.fullmatch(qualification_set_manifest_sha256) is None
    ):
        raise ValueError("rapid lane qualification manifest binding is invalid")
    if lane.study_version in {5, 6} and lane.qualification_set is not None and (
        qualification_set_manifest_sha256 is None
    ):
        raise ValueError("rapid v5 defended lane needs a qualification manifest digest")

    result = verify_result(result_root)
    experiment = result.experiment
    summary = experiment.get("summary")
    configuration = experiment.get("configuration")
    source = experiment.get("source")
    if (
        experiment.get("status") != "complete"
        or experiment.get("name") != lane.campaign_name
        or experiment.get("purpose") != ("evaluation" if lane.role == "formal" else "smoke")
        or not isinstance(summary, Mapping)
        or summary.get("planned") != lane.sample_count
        or summary.get("accepted") != lane.sample_count
        or summary.get("failed") != 0
        or summary.get("passed") is not True
        or not isinstance(configuration, Mapping)
        or configuration.get("campaign_sha256") != campaign_sha256
        or configuration.get("profile") != "research-1200"
        or configuration.get("request_policies") != ["as-defined"]
        or configuration.get("chaff_qualification_set") != lane.qualification_set
        or not isinstance(source, Mapping)
        or source.get("image_digest") != collection_image_digest
        or source.get("lab_commit") != lab_commit
        or source.get("lab_dirty") is not False
    ):
        raise ValueError("rapid lane result differs from its complete frozen plan")
    if (
        qualification_set_manifest_sha256 is not None
        and configuration.get("chaff_qualification_set_manifest_sha256")
        != qualification_set_manifest_sha256
    ):
        raise ValueError("rapid lane result changed its qualification manifest")
    observed_modes = configuration.get("defenses")
    if (
        not isinstance(observed_modes, list)
        or len(observed_modes) != 1
        or not isinstance(observed_modes[0], Mapping)
        or observed_modes[0].get("name") != lane.mode
    ):
        raise ValueError("rapid lane result has another defence mode")
    observed_workloads = configuration.get("workloads")
    if (
        not isinstance(observed_workloads, list)
        or len(observed_workloads) != len(lane.workload_ids)
    ):
        raise ValueError("rapid lane result has another workload cohort")
    if {
        row.get("id"): (row.get("sha256"), row.get("visits"))
        for row in observed_workloads if isinstance(row, Mapping)
    } != {
        workload_id: (workload_sha256s[workload_id], lane.visits_per_workload)
        for workload_id in lane.workload_ids
    }:
        raise ValueError("rapid lane result changed a workload or visit count")
    expected_slots = {
        (workload_id, visit, lane.mode)
        for workload_id in lane.workload_ids
        for visit in range(lane.visits_per_workload)
    }
    samples = experiment.get("samples")
    if not isinstance(samples, list):
        raise ValueError("rapid lane has no sample inventory")
    observed_slots = [
        (sample.get("workload_id"), sample.get("visit"), sample.get("defense"))
        for sample in samples if isinstance(sample, Mapping)
    ]
    if (
        len(observed_slots) != lane.sample_count
        or len(set(observed_slots)) != lane.sample_count
        or set(observed_slots) != expected_slots
        or any(
            not isinstance(sample, Mapping)
            or sample.get("state") != "accepted"
            or sample.get("request_policy") != "as-defined"
            for sample in samples
        )
    ):
        raise ValueError("rapid lane is missing, repeating, or rejecting a planned sample")
    seal = Path(result_root) / "evidence.sha256"
    return {
        "campaign_name": lane.campaign_name,
        "block": lane.block,
        "shard": lane.shard,
        "mode": lane.mode,
        "accepted": lane.sample_count,
        "result_root": str(Path(result_root).resolve()),
        "result_seal_sha256": _sha(seal.read_bytes()),
        "scientific_credit": (
            "none-diagnostic" if lane.role == "diagnostic"
            else "formal-only-if-bound-to-rolling-enrollment" if lane.study_version == 6
            else "formal-only-if-bound-to-final-50-plan"
        ),
    }


def _safe_child(root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, str) or not reference or "\\" in reference:
        raise ValueError(f"{label} reference is invalid")
    relative = PurePosixPath(reference)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != reference
    ):
        raise ValueError(f"{label} reference is not a canonical relative path")
    parent = Path(root)
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"{label} root is not a regular directory")
    for part in relative.parts:
        parent = parent / part
        if parent.is_symlink():
            raise ValueError(f"{label} reference traverses a symlink")
    return parent


def _receipt_json(path: Path, digest: str, label: str) -> Mapping[str, Any]:
    raw = _checked_file(path, digest, label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not UTF-8 JSON") from error
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} is not a JSON object")
    return value


def verify_formal_manifest(
    manifest: Mapping[str, Any],
    sites: Sequence[Site],
    *,
    bindings: FrozenBindings,
    curated_source: Path,
    fallback_catalogue: Path,
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
    verify_site_workload: Callable[[str], Site],
    campaign_dir: Path,
    workload_root: Path,
    result_root: Path,
    launch_receipt_root: Path,
    lineage_receipt_root: Path,
    verify_launch_receipt: Callable[[Path], Mapping[str, Any]],
    verify_execution_lineage: Callable[[Path], Mapping[str, Any]],
) -> dict[str, Any]:
    """Reopen the 50-site cohort and all 800 physical, launch-bound results.

    ``verify_site_workload`` independently derives a prepared ``Site`` from
    an admitted terminal. The launch callback reopens its DNS-pin evidence;
    the lineage callback reopens source/launcher and predecessor-history
    evidence and attests that a repaired generation remains comparable with
    the frozen cohort. This verifier also checks predecessor campaign bytes.
    Earlier generations remain on disk but only one complete generation of
    each logical lane enters this manifest.
    """

    _check_bindings(bindings)
    selected = _check_sites(sites, final=True)
    if bindings.study_version == 5 and any(
        site.qualification_set_manifest_sha256 is None for site in selected
    ):
        raise ValueError("rapid v5 sites require qualification manifest digests")
    _check_workload_files(selected, workload_root)
    source_bytes = _checked_file(curated_source, SOURCE_SHA256, "rapid curated source")
    catalogue_bytes = _checked_file(
        fallback_catalogue, FALLBACK_CATALOGUE_SHA256, "rapid fallback catalogue"
    )
    profile = _receipt_json(
        bindings.profile_receipt, bindings.profile_sha256, "rapid profile receipt"
    )
    cohort = _receipt_json(
        bindings.cohort_receipt, bindings.cohort_sha256, "rapid cohort receipt"
    )
    profile_validator = (
        validate_v5_profile_receipt if bindings.study_version == 5
        else validate_profile_receipt
    )
    cohort_validator = (
        validate_v5_cohort_receipt if bindings.study_version == 5
        else validate_cohort_receipt
    )
    profile_validator(profile, source_bytes, catalogue_bytes)
    if bindings.selection_amendment_receipt is not None:
        from .rapid_selection_amendment import validate_amended_cohort_receipt
        candidate_ids = validate_amended_cohort_receipt(
            cohort, profile, source_bytes, catalogue_bytes,
            selection_amendment=_receipt_json(
                bindings.selection_amendment_receipt,
                bindings.selection_amendment_sha256, "rapid selection amendment",
            ),
            execution_binding=execution_binding,
            deep_verify_terminal=deep_verify_terminal,
        )
    else:
        candidate_ids = cohort_validator(
            cohort, profile, source_bytes, catalogue_bytes,
            execution_binding=execution_binding,
            deep_verify_terminal=deep_verify_terminal,
        )
    payload = cohort["payload"]
    if payload.get("generation") != "final-50" or candidate_ids != tuple(
        site.candidate_id for site in selected
    ):
        raise ValueError("rapid formal sites differ from the validated final cohort")
    terminal_by_candidate = {
        row["candidate_id"]: row["terminal_receipt_sha256"]
        for row in payload["terminal_decisions"] if row["outcome"] == "admitted"
    }
    for site in selected:
        independently_derived = verify_site_workload(
            terminal_by_candidate[site.candidate_id]
        )
        if independently_derived != site:
            raise ValueError("rapid workload differs from its admitted site evidence")

    corpus_type = V5_CORPUS_TYPE if bindings.study_version == 5 else CORPUS_TYPE
    if not isinstance(manifest, Mapping) or set(manifest) != {
        "schema_version", "artifact_type", "bindings", "lanes"
    } or type(manifest.get("schema_version")) is not int or (
        manifest.get("schema_version") != 1
    ) or manifest.get("artifact_type") != corpus_type:
        raise ValueError("rapid formal corpus manifest schema is invalid")
    if manifest.get("bindings") != bindings.digests():
        raise ValueError("rapid formal corpus manifest has another frozen source binding")
    rows = manifest.get("lanes")
    expected_lanes = plan_lanes(
        selected, final=True, study_version=bindings.study_version
    )
    expected_by_name = {lane.logical_name: lane for lane in expected_lanes}
    if not isinstance(rows, list) or len(rows) != len(expected_lanes):
        raise ValueError("rapid formal corpus manifest is missing lane rows")
    row_by_name: dict[str, Mapping[str, Any]] = {}
    lane_by_name: dict[str, Lane] = {}
    result_references: set[str] = set()
    launch_references: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "logical_lane", "generation", "campaign_name", "campaign_sha256",
            "execution_generation", "collection_image_digest", "lab_commit",
            "base_launcher_sha256", "host_launcher_sha256",
            "lineage_receipt_relpath", "lineage_receipt_sha256", "result_relpath",
            "result_seal_sha256", "launch_receipt_relpath",
            "launch_receipt_sha256", "dns_pin_receipt_sha256",
        }:
            raise ValueError("rapid formal corpus lane row is invalid")
        name = row["logical_lane"]
        if name not in expected_by_name or name in row_by_name:
            raise ValueError("rapid formal corpus repeats or invents a lane")
        generation = row["generation"]
        if type(generation) is not int or not 1 <= generation <= MAX_LANE_GENERATION:
            raise ValueError("rapid formal corpus lane generation is invalid")
        lane = (
            expected_by_name[name] if generation == 1
            else successor_lane(expected_by_name[name], generation)
        )
        if row["campaign_name"] != lane.campaign_name:
            raise ValueError("rapid formal corpus campaign generation is misnamed")
        if (
            not isinstance(row["execution_generation"], str)
            or IDENTIFIER_RE.fullmatch(row["execution_generation"]) is None
            or not isinstance(row["collection_image_digest"], str)
            or IMAGE_RE.fullmatch(row["collection_image_digest"]) is None
            or not isinstance(row["lab_commit"], str)
            or re.fullmatch(r"[0-9a-f]{40}", row["lab_commit"]) is None
        ):
            raise ValueError("rapid formal corpus execution identity is invalid")
        for key in (
            "campaign_sha256", "result_seal_sha256", "launch_receipt_sha256",
            "dns_pin_receipt_sha256", "lineage_receipt_sha256",
            "base_launcher_sha256", "host_launcher_sha256",
        ):
            value = row[key]
            if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"rapid formal corpus {key} is invalid")
        result_path = _safe_child(result_root, row["result_relpath"], "result")
        launch_path = _safe_child(
            launch_receipt_root, row["launch_receipt_relpath"], "launch receipt"
        )
        lineage_path = _safe_child(
            lineage_receipt_root, row["lineage_receipt_relpath"], "lineage receipt"
        )
        if PurePosixPath(row["result_relpath"]).parts[0] != lane.campaign_name:
            raise ValueError("rapid result is outside its campaign namespace")
        if row["result_relpath"] in result_references or (
            row["launch_receipt_relpath"] in launch_references
        ):
            raise ValueError("rapid formal corpus reuses an evidence path")
        result_references.add(row["result_relpath"])
        launch_references.add(row["launch_receipt_relpath"])
        if not result_path.is_dir() or not launch_path.is_file() or (
            not lineage_path.is_file()
        ):
            raise ValueError("rapid formal corpus lane evidence is absent")
        row_by_name[name] = row
        lane_by_name[name] = lane
    if set(row_by_name) != set(expected_by_name):
        raise ValueError("rapid formal corpus has missing lanes")

    verified: list[dict[str, Any]] = []
    for logical_lane in expected_lanes:
        row = row_by_name[logical_lane.logical_name]
        lane = lane_by_name[logical_lane.logical_name]
        campaign_path = _safe_child(
            campaign_dir, f"{lane.campaign_name}.yml", "campaign"
        )
        expected_campaign = render_lane_campaign(lane, selected)
        _checked_file(campaign_path, row["campaign_sha256"], "rapid lane campaign")
        if campaign_path.read_bytes() != expected_campaign:
            raise ValueError("rapid lane YAML differs from the registered grid")
        result_path = _safe_child(result_root, row["result_relpath"], "result")
        launch_path = _safe_child(
            launch_receipt_root, row["launch_receipt_relpath"], "launch receipt"
        )
        lineage_path = _safe_child(
            lineage_receipt_root, row["lineage_receipt_relpath"], "lineage receipt"
        )
        _checked_file(launch_path, row["launch_receipt_sha256"], "rapid launch receipt")
        _checked_file(
            lineage_path, row["lineage_receipt_sha256"], "rapid lineage receipt"
        )
        expected_lineage = {
            "execution_generation": row["execution_generation"],
            "profile_receipt_sha256": bindings.profile_sha256,
            "cohort_receipt_sha256": bindings.cohort_sha256,
            "research_profile_sha256": RESEARCH_PROFILE_SHA256,
            "buflo_parameters_sha256": BUFLO_PARAMETERS_SHA256,
            "cs_buflo_parameters_sha256": CS_BUFLO_PARAMETERS_SHA256,
            "collection_image_digest": row["collection_image_digest"],
            "lab_commit": row["lab_commit"],
            "base_launcher_sha256": row["base_launcher_sha256"],
            "host_launcher_sha256": row["host_launcher_sha256"],
            "equivalent_to_cohort": True,
        }
        if bindings.selection_amendment_sha256 is not None:
            expected_lineage["selection_amendment_sha256"] = bindings.selection_amendment_sha256
        if lane.generation > 1:
            predecessor = replace(
                lane,
                generation=lane.generation - 1,
                campaign_name=_campaign_name(
                    lane.role, lane.block, lane.shard, lane.mode,
                    lane.generation - 1, lane.study_version,
                ),
            )
            predecessor_path = _safe_child(
                campaign_dir, f"{predecessor.campaign_name}.yml",
                "predecessor campaign",
            )
            predecessor_bytes = render_lane_campaign(predecessor, selected)
            _checked_file(
                predecessor_path, _sha(predecessor_bytes),
                "rapid predecessor campaign",
            )
            expected_lineage.update({
                "predecessor_campaign_name": predecessor.campaign_name,
                "predecessor_campaign_sha256": _sha(predecessor_bytes),
            })
        else:
            expected_lineage.update({
                "predecessor_campaign_name": None,
                "predecessor_campaign_sha256": None,
            })
        lineage = verify_execution_lineage(lineage_path)
        if not isinstance(lineage, Mapping) or any(
            lineage.get(key) != value for key, value in expected_lineage.items()
        ):
            raise ValueError("rapid execution lineage is not cohort-equivalent")
        lane_result = verify_lane_result(
            result_path, lane,
            collection_image_digest=row["collection_image_digest"],
            lab_commit=row["lab_commit"],
            campaign_sha256=row["campaign_sha256"],
            workload_sha256s={
                site.workload_id: site.workload_sha256
                for site in selected if site.workload_id in lane.workload_ids
            },
            qualification_set_manifest_sha256=(
                next(
                    site.qualification_set_manifest_sha256
                    for site in selected if site.workload_id == lane.workload_ids[0]
                )
                if lane.qualification_set is not None else None
            ),
        )
        if lane_result["result_seal_sha256"] != row["result_seal_sha256"]:
            raise ValueError("rapid lane result seal differs from the manifest")
        launch = verify_launch_receipt(launch_path)
        expected_launch = {
            "campaign_name": lane.campaign_name,
            "campaign_sha256": row["campaign_sha256"],
            "profile_receipt_sha256": bindings.profile_sha256,
            "cohort_receipt_sha256": bindings.cohort_sha256,
            "execution_generation": row["execution_generation"],
            "lineage_receipt_sha256": row["lineage_receipt_sha256"],
            "base_launcher_sha256": row["base_launcher_sha256"],
            "host_launcher_sha256": row["host_launcher_sha256"],
            "collection_image_digest": row["collection_image_digest"],
            "lab_commit": row["lab_commit"],
            "result_root": str(result_path.resolve()),
            "result_seal_sha256": row["result_seal_sha256"],
            "dns_pin_receipt_sha256": row["dns_pin_receipt_sha256"],
        }
        if not isinstance(launch, Mapping) or any(
            launch.get(key) != value for key, value in expected_launch.items()
        ):
            raise ValueError("rapid launch receipt differs from the verified lane")
        verified.append(lane_result)
    accepted = sum(row["accepted"] for row in verified)
    if accepted != FINAL_SAMPLE_TARGET:
        raise ValueError("rapid formal corpus has missing accepted samples")
    return {
        "valid": True,
        "artifact_type": corpus_type,
        "profile_sha256": bindings.profile_sha256,
        "cohort_sha256": bindings.cohort_sha256,
        "lanes": len(verified),
        "accepted": accepted,
        "result_seal_sha256s": {
            row["logical_lane"]: row["result_seal_sha256"] for row in rows
        },
    }
