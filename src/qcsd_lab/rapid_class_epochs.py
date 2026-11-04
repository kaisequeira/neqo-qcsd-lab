"""Prospective, create-only class refreshes and matched 100-trace blocks.

The original cohort fixes class membership and selected URLs. A class epoch
changes its complete prepared graph, never its label. A block declares five
epochs before launch and earns formal credit only when all five conditions
deep-verify. This is separate authority: historical plans remain unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, OrderedDict
from collections.abc import Mapping
from dataclasses import asdict, replace
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Any

import yaml

from . import rapid_capture_plan as plan
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as admission
from .application_response_policy import (
    build_primary_document_identity_evidence, validate_application_responses,
    validate_primary_document_identity_evidence,
)
from .util import durable_create
from .verification import verify_result

POLICY_TYPE = "qcsd-rapid-v5-class-epoch-policy-v1"
CLASS_TYPE = "qcsd-rapid-v5-class-epoch-v1"
BLOCK_TYPE = "qcsd-rapid-v5-matched-block-declaration-v1"
RETIREMENT_TYPE = "qcsd-rapid-v5-observed-drift-block-retirement-v1"
COMPLETE_TYPE = "qcsd-rapid-v5-epoch-lane-completion-v1"
COMMIT_TYPE = "qcsd-rapid-v5-matched-block-commit-v1"
CORPUS_TYPE = "qcsd-rapid-v5-class-epoch-formal-corpus-v1"
IMAGE_TYPE = "qcsd-rapid-v5-executed-epoch-block-check-v1"
BLOCK_COUNT = plan.FINAL_BLOCKS * plan.FINAL_CLASS_COUNT // plan.SHARD_SIZE
BLOCK_SAMPLE_COUNT = plan.SHARD_SIZE * len(plan.MODES) * plan.FINAL_VISITS_PER_BLOCK
_VALIDATION_CACHE: ContextVar[OrderedDict | None] = ContextVar("rapid_epoch_validation", default=None)


def _operation(function):
    """Share reopened immutable predecessors within one operation, never across it.

    Recursive epoch history would otherwise repeatedly revalidate every older
    block for each condition. A fresh operator action always gets a fresh cache.
    Launch clears it after host actuation before inspecting resulting evidence.
    The bound prevents a final corpus traversal retaining all large image proofs.
    """
    @wraps(function)
    def call(*args, **kwargs):
        if _VALIDATION_CACHE.get() is not None:
            return function(*args, **kwargs)
        token = _VALIDATION_CACHE.set(OrderedDict())
        try:
            return function(*args, **kwargs)
        finally:
            _VALIDATION_CACHE.reset(token)
    return call


def _memoized(function):
    @wraps(function)
    @_operation
    def call(spec, root, *args, **kwargs):
        cache = _VALIDATION_CACHE.get()
        path = args[0] if args else root / "policy.json"
        key = (function.__name__, id(spec), str(root), str(path), _sha(admission._read(path)))
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        result = function(spec, root, *args, **kwargs)
        cache[key] = result
        if len(cache) > 128:
            cache.popitem(last=False)
        return result
    return call


def _clear_validation_cache() -> None:
    cache = _VALIDATION_CACHE.get()
    if cache is not None:
        cache.clear()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, kind: str, value: Mapping[str, Any]) -> Path:
    durable_create(path, admission._json(admission._bind(kind, value)))
    return path


def _open(path: Path, kind: str) -> dict[str, Any]:
    return admission._unpack(admission._read(path), kind)


def _reference(root: Path, path: Path) -> dict[str, str]:
    return admission.evidence_reference(root, path)


def _child(root: Path, reference: Mapping[str, str]) -> Path:
    return admission._child(root, reference)


def _data_path(spec: lanes.CaptureSpec, reference: str) -> Path:
    return plan._safe_child(spec.data_root, reference, "epoch data")


def _data_reference(spec: lanes.CaptureSpec, path: Path) -> str:
    path = Path(path).absolute()
    relative = path.relative_to(spec.data_root).as_posix()
    if _data_path(spec, relative) != path:
        raise ValueError("epoch artifact escapes the mounted data root")
    admission._read(path)
    return relative


def _check_keys(value: Any, fields: set[str], label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} exact fields differ")


def _time(value: Any):
    if not isinstance(value, str):
        raise ValueError("epoch time is not an explicit UTC timestamp")
    return admission._utc(value)


def _classes(spec: lanes.CaptureSpec, proof: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Derive labels and exact page URLs from the original scientific terminals."""
    if proof["cohort_generation"] != "final-50":
        raise ValueError("class epochs require the original final-50 cohort")
    sites = lanes._validate_image_proof(proof, spec)
    context = admission.load_admission_context(spec.acquisition_root)
    status = admission.acquisition_status(context)
    lookup = {item["sha256"]: _child(context.root, item) for item in status["terminal_prefix"]}
    cohort = admission._load(admission._read(spec.cohort))
    selected = admission.validate_acquisition_cohort(
        context, cohort, lambda digest: admission.verify_site_terminal(lookup[digest], context),
    )
    if selected != tuple(site.candidate_id for site in sites):
        raise ValueError("epoch classes differ from independently reopened membership")
    by_id = {
        admission.verify_site_terminal(path, context)["candidate_id"]: (digest, path)
        for digest, path in lookup.items()
        if admission.verify_site_terminal(path, context)["outcome"] == "admitted"
    }
    rows = []
    for site in sites:
        digest, terminal = by_id[site.candidate_id]
        facts = admission.verify_site_terminal(terminal, context)
        rows.append({"candidate_id": site.candidate_id,
                     "selected_url": facts["admission"]["selected_page_url"],
                     "original_terminal_sha256": digest, "initial_site": asdict(site)})
    return rows


@_operation
def initialize_study(spec: lanes.CaptureSpec, root: Path, *, installation: Path | None = None) -> Path:
    """Run the real image gate, then publish authority before any epoch capture."""
    root = lanes._regular_directory(root)
    if not root.is_relative_to(spec.data_root) or installation is None and any(root.iterdir()):
        raise ValueError("epoch study requires an empty create-only directory in the data root")
    with lanes.capture_lock(spec.execution_root):
        environment = {}
        if installation is not None:
            from . import rapid_capture_control_installation as control
            installation = Path(installation).absolute()
            installed, _ = control.validate_capsule(installation, actual_image=spec.collection_image_digest)
            control.check_current_spec(installed, spec)
            if (installed["evidence_root"] != str(root) or installation.parent != root
                or installation.name in {"policy.json", "objects", "control-installation-checks"}
                or {path.name for path in root.iterdir()} - {installation.name, "objects", "control-installation-checks"}
                or any(root.rglob("intent.json"))):
                raise ValueError("epoch installation bootstrap permits only its declared capsule/checks/objects")
            environment = {"QCSD_RAPID_COLLECTION_COMPATIBILITY": str(installation),
                           "QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION": str(installation)}
        saved = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        try:
            checked = lanes.check_bound_image(spec, root)
        finally:
            for key, old in saved.items():
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old
        classes = _classes(spec, checked["proof"])
        published = admission._now()
        payload = {"base_spec": spec.serializable(), "image_check": checked,
                   "classes": classes, "published_at": published,
                   "block_count": BLOCK_COUNT, "traces_per_block": BLOCK_SAMPLE_COUNT,
                   "formal_trace_target": plan.FINAL_SAMPLE_TARGET,
                   "modes": list(plan.MODES), "visits_per_condition": plan.FINAL_VISITS_PER_BLOCK,
                   "refresh_rule": "observed-complete-response-drift-and-actual-block-retirement",
                   "comparison_rule": "same-five-class-epoch-vector-in-all-five-conditions",
                   "selection_rule": "one-explicit-complete-block-commit-no-newest-selection",
                   "scientific_credit": False}
        path = _write(root / "policy.json", POLICY_TYPE, payload)
        for row in classes:
            site = row["initial_site"]
            _write(root / "classes" / row["candidate_id"] / "e0001.json", CLASS_TYPE, {
                "policy": _reference(root, path), "candidate_id": row["candidate_id"], "ordinal": 1,
                "selected_url": row["selected_url"], "site": site,
                "predecessor": None, "retirement": None, "preparation": None,
                "created_at": published, "scientific_credit": False,
            })
    return path


@_memoized
def verify_policy(spec: lanes.CaptureSpec, root: Path) -> dict[str, Any]:
    value = _open(root / "policy.json", POLICY_TYPE)
    _check_keys(value, {"base_spec", "image_check", "classes", "published_at", "block_count",
                       "traces_per_block", "formal_trace_target", "modes", "visits_per_condition",
                       "refresh_rule", "comparison_rule", "selection_rule", "scientific_credit"}, "epoch policy")
    checked = value["image_check"]
    execution = checked["execution"]
    reference = execution.get("capture_control_installation")
    capsule_path = None
    if reference is not None:
        if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not Path(reference["path"]).is_absolute()
            or _sha(admission._read(Path(reference["path"]))) != reference["sha256"]):
            raise ValueError("epoch policy changed its sealed capture-control installation")
        capsule_path = Path(reference["path"])
        from . import rapid_capture_control_installation as installation
        from .rapid_runtime_epochs import _runtime_projection
        installed, _ = installation.validate_capsule(capsule_path, actual_image=spec.collection_image_digest)
        installation.check_current_spec(installed, spec)
        if (installed["evidence_root"] != str(root)
            or _runtime_projection(checked["proof"]) != installed["new_runtime_check"]["proof"]["runtime_proof"]
            or _time(execution["started_at"]) < _time(installed["published_at"])):
            raise ValueError("epoch policy differs from its prospectively installed current source")
    if (value["base_spec"] != spec.serializable() or value["scientific_credit"] is not False
        or type(execution["returncode"]) is not int or execution["returncode"] != 0
        or execution["command"] != lanes.image_check_command(spec, capture_control_installation=capsule_path,
                                                            inherit_environment=False)
        or execution["validator_script_sha256"] != _sha(lanes.IMAGE_CHECK_SCRIPT.encode())
        or admission._load(lanes._object(root, execution["stdout"])) != checked["proof"]):
        raise ValueError("epoch policy lacks the actual matching installed-image execution")
    lanes._object(root, execution["stderr"])
    published = _time(value["published_at"])
    if not _time(execution["started_at"]) <= _time(execution["completed_at"]) <= published <= _time(admission._now()):
        raise ValueError("epoch policy publication predates its actual validation")
    expected = {"block_count": BLOCK_COUNT, "traces_per_block": BLOCK_SAMPLE_COUNT,
                "formal_trace_target": plan.FINAL_SAMPLE_TARGET, "modes": list(plan.MODES),
                "visits_per_condition": plan.FINAL_VISITS_PER_BLOCK,
                "refresh_rule": "observed-complete-response-drift-and-actual-block-retirement",
                "comparison_rule": "same-five-class-epoch-vector-in-all-five-conditions",
                "selection_rule": "one-explicit-complete-block-commit-no-newest-selection"}
    if any(type(value[key]) is not type(item) or value[key] != item for key, item in expected.items()):
        raise ValueError("epoch policy changes the prospectively fixed study protocol")
    if value["classes"] != _classes(spec, checked["proof"]):
        raise ValueError("epoch policy changes the original 50 classes or selected URLs")
    return value


def _fresh_preparation(spec: lanes.CaptureSpec, root: Path, row: Mapping[str, Any],
                       workload: Path, graph: Path, *, not_before: str) -> dict[str, Any]:
    """Reopen original JSON ledgers, including all three actual full-graph repeats."""
    from .prepare import _failure_child_execution
    context = admission.load_admission_context(spec.acquisition_root)
    facts = admission.verify_prepared_workload(workload, graph, context, selected_page_url=row["selected_url"])
    manifest = admission._load(admission._read(workload))
    preparation = manifest["preparation"]
    primary_policy = getattr(context, "primary_document_identity_policy", None)
    variable_primary = primary_policy is not None
    primary_proof = validate_primary_document_identity_evidence(manifest) if variable_primary else None
    if (preparation.get("application_response_policy") != context.application_response_policy
        or preparation.get("primary_document_identity_policy") != primary_policy):
        raise ValueError("refreshed class changes the prospectively registered response policy")
    if admission.origin(preparation["final_url"]) != row["initial_site"]["primary_origin"]:
        raise ValueError("refreshed class changed its original primary origin")
    raw_root = workload.parent / f"{workload.stem}-application-response-evidence"
    inventory_raw = admission._read(raw_root / "inventory.json")
    inventory = admission._load(inventory_raw)
    fields = {"schema_version", "artifact_type", "workload_id", "original_directory",
              "capture_source_before", "capture_source_after", "started_at", "completed_at",
              "policy_evidence", "files", "scientific_credit"}
    if variable_primary:
        fields |= {"primary_document_identity_policy", "primary_document_identity_evidence"}
    _check_keys(inventory, fields, "fresh epoch preparation inventory")
    if (type(inventory["schema_version"]) is not int or inventory["schema_version"] != (2 if variable_primary else 1)
        or inventory["artifact_type"] != "qcsd-application-response-preparation-evidence"
        or inventory["workload_id"] != workload.stem or inventory["scientific_credit"] is not False
        or any(inventory[key] != context.expected_runtime_source
               for key in ("capture_source_before", "capture_source_after"))
        or type(preparation["stability_runs"]) is not int or preparation["stability_runs"] != 3):
        raise ValueError("refreshed class lacks its exact fresh three-repeat runtime proof")
    if variable_primary and (primary_proof is None
        or inventory["primary_document_identity_policy"] != primary_policy
        or inventory["primary_document_identity_evidence"] != primary_proof):
        raise ValueError("refreshed class changes its actual primary-document witnesses")
    start, end = _time(inventory["started_at"]), _time(inventory["completed_at"])
    if not _time(not_before) <= start <= end <= _time(admission._now()):
        raise ValueError("refreshed preparation predates observed retirement")
    names = {"probe-input.json", "probe-output.json", "probe.log.execution.json",
             "probe-output.probe-head/run.json", "stability-input.json",
             *[name for index in range(3) for name in (f"stability-{index}/run.json",
                                                       f"stability-{index}.log.execution.json")]}
    get_name = "probe-output.probe-get/run.json"
    if not variable_primary or inventory["policy_evidence"] is not None or get_name in inventory["files"]:
        names.add(get_name)
    if set(inventory["files"]) != names:
        raise ValueError("fresh epoch preparation omits a raw probe or repeat")
    observed = set()
    for path in raw_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("epoch raw preparation traverses linked evidence")
        if path.is_file():
            observed.add(path.relative_to(raw_root).as_posix())
    if observed != {"inventory.json", *[f"artifacts/{name}" for name in names]}:
        raise ValueError("epoch raw preparation inventory is not closed")
    artifacts = {}
    for name in names:
        raw = admission._read(raw_root / "artifacts" / name)
        if inventory["files"][name] != {"sha256": _sha(raw), "size": len(raw)}:
            raise ValueError("epoch raw preparation bytes differ from their inventory")
        artifacts[name] = raw
    original = Path(inventory["original_directory"])
    if not original.is_absolute() or ".." in original.parts or not original.name.startswith(f".{workload.stem}-prepare-"):
        raise ValueError("epoch actual preparation directory is malformed")
    prepared_graph = [{key: item[key] for key in ("id", "url", "type", "depends_on")}
                      for item in manifest["resources"]]
    for name in ("probe-input.json", "probe-output.json", "stability-input.json"):
        source = admission._load(artifacts[name])
        if [{key: item[key] for key in ("id", "url", "type", "depends_on")}
            for item in source["resources"]] != prepared_graph:
            raise ValueError("refreshed epoch removed or substituted part of its discovered graph")
    probe = _failure_child_execution(artifacts, "probe.log.execution.json", "probe", returncode=0)
    if not start <= _time(probe["started_at"]) <= _time(probe["completed_at"]) <= end:
        raise ValueError("fresh epoch probe lies outside its actual preparation")
    previous = _time(probe["completed_at"])
    runs = []
    for index in range(3):
        child = _failure_child_execution(artifacts, f"stability-{index}.log.execution.json", "run", returncode=0)
        command = child["command"]
        expected = ["run", "--application-response-policy", context.application_response_policy,
                    "--workload", str(original / "stability-input.json"), "--profile", "live",
                    "--defense", "none", "--seed", "0", "--output-dir", str(original / f"stability-{index}"),
                    "--max-response-bytes", str(preparation["max_response_bytes"]),
                    "--timeout-seconds", str(preparation["timeout_seconds"])]
        if command[command.index("run"):] != expected:
            raise ValueError("fresh epoch repeat changes the actual runtime command")
        if child["configured_timeout_seconds"] != preparation["timeout_seconds"]:
            raise ValueError("fresh epoch repeat changes its declared timeout")
        if not previous <= _time(child["started_at"]) <= _time(child["completed_at"]) <= end:
            raise ValueError("fresh epoch repeats are not actually fresh and ordered")
        previous = _time(child["completed_at"])
        run = admission._load(artifacts[f"stability-{index}/run.json"])
        validate_application_responses(manifest, run)
        run_start, run_end = run.get("started_unix_ns"), run.get("ended_unix_ns")
        if (type(run_start) is not int or type(run_end) is not int or run.get("time_anchor_unix_ns") != run_start
            or not _time(child["started_at"]).timestamp() * 1e9 - 1_000 <= run_start <= run_end <=
            _time(child["completed_at"]).timestamp() * 1e9 + 1_000):
            raise ValueError("fresh epoch actual runner clock differs from its child execution")
        endpoints = run.get("endpoints")
        expected_origins = {admission.origin(resource["url"]) for resource in manifest["resources"]}
        if (not isinstance(endpoints, list) or len(endpoints) != len(expected_origins)
            or {admission.origin(item["origin"]) for item in endpoints} != expected_origins
            or any(item.get("negotiated_protocol") != "h3" for item in endpoints)
            or run.get("workload_hash_sha256") != _sha(artifacts["stability-input.json"])
            or any(run.get(key) != preparation[key] for key in (
                "neqo_version", "neqo_base_commit", "published_qcsd_commit", "migration_commit"))):
            raise ValueError("fresh epoch repeat lacks actual complete-graph HTTP/3/source bindings")
        runs.append(run)
    if variable_primary and build_primary_document_identity_evidence(
        manifest, runs, stability_run_sha256s=[_sha(artifacts[f"stability-{index}/run.json"]) for index in range(3)]
    ) != primary_proof:
        raise ValueError("refreshed primary-document witnesses differ from all three actual raw replays")
    return {"workload_path": _data_reference(spec, workload), "graph_path": _data_reference(spec, graph),
            "workload_sha256": _sha(admission._read(workload)), "graph_sha256": _sha(admission._read(graph)),
            "raw_inventory_sha256": _sha(inventory_raw), "facts": facts,
            "started_at": inventory["started_at"], "completed_at": inventory["completed_at"]}


@_memoized
def verify_class_epoch(spec: lanes.CaptureSpec, root: Path, path: Path,
                       *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    policy = verify_policy(spec, root)
    value = _open(path, CLASS_TYPE)
    _check_keys(value, {"policy", "candidate_id", "ordinal", "selected_url", "site", "predecessor",
                       "retirement", "preparation", "created_at", "scientific_credit"}, "class epoch")
    row = next((item for item in policy["classes"] if item["candidate_id"] == value["candidate_id"]), None)
    ordinal = value["ordinal"]
    if (row is None or type(ordinal) is not int or not 1 <= ordinal <= 9999
        or value["policy"] != _reference(root, root / "policy.json")
        or path != root / "classes" / value["candidate_id"] / f"e{ordinal:04d}.json"
        or value["selected_url"] != row["selected_url"] or value["scientific_credit"] is not False
        or not _time(policy["published_at"]) <= _time(value["created_at"]) <= _time(admission._now())):
        raise ValueError("class epoch changes its fixed label, URL, chronology or namespace")
    site = plan.Site(**value["site"])
    if site.candidate_id != row["candidate_id"] or site.primary_origin != row["initial_site"]["primary_origin"]:
        raise ValueError("class epoch substitutes a class or primary origin")
    if ordinal == 1:
        if (value["site"] != row["initial_site"] or value["created_at"] != policy["published_at"]
            or any(value[key] is not None for key in ("predecessor", "retirement", "preparation"))):
            raise ValueError("initial class epoch differs from its original admitted bytes")
    else:
        previous_path = root / "classes" / value["candidate_id"] / f"e{ordinal - 1:04d}.json"
        if value["predecessor"] != _reference(root, previous_path):
            raise ValueError("class epoch skips its actual predecessor")
        previous = verify_class_epoch(spec, root, previous_path, policy=policy)
        retired = verify_block_retirement(spec, root, _child(root, value["retirement"]), policy=policy)
        if value["candidate_id"] not in retired["drifting_candidates"]:
            raise ValueError("class refresh has no observed drift for this class")
        retired_epoch = next(item for item in retired["epochs"] if item["candidate_id"] == value["candidate_id"])
        if retired_epoch["receipt"] != value["predecessor"]:
            raise ValueError("class refresh is not based on its observed drifting predecessor")
        if site.workload_id == previous["site"]["workload_id"] or site.workload_sha256 == previous["site"]["workload_sha256"]:
            raise ValueError("class refresh must preserve old files and bind new workload bytes")
        facts = value["preparation"]
        checked = _fresh_preparation(spec, root, row, _data_path(spec, facts["workload_path"]),
                                     _data_path(spec, facts["graph_path"]), not_before=retired["observed_at"])
        if facts != checked or site.workload_sha256 != facts["workload_sha256"] or _time(value["created_at"]) < _time(facts["completed_at"]):
            raise ValueError("class epoch differs from reopened fresh preparation")
    return value


@_operation
def register_class_epoch(spec: lanes.CaptureSpec, root: Path, *, candidate_id: str,
                          workload: Path, graph: Path, retirement: Path) -> Path:
    """Register actual fresh full-graph preparation after observed drift retirement."""
    policy = verify_policy(spec, root)
    retired = verify_block_retirement(spec, root, retirement, policy=policy)
    row = next((item for item in policy["classes"] if item["candidate_id"] == candidate_id), None)
    if row is None or candidate_id not in retired["drifting_candidates"]:
        raise ValueError("refresh requires drift of an original class")
    directory = root / "classes" / candidate_id
    paths = sorted(directory.glob("e[0-9][0-9][0-9][0-9].json"))
    previous = verify_class_epoch(spec, root, paths[-1], policy=policy)
    retired_epoch = next(item for item in retired["epochs"] if item["candidate_id"] == candidate_id)
    if retired_epoch["receipt"] != _reference(root, paths[-1]):
        raise ValueError("refresh is not based on this class's immediate observed predecessor")
    facts = _fresh_preparation(spec, root, row, workload, graph, not_before=retired["observed_at"])
    original_site = plan.Site(**row["initial_site"])
    site = replace(original_site, workload_id=workload.stem, workload_sha256=facts["workload_sha256"])
    ordinal = previous["ordinal"] + 1
    if (ordinal > 9999 or site.workload_id == previous["site"]["workload_id"]
        or site.workload_sha256 == previous["site"]["workload_sha256"]):
        raise ValueError("class refresh requires a new workload namespace and bytes")
    output = directory / f"e{ordinal:04d}.json"
    value = {"policy": _reference(root, root / "policy.json"), "candidate_id": candidate_id,
             "ordinal": ordinal, "selected_url": row["selected_url"], "site": asdict(site),
             "predecessor": _reference(root, paths[-1]), "retirement": _reference(root, retirement),
             "preparation": facts, "created_at": admission._now(), "scientific_credit": False}
    _write(output, CLASS_TYPE, value)
    verify_class_epoch(spec, root, output, policy=policy)
    return output


def _block_directory(root: Path, block: int, shard: int, ordinal: int) -> Path:
    if (type(block) is not int or not 1 <= block <= plan.FINAL_BLOCKS
        or type(shard) is not int or not 1 <= shard <= plan.FINAL_CLASS_COUNT // plan.SHARD_SIZE
        or type(ordinal) is not int or not 1 <= ordinal <= 9999):
        raise ValueError("epoch block is outside the fixed 160-block grid")
    return root / "blocks" / f"b{block:02d}-s{shard:02d}" / f"e{ordinal:04d}"


def _epoch_lane(value: Mapping[str, Any], sites: tuple[plan.Site, ...], mode: str, generation: int = 1) -> plan.Lane:
    base = next(item for item in plan.plan_lanes(sites, final=True, study_version=5)
                if item.block == value["block"] and item.shard == value["shard"] and item.mode == mode)
    lane = base if generation == 1 else plan.successor_lane(base, generation)
    return replace(lane, campaign_name=plan.epoch_campaign_name(lane, value["ordinal"]))


def render_epoch_lane(lane: plan.Lane, sites: tuple[plan.Site, ...], epoch: int) -> bytes:
    if lane.campaign_name != plan.epoch_campaign_name(lane, epoch):
        raise ValueError("epoch lane has another physical namespace")
    original = replace(lane, campaign_name=plan._campaign_name(
        lane.role, lane.block, lane.shard, lane.mode, lane.generation, 5))
    value = yaml.safe_load(plan.render_lane_campaign(original, sites))
    value["name"] = lane.campaign_name
    value["seed"] = int(_sha(lane.campaign_name.encode("ascii"))[:16], 16)
    return yaml.safe_dump(value, sort_keys=False, width=100).encode()


def _block_sites(spec: lanes.CaptureSpec, root: Path, value: Mapping[str, Any], policy: Mapping[str, Any],
                   *, require_current: bool = False) -> tuple[plan.Site, ...]:
    from .chaff_qualification import RESPONSE_ONLY_QUALIFICATION_SCOPE, validate_named_qualification_set_manifest
    rows = policy["classes"][(value["shard"] - 1) * 5:value["shard"] * 5]
    if [item["candidate_id"] for item in value["epochs"]] != [item["candidate_id"] for item in rows]:
        raise ValueError("matched block changes its original five-class shard")
    effective = []
    for entry in value["epochs"]:
        _check_keys(entry, {"candidate_id", "receipt"}, "block class epoch entry")
        epoch = verify_class_epoch(spec, root, _child(root, entry["receipt"]), policy=policy)
        if epoch["candidate_id"] != entry["candidate_id"] or _time(epoch["created_at"]) > _time(value["declared_at"]):
            raise ValueError("block epoch was registered after its capture declaration")
        effective.append(plan.Site(**epoch["site"]))
    qualification = value["qualification"]
    _check_keys(qualification, {"name", "manifest_path", "manifest_sha256"}, "epoch qualifier")
    manifest_path = _data_path(spec, qualification["manifest_path"])
    expected_path = spec.campaign_dir.parent / "chaff-response-qualification-store/sets" / qualification["name"] / "_qualification-set.json"
    if manifest_path != expected_path or _sha(admission._read(manifest_path)) != qualification["manifest_sha256"]:
        raise ValueError("epoch qualification is not the exact installed immutable set")
    for site in effective:
        if _sha(admission._read(spec.workload_root / f"{site.workload_id}.json")) != site.workload_sha256:
            raise ValueError("epoch materialized workload differs from its prepared bytes")
    validate_named_qualification_set_manifest(admission._load(admission._read(manifest_path)),
        workload_root=spec.workload_root, sidecar_root=manifest_path.parent, prefix_spec_root=None,
        expected_qualification_set=qualification["name"], expected_workload_ids=[site.workload_id for site in effective],
        expected_qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
        require_current_implementation=require_current)
    proof = policy["image_check"]["proof"]
    original_proof = None
    for site in effective:
        sidecar = admission._load(admission._read(manifest_path.parent / f"{site.workload_id}.json"))
        if (sidecar["qualification_image_digest"] != spec.collection_image_digest
            or sidecar["qualification_source"] != proof["runtime_source"]
            or sidecar["implementation_receipt"] != proof["qualification_implementation"]):
            if original_proof is None:
                reference = policy["image_check"]["execution"].get("capture_control_installation")
                if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
                    or not Path(reference["path"]).is_absolute()
                    or _sha(admission._read(Path(reference["path"]))) != reference["sha256"]):
                    raise ValueError("epoch qualifier changes the exact installed image/client/source")
                from . import rapid_capture_control_installation as installation
                from .rapid_runtime_epochs import _runtime_projection
                installed, _ = installation.validate_capsule(Path(reference["path"]), actual_image=spec.collection_image_digest)
                installation.check_current_spec(installed, spec)
                if (installed["evidence_root"] != str(root)
                    or _runtime_projection(proof) != installed["new_runtime_check"]["proof"]["runtime_proof"]
                    or _time(policy["image_check"]["execution"]["started_at"]) < _time(installed["published_at"])):
                    raise ValueError("epoch qualifier lacks its exact prospectively installed current source")
                original_proof = installed["old_image_check"]["proof"]
            if (sidecar["qualification_image_digest"] != original_proof["collection_image_digest"]
                or sidecar["qualification_source"] != original_proof["runtime_source"]
                or sidecar["implementation_receipt"] != original_proof["qualification_implementation"]):
                raise ValueError("epoch qualifier changes its preserved original image/client/source")
    effective = [replace(site, qualification_set=qualification["name"],
                         qualification_set_manifest_sha256=qualification["manifest_sha256"]) for site in effective]
    selected = [plan.Site(**row["initial_site"]) for row in policy["classes"]]
    selected[(value["shard"] - 1) * 5:value["shard"] * 5] = effective
    return plan._check_sites(selected, final=True)


def _replacement_vector(spec: lanes.CaptureSpec, root: Path, value: Mapping[str, Any],
                         retired: Mapping[str, Any]) -> None:
    old = {item["candidate_id"]: item["receipt"] for item in retired["epochs"]}
    drifting = set(retired["drifting_candidates"])
    for entry in value["epochs"]:
        candidate, reference = entry["candidate_id"], entry["receipt"]
        if candidate not in drifting:
            if reference != old.get(candidate):
                raise ValueError("replacement changes an unrelated class's actual epoch")
            continue
        epoch = verify_class_epoch(spec, root, _child(root, reference))
        if (epoch["predecessor"] != old[candidate]
            or epoch["retirement"] != value["predecessor_retirement"]):
            raise ValueError("replacement requires this drifting class's actual fresh registered epoch")


@_memoized
def verify_block(spec: lanes.CaptureSpec, root: Path, path: Path,
                  *, policy: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], tuple[plan.Site, ...]]:
    policy = verify_policy(spec, root)
    value = _open(path, BLOCK_TYPE)
    _check_keys(value, {"policy", "block", "shard", "ordinal", "epochs", "qualification", "predecessor_retirement",
                       "campaigns", "declared_at", "scientific_credit"}, "matched block declaration")
    directory = _block_directory(root, value["block"], value["shard"], value["ordinal"])
    if (path != directory / "declaration.json" or value["policy"] != _reference(root, root / "policy.json")
        or value["scientific_credit"] is not False
        or not _time(policy["published_at"]) <= _time(value["declared_at"]) <= _time(admission._now())):
        raise ValueError("matched block changed its prospective authority or namespace")
    if value["ordinal"] == 1:
        if value["predecessor_retirement"] is not None:
            raise ValueError("initial block invents predecessor history")
    else:
        prior = _block_directory(root, value["block"], value["shard"], value["ordinal"] - 1)
        if value["predecessor_retirement"] != _reference(root, prior / "retirement.json"):
            raise ValueError("block replacement skips its immediately retired predecessor")
        retired = verify_block_retirement(spec, root, prior / "retirement.json", policy=policy)
        if _time(value["declared_at"]) < _time(retired["observed_at"]):
            raise ValueError("replacement block was declared before actual retirement")
        _replacement_vector(spec, root, value, retired)
    sites = _block_sites(spec, root, value, policy)
    if set(value["campaigns"]) != set(plan.MODES):
        raise ValueError("matched block omits one of the five conditions")
    for mode in plan.MODES:
        lane = _epoch_lane(value, sites, mode)
        raw = render_epoch_lane(lane, sites, value["ordinal"])
        if (value["campaigns"][mode] != {"name": lane.campaign_name, "sha256": _sha(raw)}
            or admission._read(spec.campaign_dir / f"{lane.campaign_name}.yml") != raw):
            raise ValueError("matched block campaign changes its declared epoch vector")
    return value, sites


@_operation
def declare_block(spec: lanes.CaptureSpec, root: Path, *, block: int, shard: int,
                    epochs: Mapping[str, Path] | None = None, qualification_manifest: Path,
                    predecessor_retirement: Path | None = None) -> Path:
    """Declare all five conditions before capture; never select a newer result."""
    policy = verify_policy(spec, root)
    ordinal = 1
    if predecessor_retirement is not None:
        retired = verify_block_retirement(spec, root, predecessor_retirement, policy=policy)
        if (retired["block"], retired["shard"]) != (block, shard):
            raise ValueError("replacement retirement belongs to another logical block")
        ordinal = retired["ordinal"] + 1
    directory = _block_directory(root, block, shard, ordinal)
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("matched block epoch destination is already claimed")
    rows = policy["classes"][(shard - 1) * 5:shard * 5]
    supplied = dict(epochs or {})
    if set(supplied) - {row["candidate_id"] for row in rows}:
        raise ValueError("block epoch override introduces another class")
    vector = [{"candidate_id": row["candidate_id"], "receipt": _reference(root, supplied.get(
        row["candidate_id"], root / "classes" / row["candidate_id"] / "e0001.json"))} for row in rows]
    qualifier = admission._load(admission._read(qualification_manifest))
    value = {"policy": _reference(root, root / "policy.json"), "block": block, "shard": shard,
             "ordinal": ordinal, "epochs": vector,
             "qualification": {"name": qualifier["qualification_set"],
                               "manifest_path": _data_reference(spec, qualification_manifest),
                               "manifest_sha256": _sha(admission._read(qualification_manifest))},
             "predecessor_retirement": _reference(root, predecessor_retirement) if predecessor_retirement else None,
             "campaigns": {}, "declared_at": admission._now(), "scientific_credit": False}
    sites = _block_sites(spec, root, value, policy)
    if predecessor_retirement is not None:
        _replacement_vector(spec, root, value, retired)
    rendered = {}
    for mode in plan.MODES:
        lane = _epoch_lane(value, sites, mode)
        raw = render_epoch_lane(lane, sites, ordinal)
        rendered[spec.campaign_dir / f"{lane.campaign_name}.yml"] = raw
        value["campaigns"][mode] = {"name": lane.campaign_name, "sha256": _sha(raw)}
    if any(path.exists() or path.is_symlink() for path in rendered):
        raise FileExistsError("epoch campaign namespace was previously claimed")
    directory.mkdir(parents=True)
    _write(directory / "allocation.json", "qcsd-rapid-v5-block-epoch-allocation-v1", {
        "policy": value["policy"], "block": block, "shard": shard, "ordinal": ordinal,
        "allocated_at": value["declared_at"], "scientific_credit": False})
    for path, raw in rendered.items():
        durable_create(path, raw)
    output = _write(directory / "declaration.json", BLOCK_TYPE, value)
    verify_block(spec, root, output, policy=policy)
    return output


@_operation
def executed_image_epoch_check(value: Mapping[str, Any]) -> dict[str, Any]:
    """Execute inside the selected immutable image, reopening actual qualifiers."""
    _check_keys(value, {"spec", "root", "declaration"}, "epoch image inputs")
    spec = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item
                                for key, item in value["spec"].items()})
    root = lanes._regular_directory(Path(value["root"]))
    declaration = Path(value["declaration"])
    if not root.is_relative_to(spec.data_root):
        raise ValueError("epoch image root escapes the explicit mounted data root")
    base_proof = lanes.executed_image_plan_check(spec.serializable())
    policy = verify_policy(spec, root)
    block, sites = verify_block(spec, root, declaration, policy=policy)
    _block_sites(spec, root, block, policy, require_current=True)
    return {"schema_version": 1, "artifact_type": IMAGE_TYPE, "base_proof": base_proof,
            "policy": _reference(root, root / "policy.json"), "declaration": _reference(root, declaration),
            "effective_sites": [asdict(site) for site in sites], "scientific_credit": False}


@_operation
def validate_host_epoch_launch(value: Mapping[str, Any], *, expected_campaign: str,
                                 actual_image: str) -> dict[str, Any]:
    """Actual read-only image preflight for the host launcher's epoch branch."""
    _check_keys(value, {"spec", "root", "intent", "intent_sha256"}, "host epoch launch inputs")
    from . import rapid_runtime_epochs as runtime_epochs
    if runtime_epochs._kind(Path(value["intent"])) in {runtime_epochs.INTENT_TYPE, runtime_epochs.CANARY_INTENT_TYPE}:
        return runtime_epochs.validate_host_launch(value, expected_campaign=expected_campaign, actual_image=actual_image)
    spec = lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item
                                for key, item in value["spec"].items()})
    root, intent_path = Path(value["root"]), Path(value["intent"])
    if (actual_image != spec.collection_image_digest
        or _sha(admission._read(intent_path)) != value["intent_sha256"]):
        raise ValueError("host epoch launch changed its actual image or predeclared intent")
    intent, _, _, lane = _intent(spec, root, intent_path)
    if lane.campaign_name != expected_campaign:
        raise ValueError("host epoch authority belongs to another campaign")
    directory = intent_path.parent
    if (directory / "host-process.json").exists() or (directory / "retirement.json").exists():
        raise ValueError("host epoch intent was already attempted to completion or retirement")
    declaration = _child(root, intent["epoch_declaration"])
    if (declaration.parent / "commit.json").exists() or (declaration.parent / "retirement.json").exists():
        raise ValueError("host epoch block was already committed or retired")
    return executed_image_epoch_check({"spec": spec.serializable(), "root": str(root),
                                      "declaration": str(declaration)})


IMAGE_SCRIPT = (
    "import json,sys; from qcsd_lab.rapid_class_epochs import executed_image_epoch_check; "
    "print(json.dumps(executed_image_epoch_check(json.loads(sys.argv[1])),sort_keys=True,allow_nan=False))"
)


def image_check_command(spec: lanes.CaptureSpec, root: Path, declaration: Path) -> list[str]:
    policy = _open(root / "policy.json", POLICY_TYPE)
    reference = policy["image_check"]["execution"].get("capture_control_installation")
    capsule_path = None
    if reference is not None:
        if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not Path(reference["path"]).is_absolute()
            or _sha(admission._read(Path(reference["path"]))) != reference["sha256"]):
            raise ValueError("epoch image check changed its sealed capture-control installation")
        capsule_path = Path(reference["path"])
    command = lanes.image_check_command(spec, capture_control_installation=capsule_path, inherit_environment=False)
    command[-2:] = [IMAGE_SCRIPT, json.dumps({"spec": spec.serializable(), "root": str(root),
                                           "declaration": str(declaration)}, sort_keys=True)]
    return command


def _verified_check(spec: lanes.CaptureSpec, root: Path, declaration: Path, checked: Mapping[str, Any]) -> None:
    execution = checked["execution"]
    proof = checked["proof"]
    if (type(execution["returncode"]) is not int or execution["returncode"] != 0
        or execution["command"] != image_check_command(spec, root, declaration)
        or execution["validator_script_sha256"] != _sha(IMAGE_SCRIPT.encode())
        or admission._load(lanes._object(root, execution["stdout"])) != proof):
        raise ValueError("epoch launch lacks the actual matching installed-image execution")
    lanes._object(root, execution["stderr"])
    _check_keys(proof, {"schema_version", "artifact_type", "base_proof", "policy", "declaration",
                       "effective_sites", "scientific_credit"}, "epoch image proof")
    if (type(proof["schema_version"]) is not int or proof["schema_version"] != 1
        or proof["artifact_type"] != IMAGE_TYPE or proof["scientific_credit"] is not False
        or proof["policy"] != _reference(root, root / "policy.json")
        or proof["declaration"] != _reference(root, declaration)):
        raise ValueError("epoch image check belongs to another declared block")
    lanes._validate_image_proof(proof["base_proof"], spec)
    block, sites = verify_block(spec, root, declaration)
    if proof["effective_sites"] != [asdict(site) for site in sites]:
        raise ValueError("epoch image check changed the declared class vector")
    if not _time(block["declared_at"]) <= _time(execution["started_at"]) <= _time(execution["completed_at"]) <= _time(admission._now()):
        raise ValueError("epoch image check predates its prospective declaration")


@_operation
def check_bound_image(spec: lanes.CaptureSpec, root: Path, declaration: Path) -> dict[str, Any]:
    command = image_check_command(spec, root, declaration)
    started = admission._now()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=300, check=False)
    record = {"command": command, "returncode": result.returncode, "started_at": started,
              "completed_at": admission._now(), "stdout": lanes._put_object(root, result.stdout.encode()),
              "stderr": lanes._put_object(root, result.stderr.encode()),
              "validator_script_sha256": _sha(IMAGE_SCRIPT.encode())}
    durable_create(root / f"epoch-image-check-{_sha(admission._json(record))}.json", admission._json(record))
    if result.returncode != 0:
        raise ValueError("bound image rejected the epoch block; actual raw execution retained")
    checked = {"execution": record, "proof": admission._load(result.stdout.encode())}
    _verified_check(spec, root, declaration, checked)
    return checked


def _runtime_identity(proof: Mapping[str, Any]) -> dict[str, Any]:
    return {key: proof[key] for key in ("collection_image_digest", "runtime_source", "client_sha256",
                                        "base_launcher_sha256", "host_launcher_sha256", "traffic_hashes")}


@_memoized
def _intent(spec: lanes.CaptureSpec, root: Path, path: Path) -> tuple[dict[str, Any], dict[str, Any], tuple[plan.Site, ...], plan.Lane]:
    from . import rapid_runtime_epochs as runtime_epochs
    if runtime_epochs._kind(path) == runtime_epochs.INTENT_TYPE:
        return runtime_epochs.validate_intent(spec, root, path)
    value = _open(path, lanes.INTENT_TYPE)
    _check_keys(value, {"campaign_name", "campaign_sha256", "logical_lane", "generation", "bindings",
                       "runtime_identity", "lineage", "started_at", "actuator", "scientific_credit",
                       "epoch_declaration", "mode", "image_check", "predecessor_intent",
                       "predecessor_attempt"}, "epoch launch intent")
    declaration = _child(root, value["epoch_declaration"])
    block, sites = verify_block(spec, root, declaration)
    lane = _epoch_lane(block, sites, value["mode"], value["generation"])
    raw = render_epoch_lane(lane, sites, block["ordinal"])
    if (path != declaration.parent / "lanes" / lane.campaign_name / "intent.json"
        or value["actuator"] not in {"run", "parallel-formal-worker"} or value["scientific_credit"] is not False
        or value["campaign_name"] != lane.campaign_name or value["logical_lane"] != lane.logical_name
        or value["campaign_sha256"] != _sha(raw)
        or admission._read(spec.campaign_dir / f"{lane.campaign_name}.yml") != raw
        or not _time(block["declared_at"]) <= _time(value["started_at"]) <= _time(admission._now())):
        raise ValueError("epoch launch changes its declared workload/condition/physical namespace")
    _verified_check(spec, root, declaration, value["image_check"])
    base = value["image_check"]["proof"]["base_proof"]
    if (value["bindings"] != base["bindings"] or value["runtime_identity"] != _runtime_identity(base)
        or value["lineage"] != value["epoch_declaration"]
        or _time(value["started_at"]) < _time(value["image_check"]["execution"]["completed_at"])):
        raise ValueError("epoch intent differs from its actual installed-source/traffic check")
    if (root / "runtime-epochs/policy.json").is_file():
        runtime_policy = runtime_epochs.verify_policy(spec, root)
        if _time(value["started_at"]) < _time(runtime_policy["published_at"]):
            raise ValueError("historical formal launch predates prospective collection runtime authority")
    if lane.generation == 1:
        if value["predecessor_intent"] is not None or value["predecessor_attempt"] is not None:
            raise ValueError("initial epoch lane invents ordinary retry history")
    else:
        previous_lane = _epoch_lane(block, sites, lane.mode, lane.generation - 1)
        previous_path = path.parent.parent / previous_lane.campaign_name / "intent.json"
        if value["predecessor_intent"] != _reference(root, previous_path) or (previous_path.parent / "complete.json").exists():
            raise ValueError("ordinary epoch retry skips its immediate incomplete predecessor")
        previous, _, _, _ = _intent(spec, root, previous_path)
        if previous["runtime_identity"] != value["runtime_identity"] or previous["epoch_declaration"] != value["epoch_declaration"]:
            raise ValueError("g02 cannot change source, traffic settings or class epochs")
        _incomplete_predecessor(spec, root, previous_path, previous_lane)
        if value["predecessor_attempt"] != _attempt_inventory(spec, root, previous_path, previous_lane):
            raise ValueError("epoch successor changed or omitted its actual predecessor evidence")
    return value, block, sites, lane


def _terminal_process(spec: lanes.CaptureSpec, root: Path, intent: Path, lane: plan.Lane) -> dict[str, Any]:
    directory = intent.parent
    process = directory / "host-process.json"
    retirement = directory / "retirement.json"
    if not process.is_file() and not retirement.is_file():
        raise ValueError("epoch launch is active or lacks verified actual retirement")
    if process.is_file():
        intent_raw = admission._read(intent)
        value = lanes._verified_host_process(admission._read(process), root, intent_raw, lane.campaign_name)
        if ((value.get("actuator") == "parallel-formal-worker")
                != (lanes._host_intent(intent_raw).get("actuator", "run") == "parallel-formal-worker")):
            raise ValueError("epoch process actuator differs from its bound launch intent")
        if not lanes._process_matches_lane(value, spec, lane.campaign_name):
            raise ValueError("epoch process command differs from its bound physical lane")
        if value.get("actuator") == "parallel-formal-worker":
            return value  # The typed validator reopens actual Docker retirement and absence.
        start = lanes._validated_host_start(lanes._object(root, value["start"]), admission._read(intent), campaign_name=lane.campaign_name)
        for key in ("host", "supervisor"):
            lanes._retired_identity(start[key])
        return value
    return lanes._verified_retirement(admission._read(retirement), root, admission._read(intent), lane.campaign_name)


def _incomplete_predecessor(spec: lanes.CaptureSpec, root: Path, path: Path, lane: plan.Lane) -> None:
    """Receipt publication failure cannot turn a complete flight into a retry."""
    _terminal_process(spec, root, path, lane)
    namespace = spec.execution_root / "results" / lane.campaign_name
    if not namespace.exists():
        return  # Actual terminal launch failed before allocating any result.
    if namespace.is_symlink() or not namespace.is_dir():
        raise ValueError("incomplete predecessor has a linked or invalid result namespace")
    children = list(namespace.iterdir())
    if len(children) > 1 or any(item.is_symlink() or not item.is_dir() for item in children):
        raise ValueError("incomplete predecessor hides or repeats a physical result")
    for result in children:
        experiment_path = result / "experiment.json"
        if not experiment_path.exists():
            if (result / "evidence.sha256").exists():
                raise ValueError("incomplete predecessor seal has no actual experiment")
            continue  # Retired pre-checkpoint allocation retains zero authority.
        experiment = (verify_result(result).experiment if (result / "evidence.sha256").exists()
                      else admission._load(admission._read(experiment_path)))
        intent = lanes._host_intent(admission._read(path))
        if (experiment["status"] not in {"running", "incomplete"}
            or experiment["name"] != lane.campaign_name
            or experiment["configuration"]["campaign_sha256"] != intent["campaign_sha256"]
            or experiment["source"] != intent["runtime_identity"]["runtime_source"]):
            raise ValueError("ordinary epoch retry requires actual incomplete predecessor capture")


def _attempt_inventory(spec: lanes.CaptureSpec, root: Path, path: Path, lane: plan.Lane) -> dict[str, Any]:
    files = {}
    for item in sorted(path.parent.rglob("*")):
        if item.is_symlink() or not item.is_dir() and not item.is_file():
            raise ValueError("epoch physical attempt inventory contains linked or special evidence")
        if item.is_file():
            raw = admission._read(item)
            files[item.relative_to(path.parent).as_posix()] = {"sha256": _sha(raw), "size": len(raw)}
    return {"intent": _reference(root, path), "lane_inventory": files,
            "result_inventory": _result_inventory(spec, lane)}


@_operation
def prepare_block_lane_intent(spec: lanes.CaptureSpec, root: Path, declaration: Path, *, mode: str,
                              generation: int = 1, predecessor_intent: Path | None = None,
                              checked: Mapping[str, Any] | None = None, actuator: str = "run") -> Path:
    """Claim one create-only block lane; the caller holds its capture lock."""
    if actuator not in {"run", "parallel-formal-worker"}:
        raise ValueError("epoch lane requires an explicit supported actuator")
    root = lanes._regular_directory(root)
    block, sites = verify_block(spec, root, declaration)
    if (declaration.parent / "commit.json").exists() or (declaration.parent / "retirement.json").exists():
        raise ValueError("committed or retired block cannot launch more captures")
    lane = _epoch_lane(block, sites, mode, generation)
    directory = declaration.parent / "lanes" / lane.campaign_name
    namespace = spec.execution_root / "results" / lane.campaign_name
    if directory.exists() or directory.is_symlink() or namespace.exists() or namespace.is_symlink():
        raise FileExistsError("epoch physical lane namespace was previously claimed")
    if generation == 1 and predecessor_intent is not None:
        raise ValueError("initial epoch lane cannot consume a predecessor")
    if generation > 1:
        previous_lane = _epoch_lane(block, sites, mode, generation - 1)
        expected_path = declaration.parent / "lanes" / previous_lane.campaign_name / "intent.json"
        if predecessor_intent != expected_path or (expected_path.parent / "complete.json").exists():
            raise ValueError("ordinary epoch retry requires its actual immediate incomplete predecessor")
        _intent(spec, root, expected_path)
        _incomplete_predecessor(spec, root, expected_path, previous_lane)
    campaign = spec.campaign_dir / f"{lane.campaign_name}.yml"
    raw = render_epoch_lane(lane, sites, block["ordinal"])
    if generation > 1:
        durable_create(campaign, raw)
    elif admission._read(campaign) != raw:
        raise ValueError("initial epoch campaign differs from its declaration")
    if checked is None:
        checked = check_bound_image(spec, root, declaration)
    else:
        _verified_check(spec, root, declaration, checked)
    base = checked["proof"]["base_proof"]
    directory.mkdir(parents=True)
    intent = {"campaign_name": lane.campaign_name, "campaign_sha256": _sha(raw),
              "logical_lane": lane.logical_name, "generation": generation, "bindings": base["bindings"],
              "runtime_identity": _runtime_identity(base), "lineage": _reference(root, declaration),
              "started_at": admission._now(), "actuator": actuator, "scientific_credit": False,
              "epoch_declaration": _reference(root, declaration), "mode": mode, "image_check": checked,
              "predecessor_intent": _reference(root, predecessor_intent) if predecessor_intent else None,
              "predecessor_attempt": _attempt_inventory(spec, root, expected_path, previous_lane)
              if predecessor_intent else None}
    return _write(directory / "intent.json", lanes.INTENT_TYPE, intent)


@_operation
def launch_block_lane(spec: lanes.CaptureSpec, root: Path, declaration: Path, *, mode: str,
                        generation: int = 1, predecessor_intent: Path | None = None) -> Path:
    """Use the existing guarded host/DNS actuator with explicit epoch authority."""
    root = lanes._regular_directory(root)
    with lanes.capture_lock(spec.execution_root) as descriptor:
        output = prepare_block_lane_intent(spec, root, declaration, mode=mode, generation=generation,
                                          predecessor_intent=predecessor_intent)
        directory = output.parent
        campaign = spec.campaign_dir / f"{directory.name}.yml"
        env = dict(os.environ)
        env.update(QCSD_LAB_COLLECTION_IMAGE=spec.collection_image_digest,
                   QCSD_RAPID_IMAGE_SOURCE_QCSD=str(spec.base_launcher),
                   QCSD_RAPID_V5_PROFILE_PATH=str(lanes._study_profile(spec.execution_root)),
                   QCSD_RAPID_DNS_RECEIPT_PATH=str(directory / "dns.json"))
        env["QCSD_RAPID_EPOCH_LAUNCH_INPUT"] = json.dumps({
            "spec": spec.serializable(), "root": str(root), "intent": str(output),
            "intent_sha256": _sha(admission._read(output))}, sort_keys=True)
        reference = verify_policy(spec, root)["image_check"]["execution"].get("capture_control_installation")
        if reference is not None:
            env["QCSD_RAPID_COLLECTION_COMPATIBILITY"] = reference["path"]
            env["QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"] = reference["path"]
        command = [str(spec.host_launcher), "run", str(campaign)]
        lanes._actuate_host(spec, root, directory, command, env, descriptor)
        _clear_validation_cache()
        complete = complete_lane(spec, root, output)
        if _open(directory / "host-process.json", lanes.PROCESS_TYPE)["returncode"] != 0:
            raise RuntimeError("epoch trace completed but actual host exit requires lifecycle diagnosis")
        return complete


@_memoized
def _deep_lane(spec: lanes.CaptureSpec, root: Path, intent_path: Path) -> dict[str, Any]:
    intent, block, sites, lane = _intent(spec, root, intent_path)
    from .rapid_runtime_epochs import runtime_for_intent
    runtime = runtime_for_intent(spec, root, intent)
    process = _terminal_process(runtime, root, intent_path, lane)
    if process.get("returncode") is None or process.get("interruption") is not None:
        raise ValueError("interrupted epoch lane needs an unchanged-input fresh g02 retry")
    parallel = process.get("actuator") == "parallel-formal-worker"
    if parallel and process["returncode"] != 0:
        raise ValueError("a failed formal worker cannot produce an epoch completion receipt")
    namespace = spec.execution_root / "results" / lane.campaign_name
    children = list(namespace.iterdir())
    if len(children) != 1 or children[0].is_symlink() or not children[0].is_dir():
        raise ValueError("epoch physical lane must own exactly one result root")
    result = children[0]
    experiment = admission._load(admission._read(result / "experiment.json"))
    if not (_time(process["started_at"]) <= _time(experiment["started_at"])
            <= _time(experiment["completed_at"]) <= _time(process["completed_at"])):
        raise ValueError("epoch capture timestamps lie outside its actual bound host execution")
    workloads = {site.workload_id: admission._read(spec.workload_root / f"{site.workload_id}.json")
                 for site in sites if site.workload_id in lane.workload_ids}
    if any(_sha(workloads[site.workload_id]) != site.workload_sha256
           for site in sites if site.workload_id in lane.workload_ids):
        raise ValueError("epoch workload bytes changed during actual capture")
    dns = lanes.verify_dns_receipt(admission._read(intent_path.parent / "dns.json"), lane.campaign_name, workloads)
    checked = plan.verify_lane_result(result, lane, collection_image_digest=runtime.collection_image_digest,
        lab_commit=intent["runtime_identity"]["runtime_source"]["lab_commit"], campaign_sha256=intent["campaign_sha256"],
        workload_sha256s={key: _sha(raw) for key, raw in workloads.items()},
        qualification_set_manifest_sha256=block["qualification"]["manifest_sha256"] if lane.qualification_set else None,
        block_epoch=block["ordinal"])
    if parallel:
        from .rapid_formal_parallel import verify_worker_result
        verify_worker_result(process, result)
    return {"intent": _reference(root, intent_path), "declaration": intent["epoch_declaration"],
            "mode": lane.mode, "generation": lane.generation, "campaign_name": lane.campaign_name,
            "result_relpath": result.relative_to(spec.execution_root / "results").as_posix(),
            "result_seal_sha256": checked["result_seal_sha256"], "dns_sha256": dns,
            "accepted": lane.sample_count, "scientific_credit": "conditional-on-matched-block-commit",
            **({"runtime_epoch": intent["runtime_epoch"]} if "runtime_epoch" in intent else {})}


@_operation
def complete_lane(spec: lanes.CaptureSpec, root: Path, intent: Path) -> Path:
    value = _deep_lane(spec, root, intent)
    value["completed_at"] = admission._now()
    from . import rapid_runtime_epochs as runtime_epochs
    kind = runtime_epochs.COMPLETE_TYPE if "runtime_epoch" in value else COMPLETE_TYPE
    return _write(intent.parent / "complete.json", kind, value)


@_memoized
def verify_lane(spec: lanes.CaptureSpec, root: Path, path: Path) -> dict[str, Any]:
    from . import rapid_runtime_epochs as runtime_epochs
    kind = runtime_epochs._kind(path)
    if kind not in {COMPLETE_TYPE, runtime_epochs.COMPLETE_TYPE}:
        raise ValueError("unknown matched-block lane completion")
    value = _open(path, kind)
    checked = _deep_lane(spec, root, _child(root, value["intent"]))
    if {key: item for key, item in value.items() if key != "completed_at"} != checked:
        raise ValueError("epoch completion differs from independently reopened capture")
    intent_raw = admission._read(_child(root, value["intent"]))
    intent = lanes._host_intent(intent_raw)
    if ("runtime_epoch" in value) != (kind == runtime_epochs.COMPLETE_TYPE):
        raise ValueError("historical completion cannot acquire collection runtime authority")
    process = lanes._verified_host_process(admission._read(path.parent / "host-process.json"), root,
                                           intent_raw, value["campaign_name"])
    if process.get("actuator") == "parallel-formal-worker":
        from .rapid_formal_parallel import require_batch_closure
        require_batch_closure(process)
    if not _time(intent["started_at"]) <= _time(process["completed_at"]) <= _time(value["completed_at"]) <= _time(admission._now()):
        raise ValueError("epoch completion chronology is invalid")
    return value


@_operation
def retire_lane(spec: lanes.CaptureSpec, root: Path, intent_path: Path) -> Path:
    """Retain real process/Docker retirement after an interrupted epoch worker."""
    with lanes.capture_lock(spec.execution_root):
        _, _, _, lane = _intent(spec, root, intent_path)
        directory = intent_path.parent
        if (directory / "complete.json").exists() or (directory / "host-process.json").exists():
            raise ValueError("epoch lane already has actual terminal process evidence")
        start_raw = admission._read(directory / "host-start.json")
        start = lanes._validated_host_start(start_raw, admission._read(intent_path), campaign_name=lane.campaign_name)
        retired = {key: lanes._retired_identity(start[key]) for key in ("host", "supervisor")}
        with lanes.capture_lock(spec.execution_root, lifecycle=True) as descriptor:
            checks = lanes._retirement_quiescence(root, descriptor)
            if retired != {key: lanes._retired_identity(start[key]) for key in retired}:
                raise ValueError("epoch process census changed during actual retirement")
            value = {"command": start["command"], "execution_root": start["execution_root"],
                     "started_at": start["started_at"], "observed_at": admission._now(), "scientific_credit": False,
                     "host_start": lanes._put_object(root, start_raw), "retired_processes": retired, "checks": checks}
            return _write(directory / "retirement.json", lanes.RETIREMENT_TYPE, value)


def _block_launches(spec: lanes.CaptureSpec, root: Path, declaration: Path) -> list[Path]:
    directory = declaration.parent / "lanes"
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("matched block has no regular physical-lane inventory")
    paths = []
    allowed = {"intent.json", "host-start.json", "host-process.json", "retirement.json", "complete.json",
               "host.stdout.log", "host.stderr.log", "supervisor.stdout.log", "supervisor.stderr.log", "dns.json"}
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            raise ValueError("matched block contains a linked or unexpected physical-lane entry")
        if any(item.is_symlink() or not item.is_file() or item.name not in allowed for item in entry.iterdir()):
            raise ValueError("matched block physical-lane inventory is enlarged or linked")
        path = entry / "intent.json"
        if not path.is_file():
            raise ValueError("matched block cannot hide an interrupted physical lane without its intent")
        paths.append(path)
    if not paths:
        raise ValueError("matched block has no actual launched conditions")
    for path in paths:
        intent, _, _, lane = _intent(spec, root, path)
        if intent["epoch_declaration"] != _reference(root, declaration):
            raise ValueError("matched block contains another epoch's launch")
        _terminal_process(spec, root, path, lane)
    return paths


@_operation
def _observed_drift(spec: lanes.CaptureSpec, root: Path, declaration: Path) -> list[dict[str, Any]]:
    from .experiment import resolved_attempt_directory
    from .orchestrator import _prepared_response_identity_failure
    from types import SimpleNamespace
    _, sites = verify_block(spec, root, declaration)
    by_workload = {site.workload_id: site for site in sites}
    records = []
    for intent_path in _block_launches(spec, root, declaration):
        intent, _, _, lane = _intent(spec, root, intent_path)
        namespace = spec.execution_root / "results" / lane.campaign_name
        for result in sorted(namespace.iterdir()) if namespace.is_dir() else []:
            if not (result / "evidence.sha256").is_file():
                # An actually retired interrupted attempt has zero scientific
                # authority. Its whole raw inventory is retained separately;
                # it cannot supply the drift witness or any accepted slots.
                continue
            verified = verify_result(result)
            experiment = verified.experiment
            if (experiment["name"] != lane.campaign_name
                or experiment["configuration"]["campaign_sha256"] != intent["campaign_sha256"]
                or experiment["source"] != intent["runtime_identity"]["runtime_source"]):
                raise ValueError("observed drift came from another campaign or source")
            for sample in experiment["samples"]:
                if (sample.get("failure") or {}).get("type") != "StrictPreparedResponseIdentityFailure":
                    continue
                site = by_workload[sample["workload_id"]]
                manifest_raw = admission._read(spec.workload_root / f"{site.workload_id}.json")
                if _sha(manifest_raw) != site.workload_sha256:
                    raise ValueError("observed drift's frozen workload bytes changed")
                manifest = admission._load(manifest_raw)
                attempt = resolved_attempt_directory(result, sample)
                raw_run = admission._read(attempt / "neqo/run.json")
                run = admission._load(raw_run)
                # Transport loss is not application drift. All actual responses
                # must be complete and cover the original graph before refresh.
                responses = run.get("responses")
                identifiers = {item["id"] for item in manifest["resources"]}
                if (run.get("completion_status") != "complete" or run.get("error") is not None
                    or not isinstance(responses, list) or len(responses) != len(identifiers)
                    or {item.get("resource_id") for item in responses} != identifiers
                    or any(item.get("complete") is not True or item.get("outcome") != "succeeded" for item in responses)):
                    raise ValueError("block replacement requires complete response drift, not transport failure")
                by_id = {item["id"]: item for item in manifest["resources"]}
                if any(item.get("url") != by_id[item["resource_id"]]["url"] for item in responses):
                    raise ValueError("observed drift substitutes a frozen graph URL")
                observed = _prepared_response_identity_failure(SimpleNamespace(id=site.workload_id, data=manifest), attempt)
                if observed is None or sample["failure"] != observed:
                    raise ValueError("drift summary differs from the actual retained response ledger")
                record = {"candidate_id": site.candidate_id, "intent": _reference(root, intent_path),
                          "result_relpath": result.relative_to(spec.execution_root / "results").as_posix(),
                          "result_seal_sha256": _sha(admission._read(result / "evidence.sha256")),
                          "sample_id": sample["sample_id"], "run_sha256": _sha(raw_run), "failure": observed}
                records.append(record)
    if not records:
        raise ValueError("block replacement lacks observed raw application-response drift")
    return records


def _result_inventory(spec: lanes.CaptureSpec, lane: plan.Lane) -> dict[str, Any]:
    namespace = spec.execution_root / "results" / lane.campaign_name
    result = {}
    if namespace.exists():
        if namespace.is_symlink() or not namespace.is_dir():
            raise ValueError("retired result namespace is not a regular directory")
        for path in sorted(namespace.rglob("*")):
            if path.is_symlink():
                raise ValueError("retired raw result contains linked evidence")
            if path.is_file():
                raw = admission._read(path)
                result[path.relative_to(namespace).as_posix()] = {"sha256": _sha(raw), "size": len(raw)}
    return result


@_operation
def retire_block(spec: lanes.CaptureSpec, root: Path, declaration: Path) -> Path:
    """Retire only an attempted, uncommitted block after actual observed drift."""
    with lanes.capture_lock(spec.execution_root):
        block, _ = verify_block(spec, root, declaration)
        if (declaration.parent / "commit.json").exists():
            raise ValueError("a committed comparable block cannot be post-hoc replaced")
        drift = _observed_drift(spec, root, declaration)
        with lanes.capture_lock(spec.execution_root, lifecycle=True) as descriptor:
            checks = lanes._retirement_quiescence(root, descriptor)
            attempts = []
            for path in _block_launches(spec, root, declaration):
                _, _, _, lane = _intent(spec, root, path)
                start_path = path.parent / "host-start.json"
                start = lanes._validated_host_start(admission._read(start_path), admission._read(path),
                    campaign_name=lanes._host_intent(admission._read(path))["campaign_name"])
                attempts.append({"intent": _reference(root, path),
                    "host_start": _reference(root, start_path),
                    "retired_processes": {key: lanes._retired_identity(start[key]) for key in ("host", "supervisor")},
                    "result_inventory": _result_inventory(spec, lane),
                    "host_process": _reference(root, path.parent / "host-process.json")
                    if (path.parent / "host-process.json").is_file() else None,
                    "retirement": _reference(root, path.parent / "retirement.json")
                    if (path.parent / "retirement.json").is_file() else None})
            value = {"declaration": _reference(root, declaration), "block": block["block"],
                     "shard": block["shard"], "ordinal": block["ordinal"],
                     "drift": drift, "drifting_candidates": sorted({item["candidate_id"] for item in drift}),
                     "epochs": block["epochs"], "attempts": attempts, "checks": checks,
                     "observed_at": admission._now(), "scientific_credit": False}
            return _write(declaration.parent / "retirement.json", RETIREMENT_TYPE, value)


@_memoized
def verify_block_retirement(spec: lanes.CaptureSpec, root: Path, path: Path,
                             *, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    value = _open(path, RETIREMENT_TYPE)
    _check_keys(value, {"declaration", "block", "shard", "ordinal", "drift", "drifting_candidates", "epochs",
                       "attempts", "checks", "observed_at", "scientific_credit"}, "block retirement")
    declaration = _child(root, value["declaration"])
    block, _ = verify_block(spec, root, declaration, policy=policy)
    if (path != declaration.parent / "retirement.json" or (declaration.parent / "commit.json").exists()
        or value["scientific_credit"] is not False or value["epochs"] != block["epochs"]
        or any(type(value[key]) is not int or value[key] != block[key] for key in ("block", "shard", "ordinal"))
        or value["drift"] != _observed_drift(spec, root, declaration)
        or value["drifting_candidates"] != sorted({item["candidate_id"] for item in value["drift"]})
        or not _time(block["declared_at"]) <= _time(value["observed_at"]) <= _time(admission._now())):
        raise ValueError("block retirement differs from actual observed complete-response drift")
    actual = _block_launches(spec, root, declaration)
    if [item["intent"] for item in value["attempts"]] != [_reference(root, path) for path in actual]:
        raise ValueError("block retirement hides an active or additional physical attempt")
    checks = value["checks"]
    # Reuse the strict actual Docker/lifecycle observation validator by binding
    # each launch's actual host-start to the shared quiescence observation.
    for path, entry in zip(actual, value["attempts"], strict=True):
        _check_keys(entry, {"intent", "host_process", "retirement", "host_start", "retired_processes", "result_inventory"}, "block retired launch")
        _, _, _, lane = _intent(spec, root, path)
        terminal = _terminal_process(spec, root, path, lane)
        if _time(terminal.get("completed_at", terminal.get("observed_at"))) > _time(value["observed_at"]):
            raise ValueError("block retirement predates its actual terminal host or lane retirement")
        if entry["result_inventory"] != _result_inventory(spec, lane):
            raise ValueError("retired block raw capture inventory changed")
        for key, filename in (("host_process", "host-process.json"), ("retirement", "retirement.json")):
            expected = _reference(root, path.parent / filename) if (path.parent / filename).is_file() else None
            if entry[key] != expected:
                raise ValueError("block retirement changed its actual terminal process inventory")
        start_raw = admission._read(path.parent / "host-start.json")
        if entry["host_start"] != _reference(root, path.parent / "host-start.json"):
            raise ValueError("block retirement substitutes actual process birth evidence")
        start = lanes._validated_host_start(start_raw, admission._read(path), campaign_name=lanes._host_intent(admission._read(path))["campaign_name"])
        observed = {"command": start["command"], "execution_root": start["execution_root"],
                    "started_at": start["started_at"], "observed_at": value["observed_at"],
                    "scientific_credit": False, "host_start": entry["host_start"],
                    "retired_processes": entry["retired_processes"], "checks": checks}
        # No generated observation is published. The real census and Docker
        # outputs were retained by retire_block while both locks were held.
        lanes._verified_retirement(admission._json(admission._bind(lanes.RETIREMENT_TYPE, observed)),
                                   root, admission._read(path), lanes._host_intent(admission._read(path))["campaign_name"])
    return value


@_operation
def commit_block(spec: lanes.CaptureSpec, root: Path, declaration: Path) -> Path:
    """Select a matched block explicitly; every physical attempt stays visible."""
    with lanes.capture_lock(spec.execution_root):
        block, _ = verify_block(spec, root, declaration)
        if (declaration.parent / "retirement.json").exists():
            raise ValueError("a retired block cannot gain formal credit")
        attempts = _block_launches(spec, root, declaration)
        selected = {}
        for path in sorted((declaration.parent / "lanes").glob("*/complete.json")):
            facts = verify_lane(spec, root, path)
            if facts["mode"] in selected:
                raise ValueError("block repeats a completed physical condition")
            selected[facts["mode"]] = _reference(root, path)
        if set(selected) != set(plan.MODES):
            raise ValueError("matched block needs all five complete deep-verified conditions")
        value = {"declaration": _reference(root, declaration), "selected_lanes": selected,
                 "block": block["block"], "shard": block["shard"], "ordinal": block["ordinal"],
                 "accepted": BLOCK_SAMPLE_COUNT, "committed_at": admission._now(),
                 "unselected_attempts": [_attempt_inventory(spec, root, path, _intent(spec, root, path)[3])
                                         for path in attempts if not (path.parent / "complete.json").exists()],
                 "scientific_credit": "formal-only-in-complete-160-block-corpus"}
        return _write(declaration.parent / "commit.json", COMMIT_TYPE, value)


@_memoized
def verify_commit(spec: lanes.CaptureSpec, root: Path, path: Path) -> dict[str, Any]:
    value = _open(path, COMMIT_TYPE)
    _check_keys(value, {"declaration", "selected_lanes", "block", "shard", "ordinal", "accepted",
                       "committed_at", "unselected_attempts", "scientific_credit"}, "matched block commit")
    declaration = _child(root, value["declaration"])
    block, _ = verify_block(spec, root, declaration)
    if (path != declaration.parent / "commit.json" or (declaration.parent / "retirement.json").exists()
        or type(value["accepted"]) is not int or value["accepted"] != BLOCK_SAMPLE_COUNT
        or any(type(value[key]) is not int or value[key] != block[key] for key in ("block", "shard", "ordinal"))
        or value["scientific_credit"] != "formal-only-in-complete-160-block-corpus"
        or set(value["selected_lanes"]) != set(plan.MODES)):
        raise ValueError("matched block commit changes its authority or sample arithmetic")
    attempts = _block_launches(spec, root, declaration)
    unselected = [_attempt_inventory(spec, root, item, _intent(spec, root, item)[3])
                  for item in attempts if not (item.parent / "complete.json").exists()]
    if value["unselected_attempts"] != unselected:
        raise ValueError("matched block commit changed or omitted actual unselected capture attempts")
    complete_paths = sorted((declaration.parent / "lanes").glob("*/complete.json"))
    if set(tuple(sorted(_reference(root, item).items())) for item in complete_paths) != set(
        tuple(sorted(item.items())) for item in value["selected_lanes"].values()):
        raise ValueError("block commit omits or repeats a completed condition")
    for mode in plan.MODES:
        facts = verify_lane(spec, root, _child(root, value["selected_lanes"][mode]))
        if facts["mode"] != mode or facts["declaration"] != value["declaration"]:
            raise ValueError("block conditions use different class epoch vectors")
        if not _time(facts["completed_at"]) <= _time(value["committed_at"]) <= _time(admission._now()):
            raise ValueError("block commit predates actual completion")
    return value


@_operation
def corpus_manifest(spec: lanes.CaptureSpec, root: Path) -> dict[str, Any]:
    """Reopen exactly 160 explicit block commits, disclosing every retired epoch."""
    policy = verify_policy(spec, root)
    registered = []
    expected_classes = {item["candidate_id"] for item in policy["classes"]}
    if {item.name for item in (root / "classes").iterdir()} != expected_classes:
        raise ValueError("epoch corpus changes or hides the registered class inventory")
    for row in policy["classes"]:
        directory = root / "classes" / row["candidate_id"]
        files = sorted(directory.iterdir())
        if [path.name for path in files] != [f"e{index:04d}.json" for index in range(1, len(files) + 1)]:
            raise ValueError("epoch corpus skips or hides a registered class epoch")
        for path in files:
            verify_class_epoch(spec, root, path, policy=policy)
            registered.append({"candidate_id": row["candidate_id"], "receipt": _reference(root, path)})
    selected = {}
    histories = {}
    directories = []
    for logical in sorted((root / "blocks").iterdir()) if (root / "blocks").is_dir() else []:
        if logical.is_symlink() or not logical.is_dir() or re.fullmatch(r"b[0-9]{2}-s[0-9]{2}", logical.name) is None:
            raise ValueError("epoch corpus has an unexpected logical block inventory entry")
        directories.extend(sorted(logical.iterdir()))
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("epoch block inventory has a linked or unexpected entry")
        declaration = directory / "declaration.json"
        block, _ = verify_block(spec, root, declaration, policy=policy)
        key = (block["block"], block["shard"])
        histories.setdefault(key, []).append(block["ordinal"])
        commit = directory / "commit.json"
        retirement = directory / "retirement.json"
        if commit.is_file():
            verify_commit(spec, root, commit)
            if key in selected:
                raise ValueError("formal corpus has two committed epochs for one logical block")
            selected[key] = _reference(root, commit)
        elif retirement.is_file():
            verify_block_retirement(spec, root, retirement, policy=policy)
        else:
            raise ValueError("formal corpus cannot hide an unfinished or unretired block epoch")
    expected = {(block, shard) for block in range(1, plan.FINAL_BLOCKS + 1)
                for shard in range(1, plan.FINAL_CLASS_COUNT // plan.SHARD_SIZE + 1)}
    if set(selected) != expected:
        raise ValueError("formal corpus needs exactly 160 committed matched blocks")
    for key, ordinals in histories.items():
        if ordinals != list(range(1, len(ordinals) + 1)):
            raise ValueError("formal corpus skips a claimed predecessor block epoch")
        commit = _open(_child(root, selected[key]), COMMIT_TYPE)
        if commit["ordinal"] != ordinals[-1]:
            raise ValueError("formal corpus selects an epoch before a subsequent attempted replacement")
    counts = Counter()
    for key in sorted(expected):
        commit = verify_commit(spec, root, _child(root, selected[key]))
        declaration, _ = verify_block(spec, root, _child(root, commit["declaration"]), policy=policy)
        for item in declaration["epochs"]:
            for mode in plan.MODES:
                counts[(item["candidate_id"], mode)] += plan.FINAL_VISITS_PER_BLOCK
    if (len(counts) != plan.FINAL_CLASS_COUNT * len(plan.MODES)
        or set(counts.values()) != {plan.FINAL_BLOCKS * plan.FINAL_VISITS_PER_BLOCK}
        or sum(counts.values()) != plan.FINAL_SAMPLE_TARGET):
        raise ValueError("epoch corpus does not contain exactly 50 by five by 64 formal traces")
    from . import rapid_runtime_epochs as runtime_epochs
    prospective = (root / "runtime-epochs/policy.json").is_file()
    runtime_inventory = []
    if prospective:
        runtime_epochs.verify_policy(spec, root)
        directories = sorted((root / "runtime-epochs").glob("e[0-9][0-9][0-9][0-9]"))
        if ({item.name for item in (root / "runtime-epochs").iterdir()}
            != {"policy.json", *(item.name for item in directories)}
            or any(item.is_symlink() or not item.is_dir() for item in directories)):
            raise ValueError("runtime corpus contains an unregistered collection epoch")
        if [item.name for item in directories] != [f"e{ordinal:04d}" for ordinal in range(2, len(directories) + 2)]:
            raise ValueError("runtime corpus skips a claimed collection epoch")
        for directory in directories:
            activation = directory / "activation.json"
            retirement = directory / "retirement.json"
            if activation.is_file():
                runtime_epochs.verify_activation(spec, root, activation)
                runtime_inventory.append({"activation": _reference(root, activation)})
            elif retirement.is_file():
                runtime_epochs.verify_candidate_retirement(spec, root, retirement)
                runtime_inventory.append({"retirement": _reference(root, retirement)})
            else:
                raise ValueError("runtime corpus cannot hide an unactivated or unretired collection candidate")
    return {"schema_version": 1, "artifact_type": runtime_epochs.CORPUS_TYPE if prospective else CORPUS_TYPE,
            "policy": _reference(root, root / "policy.json"),
            "registered_class_epochs": registered,
            "blocks": [{"block": key[0], "shard": key[1], "commit": selected[key]} for key in sorted(expected)],
            **({"collection_runtime_policy": _reference(root, root / "runtime-epochs/policy.json"),
                "collection_runtime_epochs": runtime_inventory} if prospective else {}),
            "accepted": plan.FINAL_SAMPLE_TARGET}


@_operation
def verify_corpus_manifest(spec: lanes.CaptureSpec, root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != corpus_manifest(spec, root):
        raise ValueError("epoch corpus manifest differs from independently reopened explicit block selections")
    return {"valid": True, "accepted": plan.FINAL_SAMPLE_TARGET,
            "classes": plan.FINAL_CLASS_COUNT, "conditions": len(plan.MODES), "blocks": BLOCK_COUNT}


@_operation
def publish_corpus_manifest(spec: lanes.CaptureSpec, root: Path, output: Path) -> dict[str, Any]:
    manifest = corpus_manifest(spec, root)
    if output.parent != root:
        raise ValueError("epoch corpus publication must use its explicit evidence root")
    durable_create(output, admission._json(manifest))
    return {"valid": True, "accepted": plan.FINAL_SAMPLE_TARGET, "manifest_sha256": _sha(admission._read(output))}


CORPUS_SCRIPT = (
    "import json,sys; from pathlib import Path; from qcsd_lab import rapid_class_epochs as e; "
    "from qcsd_lab import rapid_lane_evidence as l; v=json.loads(sys.argv[1]); "
    "s=l.CaptureSpec(**{k:Path(x) if k in l.PATH_KEYS else x for k,x in v['spec'].items()}); "
    "r=Path(v['root']); l.executed_image_plan_check(s.serializable()); "
    "f=e.publish_corpus_manifest(s,r,Path(v['path'])) if v['publish'] "
    "else e.verify_corpus_manifest(s,r,e.admission._load(e.admission._read(Path(v['path'])))); "
    "print(json.dumps(f,sort_keys=True,allow_nan=False))"
)


def check_corpus_in_image(spec: lanes.CaptureSpec, root: Path, path: Path, *, publish: bool) -> dict[str, Any]:
    """The operator's final corpus action runs the closure in the bound image."""
    if path.parent != root:
        raise ValueError("epoch corpus action must use its explicit evidence root")
    policy = verify_policy(spec, root)
    reference = policy["image_check"]["execution"].get("capture_control_installation")
    command = lanes.image_check_command(spec,
        capture_control_installation=Path(reference["path"]) if reference is not None else None,
        inherit_environment=False)
    index = command.index("--entrypoint")
    command[index:index] = ["--volume", f"{root}:{root}:{'rw' if publish else 'ro'}"]
    command[-2:] = [CORPUS_SCRIPT, json.dumps({"spec": spec.serializable(), "root": str(root),
                                           "path": str(path), "publish": publish}, sort_keys=True)]
    started = admission._now()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    record = {"command": command, "returncode": result.returncode, "started_at": started,
              "completed_at": admission._now(), "stdout": lanes._put_object(root, result.stdout.encode()),
              "stderr": lanes._put_object(root, result.stderr.encode()),
              "validator_script_sha256": _sha(CORPUS_SCRIPT.encode())}
    durable_create(root / f"epoch-corpus-check-{_sha(admission._json(record))}.json", admission._json(record))
    if result.returncode:
        raise ValueError("bound image rejected epoch corpus closure; actual raw execution retained")
    facts = admission._load(result.stdout.encode())
    if facts.get("valid") is not True or type(facts.get("accepted")) is not int or facts["accepted"] != plan.FINAL_SAMPLE_TARGET:
        raise ValueError("bound image did not independently close all 16,000 formal traces")
    return facts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("initialize", "verify-policy", "register-class", "declare-block", "launch-lane", "verify-lane",
                 "complete-lane", "retire-lane", "retire-block", "commit-block", "publish-manifest", "verify-manifest"):
        command = commands.add_parser(name)
        command.add_argument("--spec", type=Path, required=True, help="unchanged portable final-50 operator spec")
        command.add_argument("--evidence-root", type=Path, required=True, help="separate create-only epoch evidence tree")
        if name == "initialize":
            command.add_argument("--installation", type=Path, help="closed zero-credit capture-control capsule in this evidence root")
        elif name == "register-class":
            command.add_argument("--candidate-id", required=True)
            for flag in ("workload", "graph", "retirement"):
                command.add_argument(f"--{flag}", type=Path, required=True)
        elif name == "declare-block":
            command.add_argument("--block", type=int, required=True)
            command.add_argument("--shard", type=int, required=True)
            command.add_argument("--qualification-manifest", type=Path, required=True)
            command.add_argument("--class-epoch", action="append", default=[], metavar="CANDIDATE=PATH")
            command.add_argument("--predecessor-retirement", type=Path)
        elif name in {"launch-lane", "retire-block", "commit-block"}:
            command.add_argument("--declaration", type=Path, required=True)
            if name == "launch-lane":
                command.add_argument("--mode", choices=plan.MODES, required=True)
                command.add_argument("--generation", type=int, default=1)
                command.add_argument("--predecessor-intent", type=Path)
        elif name == "verify-lane":
            command.add_argument("--receipt", type=Path, required=True)
        elif name in {"retire-lane", "complete-lane"}:
            command.add_argument("--intent", type=Path, required=True)
        elif name == "publish-manifest":
            command.add_argument("--output", type=Path, required=True)
        elif name == "verify-manifest":
            command.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        spec = lanes.load_capture_spec(args.spec)
        root = lanes._regular_directory(args.evidence_root)
        path = None
        if args.command == "initialize":
            path = initialize_study(spec, root, installation=args.installation)
        elif args.command == "verify-policy":
            verify_policy(spec, root)
        elif args.command == "register-class":
            path = register_class_epoch(spec, root, candidate_id=args.candidate_id,
                workload=args.workload.absolute(), graph=args.graph.absolute(), retirement=args.retirement.absolute())
        elif args.command == "declare-block":
            overrides = {}
            for item in args.class_epoch:
                candidate, separator, reference = item.partition("=")
                if not separator or not reference or candidate in overrides:
                    raise ValueError("class epoch arguments must be distinct CANDIDATE=PATH entries")
                overrides[candidate] = Path(reference).absolute()
            path = declare_block(spec, root, block=args.block, shard=args.shard, epochs=overrides,
                qualification_manifest=args.qualification_manifest.absolute(),
                predecessor_retirement=args.predecessor_retirement.absolute() if args.predecessor_retirement else None)
        elif args.command == "launch-lane":
            path = launch_block_lane(spec, root, args.declaration.absolute(), mode=args.mode, generation=args.generation,
                predecessor_intent=args.predecessor_intent.absolute() if args.predecessor_intent else None)
        elif args.command == "verify-lane":
            result = verify_lane(spec, root, args.receipt.absolute())
            print(json.dumps(result, sort_keys=True, allow_nan=False))
            return 0
        elif args.command == "complete-lane":
            path = complete_lane(spec, root, args.intent.absolute())
        elif args.command == "retire-lane":
            path = retire_lane(spec, root, args.intent.absolute())
        elif args.command == "retire-block":
            path = retire_block(spec, root, args.declaration.absolute())
        elif args.command == "commit-block":
            path = commit_block(spec, root, args.declaration.absolute())
        else:
            result = check_corpus_in_image(spec, root,
                (args.output if args.command == "publish-manifest" else args.manifest).absolute(),
                publish=args.command == "publish-manifest")
            print(json.dumps(result, sort_keys=True, allow_nan=False))
            return 0
        print(json.dumps({"valid": True, "receipt": str(path) if path else None,
                          "formal_accepted_trace_count": 0, "scientific_credit": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"rapid class epochs: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
