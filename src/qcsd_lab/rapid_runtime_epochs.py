"""Prospective collection repairs with a separate runtime for each physical lane.

The original class policy and every historical receipt remain immutable. A
repair candidate binds a closed failed attempt, an actual original-image
qualification check and an actual replacement-image identity check. It gains
launch authority only after ten ordinary deep-verified diagnostic traces.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from contextvars import ContextVar
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Mapping

import yaml

from . import rapid_capture_plan as plan
from . import rapid_class_epochs as classes
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as admission
from . import rapid_runtime_compatibility as compatibility
from .util import durable_create

POLICY_TYPE = "qcsd-rapid-v5-collection-runtime-policy-v1"
PROPOSAL_TYPE = "qcsd-rapid-v5-collection-runtime-proposal-v1"
ACTIVATION_TYPE = "qcsd-rapid-v5-collection-runtime-activation-v1"
RETIREMENT_TYPE = "qcsd-rapid-v5-collection-runtime-candidate-retirement-v1"
INTENT_TYPE = "qcsd-rapid-v5-runtime-epoch-lane-intent-v1"
CANARY_INTENT_TYPE = "qcsd-rapid-v5-runtime-epoch-canary-intent-v1"
CANARY_COMPLETE_TYPE = "qcsd-rapid-v5-runtime-epoch-canary-completion-v1"
COMPLETE_TYPE = "qcsd-rapid-v5-runtime-epoch-lane-completion-v1"
CORPUS_TYPE = "qcsd-rapid-v5-runtime-epoch-formal-corpus-v1"
CAPSULE_TYPE = "qcsd-rapid-v5-collection-runtime-launch-capsule-v1"
COMPATIBILITY_ENV = "QCSD_RAPID_COLLECTION_COMPATIBILITY"
_CURRENT_BRIDGE: ContextVar[dict | None] = ContextVar("rapid_collection_bridge", default=None)
_CHECKING_CAPSULE: ContextVar[bool] = ContextVar("rapid_collection_capsule_check", default=False)
RUNTIME_MUTABLE_KEYS = {"runtime_source_root", "module_root", "source_manifest", "client_binary",
                        "base_launcher", "collection_image_digest", "execution_generation"}


def _spec(value: Mapping[str, str]) -> lanes.CaptureSpec:
    if set(value) != lanes.PATH_KEYS | {"collection_image_digest", "execution_generation"}:
        raise ValueError("runtime epoch spec fields differ")
    return lanes.CaptureSpec(**{key: Path(item) if key in lanes.PATH_KEYS else item
                                for key, item in value.items()})


def _directory(root: Path, ordinal: int) -> Path:
    if type(ordinal) is not int or not 2 <= ordinal <= 9999:
        raise ValueError("replacement runtime ordinal must be in 2..9999")
    return root / "runtime-epochs" / f"e{ordinal:04d}"


def _kind(path: Path) -> str:
    return admission._load(admission._read(path)).get("receipt_type", "")


def open_intent(path: Path) -> dict[str, Any]:
    kind = _kind(path)
    if kind not in {lanes.INTENT_TYPE, INTENT_TYPE, CANARY_INTENT_TYPE}:
        raise ValueError("unknown collection launch intent")
    return classes._open(path, kind)


def _sources(spec: lanes.CaptureSpec) -> dict[str, bytes]:
    """Read the actual versioned Python and static qualification source surface."""
    from .chaff_qualification import IMPLEMENTATION_FILES
    names = set(IMPLEMENTATION_FILES)
    names.update(path.relative_to(spec.runtime_source_root).as_posix()
                 for folder in ("src/qcsd_lab", "tools")
                 for path in (spec.runtime_source_root / folder).glob("*.py"))
    names.update(relative for relative, _ in lanes.TRAFFIC_FILES.values())
    return {name: admission._read(spec.runtime_source_root / name) for name in sorted(names)}


def _runtime_projection(proof):
    """The actual plan check contains the runtime check's complete identity."""
    return {"schema_version": 1, "artifact_type": "qcsd-rapid-v5-installed-runtime-preflight",
        **{key: proof[key] for key in ("collection_image_digest", "runtime_source", "source_manifest_sha256", "client_sha256",
            "base_launcher_sha256", "host_launcher_sha256", "qualification_implementation", "traffic_hashes")},
        "formal_accepted_trace_count": 0, "scientific_credit": False}


def _matching_layout(base: lanes.CaptureSpec, runtime: lanes.CaptureSpec) -> None:
    for key, value in base.serializable().items():
        if key not in RUNTIME_MUTABLE_KEYS and runtime.serializable()[key] != value:
            raise ValueError(f"collection repair changes fixed study input: {key}")
    lanes._check_spec(runtime)
    # The unchanged host launcher can transport both source snapshots through
    # one explicit read-only data root. There is no machine-specific root.
    for spec in (base, runtime):
        for key in ("runtime_source_root", "module_root", "source_manifest", "client_binary", "base_launcher"):
            if not getattr(spec, key).is_relative_to(base.data_root):
                raise ValueError("runtime snapshots must be retained beneath the explicit study data root")
    if runtime.module_root != runtime.runtime_source_root:
        raise ValueError("runtime epoch must execute its own declared collection source")


def initialize_policy(spec: lanes.CaptureSpec, root: Path) -> Path:
    """Publish opt-in authority before the first physical formal launch."""
    with lanes.capture_lock(spec.execution_root):
        policy = classes.verify_policy(spec, root)
        if list((root / "blocks").glob("**/intent.json")):
            raise ValueError("collection runtime authority must precede formal physical launches")
        _matching_layout(spec, spec)
        directory = root / "runtime-epochs"
        if directory.exists():
            raise FileExistsError("collection runtime policy namespace was previously claimed")
        directory.mkdir()
        return classes._write(directory / "policy.json", POLICY_TYPE, {
            "class_policy": classes._reference(root, root / "policy.json"),
            "base_spec": spec.serializable(), "base_image_check": policy["image_check"],
            "repair_rule": "reviewed-collector-functions-unchanged-native-client-method-and-traffic",
            "canary_rule": "five-fixed-sites-baseline-plus-affected-condition-one-visit",
            "published_at": admission._now(), "scientific_credit": False})


def verify_policy(spec: lanes.CaptureSpec, root: Path) -> dict[str, Any]:
    value = classes._open(root / "runtime-epochs/policy.json", POLICY_TYPE)
    classes._check_keys(value, {"class_policy", "base_spec", "base_image_check", "repair_rule",
                               "canary_rule", "published_at", "scientific_credit"}, "collection runtime policy")
    policy = classes.verify_policy(spec, root)
    if (value["base_spec"] != spec.serializable()
        or value["class_policy"] != classes._reference(root, root / "policy.json")
        or value["base_image_check"] != policy["image_check"]
        or value["repair_rule"] != "reviewed-collector-functions-unchanged-native-client-method-and-traffic"
        or value["canary_rule"] != "five-fixed-sites-baseline-plus-affected-condition-one-visit"
        or value["scientific_credit"] is not False
        or not classes._time(policy["published_at"]) <= classes._time(value["published_at"]) <= classes._time(admission._now())):
        raise ValueError("collection runtime policy changes its prospective authority")
    return value


CANDIDATE_SCRIPT = (
    "import json,sys; from qcsd_lab.rapid_runtime_epochs import executed_candidate_check; "
    "print(json.dumps(executed_candidate_check(json.loads(sys.argv[1])),sort_keys=True,allow_nan=False))"
)


def executed_candidate_check(value: Mapping[str, Any]) -> dict[str, Any]:
    classes._check_keys(value, {"base_spec", "runtime_spec", "old_proof", "review"}, "runtime candidate image inputs")
    base, runtime = _spec(value["base_spec"]), _spec(value["runtime_spec"])
    _matching_layout(base, runtime)
    current = lanes.executed_image_runtime_check({key: runtime.serializable()[key] for key in lanes.RUNTIME_KEYS})
    from .runtime_provenance import validate_runtime_receipt
    installed = validate_runtime_receipt(required_schema_version=2)
    for relative, digest in installed["source_files"].items():
        if classes._sha(admission._read(runtime.runtime_source_root / relative)) != digest:
            raise ValueError("replacement image differs from its complete source snapshot")
    if admission._read(Path(__file__)) != admission._read(runtime.runtime_source_root / "src/qcsd_lab/rapid_runtime_epochs.py"):
        raise ValueError("runtime authority validator is not installed from the declared source")
    if value["review"].get("repair_scope") == "parallel-capture-control-only":
        from . import rapid_capture_control_compatibility as control
        groups = admission.load_admission_context(base.acquisition_root).mounted_module_hashes
        bridge = control.validate_compatibility(value["old_proof"], current,
            _sources(base), _sources(runtime), value["review"], acquisition_source_groups=groups)
    else:
        bridge = compatibility.validate_compatibility(value["old_proof"], current,
            _sources(base), _sources(runtime), value["review"])
    return {"runtime_proof": current, "compatibility_bridge": bridge}


def _candidate_command(base: lanes.CaptureSpec, runtime: lanes.CaptureSpec, old_proof, review) -> list[str]:
    command = lanes.image_check_command(runtime)
    command[-3:] = ["-I", "-c", CANDIDATE_SCRIPT, json.dumps({"base_spec": base.serializable(),
        "runtime_spec": runtime.serializable(), "old_proof": old_proof, "review": review}, sort_keys=True)]
    return command


def _check_candidate(base, runtime, root, old_proof, review) -> dict[str, Any]:
    command = _candidate_command(base, runtime, old_proof, review)
    started = admission._now()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=300, check=False)
    execution = {"command": command, "returncode": result.returncode, "started_at": started,
        "completed_at": admission._now(), "stdout": lanes._put_object(root, result.stdout.encode()),
        "stderr": lanes._put_object(root, result.stderr.encode()),
        "validator_script_sha256": classes._sha(CANDIDATE_SCRIPT.encode())}
    durable_create(root / f"runtime-candidate-check-{classes._sha(admission._json(execution))}.json", admission._json(execution))
    if result.returncode != 0:
        raise ValueError("replacement image check failed; actual execution retained")
    return {"execution": execution, "proof": admission._load(result.stdout.encode())}


def propose_epoch(spec: lanes.CaptureSpec, root: Path, runtime: lanes.CaptureSpec, *,
                  failed_intent: Path, review: Mapping[str, Any]) -> Path:
    with lanes.capture_lock(spec.execution_root):
        verify_policy(spec, root)
        _matching_layout(spec, runtime)
        failed, block, sites, lane = classes._intent(spec, root, failed_intent)
        if (failed_intent.parent / "complete.json").exists() or lane.mode == "undefended":
            raise ValueError("repair candidate requires an incomplete nonbaseline defense lane")
        classes._incomplete_predecessor(spec, root, failed_intent, lane)
        prior = sorted((root / "runtime-epochs").glob("e[0-9][0-9][0-9][0-9]"))
        if prior:
            if (prior[-1] / "activation.json").is_file():
                verify_activation(spec, root, prior[-1] / "activation.json")
            elif (prior[-1] / "retirement.json").is_file():
                verify_candidate_retirement(spec, root, prior[-1] / "retirement.json")
            else:
                raise ValueError("an unactivated prior runtime candidate requires actual retirement; it cannot be skipped")
        ordinal = len(prior) + 2
        directory = _directory(root, ordinal)
        if directory.exists():
            raise FileExistsError("runtime epoch namespace was previously claimed")
        declaration = classes._child(root, failed["epoch_declaration"])
        # Reopen the actual original qualifier in its original installed image.
        # This is an offline check of all 120 raw responses, not requalification.
        original = classes.check_bound_image(spec, root, declaration)
        checked = _check_candidate(spec, runtime, root, _runtime_projection(original["proof"]["base_proof"]), review)
        directory.mkdir()
        return classes._write(directory / "proposal.json", PROPOSAL_TYPE, {
            "policy": classes._reference(root, root / "runtime-epochs/policy.json"),
            "ordinal": ordinal, "runtime_spec": runtime.serializable(), "review": dict(review),
            "original_block_check": original, "candidate_check": checked,
            "failed_intent": classes._reference(root, failed_intent),
            "failed_attempt": classes._attempt_inventory(spec, root, failed_intent, lane),
            "declaration": classes._reference(root, declaration), "mode": lane.mode,
            "predecessor_runtime": failed.get("runtime_epoch"),
            "proposed_at": admission._now(), "scientific_credit": False})


@classes._memoized
def verify_proposal(spec: lanes.CaptureSpec, root: Path, path: Path) -> tuple[dict, lanes.CaptureSpec]:
    policy = verify_policy(spec, root)
    value = classes._open(path, PROPOSAL_TYPE)
    classes._check_keys(value, {"policy", "ordinal", "runtime_spec", "review", "original_block_check", "candidate_check",
        "failed_intent", "failed_attempt", "declaration", "mode", "predecessor_runtime", "proposed_at", "scientific_credit"}, "runtime proposal")
    runtime = _spec(value["runtime_spec"])
    _matching_layout(spec, runtime)
    if (path != _directory(root, value["ordinal"]) / "proposal.json"
        or value["policy"] != classes._reference(root, root / "runtime-epochs/policy.json")
        or value["scientific_credit"] is not False):
        raise ValueError("runtime proposal changes its prospective policy or physical namespace")
    if classes._time(value["proposed_at"]) < classes._time(policy["published_at"]):
        raise ValueError("runtime proposal predates prospective runtime authority")
    if value["ordinal"] > 2:
        previous = _directory(root, value["ordinal"] - 1)
        if (previous / "activation.json").is_file():
            verify_activation(spec, root, previous / "activation.json")
        elif (previous / "retirement.json").is_file():
            verify_candidate_retirement(spec, root, previous / "retirement.json")
        else:
            raise ValueError("runtime proposal skips an unactivated or unretired previous candidate")
    failed_path = classes._child(root, value["failed_intent"])
    failed, block, sites, lane = classes._intent(spec, root, failed_path)
    if (value["declaration"] != failed["epoch_declaration"] or value["mode"] != lane.mode
        or lane.mode == "undefended" or (failed_path.parent / "complete.json").exists()
        or value["predecessor_runtime"] != failed.get("runtime_epoch")):
        raise ValueError("runtime proposal changes or promotes its failed defense predecessor")
    classes._incomplete_predecessor(spec, root, failed_path, lane)
    if value["failed_attempt"] != classes._attempt_inventory(spec, root, failed_path, lane):
        raise ValueError("runtime proposal hides or alters its failed physical attempt")
    declaration = classes._child(root, value["declaration"])
    classes._verified_check(spec, root, declaration, value["original_block_check"])
    original = _runtime_projection(value["original_block_check"]["proof"]["base_proof"])
    checked, execution = value["candidate_check"], value["candidate_check"]["execution"]
    if (execution["command"] != _candidate_command(spec, runtime, original, value["review"])
        or type(execution["returncode"]) is not int or execution["returncode"] != 0
        or execution["validator_script_sha256"] != classes._sha(CANDIDATE_SCRIPT.encode())
        or admission._load(lanes._object(root, execution["stdout"])) != checked["proof"]):
        raise ValueError("runtime proposal lacks an actual matching installed-image check")
    lanes._object(root, execution["stderr"])
    current = checked["proof"]["runtime_proof"]
    if value["review"].get("repair_scope") == "parallel-capture-control-only":
        from . import rapid_capture_control_compatibility as control
        groups = admission.load_admission_context(spec.acquisition_root).mounted_module_hashes
        bridge = control.validate_compatibility(original, current, _sources(spec), _sources(runtime),
            value["review"], acquisition_source_groups=groups)
    else:
        bridge = compatibility.validate_compatibility(original, current, _sources(spec), _sources(runtime), value["review"])
    if checked["proof"]["compatibility_bridge"] != bridge:
        raise ValueError("runtime compatibility differs from independently reopened source roles")
    published = classes._time(value["proposed_at"])
    original_end = classes._time(value["original_block_check"]["execution"]["completed_at"])
    if not original_end <= classes._time(execution["started_at"]) <= classes._time(execution["completed_at"]) <= published <= classes._time(admission._now()):
        raise ValueError("runtime proposal predates its actual proof")
    return value, runtime


def _canary_lane(spec, root, proposal, mode) -> tuple[plan.Lane, tuple[plan.Site, ...]]:
    block, sites = classes.verify_block(spec, root, classes._child(root, proposal["declaration"]))
    if mode not in {"undefended", proposal["mode"]}:
        raise ValueError("runtime canary must be baseline or its affected defense")
    original = classes._epoch_lane(block, sites, mode)
    name = (f"rapid-curated-tranco50-v2-diagnostic-runtime-e{proposal['ordinal']:04d}"
            f"-b{block['block']:02d}-s{block['shard']:02d}-{mode}")
    return replace(original, role="diagnostic", campaign_name=name, visits_per_workload=1), sites


def _canary_bytes(lane, sites) -> bytes:
    # Preserve the registered traffic bytes and full graphs; only the role,
    # namespace, deterministic seed and visit count become diagnostic.
    ordinary = replace(lane, role="formal", visits_per_workload=plan.FINAL_VISITS_PER_BLOCK,
        campaign_name=plan._campaign_name("formal", lane.block, lane.shard, lane.mode, 1, 5))
    value = yaml.safe_load(plan.render_lane_campaign(ordinary, sites))
    value["name"] = lane.campaign_name
    value["purpose"] = "smoke"
    value["workloads"] = {identifier: 1 for identifier in lane.workload_ids}
    value["seed"] = int(classes._sha(lane.campaign_name.encode())[:16], 16)
    return yaml.safe_dump(value, sort_keys=False, width=100).encode()


def _capsule(spec, root, intent_path, runtime) -> Path:
    relative = intent_path.relative_to(root).as_posix().replace("/", "-")
    path = spec.execution_root / "config/rapid-runtime-epochs" / f"{relative}-authority.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return classes._write(path, CAPSULE_TYPE, {"base_spec": spec.serializable(), "runtime_spec": runtime.serializable(),
        "evidence_root": str(root), "intent": str(intent_path), "intent_sha256": classes._sha(admission._read(intent_path)),
        "scientific_credit": False})


def _launch_env(spec, root, intent, runtime) -> dict[str, str]:
    env = dict(os.environ)
    capsule = _capsule(spec, root, intent, runtime)
    env.update(QCSD_LAB_COLLECTION_IMAGE=runtime.collection_image_digest,
        QCSD_RAPID_IMAGE_SOURCE_QCSD=str(runtime.base_launcher),
        QCSD_RAPID_V5_PROFILE_PATH=str(lanes._study_profile(spec.execution_root)),
        QCSD_RAPID_DNS_RECEIPT_PATH=str(intent.parent / "dns.json"))
    env[COMPATIBILITY_ENV] = str(capsule)
    env["QCSD_RAPID_EPOCH_LAUNCH_INPUT"] = json.dumps({"spec": runtime.serializable(),
        "root": str(root), "intent": str(intent), "intent_sha256": classes._sha(admission._read(intent))}, sort_keys=True)
    reference = classes.verify_policy(spec, root)["image_check"]["execution"].get("capture_control_installation")
    if reference is not None:
        env["QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"] = reference["path"]
    return env


def launch_canary(spec, root, proposal_path, *, mode: str) -> Path:
    with lanes.capture_lock(spec.execution_root) as descriptor:
        proposal, runtime = verify_proposal(spec, root, proposal_path)
        if (proposal_path.parent / "activation.json").exists() or (proposal_path.parent / "retirement.json").exists():
            raise ValueError("activated or retired runtime cannot replace its diagnostic evidence")
        lane, sites = _canary_lane(spec, root, proposal, mode)
        directory = proposal_path.parent / "canaries" / mode
        campaign = spec.campaign_dir / f"{lane.campaign_name}.yml"
        if directory.exists() or (spec.execution_root / "results" / lane.campaign_name).exists():
            raise FileExistsError("runtime canary namespace was previously claimed")
        durable_create(campaign, _canary_bytes(lane, sites))
        directory.mkdir(parents=True)
        intent = classes._write(directory / "intent.json", CANARY_INTENT_TYPE, {
            "proposal": classes._reference(root, proposal_path), "mode": mode, "campaign_name": lane.campaign_name,
            "campaign_sha256": classes._sha(admission._read(campaign)), "runtime_identity": classes._runtime_identity(proposal["candidate_check"]["proof"]["runtime_proof"]),
            "started_at": admission._now(), "scientific_credit": False})
        lanes._actuate_host(runtime, root, directory, [str(runtime.host_launcher), "run", str(campaign)],
                            _launch_env(spec, root, intent, runtime), descriptor)
        classes._clear_validation_cache()
        checked = _deep_canary(spec, root, intent)
        return classes._write(directory / "complete.json", CANARY_COMPLETE_TYPE, {**checked, "completed_at": admission._now()})


def validate_canary_intent(spec, root, path):
    intent = classes._open(path, CANARY_INTENT_TYPE)
    classes._check_keys(intent, {"proposal", "mode", "campaign_name", "campaign_sha256", "runtime_identity", "started_at", "scientific_credit"}, "runtime canary intent")
    proposal_path = classes._child(root, intent["proposal"])
    proposal, runtime = verify_proposal(spec, root, proposal_path)
    lane, sites = _canary_lane(spec, root, proposal, intent["mode"])
    raw = _canary_bytes(lane, sites)
    if (path != proposal_path.parent / "canaries" / lane.mode / "intent.json"
        or intent["campaign_name"] != lane.campaign_name or intent["campaign_sha256"] != classes._sha(raw)
        or admission._read(spec.campaign_dir / f"{lane.campaign_name}.yml") != raw
        or intent["runtime_identity"] != classes._runtime_identity(proposal["candidate_check"]["proof"]["runtime_proof"])
        or intent["scientific_credit"] is not False
        or classes._time(intent["started_at"]) < classes._time(proposal["proposed_at"])):
        raise ValueError("runtime canary changes its declared fixed inputs or installed runtime")
    return intent, proposal, runtime, lane, sites


def _deep_canary(spec, root, path) -> dict[str, Any]:
    intent, proposal, runtime, lane, sites = validate_canary_intent(spec, root, path)
    process = classes._terminal_process(runtime, root, path, lane)
    if process.get("returncode") != 0 or process.get("interruption") is not None:
        raise ValueError("runtime canary requires an actual successful terminal host process")
    namespace = spec.execution_root / "results" / lane.campaign_name
    children = list(namespace.iterdir())
    if len(children) != 1 or children[0].is_symlink() or not children[0].is_dir():
        raise ValueError("runtime canary must own exactly one ordinary result")
    result = children[0]
    experiment = admission._load(admission._read(result / "experiment.json"))
    if not classes._time(process["started_at"]) <= classes._time(experiment["started_at"]) <= classes._time(experiment["completed_at"]) <= classes._time(process["completed_at"]):
        raise ValueError("runtime canary result lies outside its actual host execution")
    workloads = {site.workload_id: admission._read(spec.workload_root / f"{site.workload_id}.json")
                 for site in sites if site.workload_id in lane.workload_ids}
    if any(classes._sha(workloads[site.workload_id]) != site.workload_sha256 for site in sites if site.workload_id in workloads):
        raise ValueError("runtime canary changes a registered full workload graph")
    dns = lanes.verify_dns_receipt(admission._read(path.parent / "dns.json"), lane.campaign_name, workloads)
    checked = plan.verify_lane_result(result, lane, collection_image_digest=runtime.collection_image_digest,
        lab_commit=intent["runtime_identity"]["runtime_source"]["lab_commit"], campaign_sha256=intent["campaign_sha256"],
        workload_sha256s={key: classes._sha(raw) for key, raw in workloads.items()},
        qualification_set_manifest_sha256=proposal["original_block_check"]["proof"]["effective_sites"][(lane.shard - 1) * 5]["qualification_set_manifest_sha256"] if lane.qualification_set else None,
        collection_runtime_epoch=proposal["ordinal"])
    return {"intent": classes._reference(root, path), "mode": lane.mode, "accepted": checked["accepted"],
        "result_relpath": result.relative_to(spec.execution_root / "results").as_posix(),
        "result_seal_sha256": checked["result_seal_sha256"], "dns_sha256": dns,
        "runtime_proposal": intent["proposal"], "formal_accepted_trace_count": 0, "scientific_credit": False}


def verify_canary(spec, root, path) -> dict:
    value = classes._open(path, CANARY_COMPLETE_TYPE)
    checked = _deep_canary(spec, root, classes._child(root, value["intent"]))
    if {key: item for key, item in value.items() if key != "completed_at"} != checked:
        raise ValueError("runtime canary completion differs from its actual ordinary deep result")
    process = classes._open(path.parent / "host-process.json", lanes.PROCESS_TYPE)
    if not classes._time(process["completed_at"]) <= classes._time(value["completed_at"]) <= classes._time(admission._now()):
        raise ValueError("runtime canary completion predates actual capture")
    return value


def activate_epoch(spec, root, proposal_path) -> Path:
    with lanes.capture_lock(spec.execution_root):
        proposal, runtime = verify_proposal(spec, root, proposal_path)
        if (proposal_path.parent / "retirement.json").exists():
            raise ValueError("retired runtime candidate cannot gain launch authority")
        canaries = {mode: proposal_path.parent / "canaries" / mode / "complete.json"
                    for mode in ("undefended", proposal["mode"])}
        if any(verify_canary(spec, root, path)["accepted"] != 5 for path in canaries.values()):
            raise ValueError("runtime activation needs ten deep-verified fixed-site canary traces")
        return classes._write(proposal_path.parent / "activation.json", ACTIVATION_TYPE, {
            "proposal": classes._reference(root, proposal_path),
            "canaries": {mode: classes._reference(root, path) for mode, path in canaries.items()},
            "activated_at": admission._now(), "formal_accepted_trace_count": 0, "scientific_credit": False})


@classes._memoized
def verify_activation(spec, root, path) -> tuple[dict, dict, lanes.CaptureSpec]:
    value = classes._open(path, ACTIVATION_TYPE)
    classes._check_keys(value, {"proposal", "canaries", "activated_at", "formal_accepted_trace_count", "scientific_credit"}, "runtime activation")
    proposal_path = classes._child(root, value["proposal"])
    proposal, runtime = verify_proposal(spec, root, proposal_path)
    if (path != proposal_path.parent / "activation.json" or set(value["canaries"]) != {"undefended", proposal["mode"]}
        or (proposal_path.parent / "retirement.json").exists()
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False):
        raise ValueError("runtime activation changes its declared canary gate or scientific role")
    for mode, reference in value["canaries"].items():
        canary_path = classes._child(root, reference)
        canary = verify_canary(spec, root, canary_path)
        if (canary_path != proposal_path.parent / "canaries" / mode / "complete.json" or canary["mode"] != mode
            or canary["accepted"] != 5 or canary["runtime_proposal"] != value["proposal"]
            or not classes._time(canary["completed_at"]) <= classes._time(value["activated_at"]) <= classes._time(admission._now())):
            raise ValueError("runtime activation lacks its two actual contemporaneous canaries")
    return value, proposal, runtime


def retire_canary(spec, root, proposal_path, *, mode: str) -> Path:
    """Close a lost canary worker using the existing actual process census."""
    with lanes.capture_lock(spec.execution_root):
        proposal, runtime = verify_proposal(spec, root, proposal_path)
        path = proposal_path.parent / "canaries" / mode / "intent.json"
        _, _, _, lane, _ = validate_canary_intent(spec, root, path)
        if (path.parent / "host-process.json").exists() or (path.parent / "complete.json").exists():
            raise ValueError("canary already has actual terminal process evidence")
        start_raw = admission._read(path.parent / "host-start.json")
        start = lanes._validated_host_start(start_raw, admission._read(path), campaign_name=lane.campaign_name)
        retired = {key: lanes._retired_identity(start[key]) for key in ("host", "supervisor")}
        with lanes.capture_lock(spec.execution_root, lifecycle=True) as descriptor:
            checks = lanes._retirement_quiescence(root, descriptor)
            if retired != {key: lanes._retired_identity(start[key]) for key in retired}:
                raise ValueError("runtime canary census changed during retirement")
            return classes._write(path.parent / "retirement.json", lanes.RETIREMENT_TYPE, {
                "command": start["command"], "execution_root": start["execution_root"], "started_at": start["started_at"],
                "observed_at": admission._now(), "scientific_credit": False, "host_start": lanes._put_object(root, start_raw),
                "retired_processes": retired, "checks": checks})


def _candidate_attempts(spec, root, proposal_path):
    proposal, runtime = verify_proposal(spec, root, proposal_path)
    directory = proposal_path.parent / "canaries"
    modes = {entry.name for entry in directory.iterdir()} if directory.exists() else set()
    if not modes <= {"undefended", proposal["mode"]}:
        raise ValueError("runtime candidate contains an undeclared canary")
    attempts = []
    for mode in sorted(modes):
        path = directory / mode / "intent.json"
        _, _, _, lane, _ = validate_canary_intent(spec, root, path)
        classes._terminal_process(runtime, root, path, lane)
        attempts.append(classes._attempt_inventory(spec, root, path, lane))
    return attempts


def retire_candidate(spec, root, proposal_path, *, reason: str) -> Path:
    with lanes.capture_lock(spec.execution_root):
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("candidate retirement needs an explicit diagnosis")
        if (proposal_path.parent / "activation.json").exists():
            raise ValueError("activated runtime cannot be retired as an unlaunched candidate")
        attempts = _candidate_attempts(spec, root, proposal_path)
        return classes._write(proposal_path.parent / "retirement.json", RETIREMENT_TYPE, {
            "proposal": classes._reference(root, proposal_path), "attempts": attempts, "reason": reason,
            "retired_at": admission._now(), "formal_accepted_trace_count": 0, "scientific_credit": False})


def verify_candidate_retirement(spec, root, path):
    value = classes._open(path, RETIREMENT_TYPE)
    classes._check_keys(value, {"proposal", "attempts", "reason", "retired_at", "formal_accepted_trace_count", "scientific_credit"}, "runtime candidate retirement")
    proposal_path = classes._child(root, value["proposal"])
    proposal, _ = verify_proposal(spec, root, proposal_path)
    if (path != proposal_path.parent / "retirement.json" or (proposal_path.parent / "activation.json").exists()
        or value["attempts"] != _candidate_attempts(spec, root, proposal_path)
        or not isinstance(value["reason"], str) or not value["reason"].strip()
        or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
        or value["scientific_credit"] is not False
        or not classes._time(proposal["proposed_at"]) <= classes._time(value["retired_at"]) <= classes._time(admission._now())):
        raise ValueError("runtime retirement omits or changes actual attempted evidence")
    return value


def prepare_repaired_lane_intent(spec, root, activation_path, *, predecessor_intent: Path | None = None,
                                 actuator: str = "run") -> Path:
    """Claim an activated repair's immediate successor; the caller holds its lock."""
    if actuator not in {"run", "parallel-formal-worker"}:
        raise ValueError("runtime repair requires an explicit supported actuator")
    activation, proposal, runtime = verify_activation(spec, root, activation_path)
    previous_path = predecessor_intent or classes._child(root, proposal["failed_intent"])
    previous, block, sites, old_lane = classes._intent(spec, root, previous_path)
    if (previous_path != classes._child(root, proposal["failed_intent"])
        and previous.get("runtime_epoch") != classes._reference(root, activation_path)):
        raise ValueError("same-runtime retry must continue this activation's immediate failed lane")
    if previous["epoch_declaration"] != proposal["declaration"] or old_lane.mode != proposal["mode"]:
        raise ValueError("runtime retry changes its affected block or defense")
    if (classes._child(root, proposal["declaration"]).parent / "commit.json").exists() or (classes._child(root, proposal["declaration"]).parent / "retirement.json").exists():
        raise ValueError("committed or retired class block cannot consume a runtime repair")
    classes._incomplete_predecessor(spec, root, previous_path, old_lane)
    lane = classes._epoch_lane(block, sites, old_lane.mode, old_lane.generation + 1)
    directory = previous_path.parent.parent / lane.campaign_name
    campaign = spec.campaign_dir / f"{lane.campaign_name}.yml"
    if directory.exists() or (spec.execution_root / "results" / lane.campaign_name).exists():
        raise FileExistsError("repaired physical lane namespace was previously claimed")
    raw = classes.render_epoch_lane(lane, sites, block["ordinal"])
    durable_create(campaign, raw)
    directory.mkdir()
    identity = classes._runtime_identity(proposal["candidate_check"]["proof"]["runtime_proof"])
    return classes._write(directory / "intent.json", INTENT_TYPE, {
        "campaign_name": lane.campaign_name, "campaign_sha256": classes._sha(raw), "logical_lane": lane.logical_name,
        "generation": lane.generation, "bindings": previous["bindings"], "runtime_identity": identity,
        "lineage": proposal["declaration"], "started_at": admission._now(), "actuator": actuator, "scientific_credit": False,
        "epoch_declaration": proposal["declaration"], "mode": lane.mode,
        "runtime_epoch": classes._reference(root, activation_path),
        "predecessor_intent": classes._reference(root, previous_path),
        "predecessor_attempt": classes._attempt_inventory(spec, root, previous_path, old_lane)})


def launch_repaired_lane(spec, root, activation_path, *, predecessor_intent: Path | None = None) -> Path:
    with lanes.capture_lock(spec.execution_root) as descriptor:
        output = prepare_repaired_lane_intent(spec, root, activation_path, predecessor_intent=predecessor_intent)
        _, _, runtime = verify_activation(spec, root, activation_path)
        directory = output.parent
        campaign = spec.campaign_dir / f"{directory.name}.yml"
        lanes._actuate_host(runtime, root, directory, [str(runtime.host_launcher), "run", str(campaign)],
                            _launch_env(spec, root, output, runtime), descriptor)
        classes._clear_validation_cache()
        complete = classes.complete_lane(spec, root, output)
        if classes._open(directory / "host-process.json", lanes.PROCESS_TYPE)["returncode"] != 0:
            raise RuntimeError("repaired lane has a nonzero host exit; actual records retained")
        return complete


def validate_intent(spec, root, path):
    value = classes._open(path, INTENT_TYPE)
    classes._check_keys(value, {"campaign_name", "campaign_sha256", "logical_lane", "generation", "bindings", "runtime_identity",
        "lineage", "started_at", "actuator", "scientific_credit", "epoch_declaration", "mode", "runtime_epoch",
        "predecessor_intent", "predecessor_attempt"}, "repaired runtime lane intent")
    activation, proposal, runtime = verify_activation(spec, root, classes._child(root, value["runtime_epoch"]))
    prior_path = classes._child(root, value["predecessor_intent"])
    if prior_path == path:
        raise ValueError("runtime retry cannot name itself as predecessor")
    previous, block, sites, prior_lane = classes._intent(spec, root, prior_path)
    lane = classes._epoch_lane(block, sites, prior_lane.mode, prior_lane.generation + 1)
    raw = classes.render_epoch_lane(lane, sites, block["ordinal"])
    if (path != prior_path.parent.parent / lane.campaign_name / "intent.json"
        or value["campaign_name"] != lane.campaign_name or value["campaign_sha256"] != classes._sha(raw)
        or admission._read(spec.campaign_dir / f"{lane.campaign_name}.yml") != raw
        or value["logical_lane"] != lane.logical_name or value["generation"] != lane.generation
        or value["mode"] != lane.mode or value["bindings"] != previous["bindings"]
        or value["epoch_declaration"] != previous["epoch_declaration"] or value["lineage"] != previous["epoch_declaration"]
        or value["runtime_identity"] != classes._runtime_identity(proposal["candidate_check"]["proof"]["runtime_proof"])
        or (prior_path != classes._child(root, proposal["failed_intent"]) and previous.get("runtime_epoch") != value["runtime_epoch"])
        or previous["epoch_declaration"] != proposal["declaration"] or prior_lane.mode != proposal["mode"]
        or (prior_path.parent / "complete.json").exists()
        or value["predecessor_attempt"] != classes._attempt_inventory(spec, root, prior_path, prior_lane)
        or value["actuator"] not in {"run", "parallel-formal-worker"} or value["scientific_credit"] is not False
        or classes._time(value["started_at"]) < classes._time(activation["activated_at"])):
        raise ValueError("runtime repair changes source, condition, slots, class vector or immediate predecessor")
    classes._incomplete_predecessor(spec, root, prior_path, prior_lane)
    return value, block, sites, lane


def runtime_for_intent(spec, root, intent):
    if "runtime_epoch" not in intent:
        return spec
    return verify_activation(spec, root, classes._child(root, intent["runtime_epoch"]))[2]


def validate_capsule(path: Path, *, actual_image: str | None = None) -> tuple[dict, dict]:
    value = classes._open(path, CAPSULE_TYPE)
    classes._check_keys(value, {"base_spec", "runtime_spec", "evidence_root", "intent", "intent_sha256", "scientific_credit"}, "runtime launch capsule")
    spec, runtime = _spec(value["base_spec"]), _spec(value["runtime_spec"])
    _matching_layout(spec, runtime)
    root, intent_path = lanes._regular_directory(Path(value["evidence_root"])), Path(value["intent"])
    if (value["scientific_credit"] is not False or not root.is_relative_to(spec.data_root)
        or not intent_path.is_relative_to(root) or value["intent_sha256"] != classes._sha(admission._read(intent_path))
        or (actual_image is not None and actual_image != runtime.collection_image_digest)):
        raise ValueError("runtime capsule changes its actual bound image, intent or data root")
    intent = open_intent(intent_path)
    if _kind(intent_path) == CANARY_INTENT_TYPE:
        intent, proposal, declared_runtime, _, _ = validate_canary_intent(spec, root, intent_path)
        proposal_path = classes._child(root, intent["proposal"])
        if (proposal_path.parent / "retirement.json").exists():
            raise ValueError("retired candidate cannot authorize a new canary")
    elif _kind(intent_path) == INTENT_TYPE:
        # Bridge first; ordinary deep verification below may load qualifiers.
        activation_path = classes._child(root, intent["runtime_epoch"])
        activation = classes._open(activation_path, ACTIVATION_TYPE)
        proposal, declared_runtime = verify_proposal(spec, root, classes._child(root, activation["proposal"]))
    else:
        raise ValueError("legacy physical intents cannot acquire new runtime authority")
    if declared_runtime.serializable() != runtime.serializable():
        raise ValueError("runtime capsule differs from the registered replacement")
    bridge = proposal["candidate_check"]["proof"]["compatibility_bridge"]
    token = _CURRENT_BRIDGE.set(bridge)
    checking = _CHECKING_CAPSULE.set(True)
    try:
        if _kind(intent_path) == INTENT_TYPE:
            validate_intent(spec, root, intent_path)
    finally:
        _CHECKING_CAPSULE.reset(checking)
        _CURRENT_BRIDGE.reset(token)
    return value, bridge


def validate_qualification_reuse(old_receipt, current_receipt) -> None:
    """Opt-in current check; no false/historical-validation pass flag is used."""
    reference = os.environ.get(COMPATIBILITY_ENV)
    if reference:
        value = admission._load(admission._read(Path(reference)))
        from . import qualification_control_authority as control
        if value.get("artifact_type") == control.TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("control qualification cannot claim a historical runtime installation bridge")
            control.validate_current_implementation(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"))
            return
        from . import qualification_delivery_compatibility as delivery
        if value.get("artifact_type") == delivery.TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("delivery qualification cannot claim a historical runtime installation bridge")
            delivery.validate_current_implementation(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"))
            return
        from . import rapid_target_parallel_schedule as target_workers
        if value.get("artifact_type") == target_workers.CAPSULE_TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("target scheduling cannot claim a historical runtime installation")
            from .rapid_operation_facts import current_context
            target_workers.validate_current_implementation(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"), _context=current_context())
            return
        from . import rapid_selected_parallel_schedule as selected_schedule
        from . import rapid_ordinary_parallel_schedule as ordinary_parallel
        if value.get("artifact_type") == ordinary_parallel.CAPSULE_TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("ordinary scheduling cannot claim historical runtime installation or repair")
            from .rapid_operation_facts import current_context
            ordinary_parallel.validate_current_implementation(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"), _context=current_context())
            return
        if value.get("artifact_type") == selected_schedule.CAPSULE_TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("selected scheduling cannot claim historical runtime installation or repair")
            from .rapid_operation_facts import current_context
            selected_schedule.validate_current_qualification(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"), _context=current_context())
            return
        from . import rapid_original_static_parallel_schedule as original_static
        if value.get("artifact_type") == original_static.CAPSULE_TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("original static scheduling cannot claim historical installation or runtime repair")
            from .rapid_operation_facts import current_context
            original_static.validate_current_qualification(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"), _context=current_context())
            return
        from . import rapid_static_parallel_schedule as static_schedule
        if value.get("artifact_type") == static_schedule.CAPSULE_TYPE:
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("current static scheduling cannot claim historical installation or runtime repair")
            from .rapid_operation_facts import current_context
            static_schedule.validate_current_qualification(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"), _context=current_context())
            return
        from . import rapid_rolling_schedule as schedule
        from . import rapid_quick_profile as quick
        if value.get("artifact_type") == schedule.CAPSULE_TYPE or quick.is_profile(value):
            if _CURRENT_BRIDGE.get() is not None or os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"):
                raise ValueError("rolling scheduling cannot claim historical installation or runtime repair authority")
            from .rapid_operation_facts import current_context
            schedule.validate_qualification_reuse(old_receipt, current_receipt,
                {"path": str(Path(reference).absolute()), "sha256": admission._sha(admission._read(Path(reference)))},
                actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"), _context=current_context())
            return
    bridge = _CURRENT_BRIDGE.get()
    if bridge is None:
        reference = os.environ.get(COMPATIBILITY_ENV)
        if not reference:
            raise ValueError("changed qualification inventory lacks collection runtime authority")
        path = Path(reference)
        if path.is_file() and _kind(path) == "qcsd-rapid-v5-capture-control-installation-v2":
            from .rapid_capture_control_installation import validate_capsule as validate_installation
            _, bridge = validate_installation(path, actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"))
        else:
            _, bridge = validate_capsule(path, actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"))
    if bridge.get("contract") == "response-only-v2-parallel-capture-control-v2":
        from .rapid_capture_control_compatibility import validate_current_implementation
        validate_current_implementation(old_receipt, current_receipt, bridge)
    else:
        if old_receipt["sha256"] != bridge["old_implementation_sha256"]:
            reference = os.environ.get("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION")
            if not reference:
                raise ValueError("runtime repair lacks its original capture-control installation lineage")
            from . import rapid_capture_control_installation as installation
            from . import rapid_capture_control_compatibility as control
            payload, initial_bridge = installation.validate_capsule(Path(reference))
            intermediate = payload["new_runtime_check"]["proof"]["runtime_proof"]["qualification_implementation"]
            runtime_reference = os.environ.get(COMPATIBILITY_ENV)
            if not runtime_reference:
                raise ValueError("qualification chain lacks its actual runtime launch capsule")
            runtime_capsule = classes._open(Path(runtime_reference), CAPSULE_TYPE)
            installation.check_current_spec(payload, _spec(runtime_capsule["base_spec"]))
            if (payload["evidence_root"] != runtime_capsule["evidence_root"]
                or intermediate["sha256"] != bridge["old_implementation_sha256"]):
                raise ValueError("runtime repair changes its source-bound intermediate installation")
            control.validate_current_implementation(old_receipt, intermediate, initial_bridge)
            compatibility.validate_current_implementation(intermediate, current_receipt, bridge)
            return
        compatibility.validate_current_implementation(old_receipt, current_receipt, bridge)


def validate_host_launch(value, *, expected_campaign: str, actual_image: str):
    classes._check_keys(value, {"spec", "root", "intent", "intent_sha256"}, "runtime host launch inputs")
    runtime, root, intent_path = _spec(value["spec"]), Path(value["root"]), Path(value["intent"])
    policy = classes._open(root / "runtime-epochs/policy.json", POLICY_TYPE)
    spec = _spec(policy["base_spec"])
    if _kind(intent_path) == CANARY_INTENT_TYPE:
        intent, proposal, declared_runtime, _, _ = validate_canary_intent(spec, root, intent_path)
        proposal_path = classes._child(root, intent["proposal"])
        if (proposal_path.parent / "activation.json").exists() or (proposal_path.parent / "retirement.json").exists():
            raise ValueError("closed runtime candidate cannot launch a new canary")
    else:
        intent, _, _, _ = validate_intent(spec, root, intent_path)
        _, proposal, declared_runtime = verify_activation(spec, root, classes._child(root, intent["runtime_epoch"]))
    if (runtime.serializable() != declared_runtime.serializable()
        or runtime.collection_image_digest != actual_image or intent["campaign_name"] != expected_campaign
        or value["intent_sha256"] != classes._sha(admission._read(intent_path))
        or (intent_path.parent / "host-process.json").exists() or (intent_path.parent / "retirement.json").exists()):
        raise ValueError("runtime host launch changed its actual image, namespace or intent")
    current = lanes.executed_image_runtime_check({key: runtime.serializable()[key] for key in lanes.RUNTIME_KEYS})
    if current != proposal["candidate_check"]["proof"]["runtime_proof"]:
        raise ValueError("runtime host preflight differs from its actual replacement-image check")
    return {"valid": True, "scientific_credit": False, "formal_accepted_trace_count": 0}


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("initialize", "propose", "launch-canary", "retire-canary", "retire-candidate", "activate", "launch-lane", "verify-activation"):
        command = commands.add_parser(name)
        command.add_argument("--spec", type=Path, required=True)
        command.add_argument("--evidence-root", type=Path, required=True)
        if name == "propose":
            command.add_argument("--runtime-spec", type=Path, required=True)
            command.add_argument("--failed-intent", type=Path, required=True)
            command.add_argument("--review", type=Path, required=True)
        elif name in {"launch-canary", "retire-canary", "retire-candidate", "activate"}:
            command.add_argument("--proposal", type=Path, required=True)
            if name in {"launch-canary", "retire-canary"}:
                command.add_argument("--mode", choices=plan.MODES, required=True)
            elif name == "retire-candidate":
                command.add_argument("--reason", required=True)
        elif name in {"launch-lane", "verify-activation"}:
            command.add_argument("--activation", type=Path, required=True)
            if name == "launch-lane":
                command.add_argument("--predecessor-intent", type=Path)
    return parser


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        spec = lanes.load_capture_spec(args.spec)
        root = lanes._regular_directory(args.evidence_root)
        if args.command == "initialize":
            path = initialize_policy(spec, root)
        elif args.command == "propose":
            path = propose_epoch(spec, root, lanes.load_capture_spec(args.runtime_spec),
                failed_intent=args.failed_intent.absolute(), review=admission._load(admission._read(args.review)))
        elif args.command == "launch-canary":
            path = launch_canary(spec, root, args.proposal.absolute(), mode=args.mode)
        elif args.command == "activate":
            path = activate_epoch(spec, root, args.proposal.absolute())
        elif args.command == "retire-canary":
            path = retire_canary(spec, root, args.proposal.absolute(), mode=args.mode)
        elif args.command == "retire-candidate":
            path = retire_candidate(spec, root, args.proposal.absolute(), reason=args.reason)
        elif args.command == "launch-lane":
            path = launch_repaired_lane(spec, root, args.activation.absolute(),
                predecessor_intent=args.predecessor_intent.absolute() if args.predecessor_intent else None)
        else:
            verify_activation(spec, root, args.activation.absolute())
            path = args.activation
        print(json.dumps({"valid": True, "receipt": str(path), "scientific_credit": False,
                          "formal_accepted_trace_count": 0}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"rapid runtime epochs: {type(error).__name__}: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
