"""Two official rapid v5 lanes, with independent terminal evidence and recovery.

Only the optional actuator changes. Admission, traffic, the 50 x 5 x 64 grid,
ordinary deep verification and the final manifest retain their existing rules.
Diagnostic authorities cannot enter this path or acquire scientific credit.
"""
from __future__ import annotations

import ipaddress
import json
import os
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import rapid_lane_evidence as ordinary
from . import rapid_parallel_capture as shared

AUTHORITY_TYPE = "qcsd-two-worker-formal-lane-authority"
START_TYPE = "qcsd-rapid-v5-parallel-worker-start"
PROCESS_TYPE = "qcsd-rapid-v5-parallel-worker-process"
RETIREMENT_TYPE = "qcsd-rapid-v5-parallel-worker-retirement"
ACTUATOR = "parallel-formal-worker"


def _index(index: int) -> None:
    if type(index) is not int or index not in (0, 1):
        raise ValueError("formal parallel worker index must be zero or one")


def _reference(row: Any) -> Path:
    if (not isinstance(row, dict) or set(row) != {"path", "sha256"}
        or not isinstance(row["path"], str) or not Path(row["path"]).is_absolute()
        or ".." in Path(row["path"]).parts
        or shared.sha(shared.read(Path(row["path"]))) != row["sha256"]):
        raise ValueError("formal parallel input reference changed")
    return Path(row["path"])


def authority(path: Path, *, execution_root: Path | None = None, _context=None) -> dict[str, Any]:
    return _audit(path, execution_root=execution_root, _context=_context)[0]


def _audit(path: Path, *, execution_root: Path | None = None, _context=None):
    """One fresh read pass; its local facts are never cached across actions."""
    from .rapid_operation_facts import OperationFacts
    owned = _context is None
    _context = OperationFacts() if owned else _context
    raw = _context.watch_file(path)
    key = ("formal-audit", str(path.absolute()), shared.sha(raw), str(execution_root))
    if _context.has(key):
        return _context.get(key)
    value = shared.load(path)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "artifact_type", "runtime",
            "campaigns", "capture_spec", "lane_specs", "evidence_root", "lane_intents", "installation"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != AUTHORITY_TYPE
        or not isinstance(value["lane_intents"], list) or len(value["lane_intents"]) != 2
        or not isinstance(value["lane_specs"], list) or len(value["lane_specs"]) != 2
        or value["capture_spec"] != value["lane_specs"][0]):
        raise ValueError("formal parallel authority fields differ")
    shared._runtime_authority(value, execution_root=execution_root)
    spec = ordinary.load_capture_spec(_reference(value["capture_spec"]))
    root = shared.regular_dir(Path(value["evidence_root"]))
    _context._references(value, root)
    capsule = None
    if value["installation"] is not None:
        from . import rapid_capture_control_installation as installation
        capsule_path = _reference(value["installation"])
        capsule, _ = installation.validate_capsule(capsule_path, actual_image=spec.collection_image_digest)
        if capsule["evidence_root"] != str(root):
            raise ValueError("formal installation belongs to another evidence root")
    logical = []
    facts = []
    for index, reference in enumerate(value["lane_intents"]):
        worker_spec = ordinary.load_capture_spec(_reference(value["lane_specs"][index]))
        if any(worker_spec.serializable()[key] != spec.serializable()[key]
               for key in spec.serializable() if key != "plan_receipt"):
            raise ValueError("formal workers changed cohort, runtime or traffic inputs between lane specs")
        if capsule is not None:
            installation.check_current_spec(capsule, worker_spec)
        intent_path = _reference(reference)
        if not intent_path.is_relative_to(root) or intent_path.name != "intent.json":
            raise ValueError("formal worker intent escapes its official evidence root")
        fact = _lane(value, index, _facts=_context)
        _, _, _, intent, lineage, lane, sites = fact
        if capsule is not None and ordinary.admission._utc(intent["started_at"]) < ordinary.admission._utc(capsule["published_at"]):
            raise ValueError("formal intent predates prospective capture-control installation")
        effective = _effective_runtime(fact)
        if value["runtime"] != {key: effective.serializable()[key] for key in shared.RUNTIME_KEYS}:
            raise ValueError("formal parallel runtime differs from its actual official worker runtime")
        registered = "epoch_declaration" in intent
        if registered:
            stored_plan = ordinary._payload(worker_spec.plan_receipt, ordinary.PLAN_TYPE)
            generation = stored_plan["cohort_generation"]
        else:
            generation = lineage["image_check"]["proof"]["cohort_generation"]
        if lane.study_version == 6:
            from . import rapid_rolling_schedule as scheduling
            if registered or capsule is not None:
                raise ValueError("rolling parallel workers cannot claim registered epochs or historical installation")
            stored_plan = lineage["image_check"]["proof"]["plan_payload"]
            from . import rapid_ordinary_parallel_schedule as ordinary_parallel
            if ordinary_parallel.is_payload(stored_plan):
                if generation != "rolling-50" or not 1 <= len(sites) <= 5:
                    raise ValueError("ordinary parallel changed rolling cohort scope")
                ordinary_parallel.require_worker(stored_plan, lane, sites, worker_spec)
            else:
                if (generation != "rolling-50" or not 1 <= len(sites) <= 5
                    or lane.visits_per_workload != 4 or len(lane.workload_ids) != len(sites)
                    or lane.sample_count != 4 * len(lane.workload_ids) or "scheduling" not in stored_plan):
                    raise ValueError("rolling parallel worker lacks its prospective four-visit scheduling plan")
            scheduling.require_schedule(stored_plan["scheduling"], worker_spec,
                declared_at=stored_plan["declared_at"], started_at=intent["started_at"], _context=_context)
        elif (lane.study_version != 5 or lane.sample_count != 20 or len(sites) != 50
              or generation != "final-50"):
            raise ValueError("formal parallel worker is not an exact official 20-slot final-50 lane")
        if (intent["actuator"] != ACTUATOR or lane.role != "formal"
            or Path(value["campaigns"][index]["path"]) != spec.campaign_dir / f"{lane.campaign_name}.yml"
            or value["campaigns"][index]["sha256"] != intent["campaign_sha256"]):
            raise ValueError("formal parallel worker is not an exact official 20-slot final-50 lane")
        logical.append(lane.logical_name)
        facts.append(fact)
    if len(set(logical)) != 2:
        raise ValueError("formal parallel workers cannot duplicate a logical lane")
    if len({fact[5].study_version for fact in facts}) != 1:
        raise ValueError("formal parallel workers cannot mix study contracts")
    from . import rapid_ordinary_parallel_schedule as ordinary_parallel
    if all(fact[5].study_version == 6 for fact in facts):
        ordinary_parallel.require_disjoint([(fact[0], fact[4]["image_check"]["proof"]["plan_payload"], fact[5], fact[6])
            for fact in facts])
    if owned:
        _context.check()
    return _context.remember(key, (value, facts))


def _context(value: dict[str, Any], index: int = 0, *, _facts=None):
    spec = ordinary.load_capture_spec(_reference(value["lane_specs"][index]))
    root = shared.regular_dir(Path(value["evidence_root"]))
    if _facts is not None:
        _facts._references(value["lane_specs"][index], root)
        _facts.bind_capture(spec)
    return spec, root


def _lane(value: dict[str, Any], index: int, *, _facts=None):
    _index(index)
    spec, root = _context(value, index, _facts=_facts)
    path = _reference(value["lane_intents"][index])
    raw = ordinary._load(ordinary._read(path))
    if isinstance(raw.get("payload"), dict) and "epoch_declaration" in raw["payload"]:
        from . import rapid_class_epochs as classes
        intent, lineage, sites, lane = classes._intent(spec, root, path)
    else:
        if path.parent.parent != root / "lanes":
            raise ValueError("ordinary formal intent escapes its official lane namespace")
        intent, lineage, lane, sites = ordinary._intent_and_lineage(spec, root, path, _context=_facts)
    return spec, root, path, intent, lineage, lane, sites


def _effective_runtime(fact):
    spec, root, _, intent, _, _, _ = fact
    if "epoch_declaration" in intent:
        from .rapid_runtime_epochs import runtime_for_intent
        return runtime_for_intent(spec, root, intent)
    return spec


def prepare_batch(spec_path: Path, evidence_root: Path, campaigns: list[str], output: Path,
                  predecessors: list[Path | None] | None = None, *, second_spec: Path | None = None,
                  installation: Path | None = None, _context=None) -> Path:
    """Claim two ordinary intents after one actual image check; launch no worker."""
    from .rapid_operation_facts import OperationFacts
    _context = OperationFacts() if _context is None else _context
    _context.begin_action()
    spec = ordinary.load_capture_spec(spec_path)
    spec_paths = [spec_path, second_spec if second_spec is not None else spec_path]
    specs = [spec, ordinary.load_capture_spec(spec_paths[1])]
    root = shared.regular_dir(evidence_root)
    if (spec.module_root != spec.runtime_source_root
        or ordinary._read(spec.host_launcher) != ordinary._read(spec.base_launcher)):
        raise ValueError("formal parallel capture requires the newly installed matching Lab runtime")
    if any(specs[1].serializable()[key] != spec.serializable()[key]
           for key in spec.serializable() if key != "plan_receipt"):
        raise ValueError("formal worker specs may differ only in their create-only lane plan receipt")
    if not isinstance(campaigns, list) or len(campaigns) != 2 or len(set(campaigns)) != 2:
        raise ValueError("formal parallel preparation requires two distinct campaign names")
    predecessors = predecessors if predecessors is not None else [None, None]
    if len(predecessors) != 2 or output.exists() or output.is_symlink():
        raise ValueError("formal authority is create-only and needs two predecessor positions")
    installed = _installation_reference(installation, specs, root)
    for item, worker_spec in zip(spec_paths, specs, strict=True):
        _context.watch_file(item)
        _context.bind_capture(worker_spec)
    with ordinary.capture_lock(spec.execution_root), _installation_context(installed):
        _context.check()
        checks = [ordinary.check_bound_image(spec, root, _context=_context)]
        checks.append(checks[0] if specs[1] == spec else ordinary.check_bound_image(specs[1], root, _context=_context))
        sites = [ordinary._validate_image_proof(check["proof"], worker_spec, _context=_context)
                 for worker_spec, check in zip(specs, checks, strict=True)]
        lanes = [ordinary._lane(check["proof"], name) for check, name in zip(checks, campaigns, strict=True)]
        if len({lane.study_version for lane in lanes}) != 1 or len({lane.logical_name for lane in lanes}) != 2:
            raise ValueError("formal parallel preparation requires two distinct lanes under one study contract")
        for worker_spec, check, rows, lane in zip(specs, checks, sites, lanes, strict=True):
            if lane.study_version == 6:
                from . import rapid_rolling_schedule as scheduling
                if installed is not None:
                    raise ValueError("rolling scheduling cannot claim historical installation")
                payload = check["proof"]["plan_payload"]
                from . import rapid_ordinary_parallel_schedule as ordinary_parallel
                if ordinary_parallel.is_payload(payload):
                    if check["proof"]["cohort_generation"] != "rolling-50" or not 1 <= len(rows) <= 5:
                        raise ValueError("ordinary parallel changed rolling cohort scope")
                    ordinary_parallel.require_worker(payload, lane, rows, worker_spec)
                else:
                    if (check["proof"]["cohort_generation"] != "rolling-50" or not 1 <= len(rows) <= 5
                        or lane.visits_per_workload != 4 or len(lane.workload_ids) != len(rows)
                        or lane.sample_count != 4 * len(lane.workload_ids) or "scheduling" not in payload):
                        raise ValueError("rolling parallel preparation requires a prospective scheduling plan")
                scheduling.require_schedule(payload["scheduling"], worker_spec, declared_at=payload["declared_at"], _context=_context)
            elif (lane.study_version != 5 or check["proof"]["cohort_generation"] != "final-50"
                  or len(rows) != 50 or lane.sample_count != 20):
                raise ValueError("formal parallel preparation requires two official final-50 lanes")
            if lane.role != "formal":
                raise ValueError("formal parallel preparation cannot claim diagnostic lanes")
        from . import rapid_ordinary_parallel_schedule as ordinary_parallel
        ordinary_parallel.require_disjoint([(worker_spec, check["proof"]["plan_payload"], lane, rows)
            for worker_spec, check, lane, rows in zip(specs, checks, lanes, sites, strict=True)])
        # Validate both create-only claims and predecessor histories before writing either.
        lineages = []
        for worker_spec, check, lane, predecessor in zip(specs, checks, lanes, predecessors, strict=True):
            if (root / "lanes" / lane.campaign_name).exists() or (spec.execution_root / "results" / lane.campaign_name).exists():
                raise FileExistsError("formal physical lane is already claimed")
            lineages.append(ordinary._lineage_payload(worker_spec, lane, check, root, predecessor, _context=_context))
        _context.check()
        intents = [ordinary.prepare_lane_intent(worker_spec, root, name, check,
                    predecessor_intent=predecessor, actuator=ACTUATOR, _prepared_lineage=lineage, _context=_context)
                   for worker_spec, check, name, predecessor, lineage
                   in zip(specs, checks, campaigns, predecessors, lineages, strict=True)]
        spec_references = [{"path": str(item.absolute()), "sha256": shared.sha(shared.read(item))} for item in spec_paths]
        shared.put(output, {"schema_version": 1, "artifact_type": AUTHORITY_TYPE,
            "runtime": {key: spec.serializable()[key] for key in shared.RUNTIME_KEYS},
            "campaigns": [{"path": str(spec.campaign_dir / f"{name}.yml"),
                           "sha256": shared.sha(shared.read(spec.campaign_dir / f"{name}.yml"))} for name in campaigns],
            "capture_spec": spec_references[0], "lane_specs": spec_references,
            "evidence_root": str(root), "installation": installed,
            "lane_intents": [{"path": str(path), "sha256": shared.sha(shared.read(path))} for path in intents]})
        authority(output, _context=_context)
        _context.check()
    return output


def worker_inputs(path: Path, index: int, *, _audited=None, _context=None) -> dict[str, Any]:
    value, facts = _audit(path, _context=_context) if _audited is None else _audited
    _index(index)
    spec, root, intent_path, intent, _, lane, _ = facts[index]
    roots = {spec.data_root, root, *(Path(row["path"]).parent for row in value["lane_specs"])}
    readiness_roots = None
    if lane.study_version == 6:
        from . import rapid_rolling_capture as rolling
        readiness_roots = rolling.readiness_roots(spec, lane.campaign_name, _context=_context)
        roots.update(readiness_roots)
    if value["installation"] is not None:
        from . import rapid_capture_control_installation as installation
        payload, _ = installation.validate_capsule(_reference(value["installation"]), actual_image=spec.collection_image_digest)
        roots.add(Path(payload["evidence_root"]))
        for role in (payload["base_spec"], payload["runtime_spec"]):
            roots.update(Path(role[key]) for key in ("data_root", "runtime_source_root", "module_root", "execution_root"))
            roots.update(Path(role[key]).parent for key in ("source_manifest", "client_binary", "base_launcher"))
    return {"campaign_path": str(spec.campaign_dir / f"{lane.campaign_name}.yml"),
            "campaign_name": lane.campaign_name,
            "result_namespace": str(spec.execution_root / "results" / lane.campaign_name),
            "dns_path": str(intent_path.parent / "dns.json"),
            "mount_roots": sorted(str(shared.regular_dir(item)) for item in roots),
            "environment": worker_environment(value, index, fact=facts[index], _readiness_roots=readiness_roots, _context=_context)}


def worker_environment(value, index, *, fact=None, _readiness_roots=None, _context=None):
    fact = fact if fact is not None else _lane(value, index, _facts=_context)
    spec, root, intent_path, intent, _, lane, _ = fact
    environment = {}
    if lane.study_version == 6:
        from . import rapid_rolling_capture as rolling
        payload = ordinary._payload(spec.plan_receipt, ordinary.PLAN_TYPE)
        environment["QCSD_RAPID_COLLECTION_COMPATIBILITY"] = str(_reference(payload["scheduling"]))
        environment["QCSD_RAPID_ROLLING_LAUNCH_INPUT"] = json.dumps({"spec": spec.serializable(),
            "root": str(root), "intent": str(intent_path), "intent_sha256": shared.sha(shared.read(intent_path)),
            "readiness_mount_roots": [str(path) for path in (
                rolling.readiness_roots(spec, lane.campaign_name, _context=_context)
                if _readiness_roots is None else _readiness_roots)]}, sort_keys=True)
    if value["installation"] is not None:
        installation_path = str(_reference(value["installation"]))
        environment["QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION"] = installation_path
        environment["QCSD_RAPID_COLLECTION_COMPATIBILITY"] = installation_path
    if "epoch_declaration" in intent:
        runtime = _effective_runtime(fact)
        environment["QCSD_RAPID_EPOCH_LAUNCH_INPUT"] = json.dumps({"spec": runtime.serializable(),
            "root": str(root), "intent": str(intent_path), "intent_sha256": shared.sha(shared.read(intent_path))}, sort_keys=True)
        if "runtime_epoch" in intent:
            from .rapid_runtime_epochs import COMPATIBILITY_ENV
            relative = intent_path.relative_to(root).as_posix().replace("/", "-")
            capsule = spec.execution_root / "config/rapid-runtime-epochs" / f"{relative}-authority.json"
            if not capsule.exists():
                raise ValueError("registered runtime worker lacks its durable launch capsule")
            environment[COMPATIBILITY_ENV] = str(capsule)
    return environment


def prepare_registered_batch(spec_path: Path, evidence_root: Path, requests: list[dict[str, Any]],
                             output: Path, *, second_spec: Path | None = None,
                             installation: Path | None = None) -> Path:
    """Claim current class/runtime block lanes using their existing authorities."""
    from . import rapid_class_epochs as classes
    from . import rapid_runtime_epochs as epochs
    paths = [spec_path, second_spec if second_spec is not None else spec_path]
    specs = [ordinary.load_capture_spec(path) for path in paths]
    root = shared.regular_dir(evidence_root)
    if (not isinstance(requests, list) or len(requests) != 2
        or any(not isinstance(row, dict) or set(row) != {"declaration", "mode", "generation", "predecessor", "activation"}
               for row in requests)):
        raise ValueError("registered parallel batch needs two exact block lane requests")
    if any(type(row["generation"]) is not int or not 1 <= row["generation"] <= 99 for row in requests):
        raise ValueError("registered parallel generations must be integers in 1..99")
    if output.exists() or output.is_symlink():
        raise FileExistsError("registered parallel authority is create-only")
    if any(specs[1].serializable()[key] != specs[0].serializable()[key]
           for key in specs[0].serializable() if key != "plan_receipt"):
        raise ValueError("registered worker specs changed their underlying cohort or qualified inputs")
    prepared = []
    installed = _installation_reference(installation, specs, root)
    with ordinary.capture_lock(specs[0].execution_root), _installation_context(installed):
        # Read both actual block/predecessor histories before claiming either.
        claims = [_registered_claim(spec, root, request) for spec, request in zip(specs, requests, strict=True)]
        runtimes = [claim[0] for claim in claims]
        runtime_rows = [{key: runtime.serializable()[key] for key in shared.RUNTIME_KEYS} for runtime in runtimes]
        if runtime_rows[0] != runtime_rows[1]:
            raise ValueError("a registered parallel batch cannot mix collection images or Native/runtime sources")
        if len({claim[1].logical_name for claim in claims}) != 2:
            raise ValueError("registered parallel batch repeats one logical lane")
        checks = [classes.check_bound_image(spec, root, Path(request["declaration"]))
                  if request["activation"] is None else None
                  for spec, request in zip(specs, requests, strict=True)]
        for spec, request, checked, runtime in zip(specs, requests, checks, runtimes, strict=True):
            if request["activation"] is None:
                prepared.append(classes.prepare_block_lane_intent(spec, root, Path(request["declaration"]),
                    mode=request["mode"], generation=request["generation"],
                    predecessor_intent=request["predecessor"], checked=checked, actuator=ACTUATOR))
            else:
                path = epochs.prepare_repaired_lane_intent(spec, root, Path(request["activation"]),
                    predecessor_intent=request["predecessor"], actuator=ACTUATOR)
                epochs._capsule(spec, root, path, runtime)
                prepared.append(path)
        rows = [ordinary._host_intent(shared.read(path)) for path in prepared]
        references = [{"path": str(path.absolute()), "sha256": shared.sha(shared.read(path))} for path in paths]
        shared.put(output, {"schema_version": 1, "artifact_type": AUTHORITY_TYPE, "runtime": runtime_rows[0],
            "campaigns": [{"path": str(spec.campaign_dir / f"{row['campaign_name']}.yml"),
                           "sha256": row["campaign_sha256"]} for spec, row in zip(specs, rows, strict=True)],
            "capture_spec": references[0], "lane_specs": references, "evidence_root": str(root), "installation": installed,
            "lane_intents": [{"path": str(path), "sha256": shared.sha(shared.read(path))} for path in prepared]})
        authority(output)
    return output


def _installation_reference(path, specs, root):
    if path is None:
        return None
    from . import rapid_capture_control_installation as installation
    payload, _ = installation.validate_capsule(path, actual_image=specs[0].collection_image_digest)
    if payload["evidence_root"] != str(root):
        raise ValueError("formal installation belongs to another evidence root")
    for spec in specs:
        installation.check_current_spec(payload, spec)
    return {"path": str(path.absolute()), "sha256": shared.sha(shared.read(path))}


@contextmanager
def _installation_context(reference):
    if reference is None:
        yield
        return
    path = str(_reference(reference))
    environment = {"QCSD_RAPID_COLLECTION_COMPATIBILITY": path,
                   "QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION": path}
    saved = {key: os.environ.get(key) for key in environment}
    os.environ.update(environment)
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def _registered_claim(spec, root, request):
    """Validate a create-only claim without writing its campaign or intent."""
    from . import rapid_class_epochs as classes
    from . import rapid_runtime_epochs as epochs
    declaration = Path(request["declaration"])
    block, sites = classes.verify_block(spec, root, declaration)
    if (declaration.parent / "commit.json").exists() or (declaration.parent / "retirement.json").exists():
        raise ValueError("committed or retired block cannot launch more captures")
    generation = request["generation"]
    lane = classes._epoch_lane(block, sites, request["mode"], generation)
    runtime = spec
    predecessor = request["predecessor"]
    if request["activation"] is not None:
        _, proposal, runtime = epochs.verify_activation(spec, root, Path(request["activation"]))
        if proposal["declaration"] != classes._reference(root, declaration) or proposal["mode"] != lane.mode:
            raise ValueError("registered worker activation belongs to another class block or defense")
        previous_path = predecessor or classes._child(root, proposal["failed_intent"])
        previous, _, _, previous_lane = classes._intent(spec, root, previous_path)
        if (previous["epoch_declaration"] != proposal["declaration"] or previous_lane.mode != lane.mode
            or previous_lane.generation + 1 != generation
            or previous_path != classes._child(root, proposal["failed_intent"])
            and previous.get("runtime_epoch") != classes._reference(root, Path(request["activation"]))):
            raise ValueError("registered runtime request skips its immediate failed generation")
        classes._incomplete_predecessor(spec, root, previous_path, previous_lane)
    elif generation == 1:
        if predecessor is not None:
            raise ValueError("initial epoch lane cannot consume a predecessor")
    else:
        previous_lane = classes._epoch_lane(block, sites, lane.mode, generation - 1)
        previous_path = declaration.parent / "lanes" / previous_lane.campaign_name / "intent.json"
        if predecessor != previous_path or (previous_path.parent / "complete.json").exists():
            raise ValueError("ordinary epoch retry requires its actual immediate incomplete predecessor")
        classes._intent(spec, root, previous_path)
        classes._incomplete_predecessor(spec, root, previous_path, previous_lane)
    directory = declaration.parent / "lanes" / lane.campaign_name
    namespace = spec.execution_root / "results" / lane.campaign_name
    if any(path.exists() or path.is_symlink() for path in (directory, namespace)):
        raise FileExistsError("epoch physical lane namespace was previously claimed")
    campaign = spec.campaign_dir / f"{lane.campaign_name}.yml"
    raw = classes.render_epoch_lane(lane, sites, block["ordinal"])
    if generation == 1:
        if ordinary._read(campaign) != raw:
            raise ValueError("initial epoch campaign differs from its declaration")
    elif campaign.exists() or campaign.is_symlink():
        raise FileExistsError("epoch successor campaign was previously claimed")
    return runtime, lane


@contextmanager
def _worker_context(value, index, fact, *, _environment=None):
    environment = worker_environment(value, index, fact=fact) if _environment is None else _environment
    saved = {key: os.environ.get(key) for key in environment}
    os.environ.update(environment)
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def _workloads(spec, lane, sites):
    return {site.workload_id: ordinary._read(spec.workload_root / f"{site.workload_id}.json")
            for site in sites if site.workload_id in lane.workload_ids}


def resolve_dns(path: Path, index: int) -> dict[str, Any]:
    """Executed in the immutable collection image for this worker's full graph."""
    from .class_acquisition import public_origin_ip_pins
    from .orchestrator import load_campaign
    value, facts = _audit(path)
    spec, _, _, _, _, lane, _ = facts[index]
    with _worker_context(value, index, facts[index]), shared._execution_parameter_context(value):
        campaign = load_campaign(spec.campaign_dir / f"{lane.campaign_name}.yml")
    origins = sorted({origin for workload in campaign.workloads
                      for origin in workload.data["preparation"]["approved_origins"]})
    rows = public_origin_ip_pins(origins)
    hosts = {}
    for origin, address in rows.items():
        host = urlsplit(origin).hostname
        if host is None or ipaddress.ip_address(address).version != 4 or not ipaddress.ip_address(address).is_global:
            raise ValueError("formal worker DNS requires a public IPv4 pin per approved origin")
        if host in hosts and hosts[host] != address:
            raise ValueError("formal worker DNS pins disagree for one hostname")
        hosts[host] = address
    return {"schema_version": 1, "campaign": lane.campaign_name,
            "hosts": [[host, hosts[host]] for host in sorted(hosts)]}


def image_preflight(path: Path, expected_sha: str, *, _context=None) -> dict[str, Any]:
    from .runtime_provenance import validate_runtime_receipt
    from .orchestrator import load_campaign
    if shared.sha(shared.read(path)) != expected_sha:
        raise ValueError("formal authority changed before image preflight")
    from .rapid_operation_facts import OperationFacts
    _context = OperationFacts() if _context is None else _context
    _context.begin_action()
    value, facts = _audit(path, _context=_context)
    environments = [worker_environment(value, index, fact=facts[index], _context=_context) for index in range(2)]
    spec = _effective_runtime(facts[0])
    proofs = []
    epoch_proofs = []
    runtime_proofs = []
    for index in range(2):
        worker_spec, root, intent_path, intent, block, lane, _ = facts[index]
        with _context.scope(), _worker_context(value, index, facts[index], _environment=environments[index]):
            if "runtime_epoch" in intent:
                from . import rapid_runtime_epochs as epochs
                from . import rapid_class_epochs as classes
                runtime = _effective_runtime(facts[index])
                epochs.validate_host_launch(json.loads(worker_environment(value, index, fact=facts[index])[
                    "QCSD_RAPID_EPOCH_LAUNCH_INPUT"]), expected_campaign=lane.campaign_name,
                    actual_image=runtime.collection_image_digest)
                _, proposal, _ = epochs.verify_activation(worker_spec, root, classes._child(root, intent["runtime_epoch"]))
                proof = proposal["original_block_check"]["proof"]["base_proof"]
                epoch_proof = None
                runtime_proof = ordinary.executed_image_runtime_check(value["runtime"])
                if runtime_proof != proposal["candidate_check"]["proof"]["runtime_proof"]:
                    raise ValueError("formal worker runtime differs from its activated actual image")
                classes._block_sites(worker_spec, root, block, classes.verify_policy(worker_spec, root), require_current=True)
            elif "epoch_declaration" in intent:
                from . import rapid_class_epochs as classes
                epoch_proof = classes.executed_image_epoch_check({"spec": worker_spec.serializable(),
                    "root": str(root), "declaration": str(classes._child(root, intent["epoch_declaration"]))})
                proof = epoch_proof["base_proof"]
                from .rapid_runtime_epochs import _runtime_projection
                runtime_proof = _runtime_projection(proof)
            else:
                proof = (proofs[0] if index == 1 and worker_spec == facts[0][0]
                         and "epoch_declaration" not in facts[0][3]
                         else ordinary.executed_image_plan_check(worker_spec.serializable(), _context=_context))
                epoch_proof = None
                from .rapid_runtime_epochs import _runtime_projection
                runtime_proof = _runtime_projection(proof)
        ordinary._validate_image_proof(proof, worker_spec, _context=_context)
        proofs.append(proof)
        epoch_proofs.append(epoch_proof)
        runtime_proofs.append(runtime_proof)
    if runtime_proofs[0] != runtime_proofs[1]:
        raise ValueError("formal workers did not execute the same installed runtime")
    installed = validate_runtime_receipt(required_schema_version=2)
    for relative, digest in installed["source_files"].items():
        if shared.sha(shared.read(spec.runtime_source_root / relative)) != digest:
            raise ValueError("formal parallel full installed source differs")
    for relative in ("rapid_parallel_capture.py", "rapid_formal_parallel.py"):
        source = spec.runtime_source_root / "src/qcsd_lab" / relative
        if shared.read(Path(__file__).parent / relative) != shared.read(source):
            raise ValueError("formal parallel installed coordinator differs from source")
    files = {str(_reference(row)): row["sha256"] for row in value["lane_specs"]}
    campaigns = []
    hosts = set()
    for index in range(2):
        worker_spec, _, intent_path, _, _, lane, sites = facts[index]
        with _context.scope(), _worker_context(value, index, facts[index], _environment=environments[index]), shared._execution_parameter_context(value):
            campaign = load_campaign(Path(value["campaigns"][index]["path"]))
        paths = [campaign.path, intent_path, worker_spec.qualification_spec, worker_spec.plan_receipt, worker_spec.cohort]
        for workload in campaign.workloads:
            paths.extend(getattr(workload, key) for key in ("path", "chaff_qualification_path",
                "chaff_manifest_path", "qualification_set_manifest_path") if getattr(workload, key) is not None)
            hosts.update(urlsplit(origin).hostname for origin in workload.data["preparation"]["approved_origins"])
        for defense in campaign.defenses:
            paths.extend(getattr(defense, key) for key in ("parameters_path", "parameters_provenance_path")
                         if getattr(defense, key) is not None)
        files.update({str(item): shared.sha(shared.read(item)) for item in paths})
        campaigns.append({"name": lane.campaign_name, "mode": lane.mode,
                          "workloads": {name: shared.sha(raw) for name, raw in _workloads(spec, lane, sites).items()}})
    _context.check()
    return {"authority_sha256": expected_sha, "runtime": runtime_proofs[0], "worker_plan_proofs": proofs,
            "worker_epoch_proofs": epoch_proofs, "worker_runtime_proofs": runtime_proofs, "python_runtime_receipt": installed,
            "input_files": files, "campaigns": campaigns, "approved_hostnames": sorted(hosts),
            "formal_accepted_trace_count": 0, "scientific_credit": False}


def _preflight(value, output, expected_sha, *, facts=None, _context=None):
    proof = shared.reopen_preflight(output, expected_sha)
    if (len(proof["worker_plan_proofs"]) != 2 or len(proof["worker_epoch_proofs"]) != 2
        or len(proof["worker_runtime_proofs"]) != 2
        or proof["worker_runtime_proofs"] != [proof["runtime"], proof["runtime"]]):
        raise ValueError("formal per-worker image plan proofs differ")
    for index in range(2):
        spec, root, _, intent, _, _, _ = facts[index] if facts is not None else _lane(value, index)
        ordinary._validate_image_proof(proof["worker_plan_proofs"][index], spec, _context=_context)
        if "runtime_epoch" in intent:
            from . import rapid_class_epochs as classes
            from . import rapid_runtime_epochs as epochs
            _, proposal, _ = epochs.verify_activation(spec, root, classes._child(root, intent["runtime_epoch"]))
            if (proof["worker_epoch_proofs"][index] is not None
                or proof["worker_runtime_proofs"][index] != proposal["candidate_check"]["proof"]["runtime_proof"]
                or proof["worker_plan_proofs"][index] != proposal["original_block_check"]["proof"]["base_proof"]):
                raise ValueError("formal preflight changed its activated runtime or original qualification proof")
        else:
            from .rapid_runtime_epochs import _runtime_projection
            if proof["worker_runtime_proofs"][index] != _runtime_projection(proof["worker_plan_proofs"][index]):
                raise ValueError("formal preflight changed its actual installed runtime")
            epoch_proof = proof["worker_epoch_proofs"][index]
            if "epoch_declaration" in intent:
                from . import rapid_class_epochs as classes
                declaration = classes._child(root, intent["epoch_declaration"])
                _, sites = classes.verify_block(spec, root, declaration)
                if (not isinstance(epoch_proof, dict) or set(epoch_proof) != {"schema_version", "artifact_type",
                        "base_proof", "policy", "declaration", "effective_sites", "scientific_credit"}
                    or type(epoch_proof["schema_version"]) is not int or epoch_proof["schema_version"] != 1
                    or epoch_proof["artifact_type"] != classes.IMAGE_TYPE or epoch_proof["scientific_credit"] is not False
                    or epoch_proof["base_proof"] != proof["worker_plan_proofs"][index]
                    or epoch_proof["policy"] != classes._reference(root, root / "policy.json")
                    or epoch_proof["declaration"] != classes._reference(root, declaration)
                    or epoch_proof["effective_sites"] != [asdict(site) for site in sites]):
                    raise ValueError("formal preflight changed its actual declared class block")
            elif epoch_proof is not None:
                raise ValueError("ordinary formal preflight invented a class epoch")
    return proof


def _dns_bindings(value, *, facts=None):
    rows = []
    for index in range(2):
        spec, _, intent_path, _, _, lane, sites = facts[index] if facts is not None else _lane(value, index)
        dns_path = intent_path.parent / "dns.json"
        digest = ordinary.verify_dns_receipt(ordinary._read(dns_path), lane.campaign_name, _workloads(spec, lane, sites))
        rows.append({"path": str(dns_path), "sha256": digest})
    return rows


def initialize(path: Path, output: Path, expected_sha: str, available: list[int], *, _context=None) -> dict[str, Any]:
    from .rapid_operation_facts import OperationFacts
    _context = OperationFacts() if _context is None else _context
    _context.begin_action()
    value, facts = _audit(path, _context=_context)
    if shared.sha(shared.read(path)) != expected_sha:
        raise ValueError("formal authority changed before initialization")
    output = shared.regular_dir(output)
    preflight = _preflight(value, output, expected_sha, facts=facts, _context=_context)
    dns = _dns_bindings(value, facts=facts)
    cpu = shared.select_pairs(available)
    # Validate both destinations before allocating either canonical namespace.
    namespaces = [fact[0].execution_root / "results" / fact[5].campaign_name for fact in facts]
    if any(namespace.exists() or namespace.is_symlink() for namespace in namespaces):
        raise FileExistsError("formal worker namespace is already claimed")
    _context.check()
    for index, namespace in enumerate(namespaces):
        lane = output / f"lane-{index+1}"
        lane.mkdir()
        for name in ("capture", "gate"):
            (lane / name).mkdir()
        namespace.mkdir(parents=True)
    shared.put(output / "batch-intent.json", {"schema_version": 1, "authority_sha256": expected_sha,
        "authority_path": str(path.absolute()), "authority": value, "created_at": shared.now(),
        "cpu_selection": cpu, "image_preflight_sha256": shared.sha(shared.read(output / "image-preflight.json")),
        "dns_pins": dns, "preflight": preflight, "formal_accepted_trace_count": 0, "scientific_credit": False})
    return cpu


def _reopen_intent(path, output, value, *, facts=None, _context=None):
    intent = shared.load(output / "batch-intent.json")
    if (intent["authority_sha256"] != shared.sha(shared.read(path)) or intent["authority"] != value
        or intent["authority_path"] != str(path.absolute())
        or intent["image_preflight_sha256"] != shared.sha(shared.read(output / "image-preflight.json"))
        or intent["dns_pins"] != _dns_bindings(value, facts=facts)):
        raise ValueError("formal batch input or independent DNS binding changed")
    _preflight(value, output, intent["authority_sha256"], facts=facts, _context=_context)
    return intent


def _partitions(value, intent, actual):
    from .process_scheduler import build_peer_host_partition
    workers = actual["workers"]
    if (len(workers) != 2 or len(actual["sidecars"]) != 2 or len({row["id"] for row in workers}) != 2
        or any(row["image_id"] != value["runtime"]["collection_image_digest"] for row in workers)
        or [[row["client_cpu"], row["orchestrator_cpu"]] for row in workers] != intent["cpu_selection"]["pairs"]
        or actual["available_cpus"] != intent["cpu_selection"]["sidecar_cpus"]
           + intent["cpu_selection"]["pairs"][0] + intent["cpu_selection"]["pairs"][1]):
        raise ValueError("formal actual workers differ from their immutable runtime and CPU allocation")
    return [build_peer_host_partition(actual["inspected_containers"], actual["available_cpus"],
                workers, actual["sidecars"], worker["id"], docker_ncpu=actual["docker_ncpu"]) for worker in workers]


def _operator_start(path, output, value):
    from .rapid_lane_evidence import HOST_GATE_SCRIPT
    start = shared.load(output / "host-start.json")
    operator = shared.load(output / "operator-intent.json")
    command = [value["runtime"]["host_launcher"], "parallel-formal-run", str(path), str(output)]
    argv = start["host"]["argv"]
    if (start["command"] != command or operator["command"] != command
        or start["authority_sha256"] != shared.sha(shared.read(path))
        or operator["authority_sha256"] != start["authority_sha256"]
        or start["gate_script_sha256"] != shared.sha(HOST_GATE_SCRIPT.encode())
        or len(argv) != 5 or argv[1:3] != ["-c", HOST_GATE_SCRIPT]
        or json.loads(argv[3]) != command or not argv[4].isdigit()):
        raise ValueError("formal worker lacks its actual gated batch host invocation")
    return start, command


def _worker_inputs_actual(value, output, index, actual, *, fact=None, _environment=None, _context=None):
    """Reopen the inspected mount and DNS isolation, not just claimed argv."""
    spec, _, intent_path, _, _, lane, _ = fact if fact is not None else _lane(value, index)
    worker = actual["workers"][index]
    observed = next(item for item in actual["inspected_containers"] if item["Id"] == worker["id"])
    shared._worker_identity(observed, worker)
    mounts = observed["Mounts"]
    namespace = str(spec.execution_root / "results" / lane.campaign_name)
    if (sum(item["Destination"] == "/lab/results" and item["Source"] == str(spec.execution_root / "results")
            and item["RW"] is False for item in mounts) != 1
        or sum(item["Destination"] == f"/lab/results/{lane.campaign_name}" and item["Source"] == namespace
               and item["RW"] is True for item in mounts) != 1
        or any(item["RW"] is not False and (item["Destination"] == "/lab"
               or item["Destination"].startswith("/lab/results"))
               and (item["Destination"] != f"/lab/results/{lane.campaign_name}" or item["Source"] != namespace)
               for item in mounts)):
        raise ValueError("formal worker does not own only its canonical writable result namespace")
    dns = shared.load(intent_path.parent / "dns.json")
    # Docker inspect canonicalizes --add-host HOST=IP to HOST:IP.
    expected = sorted(f"{host}:{address}" for host, address in dns["hosts"])
    if sorted(observed["HostConfig"].get("ExtraHosts") or []) != expected:
        raise ValueError("formal actual worker DNS pins differ from its independent receipt")
    environment = {}
    for row in observed["Config"].get("Env") or []:
        key, separator, item = row.partition("=")
        if separator:
            if key in environment:
                raise ValueError("formal actual worker environment repeats a key")
            environment[key] = item
    expected_environment = (worker_environment(value, index, fact=fact, _context=_context)
                            if _environment is None else _environment)
    if any(environment.get(key) != item for key, item in expected_environment.items()):
        raise ValueError("formal actual worker environment belongs to another official intent")
    argv = shared.load(output / f"lane-{index+1}" / "worker-argv.json")
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        raise ValueError("formal worker lacks retained actual Docker launch argv")
    return shared.sha(shared.read(output / f"lane-{index+1}" / "worker-argv.json"))


def _release_fence(path, value, facts, preflight):
    """Finite immutable inputs checked before birth, excluding live results.

    This hashes bytes and membership, not scientific summaries. The full
    validators run before it is minted and still run in each installed worker
    and ordinary deep verifier. No frame survives a public operation.
    """
    from . import rapid_rolling_readiness as evidence
    from . import rapid_rolling_capture as rolling
    from . import rapid_ordinary_parallel_schedule as ordinary_parallel
    import stat as permissions
    full_modes = any(ordinary_parallel.is_payload(fact[4]["image_check"]["proof"]["plan_payload"]) for fact in facts)
    files, trees, documents, runtimes = {}, {}, set(), set()

    def file(item, expected=None):
        item = Path(item).absolute()
        raw = shared.read(item)
        if expected is not None and shared.sha(raw) != expected:
            raise ValueError("formal release input changed before its byte fence was minted")
        files[str(item)] = {"sha256": shared.sha(raw), "executable": bool(item.stat().st_mode & 0o111)}
        if full_modes:
            files[str(item)]["mode"] = permissions.S_IMODE(item.stat().st_mode)
        return raw

    def tree(item, expected=None):
        item = shared.regular_dir(Path(item))
        if str(item) in trees:
            previous = trees[str(item)]
            if full_modes and "files" in previous:
                previous = {name: {key: value for key, value in record.items() if key != "mode"}
                    for name, record in previous["files"].items()}
            if expected is not None and previous != expected:
                raise ValueError("formal release source tree differs from its closed inventory")
            return
        inventory = evidence._inventory(item)
        if expected is not None and inventory != expected:
            raise ValueError("formal release source tree differs from its closed inventory")
        if full_modes:
            observed = {name: {**record, "mode": permissions.S_IMODE((item / name).stat().st_mode)}
                for name, record in inventory.items()}
            directories = {".": permissions.S_IMODE(item.stat().st_mode),
                **{path.relative_to(item).as_posix(): permissions.S_IMODE(path.stat().st_mode)
                   for path in item.rglob("*") if path.is_dir() and ".git" not in path.relative_to(item).parts}}
            trees[str(item)] = {"files": observed, "directories": directories}
            files.update({str(item / name): record for name, record in observed.items()})
        else:
            trees[str(item)] = inventory
            files.update({str(item / name): record for name, record in inventory.items()})

    def references(item, root):
        if isinstance(item, dict):
            if item.get("artifact_type") == "qcsd-chaff-qualification-implementation":
                # These executable paths name the image namespace. The
                # authenticated host source/client roles are fenced below;
                # actual installed executables were checked in preflight.
                return
            if set(item) == {"path", "sha256"}:
                target = Path(item["path"])
                target = target if target.is_absolute() else root / target
                raw = file(target, item["sha256"])
                # Follow only authenticated lab receipt containers, never a
                # webpage's JSON body or arbitrary absolute-path strings.
                if str(target) not in documents:
                    documents.add(str(target))
                    try:
                        document = ordinary._load(raw)
                    except (ValueError, UnicodeError, TypeError):
                        document = None
                    if (isinstance(document, dict)
                        and isinstance(document.get("receipt_type"), str)
                        and document["receipt_type"].startswith("qcsd-")):
                        references(document, root)
            else:
                for child in item.values():
                    references(child, root)
        elif isinstance(item, list):
            for child in item:
                references(child, root)

    def runtime(reference, role):
        canonical_path = _reference(reference)
        if str(canonical_path) in runtimes:
            return
        runtimes.add(str(canonical_path))
        canonical = shared.load(canonical_path)
        directory = canonical_path.parent
        # Canonical runtime roots are closed. Record their shallow recipe,
        # command, status and raw-log inventory, plus both source copies.
        names = sorted(item.name for item in directory.iterdir() if item.is_file())
        trees[str(directory)] = {"shallow_files": names}
        if full_modes:
            trees[str(directory)]["mode"] = permissions.S_IMODE(directory.stat().st_mode)
        for name in names:
            file(directory / name)
        for name, record in canonical["actual_operation_completions"].items():
            file(directory / (name + "-started.json"), record["started_record_sha256"])
            completed = ordinary._load(file(directory / (name + "-completed.json"), record["record_sha256"]))
            file(directory / (name + ".stdout.log"), completed["stdout_sha256"])
            file(directory / (name + ".stderr.log"), completed["stderr_sha256"])
        inventory = shared.load(directory / "source-inventory.json")
        file(directory / "source-inventory.json", canonical["source_inventory_sha256"])
        tree(Path(role["runtime_source_root"]), inventory)
        tree(directory / "image-context/source", inventory)
        references(canonical, directory)
        previous = canonical.get("original_canonical")
        if previous is not None:
            original_root = _reference(previous).parent / "image-context/source"
            original_role = {"runtime_source_root": str(original_root)}
            runtime(previous, original_role)

    file(path)
    references(value, Path(value["evidence_root"]))
    for name in preflight["input_files"]:
        file(name)
    seen_specs, seen_canaries = set(), set()
    for spec, root, intent_path, _, _, lane, sites in facts:
        for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher",
                     "qualification_spec", "plan_receipt", "cohort"):
            file(getattr(spec, name))
        file(intent_path)
        file(intent_path.parent / "lineage.json")
        file(intent_path.parent / "dns.json")
        key = shared.sha(ordinary._json(spec.serializable()))
        if key not in seen_specs:
            seen_specs.add(key)
            from . import rapid_selected_capture_input as selected
            payload = ordinary._payload(spec.plan_receipt, ordinary.PLAN_TYPE)
            from . import rapid_ordinary_parallel_schedule as ordinary_parallel
            selected_context = payload.get("data_role") == selected.ROLE
            if ordinary_parallel.is_payload(payload):
                capsule = ordinary_parallel.require_plan(payload)
                base = ordinary_parallel._spec(capsule["base_spec"])
                own_files, own_trees = ordinary_parallel.input_dependencies(base, sites)
                references(capsule, Path(payload["scheduling"]["path"]).parent)
                for item in own_files:
                    file(item)
                for item in own_trees:
                    tree(item)
                for site in sites:
                    file(spec.workload_root / f"{site.workload_id}.json", site.workload_sha256)
                runtime(capsule["current_canonical"], capsule["runtime"])
                static_context = None
            elif selected_context:
                from . import rapid_selected_parallel_schedule as selected_schedule
                payload = ordinary._payload(spec.plan_receipt, ordinary.PLAN_TYPE)
                capsule = selected_schedule.require_plan(payload)
                selected_files, selected_trees = selected_schedule.input_dependencies(
                    spec.cohort, spec.workload_root, payload["sites"])
                for item in selected_files:
                    file(item)
                for item in selected_trees:
                    tree(item)
                static_context = None
            else:
                batch_path = spec.cohort
                while True:
                    batch = ordinary.admission._unpack(file(batch_path), rolling.ENROLLMENT_TYPE)
                    policy_path = rolling._open_ref(batch["policy"])
                    policy_raw = file(policy_path)
                    policy_type = ordinary._load(policy_raw).get("receipt_type")
                    if policy_type not in {rolling.POLICY_TYPE, rolling.STATIC_POLICY_TYPE}:
                        raise ValueError("formal release fence has an unknown policy role")
                    policy = ordinary.admission._unpack(policy_raw, policy_type)
                    references(policy, policy_path.parent)
                    initial = Path(policy["initial_admission_root"])
                    references(shared.load(initial / "provenance.json"), initial)
                    file(initial / "provenance.json")
                    context_root = Path(batch["admission_root"])
                    references(shared.load(context_root / "provenance.json"), context_root)
                    file(context_root / "provenance.json")
                    references(batch, context_root)
                    from . import supplied_static_admission as static
                    static_context = (rolling._context_for_policy(policy, context_root)
                                      if policy.get("contract") == rolling.STATIC_CONTRACT else None)
                    from . import whole_graph_supplement as whole
                    from . import supplied_static_budget_successor as budget
                    from . import static_budget_capture as budget_capture
                    budget_context = isinstance(static_context, (budget.Context, budget_capture.Context))
                    for decision in batch["decisions"]:
                        terminal = rolling._open_ref(decision["terminal"])
                        # Only the enrolled ordered decisions, never the whole
                        # active acquisition/archive tree or its checkpoints.
                        tree(terminal.parent)
                        terminal_type = (ordinary._load(file(terminal)).get("receipt_type") if isinstance(static_context, whole.Context) or budget_context
                            else static.TERMINAL_TYPE if isinstance(static_context, static.Context) else ordinary.admission.TERMINAL_TYPE)
                        if budget_context and terminal_type not in {budget.TERMINAL_TYPE, whole.TERMINAL_TYPE, static.TERMINAL_TYPE}:
                            raise ValueError("formal release fence has an unknown response-budget terminal role")
                        if isinstance(static_context, whole.Context) and terminal_type not in {whole.TERMINAL_TYPE, static.TERMINAL_TYPE}:
                            raise ValueError("formal release fence has an unknown mixed static terminal role")
                        references(ordinary.admission._unpack(file(terminal), terminal_type), context_root)
                    if isinstance(static_context, (static.Context, whole.Context)) or budget_context:
                        from .rapid_static_parallel_schedule import terminal_inputs
                        static_files, static_trees = terminal_inputs(batch_path)
                        for item in static_files:
                            file(item)
                        for item in static_trees:
                            tree(item)
                    if batch["parent"] is None:
                        break
                    batch_path = rolling._open_ref(batch["parent"])
            if not ordinary_parallel.is_payload(payload):
                qualifier = shared.load(spec.qualification_spec)["qualification_sets"][0]
                for name in ("manifest", "sidecar_root"):
                    target = Path(qualifier[name])
                    target = target if target.is_absolute() else spec.qualification_spec.parent / target
                    tree(target) if name == "sidecar_root" else file(target)
                for site in sites:
                    file(spec.workload_root / f"{site.workload_id}.json", site.workload_sha256)
                    if not selected_context and not isinstance(static_context, (static.Context, whole.Context, budget.Context, budget_capture.Context)):
                        tree(spec.workload_root / f"{site.workload_id}-application-response-evidence")
            payload = ordinary._payload(spec.plan_receipt, ordinary.PLAN_TYPE)
            capsule = shared.load(_reference(payload["scheduling"]))
            file(payload["scheduling"]["path"])
            if not ordinary_parallel.is_payload(payload):
                sidecars = Path(qualifier["sidecar_root"])
                sidecars = sidecars if sidecars.is_absolute() else spec.qualification_spec.parent / sidecars
                tree(sidecars, capsule["qualified_inputs"]["qualification_files"])
                for site in sites:
                    if selected_context:
                        from . import rapid_selected_parallel_schedule as selected_schedule
                        if (capsule.get("artifact_type") != selected_schedule.CAPSULE_TYPE
                            or capsule["qualified_inputs"]["workloads"][site.workload_id]["workload_sha256"] != site.workload_sha256):
                            raise ValueError("selected release fence requires its exact inline raw GET capsule")
                    elif isinstance(static_context, static.Context):
                        from .rapid_static_parallel_schedule import CAPSULE_TYPE as STATIC_CAPSULE_TYPE
                        from .rapid_original_static_parallel_schedule import CAPSULE_TYPE as ORIGINAL_STATIC_CAPSULE_TYPE
                        if (capsule.get("artifact_type") not in {STATIC_CAPSULE_TYPE, ORIGINAL_STATIC_CAPSULE_TYPE}
                            or capsule["qualified_inputs"]["workloads"][site.workload_id]["application_evidence"] is not None):
                            raise ValueError("static release fence requires its authenticated inline GET capsule")
                    else:
                        tree(spec.workload_root / f"{site.workload_id}-application-response-evidence",
                             capsule["qualified_inputs"]["workloads"][site.workload_id]["application_evidence"])
                runtime(capsule["original_canonical"], capsule["base_spec"])
                runtime(capsule["current_canonical"], capsule["runtime"])
        payload = ordinary._payload(spec.plan_receipt, ordinary.PLAN_TYPE)
        reference = payload["readiness"][lane.mode]
        marker = shared.sha(ordinary._json(reference))
        if marker not in seen_canaries:
            seen_canaries.add(marker)
            references(reference, spec.data_root)
            canary = shared.load(_reference(reference["plan"]))
            inventory_path = Path(reference["plan"]["path"]).parent / "source-inventory.json"
            inventory = shared.load(inventory_path)
            file(inventory_path, canary["canonical_runtime"]["source_inventory_sha256"])
            tree(Path(canary["clean_runtime_root"]), inventory)
            for name, record in inventory.items():
                file(Path(canary["execution_root"]) / name, record["sha256"])
                if files[str(Path(canary["execution_root"]) / name)]["executable"] is not record["executable"]:
                    raise ValueError("formal release canary source executable mode changed")
            deep = shared.load(_reference(reference["deep_receipt"]))
            result = Path(canary["execution_root"]) / "results" / Path(deep["root"]).relative_to("/lab/results")
            from .verification import _read_checksums, authoritative_files
            file(result / "evidence.sha256", deep["evidence_index_sha256"])
            checksums = _read_checksums(result, result / "evidence.sha256")
            sealed = authoritative_files(result)
            if set(sealed) != set(checksums):
                raise ValueError("formal release canary seal changed membership")
            for name, item in sealed.items():
                file(item, checksums[name])
            tree(result)
            if reference.get("source_equivalence") is not None:
                equivalence = shared.load(_reference(reference["source_equivalence"]))
                references(equivalence, spec.data_root)
    return {"files": files, "trees": trees}


def _check_release_fence(fence, path, value, facts, preflight):
    if not isinstance(fence, dict) or set(fence) != {"files", "trees"}:
        raise ValueError("prepared release lacks its exact immutable input fence")
    # Derive membership again from the sealed, source-checked authority. A
    # forged frame cannot omit a changed child or substitute arbitrary paths.
    if _release_fence(path, value, facts, preflight) != fence:
        raise ValueError("formal input bytes or inventory changed after pre-birth validation")


def prepare_release(path: Path, output: Path) -> str:
    """Close expensive immutable checks before either worker/router is born."""
    from .rapid_operation_facts import OperationFacts
    context = OperationFacts()
    value, facts = _audit(path, _context=context)
    if any(fact[5].study_version != 6 for fact in facts):
        raise ValueError("pre-birth release factoring is only the prospective rolling contract")
    intent = _reopen_intent(path, output, value, facts=facts, _context=context)
    _operator_start(path, output, value)
    if any((output / name).exists() for name in ("actual-launch.json", "batch-launch.json", "release-prepared.json")):
        raise FileExistsError("pre-birth release preparation must precede actual worker launch")
    inputs = [worker_inputs(path, index, _audited=(value, facts), _context=context) for index in range(2)]
    environments = [item["environment"] for item in inputs]
    preflight = shared.reopen_preflight(output, intent["authority_sha256"])
    fence = _release_fence(path, value, facts, preflight)
    context.check()
    return shared.put(output / "release-prepared.json", {"schema_version": 1,
        "artifact_type": "qcsd-formal-pre-birth-release-v1", "prepared_at": shared.now(),
        "authority_sha256": shared.sha(shared.read(path)), "authority": value,
        "batch_intent_sha256": shared.sha(shared.read(output / "batch-intent.json")),
        "facts": [[spec.serializable(), str(root), str(intent_path), intent, lineage, asdict(lane),
                   [asdict(site) for site in sites]] for spec, root, intent_path, intent, lineage, lane, sites in facts],
        "environments": environments, "worker_inputs": inputs, "input_fence": fence,
        "formal_accepted_trace_count": 0, "scientific_credit": False})


def prepared_worker_inputs(path: Path, output: Path, index: int, prepared_sha256: str) -> dict[str, Any]:
    """Carry already checked transport through the same host operation."""
    _index(index)
    raw = shared.read(output / "release-prepared.json")
    if shared.sha(raw) != prepared_sha256:
        raise ValueError("formal prepared release differs from its pre-birth digest")
    frame = shared.load(output / "release-prepared.json")
    if (frame["authority_sha256"] != shared.sha(shared.read(path))
        or frame["authority"] != shared.load(path)
        or frame["batch_intent_sha256"] != shared.sha(shared.read(output / "batch-intent.json"))
        or len(frame["worker_inputs"]) != 2
        or frame["worker_inputs"][index]["environment"] != frame["environments"][index]):
        raise ValueError("formal prepared worker transport changed")
    return frame["worker_inputs"][index]


def release(path: Path, output: Path, actual: dict[str, Any], *, prepared_sha256=None) -> None:
    from .rapid_operation_facts import OperationFacts
    context = OperationFacts()
    prepared_path = output / "release-prepared.json"
    environments = None
    if prepared_path.exists():
        if shared.sha(shared.read(prepared_path)) != prepared_sha256:
            raise ValueError("formal prepared release differs from its pre-birth digest")
        frame = shared.load(prepared_path)
        if (set(frame) != {"schema_version", "artifact_type", "prepared_at", "authority_sha256", "authority",
                "batch_intent_sha256", "facts", "environments", "worker_inputs", "input_fence", "formal_accepted_trace_count", "scientific_credit"}
            or type(frame["schema_version"]) is not int or frame["schema_version"] != 1
            or frame["artifact_type"] != "qcsd-formal-pre-birth-release-v1"
            or frame["formal_accepted_trace_count"] != 0 or type(frame["formal_accepted_trace_count"]) is not int
            or frame["scientific_credit"] is not False or frame["authority_sha256"] != shared.sha(shared.read(path))
            or frame["authority"] != shared.load(path)
            or frame["batch_intent_sha256"] != shared.sha(shared.read(output / "batch-intent.json"))
            or len(frame["facts"]) != 2 or len(frame["environments"]) != 2
            or len(frame["worker_inputs"]) != 2
            or any(row["environment"] != frame["environments"][index]
                   for index, row in enumerate(frame["worker_inputs"]))):
            raise ValueError("formal release changed its pre-birth checked facts")
        value = frame["authority"]
        from . import rapid_ordinary_parallel_schedule as ordinary_parallel
        facts = [(ordinary.CaptureSpec(**{key: Path(item) if key in ordinary.PATH_KEYS else item
                   for key, item in row[0].items()}), Path(row[1]), Path(row[2]), row[3], row[4],
                   (ordinary_parallel.prepared_lane(row[5]) if ordinary_parallel.is_payload(row[4]["image_check"]["proof"]["plan_payload"])
                    else ordinary.plan.Lane(**{**row[5], "workload_ids": tuple(row[5]["workload_ids"])})),
                   ordinary_parallel.prepared_sites(row[4]["image_check"]["proof"]["plan_payload"], row[6])) for row in frame["facts"]]
        environments = frame["environments"]
        intent = shared.load(output / "batch-intent.json")
        if not ordinary.admission._utc(intent["created_at"]) <= ordinary.admission._utc(frame["prepared_at"]) <= ordinary.admission._utc(shared.now()):
            raise ValueError("formal release preparation has invalid chronology")
        for index, fact in enumerate(facts):
            spec, root, intent_path, lane_intent, lineage, lane, sites = fact
            if (spec != ordinary.load_capture_spec(_reference(value["lane_specs"][index]))
                or root != Path(value["evidence_root"])
                or intent_path != _reference(value["lane_intents"][index])
                or lane_intent != ordinary._payload(intent_path, ordinary.INTENT_TYPE)
                or lineage != ordinary._payload(ordinary.admission._child(root, lane_intent["lineage"]), ordinary.LINEAGE_TYPE)
                or lane != ordinary._lane(lineage["image_check"]["proof"], lane_intent["campaign_name"])
                or sites != ordinary_parallel.prepared_sites(lineage["image_check"]["proof"]["plan_payload"], lineage["image_check"]["proof"]["sites"])):
                raise ValueError("formal prepared facts differ from their exact sealed official intents")
        preflight = shared.reopen_preflight(output, frame["authority_sha256"])
        _check_release_fence(frame["input_fence"], path, value, facts, preflight)
        for worker in actual["workers"]:
            observed = next(item for item in actual["inspected_containers"] if item["Id"] == worker["id"])
            if (ordinary.admission._utc(observed["Created"]) < ordinary.admission._utc(frame["prepared_at"])
                or observed["Config"].get("Labels", {}).get("org.qcsd.release-preparation-sha256") != prepared_sha256):
                raise ValueError("formal worker was born before immutable release preparation")
    else:
        if prepared_sha256 is not None:
            raise ValueError("formal release digest lacks its actual pre-birth preparation")
        # Historical v5 and callers without the new pre-birth transport retain
        # their complete fresh validation; they acquire no cached authority.
        value, facts = _audit(path, _context=context)
        intent = _reopen_intent(path, output, value, facts=facts, _context=context)
    partitions = _partitions(value, intent, actual)
    start, command = _operator_start(path, output, value)
    argv_hashes = [_worker_inputs_actual(value, output, index, actual, fact=facts[index],
        _environment=environments[index] if environments is not None else None, _context=context) for index in range(2)]
    context.check()
    shared.put(output / "batch-launch.json", {"schema_version": 1, "started_at": shared.now(),
        "authority_sha256": intent["authority_sha256"], "actual": actual,
        "host_start_sha256": shared.sha(shared.read(output / "host-start.json")),
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    launch_sha = shared.sha(shared.read(output / "batch-launch.json"))
    for index, partition in enumerate(partitions):
        gate = output / f"lane-{index+1}" / "gate"
        digest = shared.put(gate / "host-partition.json", partition)
        spec, root, intent_path, _, _, lane, _ = facts[index]
        ordinary._create(root, intent_path.parent / "host-start.json", START_TYPE, {
            "command": command, "execution_root": str(spec.execution_root),
            "started_at": shared.load(output / "batch-launch.json")["started_at"],
            "intent_sha256": shared.sha(shared.read(intent_path)),
            "authority": {"path": str(path.absolute()), "sha256": intent["authority_sha256"]},
            "batch_root": str(output.absolute()), "worker_index": index, "batch_launch_sha256": launch_sha,
            "worker_argv_sha256": argv_hashes[index], "host_partition_sha256": digest})
    # Every birth is durable before either worker can enter the capture command.
    for index in range(2):
        shared.put(output / f"lane-{index+1}" / "gate/release.json", {
            "authority_sha256": intent["authority_sha256"],
            "host_partition_sha256": shared.sha(shared.read(output / f"lane-{index+1}" / "gate/host-partition.json")),
            "worker_id": actual["workers"][index]["id"],
            "campaign": "/lab/" + str(Path(value["campaigns"][index]["path"]).relative_to(value["runtime"]["execution_root"]))})


def reopen_launch(path: Path, output: Path, value: dict[str, Any], *, facts=None) -> None:
    intent = _reopen_intent(path, output, value, facts=facts)
    launch = shared.load(output / "batch-launch.json")
    actual = shared.load(output / "actual-launch.json")
    start, _ = _operator_start(path, output, value)
    if (launch["actual"] != actual or launch["authority_sha256"] != intent["authority_sha256"]
        or launch["host_start_sha256"] != shared.sha(shared.read(output / "host-start.json"))
        or ordinary.admission._utc(launch["started_at"]) < ordinary.admission._utc(start["started_at"])):
        raise ValueError("formal batch launch changed or predates actual host birth")
    for index, expected in enumerate(_partitions(value, intent, actual)):
        gate = output / f"lane-{index+1}" / "gate"
        partition = shared.load(gate / "host-partition.json")
        expected["captured_at_unix_ns"] = partition["captured_at_unix_ns"]
        release_value = shared.load(gate / "release.json")
        if (partition != expected or release_value != {
            "authority_sha256": intent["authority_sha256"], "host_partition_sha256": shared.sha(shared.read(gate / "host-partition.json")),
            "worker_id": actual["workers"][index]["id"],
            "campaign": "/lab/" + str(Path(value["campaigns"][index]["path"]).relative_to(value["runtime"]["execution_root"]))}):
            raise ValueError("formal actual worker gate or peer partition changed")
        _worker_inputs_actual(value, output, index, actual, fact=facts[index] if facts is not None else None)


def verified_worker_start(raw: bytes, intent_raw: bytes, campaign_name: str) -> dict[str, Any]:
    value = ordinary.admission._unpack(raw, START_TYPE)
    if set(value) != {"command", "execution_root", "started_at", "intent_sha256", "authority",
                      "batch_root", "worker_index", "batch_launch_sha256", "worker_argv_sha256", "host_partition_sha256"}:
        raise ValueError("formal worker birth fields differ")
    path = _reference(value["authority"])
    inputs, facts = _audit(path)
    index = value["worker_index"]
    _index(index)
    spec, root, intent_path, intent, _, lane, _ = facts[index]
    if (intent["actuator"] != ACTUATOR or lane.campaign_name != campaign_name
        or shared.read(intent_path) != intent_raw or value["intent_sha256"] != shared.sha(intent_raw)
        or value["execution_root"] != str(spec.execution_root)):
        raise ValueError("formal worker birth belongs to another official lane")
    output = shared.regular_dir(Path(value["batch_root"]))
    if not output.is_relative_to(spec.execution_root / "results"):
        raise ValueError("formal batch evidence escapes its execution root")
    reopen_launch(path, output, inputs, facts=facts)
    _, command = _operator_start(path, output, inputs)
    launch = shared.load(output / "batch-launch.json")
    if (value["command"] != command or value["started_at"] != launch["started_at"]
        or value["batch_launch_sha256"] != shared.sha(shared.read(output / "batch-launch.json"))
        or value["worker_argv_sha256"] != shared.sha(shared.read(output / f"lane-{index+1}" / "worker-argv.json"))
        or value["host_partition_sha256"] != shared.sha(shared.read(output / f"lane-{index+1}" / "gate/host-partition.json"))
        or ordinary.admission._utc(value["started_at"]) < ordinary.admission._utc(intent["started_at"])):
        raise ValueError("formal worker birth changed after its actual release")
    return {**value, "actuator": ACTUATOR, "campaign_name": campaign_name,
            "_evidence_root": str(root), "_authority_value": inputs}


def _retirement(start, root, reference):
    output = Path(start["batch_root"])
    index = start["worker_index"]
    raw = ordinary._object(root, reference)
    if raw != shared.read(output / f"lane-{index+1}" / "retirement.json"):
        raise ValueError("formal worker retirement reference changed")
    receipt = ordinary._load(raw)
    launch = shared._verify_retirement_actual(output, index, receipt["actual"])
    if (receipt["authority_sha256"] != launch["authority_sha256"]
        or ordinary.admission._utc(receipt["retired_at"]) < ordinary.admission._utc(start["started_at"])):
        raise ValueError("formal worker retirement differs from its actual launch")
    return receipt


def verified_worker_process(raw: bytes, root: Path, intent_raw: bytes, campaign_name: str) -> dict[str, Any]:
    value = ordinary.admission._unpack(raw, PROCESS_TYPE)
    if set(value) != {"command", "execution_root", "started_at", "completed_at", "returncode",
                      "interruption", "start", "stdout", "stderr", "retirement"}:
        raise ValueError("formal worker terminal fields differ")
    start = verified_worker_start(ordinary._object(root, value["start"]), intent_raw, campaign_name)
    if root != Path(start["_evidence_root"]):
        raise ValueError("formal worker terminal uses another evidence root")
    retired = _retirement(start, root, value["retirement"])
    if (type(value["returncode"]) is not int or value["interruption"] is not None
        or value["returncode"] != retired["actual"]["worker_exit_code"]
        or value["completed_at"] != retired["retired_at"]
        or any(value[key] != start[key] for key in ("command", "execution_root", "started_at"))):
        raise ValueError("formal worker terminal differs from its actual Docker exit and retirement")
    lane_root = Path(start["batch_root"]) / f"lane-{start['worker_index']+1}"
    for key in ("stdout", "stderr"):
        if ordinary._object(root, value[key]) != shared.read(lane_root / f"worker.{key}"):
            raise ValueError("formal worker raw Docker logs changed")
    return {**value, "actuator": ACTUATOR, "campaign_name": campaign_name,
            "authority": start["authority"], "batch_root": start["batch_root"], "worker_index": start["worker_index"],
            "_authority_value": start["_authority_value"]}


def verified_worker_retirement(raw: bytes, root: Path, intent_raw: bytes, campaign_name: str) -> dict[str, Any]:
    value = ordinary.admission._unpack(raw, RETIREMENT_TYPE)
    if set(value) != {"command", "execution_root", "started_at", "observed_at", "scientific_credit", "host_start", "retirement"}:
        raise ValueError("formal worker retirement fields differ")
    start = verified_worker_start(ordinary._object(root, value["host_start"]), intent_raw, campaign_name)
    if root != Path(start["_evidence_root"]):
        raise ValueError("formal worker retirement uses another evidence root")
    retired = _retirement(start, root, value["retirement"])
    if (value["scientific_credit"] is not False or value["observed_at"] != retired["retired_at"]
        or any(value[key] != start[key] for key in ("command", "execution_root", "started_at"))):
        raise ValueError("formal worker retirement differs from actual start and absence")
    return {**value, "actuator": ACTUATOR, "campaign_name": campaign_name}


def verify_worker_result(process: dict[str, Any], result: Path) -> None:
    if process["returncode"] != 0:
        raise ValueError("a failed formal worker cannot produce a completion receipt")
    partition = shared.load(Path(process["batch_root"]) / f"lane-{process['worker_index']+1}" / "gate/host-partition.json")
    shared.verify_peer_sample_bindings(shared.load(result / "experiment.json"), partition)


def require_batch_closure(process: dict[str, Any]) -> None:
    path = _reference(process["authority"])
    value = process.get("_authority_value") or authority(path)
    shared.verify_operator_closure(path, Path(process["batch_root"]), value)


def retire_lane(output: Path, index: int, actual: dict[str, Any]) -> None:
    launch = shared._verify_retirement_actual(output, index, actual)
    batch = shared.load(output / "batch-intent.json")
    path = Path(batch["authority_path"])
    value, facts = _audit(path)
    spec, root, intent_path, intent, _, lane, _ = facts[index]
    retired_path = output / f"lane-{index+1}" / "retirement.json"
    shared.put(retired_path, {"schema_version": 1, "retired_at": shared.now(), "actual": actual,
        "authority_sha256": launch["authority_sha256"], "formal_accepted_trace_count": 0, "scientific_credit": False})
    start_raw = shared.read(intent_path.parent / "host-start.json")
    start = verified_worker_start(start_raw, shared.read(intent_path), lane.campaign_name)
    retirement = ordinary._put_object(root, shared.read(retired_path))
    common = {key: start[key] for key in ("command", "execution_root", "started_at")}
    observed = shared.load(retired_path)["retired_at"]
    ordinary._create(root, intent_path.parent / "retirement.json", RETIREMENT_TYPE, {
        **common, "observed_at": observed, "scientific_credit": False,
        "host_start": ordinary._put_object(root, start_raw), "retirement": retirement})
    ordinary._create(root, intent_path.parent / "host-process.json", PROCESS_TYPE, {
        **common, "completed_at": observed, "returncode": actual["worker_exit_code"], "interruption": None,
        "start": ordinary._put_object(root, start_raw), "retirement": retirement,
        "stdout": ordinary._put_object(root, shared.read(output / f"lane-{index+1}" / "worker.stdout")),
        "stderr": ordinary._put_object(root, shared.read(output / f"lane-{index+1}" / "worker.stderr"))})
    if lane.study_version == 6:
        # The installed deep operation starts only after the batch host and both
        # real workers have retired. A peer may still be collecting here.
        return
    # Deep failure is retained per lane and never aborts the unaffected worker.
    try:
        if "epoch_declaration" in intent:
            from . import rapid_class_epochs as classes
            classes.complete_lane(spec, root, intent_path)
        else:
            ordinary.complete_lane(spec, root, intent_path)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        failure_path = (output / f"lane-{index+1}" if "epoch_declaration" in intent else intent_path.parent) / "completion-failure.json"
        shared.put(failure_path, {"schema_version": 1,
            "observed_at": shared.now(), "exception_type": type(error).__name__, "message": str(error),
            "formal_accepted_trace_count": 0, "scientific_credit": False})


def verify_results(path: Path, output: Path) -> dict[str, Any]:
    value, facts = _audit(path)
    shared.verify_operator_closure(path, output, value)
    reopen_launch(path, output, value, facts=facts)
    rows = []
    for index in range(2):
        spec, root, intent_path, intent, _, lane, _ = facts[index]
        process = ordinary._verified_host_process(shared.read(intent_path.parent / "host-process.json"),
                    root, shared.read(intent_path), lane.campaign_name)
        row = {"campaign": lane.campaign_name, "valid": False, "accepted": 0, "actual_exit_code": process["returncode"]}
        try:
            if lane.study_version == 6:
                from . import rapid_rolling_capture as rolling
                if type(process["returncode"]) is not int or process["returncode"] != 0:
                    raise ValueError("rolling worker did not complete successfully; terminal evidence retained")
                checked_path = output / f"lane-{index+1}" / "installed-deep.json"
                if checked_path.exists():
                    reference = shared.load(checked_path)
                else:
                    receipt = intent_path.parent / "complete.json"
                    checked = rolling.check_lane_in_image(spec, root,
                        receipt if receipt.exists() else intent_path, complete=not receipt.exists())
                    reference = checked["closure"]
                    shared.put(checked_path, reference)
                checked_spec, receipt, reopened, checked_lane, checked_sites = rolling._reopen_lane_check(reference)
                if (checked_spec != spec or receipt != intent_path.parent / "complete.json"
                    or checked_lane != lane or checked_sites != facts[index][6]):
                    raise ValueError("installed rolling deep closure belongs to another formal worker")
                row["installed_deep"] = reference
            elif "epoch_declaration" in intent:
                from . import rapid_class_epochs as classes
                reopened = classes.verify_lane(spec, root, intent_path.parent / "complete.json")
            else:
                reopened = ordinary.verify_launch_receipt(intent_path.parent / "complete.json", spec=spec, evidence_root=root)
            row.update(valid=True, accepted=reopened["accepted"], launch_receipt=str(intent_path.parent / "complete.json"),
                       launch_receipt_sha256=shared.sha(shared.read(intent_path.parent / "complete.json")),
                       scientific_credit=reopened["scientific_credit"])
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            row["error"] = f"{type(error).__name__}: {error}"
        rows.append(row)
    return {"schema_version": 1, "lanes": rows, "valid": all(row["valid"] for row in rows),
            "host_returncode": shared.load(output / "host-process.json")["returncode"],
            "formal_accepted_trace_count": sum(row["accepted"] for row in rows
                if row.get("scientific_credit") in {"formal-only-if-bound-to-final-50-plan",
                    "formal-only-if-bound-to-rolling-enrollment"}),
            "scientific_credit": "per-lane; registered blocks require their matched commit"}
