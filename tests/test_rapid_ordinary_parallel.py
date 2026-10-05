"""Ordinary two-worker controls with real chunk/plan/fence functions.

Original admission/raw GET, installed canonical operations, canary packet
verification and physical actuation are explicit synthetic boundaries. These
checks grant no measured equivalence, installed authority or formal credit.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_ordinary_parallel_schedule as parallel
from qcsd_lab import rapid_ordinary_group_canary as group
from qcsd_lab import rapid_ordinary_transport_control as transport
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_slot_chunks as chunks
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_parallel_capture as shared
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_per_class_selected_enrollment as per_class
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import verification
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_undefended_capture import fixtures, encoded, ROOT


@pytest.fixture
def current(tmp_path, monkeypatch, request):
    enrollment, runtime, batch, classes, policy = fixtures(tmp_path, monkeypatch)
    source = Path(runtime["runtime_source_root"])
    runtime["module_root"] = str(source)
    execution = Path(runtime["execution_root"])
    # Source equality is real for every new control; canonical installation and
    # original raw proof semantics are the labeled boundaries below.
    for relative in parallel.CONTROL_FILES:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    (execution / "qcsd-lab").write_bytes((source / "qcsd-lab").read_bytes())
    raw_root = tmp_path / "immutable-original-raw"
    raw_root.mkdir()
    (raw_root / "raw.bin").write_bytes(b"controlled original network boundary")
    canary_file = tmp_path / "retained-current-canary.json"
    canary_file.write_bytes(encoded({"engineering_fixture": "original current packet proof"}))
    canary = {"schema_version": 5, "artifact_type": group.TYPE,
              "fixture_reference": rolling._ref(canary_file)}
    source_label = json.loads(Path(runtime["source_manifest"]).read_bytes())
    facts = {"mode": "undefended", "recorded_image_deep_reopened": True,
        "workload_sha256": classes[0]["prepared_workload"]["sha256"],
        "source": {**source_label, "image_digest": runtime["collection_image_digest"]},
        "authority_source": {**source_label, "image_digest": runtime["collection_image_digest"]},
        "client_sha256": lanes._sha(Path(runtime["client_binary"]).read_bytes()),
        "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()}}
    body_policy = getattr(request, "param", None)
    if body_policy is not None:
        facts["application_body_identity_policy"] = body_policy
    monkeypatch.setattr(readiness, "validate_canary", lambda reference, **kwargs: facts)
    monkeypatch.setattr(rolling, "require_mode_readiness", lambda *args, **kwargs: canary)
    monkeypatch.setattr(OperationFacts, "bind_canary",
        lambda self, reference, actual_runtime: self.watch_file(canary_file))
    def bind(self, spec):
        for name in ("cohort", "qualification_spec", "plan_receipt", "source_manifest",
                     "client_binary", "base_launcher", "host_launcher"):
            self.watch_file(getattr(spec, name))
    monkeypatch.setattr(OperationFacts, "bind_capture", bind)
    monkeypatch.setattr(per_class, "enrollment_kind", lambda path: False)
    monkeypatch.setattr(additive, "enrollment_kind", lambda path: True)
    monkeypatch.setattr(additive, "membership_inputs",
        lambda path: {enrollment, Path(batch["policy"]["path"])})
    monkeypatch.setattr(selected, "preparation_inputs",
        lambda preparation, resources: ({canary_file}, {raw_root}))
    inputs = ordinary.publish_inputs(enrollment, runtime, tmp_path / "ordinary-input.json")
    output = rolling.publish_plan(Path(batch["policy"]["path"]).parent, enrollment, inputs,
        tmp_path / "study" / "serial-plan.json", readiness={"undefended": canary}, runtime_inputs=runtime,
        application_body_identity_policy=body_policy)
    spec = rolling.capture_spec(Path(batch["policy"]["path"]).parent, enrollment, inputs, output)
    sites, payload = rolling.verify_capture_plan(spec, require_current=True)
    canonical_dir = tmp_path / "closed-canonical"
    canonical_dir.mkdir()
    canonical = {"source": source_label, "collection_image_digest": runtime["collection_image_digest"],
        "verified_at": "2026-10-05T00:00:00Z", "actual_operation_completions": {}}
    inventory = {relative: {"sha256": lanes._sha((source / relative).read_bytes()),
                           "executable": bool((source / relative).stat().st_mode & 0o111)}
                 for relative in parallel.CONTROL_FILES}
    inventory_path = canonical_dir / "source-inventory.json"
    inventory_path.write_bytes(encoded(inventory))
    canonical["source_inventory_sha256"] = lanes._sha(inventory_path.read_bytes())
    # Release fence validates its genuine closed Source inventory against both
    # synthetic runtime copies, without treating this as an actual install.
    image_source = canonical_dir / "image-context/source"
    for relative in parallel.CONTROL_FILES:
        target = image_source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / relative).read_bytes())
        target.chmod((source / relative).stat().st_mode & 0o777)
    canonical_path = canonical_dir / "canonical.json"
    canonical_path.write_bytes(encoded(canonical))
    reference = rolling._ref(canonical_path)
    monkeypatch.setattr(schedule, "reopen_runtime", lambda ref, actual_runtime, **kwargs:
        (canonical, {relative: (source / relative).read_bytes() for relative in parallel.CONTROL_FILES}))
    return SimpleNamespace(spec=spec, sites=sites, payload=payload, runtime=runtime,
        canonical=canonical, canonical_ref=reference, canonical_dir=canonical_dir,
        root=tmp_path / "study", classes=classes, policy=policy, facts=facts,
        canary=canary, canary_file=canary_file, raw_root=raw_root, inventory=inventory)


def capsule(current, base=None, suffix="one"):
    base = current.spec if base is None else base
    ref = parallel.publish_schedule(base, current.runtime, base.qualification_spec,
        current.canonical_ref, current.canonical_ref, current.root / (suffix + "-capsule.json"),
        reason="prospective HOST two-worker authority")
    path = parallel.publish_plan(base, ref, current.root / (suffix + "-plan.json"))
    spec = replace(base, plan_receipt=path)
    sites, payload = rolling.verify_capture_plan(spec, require_current=True)
    return spec, sites, payload, ref


def chunk_base(current, monkeypatch, count):
    prior = current.root / ("prior-" + str(count) + ".json")
    prior.write_bytes(encoded({"controlled_progress_boundary": True}))
    # Explicit original progress proof boundary: class1 TAM actual metadata is
    # independently retained elsewhere; no fixture status receives credit.
    monkeypatch.setattr(chunks, "prior_progress", lambda reference, classes:
        ({"closed_at": "2026-10-05T00:00:00Z"}, set(), {rolling._open_ref(reference)}))
    policy = chunks.publish_policy(current.spec, rolling._ref(prior),
        current.root / ("chunk-" + str(count) + "-policy.json"),
        modes=["undefended"], maximum_visits=count)
    path = chunks.publish_plan(current.spec, rolling._ref(policy),
        current.root / ("chunk-" + str(count) + "-plan.json"))
    return replace(current.spec, plan_receipt=path)


@pytest.mark.parametrize("count", [1, 4, 16])
def test_real_chunk_capsule_preserves_graph_limits_and_disjoint_slots(current, monkeypatch, count):
    base = chunk_base(current, monkeypatch, count)
    spec, sites, payload, ref = capsule(current, base, str(count))
    assert payload["sites"] == current.payload["sites"]
    assert payload["capture_limits"] == current.policy["capture_limits"]
    assert payload["formal_accepted_trace_count"] == 0 and payload["scientific_credit"] is False
    assert all(row["qualification_set"] is None for row in payload["lanes"])
    chosen = [lanes._lane({"plan_payload": payload}, row["campaign_name"]) for row in payload["lanes"][:2]]
    assert [parallel.prepared_lane(asdict(lane)) for lane in chosen] == chosen
    assert all(isinstance(lane, chunks.ChunkLane) and lane.visits_per_workload == count for lane in chosen)
    parallel.require_disjoint([(spec, payload, lane, sites) for lane in chosen])
    assert len(parallel.require_worker(payload, chosen[0], sites, spec)) == 5 * count
    assert parallel.prepared_sites(payload, payload["sites"]) == sites
    document = yaml.safe_load(lanes._render_lane_campaign(spec, chosen[0], sites))
    assert document["limits"] == current.policy["capture_limits"]
    assert document["workloads"] == {site.workload_id: count for site in sites}
    assert parallel.validate_schedule(ref)["canary"] == current.canary


def test_overlap_mixed_and_unregistered_worker_refused(current):
    spec, sites, payload, _ = capsule(current)
    own = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    peer = lanes._lane({"plan_payload": payload}, payload["lanes"][1]["campaign_name"])
    with pytest.raises(ValueError, match="repeat"):
        parallel.require_disjoint([(spec, payload, own, sites), (spec, payload, own, sites)])
    with pytest.raises(ValueError, match="mix"):
        parallel.require_disjoint([(spec, payload, own, sites), (current.spec, current.payload, peer, sites)])
    with pytest.raises(ValueError, match="registered"):
        parallel.require_worker(payload, replace(own, mode="tamaraw"), sites, spec)


@pytest.mark.parametrize("field", ["capture_limits", "body_policy", "traffic_hashes", "control_sources"])
def test_rehashed_capsule_cannot_change_caps_body_traffic_or_source(current, field):
    _, _, _, ref = capsule(current)
    value = json.loads(Path(ref["path"]).read_bytes())
    value[field] = "substitution"
    changed = current.root / (field + "-changed.json")
    changed.write_bytes(encoded(value))
    with pytest.raises(ValueError, match="changed full"):
        parallel.validate_schedule(rolling._ref(changed))


def test_changed_canonical_and_historical_retry_refused(current):
    with pytest.raises(ValueError, match="one current"):
        parallel.publish_schedule(current.spec, current.runtime, current.spec.qualification_spec,
            {**current.canonical_ref, "sha256": "0" * 64}, current.canonical_ref,
            current.root / "bad.json", reason="fixture")
    current.canary["schema_version"] = 4
    with pytest.raises(ValueError, match="successful current"):
        capsule(current)
    current.canary["schema_version"] = 5
    current.canonical["collection_image_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError, match="image/client"):
        capsule(current, suffix="image")


def test_bound_dependencies_memo_uses_full_capsule_key(current, monkeypatch):
    calls = []
    original = parallel.input_dependencies
    monkeypatch.setattr(parallel, "input_dependencies",
        lambda *args, **kwargs: (calls.append(1), original(*args, **kwargs))[1])
    value = {"base_spec": current.spec.serializable(), "current_canonical": current.canonical_ref}
    with OperationFacts().scope() as context:
        parallel.bind_dependencies(value, context)
        parallel.bind_dependencies(value, context)
        assert len(calls) == 1
        current.raw_root.joinpath("late.bin").write_bytes(b"new raw membership")
        with pytest.raises(ValueError, match="tree"):
            context.check()


def test_real_release_fence_has_no_padding_and_rejects_raw_mode_membership(current, monkeypatch):
    spec, sites, payload, ref = capsule(current)
    lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    intent = current.root / "retired-boundary/intent.json"
    intent.parent.mkdir()
    for name in ("intent.json", "lineage.json", "dns.json"):
        intent.with_name(name).write_bytes(encoded({}))
    # Original canary packet boundary is controlled, but its exact public
    # namespace, inventory and sealed raw-file membership are real.
    canary_dir = current.root / "canary-boundary"
    canary_dir.mkdir()
    canary_source = canary_dir / "source"
    canary_source.mkdir()
    (canary_source / "control.py").write_bytes(b"controlled original deep Source")
    canary_execution = canary_dir / "execution"
    canary_execution.mkdir()
    (canary_execution / "control.py").write_bytes((canary_source / "control.py").read_bytes())
    inventory = readiness._inventory(canary_source)
    inventory_path = canary_dir / "source-inventory.json"
    inventory_path.write_bytes(encoded(inventory))
    plan_path = canary_dir / "plan.json"
    plan_path.write_bytes(encoded({"canonical_runtime": {"source_inventory_sha256": shared.sha(inventory_path.read_bytes())},
        "clean_runtime_root": str(canary_source), "execution_root": str(canary_execution)}))
    result = canary_execution / "results/attempt"
    for name in verification.AUTHORITATIVE_DIRECTORIES:
        (result / name).mkdir(parents=True)
    (result / "experiment.json").write_bytes(encoded({"engineering_fixture": "sealed packet boundary"}))
    files = verification.authoritative_files(result)
    (result / "evidence.sha256").write_text("".join(
        f"{shared.sha(path.read_bytes())}  {name}\n" for name, path in files.items()))
    deep = canary_dir / "deep.json"
    deep.write_bytes(encoded({"root": "/lab/results/attempt",
        "evidence_index_sha256": shared.sha((result / "evidence.sha256").read_bytes())}))
    canary_ref = {"plan": rolling._ref(plan_path), "deep_receipt": rolling._ref(deep)}
    fence_payload = {**payload, "readiness": {"undefended": canary_ref}}
    # Capsule's already tested semantic authority is kept exact while the
    # release function consumes this synthetic retained-canary raw boundary.
    monkeypatch.setattr(parallel, "require_plan", lambda value: parallel.validate_schedule(ref))
    monkeypatch.setattr(lanes, "_payload", lambda path, kind: fence_payload)
    lineage = {"image_check": {"proof": {"plan_payload": fence_payload}}}
    facts = [(spec, current.root, intent, {}, lineage, lane, sites)]
    authority = {"evidence_root": str(current.root)}
    fence = formal._release_fence(intent, authority, facts, {"input_files": []})
    assert current.raw_root.as_posix() in fence["trees"]
    assert "qualification_sets" not in json.loads(spec.qualification_spec.read_bytes())
    raw = current.raw_root / "raw.bin"
    original_mode = raw.stat().st_mode & 0o777
    raw.chmod(0o600 if original_mode != 0o600 else 0o644)
    with pytest.raises(ValueError, match="changed"):
        formal._check_release_fence(fence, intent, authority, facts, {"input_files": []})
    raw.chmod(original_mode)
    current.raw_root.joinpath("late.bin").write_bytes(b"late membership")
    with pytest.raises(ValueError, match="changed"):
        formal._check_release_fence(fence, intent, authority, facts, {"input_files": []})


def test_terminal_failed_peer_retains_successful_worker(current, monkeypatch):
    spec, sites, payload, _ = capsule(current)
    workers = [lanes._lane({"plan_payload": payload}, row["campaign_name"]) for row in payload["lanes"][:2]]
    output = current.root / "terminal-worker-fixture"
    output.mkdir()
    authority = output / "authority.json"
    authority.write_bytes(encoded({}))
    facts = []
    for index, lane in enumerate(workers):
        intent = output / ("worker-" + str(index)) / "intent.json"
        intent.parent.mkdir()
        intent.write_bytes(encoded({"engineering_fixture": "original actor birth"}))
        intent.with_name("host-process.json").write_bytes(encoded({"returncode": 1 if index == 0 else 0}))
        intent.with_name("complete.json").write_bytes(encoded({"accepted": 20}))
        facts.append((spec, current.root, intent, {}, {}, lane, sites))
    value = {"runtime": {}, "engineering_fixture": "terminal operator"}
    monkeypatch.setattr(formal, "_audit", lambda path: (value, facts))
    monkeypatch.setattr(shared, "verify_operator_closure", lambda *args: None)
    monkeypatch.setattr(formal, "reopen_launch", lambda *args, **kwargs: None)
    monkeypatch.setattr(lanes, "_verified_host_process", lambda raw, *args: json.loads(raw))
    monkeypatch.setattr(rolling, "check_lane_in_image", lambda *args, **kwargs:
        {"closure": {"path": str(output / "independent-deep.json"), "sha256": "a" * 64}})
    monkeypatch.setattr(rolling, "_reopen_lane_check", lambda ref:
        (spec, facts[1][2].with_name("complete.json"),
         {"accepted": 20, "scientific_credit": "formal-only-if-bound-to-rolling-enrollment"}, workers[1], sites))
    (output / "lane-2").mkdir()
    (output / "host-process.json").write_bytes(encoded({"returncode": 1}))
    held = {str(path): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    report = formal.verify_results(authority, output)
    assert report["valid"] is False and report["lanes"][0]["accepted"] == 0
    assert report["lanes"][1]["valid"] is True and report["formal_accepted_trace_count"] == 20
    assert all(Path(path).read_bytes() == raw for path, raw in held.items())



def test_normal_group_canary_reference_refuses_historical_retry_shape():
    original = {name: {} for name in readiness.REFERENCE_KEYS}
    original["schema_version"] = 1
    value = group.reference(original)
    assert value["schema_version"] == 5 and value["artifact_type"] == group.TYPE
    assert "failed_deep" not in value and "declaration" not in value
    with pytest.raises(ValueError, match="exact original"):
        group.reference({**original, "schema_version": 4})


def test_real_group_deep_command_keeps_exact_renewal_and_all_ro_audits(current, monkeypatch):
    from qcsd_lab import static_evidence_transport
    directory = current.root / "command-canary"
    (directory / "lineage").mkdir(parents=True)
    original = directory / "lineage/original-manifest.json"
    original.write_bytes(encoded({"engineering_fixture": "full preparation boundary"}))
    recipe = directory / "recipe.py"
    helper = directory / "helper.py"
    recipe.write_bytes(b"original current verifier control")
    helper.write_bytes(b"original current helper control")
    renewal = directory / "renewal.json"
    renewal.write_bytes(encoded({"control_sources": ordinary._sources()}))
    audits = [current.root / "audit-one", current.root / "audit-two"]
    for path in audits:
        path.mkdir()
    plan_value = {"name": "controlled-normal-group", "ordinary_renewal": rolling._ref(renewal),
        "original_workload_sha256": shared.sha(original.read_bytes()),
        "clean_runtime_root": current.runtime["runtime_source_root"],
        "execution_root": current.runtime["execution_root"],
        "canonical_runtime": current.canonical, "recipe_sha256": shared.sha(recipe.read_bytes()),
        "helper_sha256": shared.sha(helper.read_bytes())}
    monkeypatch.setattr(static_evidence_transport, "manifest_roots", lambda manifest: [audits[0]])
    monkeypatch.setattr(group.retry, "group_roots", lambda plan, root: audits)
    command = ["docker", "run", "--user", "1000:1000", "--volume",
               str(recipe) + ":/recipe.py:ro", "--volume", str(helper) + ":/helpers.py:ro"]
    actual = readiness._deep_command(plan_value, directory, "a" * 64, "undefended",
        "/lab/results/controlled/attempt", command, ordinary_transport="current-group")
    assert actual[actual.index("--network") + 1] == "none"
    assert f"{renewal}:{renewal}:ro" in actual
    assert all(f"{path}:{path}:ro" in actual for path in audits)
    assert actual[actual.index("--entrypoint") + 1] == "/opt/qcsd-venv/bin/python3"
    assert actual[-1] == "/lab/results/controlled/attempt"
    renewal.write_bytes(encoded({"control_sources": {"historical": "b40"}}))
    plan_value["ordinary_renewal"] = rolling._ref(renewal)
    with pytest.raises(ValueError, match="historical"):
        group.transport_mounts(plan_value, directory)


def test_normal_group_validator_authenticates_real_operation_and_current_source(current, monkeypatch):
    directory = current.root / "normal-group"
    (directory / "logs").mkdir(parents=True)
    inventory = readiness._inventory(ROOT)
    inventory_path = directory / "source-inventory.json"
    inventory_path.write_bytes(encoded(inventory))
    plan_path = directory / "plan.json"
    plan_path.write_bytes(encoded({"canonical_runtime": {"source_inventory_sha256": shared.sha(inventory_path.read_bytes())},
        "clean_runtime_root": str(ROOT)}))
    deep_path = directory / "undefended-deep-verification.json"
    deep_path.write_bytes(encoded({"root": "/lab/results/controlled/attempt"}))
    command = ["controlled-original-deep-boundary"]
    stdout = directory / "logs/undefended-deep.stdout.log"
    stderr = directory / "logs/undefended-deep.stderr.log"
    stdout.write_bytes(b"controlled original semantic output")
    stderr.write_bytes(b"")
    start = directory / "logs/undefended-deep-started.json"
    end = directory / "logs/undefended-deep-completed.json"
    start.write_bytes(encoded({"started_at": "2026-10-05T00:01:00Z", "command": command}))
    end.write_bytes(encoded({"completed_at": "2026-10-05T00:01:01Z", "elapsed_seconds": 1,
        "returncode": 0, "invocation_error": None, "stdout_sha256": shared.sha(stdout.read_bytes()),
        "stderr_sha256": shared.sha(stderr.read_bytes())}))
    operation = {"started": rolling._ref(start), "completed": rolling._ref(end),
                 "stdout": rolling._ref(stdout), "stderr": rolling._ref(stderr)}
    reference = group.reference({"schema_version": 1, "plan": rolling._ref(plan_path),
        "deep_receipt": rolling._ref(deep_path), "capture": operation, "deep": operation})
    runtime = {key: current.runtime[key] for key in lanes.RUNTIME_KEYS}
    runtime.update(runtime_source_root=str(ROOT), module_root=str(ROOT))
    # The unchanged original packet acceptance body is the sole semantic seam.
    # Actual file/reference/current-Source/raw-operation validation stays real.
    monkeypatch.setattr(group, "group_roots", lambda plan, root: [current.raw_root])
    monkeypatch.setattr(readiness, "_deep_command", lambda *args, **kwargs: command)
    monkeypatch.setattr(readiness, "_validate_canary", lambda *args, **kwargs: current.facts)
    facts = group.validate(reference, runtime=runtime, mode="undefended")
    assert facts["ordinary_successful_group_canary"] == group.TYPE
    assert facts["source_equivalence_sha256"] is None
    assert "formal_accepted_trace_count" not in facts
    changed = json.loads(end.read_bytes())
    changed["returncode"] = 1
    end.write_bytes(encoded(changed))
    reference["deep"]["completed"] = rolling._ref(end)
    with pytest.raises(ValueError, match="successful actual"):
        group.validate(reference, runtime=runtime, mode="undefended")
    with pytest.raises(ValueError, match="mode"):
        group.validate(reference, runtime=runtime, mode="tamaraw")



@pytest.mark.parametrize("override", [None, "/explicit/user/python"])
def test_launch_lane_defaults_to_calling_interpreter_and_preserves_override(current, monkeypatch, override):
    import contextlib
    import sys
    if override is None:
        monkeypatch.delenv("QCSD_PARALLEL_HOST_PYTHON", raising=False)
    else:
        monkeypatch.setenv("QCSD_PARALLEL_HOST_PYTHON", override)
    payload = current.payload
    campaign = payload["lanes"][0]["campaign_name"]
    proof = {"plan_payload": payload}
    monkeypatch.setattr(lanes, "capture_lock", lambda root: contextlib.nullcontext(17))
    monkeypatch.setattr(lanes, "check_bound_image", lambda *args, **kwargs: {"proof": proof})
    def intent(spec, root, name, *args, **kwargs):
        path = root / "lanes" / name / "intent.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(encoded({}))
        return path
    monkeypatch.setattr(lanes, "prepare_lane_intent", intent)
    monkeypatch.setattr(rolling, "readiness_roots", lambda *args, **kwargs: [current.raw_root])
    observed = []
    def actuation(spec, root, directory, command, env, descriptor):
        observed.append(env)
        rolling._write(directory / "host-process.json", lanes.PROCESS_TYPE, {"returncode": 0})
    monkeypatch.setattr(lanes, "_actuate_host", actuation)
    complete = current.root / "controlled-complete.json"
    complete.write_bytes(encoded({"engineering_fixture": "installed deep boundary"}))
    monkeypatch.setattr(rolling, "check_lane_in_image",
        lambda *args, **kwargs: {"receipt": str(complete)})
    assert lanes.launch_lane(current.spec, current.root, campaign) == complete
    assert observed[0]["QCSD_PARALLEL_HOST_PYTHON"] == (sys.executable if override is None else override)



@pytest.mark.parametrize("count", [1, 16])
def test_real_prepare_batch_claims_two_chunk_workers_after_geometry_checks(current, monkeypatch, count):
    import contextlib
    original_load = lanes._load
    original_enrollment_bytes = current.spec.cohort.read_bytes()
    # Exposes only the already controlled original admission envelope to the
    # unchanged portable spec loader. Every current plan/capsule stays real.
    monkeypatch.setattr(lanes, "_load", lambda raw: {"receipt_type": additive.ENROLLMENT_TYPE}
        if raw == original_enrollment_bytes else original_load(raw))
    base = chunk_base(current, monkeypatch, count)
    spec, sites, payload, _ = capsule(current, base, "prepare-" + str(count))
    names = [row["campaign_name"] for row in payload["lanes"][:2]]
    spec_path = current.root / "prepare-spec.json"
    rolling._write_spec(spec_path, spec)
    proof = {"cohort_generation": "rolling-50", "plan_payload": payload,
             "sites": [asdict(site) for site in sites]}
    monkeypatch.setattr(lanes, "capture_lock", lambda root: contextlib.nullcontext(17))
    monkeypatch.setattr(lanes, "check_bound_image", lambda *args, **kwargs: {"proof": proof})
    # Original installed image proof and original intent lineage semantics are
    # controlled. Real prepare_batch checks the registered chunk geometry,
    # scheduling, disjoint slots and both create-only claims before writing.
    monkeypatch.setattr(lanes, "_validate_image_proof", lambda *args, **kwargs: sites)
    monkeypatch.setattr(lanes, "_lineage_payload", lambda *args, **kwargs: {"controlled_original_lineage": True})
    calls = []
    def create(spec, root, name, checked, **kwargs):
        path = root / "lanes" / name / "intent.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(encoded({"actuator": kwargs["actuator"], "campaign": name}))
        calls.append(name)
        return path
    monkeypatch.setattr(lanes, "prepare_lane_intent", create)
    monkeypatch.setattr(formal, "authority", lambda path, **kwargs: shared.load(path))
    output = current.root / "prepared-pair.json"
    assert formal.prepare_batch(spec_path, current.root, names, output) == output
    value = shared.load(output)
    assert calls == names and len(value["lane_intents"]) == 2
    assert all(Path(ref["path"]).is_file() for ref in value["lane_intents"])
    with pytest.raises(FileExistsError, match="claimed"):
        formal.prepare_batch(spec_path, current.root, names, current.root / "duplicate-pair.json")
    assert calls == names



@pytest.mark.parametrize("current", ["complete-current-application-delivery-v1"], indirect=True)
def test_complete_delivery_policy_and_requests_survive_current_chunk_capsule(current, monkeypatch):
    base = chunk_base(current, monkeypatch, 16)
    spec, sites, payload, _ = capsule(current, base, "complete-delivery")
    assert payload["application_body_identity_policy"] == current.facts["application_body_identity_policy"]
    worker = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    document = yaml.safe_load(lanes._render_lane_campaign(spec, worker, sites))
    assert document["application_body_identity_policy"] == payload["application_body_identity_policy"]
    assert all(json.loads((spec.workload_root / (site.workload_id + ".json")).read_bytes())["resources"]
        == json.loads((Path(row["prepared_workload"]["path"])).read_bytes())["resources"]
        for site, row in zip(sites, current.classes, strict=True))


@pytest.mark.parametrize("role", ["client_binary", "runtime_control"])
def test_changed_binary_or_current_frozen_control_refused(current, role):
    _, _, _, reference = capsule(current)
    path = (Path(current.runtime["client_binary"]) if role == "client_binary" else
            Path(current.runtime["runtime_source_root"]) / "src/qcsd_lab/rapid_lane_evidence.py")
    path.write_bytes(path.read_bytes() + b"changed fixture bytes")
    with pytest.raises(ValueError):
        parallel.validate_schedule(reference)
