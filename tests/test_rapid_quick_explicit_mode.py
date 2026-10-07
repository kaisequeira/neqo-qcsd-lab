"""Explicit mode boundaries; synthetic records grant no scientific credit."""
from dataclasses import asdict, replace
from pathlib import Path
import hashlib
import importlib.util
import stat

import pytest

_fixture_spec = importlib.util.spec_from_file_location(
    "explicit_mode_direct_fixture", Path(__file__).with_name("test_rapid_quick_profile.py"))
assert _fixture_spec is not None and _fixture_spec.loader is not None
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)
direct, write = _fixture.direct, _fixture.write
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab.rapid_operation_facts import OperationFacts


@pytest.fixture
def mixed(direct):
    seed = direct.capsule["seed_payload"]
    seed.pop("ordinary_capture_contract")
    site = rolling.plan.Site("candidate", "site", direct.site.workload_sha256,
        direct.site.primary_origin, "synthetic-qualified-mode", "a" * 64)
    seed["sites"] = [asdict(site)]
    seed["lanes"] = [{"role": "formal", "mode": mode, "shard": 1, "block": block,
        "visits_per_workload": 4, "workload_ids": ["site"]}
        for mode, blocks in (("undefended", range(1, 17)), ("front", (2,))) for block in blocks]
    seed["runtime_artifacts"] = {name: rolling._ref(getattr(direct.spec, name))
        for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher")}
    seed["qualification_spec_sha256"] = rolling._ref(direct.spec.qualification_spec)["sha256"]
    seed["application_body_identity_policy"] = "complete-current-application-delivery-v1"
    folder = direct.path.parent / "ready-front"
    name, result = "synthetic-front-canary", "/lab/results/synthetic-front-canary/result"
    relative = "config/campaigns/synthetic-front-canary.yml"
    campaign = write(direct.spec.execution_root / relative, b"synthetic original campaign; no capture authority")
    verifier = write(folder / "verifier.py", b"synthetic verifier source; no executed proof")
    helper = write(folder / "helpers.py", b"synthetic original helper")
    image = seed["runtime"]["collection_image_digest"]
    canonical = lanes._load(direct.canonical.read_bytes())
    canonical["checks"] = {"collection": {"source": direct.capsule["source"], "image_digest": image,
        "client_sha256": direct.capsule["client_sha256"]}}
    canonical_path = write(folder / "canonical-runtime.json", canonical)
    graph = {**direct.capsule["graphs"]["site"]}
    graph["resource_records_sha256"] = graph.pop("resources_sha256")
    command = ["env", f"QCSD_LAB_COLLECTION_IMAGE={image}",
        f"QCSD_RAPID_IMAGE_SOURCE_QCSD={direct.spec.runtime_source_root / 'qcsd-lab'}",
        f"QCSD_RAPID_DNS_RECEIPT_PATH={folder / 'dns-receipts/front.json'}",
        str(direct.spec.execution_root / "qcsd-lab"), "run", str(campaign)]
    recipe = write(folder / "plan.json", {"campaigns": [{"mode": "front", "run_argv": command,
            "name": name, "visits": 1, "campaign_relative": relative, "campaign_sha256": rolling._ref(campaign)["sha256"]}],
        "canonical_runtime": canonical, "canonical_runtime_sha256": rolling._ref(canonical_path)["sha256"],
        "execution_root": str(direct.spec.execution_root), "clean_runtime_root": str(direct.spec.runtime_source_root),
        "selection_sha256": "e" * 64, "workload_id": "site", "workload_sha256": site.workload_sha256,
        "full_graph": graph, "recipe_sha256": rolling._ref(verifier)["sha256"], "helper_sha256": rolling._ref(helper)["sha256"],
        "expected_lab_commit": direct.capsule["source"]["lab_commit"], "expected_native_commit": quick.NATIVE,
        "traffic_hashes": {key: digest for key, (_, digest) in quick._traffic_files(seed).items()},
        "capture_limits": {**seed["capture_limits"], "max_attempts": 1}})
    deep_command = ["docker", "run", "--rm", "--network", "none", "--env", f"QCSD_LAB_IMAGE_DIGEST={image}",
        "--volume", str(direct.spec.runtime_source_root) + ":/runtime-src:ro",
        "--volume", str(direct.spec.execution_root) + ":/lab:ro", "--volume", str(folder) + ":/diagnostic:rw",
        "--volume", str(verifier) + ":/recipe.py:ro", "--volume", str(helper) + ":/helpers.py:ro",
        "--entrypoint", "/opt/qcsd-venv/bin/python3", image, "-I", "-B", "/recipe.py", "verify-image",
        "--plan", "/diagnostic/plan.json", "--plan-sha256", rolling._ref(recipe)["sha256"],
        "--mode", "front", "--result", result]
    deep = write(folder / "front-deep-verification.json", {"mode": "front", "valid": True, "status": "complete", "accepted_samples": 1,
        "name": name, "purpose": "smoke", "root": result, "selection_sha256": "e" * 64,
        "canonical_runtime_sha256": rolling._ref(canonical_path)["sha256"], "full_graph": graph,
        "formal_accepted_trace_count": 0, "study_pilot_accepted_trace_count": 0, "site_credit": 0,
        "completed_at": "2000-01-01T00:00:02.5Z",
        "scientific_credit": False, "plan_sha256": rolling._ref(recipe)["sha256"], "source": direct.capsule["source"],
        "workload_sha256": site.workload_sha256, "application_body_identity_policy": seed["application_body_identity_policy"]})
    reference = {"schema_version": 1, "plan": rolling._ref(recipe), "deep_receipt": rolling._ref(deep)}
    for action in ("capture", "deep"):
        start, end = ("00", "01") if action == "capture" else ("02", "03")
        stdout = write(folder / "logs" / f"front-{action}.stdout.log", b"synthetic original output")
        stderr = write(folder / "logs" / f"front-{action}.stderr.log", b"")
        started = write(folder / "logs" / f"front-{action}-started.json", {
            "command": command if action == "capture" else deep_command, "started_at": f"2000-01-01T00:00:{start}Z"})
        completed = write(folder / "logs" / f"front-{action}-completed.json", {
            "returncode": 0, "elapsed_seconds": 1, "completed_at": f"2000-01-01T00:00:{end}Z",
            "stdout_sha256": rolling._ref(stdout)["sha256"], "stderr_sha256": rolling._ref(stderr)["sha256"]})
        reference[action] = {name: rolling._ref(path) for name, path in (
            ("started", started), ("completed", completed), ("stdout", stdout), ("stderr", stderr))}
    seed["readiness"] = {"front": reference}
    write(direct.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    selection, rows, extra = quick._mode_selection(seed, "front")
    direct.capsule.update(schema_version=2, artifact_type=quick.MODE_CAPSULE_TYPE, mode_selection=selection,
        sites=[asdict(site)], permitted_slots=quick._permitted_slots({"lanes": rows}))
    direct.capsule["archive_references"]["original_plan"] = rolling._ref(direct.spec.plan_receipt)
    direct.material = sorted(set(direct.material) | extra)
    direct.capsule["material_files"] = [rolling._ref(path) for path in direct.material]
    direct.capsule["material_modes"] = {str(path): stat.S_IMODE(path.stat().st_mode) for path in direct.material}
    write(direct.path, direct.capsule)
    direct.ref = rolling._ref(direct.path)
    direct.site = site
    direct.mode_deep = deep
    return direct


def test_explicit_front_preserves_entire_mixed_seed_and_selected_mode_slots(mixed, monkeypatch):
    monkeypatch.setattr(schedule, "reopen_runtime", lambda *a, **k: pytest.fail("historical runtime reopened"))
    from qcsd_lab import rapid_rolling_readiness as readiness
    monkeypatch.setattr(readiness, "validate_canary", lambda *a, **k: pytest.fail("historical canary recursively reopened"))
    context = OperationFacts()
    capsule = quick.validate_profile(mixed.ref, _context=context)
    context.check()
    assert {row["mode"] for row in capsule["seed_payload"]["lanes"]} == {"undefended", "front"}
    assert capsule["permitted_slots"] == [4, 5, 6, 7]
    path = quick.publish_plan(mixed.spec, mixed.ref, mixed.path.parent / "front-plan.json", slot_start=4, slot_count=1)
    candidate = replace(mixed.spec, plan_receipt=path)
    sites, value = quick.verify_plan(candidate)
    assert sites == (mixed.site,)
    assert value["lanes"][0]["mode"] == "front"
    assert value["planned_trace_count"] == 1 and value["scientific_credit"] is False
    assert set(value["readiness"]) == {"front"}
    assert schedule.validate_schedule(mixed.ref)["artifact_type"] == quick.MODE_CAPSULE_TYPE


@pytest.mark.parametrize("mode", [None, "front"])
def test_profile_publication_keeps_default_v1_and_explicit_v2_separate(mixed, monkeypatch, mode):
    seed = mixed.capsule["seed_payload"]
    write(mixed.spec.cohort, lanes.admission._bind("synthetic-enrolled-fixture", {"selected_candidate_ids": ["candidate"]}))
    seed["bindings"]["cohort_sha256"] = rolling._ref(mixed.spec.cohort)["sha256"]
    write(mixed.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    # Only the unrelated full installation boundary is replaced; the actual
    # publication, mode readiness/material checks, and typed reopening run.
    monkeypatch.setattr(quick, "_runtime_once", lambda *a: (
        lanes._load(mixed.canonical.read_bytes()), rolling._ref(mixed.inventory)))
    reference = quick.publish_profile(mixed.spec, rolling._ref(mixed.canonical),
        mixed.path.parent / "published-profile.json", mode=mode)
    value = quick.validate_profile(reference)
    assert value["seed_payload"] == seed
    if mode is None:
        assert value["schema_version"] == 1 and value["artifact_type"] == quick.CAPSULE_TYPE
        assert "mode_selection" not in value and value["permitted_slots"] == list(range(64))
        with pytest.raises(ValueError, match="independently ready fixed setting"):
            quick.publish_plan(mixed.spec, reference, mixed.path.parent / "plan.json", slot_start=4, slot_count=1)
    else:
        assert value["schema_version"] == 2 and value["artifact_type"] == quick.MODE_CAPSULE_TYPE
        assert value["mode_selection"]["mode"] == "front" and value["permitted_slots"] == [4, 5, 6, 7]


def test_explicit_mode_does_not_borrow_other_mode_slots(mixed):
    with pytest.raises(ValueError, match="remaining ledger"):
        quick.publish_plan(mixed.spec, mixed.ref, mixed.path.parent / "plan.json", slot_start=0, slot_count=1)


def test_selected_mode_with_full_original_range_keeps_slots_zero_through_63(mixed):
    seed = mixed.capsule["seed_payload"]
    seed["lanes"] = [row for row in seed["lanes"] if row["mode"] != "front"] + [
        {"role": "formal", "mode": "front", "shard": 1, "block": block,
         "visits_per_workload": 4, "workload_ids": ["site"]} for block in range(1, 17)]
    write(mixed.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    mixed.capsule["archive_references"]["original_plan"] = rolling._ref(mixed.spec.plan_receipt)
    mixed.capsule["permitted_slots"] = list(range(64))
    mixed.capsule["material_files"] = [rolling._ref(path) for path in mixed.material]
    write(mixed.path, mixed.capsule)
    assert quick.validate_profile(rolling._ref(mixed.path))["permitted_slots"] == list(range(64))


@pytest.mark.parametrize("mode", ["tamaraw", "buflo", "cs-buflo", "unknown"])
def test_mode_without_its_own_formal_lanes_and_readiness_is_rejected(mixed, mode):
    with pytest.raises(ValueError, match="own original formal lanes"):
        quick._mode_selection(mixed.capsule["seed_payload"], mode)


def test_capsule_cannot_substitute_selected_mode_or_readiness(mixed):
    mixed.capsule["mode_selection"]["mode"] = "undefended"
    write(mixed.path, mixed.capsule)
    with pytest.raises(ValueError, match="own original formal lanes"):
        quick.validate_profile(rolling._ref(mixed.path))


def test_actual_mode_receipt_mutation_is_rejected(mixed):
    mixed.mode_deep.write_bytes(mixed.mode_deep.read_bytes() + b"\nchanged")
    with pytest.raises(ValueError, match="immutable reference"):
        quick.validate_profile(mixed.ref)


def test_failed_readiness_cannot_be_selected(mixed):
    seed = mixed.capsule["seed_payload"]
    reference = seed["readiness"]["front"]["capture"]["completed"]
    path = Path(reference["path"])
    value = lanes._load(path.read_bytes())
    value["returncode"] = 1
    write(path, value)
    seed["readiness"]["front"]["capture"]["completed"] = rolling._ref(path)
    with pytest.raises(ValueError, match="closed actual readiness"):
        quick._mode_selection(seed, "front")


@pytest.mark.parametrize("campaigns", [[], [None]])
def test_malformed_original_recipe_campaigns_fail_as_a_typed_refusal(mixed, campaigns):
    seed = mixed.capsule["seed_payload"]
    reference = seed["readiness"]["front"]["plan"]
    path = Path(reference["path"])
    recipe = lanes._load(path.read_bytes())
    recipe["campaigns"] = campaigns
    write(path, recipe)
    seed["readiness"]["front"]["plan"] = rolling._ref(path)
    with pytest.raises(ValueError, match="original recipe mode differs"):
        quick._mode_selection(seed, "front")


def test_original_mode_native_client_cannot_be_replaced(mixed):
    seed = mixed.capsule["seed_payload"]
    client = write(mixed.path.parent / "different-native-client", b"different client")
    seed["runtime"]["client_binary"] = str(client)
    seed["runtime_artifacts"]["client_binary"] = rolling._ref(client)
    write(mixed.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    mixed.capsule["seed_payload"] = {**seed, "runtime": mixed.capsule["runtime"]}
    mixed.capsule["archive_references"]["original_plan"] = rolling._ref(mixed.spec.plan_receipt)
    mixed.material.append(client)
    mixed.capsule["material_files"] = [rolling._ref(path) for path in mixed.material]
    mixed.capsule["material_modes"][str(client)] = stat.S_IMODE(client.stat().st_mode)
    write(mixed.path, mixed.capsule)
    with pytest.raises(ValueError, match="canonical/source/client/image"):
        quick.validate_profile(rolling._ref(mixed.path))


@pytest.mark.parametrize("mutation", ["fabricated-command", "wrong-image", "wrong-workload", "causal-reversal", "minimal-receipt", "wrong-canonical-image"])
def test_selected_mode_requires_direct_original_runtime_command_and_causal_receipt(mixed, mutation):
    seed = mixed.capsule["seed_payload"]
    reference = seed["readiness"]["front"]
    if mutation == "wrong-canonical-image":
        path = Path(reference["plan"]["path"])
        recipe = lanes._load(path.read_bytes())
        recipe["canonical_runtime"]["collection_image_digest"] = "sha256:" + "f" * 64
        recipe["canonical_runtime"]["checks"]["collection"]["image_digest"] = "sha256:" + "f" * 64
        canonical = write(path.parent / "canonical-runtime.json", recipe["canonical_runtime"])
        recipe["canonical_runtime_sha256"] = rolling._ref(canonical)["sha256"]
        write(path, recipe)
        reference["plan"] = rolling._ref(path)
        deep_path = Path(reference["deep_receipt"]["path"])
        deep = lanes._load(deep_path.read_bytes())
        deep.update(plan_sha256=reference["plan"]["sha256"], canonical_runtime_sha256=recipe["canonical_runtime_sha256"])
        write(deep_path, deep)
        reference["deep_receipt"] = rolling._ref(deep_path)
    elif mutation in {"fabricated-command", "wrong-image", "causal-reversal"}:
        path = Path(reference["deep"]["started"]["path"])
        value = lanes._load(path.read_bytes())
        if mutation == "fabricated-command":
            value["command"] = ["fabricated-successful-deep-command"]
        elif mutation == "wrong-image":
            image = seed["runtime"]["collection_image_digest"]
            value["command"] = [item.replace(image, "sha256:" + "f" * 64) for item in value["command"]]
        else:
            value["started_at"] = "2000-01-01T00:00:00Z"
        write(path, value)
        reference["deep"]["started"] = rolling._ref(path)
    else:
        path = Path(reference["deep_receipt"]["path"])
        value = lanes._load(path.read_bytes())
        if mutation == "wrong-workload":
            value["workload_sha256"] = "f" * 64
        else:
            value = {key: value[key] for key in ("mode", "valid", "status", "accepted_samples", "scientific_credit",
                "plan_sha256", "source", "workload_sha256", "application_body_identity_policy")}
        write(path, value)
        reference["deep_receipt"] = rolling._ref(path)
    with pytest.raises(ValueError):
        quick._mode_selection(seed, "front")


def test_re_rendered_wrong_class_shard_is_rejected(mixed):
    from qcsd_lab import rapid_slot_chunks as geometry
    path = quick.publish_plan(mixed.spec, mixed.ref, mixed.path.parent / "front-original.json", slot_start=4, slot_count=1)
    sites, payload = quick.verify_plan(replace(mixed.spec, plan_receipt=path))
    lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    lane = replace(lane, shard=2)
    lane = replace(lane, campaign_name=geometry.name(lane, lane.generation))
    raw = lanes._render_lane_campaign(mixed.spec, lane, sites)
    payload["lanes"] = [{**asdict(lane), "campaign_sha256": lanes._sha(raw)}]
    forged = mixed.path.parent / "front-wrong-shard.json"
    rolling._write(forged, quick.PLAN_TYPE, payload)
    with pytest.raises(ValueError, match="original class shard"):
        quick.verify_plan(replace(mixed.spec, plan_receipt=forged))


def test_old_schema_cannot_gain_explicit_mode_authority(mixed):
    mixed.capsule.update(schema_version=1, artifact_type=quick.CAPSULE_TYPE)
    write(mixed.path, mixed.capsule)
    with pytest.raises(ValueError, match="explicit prospective contract"):
        quick.validate_profile(rolling._ref(mixed.path))


@pytest.fixture
def buflo_pair(mixed):
    """Real parameter bytes, synthetic typed records; no prepared authority."""
    _stage_spec_reader_fixtures(mixed)
    from qcsd_lab import buflo_duration_budget as budget, rapid_capture_traffic as traffic
    seed = mixed.capsule["seed_payload"]
    reference = seed["readiness"].pop("front")
    seed["readiness"]["buflo"] = reference
    for row in seed["lanes"]:
        if row["mode"] == "front":
            row["mode"] = "buflo"
    seed.update(buflo_duration_policy=budget.POLICY, static_capture_amendment={"engineering_fixture": "explicit fixed budget"})
    recipe_path = Path(reference["plan"]["path"])
    recipe = lanes._load(recipe_path.read_bytes())
    recipe["campaigns"][0]["mode"] = "buflo"
    recipe["campaigns"][0]["run_argv"] = [item.replace("dns-receipts/front.json", "dns-receipts/buflo.json")
                                            for item in recipe["campaigns"][0]["run_argv"]]
    recipe.update(buflo_duration_policy=budget.POLICY, static_capture_amendment=seed["static_capture_amendment"],
                  traffic_hashes=traffic.expected(budget.POLICY))
    write(recipe_path, recipe)
    reference["plan"] = rolling._ref(recipe_path)
    deep = lanes._load(Path(reference["deep_receipt"]["path"]).read_bytes())
    deep.update(mode="buflo", plan_sha256=reference["plan"]["sha256"])
    reference["deep_receipt"] = rolling._ref(write(recipe_path.parent / "buflo-deep-verification.json", deep))
    for action in ("capture", "deep"):
        for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                            ("stdout", ".stdout.log"), ("stderr", ".stderr.log")):
            original = Path(reference[action][key]["path"])
            raw = original.read_bytes()
            if key == "started":
                started = lanes._load(raw)
                command = recipe["campaigns"][0]["run_argv"] if action == "capture" else started["command"]
                if action == "deep":
                    command[command.index("--mode") + 1] = "buflo"
                    command[command.index("--plan-sha256") + 1] = reference["plan"]["sha256"]
                started["command"] = command
                raw = lanes._json(started)
            reference[action][key] = rolling._ref(write(recipe_path.parent / "logs" / ("buflo-" + action + suffix), raw))
    source_root = mixed.spec.runtime_source_root
    checked_root = Path(quick.__file__).resolve().parents[2]
    for filename in ("buflo-live.json", "buflo-live.json.provenance.json", "cs-buflo-ctsp-live.json",
                     "cs-buflo-ctsp-live.json.provenance.json", "buflo-duration200.json", "buflo-duration200.json.provenance.json"):
        relative = Path("config/defense-params") / filename
        raw = (checked_root / relative).read_bytes()
        write(source_root / relative, raw)
        write(mixed.spec.execution_root / relative, raw)
    source_files, directories = quick._source_layout(source_root)
    write(mixed.inventory, {name: {"sha256": rolling._ref(source_root / name)["sha256"],
        "executable": bool((source_root / name).stat().st_mode & 0o111)} for name in source_files})
    canonical = lanes._load(mixed.canonical.read_bytes())
    canonical["source_inventory_sha256"] = rolling._ref(mixed.inventory)["sha256"]
    write(mixed.canonical, canonical)
    write(mixed.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    selection, selected_rows, extra = quick._mode_selection(seed, "buflo")
    materials = {getattr(mixed.spec, key) for key in ("cohort", "qualification_spec", "source_manifest", "client_binary", "base_launcher", "host_launcher")}
    materials.update({mixed.canonical, mixed.inventory, mixed.spec.plan_receipt, mixed.manifest})
    materials.update(source_root / name for name in source_files)
    materials.update(mixed.spec.execution_root / name for name, _ in quick._traffic_files(seed).values())
    materials.update(extra)
    mixed.capsule.update(mode_selection=selection, permitted_slots=quick._permitted_slots({"lanes": selected_rows}),
        current_canonical=rolling._ref(mixed.canonical), original_canonical=rolling._ref(mixed.canonical),
        source_inventory=rolling._ref(mixed.inventory), source_directory_modes=directories,
        archive_references={"original_plan": rolling._ref(mixed.spec.plan_receipt), "cohort": rolling._ref(mixed.spec.cohort)},
        material_files=[rolling._ref(path) for path in sorted(materials)],
        material_modes={str(path): stat.S_IMODE(path.stat().st_mode) for path in materials})
    write(mixed.path, mixed.capsule)
    mixed.ref = rolling._ref(mixed.path)
    specs, campaigns = [], []
    for slot in (4, 5):
        path = quick.publish_plan(mixed.spec, mixed.ref, mixed.path.parent / f"buflo-plan-{slot}.json", slot_start=slot, slot_count=1)
        candidate = replace(mixed.spec, plan_receipt=path)
        _, payload = quick.verify_plan(candidate)
        spec_path = mixed.path.parent / f"buflo-spec-{slot}.json"
        rolling._write_spec(spec_path, candidate)
        specs.append(rolling._ref(spec_path))
        campaign = candidate.campaign_dir / (payload["lanes"][0]["campaign_name"] + ".yml")
        campaigns.append(rolling._ref(campaign))
    from qcsd_lab.rapid_parallel_capture import RUNTIME_KEYS
    mixed.parameter_context = {"artifact_type": "qcsd-two-worker-formal-lane-authority", "lane_specs": specs,
        "runtime": {key: mixed.spec.serializable()[key] for key in RUNTIME_KEYS}, "campaigns": campaigns}
    return mixed


def test_v2_buflo200_parameter_context_reopens_selected_policy_and_real_parameter_bytes(buflo_pair):
    from qcsd_lab import parameters, rapid_parallel_capture as parallel, buflo_duration_budget as budget
    previous = parameters.LAB_ROOT
    with parallel._execution_parameter_context(buflo_pair.parameter_context):
        assert parameters.LAB_ROOT == buflo_pair.spec.execution_root
        selected = buflo_pair.spec.execution_root / budget.PARAMETER_PATH
        assert lanes._sha(selected.read_bytes()) == budget.PARAMETER_SHA256
        assert budget.parse_parameters(selected.read_bytes())[budget.PARAMETER_FIELD] == budget.POLICY
    assert parameters.LAB_ROOT == previous


@pytest.mark.parametrize("mutation", ["parameter-bytes", "provenance-bytes", "missing-typed-lanes", "wrong-campaign-hash"])
def test_buflo200_context_rejects_unbound_or_changed_inputs(buflo_pair, mutation):
    from qcsd_lab import rapid_parallel_capture as parallel, buflo_duration_budget as budget, rapid_capture_traffic as traffic
    value = buflo_pair.parameter_context
    if mutation in {"parameter-bytes", "provenance-bytes"}:
        path = buflo_pair.spec.execution_root / (budget.PARAMETER_PATH if mutation == "parameter-bytes" else traffic.PROVENANCE_PATH)
        path.write_bytes(path.read_bytes() + b"\nchanged")
    elif mutation == "missing-typed-lanes":
        value.pop("lane_specs")
    else:
        value["campaigns"][0]["sha256"] = "f" * 64
    with pytest.raises(ValueError):
        with parallel._execution_parameter_context(value):
            pytest.fail("unbound BuFLO200 context entered")


def test_buflo200_filename_cannot_borrow_a_valid_front_v2_profile(mixed):
    _stage_spec_reader_fixtures(mixed)
    from qcsd_lab import rapid_parallel_capture as parallel
    specs, campaigns = [], []
    for slot in (4, 5):
        path = quick.publish_plan(mixed.spec, mixed.ref, mixed.path.parent / f"front-context-{slot}.json", slot_start=slot, slot_count=1)
        candidate = replace(mixed.spec, plan_receipt=path)
        _, payload = quick.verify_plan(candidate)
        spec_path = mixed.path.parent / f"front-context-spec-{slot}.json"
        rolling._write_spec(spec_path, candidate)
        specs.append(rolling._ref(spec_path))
        campaigns.append(rolling._ref(candidate.campaign_dir / (payload["lanes"][0]["campaign_name"] + ".yml")))
    value = {"artifact_type": "qcsd-two-worker-formal-lane-authority", "lane_specs": specs,
        "runtime": {key: mixed.spec.serializable()[key] for key in parallel.RUNTIME_KEYS}, "campaigns": campaigns}
    with pytest.raises(ValueError, match="selected fixed profile/campaign"):
        parallel._quick_buflo_parameter_fixture(value)


def test_shell_default_route_is_exact_source58_plus_v2_type_dispatch():
    root = Path(quick.__file__).resolve().parents[2]
    raw = (root / "qcsd-lab").read_bytes()
    addition = b'          "${rapid_scheduling_kind}" == "qcsd-prospective-direct-quick-launch-profile-v2" ||\n'
    assert raw.count(addition) == 1
    assert hashlib.sha256(raw.replace(addition, b"", 1)).hexdigest() == \
        "55c33eee76a0635aa38a0bf8fe0a009e465bb8a2f61f7f7902844a703d5b7c83"


def _stage_spec_reader_fixtures(record):
    """Supply exact spec inputs only for the six parameter-context cases."""
    root = Path(quick.__file__).resolve().parents[2]
    paths = {lanes.STUDY_PROFILE_FILE,
             *(relative for relative, _ in quick._traffic_files(record.capsule["seed_payload"]).values())}
    for relative in paths:
        source = root / relative
        copied = write(record.spec.execution_root / relative, source.read_bytes())
        copied.chmod(stat.S_IMODE(source.stat().st_mode))
    # The public loader checks the original enrollment type even when its
    # directly bound quick plan supplies the qualification layout. This is a
    # synthetic typed fixture, never an enrollment or capture authority.
    seed = record.capsule["seed_payload"]
    write(record.spec.cohort, lanes.admission._bind("qcsd-rapid-v6-immutable-enrollment-batch", {
        "selected_candidate_ids": [site["candidate_id"] for site in seed["sites"]],
        "engineering_fixture": "public spec reader layout only", "scientific_credit": False}))
    seed["bindings"]["cohort_sha256"] = rolling._ref(record.spec.cohort)["sha256"]
    write(record.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    record.capsule["archive_references"].update(
        original_plan=rolling._ref(record.spec.plan_receipt), cohort=rolling._ref(record.spec.cohort))
    record.capsule["material_files"] = [rolling._ref(Path(ref["path"])) for ref in record.capsule["material_files"]]
    record.capsule["material_modes"] = {ref["path"]: stat.S_IMODE(Path(ref["path"]).stat().st_mode)
        for ref in record.capsule["material_files"]}
    write(record.path, record.capsule)
    record.ref = rolling._ref(record.path)
