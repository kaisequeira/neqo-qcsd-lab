"""Synthetic direct FRONT50 boundaries; no fixture grants capture credit."""
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path

import pytest
import yaml

from qcsd_lab import capture_acceptance_policy as acceptance
from qcsd_lab import front_fixed_configuration as front
from qcsd_lab import front_incoming_acceptance as incoming
from qcsd_lab import rapid_front_quick_profile as front_quick
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_front_v5_light_capture import preparation
from tests.test_rapid_quick_explicit_mode import direct, mixed, write


BODY = "complete-current-application-delivery-v1"
CLIENTS = [b"synthetic portable client architecture A; no runtime authority",
           b"synthetic portable client architecture B; no runtime authority"]


def _seal_original(case):
    """Rebind synthetic bytes so negative controls reach their semantic gate."""
    reference = case.seed["readiness"]["front"]
    plan_path = Path(reference["plan"]["path"])
    write(plan_path, case.recipe)
    reference["plan"] = rolling._ref(plan_path)
    case.deep["plan_sha256"] = reference["plan"]["sha256"]
    deep_path = Path(reference["deep_receipt"]["path"])
    write(deep_path, case.deep)
    reference["deep_receipt"] = rolling._ref(deep_path)
    started_path = Path(reference["deep"]["started"]["path"])
    started = lanes._load(started_path.read_bytes())
    index = started["command"].index("--plan-sha256") + 1
    started["command"][index] = reference["plan"]["sha256"]
    write(started_path, started)
    reference["deep"]["started"] = rolling._ref(started_path)
    write(case.spec.plan_receipt, lanes.admission._bind(lanes.PLAN_TYPE, case.seed))


def _refresh_workload(case, manifest):
    write(case.manifest, manifest)
    case.site = replace(case.site, workload_sha256=lanes._sha(case.manifest.read_bytes()))
    case.seed["sites"] = [asdict(case.site)]
    from urllib.parse import urlsplit
    resources = manifest["resources"]
    graph = {"resource_count": len(resources),
        "resource_records_sha256": lanes._sha(lanes._json(resources)),
        "origins": sorted({urlsplit(row["url"]).scheme + "://" + urlsplit(row["url"]).netloc
                           for row in resources})}
    for value in (case.recipe, case.deep):
        value["workload_sha256"] = case.site.workload_sha256
        value["full_graph"] = graph


def _publish(case, name="front50-profile.json", *, mode="front"):
    return quick.publish_profile(case.spec, rolling._ref(case.canonical),
        case.path.parent / name, workloads=[case.site.workload_id], mode=mode)


@pytest.fixture
def front50(mixed, monkeypatch, request):
    case = mixed
    case.seed = case.capsule["seed_payload"]
    reference = case.seed["readiness"]["front"]
    case.recipe = lanes._load(Path(reference["plan"]["path"]).read_bytes())
    case.deep = lanes._load(Path(reference["deep_receipt"]["path"]).read_bytes())
    case.seed.update({front.FIELD: front.POLICY, incoming.FIELD: incoming.POLICY,
        "application_body_identity_policy": BODY,
        "static_capture_amendment": {"path": str(case.path.parent / "synthetic-amendment.json"),
                                     "sha256": "0" * 64}})
    source = lanes._load(case.spec.source_manifest.read_bytes())
    source.update(neqo_commit=front_quick.NATIVE, neqo_pinned_commit=front_quick.NATIVE)
    write(case.spec.source_manifest, source)
    write(case.spec.client_binary, getattr(request, "param", CLIENTS[0]))
    case.client_sha = lanes._sha(case.spec.client_binary.read_bytes())
    case.seed["runtime_artifacts"] = {name: rolling._ref(getattr(case.spec, name))
        for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher")}
    registered = Path(quick.__file__).resolve().parents[2]
    traffic = quick._traffic_files(case.seed)
    roots = {case.spec.execution_root, case.spec.runtime_source_root, case.spec.module_root}
    for relative, digest in traffic.values():
        raw = (registered / relative).read_bytes()
        assert lanes._sha(raw) == digest
        for root in roots:
            write(root / relative, raw).chmod(0o644)
    # The existing parameter context independently compares these four copies.
    for filename in ("buflo-live.json", "buflo-live.json.provenance.json",
                     "cs-buflo-ctsp-live.json", "cs-buflo-ctsp-live.json.provenance.json"):
        relative = Path("config/defense-params") / filename
        for root in roots:
            write(root / relative, (registered / relative).read_bytes()).chmod(0o644)
    write(case.spec.execution_root / lanes.STUDY_PROFILE_FILE,
          (registered / lanes.STUDY_PROFILE_FILE).read_bytes())
    inventory = {path.relative_to(case.spec.runtime_source_root).as_posix():
        {"sha256": lanes._sha(path.read_bytes()), "executable": bool(path.stat().st_mode & 0o111)}
        for path in case.spec.runtime_source_root.rglob("*") if path.is_file()}
    write(case.inventory, inventory)
    canonical = lanes._load(case.canonical.read_bytes())
    canonical.update(source=source, installed_client_sha256=case.client_sha,
        exported_source_manifest_sha256=rolling._ref(case.spec.source_manifest)["sha256"],
        source_inventory_sha256=rolling._ref(case.inventory)["sha256"])
    canonical["checks"] = {"collection": {"source": source,
        "image_digest": case.spec.collection_image_digest, "client_sha256": case.client_sha}}
    write(case.canonical, canonical)
    original_canonical = write(Path(reference["plan"]["path"]).parent / "canonical-runtime.json", canonical)
    case.recipe.update(canonical_runtime=canonical,
        canonical_runtime_sha256=rolling._ref(original_canonical)["sha256"],
        expected_native_commit=front_quick.NATIVE,
        traffic_hashes={key: digest for key, (_, digest) in traffic.items()})
    case.deep.update(source=source, canonical_runtime_sha256=rolling._ref(original_canonical)["sha256"],
        front_configuration_sha256=front.CONFIGURATION_SHA256)
    for value in (case.recipe, case.deep):
        value.update({front.FIELD: front.POLICY, incoming.FIELD: incoming.POLICY,
                      "application_body_identity_policy": BODY})
    campaign = case.recipe["campaigns"][0]
    case.original_campaign = case.spec.execution_root / campaign["campaign_relative"]
    write(case.original_campaign, yaml.safe_dump({"profile": "research-1200",
        "request_policies": ["as-defined"], "defenses": [{"name": "front", "kind": "front"}],
        "workloads": {case.site.workload_id: 1}, "application_body_identity_policy": BODY,
        front.FIELD: front.POLICY, incoming.FIELD: incoming.POLICY}).encode())
    campaign["campaign_sha256"] = rolling._ref(case.original_campaign)["sha256"]
    manifest = lanes._load(case.manifest.read_bytes())
    manifest["preparation"] = {**preparation(),
        acceptance.TERMINAL_PRIMARY_FIELD: acceptance.TERMINAL_PRIMARY_POLICY}
    _refresh_workload(case, manifest)
    write(case.spec.cohort, lanes.admission._bind("synthetic-enrolled-fixture",
        {"selected_candidate_ids": [case.site.candidate_id]}))
    case.seed["bindings"]["cohort_sha256"] = rolling._ref(case.spec.cohort)["sha256"]
    _seal_original(case)

    def installation_boundary(spec, canonical_ref, *, front=False):
        # Only the unrelated twelve-operation installation closure is replaced.
        # Profile publication/reopening, readiness, graph and artifact checks run.
        assert front is True and spec == case.spec
        assert canonical_ref == rolling._ref(case.canonical)
        return lanes._load(case.canonical.read_bytes()), rolling._ref(case.inventory)

    monkeypatch.setattr(quick, "_runtime_once", installation_boundary)
    case.ref = _publish(case)
    case.profile_path = Path(case.ref["path"])
    return case


@pytest.mark.parametrize("front50", CLIENTS, indirect=True)
def test_front50_profile_and_plan_bind_each_actual_client_digest(front50):
    context = OperationFacts()
    capsule = quick.validate_profile(front50.ref, _context=context)
    context.check()
    assert capsule["artifact_type"] == front_quick.PROFILE_TYPE == quick.FRONT_CAPSULE_TYPE
    assert capsule["schema_version"] == 3
    assert set(capsule["mode_selection"]) == {"mode", "readiness"}
    assert capsule["mode_selection"]["mode"] == "front"
    assert capsule["client_sha256"] == front50.client_sha
    assert capsule["client_sha256"] == lanes._sha(front50.spec.client_binary.read_bytes())
    assert capsule["source"]["neqo_commit"] == front_quick.NATIVE
    assert capsule["seed_payload"] == front50.seed
    assert {row["mode"] for row in capsule["seed_payload"]["lanes"]} == {"undefended", "front"}
    assert capsule["permitted_slots"] == [4, 5, 6, 7]
    path = quick.publish_plan(front50.spec, front50.ref, front50.path.parent / "worker-plan.json",
        slot_start=4, slot_count=2)
    spec = replace(front50.spec, plan_receipt=path)
    sites, payload = quick.verify_plan(spec)
    row = payload["lanes"][0]
    lane = quick.prepared_lane({key: item for key, item in row.items() if key != "campaign_sha256"})
    campaign_path = spec.campaign_dir / (lane.campaign_name + ".yml")
    campaign = yaml.safe_load(campaign_path.read_bytes())
    assert sites == (front50.site,)
    assert payload[front.FIELD] == campaign[front.FIELD] == front.POLICY
    assert payload[incoming.FIELD] == campaign[incoming.FIELD] == incoming.POLICY
    assert campaign["profile"] == "research-1200"
    assert campaign["workloads"] == {front50.site.workload_id: 2}
    assert payload["planned_trace_count"] == 2
    assert payload["formal_accepted_trace_count"] == capsule["formal_accepted_trace_count"] == 0
    assert payload["scientific_credit"] is capsule["scientific_credit"] is False
    assert campaign_path.read_bytes() == lanes._render_lane_campaign(spec, lane, sites)
    material = {item["path"] for item in capsule["material_files"]}
    for relative, _ in quick._traffic_files(front50.seed).values():
        assert str(front50.spec.execution_root / relative) in material
    assert front.resolved_configuration()["control_interval_us"] == 10000
    assert front.resolved_configuration()["defense"]["n_client_packets"] == 450


@pytest.mark.parametrize("mode", [None, "undefended", "tamaraw"])
def test_front50_cannot_borrow_default_or_another_mode(front50, mode):
    with pytest.raises(ValueError):
        _publish(front50, "wrong-mode.json", mode=mode)


@pytest.mark.parametrize("where,key,value", [
    ("seed", front.FIELD, None), ("seed", incoming.FIELD, None),
    ("seed", incoming.FIELD, "unknown"), ("seed", front.FIELD, "unknown"),
    ("seed", "application_body_identity_policy", "exact-prepared-application-body-v1"),
    ("recipe", incoming.FIELD, None), ("recipe", front.FIELD, "unknown"),
    ("deep", incoming.FIELD, "unknown"), ("deep", "front_configuration_sha256", "0" * 64),
    ("deep", "front_configuration_sha256", None),
    ("deep", "application_body_identity_policy", "exact-prepared-application-body-v1"),
])
def test_resealed_readiness_cannot_change_or_drop_front50_authority(front50, where, key, value):
    target = getattr(front50, where)
    if value is None:
        target.pop(key)
    else:
        target[key] = value
    _seal_original(front50)
    with pytest.raises(ValueError):
        _publish(front50, "changed-authority.json")


@pytest.mark.parametrize("change", ["profile", "request", "defense", "policy"])
def test_resealed_original_campaign_requires_complete_front50_setting(front50, change):
    campaign = yaml.safe_load(front50.original_campaign.read_bytes())
    if change == "profile": campaign["profile"] = "research"
    elif change == "request": campaign["request_policies"] = ["other"]
    elif change == "defense": campaign["defenses"].append({"name": "buflo", "kind": "buflo"})
    else: campaign.pop(incoming.FIELD)
    write(front50.original_campaign, yaml.safe_dump(campaign).encode())
    front50.recipe["campaigns"][0]["campaign_sha256"] = rolling._ref(front50.original_campaign)["sha256"]
    _seal_original(front50)
    with pytest.raises(ValueError):
        _publish(front50, "changed-campaign.json")


@pytest.mark.parametrize("kind", ["single-origin", "missing-native-preparation", "missing-terminal-preparation"])
def test_resealed_workload_requires_full_graph_and_both_prepared_policies(front50, kind):
    manifest = lanes._load(front50.manifest.read_bytes())
    if kind == "single-origin":
        manifest["resources"] = manifest["resources"][:1]
    else:
        key = acceptance.FRONT_FIELD if kind == "missing-native-preparation" else acceptance.TERMINAL_PRIMARY_FIELD
        manifest["preparation"].pop(key)
    _refresh_workload(front50, manifest)
    _seal_original(front50)
    with pytest.raises(ValueError):
        _publish(front50, "changed-workload.json")


@pytest.mark.parametrize("root_name", ["execution_root", "runtime_source_root"])
@pytest.mark.parametrize("change", ["control", "provenance", "mode"])
def test_native_config_and_provenance_copies_are_exact(front50, root_name, change):
    root = getattr(front50.spec, root_name)
    path = root / (front.PROVENANCE_PATH if change == "provenance" else front.CONFIGURATION_PATH)
    if change == "control":
        path.write_bytes(path.read_bytes().replace(b"control_interval_us = 10000", b"control_interval_us = 50000"))
    elif change == "provenance": path.write_bytes(path.read_bytes() + b"\nchanged")
    else: path.chmod(0o600)
    with pytest.raises(ValueError):
        _publish(front50, "changed-artifact.json")


def test_profile_client_bytes_cannot_change_after_publication(front50):
    front50.spec.client_binary.write_bytes(CLIENTS[1])
    with pytest.raises(ValueError):
        quick.validate_profile(front50.ref)


def test_original_canary_client_binding_cannot_be_resealed_to_another_digest(front50):
    reference = front50.seed["readiness"]["front"]["plan"]
    canonical_path = Path(reference["path"]).parent / "canonical-runtime.json"
    canonical = lanes._load(canonical_path.read_bytes())
    canonical["installed_client_sha256"] = "f" * 64
    canonical["checks"]["collection"]["client_sha256"] = "f" * 64
    write(canonical_path, canonical)
    front50.recipe["canonical_runtime"] = canonical
    front50.recipe["canonical_runtime_sha256"] = rolling._ref(canonical_path)["sha256"]
    front50.deep["canonical_runtime_sha256"] = rolling._ref(canonical_path)["sha256"]
    _seal_original(front50)
    with pytest.raises(ValueError, match="canonical/source/client/image"):
        _publish(front50, "changed-original-client.json")


def test_native_d2_without_front50_selection_keeps_the_native818_boundary(direct):
    source = lanes._load(direct.spec.source_manifest.read_bytes())
    source.update(neqo_commit=front_quick.NATIVE, neqo_pinned_commit=front_quick.NATIVE)
    write(direct.spec.source_manifest, source)
    canonical = lanes._load(direct.canonical.read_bytes())
    canonical.update(source=source,
        exported_source_manifest_sha256=rolling._ref(direct.spec.source_manifest)["sha256"])
    write(direct.canonical, canonical)
    assert not front_quick.selected(direct.capsule["seed_payload"], "front")
    with pytest.raises(ValueError, match="Native818 installation"):
        quick._runtime_once(direct.spec, rolling._ref(direct.canonical))


@pytest.mark.parametrize("change", ["claim-client", "downgrade-v2", "borrow-mode", "omit-helper",
                                   "null-selection", "list-selection"])
def test_v3_capsule_cannot_substitute_its_claims_or_material(front50, change):
    capsule = lanes._load(front50.profile_path.read_bytes())
    if change == "claim-client": capsule["client_sha256"] = "f" * 64
    elif change == "downgrade-v2": capsule.update(schema_version=2, artifact_type=quick.MODE_CAPSULE_TYPE)
    elif change == "borrow-mode": capsule["mode_selection"]["mode"] = "undefended"
    elif change == "null-selection": capsule["mode_selection"] = None
    elif change == "list-selection": capsule["mode_selection"] = ["front"]
    else:
        helper = str(front50.spec.execution_root / incoming.SOURCE_PATH)
        capsule["material_files"] = [item for item in capsule["material_files"] if item["path"] != helper]
        capsule["material_modes"].pop(helper)
    path = write(front50.path.parent / "changed-profile.json", capsule)
    with pytest.raises(ValueError):
        quick.validate_profile(rolling._ref(path))


@pytest.mark.parametrize("start,count", [(0, 1), (7, 2), (64, 1), (4, 17)])
def test_front50_plan_cannot_borrow_slots_or_expand_worker(front50, start, count):
    with pytest.raises(ValueError):
        quick.publish_plan(front50.spec, front50.ref, front50.path.parent / "outside-plan.json",
            slot_start=start, slot_count=count)


def _workers(case):
    specifications, campaigns = [], []
    for slot in (4, 5):
        plan_path = quick.publish_plan(case.spec, case.ref, case.path.parent / f"worker-{slot}-plan.json",
            slot_start=slot, slot_count=1)
        spec = replace(case.spec, plan_receipt=plan_path)
        spec_path = write(case.path.parent / f"worker-{slot}-spec.json", {
            "schema_version": 1, "artifact_type": lanes.SPEC_TYPE, "inputs": spec.serializable()})
        payload = lanes.plan_payload(plan_path.read_bytes())
        campaign_path = spec.campaign_dir / (payload["lanes"][0]["campaign_name"] + ".yml")
        specifications.append(rolling._ref(spec_path))
        campaigns.append(rolling._ref(campaign_path))
    return {"artifact_type": "qcsd-two-worker-formal-lane-authority",
        "lane_specs": specifications, "campaigns": campaigns,
        "runtime": {key: case.spec.serializable()[key] for key in parallel.RUNTIME_KEYS}}


def test_two_disjoint_quick_front50_workers_materialize_exact_native_fixture(front50):
    from qcsd_lab import parameters
    value = _workers(front50)
    assert parallel._target_front_v5_parameter_fixture(value) == front.INPUT
    previous = parameters.LAB_ROOT
    with parallel._execution_parameter_context(value):
        assert parameters.LAB_ROOT == front50.spec.execution_root
        assert (parameters.LAB_ROOT / front.CONFIGURATION_PATH).read_bytes() == front.configuration_bytes()
    assert parameters.LAB_ROOT == previous


@pytest.mark.parametrize("change", ["duplicate-worker", "campaign-bytes"])
def test_front50_materialization_refuses_duplicate_or_changed_worker(front50, change):
    value = _workers(front50)
    if change == "duplicate-worker":
        value["lane_specs"][1] = deepcopy(value["lane_specs"][0])
        value["campaigns"][1] = deepcopy(value["campaigns"][0])
    else:
        path = Path(value["campaigns"][0]["path"])
        path.write_bytes(path.read_bytes() + b"\nchanged")
    with pytest.raises(ValueError):
        parallel._target_front_v5_parameter_fixture(value)
