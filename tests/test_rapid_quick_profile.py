"""Direct quick-profile boundaries; synthetic fixtures grant no capture credit."""
from dataclasses import asdict, replace
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_slot_chunks as geometry
from qcsd_lab.rapid_operation_facts import OperationFacts
from qcsd_lab.rapid_undefended_capture import OrdinarySite, FIELD, CONTRACT


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else lanes._json(value))
    return path


@pytest.fixture
def direct(tmp_path):
    source, execution = tmp_path / "source", tmp_path / "execution"
    for folder in (source, execution / "config/campaigns", execution / "config/workloads", tmp_path / "acquisition"):
        folder.mkdir(parents=True)
    manifest = write(execution / "config/workloads/site.json", {"resources": [
        {"id": "main", "url": "https://site.example/"},
        {"id": "asset", "url": "https://cdn.example/asset"}]})
    site = OrdinarySite("candidate", "site", lanes._sha(manifest.read_bytes()), "https://site.example", None, None)
    cohort = write(tmp_path / "cohort.json", {"engineering_fixture": "direct immutable membership"})
    qualifier = write(tmp_path / "qualification.json", {"engineering_fixture": "ordinary unqualified input"})
    metadata = {"lab_commit": "b" * 40, "lab_dirty": False, "neqo_commit": quick.NATIVE,
        "neqo_pinned_commit": quick.NATIVE, "neqo_dirty": False,
        "lab_patch_sha256": quick.EMPTY_SHA256, "neqo_patch_sha256": quick.EMPTY_SHA256}
    source_manifest = write(tmp_path / "source.json", metadata)
    client = write(tmp_path / "client", b"synthetic client; no runtime authority")
    base = write(source / "qcsd-lab", b"synthetic launcher")
    host = write(execution / "qcsd-lab", base.read_bytes())
    from qcsd_lab import rapid_capture_traffic as traffic
    for relative, _ in traffic.files().values():
        write(execution / relative, b"synthetic fixed traffic material")
    inventory = write(tmp_path / "inventory.json", {"qcsd-lab": {"sha256": lanes._sha(base.read_bytes()), "executable": False}})
    canonical = write(tmp_path / "canonical.json", {"engineering_fixture": "current closed record",
        "source": metadata, "collection_image_digest": "sha256:" + "d" * 64,
        "installed_client_sha256": lanes._sha(client.read_bytes()), "source_inventory_sha256": rolling._ref(inventory)["sha256"],
        "exported_source_manifest_sha256": lanes._sha(source_manifest.read_bytes()), "installed_byte_verification_completed": True,
        "scientific_credit": False})
    old_plan = tmp_path / "original-plan.json"
    spec = lanes.CaptureSpec(tmp_path, source, source, execution, tmp_path / "acquisition", cohort,
        qualifier, manifest.parent, execution / "config/campaigns", old_plan, source_manifest, client,
        base, host, "sha256:" + "d" * 64, "quick-fixture")
    seed = {"study_version": 6, "cohort_generation": "rolling-50", "bindings": {"cohort_sha256": lanes._sha(cohort.read_bytes())},
        "runtime": {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS},
        "sites": [asdict(site)], "lanes": [{"mode": "undefended", "shard": 1, "block": 2, "visits_per_workload": 4}],
        FIELD: CONTRACT, "capture_limits": dict(rolling.plan.V5_CAPTURE_LIMITS)}
    write(old_plan, lanes.admission._bind(lanes.PLAN_TYPE, seed))
    material = sorted({cohort, qualifier, source_manifest, client, base, host, canonical, inventory, old_plan, manifest,
        *(execution / relative for relative, _ in traffic.files().values())})
    graph = {"resource_count": 2, "origins": ["https://cdn.example", "https://site.example"],
        "resources_sha256": lanes._sha(lanes._json(lanes._load(manifest.read_bytes())["resources"]))}
    capsule = {"schema_version": 1, "artifact_type": quick.CAPSULE_TYPE, "contract": quick.CONTRACT,
        "base_spec": spec.serializable(), "runtime": seed["runtime"], "qualification_spec": rolling._ref(qualifier),
        "current_canonical": rolling._ref(canonical), "original_canonical": rolling._ref(canonical),
        "source_inventory": rolling._ref(inventory), "source": metadata, "client_sha256": lanes._sha(client.read_bytes()),
        "source_directory_modes": {".": stat.S_IMODE(source.stat().st_mode)},
        "sites": [asdict(site)], "graphs": {"site": graph}, "seed_payload": seed, "permitted_slots": [4, 5, 6, 7],
        "material_files": [rolling._ref(path) for path in material], "material_modes": {str(path): stat.S_IMODE(path.stat().st_mode) for path in material},
        "archive_references": {"original_plan": rolling._ref(old_plan), "cohort": rolling._ref(cohort)},
        "class_target": 50, "modes": list(rolling.plan.MODES), "visits_per_class_mode": 64, "formal_trace_target": 16000,
        "published_at": "2000-01-01T00:00:00Z", "reason": "synthetic direct profile boundary",
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    path = write(tmp_path / "profile.json", capsule)
    return SimpleNamespace(spec=spec, path=path, ref=rolling._ref(path), capsule=capsule,
        material=material, manifest=manifest, site=site, canonical=canonical, inventory=inventory)


def test_material_profile_does_not_reopen_historical_runtime_or_canary(direct, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("direct profile reopened historical scientific ancestry")
    monkeypatch.setattr(schedule, "reopen_runtime", forbidden)
    monkeypatch.setattr(rolling, "_verify_enrollment", forbidden)
    from qcsd_lab import rapid_rolling_readiness as readiness
    monkeypatch.setattr(readiness, "validate_canary", forbidden)
    context = OperationFacts()
    value = quick.validate_profile(direct.ref, _context=context)
    context.check()
    assert value["formal_accepted_trace_count"] == 0
    assert value["scientific_credit"] is False
    assert context._trees == {}


@pytest.mark.parametrize("changed", ["manifest", "canonical", "inventory"])
def test_direct_material_mutation_is_rejected(direct, changed):
    path = getattr(direct, changed)
    path.write_bytes(path.read_bytes() + b"\nchanged")
    with pytest.raises(ValueError, match="immutable reference"):
        quick.validate_profile(direct.ref)


def test_current_material_permission_mutation_is_rejected(direct):
    direct.manifest.chmod(0o600)
    with pytest.raises(ValueError, match="permissions"):
        quick.validate_profile(direct.ref)


def test_capsule_cannot_substitute_claimed_seed_settings(direct):
    direct.capsule["seed_payload"]["capture_limits"]["timeout_seconds"] = 999
    write(direct.path, direct.capsule)
    with pytest.raises(ValueError, match="archived membership/settings"):
        quick.validate_profile(rolling._ref(direct.path))


def test_capsule_cannot_drop_current_host_source_fence(direct):
    base = str(direct.spec.base_launcher)
    direct.capsule["material_files"] = [item for item in direct.capsule["material_files"] if item["path"] != base]
    del direct.capsule["material_modes"][base]
    write(direct.path, direct.capsule)
    with pytest.raises(ValueError, match="installed source"):
        quick.validate_profile(rolling._ref(direct.path))


def test_action_local_memo_still_fences_material_before_effect(direct):
    context = OperationFacts()
    quick.validate_profile(direct.ref, _context=context)
    direct.manifest.write_bytes(direct.manifest.read_bytes() + b"\nchanged")
    with pytest.raises(ValueError, match="dependency bytes"):
        context.check()


def test_added_unlisted_current_source_file_is_rejected(direct):
    write(direct.spec.runtime_source_root / "unlisted_control.py", b"unexpected control module")
    with pytest.raises(ValueError, match="source member names"):
        quick.validate_profile(direct.ref)


def test_capsule_cannot_broaden_material_mount_scope(direct):
    extra = write(direct.path.parent / "unrelated/input.json", {"not": "capture material"})
    direct.capsule["material_files"].append(rolling._ref(extra))
    direct.capsule["material_modes"][str(extra)] = stat.S_IMODE(extra.stat().st_mode)
    write(direct.path, direct.capsule)
    with pytest.raises(ValueError, match="complete material identities"):
        quick.validate_profile(rolling._ref(direct.path))


def test_profile_plan_rejects_slot_outside_declared_remaining_ledger(direct):
    with pytest.raises(ValueError, match="remaining ledger"):
        quick.publish_plan(direct.spec, direct.ref, direct.path.parent / "plan.json", slot_start=0, slot_count=1)


def test_one_slot_workers_have_disjoint_complete_class_slots(direct):
    plans = []
    for slot in (4, 5):
        path = quick.publish_plan(direct.spec, direct.ref, direct.path.parent / f"plan-{slot}.json", slot_start=slot, slot_count=1)
        payload = lanes.plan_payload(path.read_bytes())
        lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
        assert lane.sample_count == 1
        assert payload["sites"] == [asdict(direct.site)]
        plans.append((replace(direct.spec, plan_receipt=path), payload, lane, (direct.site,)))
    quick.require_disjoint(plans)
    with pytest.raises(ValueError, match="duplicate"):
        quick.require_disjoint([plans[0], plans[0]])


def test_image_enrollment_mount_dispatch_avoids_legacy_admission(direct, monkeypatch):
    path = quick.publish_plan(direct.spec, direct.ref, direct.path.parent / "plan.json", slot_start=4, slot_count=1)
    candidate = replace(direct.spec, plan_receipt=path)
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda *args: pytest.fail("legacy ancestry reopened"))
    roots = rolling.enrollment_roots(candidate)
    assert direct.spec.data_root in roots
    assert direct.spec.runtime_source_root in roots
    assert direct.spec.execution_root in roots


def test_quick_spec_uses_complete_declared_fixed_traffic(direct):
    from qcsd_lab import rapid_capture_traffic as traffic
    path = quick.publish_plan(direct.spec, direct.ref, direct.path.parent / "plan.json", slot_start=4, slot_count=1)
    candidate = replace(direct.spec, plan_receipt=path)
    assert traffic.spec_files(candidate) == dict(lanes.TRAFFIC_FILES)
    assert quick.verify_plan(candidate)[0] == (direct.site,)


def test_release_keeps_current_source_member_fence_without_ancestor_trees(direct):
    from qcsd_lab import rapid_formal_parallel as formal
    plan_path = quick.publish_plan(direct.spec, direct.ref, direct.path.parent / "plan.json", slot_start=4, slot_count=1)
    candidate = replace(direct.spec, plan_receipt=plan_path)
    payload = lanes.plan_payload(plan_path.read_bytes())
    lane = lanes._lane({"plan_payload": payload}, payload["lanes"][0]["campaign_name"])
    root = direct.path.parent / "evidence"
    intent = write(root / "intent.json", {"engineering_fixture": "closed claim"})
    write(root / "lineage.json", {"engineering_fixture": "closed lineage"})
    authority = write(root / "authority.json", {"engineering_fixture": "prospective pair"})
    spec_path = write(root / "spec.json", {"engineering_fixture": "current spec"})
    value = {"lane_specs": [rolling._ref(spec_path)], "lane_intents": [rolling._ref(intent)]}
    facts = [(candidate, root, intent, {}, {}, lane, (direct.site,))]
    fence = quick.release_fence(authority, value, facts, {"input_files": {}}, include_dns=False)
    assert set(fence["trees"]) == {str(candidate.runtime_source_root)}
    formal._check_release_fence(fence, authority, value, facts, {"input_files": {}}, include_dns=False)
    write(candidate.runtime_source_root / "neqo-qcsd/unlisted.rs", b"unexpected Native member")
    with pytest.raises(ValueError, match="input bytes or inventory"):
        formal._check_release_fence(fence, authority, value, facts, {"input_files": {}}, include_dns=False)
