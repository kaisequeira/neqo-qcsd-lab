"""Check the registered rapid-study sample grid and lane evidence boundary."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_capture_plan as plan


def _sites(count: int) -> tuple[plan.Site, ...]:
    return tuple(
        plan.Site(
            candidate_id=f"candidate-{index}",
            workload_id=f"workload-{index}",
            workload_sha256=f"{index + 1:064x}",
            primary_origin=f"https://site{index}.example",
            qualification_set=f"qualification-{index // 5}",
        )
        for index in range(count)
    )


def test_final_grid_is_50_classes_five_modes_64_visits() -> None:
    lanes = plan.plan_lanes(_sites(50), final=True)
    assert len(lanes) == 800
    assert len({lane.campaign_name for lane in lanes}) == len(lanes)
    assert {lane.mode for lane in lanes} == set(plan.MODES)
    assert {(lane.block, lane.shard) for lane in lanes} == {
        (block, shard) for block in range(1, 17) for shard in range(1, 11)
    }
    assert all(lane.sample_count == 20 for lane in lanes)
    assert sum(lane.sample_count for lane in lanes) == 16_000
    assert all(lane.campaign_name.startswith("rapid-curated-tranco50-v4-") for lane in lanes)

    v5_sites = tuple(
        replace(site, qualification_set_manifest_sha256=f"{index // 5 + 1:064x}")
        for index, site in enumerate(_sites(50))
    )
    v5_lanes = plan.plan_lanes(v5_sites, final=True, study_version=5)
    assert len(v5_lanes) == 800
    assert sum(lane.sample_count for lane in v5_lanes) == 16_000
    assert all(lane.campaign_name.startswith("rapid-curated-tranco50-v5-") for lane in v5_lanes)
    assert yaml.safe_load(plan.render_lane_campaign(v5_lanes[0], v5_sites))["limits"]["settle_seconds"] == 2
    assert yaml.safe_load(plan.render_lane_campaign(lanes[0], _sites(50)))["limits"]["settle_seconds"] == 0
    assert not ({lane.campaign_name for lane in lanes} & {
        lane.campaign_name for lane in v5_lanes
    })
    with pytest.raises(ValueError, match="qualification manifest digests"):
        plan.plan_lanes(_sites(50), final=True, study_version=5)


def test_shakedown_has_50_separate_zero_credit_slots() -> None:
    lanes = plan.plan_lanes(_sites(10), final=False)
    assert len(lanes) == 10
    assert sum(lane.sample_count for lane in lanes) == 50
    assert {lane.block for lane in lanes} == {1}
    assert all("-diagnostic-" in lane.campaign_name for lane in lanes)


def test_lane_yaml_has_one_mode_and_exact_shard_visits() -> None:
    sites = _sites(50)
    baseline, front, _, buflo, cs_buflo = plan.plan_lanes(sites, final=True)[:5]
    baseline_doc = yaml.safe_load(plan.render_lane_campaign(baseline, sites))
    front_doc = yaml.safe_load(plan.render_lane_campaign(front, sites))
    buflo_doc = yaml.safe_load(plan.render_lane_campaign(buflo, sites))
    cs_doc = yaml.safe_load(plan.render_lane_campaign(cs_buflo, sites))
    assert baseline_doc["purpose"] == "evaluation"
    assert baseline_doc["workloads"] == {f"workload-{i}": 4 for i in range(5)}
    assert baseline_doc["defenses"] == ["undefended"]
    assert "chaff_qualification_set" not in baseline_doc
    assert front_doc["defenses"] == ["front"]
    assert front_doc["chaff_qualification_set"] == "qualification-0"
    assert buflo_doc["defenses"][0]["parameters"] == "../defense-params/buflo-live.json"
    assert cs_doc["defenses"][0]["kind"] == "cs_buflo"
    assert plan.render_lane_campaign(buflo, sites) == plan.render_lane_campaign(buflo, sites)
    with pytest.raises(ValueError, match="differs"):
        plan.render_lane_campaign(replace(buflo, visits_per_workload=3), sites)
    with pytest.raises(ValueError, match="role is unregistered"):
        plan.render_lane_campaign(replace(buflo, role="another-role"), sites)
    repaired = plan.successor_lane(buflo, 2)
    assert repaired.campaign_name == buflo.campaign_name + "-g02"
    assert (
        yaml.safe_load(plan.render_lane_campaign(repaired, sites))["name"]
        == repaired.campaign_name
    )
    with pytest.raises(ValueError, match="advance"):
        plan.successor_lane(repaired, 2)


def test_plan_rejects_broken_site_identity_and_shard() -> None:
    sites = list(_sites(10))
    sites[1] = plan.Site(
        **{**sites[1].__dict__, "primary_origin": "https://site1.example/path"}
    )
    with pytest.raises(ValueError, match="identity"):
        plan.plan_lanes(sites, final=False)
    sites = list(_sites(10))
    sites[1] = plan.Site(
        **{**sites[1].__dict__, "qualification_set": "another-set"}
    )
    with pytest.raises(ValueError, match="share one qualification"):
        plan.plan_lanes(sites, final=False)
    sites = list(_sites(10))
    sites[0] = replace(sites[0], qualification_set_manifest_sha256="a" * 64)
    with pytest.raises(ValueError, match="share one qualification manifest"):
        plan.plan_lanes(sites, final=False)
    sites[1:5] = [
        replace(site, qualification_set_manifest_sha256="a" * 64)
        for site in sites[1:5]
    ]
    assert len(plan.plan_lanes(sites, final=False)) == 10


def test_complete_lane_requires_exact_source_workload_and_slots(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lane = plan.Lane(
        "diagnostic", 1, 1, "undefended",
        "rapid-curated-tranco50-v4-diagnostic-b01-s01-undefended-1200",
        ("workload-0",), 1, None,
    )
    image = "sha256:" + "a" * 64
    commit = "b" * 40
    campaign_sha = "c" * 64
    workload_sha = "d" * 64
    experiment = {
        "status": "complete",
        "name": lane.campaign_name,
        "purpose": "smoke",
        "summary": {"planned": 1, "accepted": 1, "failed": 0, "passed": True},
        "source": {"image_digest": image, "lab_commit": commit, "lab_dirty": False},
        "configuration": {
            "campaign_sha256": campaign_sha,
            "profile": "research-1200",
            "request_policies": ["as-defined"],
            "defenses": [{"name": "undefended"}],
            "workloads": [{"id": "workload-0", "sha256": workload_sha, "visits": 1}],
        },
        "samples": [{"workload_id": "workload-0", "visit": 0, "defense": "undefended",
                     "request_policy": "as-defined", "state": "accepted"}],
    }
    (tmp_path / "evidence.sha256").write_text("sealed\n")
    monkeypatch.setattr(plan, "verify_result", lambda _: SimpleNamespace(experiment=experiment))
    expected = {
        "collection_image_digest": image,
        "lab_commit": commit,
        "campaign_sha256": campaign_sha,
        "workload_sha256s": {"workload-0": workload_sha},
    }
    verified = plan.verify_lane_result(tmp_path, lane, **expected)
    assert verified["accepted"] == 1
    assert verified["scientific_credit"] == "none-diagnostic"
    assert verified["result_seal_sha256"] == hashlib.sha256(b"sealed\n").hexdigest()

    for change in (
        lambda x: x.update(status="incomplete"),
        lambda x: x.update(name="rapid-curated-tranco50-v2-diagnostic-buflo-one-002"),
        lambda x: x["summary"].update(accepted=0),
        lambda x: x["samples"][0].update(state="failed"),
        lambda x: x["source"].update(image_digest="sha256:" + "e" * 64),
        lambda x: x["source"].update(lab_commit="e" * 40),
        lambda x: x["configuration"].update(defenses=[{"name": "front"}]),
        lambda x: x["samples"][0].update(visit=1),
    ):
        tampered = copy.deepcopy(experiment)
        change(tampered)
        monkeypatch.setattr(
            plan, "verify_result",
            lambda _, value=tampered: SimpleNamespace(experiment=value),
        )
        with pytest.raises(ValueError):
            plan.verify_lane_result(tmp_path, lane, **expected)

    front = replace(
        lane,
        mode="front",
        campaign_name=lane.campaign_name.replace("undefended", "front"),
        qualification_set="qualification-0",
    )
    front_experiment = copy.deepcopy(experiment)
    front_experiment["name"] = front.campaign_name
    front_experiment["configuration"].update({
        "defenses": [{"name": "front"}],
        "chaff_qualification_set": front.qualification_set,
        "chaff_qualification_set_manifest_sha256": "e" * 64,
    })
    front_experiment["samples"][0]["defense"] = "front"
    monkeypatch.setattr(
        plan, "verify_result",
        lambda _: SimpleNamespace(experiment=front_experiment),
    )
    qualification_binding = {"qualification_set_manifest_sha256": "e" * 64}
    assert plan.verify_lane_result(
        tmp_path, front, **expected, **qualification_binding
    )["accepted"] == 1
    front_experiment["configuration"]["chaff_qualification_set_manifest_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="qualification manifest"):
        plan.verify_lane_result(tmp_path, front, **expected, **qualification_binding)
    v5_front = replace(
        front,
        campaign_name=front.campaign_name.replace("-v4-", "-v5-"),
        study_version=5,
    )
    with pytest.raises(ValueError, match="needs a qualification manifest digest"):
        plan.verify_lane_result(tmp_path, v5_front, **expected)


@pytest.mark.parametrize("study_version,amended", [(4, False), (5, False), (5, True)])
def test_formal_manifest_reopens_all_lanes_and_rejects_tampering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, study_version: int, amended: bool
) -> None:
    def frozen_file(name: str, content: bytes) -> tuple[Path, str]:
        path = tmp_path / name
        path.write_bytes(content)
        return path, hashlib.sha256(content).hexdigest()

    profile_receipt = {
        "schema_version": study_version,
        "receipt_type": (
            plan.V5_PROFILE_RECEIPT_TYPE if study_version == 5
            else plan.PROFILE_RECEIPT_TYPE
        ),
        "payload": {},
    }
    profile, profile_sha = frozen_file(
        "profile.json", json.dumps(profile_receipt).encode()
    )
    if study_version == 5:
        monkeypatch.setattr(plan, "FROZEN_V5_PROFILE_SHA256", profile_sha)
    cohort_payload = {
        "payload": {
            "generation": "final-50",
            "terminal_decisions": [
                {
                    "candidate_id": f"candidate-{i}",
                    "terminal_receipt_sha256": f"{i + 1000:064x}",
                    "outcome": "admitted",
                }
                for i in range(50)
            ],
        }
    }
    cohort_payload.update({
        "schema_version": study_version,
        "receipt_type": (
            plan.V5_COHORT_RECEIPT_TYPE if study_version == 5
            else plan.COHORT_RECEIPT_TYPE
        ),
    })
    cohort_payload["payload"]["profile_receipt_sha256"] = profile_sha
    cohort, cohort_sha = frozen_file("cohort.json", json.dumps(cohort_payload).encode())
    _, base_launcher_sha = frozen_file("base-launcher", b"base\n")
    _, host_launcher_sha = frozen_file("host-launcher", b"overlay\n")
    curated, curated_sha = frozen_file("curated.json", b"curated\n")
    fallback, fallback_sha = frozen_file("fallback.json", b"fallback\n")
    monkeypatch.setattr(plan, "SOURCE_SHA256", curated_sha)
    monkeypatch.setattr(plan, "FALLBACK_CATALOGUE_SHA256", fallback_sha)
    monkeypatch.setattr(
        plan,
        "validate_v5_profile_receipt" if study_version == 5 else "validate_profile_receipt",
        lambda *_: (),
    )
    monkeypatch.setattr(
        plan,
        "validate_v5_cohort_receipt" if study_version == 5 else "validate_cohort_receipt",
        lambda *_, **__: tuple(f"candidate-{i}" for i in range(50)),
    )
    bindings = plan.FrozenBindings(
        profile, profile_sha, cohort, cohort_sha, study_version,
    )
    if amended:
        from datetime import datetime, timezone
        from qcsd_lab import rapid_selection_amendment as amendment

        class FrozenClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 10, 2, 14, tzinfo=timezone.utc)

        monkeypatch.setattr(amendment, "datetime", FrozenClock)
        monkeypatch.setattr(amendment.profile, "FROZEN_V5_PROFILE_SHA256", profile_sha)
        selection = amendment.build_selection_amendment(
            published_at_utc="2026-10-02T13:30:00Z", parent_profile_sha256=profile_sha,
        )
        selection_path, selection_sha = frozen_file(
            "selection-amendment.json", json.dumps(selection).encode(),
        )
        cohort_payload["receipt_type"] = amendment.AMENDED_COHORT_RECEIPT_TYPE
        cohort_payload["payload"]["selection_amendment_sha256"] = selection_sha
        cohort, cohort_sha = frozen_file("cohort.json", json.dumps(cohort_payload).encode())
        bindings = replace(
            bindings, cohort_sha256=cohort_sha,
            selection_amendment_receipt=selection_path,
            selection_amendment_sha256=selection_sha,
        )
        amended_calls = []

        def verified_amended_cohort(*args, **kwargs):
            amended_calls.append(kwargs["selection_amendment"])
            assert kwargs["selection_amendment"] == selection
            return tuple(f"candidate-{i}" for i in range(50))

        monkeypatch.setattr(amendment, "validate_amended_cohort_receipt", verified_amended_cohort)
    workload_root = tmp_path / "workloads"
    workload_root.mkdir()
    content = b'{"prepared":true}\n'
    workload_sha = hashlib.sha256(content).hexdigest()
    sites = tuple(
        replace(
            site,
            workload_sha256=workload_sha,
            qualification_set_manifest_sha256=f"{index // 5 + 1:064x}",
        )
        for index, site in enumerate(_sites(50))
    )
    for site in sites:
        (workload_root / f"{site.workload_id}.json").write_bytes(content)
    campaign_dir = tmp_path / "campaigns"
    campaign_dir.mkdir()
    # Durability is covered by util tests; avoid 800 fsyncs in this grid test.
    monkeypatch.setattr(plan, "durable_create", lambda path, value: path.write_bytes(value))
    campaign_hashes = plan.materialize_lane_campaigns(
        campaign_dir, sites, final=True, bindings=bindings,
        workload_root=workload_root,
    )
    assert len(campaign_hashes) == 800
    with pytest.raises(FileExistsError, match="already exists"):
        plan.materialize_lane_campaigns(
            campaign_dir, sites, final=True, bindings=bindings,
            workload_root=workload_root,
        )
    cohort.write_bytes(b"changed cohort\n")
    with pytest.raises(ValueError, match="cohort receipt bytes differ"):
        plan.materialize_lane_campaigns(
            campaign_dir, sites, final=True, bindings=bindings,
            workload_root=workload_root,
        )
    cohort.write_bytes(json.dumps(cohort_payload).encode())
    result_root = tmp_path / "results"
    result_root.mkdir()
    launch_root = tmp_path / "launches"
    launch_root.mkdir()
    lineage_root = tmp_path / "lineages"
    lineage_root.mkdir()
    (lineage_root / "base-v147.json").write_bytes(b"lineage\n")
    lineage_sha = hashlib.sha256(b"lineage\n").hexdigest()
    seal_sha = hashlib.sha256(b"seal\n").hexdigest()
    launch_sha = hashlib.sha256(b"launch\n").hexdigest()
    dns_sha = "c" * 64
    rows = []
    for lane in plan.plan_lanes(sites, final=True, study_version=study_version):
        (result_root / lane.campaign_name / "run-001").mkdir(parents=True)
        (launch_root / f"{lane.campaign_name}.json").write_bytes(b"launch\n")
        rows.append({
            "logical_lane": lane.logical_name,
            "generation": 1,
            "campaign_name": lane.campaign_name,
            "campaign_sha256": campaign_hashes[lane.campaign_name],
            "execution_generation": "base-v147",
            "collection_image_digest": "sha256:" + "a" * 64,
            "lab_commit": "b" * 40,
            "base_launcher_sha256": base_launcher_sha,
            "host_launcher_sha256": host_launcher_sha,
            "lineage_receipt_relpath": "base-v147.json",
            "lineage_receipt_sha256": lineage_sha,
            "result_relpath": f"{lane.campaign_name}/run-001",
            "result_seal_sha256": seal_sha,
            "launch_receipt_relpath": f"{lane.campaign_name}.json",
            "launch_receipt_sha256": launch_sha,
            "dns_pin_receipt_sha256": dns_sha,
        })
    manifest = {
        "schema_version": 1,
        "artifact_type": (
            plan.V5_CORPUS_TYPE if study_version == 5 else plan.CORPUS_TYPE
        ),
        "bindings": bindings.digests(),
        "lanes": rows,
    }
    sites_by_terminal = {
        f"{i + 1000:064x}": site for i, site in enumerate(sites)
    }
    rows_by_name = {row["campaign_name"]: row for row in rows}
    calls: list[str] = []

    def verified_lane(path: Path, lane: plan.Lane, **_: object) -> dict[str, object]:
        calls.append(lane.campaign_name)
        assert _["qualification_set_manifest_sha256"] == (
            None if lane.mode == "undefended"
            else sites[(lane.shard - 1) * 5].qualification_set_manifest_sha256
        )
        if lane.generation == 2:
            assert _["collection_image_digest"] == "sha256:" + "d" * 64
            assert _["lab_commit"] == "e" * 40
        return {
            "accepted": lane.sample_count,
            "result_seal_sha256": seal_sha,
        }

    def verified_launch(path: Path) -> dict[str, str]:
        name = path.stem
        row = rows_by_name[name]
        return {
            "campaign_name": name,
            "campaign_sha256": row["campaign_sha256"],
            "profile_receipt_sha256": profile_sha,
            "cohort_receipt_sha256": cohort_sha,
            "execution_generation": row["execution_generation"],
            "lineage_receipt_sha256": row["lineage_receipt_sha256"],
            "base_launcher_sha256": row["base_launcher_sha256"],
            "host_launcher_sha256": row["host_launcher_sha256"],
            "collection_image_digest": row["collection_image_digest"],
            "lab_commit": row["lab_commit"],
            "result_root": str((result_root / row["result_relpath"]).resolve()),
            "result_seal_sha256": seal_sha,
            "dns_pin_receipt_sha256": dns_sha,
        }

    def verified_lineage(path: Path) -> dict[str, object]:
        row = next(
            row for row in rows_by_name.values()
            if row["lineage_receipt_relpath"] == path.name
        )
        generation = row["generation"]
        predecessor_name = (
            None if generation == 1 else row["logical_lane"]
            if generation == 2 else f"{row['logical_lane']}-g{generation - 1:02d}"
        )
        return {
            "execution_generation": row["execution_generation"],
            "profile_receipt_sha256": profile_sha,
            "cohort_receipt_sha256": cohort_sha,
            **({"selection_amendment_sha256": selection_sha} if amended else {}),
            "research_profile_sha256": plan.RESEARCH_PROFILE_SHA256,
            "buflo_parameters_sha256": plan.BUFLO_PARAMETERS_SHA256,
            "cs_buflo_parameters_sha256": plan.CS_BUFLO_PARAMETERS_SHA256,
            "collection_image_digest": row["collection_image_digest"],
            "lab_commit": row["lab_commit"],
            "base_launcher_sha256": row["base_launcher_sha256"],
            "host_launcher_sha256": row["host_launcher_sha256"],
            "equivalent_to_cohort": True,
            "predecessor_campaign_name": predecessor_name,
            "predecessor_campaign_sha256": (
                None if predecessor_name is None
                else campaign_hashes.get(predecessor_name, "0" * 64)
            ),
        }

    monkeypatch.setattr(plan, "verify_lane_result", verified_lane)
    kwargs = {
        "bindings": bindings,
        "curated_source": curated,
        "fallback_catalogue": fallback,
        "execution_binding": {},
        "deep_verify_terminal": lambda _: {},
        "verify_site_workload": sites_by_terminal.__getitem__,
        "campaign_dir": campaign_dir,
        "workload_root": workload_root,
        "result_root": result_root,
        "launch_receipt_root": launch_root,
        "lineage_receipt_root": lineage_root,
        "verify_launch_receipt": verified_launch,
        "verify_execution_lineage": verified_lineage,
    }
    verified = plan.verify_formal_manifest(manifest, sites, **kwargs)
    assert verified["valid"] and verified["lanes"] == 800
    assert verified["accepted"] == 16_000 and len(calls) == 800
    if amended:
        assert amended_calls == [selection]
        without_amendment = copy.deepcopy(manifest)
        without_amendment["bindings"].pop("selection_amendment_sha256")
        with pytest.raises(ValueError, match="another frozen source binding"):
            plan.verify_formal_manifest(without_amendment, sites, **kwargs)
        with pytest.raises(ValueError, match="not cohort-equivalent"):
            plan.verify_formal_manifest(
                manifest, sites,
                **{**kwargs, "verify_execution_lineage": lambda path: {
                    key: value for key, value in verified_lineage(path).items()
                    if key != "selection_amendment_sha256"
                }},
            )
    if study_version == 5:
        historical_type = copy.deepcopy(manifest)
        historical_type["artifact_type"] = plan.CORPUS_TYPE
        with pytest.raises(ValueError, match="manifest schema"):
            plan.verify_formal_manifest(historical_type, sites, **kwargs)
        historical_lane = copy.deepcopy(manifest)
        historical_lane["lanes"][0]["campaign_name"] = (
            historical_lane["lanes"][0]["campaign_name"].replace("-v5-", "-v4-")
        )
        with pytest.raises(ValueError, match="misnamed"):
            plan.verify_formal_manifest(historical_lane, sites, **kwargs)
        without_qualification = tuple(
            replace(site, qualification_set_manifest_sha256=None) for site in sites
        )
        with pytest.raises(ValueError, match="qualification manifest digests"):
            plan.verify_formal_manifest(manifest, without_qualification, **kwargs)
        original_profile_bytes = profile.read_bytes()
        v4_profile_bytes = json.dumps({
            **profile_receipt,
            "receipt_type": "qcsd-curated-tranco-rapid-profile-v4",
        }).encode()
        profile.write_bytes(v4_profile_bytes)
        wrong_profile = replace(
            bindings, profile_sha256=hashlib.sha256(v4_profile_bytes).hexdigest()
        )
        with pytest.raises(ValueError, match="frozen receipt"):
            plan.verify_formal_manifest(
                manifest, sites, **{**kwargs, "bindings": wrong_profile}
            )
        monkeypatch.setattr(
            plan, "FROZEN_V5_PROFILE_SHA256", wrong_profile.profile_sha256
        )
        with pytest.raises(ValueError, match=(
            "selection amendment parent" if amended else "identities differ"
        )):
            plan.verify_formal_manifest(
                manifest, sites, **{**kwargs, "bindings": wrong_profile}
            )
        monkeypatch.setattr(plan, "FROZEN_V5_PROFILE_SHA256", profile_sha)
        profile.write_bytes(original_profile_bytes)
        original_cohort_bytes = cohort.read_bytes()
        v4_cohort_bytes = json.dumps({
            **cohort_payload,
            "receipt_type": "qcsd-curated-tranco-rapid-cohort-selection-v4",
        }).encode()
        cohort.write_bytes(v4_cohort_bytes)
        wrong_cohort = replace(
            bindings, cohort_sha256=hashlib.sha256(v4_cohort_bytes).hexdigest()
        )
        with pytest.raises(ValueError, match="identities differ"):
            plan.verify_formal_manifest(
                manifest, sites, **{**kwargs, "bindings": wrong_cohort}
            )
        cohort.write_bytes(original_cohort_bytes)
    else:
        original_profile_bytes = profile.read_bytes()
        v5_profile_bytes = json.dumps({
            **profile_receipt,
            "schema_version": 5,
            "receipt_type": plan.V5_PROFILE_RECEIPT_TYPE,
        }).encode()
        profile.write_bytes(v5_profile_bytes)
        wrong_profile = replace(
            bindings, profile_sha256=hashlib.sha256(v5_profile_bytes).hexdigest()
        )
        with pytest.raises(ValueError, match="identities differ"):
            plan.verify_formal_manifest(
                manifest, sites, **{**kwargs, "bindings": wrong_profile}
            )
        profile.write_bytes(original_profile_bytes)

    first_lane = plan.plan_lanes(sites, final=True, study_version=study_version)[0]
    repaired_lane = plan.successor_lane(first_lane, 2)
    repaired_campaign_sha = plan.materialize_successor_campaign(
        campaign_dir, sites, repaired_lane, bindings=bindings,
        workload_root=workload_root,
    )
    campaign_hashes[repaired_lane.campaign_name] = repaired_campaign_sha
    with pytest.raises(FileExistsError, match="already exists"):
        plan.materialize_successor_campaign(
            campaign_dir, sites, repaired_lane, bindings=bindings,
            workload_root=workload_root,
        )
    (result_root / repaired_lane.campaign_name / "run-001").mkdir(parents=True)
    (launch_root / f"{repaired_lane.campaign_name}.json").write_bytes(b"launch\n")
    (lineage_root / "repair-v148.json").write_bytes(b"repaired lineage\n")
    repaired_row = {
        **rows[0],
        "generation": 2,
        "campaign_name": repaired_lane.campaign_name,
        "campaign_sha256": repaired_campaign_sha,
        "execution_generation": "repair-v148",
        "collection_image_digest": "sha256:" + "d" * 64,
        "lab_commit": "e" * 40,
        "host_launcher_sha256": "f" * 64,
        "lineage_receipt_relpath": "repair-v148.json",
        "lineage_receipt_sha256": hashlib.sha256(b"repaired lineage\n").hexdigest(),
        "result_relpath": f"{repaired_lane.campaign_name}/run-001",
        "launch_receipt_relpath": f"{repaired_lane.campaign_name}.json",
    }
    rows_by_name[repaired_lane.campaign_name] = repaired_row
    mixed_manifest = copy.deepcopy(manifest)
    mixed_manifest["lanes"][0] = repaired_row
    mixed_verified = plan.verify_formal_manifest(mixed_manifest, sites, **kwargs)
    assert mixed_verified["accepted"] == 16_000
    assert repaired_lane.campaign_name in calls
    with pytest.raises(ValueError, match="not cohort-equivalent"):
        plan.verify_formal_manifest(
            mixed_manifest, sites,
            **{
                **kwargs,
                "verify_execution_lineage": lambda path: {
                    **verified_lineage(path),
                    "predecessor_campaign_name": None,
                },
            },
        )

    second_lane = plan.plan_lanes(sites, final=True, study_version=study_version)[1]
    skipped_generation = plan.successor_lane(second_lane, 3)
    with pytest.raises(ValueError, match="predecessor campaign is not a regular file"):
        plan.materialize_successor_campaign(
            campaign_dir, sites, skipped_generation, bindings=bindings,
            workload_root=workload_root,
        )
    skipped_bytes = plan.render_lane_campaign(skipped_generation, sites)
    skipped_campaign_sha = hashlib.sha256(skipped_bytes).hexdigest()
    (campaign_dir / f"{skipped_generation.campaign_name}.yml").write_bytes(skipped_bytes)
    (result_root / skipped_generation.campaign_name / "run-001").mkdir(parents=True)
    (launch_root / f"{skipped_generation.campaign_name}.json").write_bytes(b"launch\n")
    (lineage_root / "skip-v149.json").write_bytes(b"skip lineage\n")
    skipped_row = {
        **rows[1],
        "generation": 3,
        "campaign_name": skipped_generation.campaign_name,
        "campaign_sha256": skipped_campaign_sha,
        "lineage_receipt_relpath": "skip-v149.json",
        "lineage_receipt_sha256": hashlib.sha256(b"skip lineage\n").hexdigest(),
        "result_relpath": f"{skipped_generation.campaign_name}/run-001",
        "launch_receipt_relpath": f"{skipped_generation.campaign_name}.json",
    }
    rows_by_name[skipped_generation.campaign_name] = skipped_row
    skipped_manifest = copy.deepcopy(manifest)
    skipped_manifest["lanes"][1] = skipped_row
    with pytest.raises(ValueError, match="predecessor campaign is not a regular file"):
        plan.verify_formal_manifest(skipped_manifest, sites, **kwargs)

    missing = copy.deepcopy(manifest)
    missing["lanes"].pop()
    with pytest.raises(ValueError, match="missing lane"):
        plan.verify_formal_manifest(missing, sites, **kwargs)
    duplicate = copy.deepcopy(manifest)
    duplicate["lanes"][1] = duplicate["lanes"][0]
    with pytest.raises(ValueError, match="repeats"):
        plan.verify_formal_manifest(duplicate, sites, **kwargs)
    altered = copy.deepcopy(manifest)
    altered["lanes"][0]["result_seal_sha256"] = "d" * 64
    with pytest.raises(ValueError, match="seal differs"):
        plan.verify_formal_manifest(altered, sites, **kwargs)
    with pytest.raises(ValueError, match="launch receipt differs"):
        plan.verify_formal_manifest(
            manifest, sites,
            **{
                **kwargs,
                "verify_launch_receipt": lambda path: {
                    **verified_launch(path), "host_launcher_sha256": "d" * 64
                },
            },
        )
    with pytest.raises(ValueError, match="not cohort-equivalent"):
        plan.verify_formal_manifest(
            manifest, sites,
            **{
                **kwargs,
                "verify_execution_lineage": lambda path: {
                    **verified_lineage(path), "equivalent_to_cohort": False
                },
            },
        )
    with pytest.raises(ValueError, match="workload differs"):
        plan.verify_formal_manifest(
            manifest, sites,
            **{
                **kwargs,
                "verify_site_workload": lambda _: sites[1],
            },
        )
    (campaign_dir / f"{rows[0]['campaign_name']}.yml").write_text("tampered\n")
    with pytest.raises(ValueError, match="bytes differ"):
        plan.verify_formal_manifest(manifest, sites, **kwargs)
