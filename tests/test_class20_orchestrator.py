"""Admission tests for the prospective 20-site campaign matrix."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import orchestrator
from qcsd_lab import util
from qcsd_lab import class_cohort20
from qcsd_lab.capture_session import Limits
from qcsd_lab.class_campaigns import CAPTURE_LIMITS, ORIGIN_AWARE_WINDOW
from qcsd_lab.class_layout import class_study_layout
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    CLASS20_STUDY_ID,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    load_class20_profile_contract,
)


_STAGE_SUFFIX = {
    "pilot-fitting": "pilot-fitting-120-1200",
    "pilot-compatibility": "pilot-compatibility-270-1200",
    "authoritative-fitting": "authoritative-fitting-400-1200",
    "certification": "certification-180-1200",
}
_KINDS = {
    "undefended": "none",
    "static": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}


def _campaign(role: str, *, block: int = 1) -> orchestrator.Campaign:
    profile = load_class20_profile_contract()
    layout = class_study_layout(profile=profile)
    suffix = (
        f"{role}-{block:02d}-1200"
        if role in {"canary", "formal"}
        else _STAGE_SUFFIX[role]
    )
    name = f"{CLASS20_STUDY_ID}-{suffix}"
    pilot = role.startswith("pilot-")
    count = profile.pilot_count if pilot else profile.final_count
    visits = {
        "pilot-fitting": 2,
        "pilot-compatibility": 1,
        "authoritative-fitting": 10,
        "certification": 1,
        "canary": 1,
        "formal": profile.formal_visits_per_block,
    }[role]
    modes = (
        ("undefended",)
        if role in {"pilot-fitting", "authoritative-fitting", "canary"}
        else FORMAL_MODES if role == "formal" else COMPATIBILITY_MODES
    )
    qualification_set = {
        "pilot-compatibility": layout.pilot_qualification_set_root.name,
        "certification": layout.final_qualification_set_root.name,
        "formal": layout.final_qualification_set_root.name,
    }.get(role)
    return orchestrator.Campaign(
        path=Path(f"/synthetic/{name}.yml"),
        source_bytes=b"synthetic",
        name=name,
        purpose=(
            "fitting" if role.endswith("fitting")
            else "evaluation" if role == "formal" else "smoke"
        ),
        seed=int.from_bytes(
            hashlib.sha256(f"{CLASS20_STUDY_ID}\0{name}".encode()).digest()[:4],
            "big",
        ),
        profile="research-1200",
        workloads=tuple(
            SimpleNamespace(
                id=f"site-{index:02d}",
                visits=visits,
                path=Path(f"/synthetic/site-{index:02d}.json"),
                sha256=f"{index:064x}",
            )
            for index in range(count)
        ),
        request_policies=(
            ("as-defined", "half-duplex")
            if role.endswith("fitting") else ("as-defined",)
        ),
        defenses=tuple(
            SimpleNamespace(name=mode, kind=_KINDS[mode], baseline=mode == "undefended")
            for mode in modes
        ),
        limits=Limits(**{**CAPTURE_LIMITS, "max_attempts": 1 if role == "certification" else 3}),
        chaff_qualification_set=qualification_set,
        defense_order_scheme=(
            "seeded-shuffle" if role.endswith("fitting") else "cyclic-latin-square"
        ),
        defense_order_block=(
            None if role.endswith("fitting")
            else block - 1 if role in {"canary", "formal"} else 0
        ),
        schema_version=2,
        evidence_role=role,
        sample_order_scheme="origin-aware-windowed",
        sample_order_window=ORIGIN_AWARE_WINDOW,
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
        class_study_id=CLASS20_STUDY_ID,
        class_study_launch_namespace=f".{CLASS20_STUDY_ID}-launches",
    )


@pytest.mark.parametrize(
    "role", (
        "pilot-fitting", "authoritative-fitting",
        "certification", "canary", "formal",
    )
)
def test_profile20_admits_only_its_registered_campaign_matrix(role: str) -> None:
    campaign = _campaign(role)
    orchestrator._validate_class_study_campaign_contract(campaign)
    assert orchestrator._is_class_study_campaign(campaign)
    if role.endswith("fitting"):
        orchestrator._validate_fitting_campaign(
            campaign, raw_limits=CAPTURE_LIMITS,
        )


def test_profile20_rejects_forged_pilot_compatibility_campaign() -> None:
    campaign = _campaign("pilot-compatibility")
    with pytest.raises(ValueError, match="separate deep receipt"):
        orchestrator._validate_class_study_campaign_contract(campaign)


def test_profile20_rejects_100_site_dimensions_and_identity() -> None:
    campaign = _campaign("formal")
    with pytest.raises(ValueError, match="requires 20 workloads"):
        orchestrator._validate_class_study_campaign_contract(
            replace(campaign, workloads=campaign.workloads * 5)
        )
    with pytest.raises(ValueError, match="10 visit"):
        orchestrator._validate_class_study_campaign_contract(
            replace(campaign, workloads=tuple(SimpleNamespace(visits=2) for _ in range(20)))
        )
    with pytest.raises(ValueError, match="not canonical"):
        orchestrator._validate_class_study_campaign_contract(
            replace(campaign, class_study_id="classifier-multiorigin100-v1")
        )
    with pytest.raises(ValueError, match="100-site successor"):
        orchestrator._validate_class_study_campaign_contract(
            replace(campaign, class_study_successor_sha256="c" * 64)
        )


def test_profile20_rejects_wrong_qualification_and_block() -> None:
    campaign = _campaign("formal", block=10)
    with pytest.raises(ValueError, match="qualification-set identity"):
        orchestrator._validate_class_study_campaign_contract(
            replace(
                campaign,
                chaff_qualification_set="classifier-multiorigin100-v1-final100-full-v1",
            )
        )
    with pytest.raises(ValueError, match="defense-order block"):
        orchestrator._validate_class_study_campaign_contract(
            replace(campaign, defense_order_block=0)
        )


def test_profile20_and_100_site_fresh_paths_cannot_be_exchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    other_names = (
        (
            "classifier-multiorigin100-v1-campaigns",
            f"{CLASS20_STUDY_ID}-pilot-fitting-120-1200",
        ),
        (
            f"{CLASS20_STUDY_ID}-campaigns",
            "classifier-multiorigin100-v1-pilot-fitting-1200",
        ),
    )
    for directory, name in other_names:
        campaign_root = tmp_path / "config" / directory
        campaign_root.mkdir(parents=True)
        path = campaign_root / f"{name}.yml"
        path.write_text(json.dumps({"schema": 2, "name": name}), encoding="utf-8")
        with pytest.raises(ValueError, match="canonical class-study layout"):
            orchestrator.load_campaign(path)


def test_profile20_cannot_claim_schema_one_or_successor_restart(tmp_path: Path) -> None:
    name = f"{CLASS20_STUDY_ID}-pilot-fitting-120-1200"
    path = tmp_path / f"{name}.yml"
    path.write_text(json.dumps({"schema": 1, "name": name}), encoding="utf-8")
    with pytest.raises(ValueError, match="require schema two"):
        orchestrator.load_campaign(path)
    path.write_text(
        json.dumps({"schema": 2, "name": name, "class_study_successor": "restart.json"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="100-site successor"):
        orchestrator.load_campaign(path)


def test_profile20_cohort_binding_requires_order_and_prepared_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = load_class20_profile_contract()
    config_root = tmp_path / "config"
    campaign_root = config_root / f"{profile.study_id}-campaigns"
    study_root = config_root / "class-study/v2"
    campaign_root.mkdir(parents=True)
    study_root.mkdir(parents=True)
    cohort = study_root / f"{profile.study_id}-pilot-cohort.json"
    assembly = study_root / f"{profile.study_id}-pilot-cohort-assembly.json"
    cohort.write_text("{}\n", encoding="utf-8")
    ids = tuple(f"site-{index:02d}" for index in range(profile.pilot_count))
    hashes = {candidate_id: f"{index:064x}" for index, candidate_id in enumerate(ids)}
    assembly.write_text(
        json.dumps({
            "payload": {
                "candidates": [
                    {
                        "candidate_id": candidate_id,
                        "prepared_workload": {"sha256": hashes[candidate_id]},
                    }
                    for candidate_id in ids
                ]
            }
        }),
        encoding="utf-8",
    )
    observed_modes: list[bool] = []

    def verified_cohort(_cohort: Path, _assembly: Path, *, profile, require_deep: bool):
        assert _cohort == cohort and _assembly == assembly
        assert profile == load_class20_profile_contract()
        observed_modes.append(require_deep)
        return ids, ()

    monkeypatch.setattr(class_cohort20, "load_validated_profile_cohort", verified_cohort)
    kwargs = dict(
        schema_version=2,
        evidence_role="pilot-fitting",
        raw_path=f"../class-study/v2/{cohort.name}",
        raw_assembly_path=f"../class-study/v2/{assembly.name}",
        campaign_path=campaign_root / f"{profile.study_id}-pilot-fitting-120-1200.yml",
        config_root=config_root,
        frozen_inputs=None,
        workload_ids=ids,
        workload_hashes=hashes,
        profile=profile,
    )
    paths = orchestrator._load_class_study_cohort_binding(**kwargs)
    assert paths[0] == cohort and paths[2] == assembly
    assert observed_modes == [True]
    with pytest.raises(ValueError, match="workload order"):
        orchestrator._load_class_study_cohort_binding(
            **{**kwargs, "workload_ids": tuple(reversed(ids))}
        )
    with pytest.raises(ValueError, match="prepared workload bytes"):
        orchestrator._load_class_study_cohort_binding(
            **{**kwargs, "workload_hashes": {**hashes, ids[0]: "f" * 64}}
        )


def test_profile20_changed_campaign_fails_before_launch_claim(tmp_path: Path) -> None:
    campaign = _campaign("pilot-fitting")
    path = tmp_path / "campaign.yml"
    path.write_bytes(b"changed after load")
    with pytest.raises(ValueError, match="20-site campaign changed"):
        orchestrator._validate_class_study_preclaim_authority(
            replace(campaign, path=path),
            source={},
            started_at=datetime.now(timezone.utc),
        )


def test_profile20_preflight_reports_registered_overlay_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign("pilot-fitting")
    campaign = replace(
        campaign,
        workloads=tuple(
            SimpleNamespace(**vars(workload), resource_count=3, origin_count=2)
            for workload in campaign.workloads
        ),
        defenses=(orchestrator.capture_engine.Defense(
            name="undefended", kind="none", baseline=True
        ),),
    )
    monkeypatch.setattr(orchestrator, "load_campaign", lambda _path: campaign)
    monkeypatch.setattr(orchestrator, "plan_campaign", lambda _campaign: [])
    monkeypatch.setattr(
        orchestrator, "_validate_fitting_capture_source", lambda _source: None
    )
    result = orchestrator.preflight_campaign(campaign.path)
    assert result["class_study_id"] == CLASS20_STUDY_ID
    assert result["class_study_profile_sha256"] == util.sha256_file(
        Path(orchestrator.__file__).resolve().parents[2]
        / "config/class-study/v2/study.json"
    )


def test_profile20_frozen_configuration_binds_overlay_and_rejects_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qcsd_lab import buflo_study, class_attestation

    inputs = tmp_path / "inputs"
    inputs.mkdir()
    campaign_path = inputs / "campaign.yml"
    campaign_path.write_bytes(b"synthetic")
    (inputs / "source.json").write_text(
        json.dumps({"image_digest": "sha256:" + "a" * 64}), encoding="utf-8"
    )
    (inputs / "study-environment.json").write_text("{}\n", encoding="utf-8")
    campaign = replace(
        _campaign("pilot-fitting"), path=campaign_path, workloads=(), defenses=()
    )
    monkeypatch.setattr(
        orchestrator, "_validate_frozen_class_study_authority", lambda *_args: {}
    )
    monkeypatch.setattr(
        buflo_study, "validate_study_environment_receipt", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        class_attestation,
        "validate_class_foundation_attestation",
        lambda *_args, **_kwargs: {"build_execution_identity": None},
    )
    configuration = orchestrator._frozen_configuration(tmp_path, campaign)
    assert configuration["class_study_profile_sha256"] == (
        orchestrator._registered_class20_profile_sha256()
    )
    monkeypatch.setattr(
        orchestrator, "_campaign_from_frozen_inputs", lambda *_args, **_kwargs: campaign
    )
    altered = {**configuration, "class_study_profile_sha256": "0" * 64}
    with pytest.raises(ValueError, match="configuration does not match"):
        orchestrator.validate_frozen_experiment_contract(
            tmp_path,
            {"name": campaign.name, "purpose": campaign.purpose, "configuration": altered},
        )


def test_profile20_coordinator_rejects_mixed_frozen_configuration() -> None:
    campaign = _campaign("formal")
    configuration = {
        "name": campaign.name,
        "evidence_role": campaign.evidence_role,
        "class_study_id": campaign.class_study_id,
        "campaign_sha256": "a" * 64,
        "class_study_cohort_sha256": campaign.class_study_cohort_sha256,
        "class_study_cohort_assembly_sha256": campaign.class_study_cohort_assembly_sha256,
        "class_study_profile_sha256": "0" * 64,
    }
    with pytest.raises(ValueError, match="another study profile"):
        orchestrator._class_study_coordinator_campaign_identity(configuration)
    configuration["class_study_profile_sha256"] = (
        orchestrator._registered_class20_profile_sha256()
    )
    assert orchestrator._class_study_coordinator_campaign_identity(configuration) is not None


@pytest.mark.parametrize("frozen", (False, True))
def test_profile20_defense_loader_threads_trusted_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen: bool
) -> None:
    import qcsd_lab.parameters as parameters

    base = tmp_path / "campaigns"
    bundle = (
        tmp_path / "inputs/defense-parameters/class-study"
        if frozen else base / "bundle"
    )
    bundle.mkdir(parents=True)
    parameter = bundle / "traffic-morphing.json"
    provenance = bundle / "provenance.json"
    parameter.write_text("{}\n", encoding="utf-8")
    provenance.write_text(
        json.dumps({"artifact_type": "qcsd-class-study-research-defense-bundle"}),
        encoding="utf-8",
    )
    observed: list[object] = []

    def admitted(path: Path, **kwargs: object) -> parameters.ParameterArtifact:
        observed.append(kwargs.get("expected_study_profile"))
        return parameters.ParameterArtifact(
            path=path,
            sha256=util.sha256_file(path),
            provenance_path=provenance,
            provenance_sha256=util.sha256_file(provenance),
            input_policy="sealed-class-study-pilot-fitting-v1",
        )

    monkeypatch.setattr(
        orchestrator,
        "validate_frozen_parameter_artifact" if frozen else "validate_parameter_artifact",
        admitted,
    )
    defenses = orchestrator._load_defenses(
        base,
        [
            "undefended",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": "bundle/traffic-morphing.json",
            },
        ],
        "smoke",
        "research-1200",
        {"site-00": "a" * 64},
        frozen_inputs=tmp_path / "inputs" if frozen else None,
        expected_study_profile=CLASS20_PROFILE,
    )
    assert len(defenses) == 2
    assert observed == [CLASS20_PROFILE]
