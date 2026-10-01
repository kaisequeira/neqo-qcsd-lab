"""Cheap v2 coordinator and host launch routing checks; no live capture."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_build_admission as host
from qcsd_lab import class_capture20, class_pipeline as pipeline
from qcsd_lab import class_attestation
from qcsd_lab.class_study import load_class20_profile_contract
from qcsd_lab.util import sha256_file


def _setup_profile_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict, dict]:
    profile = load_class20_profile_contract()
    (tmp_path / "study.json").write_text("{}", encoding="utf-8")
    campaign = tmp_path / f"{profile.study_id}-canary-01-1200.yml"
    campaign.write_text("name: synthetic\n", encoding="utf-8")
    layout = SimpleNamespace(
        study_config_root=tmp_path,
        campaign_root=tmp_path,
        results_root=tmp_path / "results",
    )
    monkeypatch.setattr(pipeline, "class_study_layout", lambda **_kwargs: layout)
    proof = {
        "valid": True,
        "campaign_name": campaign.stem,
        "campaign_sha256": sha256_file(campaign),
        "evidence_role": "canary",
        "block": 1,
        "planned_samples": 20,
        "cohort_sha256": "a" * 64,
        "cohort_assembly_sha256": "b" * 64,
        "foundation_sha256": "c" * 64,
        "readiness_sha256": "d" * 64,
        "historical_pre_snapshot_sha256": "e" * 64,
        "historical_pre_recorded_at": "2020-01-01T00:00:00+00:00",
        "source": {"pinned": True},
        "expected_defense_runtime_inputs": {"undefended": {"runtime_kind": "none"}},
        "prerequisite_ledger": (
            {
                "name": f"{profile.study_id}-authoritative-fitting-400-1200",
                "evidence_role": "authoritative-fitting", "block": None,
                "root": "/lab/results/fitting", "evidence_sha256": "f" * 64,
            },
            {
                "name": f"{profile.study_id}-certification-180-1200",
                "evidence_role": "certification", "block": None,
                "root": "/lab/results/certification", "evidence_sha256": "0" * 64,
            },
        ),
        "required_environment": {
            "QCSD_CLASS_FOUNDATION_ATTESTATION": str(tmp_path / "foundation.json"),
            "QCSD_CLASS_READINESS_ATTESTATION": str(tmp_path / "readiness.json"),
            "QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT": str(tmp_path / "pre.json"),
        },
    }
    preflight = {
        "name": campaign.stem,
        "evidence_role": "canary",
        "class_study_id": profile.study_id,
        "class_study_profile_sha256": sha256_file(tmp_path / "study.json"),
        "class_study_cohort_sha256": proof["cohort_sha256"],
        "class_study_cohort_assembly_sha256": proof["cohort_assembly_sha256"],
        "sample_count": 20,
        "defense_runtime_inputs": proof["expected_defense_runtime_inputs"],
    }
    monkeypatch.setattr(
        class_capture20, "verify_profile_capture_prerequisites", lambda **_kwargs: proof
    )
    monkeypatch.setattr(pipeline, "preflight_campaign", lambda _path: preflight)
    return campaign, proof, preflight


def _capture_kwargs(campaign: Path) -> dict:
    return {
        "profile": load_class20_profile_contract(),
        "campaign": campaign,
        "results_root": None,
        "capture_result": None,
        "prerequisite_roots": (Path("fitting"), Path("certification")),
        "pilot_cohort_receipt": None,
        "pilot_cohort_assembly": None,
        "final_cohort_receipt": Path("cohort.json"),
        "final_cohort_assembly": Path("assembly.json"),
        "foundation_attestation": Path("foundation.json"),
        "readiness_attestation": Path("readiness.json"),
        "historical_pre_snapshot": Path("pre.json"),
        "numeric_bundle_root": None,
        "final_bundle_root": None,
        "qualification_workload_root": None,
        "qualification_sidecar_root": None,
        "qualification_prefix_root": None,
        "execute": False,
    }


def test_v2_capture_ready_requires_deep_verifier_and_matching_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, proof, preflight = _setup_profile_capture(tmp_path, monkeypatch)
    result = pipeline._coordinate_profile_capture("capture", **_capture_kwargs(campaign))
    assert result.status == "ready"
    assert result.details["capture_prerequisites"] is proof
    preflight["sample_count"] = 100
    with pytest.raises(ValueError, match="preflight differs"):
        pipeline._coordinate_profile_capture("capture", **_capture_kwargs(campaign))


def test_v2_capture_execute_passes_exact_ledger_and_verifies_sealed_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, proof, _preflight = _setup_profile_capture(tmp_path, monkeypatch)
    output = tmp_path / "result"
    calls = []

    @contextmanager
    def authority(configuration: dict, ledger: tuple, *_args: object):
        calls.append((configuration, ledger))
        yield

    monkeypatch.setattr(pipeline, "_class_study_coordinator_capture_authority", authority)
    monkeypatch.setattr(pipeline, "require_canonical_fresh_path", lambda path, **_kwargs: path)
    monkeypatch.setattr(pipeline, "run_campaign", lambda *_args: output)
    from qcsd_lab import class_profile_result

    monkeypatch.setattr(
        class_profile_result, "verify_profile_class_result",
        lambda root, **_kwargs: {
            "valid": True, "root": str(root), "samples": 20, "accepted": 20,
        },
    )
    kwargs = _capture_kwargs(campaign)
    kwargs.update(execute=True, results_root=tmp_path / "results")
    result = pipeline._coordinate_profile_capture("capture", **kwargs)
    assert result.status == "complete"
    assert calls[0][1] == proof["prerequisite_ledger"]
    assert calls[0][0]["campaign_sha256"] == proof["campaign_sha256"]


def test_v2_resume_rejects_changed_frozen_readiness_before_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, proof, _preflight = _setup_profile_capture(tmp_path, monkeypatch)
    result_root = tmp_path / "results" / "partial"
    (result_root / "inputs").mkdir(parents=True)
    (result_root / "inputs/campaign.yml").write_bytes(campaign.read_bytes())
    configuration = {
        "campaign_sha256": proof["campaign_sha256"],
        "class_study_id": load_class20_profile_contract().study_id,
        "class_study_profile_sha256": sha256_file(tmp_path / "study.json"),
        "evidence_role": "canary",
        "class_study_cohort_sha256": proof["cohort_sha256"],
        "class_study_cohort_assembly_sha256": proof["cohort_assembly_sha256"],
        pipeline.CLASS_STUDY_FOUNDATION_CONFIGURATION_KEY: proof["foundation_sha256"],
        pipeline.CLASS_STUDY_READINESS_CONFIGURATION_KEY: "0" * 64,
        pipeline.CLASS_STUDY_HISTORICAL_PRE_CONFIGURATION_KEY: proof["historical_pre_snapshot_sha256"],
    }
    (result_root / "experiment.json").write_text(json.dumps({
        "name": campaign.stem, "configuration": configuration,
        "source": proof["source"], "started_at": "2020-01-02T00:00:00+00:00",
    }), encoding="utf-8")
    monkeypatch.setattr(pipeline, "resume_campaign", lambda *_args: pytest.fail("resume called"))
    kwargs = _capture_kwargs(campaign)
    kwargs.update(campaign=None, capture_result=result_root)
    with pytest.raises(ValueError, match="frozen profile capture authority"):
        pipeline._coordinate_profile_capture("resume", **kwargs)


@pytest.mark.parametrize("phase", ["pre-formal", "post-formal"])
def test_v2_historical_snapshot_route_uses_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    from qcsd_lab import class_attestation

    output = pipeline.class_study_layout(profile=load_class20_profile_contract()).artifacts_root / "snapshot-test.json"
    calls = []
    monkeypatch.setattr(
        class_attestation, "create_class_historical_snapshot",
        lambda path, **kwargs: calls.append((path, kwargs)) or path,
    )
    monkeypatch.setattr(
        class_attestation, "validate_class_historical_snapshot",
        lambda _path, **kwargs: {"phase": kwargs["expected_phase"]},
    )
    result = pipeline.run_class_study_action(
        "historical-snapshot", study_id=load_class20_profile_contract().study_id,
        snapshot_phase=phase, destination=output,
        readiness_attestation=tmp_path / "readiness.json",
        historical_pre_snapshot=(tmp_path / "pre.json") if phase == "post-formal" else None,
        formal_result_roots=(tmp_path / "formal",) if phase == "post-formal" else (),
    )
    assert result.status == "complete"
    assert calls[0][1]["phase"] == phase


def test_host_v2_capture_ledger_requires_exact_order_and_cohort_paths(tmp_path: Path) -> None:
    study_id = load_class20_profile_contract().study_id
    resolver = host._Resolver(tmp_path, study_id=study_id)
    cohort_root = tmp_path / "config/class-study/v2"
    cohort_root.mkdir(parents=True)
    cohort = cohort_root / f"{study_id}-cohort.json"
    assembly = cohort_root / f"{study_id}-cohort-assembly.json"
    cohort.write_text("{}", encoding="utf-8")
    assembly.write_text("{}", encoding="utf-8")
    names = (
        f"{study_id}-authoritative-fitting-400-1200",
        f"{study_id}-certification-180-1200",
        f"{study_id}-canary-01-1200",
    )
    roots = []
    for index, name in enumerate(names):
        root = tmp_path / f"result-{index}"
        root.mkdir()
        (root / "experiment.json").write_text(json.dumps({"name": name}), encoding="utf-8")
        roots.append(str(root))
    arguments = {
        "campaign_name": f"{study_id}-formal-01-1200",
        "role": "formal", "roots": roots,
        "final_cohort": str(cohort), "final_assembly": str(assembly),
    }
    host._require_class20_capture_ledger(resolver, **arguments)
    with pytest.raises(ValueError, match="exact preceding result ledger"):
        host._require_class20_capture_ledger(resolver, **{**arguments, "roots": roots[:2]})
    with pytest.raises(ValueError, match="order differs"):
        host._require_class20_capture_ledger(resolver, **{**arguments, "roots": roots[::-1]})
    pilot_cohort = cohort_root / f"{study_id}-pilot-cohort.json"
    pilot_assembly = cohort_root / f"{study_id}-pilot-cohort-assembly.json"
    pilot_cohort.write_text("{}", encoding="utf-8")
    pilot_assembly.write_text("{}", encoding="utf-8")
    host._require_class20_capture_ledger(
        resolver, campaign_name=f"{study_id}-pilot-fitting-120-1200",
        role="pilot-fitting", roots=(), pilot_cohort=str(pilot_cohort),
        pilot_assembly=str(pilot_assembly),
    )
    pilot_result = tmp_path / "pilot-result"
    pilot_result.mkdir()
    (pilot_result / "experiment.json").write_text(json.dumps({
        "name": f"{study_id}-pilot-fitting-120-1200"
    }), encoding="utf-8")
    host._require_class20_capture_ledger(
        resolver, campaign_name=f"{study_id}-authoritative-fitting-400-1200",
        role="authoritative-fitting", roots=(str(pilot_result),),
        final_cohort=str(cohort), final_assembly=str(assembly),
    )
    host._require_class20_capture_ledger(
        resolver, campaign_name=f"{study_id}-certification-180-1200",
        role="certification", roots=(roots[0],),
        final_cohort=str(cohort), final_assembly=str(assembly),
    )


def test_v2_capture_action_routes_around_v1_cohort_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = []
    monkeypatch.setattr(
        pipeline, "_coordinate_profile_capture",
        lambda action, **kwargs: captured.append((action, kwargs))
        or pipeline.ClassStudyActionResult(action, "ready", {"valid": True}),
    )
    result = pipeline.run_class_study_action(
        "capture", study_id=load_class20_profile_contract().study_id,
        campaign=Path("/lab/campaign.yml"),
    )
    assert result.status == "ready"
    assert captured[0][0] == "capture"
    assert captured[0][1]["profile"] == load_class20_profile_contract()


def test_host_v2_receipt_schemas_are_exact_and_cross_profile_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolver = host._Resolver(tmp_path, study_id=load_class20_profile_contract().study_id)
    admitted = SimpleNamespace(identity={"build": "fixed"}, source={"source": "fixed"}, cohort_version=1)
    monkeypatch.setattr(host, "_bound_file", lambda *_args, **_kwargs: tmp_path / "bound.json")
    monkeypatch.setattr(host, "_require_same_build", lambda values: values[0])
    monkeypatch.setattr(resolver, "build", lambda *_args, **_kwargs: admitted)
    monkeypatch.setattr(host, "_sha256", lambda _path: host.hashlib.sha256(host._canonical_json_bytes({})).hexdigest())
    holder = {"payload": {
        "artifact_type": host._FOUNDATION,
        "study_id": host._CLASS20_STUDY_ID,
        "study_profile_sha256": host._CLASS20_OVERLAY_SHA256,
        "attestation_schema_version": host._CLASS20_FOUNDATION_SCHEMA,
        "evidence": {"build_execution": {"path": "bound.json", "sha256": "a" * 64}},
        "build_execution_identity": admitted.identity,
        "source": admitted.source,
        "cohort_version": 1,
    }}
    monkeypatch.setattr(
        host, "_envelope", lambda *_args, **_kwargs: (tmp_path / "receipt.json", {}, holder["payload"])
    )
    assert resolver.foundation("receipt.json") is admitted
    holder["payload"] = {**holder["payload"], "attestation_schema_version": 4}
    with pytest.raises(ValueError, match="not current build authority"):
        resolver.foundation("receipt.json")
    holder["payload"] = {**holder["payload"], "attestation_schema_version": 5,
                         "study_profile_sha256": "0" * 64}
    with pytest.raises(ValueError, match="another study profile"):
        resolver.foundation("receipt.json")


@pytest.mark.parametrize(
    ("role", "suffix", "expected_count"),
    [
        ("pilot-fitting", "pilot-fitting-120-1200", 120),
        ("authoritative-fitting", "authoritative-fitting-400-1200", 400),
        ("certification", "certification-180-1200", 180),
    ],
)
def test_v2_initial_capture_requires_role_specific_predecessor_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    role: str, suffix: str, expected_count: int,
) -> None:
    profile = load_class20_profile_contract()
    campaign = tmp_path / f"{profile.study_id}-{suffix}.yml"
    campaign.write_text(
        f"name: {campaign.stem}\nevidence_role: {role}\n", encoding="utf-8"
    )
    (tmp_path / "study.json").write_text("{}", encoding="utf-8")
    cohort = tmp_path / ("pilot.json" if role == "pilot-fitting" else "final.json")
    assembly = tmp_path / "assembly.json"
    foundation = tmp_path / "foundation.json"
    for path in (cohort, assembly, foundation):
        path.write_text("{}", encoding="utf-8")
    layout = SimpleNamespace(campaign_root=tmp_path, study_config_root=tmp_path)
    monkeypatch.setattr(class_capture20, "class_study_layout", lambda **_kwargs: layout)
    monkeypatch.setattr(class_capture20, "require_canonical_fresh_child", lambda path, **_kwargs: path)
    monkeypatch.setattr(class_capture20, "load_validated_profile_cohort", lambda *_args, **_kwargs: (
        tuple(f"pilot-{index}" for index in range(30)),
        () if role == "pilot-fitting" else tuple(f"final-{index}" for index in range(20)),
    ))
    monkeypatch.setattr(class_capture20, "validate_campaign_document", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(class_capture20, "source_metadata", lambda: {"pinned": True})
    monkeypatch.setattr(class_attestation, "_validate_immutable_source", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(class_attestation, "validate_class_foundation_attestation", lambda *_args, **_kwargs: {
        "study_id": profile.study_id,
        "attestation_schema_version": class_attestation.CLASS20_FOUNDATION_SCHEMA_VERSION,
        "study_profile_sha256": sha256_file(tmp_path / "study.json"),
        "source": {"pinned": True},
        "recorded_at": "2020-01-01T00:00:00+00:00",
        "build_execution_identity": {"same": "build"},
    })
    kwargs = {
        "campaign_path": campaign, "cohort_receipt": cohort,
        "cohort_assembly": assembly,
        "prerequisite_roots": (tmp_path / "extra",) if role == "pilot-fitting" else (),
        "foundation_attestation": foundation,
        "profile": profile,
    }
    with pytest.raises(ValueError, match="preceding result ledger"):
        class_capture20.verify_profile_initial_capture_prerequisites(**kwargs)
    if role == "pilot-fitting":
        kwargs["prerequisite_roots"] = ()
        admitted = class_capture20.verify_profile_initial_capture_prerequisites(**kwargs)
        assert admitted["planned_samples"] == expected_count
        assert admitted["prerequisite_ledger"] == ()
        assert admitted["readiness_sha256"] is None
    else:
        assert expected_count in {400, 180}


@pytest.mark.parametrize(
    ("role", "suffix", "samples"),
    [
        ("pilot-fitting", "pilot-fitting-120-1200", 120),
        ("authoritative-fitting", "authoritative-fitting-400-1200", 400),
        ("certification", "certification-180-1200", 180),
    ],
)
def test_v2_coordinator_routes_initial_roles_without_promotion_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    role: str, suffix: str, samples: int,
) -> None:
    campaign, proof, preflight = _setup_profile_capture(tmp_path, monkeypatch)
    profile = load_class20_profile_contract()
    target = tmp_path / f"{profile.study_id}-{suffix}.yml"
    target.write_bytes(campaign.read_bytes())
    runtime = (
        {mode: {"runtime_kind": mode} for mode in (
            "undefended", "static", "front", "tamaraw", "traffic-morphing",
            "wtf-pad", "walkie-talkie", "buflo", "cs-buflo",
        )} if role == "certification" else
        {"undefended": {"runtime_kind": "none"}}
    )
    proof.update({
        "campaign_name": target.stem, "campaign_sha256": sha256_file(target),
        "evidence_role": role, "block": None, "planned_samples": samples,
        "readiness_sha256": None, "historical_pre_snapshot_sha256": None,
        "foundation_recorded_at": "2020-01-01T00:00:00+00:00",
        "expected_defense_runtime_inputs": runtime,
        "qualification_manifest_sha256": "a" * 64 if role == "certification" else None,
        "fitting_generation": {"verified": "generation"} if role == "certification" else None,
        "required_environment": {
            "QCSD_CLASS_FOUNDATION_ATTESTATION": str(tmp_path / "foundation.json")
        },
    })
    preflight.update({
        "name": target.stem, "evidence_role": role,
        "sample_count": samples, "defense_runtime_inputs": runtime,
    })
    if role == "certification":
        preflight["chaff_qualification_set_manifest_sha256"] = "a" * 64
    monkeypatch.setattr(
        class_capture20, "verify_profile_initial_capture_prerequisites",
        lambda **_kwargs: proof,
    )
    kwargs = _capture_kwargs(target)
    kwargs.update(readiness_attestation=None, historical_pre_snapshot=None)
    if role == "pilot-fitting":
        kwargs.update(
            pilot_cohort_receipt=Path("pilot.json"),
            pilot_cohort_assembly=Path("pilot-assembly.json"),
            prerequisite_roots=(),
        )
    else:
        kwargs["prerequisite_roots"] = (Path("previous"),)
    result = pipeline._coordinate_profile_capture("capture", **kwargs)
    assert result.status == "ready"
    assert result.details["capture_prerequisites"]["planned_samples"] == samples
    kwargs["readiness_attestation"] = Path("too-late.json")
    with pytest.raises(ValueError, match="later promotion authority"):
        pipeline._coordinate_profile_capture("capture", **kwargs)

    kwargs["readiness_attestation"] = None
    kwargs.update(execute=True, results_root=tmp_path / "results")
    output = tmp_path / "sealed-result"
    passed = []

    @contextmanager
    def authority(_configuration: dict, ledger: tuple, generation: object):
        passed.append((ledger, generation))
        yield

    from qcsd_lab import class_profile_result

    monkeypatch.setattr(pipeline, "_class_study_coordinator_capture_authority", authority)
    monkeypatch.setattr(pipeline, "require_canonical_fresh_path", lambda path, **_kwargs: path)
    monkeypatch.setattr(pipeline, "run_campaign", lambda *_args: output)
    monkeypatch.setattr(
        class_profile_result, "verify_profile_class_result",
        lambda root, **_kwargs: {
            "valid": True, "root": str(root), "samples": samples, "accepted": samples,
        },
    )
    executed = pipeline._coordinate_profile_capture("capture", **kwargs)
    assert executed.status == "complete"
    assert passed == [(proof["prerequisite_ledger"], proof["fitting_generation"])]


def test_v2_certification_requires_complete_120_qualification_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from qcsd_lab import class_fitting, orchestrator

    profile = load_class20_profile_contract()
    source = {"pinned": True}
    final_ids = tuple(f"site-{index:02d}" for index in range(20))
    campaign = tmp_path / f"{profile.study_id}-certification-180-1200.yml"
    campaign.write_text(f"name: {campaign.stem}\nevidence_role: certification\n", encoding="utf-8")
    study = tmp_path / "study.json"
    study.write_text("{}", encoding="utf-8")
    cohort = tmp_path / "final.json"
    assembly = tmp_path / "assembly.json"
    foundation = tmp_path / "foundation.json"
    for item in (cohort, assembly, foundation):
        item.write_text("{}", encoding="utf-8")
    fit = tmp_path / "fit"
    fit.mkdir()
    (fit / "experiment.json").write_text(json.dumps({
        "source": source, "started_at": "2020-01-02T00:00:00+00:00",
        "completed_at": "2020-01-02T01:00:00+00:00",
    }), encoding="utf-8")
    numeric = tmp_path / "numeric"
    final_bundle = tmp_path / "final-bundle"
    workloads = tmp_path / "workloads"
    sidecars = tmp_path / "sidecars"
    prefixes = sidecars / "_prefix-specs"
    for directory in (numeric, final_bundle, workloads, prefixes):
        directory.mkdir(parents=True)
    (sidecars / "_qualification-set.json").write_text("{}", encoding="utf-8")
    layout = SimpleNamespace(
        campaign_root=tmp_path, study_config_root=tmp_path,
        authoritative_numeric_root=numeric,
        authoritative_final_root=final_bundle,
        workload_root=workloads,
        final_qualification_set_root=sidecars,
    )
    monkeypatch.setattr(class_capture20, "class_study_layout", lambda **_kwargs: layout)
    monkeypatch.setattr(class_capture20, "require_canonical_fresh_child", lambda path, **_kwargs: path)
    monkeypatch.setattr(class_capture20, "load_validated_profile_cohort", lambda *_args, **_kwargs: (
        tuple(f"pilot-{index}" for index in range(30)), final_ids,
    ))
    monkeypatch.setattr(class_capture20, "validate_campaign_document", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(class_capture20, "source_metadata", lambda: source)
    monkeypatch.setattr(class_attestation, "_validate_immutable_source", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(class_attestation, "validate_class_foundation_attestation", lambda *_args, **_kwargs: {
        "study_id": profile.study_id,
        "attestation_schema_version": class_attestation.CLASS20_FOUNDATION_SCHEMA_VERSION,
        "study_profile_sha256": sha256_file(study), "source": source,
        "recorded_at": "2020-01-01T00:00:00+00:00",
        "build_execution_identity": {"same": "build"},
    })
    monkeypatch.setattr(class_attestation, "class_qualification_authority", lambda *_args, **_kwargs: {"qualified": True})
    monkeypatch.setattr(class_capture20, "verify_profile_class_result", lambda root, **_kwargs: {
        "valid": True, "root": str(root), "evidence_role": "authoritative-fitting",
        "class_study_id": profile.study_id,
        "class_study_profile_sha256": sha256_file(study),
        "class_study_foundation_sha256": sha256_file(foundation),
        "cohort_sha256": sha256_file(cohort),
        "cohort_assembly_sha256": sha256_file(assembly),
        "samples": 400, "accepted": 400, "evidence_sha256": "a" * 64,
    })
    monkeypatch.setattr(class_capture20, "verify_result", lambda _root: SimpleNamespace())
    monkeypatch.setattr(class_capture20, "_validate_result_environment", lambda *_args: {"same": "environment"})
    monkeypatch.setattr(class_attestation, "_one_class_build_execution_identity", lambda *_args, **_kwargs: {"same": "build"})
    monkeypatch.setattr(class_fitting, "verify_numeric_fitting_bundle", lambda *_args, **_kwargs: SimpleNamespace(
        stage=class_fitting.AUTHORITATIVE_STAGE,
        provenance={
            "study_id": profile.study_id, "study_profile_sha256": sha256_file(study),
            "fitting_contract": {"workload_order": list(final_ids)},
        },
    ))
    qualification = {
        "qualification_manifest": {"workload_count": 20, "workload_ids": list(final_ids)},
        "qualification_bindings": [{} for _ in range(20)],
        "qualification_manifest_sha256": sha256_file(sidecars / "_qualification-set.json"),
    }
    monkeypatch.setattr(class_fitting, "verify_class_fitting_bundle", lambda *_args, **_kwargs: SimpleNamespace(
        stage=class_fitting.AUTHORITATIVE_STAGE,
        provenance={
            "study_id": profile.study_id, "study_profile_sha256": sha256_file(study),
            "qualification_inputs": qualification,
        },
    ))
    runtime = {mode: {"runtime_kind": mode} for mode in (
        "undefended", "static", "front", "tamaraw", "traffic-morphing",
        "wtf-pad", "walkie-talkie", "buflo", "cs-buflo",
    )}
    generation = {
        "evidence_role": "certification",
        "source_result": {"root": str(fit), "evidence_sha256": "a" * 64},
        "capture_runtime": {"defense_runtime_inputs": runtime},
    }
    monkeypatch.setattr(orchestrator, "verify_class_study_fitting_generation", lambda **_kwargs: generation)
    kwargs = {
        "campaign_path": campaign, "cohort_receipt": cohort,
        "cohort_assembly": assembly, "prerequisite_roots": (fit,),
        "foundation_attestation": foundation,
        "numeric_bundle_root": numeric, "final_bundle_root": final_bundle,
        "qualification_workload_root": workloads,
        "qualification_sidecar_root": sidecars,
        "qualification_prefix_root": prefixes,
        "profile": profile,
    }
    admitted = class_capture20.verify_profile_initial_capture_prerequisites(**kwargs)
    assert admitted["planned_samples"] == 180
    assert admitted["qualification_manifest_sha256"] == qualification["qualification_manifest_sha256"]
    assert admitted["fitting_generation"] is generation
    qualification["qualification_bindings"].pop()
    with pytest.raises(ValueError, match="120 full qualification"):
        class_capture20.verify_profile_initial_capture_prerequisites(**kwargs)


def test_v2_readiness_uses_published_final_prefixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from qcsd_lab import util

    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    profile = load_class20_profile_contract()
    layout = pipeline.class_study_layout(profile=profile)
    target = layout.artifacts_root / "readiness-test.json"
    published_prefixes = layout.final_qualification_set_root / "_prefix-specs"
    inputs = {
        "study_id": profile.study_id,
        "destination": target,
        "numeric_bundle_root": layout.authoritative_numeric_root,
        "prefix_spec_root": published_prefixes,
        "final_bundle_root": layout.authoritative_final_root,
        "qualification_sidecar_root": layout.final_qualification_set_root,
        "foundation_attestation": tmp_path / "foundation.json",
        "cohort_version": 1,
        "candidate_catalogue_path": tmp_path / "catalogue.json",
        "stability_root": tmp_path / "stability",
        "workload_root": layout.workload_root,
        "acquisition_completion_path": tmp_path / "completion.json",
        "pilot_cohort_receipt_path": tmp_path / "pilot.json",
        "pilot_cohort_assembly_path": tmp_path / "pilot-assembly.json",
        "final_selection_path": tmp_path / "selection.json",
        "final_cohort_receipt_path": tmp_path / "final.json",
        "final_cohort_assembly_path": tmp_path / "final-assembly.json",
        "authoritative_fitting_result": tmp_path / "fit",
        "certification_result": tmp_path / "certification",
    }
    captured = []
    monkeypatch.setattr(class_attestation, "create_class_readiness_attestation",
                        lambda path, **kwargs: captured.append(kwargs) or path)
    monkeypatch.setattr(class_attestation, "validate_class_readiness_attestation",
                        lambda _path, **_kwargs: {"valid": True})
    result = pipeline.run_class_study_action("readiness", **inputs)
    assert result.status == "complete"
    assert captured[0]["qualification_prefix_root"] == published_prefixes
    with pytest.raises(ValueError, match="qualification prefix root.*canonical"):
        pipeline.run_class_study_action(
            "readiness", **{**inputs, "prefix_spec_root": layout.authoritative_prefix_root}
        )


def test_host_v2_formal_resume_uses_ten_visits_and_rejects_cross_profile(
    tmp_path: Path,
) -> None:
    base = {
        "id": "site-01", "visits": 10,
        "manifest": "inputs/workloads/site-01.json", "sha256": "a" * 64,
        "resource_count": 1, "origin_count": 1,
        "chaff_qualification": "inputs/chaff-qualifications/site-01.json",
        "chaff_qualification_sha256": "b" * 64,
        "chaff_manifest": "inputs/chaff-manifests/site-01.json",
        "chaff_manifest_sha256": "c" * 64,
        "runtime_manifest": "inputs/runtime-workloads/site-01.json",
        "runtime_manifest_sha256": "d" * 64,
        "chaff_prefix_spec": "inputs/chaff-prefix-specs/site-01.json",
        "chaff_prefix_spec_sha256": "e" * 64,
    }
    profile_resolver = host._Resolver(tmp_path, study_id=host._CLASS20_STUDY_ID)
    base_resolver = host._Resolver(tmp_path, study_id=host._BASE_STUDY_ID)
    kwargs = {
        "result": tmp_path / "result", "role": "formal", "workload_ids": ("site-01",),
    }
    with pytest.raises(ValueError, match="not a regular file"):
        profile_resolver.frozen_workload_inventory(
            **kwargs, configuration={"workloads": [base]}
        )
    with pytest.raises(ValueError, match="workload record is invalid"):
        base_resolver.frozen_workload_inventory(
            **kwargs, configuration={"workloads": [base]}
        )
    with pytest.raises(ValueError, match="workload record is invalid"):
        profile_resolver.frozen_workload_inventory(
            **kwargs, configuration={"workloads": [{**base, "visits": 2}]}
        )


def test_host_v2_later_receipts_require_exact_profile_schemas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    admitted = SimpleNamespace(source={"pinned": True})
    resolver = host._Resolver(tmp_path, study_id=host._CLASS20_STUDY_ID)
    monkeypatch.setattr(host, "_class20_profile_bindings", lambda _root: ({"sha256": digest}, {}))
    monkeypatch.setattr(host, "_bound_file", lambda *_args, **_kwargs: tmp_path / "bound.json")
    monkeypatch.setattr(host, "_bound_directory", lambda *_args, **_kwargs: tmp_path / "handoff")
    monkeypatch.setattr(host, "_require_same_build", lambda values: values[0])
    monkeypatch.setattr(resolver, "handoff", lambda _path: admitted)
    monkeypatch.setattr(resolver, "readiness", lambda _path: admitted)
    monkeypatch.setattr(resolver, "historical", lambda _path: admitted)
    monkeypatch.setattr(resolver, "result_bindings", lambda *_args, **_kwargs: [])

    payloads = {
        "class evaluation": {
            "artifact_type": host._CLASS20_EVALUATION_ARTIFACT,
            "schema_version": host._CLASS20_EVALUATION_SCHEMA,
            "study_id": host._CLASS20_STUDY_ID,
            "study_profile_sha256": digest,
            "handoff": {},
        },
        "class comparison review": {
            "artifact_type": host._COMPARISON,
            "review_schema_version": host._CLASS20_COMPARISON_SCHEMA,
            "study_id": host._CLASS20_STUDY_ID,
            "study_profile_sha256": digest,
            "passed": True,
            "handoff": {}, "evaluation": {},
        },
        "class validation attestation": {
            "artifact_type": host._VALIDATION,
            "attestation_schema_version": host._CLASS20_VALIDATION_SCHEMA,
            "study_id": host._CLASS20_STUDY_ID,
            "study_profile_sha256": digest,
            "source": admitted.source,
            "evidence": {
                "readiness": {}, "canary_results": [{} for _ in range(10)],
                "formal_results": [{} for _ in range(10)],
                "historical_pre_snapshot": {}, "historical_post_snapshot": {},
                "handoff": {}, "evaluation": {}, "comparison_review": {},
            },
        },
        "validation readiness": {"evidence": {}},
    }
    monkeypatch.setattr(
        host, "_envelope",
        lambda _root, raw, *, label, **_kwargs: (Path(raw), {}, payloads[label]),
    )
    assert resolver.evaluation("evaluation.json") is admitted
    assert resolver.comparison("comparison.json") is admitted
    assert resolver.validation("validation.json") is admitted

    payloads["class evaluation"]["schema_version"] = host._EVALUATION_SCHEMA
    with pytest.raises(ValueError, match="evaluation schema"):
        resolver.evaluation("evaluation.json")
    payloads["class evaluation"]["schema_version"] = host._CLASS20_EVALUATION_SCHEMA
    payloads["class evaluation"]["study_profile_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="evaluation schema"):
        resolver.evaluation("evaluation.json")
    payloads["class comparison review"]["review_schema_version"] = 1
    with pytest.raises(ValueError, match="comparison review profile or schema"):
        resolver.comparison("comparison.json")
    payloads["class validation attestation"]["attestation_schema_version"] = 1
    with pytest.raises(ValueError, match="validation attestation schema"):
        resolver.validation("validation.json")
