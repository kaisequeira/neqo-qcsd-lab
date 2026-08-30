from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import (
    buflo_study,
    chaff_qualification,
    class_attestation,
    orchestrator,
    util,
)
from qcsd_lab.capture_session import Defense, Limits
from qcsd_lab.class_acquisition import validate_class_study_preparation
from qcsd_lab.class_campaigns import FINAL_QUALIFICATION_SET
from qcsd_lab.orchestrator import Campaign, Workload, plan_campaign
from qcsd_lab.util import sha256_file

FORMAL_MODES = (
    ("undefended", "none", True),
    ("front", "front", False),
    ("tamaraw", "tamaraw", False),
    ("traffic-morphing", "traffic_morphing", False),
    ("wtf-pad", "wtf_pad", False),
    ("walkie-talkie", "walkie_talkie", False),
    ("buflo", "buflo", False),
    ("cs-buflo", "cs_buflo", False),
)

_COLLECTION_IMAGE = "sha256:" + "1" * 64
_SOURCE = {
    "image_digest": _COLLECTION_IMAGE,
    "lab_commit": "2" * 40,
    "lab_dirty": False,
    "lab_patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "neqo_commit": "3" * 40,
    "neqo_pinned_commit": "3" * 40,
    "neqo_dirty": False,
    "neqo_patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
_BUILD_IDENTITY = {
    "cohort_version": 23,
    "sha256": "4" * 64,
    "collection_image": _COLLECTION_IMAGE,
    "started_at": "2026-08-28T00:00:00+00:00",
    "finished_at": "2026-08-28T00:01:00+00:00",
}
_FINAL_QUALIFICATION_MANIFEST_SHA256 = "e" * 64


def _defense(name: str, kind: str, baseline: bool) -> Defense:
    if kind in {"traffic_morphing", "wtf_pad", "walkie_talkie", "buflo", "cs_buflo"}:
        return Defense(
            name=name,
            kind=kind,
            baseline=baseline,
            parameters=f"{name}.json",
            parameters_path=Path(f"/synthetic/{name}.json"),
            parameters_sha256=(name[0] if name[0] in "abcdef" else "a") * 64,
            parameters_provenance=f"{name}-provenance.json",
            parameters_provenance_path=Path(f"/synthetic/{name}-provenance.json"),
            parameters_provenance_sha256="9" * 64,
            parameters_input_policy="sealed-class-study-fitting-v1",
        )
    if kind == "static":
        return Defense(
            name=name,
            kind=kind,
            baseline=baseline,
            schedule="static.csv",
            schedule_path=Path("/synthetic/static.csv"),
            schedule_sha256="8" * 64,
            mode="chaff-only",
        )
    return Defense(name=name, kind=kind, baseline=baseline)


def _certification_runtime_inputs() -> dict[str, dict[str, object]]:
    compatibility = (
        ("undefended", "none", True),
        ("static", "static", False),
        *(mode for mode in FORMAL_MODES[1:]),
    )
    campaign = _campaign(tuple(_workload(index) for index in range(100)))
    return orchestrator._class_study_campaign_runtime_inputs(
        replace(
            campaign,
            defenses=tuple(_defense(*mode) for mode in compatibility),
            class_study_cohort_sha256="a" * 64,
            class_study_cohort_assembly_sha256="b" * 64,
        )
    )


def _workload(index: int, *, visits: int = 2, origin_bucket: int | None = None) -> Workload:
    bucket = index if origin_bucket is None else origin_bucket
    workload_id = f"class-{index:03d}"
    manifest = {
        "resources": [
            {
                "id": 0,
                "url": f"https://origin-{bucket:03d}.test/page-{index:03d}",
                "type": "Document",
                "content_length": 1,
                "data_length": 1,
                "chaff_priority": True,
                "known_valid": True,
                "depends_on": [],
                "headers": [],
            }
        ]
    }
    return Workload(
        id=workload_id,
        visits=visits,
        path=Path(f"/synthetic/{workload_id}.json"),
        source_bytes=b"synthetic",
        sha256=f"{index:064x}",
        data=manifest,
        resource_count=1,
        origin_count=1,
    )


def _campaign(
    workloads: tuple[Workload, ...],
    *,
    block: int = 1,
    sample_order_scheme: str = "grouped",
    sample_order_window: int | None = None,
) -> Campaign:
    workloads = tuple(
        replace(
            workload,
            qualification_set_manifest_path=Path("/synthetic/qualification-set.json"),
            qualification_set_manifest_sha256=_FINAL_QUALIFICATION_MANIFEST_SHA256,
        )
        for workload in workloads
    )
    return Campaign(
        path=Path("/synthetic/formal.yml"),
        source_bytes=b"synthetic",
        name=f"classifier-multiorigin100-v1-formal-{block:02d}",
        purpose="evaluation",
        seed=2_026_082_800 + block,
        profile="research-1200",
        workloads=workloads,
        request_policies=("as-defined",),
        defenses=tuple(_defense(*mode) for mode in FORMAL_MODES),
        limits=Limits(max_attempts=3),
        chaff_qualification_set=FINAL_QUALIFICATION_SET,
        defense_order_scheme="cyclic-latin-square",
        defense_order_block=block - 1,
        schema_version=2,
        evidence_role="formal",
        sample_order_scheme=sample_order_scheme,
        sample_order_window=sample_order_window,
    )


def _install_preclaim_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    campaign: Campaign,
    *,
    foundation_source: dict[str, object] | None = None,
    readiness_cohort_sha256: str | None = None,
    snapshot_readiness_sha256: str | None = None,
    environment_build: dict[str, object] | None = None,
    readiness_runtime_inputs: dict[str, dict[str, object]] | None = None,
    foundation_recorded_at: str = "2026-08-27T23:00:00+00:00",
    snapshot_recorded_at: str = "2026-08-27T23:30:00+00:00",
) -> tuple[Path, Path | None, Path | None]:
    monkeypatch.setattr(
        orchestrator,
        "_revalidate_loaded_class_study_runtime_files",
        lambda _campaign: None,
    )
    foundation_path = tmp_path / "foundation.json"
    foundation_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv(
        orchestrator.CLASS_STUDY_FOUNDATION_ENV,
        str(foundation_path),
    )
    foundation = {
        "source": _SOURCE if foundation_source is None else foundation_source,
        "build_execution_identity": _BUILD_IDENTITY,
        "recorded_at": foundation_recorded_at,
    }
    monkeypatch.setattr(
        class_attestation,
        "validate_class_foundation_attestation",
        lambda path, *, deep_code_gate=True, runtime_role="collection": foundation,
    )

    readiness_path: Path | None = None
    snapshot_path: Path | None = None
    if campaign.evidence_role in {"canary", "formal"}:
        readiness_path = tmp_path / "readiness.json"
        readiness_path.write_text("{}\n", encoding="utf-8")
        snapshot_path = tmp_path / "historical-pre.json"
        snapshot_path.write_text("{}\n", encoding="utf-8")
        monkeypatch.setenv(
            orchestrator.CLASS_STUDY_READINESS_ENV,
            str(readiness_path),
        )
        monkeypatch.setenv(
            orchestrator.CLASS_STUDY_HISTORICAL_PRE_ENV,
            str(snapshot_path),
        )
        readiness = {
            "source": _SOURCE,
            "build_execution_identity": _BUILD_IDENTITY,
            "summary": {
                "certification_defense_runtime_inputs": (
                    _certification_runtime_inputs()
                    if readiness_runtime_inputs is None
                    else readiness_runtime_inputs
                ),
                "final_qualification_set_manifest_sha256": (
                    _FINAL_QUALIFICATION_MANIFEST_SHA256
                ),
            },
            "evidence": {
                "foundation": {"sha256": sha256_file(foundation_path)},
                "final_cohort": {
                    "sha256": (
                        campaign.class_study_cohort_sha256
                        if readiness_cohort_sha256 is None
                        else readiness_cohort_sha256
                    )
                },
                "final_cohort_assembly": {
                    "sha256": campaign.class_study_cohort_assembly_sha256
                },
            },
        }
        snapshot = {
            "source": _SOURCE,
            "recorded_at": snapshot_recorded_at,
            "readiness": {
                "sha256": (
                    sha256_file(readiness_path)
                    if snapshot_readiness_sha256 is None
                    else snapshot_readiness_sha256
                )
            },
        }
        monkeypatch.setattr(
            class_attestation,
            "validate_class_readiness_attestation",
            lambda path, *, deep_code_gate=True: readiness,
        )
        monkeypatch.setattr(
            class_attestation,
            "validate_class_historical_snapshot",
            lambda path, *, expected_phase=None: snapshot,
        )

    monkeypatch.setenv(
        "QCSD_STUDY_ENVIRONMENT_B64",
        base64.b64encode(json.dumps({"synthetic": True}).encode()).decode(),
    )
    monkeypatch.setattr(
        buflo_study,
        "validate_study_environment_receipt",
        lambda value, *, expected_image_digest=None: {
            "image_id": expected_image_digest,
            "build_execution": (
                _BUILD_IDENTITY if environment_build is None else environment_build
            ),
        },
    )
    return foundation_path, readiness_path, snapshot_path


def _assert_no_class_launch_state(results: Path, campaign: Campaign) -> None:
    assert not (results / ".classifier-multiorigin100-v1-launches").exists()
    assert not (results / campaign.name).exists()


def test_formal_block_has_exact_class_mode_counts_and_balanced_latin_rows() -> None:
    campaign = _campaign(tuple(_workload(index) for index in range(100)))

    plan = plan_campaign(campaign)

    assert len(plan) == 1_600
    assert len({sample["sample_id"] for sample in plan}) == 1_600
    assert Counter((sample["workload_id"], sample["defense"]) for sample in plan) == Counter(
        {
            (f"class-{index:03d}", mode[0]): 2
            for index in range(100)
            for mode in FORMAL_MODES
        }
    )
    first_mode = Counter(plan[offset]["defense"] for offset in range(0, len(plan), 8))
    assert first_mode == Counter({mode[0]: 25 for mode in FORMAL_MODES})


def test_certification_binds_one_complete_two_origin_graph_to_all_nine_modes(
    tmp_path: Path,
) -> None:
    workload_id = "class-000"
    origins = ["https://class-000.example", "https://cdn.class-000.example"]
    resources = [
        {
            "id": 0,
            "url": f"{origins[0]}/",
            "type": "Document",
            "content_length": 100,
            "data_length": 100,
            "chaff_priority": True,
            "known_valid": True,
            "depends_on": [],
            "headers": [],
        },
        {
            "id": 1,
            "url": f"{origins[1]}/application.js",
            "type": "Script",
            "content_length": 200,
            "data_length": 200,
            "chaff_priority": False,
            "known_valid": True,
            "depends_on": [0],
            "headers": [["referer", f"{origins[0]}/"]],
        },
    ]
    manifest = {
        "preparation": {
            "source_url": resources[0]["url"],
            "final_url": resources[0]["url"],
            "chromium_version": "test-chromium",
            "settle_ms": 3_000,
            "observed_request_count": len(resources),
            "observed_origins": origins,
            "approved_origins": origins,
            "exclusions": [],
            "prepare_image_digest": _SOURCE["image_digest"],
            "lab_source": _SOURCE,
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 120,
            "stability_runs": 3,
            "stability_profile": "live",
            "stability_defense": "none",
            "stability_seed": 0,
            "udp_payload_qualification": {
                "schema_version": 1,
                "configured_udp_payload_ceiling": 1_200,
                "runs": [
                    {
                        "run_index": run_index,
                        "packets_sha256": f"{run_index + 1:064x}",
                        "total": {
                            "packet_count": 2,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                        "incoming": {
                            "packet_count": 1,
                            "observed_udp_payload_max": 1_200,
                            "oversized_packet_count": 0,
                        },
                        "outgoing": {
                            "packet_count": 1,
                            "observed_udp_payload_max": 1_199,
                            "oversized_packet_count": 0,
                        },
                    }
                    for run_index in range(3)
                ],
            },
            "neqo_version": "test-neqo",
            "neqo_base_commit": "4" * 40,
            "published_qcsd_commit": "5" * 40,
            "migration_commit": "6" * 40,
            "expected_responses": [
                {
                    "resource_id": resource["id"],
                    "status": 200,
                    "bytes": resource["content_length"],
                    "body_sha256": f"{resource['id'] + 1:064x}",
                }
                for resource in resources
            ],
            "coverage_admission": {
                "schema_version": 1,
                "policy": "all-approved-origins-and-rendered-resources",
                "required_origins": origins,
                "required_resources": [
                    {"id": resource["id"], "url": resource["url"]} for resource in resources
                ],
            },
        },
        "resources": resources,
    }
    validate_class_study_preparation(manifest, workload_id=workload_id)
    source_bytes = orchestrator.canonical_bytes(manifest)
    manifest_path = tmp_path / f"{workload_id}.json"
    manifest_path.write_bytes(source_bytes)
    runtime = orchestrator.runtime_manifest(manifest)
    runtime_path = tmp_path / f"{workload_id}.runtime.json"
    runtime_path.write_bytes(orchestrator.canonical_bytes(runtime))
    complete = Workload(
        id=workload_id,
        visits=1,
        path=manifest_path,
        source_bytes=source_bytes,
        sha256=sha256_file(manifest_path),
        data=manifest,
        resource_count=len(resources),
        origin_count=len(origins),
        runtime_path=runtime_path,
        runtime_sha256=sha256_file(runtime_path),
    )
    workloads = (
        complete,
        *(_workload(index, visits=1) for index in range(1, 100)),
    )
    compatibility_modes = (
        ("undefended", "none", True),
        ("static", "static", False),
        *(mode for mode in FORMAL_MODES[1:]),
    )
    campaign = replace(
        _campaign(workloads, block=1),
        path=tmp_path / "classifier-multiorigin100-v1-certification-900-1200.yml",
        name="classifier-multiorigin100-v1-certification-900-1200",
        purpose="smoke",
        defenses=tuple(_defense(*mode) for mode in compatibility_modes),
        limits=Limits(max_attempts=1),
        evidence_role="certification",
    )

    plan = plan_campaign(campaign)
    cells = [sample for sample in plan if sample["workload_id"] == workload_id]
    assert len(plan) == 900
    assert [sample["defense"] for sample in cells] == [mode[0] for mode in compatibility_modes]

    workload_by_id = {workload.id: workload for workload in campaign.workloads}
    defense_by_name = {defense.name: defense for defense in campaign.defenses}
    chaff_path = tmp_path / "qualified-chaff.json"
    chaff_path.write_text("{}\n", encoding="utf-8")
    context = SimpleNamespace(
        qcsd_profile="research-1200",
        request_policy="as-defined",
        limits=campaign.limits,
    )
    bindings = []
    for sample in cells:
        selected = workload_by_id[sample["workload_id"]]
        selected_runtime = orchestrator.runtime_manifest(selected.data)
        defense = defense_by_name[sample["defense"]]
        output = tmp_path / "outputs" / defense.name
        if defense.baseline:
            command = orchestrator.capture_engine._client_command(
                selected.runtime_path,
                selected.id,
                defense,
                sample["seed"],
                context,
                output,
            )
        else:
            command = orchestrator.capture_engine._client_command(
                selected.runtime_path,
                chaff_path,
                selected.id,
                defense,
                sample["seed"],
                context,
                output,
                application_workload_source=selected.path,
            )
        bindings.append(
            {
                "mode": defense.name,
                "manifest_sha256": selected.sha256,
                "resource_ids": [resource["id"] for resource in selected_runtime["resources"]],
                "runtime_path": command[command.index("--workload") + 1],
                "application_source": (
                    command[command.index("--application-workload-source") + 1]
                    if "--application-workload-source" in command
                    else None
                ),
            }
        )

    assert {binding["manifest_sha256"] for binding in bindings} == {sha256_file(manifest_path)}
    assert all(binding["resource_ids"] == [0, 1] for binding in bindings)
    assert {binding["runtime_path"] for binding in bindings} == {str(runtime_path)}
    assert bindings[0]["application_source"] is None
    assert {binding["application_source"] for binding in bindings[1:]} == {str(manifest_path)}


def test_origin_aware_plan_is_deterministic_and_separates_available_origins() -> None:
    campaign = _campaign(
        tuple(_workload(index) for index in range(24)),
        sample_order_scheme="origin-aware-windowed",
        sample_order_window=12,
    )

    first = plan_campaign(campaign)
    second = plan_campaign(campaign)

    assert first == second
    assert len(first) == 24 * 2 * len(FORMAL_MODES)
    origins = [sample["workload_id"] for sample in first]
    assert all(left != right for left, right in zip(origins, origins[1:], strict=False))
    assert Counter(sample["workload_id"] for sample in first) == Counter(
        {f"class-{index:03d}": 2 * len(FORMAL_MODES) for index in range(24)}
    )


def test_named_full_qualification_routes_exact_class_study_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    campaign_path = config / "campaigns/formal.yml"
    workload_path = config / "workloads/class-000.json"
    sidecar = config / "chaff-qualification-store/sets/class-study-v1/class-000.json"
    set_manifest = sidecar.parent / chaff_qualification.NAMED_QUALIFICATION_SET_MANIFEST
    spec = config / "chaff-prefix-specs/sets/class-study-v1/class-000.json"
    for path in (campaign_path, workload_path, sidecar, set_manifest, spec):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    workload = _workload(0)
    workload = Workload(
        **{
            **workload.__dict__,
            "path": workload_path,
            "source_bytes": workload_path.read_bytes(),
            "sha256": sha256_file(workload_path),
        }
    )
    qualified_manifest = {
        "schema_version": 2,
        "resources": workload.data["resources"],
    }

    def load_named(path: Path, **kwargs: object) -> SimpleNamespace:
        assert path == set_manifest.resolve()
        assert kwargs["expected_qualification_scope"] == "full"
        assert kwargs["expected_workload_ids"] == ("class-000",)
        return SimpleNamespace(
            manifest_path=set_manifest.resolve(),
            manifest_sha256=sha256_file(set_manifest),
        )

    def load_full(path: Path, **kwargs: object) -> SimpleNamespace:
        assert path == sidecar.resolve()
        assert kwargs["prefix_spec_path"] == spec.resolve()
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar),
            manifest_sha256="f" * 64,
            manifest=qualified_manifest,
        )

    monkeypatch.setattr(chaff_qualification, "load_named_qualification_set", load_named)
    monkeypatch.setattr(chaff_qualification, "load_qualified_chaff", load_full)

    [qualified] = orchestrator._load_qualified_chaff_inputs(
        campaign_path,
        (workload,),
        frozen_inputs=None,
        qualification_scope="full",
        qualification_set="class-study-v1",
        config_root=config,
    )

    assert qualified.chaff_qualification_path == sidecar.resolve()
    assert qualified.chaff_prefix_spec_path == spec.resolve()
    assert qualified.qualification_set_manifest_path == set_manifest.resolve()
    assert qualified.qualification_set_manifest_sha256 == sha256_file(set_manifest)


def test_authoritative_roles_bind_exact_final_cohort_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    campaign_path = config / "campaigns/formal.yml"
    receipt_path = config / "class-study/cohort.json"
    assembly_path = config / "class-study/cohort-assembly.json"
    campaign_path.parent.mkdir(parents=True)
    receipt_path.parent.mkdir(parents=True)
    campaign_path.write_text("schema: 2\n", encoding="utf-8")
    receipt_path.write_text("{}\n", encoding="utf-8")
    assembly_path.write_text("{}\n", encoding="utf-8")
    selection = SimpleNamespace(
        pilot=tuple(SimpleNamespace(candidate_id=f"class-{index:03d}") for index in range(120)),
        final=tuple(SimpleNamespace(candidate_id=f"class-{index:03d}") for index in range(100)),
    )
    monkeypatch.setattr(
        "qcsd_lab.class_study.load_study_receipt",
        lambda path: ({}, selection) if path == receipt_path.resolve() else pytest.fail(str(path)),
    )
    workload_hashes = {f"class-{index:03d}": f"{index:064x}" for index in range(100)}
    monkeypatch.setattr(
        "qcsd_lab.class_cohort.validate_cohort_assembly_receipt",
        lambda value, *, cohort: value,
    )
    monkeypatch.setattr(
        "qcsd_lab.class_cohort.cohort_workload_hashes",
        lambda value, *, cohort, workload_ids: {
            workload_id: workload_hashes[workload_id] for workload_id in workload_ids
        },
    )

    path, digest, resolved_assembly, assembly_digest = (
        orchestrator._load_class_study_cohort_binding(
        schema_version=2,
        evidence_role="formal",
        raw_path="../class-study/cohort.json",
        raw_assembly_path="../class-study/cohort-assembly.json",
        campaign_path=campaign_path.resolve(),
        config_root=config.resolve(),
        frozen_inputs=None,
        workload_ids=tuple(f"class-{index:03d}" for index in range(100)),
        workload_hashes=workload_hashes,
        )
    )

    assert path == receipt_path.resolve()
    assert digest == sha256_file(receipt_path)
    assert resolved_assembly == assembly_path.resolve()
    assert assembly_digest == sha256_file(assembly_path)
    with pytest.raises(ValueError, match="workload order differs"):
        orchestrator._load_class_study_cohort_binding(
            schema_version=2,
            evidence_role="formal",
            raw_path="../class-study/cohort.json",
            raw_assembly_path="../class-study/cohort-assembly.json",
            campaign_path=campaign_path.resolve(),
            config_root=config.resolve(),
            frozen_inputs=None,
            workload_ids=tuple(reversed(tuple(f"class-{index:03d}" for index in range(100)))),
            workload_hashes=workload_hashes,
        )


def test_class_launch_claim_is_global_format_invariant_and_recovers_only_prelaunch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    source = _SOURCE
    started = datetime(2026, 8, 28, tzinfo=UTC)
    root, run_id, marker = orchestrator._claim_class_study_launch(
        campaign,
        results_root=results,
        source=source,
        started_at=started,
    )
    reformatted = replace(campaign, source_bytes=b"# same canonical campaign\n")
    assert orchestrator._class_study_launch_key(reformatted) == (
        orchestrator._class_study_launch_key(campaign)
    )
    root.mkdir(parents=True)
    (root / "inputs").mkdir()
    (root / "inputs/campaign.yml").write_bytes(campaign.source_bytes)
    recovered_root, recovered_run_id, recovered_marker = (
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=source,
            started_at=started,
        )
    )
    assert (recovered_root, recovered_run_id, recovered_marker) == (
        root,
        run_id,
        marker,
    )
    assert not root.exists()
    root.mkdir(parents=True)
    (root / "experiment.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="resume"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=source,
            started_at=started,
        )


@pytest.mark.parametrize(
    "role",
    (
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    ),
)
def test_every_class_role_requires_foundation_before_global_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        name=f"classifier-multiorigin100-v1-{role}-preclaim",
        evidence_role=role,
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    for name in (
        orchestrator.CLASS_STUDY_FOUNDATION_ENV,
        orchestrator.CLASS_STUDY_READINESS_ENV,
        orchestrator.CLASS_STUDY_HISTORICAL_PRE_ENV,
        "QCSD_STUDY_ENVIRONMENT_B64",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValueError, match="QCSD_CLASS_FOUNDATION_ATTESTATION"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )

    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_rejects_wrong_source_and_malformed_environment_without_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        foundation_source={**_SOURCE, "neqo_commit": "9" * 40},
    )
    with pytest.raises(ValueError, match="different source identity"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)

    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    monkeypatch.delenv("QCSD_STUDY_ENVIRONMENT_B64")
    with pytest.raises(ValueError, match="requires a host Docker environment"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)

    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    monkeypatch.setenv("QCSD_STUDY_ENVIRONMENT_B64", "not-base64!")
    with pytest.raises(ValueError, match="environment receipt is malformed"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_rejects_authority_created_after_launch_without_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        foundation_recorded_at="2026-08-29T00:00:00+00:00",
    )
    with pytest.raises(ValueError, match="precedes its foundation"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)

    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        snapshot_recorded_at="2026-08-29T00:00:00+00:00",
    )
    with pytest.raises(ValueError, match="precedes its historical pre-snapshot"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


@pytest.mark.parametrize("role", ("canary", "formal"))
def test_formal_roles_bind_readiness_snapshot_and_cohort_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    base = _campaign(tuple(_workload(index) for index in range(100)))
    campaign = replace(
        base,
        name=f"classifier-multiorigin100-v1-{role}-01-1200",
        evidence_role=role,
        defenses=(
            (Defense(name="undefended", kind="none", baseline=True),)
            if role == "canary"
            else base.defenses
        ),
        workloads=(
            tuple(
                replace(
                    workload,
                    qualification_set_manifest_path=None,
                    qualification_set_manifest_sha256=None,
                )
                for workload in base.workloads
            )
            if role == "canary"
            else base.workloads
        ),
        chaff_qualification_set=(
            None if role == "canary" else base.chaff_qualification_set
        ),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    monkeypatch.delenv(orchestrator.CLASS_STUDY_READINESS_ENV)
    with pytest.raises(ValueError, match="QCSD_CLASS_READINESS_ATTESTATION"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)

    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    monkeypatch.delenv(orchestrator.CLASS_STUDY_HISTORICAL_PRE_ENV)
    with pytest.raises(ValueError, match="QCSD_CLASS_HISTORICAL_PRE_SNAPSHOT"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)

    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        readiness_cohort_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="source, build, or cohort"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)

    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        snapshot_readiness_sha256="e" * 64,
    )
    with pytest.raises(ValueError, match="source, build, or cohort"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_rejects_different_environment_build_without_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        environment_build={**_BUILD_IDENTITY, "sha256": "9" * 64},
    )

    with pytest.raises(ValueError, match="different no-cache build"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )

    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_rejects_parameter_drift_before_global_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    base = _campaign(tuple(_workload(index) for index in range(100)))
    defenses = tuple(
        replace(defense, parameters_sha256="f" * 64)
        if defense.name == "traffic-morphing"
        else defense
        for defense in base.defenses
    )
    campaign = replace(
        base,
        defenses=defenses,
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)

    with pytest.raises(ValueError, match="runtime inputs differ"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_rejects_incomplete_certification_runtime_map_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(
        tmp_path,
        monkeypatch,
        campaign,
        readiness_runtime_inputs={"undefended": {"runtime_kind": "none"}},
    )

    with pytest.raises(ValueError, match="no complete certified runtime map"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


def test_preclaim_file_revalidation_rejects_parameter_and_manifest_races(
    tmp_path: Path,
) -> None:
    parameter = tmp_path / "traffic-morphing.json"
    provenance = tmp_path / "provenance.json"
    manifest = tmp_path / "qualification-set.json"
    parameter.write_text("parameter-v1\n", encoding="utf-8")
    provenance.write_text("provenance-v1\n", encoding="utf-8")
    manifest.write_text("manifest-v1\n", encoding="utf-8")
    defense = Defense(
        name="traffic-morphing",
        kind="traffic_morphing",
        baseline=False,
        parameters_path=parameter,
        parameters_sha256=sha256_file(parameter),
        parameters_provenance_path=provenance,
        parameters_provenance_sha256=sha256_file(provenance),
        parameters_input_policy="sealed-class-study-fitting-v1",
    )
    workload = replace(
        _workload(0),
        qualification_set_manifest_path=manifest,
        qualification_set_manifest_sha256=sha256_file(manifest),
    )
    campaign = replace(
        _campaign((workload,)),
        workloads=(workload,),
        defenses=(defense,),
        class_study_id="classifier-multiorigin100-v1",
    )
    orchestrator._revalidate_loaded_class_study_runtime_files(campaign)

    parameter.write_text("parameter-v2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="parameters changed after campaign loading"):
        orchestrator._revalidate_loaded_class_study_runtime_files(campaign)
    parameter.write_text("parameter-v1\n", encoding="utf-8")
    manifest.write_text("manifest-v2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="manifest changed after campaign loading"):
        orchestrator._revalidate_loaded_class_study_runtime_files(campaign)


@pytest.mark.parametrize(
    ("artifact_type", "source_result"),
    (
        ("qcsd-research-defense-bundle", {"study_id": "classifier-multiorigin100-v1"}),
        (
            "qcsd-class-study-research-defense-bundle",
            {
                "study_id": "classifier-multiorigin100-v2-other",
                "class_study_successor_sha256": "a" * 64,
            },
        ),
        (
            "qcsd-class-study-research-defense-bundle",
            {
                "study_id": "classifier-multiorigin100-v2-active",
                "class_study_successor_sha256": "b" * 64,
            },
        ),
    ),
    ids=("predecessor-v1", "other-v2", "same-id-different-restart"),
)
def test_successor_runtime_revalidation_requires_exact_fitting_identity(
    tmp_path: Path,
    artifact_type: str,
    source_result: dict[str, object],
) -> None:
    parameter = tmp_path / "traffic-morphing.json"
    provenance = tmp_path / "provenance.json"
    manifest = tmp_path / "qualification-set.json"
    parameter.write_text("parameter\n", encoding="utf-8")
    provenance.write_text(
        json.dumps(
            {
                "artifact_type": artifact_type,
                "source_result": source_result,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest.write_text("manifest\n", encoding="utf-8")
    defense = Defense(
        name="traffic-morphing",
        kind="traffic_morphing",
        baseline=False,
        parameters_path=parameter,
        parameters_sha256=sha256_file(parameter),
        parameters_provenance_path=provenance,
        parameters_provenance_sha256=sha256_file(provenance),
        parameters_input_policy="sealed-class-study-fitting-v1",
    )
    workload = replace(
        _workload(0),
        qualification_set_manifest_path=manifest,
        qualification_set_manifest_sha256=sha256_file(manifest),
    )
    campaign = replace(
        _campaign((workload,)),
        workloads=(workload,),
        defenses=(defense,),
        class_study_id="classifier-multiorigin100-v2-active",
        class_study_successor_sha256="a" * 64,
    )

    with pytest.raises(
        ValueError,
        match=(
            "exact class fitting bundle|"
            "predecessor or another successor restart"
        ),
    ):
        orchestrator._revalidate_loaded_class_study_runtime_files(campaign)


def test_successor_preclaim_rejects_wrong_restart_before_global_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    parameter = tmp_path / "traffic-morphing.json"
    provenance = tmp_path / "provenance.json"
    manifest = tmp_path / "qualification-set.json"
    parameter.write_text("parameter\n", encoding="utf-8")
    provenance.write_text(
        json.dumps(
            {
                "artifact_type": "qcsd-class-study-research-defense-bundle",
                "source_result": {
                    "study_id": "classifier-multiorigin100-v2-active",
                    "class_study_successor_sha256": "b" * 64,
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest.write_text("manifest\n", encoding="utf-8")
    defense = Defense(
        name="traffic-morphing",
        kind="traffic_morphing",
        baseline=False,
        parameters_path=parameter,
        parameters_sha256=sha256_file(parameter),
        parameters_provenance_path=provenance,
        parameters_provenance_sha256=sha256_file(provenance),
        parameters_input_policy="sealed-class-study-fitting-v1",
    )
    workload = replace(
        _workload(0),
        qualification_set_manifest_path=manifest,
        qualification_set_manifest_sha256=sha256_file(manifest),
    )
    campaign = replace(
        _campaign((workload,)),
        workloads=(workload,),
        defenses=(defense,),
        class_study_id="classifier-multiorigin100-v2-active",
        class_study_successor_sha256="a" * 64,
        class_study_launch_namespace=".classifier-multiorigin100-v2-active-launches",
    )
    monkeypatch.setattr(
        orchestrator,
        "_class_study_authority_paths",
        lambda _campaign: {},
    )
    monkeypatch.setattr(
        orchestrator,
        "_validate_class_study_authority_files",
        lambda *_args, **_kwargs: {},
    )

    with pytest.raises(
        ValueError,
        match="predecessor or another successor restart",
    ):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    assert list(results.iterdir()) == []


def test_class_preclaim_rejects_qualification_manifest_drift_before_global_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    base = _campaign(tuple(_workload(index) for index in range(100)))
    campaign = replace(
        base,
        workloads=tuple(
            replace(workload, qualification_set_manifest_sha256="f" * 64)
            for workload in base.workloads
        ),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)

    with pytest.raises(ValueError, match="qualification manifest differs"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_rejects_missing_named_manifest_before_global_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    base = _campaign(tuple(_workload(index) for index in range(100)))
    campaign = replace(
        base,
        workloads=(
            replace(
                base.workloads[0],
                qualification_set_manifest_path=None,
                qualification_set_manifest_sha256=None,
            ),
            *base.workloads[1:],
        ),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)

    with pytest.raises(ValueError, match="binding is inconsistent"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    _assert_no_class_launch_state(results, campaign)


def test_class_preclaim_uses_the_real_environment_receipt_build_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_class_attestation import _study_environment

    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        name="classifier-multiorigin100-v1-pilot-fitting-1200",
        evidence_role="pilot-fitting",
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    environment = _study_environment(_COLLECTION_IMAGE)
    validated_environment = buflo_study.validate_study_environment_receipt(
        environment,
        expected_image_digest=_COLLECTION_IMAGE,
    )
    environment_build = validated_environment["build_execution"]
    build_identity = {
        key: environment_build[key]
        for key in (
            "cohort_version",
            "sha256",
            "collection_image",
            "started_at",
            "finished_at",
        )
    }
    source = environment["build_execution"]["receipt"]["source"]
    foundation_path = tmp_path / "foundation.json"
    foundation_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv(
        orchestrator.CLASS_STUDY_FOUNDATION_ENV,
        str(foundation_path),
    )
    monkeypatch.setenv(
        "QCSD_STUDY_ENVIRONMENT_B64",
        base64.b64encode(json.dumps(environment).encode()).decode(),
    )
    monkeypatch.setattr(
        class_attestation,
        "validate_class_foundation_attestation",
        lambda path, *, deep_code_gate=True, runtime_role="collection": {
            "source": source,
            "build_execution_identity": build_identity,
            "recorded_at": "2026-08-27T23:00:00+00:00",
        },
    )

    orchestrator._validate_class_study_preclaim_authority(
        campaign,
        source=source,
        started_at=datetime(2026, 8, 28, tzinfo=UTC),
    )


def test_frozen_class_authority_revalidation_remains_fail_closed_for_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    root = tmp_path / "result"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "source.json").write_text(
        json.dumps(_SOURCE, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    (inputs / "class-study-foundation.json").write_text("{}\n", encoding="utf-8")
    (inputs / "class-study-readiness.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="historical-pre-snapshot"):
        orchestrator._validate_frozen_class_study_authority(root, campaign)


def test_successor_resume_rejects_wrong_fitting_lineage_before_temp_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "result"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (root / "experiment.json").write_text(
        json.dumps({"name": "classifier-multiorigin100-v2-active-formal-01-1200"})
        + "\n",
        encoding="utf-8",
    )
    (inputs / "class-study-successor.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv(orchestrator.CLASS_STUDY_PUBLIC_ORIGIN_ENV, "1")
    monkeypatch.setattr(
        orchestrator,
        "_campaign_from_frozen_inputs",
        lambda _root: (_ for _ in ()).throw(
            ValueError("class fitting artifact uses predecessor or another successor restart")
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "discard_atomic_write_temps",
        lambda _root: pytest.fail("temporary state was mutated before successor lineage gate"),
    )

    with pytest.raises(
        ValueError,
        match="predecessor or another successor restart",
    ):
        orchestrator._resume_campaign_locked(root)
    assert (inputs / "class-study-successor.json").read_text(encoding="utf-8") == "{}\n"


def test_class_capture_requires_public_origin_policy_in_direct_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    monkeypatch.delenv("QCSD_PUBLIC_ORIGIN_ONLY", raising=False)
    with pytest.raises(ValueError, match="QCSD_PUBLIC_ORIGIN_ONLY=1"):
        orchestrator._require_class_study_public_origin_policy(campaign)
    monkeypatch.setenv("QCSD_PUBLIC_ORIGIN_ONLY", "0")
    with pytest.raises(ValueError, match="QCSD_PUBLIC_ORIGIN_ONLY=1"):
        orchestrator._require_class_study_public_origin_policy(campaign)
    monkeypatch.setenv("QCSD_PUBLIC_ORIGIN_ONLY", "1")
    orchestrator._require_class_study_public_origin_policy(campaign)


def test_fresh_schema_two_campaign_requires_canonical_unsymlinked_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    alternate = tmp_path / "alternate/campaign.yml"
    alternate.parent.mkdir()
    alternate.write_text("schema: 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        orchestrator.load_campaign(alternate)

    campaign_root = tmp_path / "config/classifier-multiorigin100-v1-campaigns"
    campaign_root.mkdir(parents=True)
    linked = campaign_root / "linked.yml"
    linked.symlink_to(alternate)
    with pytest.raises(ValueError, match="symbolic-link component"):
        orchestrator.load_campaign(linked)


def test_frozen_schema_two_campaign_path_is_exempt_from_live_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "live-lab")
    inputs = tmp_path / "sealed-result/inputs"
    inputs.mkdir(parents=True)
    campaign = inputs / "campaign.yml"
    campaign.write_text("schema: 2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="campaign is missing") as error:
        orchestrator._load_campaign(
            campaign,
            frozen_inputs=inputs,
            allow_historical_research_bundle=False,
        )
    assert "canonical class-study layout" not in str(error.value)
