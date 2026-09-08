from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections import Counter
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import (
    buflo_study,
    chaff_qualification,
    class_attestation,
    orchestrator,
    util,
)
from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
    TARGET_EGRESS_APIS,
    target_egress_apis,
)
from qcsd_lab.capture_session import Defense, Limits
from qcsd_lab.class_acquisition import validate_class_study_preparation
from qcsd_lab.class_campaigns import FINAL_QUALIFICATION_SET
from qcsd_lab.class_study import STUDY_ID
from qcsd_lab.cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
)
from qcsd_lab.discover import origin
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
    RENDER_OBSERVATION_SCHEMA_VERSION,
    evidence_sha256,
    passive_render_contract,
)
from qcsd_lab.orchestrator import Campaign, Workload, plan_campaign
from qcsd_lab.util import sha256_file


def _terminal_bootstrap_prearm_summary() -> dict[str, object]:
    worker_summary = {
        "held": 0,
        "released": 0,
        "pending": 0,
        "released_after_setup_envelopes": 0,
        "owner_target_types": {
            "page": 0,
            "iframe": 0,
            "worker": 0,
            "shared_worker": 0,
        },
    }
    return {
        "schema_version": 1,
        "held_total": 0,
        "released_total": 0,
        "pending_total": 0,
        "release_before_setup_envelopes_total": 0,
        "by_worker_type": {
            "worker": deepcopy(worker_summary),
            "shared_worker": deepcopy(worker_summary),
        },
    }


def _terminal_egress_prearm_summary() -> dict[str, object]:
    return {
        "schema_version": EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "target_total": 1,
        "installed_total": 1,
        "pending_total": 0,
        "popup_guard_required_total": 1,
        "popup_guard_installed_total": 1,
        "by_target_type": {
            target_type: {
                "target_count": int(target_type == "page"),
                "installed_count": int(target_type == "page"),
                "pending_count": 0,
                "protected_api_observations": (
                    len(target_egress_apis("page")) if target_type == "page" else 0
                ),
                "unavailable_api_observations": 0,
                "popup_guard_required_count": int(target_type == "page"),
                "popup_guard_installed_count": int(target_type == "page"),
            }
            for target_type in ("page", "iframe", "worker", "shared_worker")
        },
    }


def _non_replayable_egress_summary() -> dict[str, object]:
    return {
        "schema_version": NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "attempt_count": 0,
        "protected_apis": list(TARGET_EGRESS_APIS),
        "context_init_script_installed": True,
        "context_navigation_route_installed": True,
        "root_page_bound": True,
        "context_websocket_route_installed": True,
        "context_service_worker_listener_installed": True,
        "cdp_tripwires_are_pre_io": False,
        "packet_level_completeness_claimed": False,
    }


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
        name=f"classifier-multiorigin100-v1-formal-{block:02d}-1200",
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
    # Fresh launch tests model one isolated canonical Lab workspace.  Frozen
    # result validation tests intentionally do not need this live-layout bind.
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
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


def _complete_origin_workload(
    tmp_path: Path,
    *,
    visits: int,
    workload_id: str,
    origin_count: int,
) -> Workload:
    if origin_count not in {1, 2, 3}:
        raise ValueError("synthetic complete workload supports one to three origins")
    origins = [f"https://{workload_id}.example"]
    origins.extend(
        f"https://{'cdn' if index == 1 else f'cdn-{index}'}.{workload_id}.example"
        for index in range(1, origin_count)
    )
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
        *(
            {
                "id": index,
                "url": (
                    f"{resource_origin}/application.js"
                    if index == 1
                    else f"{resource_origin}/application-{index}.js"
                ),
                "type": "Script",
                "content_length": 100 * (index + 1),
                "data_length": 100 * (index + 1),
                "chaff_priority": False,
                "known_valid": True,
                "depends_on": [0],
                "headers": [["referer", f"{origins[0]}/"]],
            }
            for index, resource_origin in enumerate(origins[1:], start=1)
        ),
    ]
    target_source = {
        "session_path": [],
        "target_id": "fixture-page",
        "target_type": "page",
        "generation": 0,
        "parent_session_path": None,
        "parent_frame_id": None,
    }
    events = []
    for resource in resources:
        resource_id = resource["id"]
        occurrence_id = f"request-{resource_id:08d}"
        dependency_evidence = (
            []
            if resource_id == 0
            else [
                {
                    "kind": "document-url",
                    "value": resources[0]["url"],
                    "resolved_resource_id": 0,
                }
            ]
        )
        events.extend(
            [
                {
                    "sequence": len(events) + 1,
                    "monotonic_ms": 0,
                    "kind": "network-request",
                    "source": target_source,
                    "network_id": f"network-{resource_id}",
                    "occurrence_id": occurrence_id,
                    "occurrence_index": 0,
                    "method": "GET",
                    "url": resource["url"],
                    "frame_id": "root-frame",
                    "resource_type": resource["type"],
                    "safe_request_headers": resource["headers"],
                    "interception_required": True,
                    "redirected": False,
                    "redirect_from_occurrence_id": None,
                    "mapping": {"kind": "resource", "resource_id": resource_id},
                    "dependency_evidence": dependency_evidence,
                    "resolved_dependency_resource_ids": resource["depends_on"],
                },
                {
                    "sequence": len(events) + 2,
                    "monotonic_ms": 0,
                    "kind": "fetch-request",
                    "source": target_source,
                    "fetch_id": f"fetch-{resource_id}",
                    "network_id": f"network-{resource_id}",
                    "redirected_fetch_id": None,
                    "network_occurrence_id": occurrence_id,
                    "method": "GET",
                    "url": resource["url"],
                    "frame_id": "root-frame",
                    "policy_decision": "continue",
                    "policy_reason": None,
                    "relationship": "primary",
                },
                {
                    "sequence": len(events) + 3,
                    "monotonic_ms": 0,
                    "kind": "network-terminal",
                    "source": target_source,
                    "network_id": f"network-{resource_id}",
                    "outcome": "finished",
                    "network_occurrence_ids": [occurrence_id],
                },
            ]
        )
    render_observation = {
        "schema_version": RENDER_OBSERVATION_SCHEMA_VERSION,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": 0,
        "load_event_ms": 0,
        "last_relevant_event_ms": 0,
        "quiet_started_ms": 10_000,
        "cutoff_ms": 13_000,
        "active_request_ids": [],
        "active_request_count": 0,
        "router_shutdown_ready": True,
        "bootstrap_prearm_summary": _terminal_bootstrap_prearm_summary(),
        "egress_prearm_summary": _terminal_egress_prearm_summary(),
        "non_replayable_egress_summary": _non_replayable_egress_summary(),
        "browser_context_service_worker_count": 0,
        "cutoff_reason": "quiescent",
    }
    render_observation_sha256 = evidence_sha256(render_observation)
    discovery_event_audit = {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": render_observation_sha256,
        "events": events,
        "summary": {
            "event_count": len(events),
            "target_event_count": 0,
            "network_request_count": len(resources),
            "fetch_request_count": len(resources),
            "fetch_internal_restart_count": 0,
            "terminal_event_count": len(resources),
            "resource_occurrence_count": len(resources),
            "exclusion_occurrence_count": 0,
        },
    }
    discovery_event_audit_sha256 = evidence_sha256(discovery_event_audit)
    origin_ip_pins = {value: "1.1.1.1" for value in sorted(origins)}
    browser_request_headers = [
        {"resource_id": resource["id"], "headers": resource["headers"]}
        for resource in resources
    ]
    manifest = {
        "preparation": {
            "source_url": resources[0]["url"],
            "final_url": resources[0]["url"],
            "chromium_version": "test-chromium",
            "settle_ms": 10_000,
            "observed_request_count": len(resources),
            "observed_origins": sorted(origins),
            "approved_origins": origins,
            "origin_ip_pins": origin_ip_pins,
            "exclusions": [],
            "browser_request_headers": browser_request_headers,
            "request_header_transformation": (
                "browser-safe-input-to-neqo-stability-frozen-runtime-v1"
            ),
            "passive_render_contract": passive_render_contract(),
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "render_observation": render_observation,
            "render_observation_sha256": render_observation_sha256,
            "discovery_event_audit": discovery_event_audit,
            "discovery_event_audit_sha256": discovery_event_audit_sha256,
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
                "schema_version": 3,
                "policy": "all-approved-origins-and-rendered-resources",
                "required_origins": origins,
                "required_resources": [
                    {"id": resource["id"], "url": resource["url"]}
                    for resource in resources
                ],
                "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
                "render_observation_sha256": render_observation_sha256,
                "discovery_event_audit_sha256": discovery_event_audit_sha256,
                "origin_ip_pins_sha256": evidence_sha256(origin_ip_pins),
                "browser_request_headers_sha256": evidence_sha256(
                    browser_request_headers
                ),
                "network_request_count": len(resources),
                "resource_occurrence_count": len(resources),
                "exclusion_occurrence_count": 0,
            },
        },
        "resources": resources,
    }
    validate_class_study_preparation(manifest, workload_id=workload_id)
    source_bytes = orchestrator.canonical_bytes(manifest)
    manifest_path = tmp_path / f"{workload_id}.fitting.json"
    manifest_path.write_bytes(source_bytes)
    runtime = orchestrator.runtime_manifest(manifest)
    runtime_path = tmp_path / f"{workload_id}.fitting.runtime.json"
    runtime_path.write_bytes(orchestrator.canonical_bytes(runtime))
    return Workload(
        id=workload_id,
        visits=visits,
        path=manifest_path,
        source_bytes=source_bytes,
        sha256=sha256_file(manifest_path),
        data=manifest,
        resource_count=len(resources),
        origin_count=len(origins),
        runtime_path=runtime_path,
        runtime_sha256=sha256_file(runtime_path),
    )


def _complete_two_origin_workload(
    tmp_path: Path, *, visits: int, workload_id: str = "class-000"
) -> Workload:
    return _complete_origin_workload(
        tmp_path,
        visits=visits,
        workload_id=workload_id,
        origin_count=2,
    )


@pytest.mark.parametrize(
    ("role", "workload_count", "visits", "expected_samples"),
    (
        ("pilot-fitting", 120, 2, 480),
        ("authoritative-fitting", 100, 10, 2_000),
    ),
)
def test_two_origin_graph_is_preserved_in_both_fitting_campaign_bindings(
    tmp_path: Path,
    role: str,
    workload_count: int,
    visits: int,
    expected_samples: int,
) -> None:
    complete = _complete_two_origin_workload(tmp_path, visits=visits)
    workloads = (
        complete,
        *(_workload(index, visits=visits) for index in range(1, workload_count)),
    )
    campaign = Campaign(
        path=tmp_path / f"classifier-multiorigin100-v1-{role}-1200.yml",
        source_bytes=b"synthetic",
        name=f"classifier-multiorigin100-v1-{role}-1200",
        purpose="fitting",
        seed=2_026_082_800,
        profile="research-1200",
        workloads=workloads,
        request_policies=("as-defined", "half-duplex"),
        defenses=(_defense("undefended", "none", True),),
        limits=Limits(max_attempts=3),
        schema_version=2,
        evidence_role=role,
    )

    plan = plan_campaign(campaign)
    cells = [sample for sample in plan if sample["workload_id"] == complete.id]
    assert len(plan) == expected_samples
    assert len(cells) == visits * 2
    assert Counter(sample["request_policy"] for sample in cells) == Counter(
        {"as-defined": visits, "half-duplex": visits}
    )

    runtime = orchestrator.runtime_manifest(complete.data)
    assert [resource["url"] for resource in runtime["resources"]] == [
        "https://class-000.example/",
        "https://cdn.class-000.example/application.js",
    ]
    assert runtime["resources"][1]["depends_on"] == [0]
    assert runtime["resources"][1]["headers"] == [
        ["referer", "https://class-000.example/"]
    ]
    assert complete.origin_count == 2
    assert complete.sha256 == sha256_file(complete.path)
    assert complete.runtime_sha256 == sha256_file(complete.runtime_path)

    context = SimpleNamespace(
        qcsd_profile="research-1200",
        request_policy="as-defined",
        limits=campaign.limits,
    )
    for sample in cells:
        context.request_policy = sample["request_policy"]
        command = orchestrator.capture_engine._client_command(
            complete.runtime_path,
            complete.id,
            campaign.defenses[0],
            sample["seed"],
            context,
            tmp_path / "outputs" / sample["sample_id"],
        )
        assert command[command.index("--workload") + 1] == str(complete.runtime_path)


@pytest.mark.parametrize(
    (
        "role",
        "cohort_filename",
        "assembly_filename",
        "selection_member",
        "visits",
        "expected_samples",
    ),
    (
        (
            "pilot-fitting",
            "classifier-multiorigin100-v1-pilot-cohort.json",
            "classifier-multiorigin100-v1-pilot-cohort-assembly.json",
            "pilot",
            2,
            480,
        ),
        (
            "authoritative-fitting",
            "classifier-multiorigin100-v1-cohort.json",
            "classifier-multiorigin100-v1-cohort-assembly.json",
            "final",
            10,
            2_000,
        ),
    ),
)
def test_loaded_fitting_campaigns_preserve_every_complete_two_origin_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    cohort_filename: str,
    assembly_filename: str,
    selection_member: str,
    visits: int,
    expected_samples: int,
) -> None:
    from qcsd_lab.class_campaigns import campaign_documents
    from qcsd_lab.class_cohort import ASSEMBLY_RECEIPT_TYPE
    from qcsd_lab.class_study import (
        bind_receipt,
        canonical_json_bytes,
        load_study_receipt,
    )
    from tests.test_class_campaigns import _assembly_receipt, _cohort_receipt

    config = tmp_path / "config"
    campaign_root = config / "classifier-multiorigin100-v1-campaigns"
    study_root = config / "class-study/v1"
    workload_root = config / "workloads"
    for root in (campaign_root, study_root, workload_root):
        root.mkdir(parents=True)
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)

    cohort = _cohort_receipt(study_root, cohort_filename)
    _, selection = load_study_receipt(cohort)
    selected_ids = tuple(
        candidate.candidate_id for candidate in getattr(selection, selection_member)
    )
    complete_by_id = {
        workload_id: _complete_two_origin_workload(
            tmp_path,
            visits=visits,
            workload_id=workload_id,
        )
        for workload_id in selected_ids
    }
    for workload_id, complete in complete_by_id.items():
        (workload_root / f"{workload_id}.json").write_bytes(complete.source_bytes)

    assembly = _assembly_receipt(
        study_root,
        cohort,
        assembly_filename,
    )
    assembly_envelope = json.loads(assembly.read_text(encoding="utf-8"))
    assembly_payload = assembly_envelope["payload"]
    for record in assembly_payload["candidates"]:
        workload = complete_by_id.get(record["candidate_id"])
        if workload is not None:
            record["prepared_workload"]["sha256"] = workload.sha256
    assembly.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                assembly_payload,
                receipt_type=ASSEMBLY_RECEIPT_TYPE,
            )
        )
    )

    documents = campaign_documents(
        cohort,
        cohort_assembly_receipt=assembly,
        cohort_reference=f"../class-study/v1/{cohort_filename}",
        cohort_assembly_reference=f"../class-study/v1/{assembly_filename}",
    )
    filename = f"classifier-multiorigin100-v1-{role}-1200.yml"
    document = documents[filename]
    assert tuple(document["workloads"]) == selected_ids
    assert set(document["workloads"].values()) == {visits}
    campaign_path = campaign_root / filename
    campaign_path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )

    campaign = orchestrator.load_campaign(campaign_path)
    plan = plan_campaign(campaign)
    first_id = selected_ids[0]
    selected_samples = [sample for sample in plan if sample["workload_id"] == first_id]

    assert campaign.schema_version == 2
    assert campaign.evidence_role == role
    assert campaign.purpose == "fitting"
    assert campaign.request_policies == ("as-defined", "half-duplex")
    assert [(defense.name, defense.kind, defense.baseline) for defense in campaign.defenses] == [
        ("undefended", "none", True)
    ]
    assert tuple(workload.id for workload in campaign.workloads) == selected_ids
    assert all(workload.visits == visits for workload in campaign.workloads)
    assert len(plan) == expected_samples
    assert Counter(sample["request_policy"] for sample in selected_samples) == Counter(
        {"as-defined": visits, "half-duplex": visits}
    )
    assert campaign.class_study_cohort_sha256 == sha256_file(cohort)
    assert campaign.class_study_cohort_assembly_sha256 == sha256_file(assembly)
    for selected in campaign.workloads:
        complete = complete_by_id[selected.id]
        runtime = orchestrator.runtime_manifest(selected.data)
        assert selected.path == (workload_root / f"{selected.id}.json").resolve()
        assert selected.sha256 == complete.sha256
        assert selected.resource_count == 2
        assert selected.origin_count == 2
        assert [resource["url"] for resource in runtime["resources"]] == [
            f"https://{selected.id}.example/",
            f"https://cdn.{selected.id}.example/application.js",
        ]
        assert runtime["resources"][1]["depends_on"] == [0]
        assert runtime["resources"][1]["headers"] == [
            ["referer", f"https://{selected.id}.example/"]
        ]
        assert selected.runtime_sha256 == orchestrator.sha256_bytes(
            orchestrator.canonical_bytes(runtime)
        )

    tampered = json.loads(json.dumps(complete_by_id[first_id].data))
    tampered["preparation"].pop("coverage_admission")
    tampered_path = workload_root / f"{first_id}.json"
    tampered_path.write_bytes(orchestrator.canonical_bytes(tampered))
    assembly_envelope = json.loads(assembly.read_text(encoding="utf-8"))
    assembly_payload = assembly_envelope["payload"]
    next(
        record
        for record in assembly_payload["candidates"]
        if record["candidate_id"] == first_id
    )["prepared_workload"]["sha256"] = sha256_file(tampered_path)
    assembly.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                assembly_payload,
                receipt_type=ASSEMBLY_RECEIPT_TYPE,
            )
        )
    )

    with pytest.raises(ValueError, match="requires a complete-coverage admission"):
        orchestrator.load_campaign(campaign_path)


def test_loaded_certification_rejects_rebound_incomplete_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from qcsd_lab.class_campaigns import campaign_documents
    from qcsd_lab.class_cohort import ASSEMBLY_RECEIPT_TYPE
    from qcsd_lab.class_study import (
        bind_receipt,
        canonical_json_bytes,
        load_study_receipt,
    )
    from tests.test_class_campaigns import _assembly_receipt, _cohort_receipt

    config = tmp_path / "config"
    campaign_root = config / "classifier-multiorigin100-v1-campaigns"
    study_root = config / "class-study/v1"
    workload_root = config / "workloads"
    for root in (campaign_root, study_root, workload_root):
        root.mkdir(parents=True)
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)

    cohort_filename = "classifier-multiorigin100-v1-cohort.json"
    assembly_filename = "classifier-multiorigin100-v1-cohort-assembly.json"
    cohort = _cohort_receipt(study_root, cohort_filename)
    _, selection = load_study_receipt(cohort)
    selected_ids = tuple(candidate.candidate_id for candidate in selection.final)
    workload_hashes = {}
    for index, workload_id in enumerate(selected_ids):
        manifest = _complete_two_origin_workload(
            tmp_path,
            visits=1,
            workload_id=workload_id,
        ).data
        if index == 0:
            manifest["preparation"].pop("coverage_admission")
        workload_path = workload_root / f"{workload_id}.json"
        workload_path.write_bytes(orchestrator.canonical_bytes(manifest))
        workload_hashes[workload_id] = sha256_file(workload_path)

    assembly = _assembly_receipt(study_root, cohort, assembly_filename)
    assembly_envelope = json.loads(assembly.read_text(encoding="utf-8"))
    assembly_payload = assembly_envelope["payload"]
    for record in assembly_payload["candidates"]:
        workload_hash = workload_hashes.get(record["candidate_id"])
        if workload_hash is not None:
            record["prepared_workload"]["sha256"] = workload_hash
    assembly.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                assembly_payload,
                receipt_type=ASSEMBLY_RECEIPT_TYPE,
            )
        )
    )

    documents = campaign_documents(
        cohort,
        cohort_assembly_receipt=assembly,
        cohort_reference=f"../class-study/v1/{cohort_filename}",
        cohort_assembly_reference=f"../class-study/v1/{assembly_filename}",
    )
    filename = "classifier-multiorigin100-v1-certification-900-1200.yml"
    campaign_path = campaign_root / filename
    campaign_path.write_text(
        yaml.safe_dump(documents[filename], sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="requires a complete-coverage admission"):
        orchestrator.load_campaign(campaign_path)


def test_formal_commands_reuse_complete_two_origin_graph_for_both_visits(
    tmp_path: Path,
) -> None:
    complete = _complete_two_origin_workload(tmp_path, visits=2)
    campaign = _campaign((complete,))
    cells = plan_campaign(campaign)
    defenses = {defense.name: defense for defense in campaign.defenses}
    chaff_path = tmp_path / "qualified-chaff.json"
    chaff_path.write_text("{}\n", encoding="utf-8")
    context = SimpleNamespace(
        qcsd_profile="research-1200",
        request_policy="as-defined",
        limits=campaign.limits,
    )
    bindings = []

    for sample in cells:
        defense = defenses[sample["defense"]]
        output = tmp_path / "outputs" / sample["sample_id"]
        if defense.baseline:
            command = orchestrator.capture_engine._client_command(
                complete.runtime_path,
                complete.id,
                defense,
                sample["seed"],
                context,
                output,
            )
            application_source = complete.path
        else:
            command = orchestrator.capture_engine._client_command(
                complete.runtime_path,
                chaff_path,
                complete.id,
                defense,
                sample["seed"],
                context,
                output,
                application_workload_source=complete.path,
            )
            application_source = Path(
                command[command.index("--application-workload-source") + 1]
            )
        runtime_path = Path(command[command.index("--workload") + 1])
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        bindings.append((runtime_path, application_source, runtime))

    assert len(bindings) == 16
    assert {
        (sample["defense"], sample["visit"])
        for sample in cells
    } == {
        (mode[0], visit)
        for mode in FORMAL_MODES
        for visit in range(2)
    }
    assert {runtime_path for runtime_path, _, _ in bindings} == {complete.runtime_path}
    assert {source_path for _, source_path, _ in bindings} == {complete.path}
    assert all(
        [resource["id"] for resource in runtime["resources"]] == [0, 1]
        and runtime["resources"][1]["depends_on"] == [0]
        and runtime["resources"][1]["headers"]
        == [["referer", "https://class-000.example/"]]
        for _, _, runtime in bindings
    )


def test_certification_binds_one_complete_two_origin_graph_to_all_nine_modes(
    tmp_path: Path,
) -> None:
    complete = _complete_two_origin_workload(tmp_path, visits=1)
    workload_id = complete.id
    manifest_path = complete.path
    runtime_path = complete.runtime_path
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


def test_mixed_origin_final_hundred_preserves_each_graph_across_all_modes(
    tmp_path: Path,
) -> None:
    """Certification and formal matrices may not flatten mixed-origin classes."""

    formal_workloads = tuple(
        _complete_origin_workload(
            tmp_path,
            visits=2,
            workload_id=f"class-{index:03d}",
            origin_count=(index % 3) + 1,
        )
        for index in range(100)
    )
    compatibility_modes = (
        ("undefended", "none", True),
        ("static", "static", False),
        *(mode for mode in FORMAL_MODES[1:]),
    )
    certification = replace(
        _campaign(tuple(replace(workload, visits=1) for workload in formal_workloads)),
        path=tmp_path / "classifier-multiorigin100-v1-certification-900-1200.yml",
        name="classifier-multiorigin100-v1-certification-900-1200",
        purpose="smoke",
        defenses=tuple(_defense(*mode) for mode in compatibility_modes),
        limits=Limits(max_attempts=1),
        evidence_role="certification",
    )
    formal = _campaign(formal_workloads)
    expected_graphs = {
        workload.id: tuple(
            resource["url"]
            for resource in orchestrator.runtime_manifest(workload.data)["resources"]
        )
        for workload in formal_workloads
    }
    expected_origin_counts = {
        workload.id: workload.origin_count for workload in formal_workloads
    }

    for campaign, modes, visits, sample_count in (
        (certification, compatibility_modes, 1, 900),
        (formal, FORMAL_MODES, 2, 1_600),
    ):
        plan = plan_campaign(campaign)
        workload_by_id = {workload.id: workload for workload in campaign.workloads}
        assert len(plan) == sample_count
        assert Counter(
            (sample["workload_id"], sample["visit"], sample["defense"])
            for sample in plan
        ) == Counter(
            (f"class-{index:03d}", visit, mode[0])
            for index in range(100)
            for visit in range(visits)
            for mode in modes
        )
        for sample in plan:
            workload = workload_by_id[sample["workload_id"]]
            runtime = orchestrator.runtime_manifest(workload.data)
            assert tuple(resource["url"] for resource in runtime["resources"]) == expected_graphs[
                workload.id
            ]
            assert workload.origin_count == expected_origin_counts[workload.id]
            assert len(
                {
                    origin(resource["url"])
                    for resource in runtime["resources"]
                }
            ) == expected_origin_counts[workload.id]


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
    marker_sha256 = sha256_file(marker)
    with pytest.raises(ValueError, match="differs from its campaign"):
        orchestrator._claim_class_study_launch(
            reformatted,
            results_root=results,
            source=source,
            started_at=started,
        )
    assert sha256_file(marker) == marker_sha256
    assert not root.exists()
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


def test_class_launch_claim_rejects_a_second_results_root_and_symlink_alias(
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
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    started = datetime(2026, 8, 28, tzinfo=UTC)

    # A normalised lexical alias resolves back to the one canonical authority.
    lexical_alias = tmp_path / "unused" / ".." / "results"
    root, _run_id, marker = orchestrator._claim_class_study_launch(
        campaign,
        results_root=lexical_alias,
        source=_SOURCE,
        started_at=started,
    )
    assert marker.parent.parent == results

    alternate = tmp_path / "alternate-results"
    alternate.mkdir()
    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=alternate,
            source=_SOURCE,
            started_at=started,
        )
    assert list(alternate.iterdir()) == []

    alias = tmp_path / "results-alias"
    alias.symlink_to(results, target_is_directory=True)
    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=alias,
            source=_SOURCE,
            started_at=started,
        )
    assert marker.is_file()
    assert not root.exists()

    rebound_namespace = replace(
        campaign,
        class_study_launch_namespace=".alternate-launches",
    )
    with pytest.raises(ValueError, match="differs from its study identity"):
        orchestrator._claim_class_study_launch(
            rebound_namespace,
            results_root=results,
            source=_SOURCE,
            started_at=started,
        )
    assert not (results / ".alternate-launches").exists()


def test_public_run_api_rejects_an_alternate_class_results_root_before_locking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    monkeypatch.setattr(orchestrator, "load_campaign", lambda _path: campaign)
    monkeypatch.setattr(
        orchestrator,
        "_require_class_study_coordinator_capture_authority",
        lambda _campaign: None,
    )
    monkeypatch.setattr(
        orchestrator,
        "_run_loaded_campaign",
        lambda *_args, **_kwargs: pytest.fail("alternate root reached campaign execution"),
    )
    alternate = tmp_path / "alternate-results"
    alternate.mkdir()

    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        orchestrator.run_campaign(tmp_path / "campaign.yml", alternate)
    assert list(alternate.iterdir()) == []


@pytest.mark.parametrize("mutation", ("symlink", "insecure-mode"))
def test_class_launch_claim_rejects_an_unsafe_canonical_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    registry = results / f".{STUDY_ID}-launches"
    if mutation == "symlink":
        foreign = tmp_path / "foreign-registry"
        foreign.mkdir(mode=0o700)
        registry.symlink_to(foreign, target_is_directory=True)
    else:
        registry.mkdir(mode=0o700)
        registry.chmod(0o750)

    with pytest.raises(ValueError, match="owner-owned mode-0700"):
        orchestrator._claim_class_study_launch(
            campaign,
            results_root=results,
            source=_SOURCE,
            started_at=datetime(2026, 8, 28, tzinfo=UTC),
        )
    assert not tuple(registry.glob("*.json"))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX process atomicity")
def test_class_launch_claim_is_atomic_across_direct_api_processes(
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
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    read_gate, write_gate = os.pipe()
    children: list[int] = []
    outputs: list[Path] = []
    for index in range(2):
        output = tmp_path / f"claim-child-{index}.json"
        outputs.append(output)
        pid = os.fork()
        if pid == 0:  # pragma: no branch - each child exits below.
            try:
                os.close(write_gate)
                os.read(read_gate, 1)
                started = datetime(2026, 8, 28, 0, 0, index, tzinfo=UTC)
                root, run_id, marker = orchestrator._claim_class_study_launch(
                    campaign,
                    results_root=results,
                    source=_SOURCE,
                    started_at=started,
                )
                output.write_text(
                    json.dumps(
                        {
                            "root": str(root),
                            "run_id": run_id,
                            "marker": str(marker),
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            except BaseException as error:  # pragma: no cover - parent reports it.
                output.write_text(
                    json.dumps({"error": f"{type(error).__name__}: {error}"}) + "\n",
                    encoding="utf-8",
                )
                os._exit(1)
            os._exit(0)
        children.append(pid)
    os.close(read_gate)
    os.write(write_gate, b"12")
    os.close(write_gate)
    statuses = [os.waitpid(pid, 0)[1] for pid in children]

    assert statuses == [0, 0]
    records = [json.loads(path.read_text(encoding="utf-8")) for path in outputs]
    assert len({record["root"] for record in records}) == 1
    assert len({record["run_id"] for record in records}) == 1
    assert len({record["marker"] for record in records}) == 1
    registry = results / f".{STUDY_ID}-launches"
    assert stat.S_IMODE(registry.stat().st_mode) == 0o700
    assert len(tuple(registry.glob("*.json"))) == 1


def test_frozen_class_launch_validation_keeps_its_historical_results_ancestor(
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
    _install_preclaim_authority(tmp_path, monkeypatch, campaign)
    root, _run_id, marker = orchestrator._claim_class_study_launch(
        campaign,
        results_root=results,
        source=_SOURCE,
        started_at=datetime(2026, 8, 28, tzinfo=UTC),
    )
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "source.json").write_text(
        json.dumps(_SOURCE, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    frozen = root / orchestrator.CLASS_STUDY_LAUNCH_INPUT
    frozen.write_bytes(marker.read_bytes())

    expected = sha256_file(frozen)
    assert orchestrator._validate_class_study_launch(root, campaign) == expected
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "different-live-checkout")
    assert orchestrator._validate_class_study_launch(root, campaign) == expected


@pytest.mark.parametrize("successor", (False, True))
@pytest.mark.parametrize(
    "mutation",
    ("missing", "mismatch", "symlink", "registry-symlink"),
)
def test_downstream_launch_validation_requires_exact_global_registry_marker(
    tmp_path: Path,
    successor: bool,
    mutation: str,
) -> None:
    """The frozen claim alone cannot establish the one-launch authority."""

    study_id = (
        "classifier-multiorigin100-v2-g01-0123456789ab"
        if successor
        else STUDY_ID
    )
    namespace = f".{study_id}-launches"
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        name=f"{study_id}-formal-01-1200",
        class_study_id=study_id,
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
        class_study_successor_sha256=("c" * 64 if successor else None),
        class_study_launch_namespace=namespace,
    )
    root = tmp_path / "results" / campaign.name / "run-001"
    inputs = root / "inputs"
    registry = root.parents[1] / namespace
    inputs.mkdir(parents=True)
    registry.mkdir()
    (inputs / "source.json").write_text(
        json.dumps(_SOURCE, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    value = orchestrator._bind_class_study_launch(
        orchestrator._class_study_launch_payload(
            campaign,
            result_root=root,
            source=_SOURCE,
            created_at="2026-08-28T00:00:00+00:00",
        )
    )
    frozen = inputs / orchestrator.CLASS_STUDY_LAUNCH_INPUT.removeprefix("inputs/")
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    frozen.write_text(encoded, encoding="utf-8")
    marker = registry / f"{value['payload']['launch_key']}.json"
    marker.write_text(encoded, encoding="utf-8")

    assert orchestrator._validate_class_study_launch(root, campaign) == sha256_file(frozen)
    if mutation == "registry-symlink":
        foreign = tmp_path / "foreign-launch-registry"
        registry.rename(foreign)
        registry.symlink_to(foreign, target_is_directory=True)
    else:
        marker.unlink()
        if mutation == "mismatch":
            marker.write_text("{}\n", encoding="utf-8")
        elif mutation == "symlink":
            marker.symlink_to(frozen)

    with pytest.raises(
        ValueError,
        match="launch registry is not a regular directory|global first-launch claim differs",
    ):
        orchestrator._validate_class_study_launch(root, campaign)


@pytest.mark.parametrize(
    ("role", "campaign_name"),
    (
        ("pilot-fitting", f"{STUDY_ID}-pilot-fitting-1200"),
        (
            "pilot-compatibility",
            f"{STUDY_ID}-pilot-compatibility-1080-1200",
        ),
        ("authoritative-fitting", f"{STUDY_ID}-authoritative-fitting-1200"),
        ("certification", f"{STUDY_ID}-certification-900-1200"),
        ("canary", f"{STUDY_ID}-canary-01-1200"),
        ("formal", f"{STUDY_ID}-formal-01-1200"),
    ),
)
def test_every_class_role_requires_foundation_before_global_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    campaign_name: str,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    results = tmp_path / "results"
    results.mkdir()
    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        name=campaign_name,
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
                "study_id": "classifier-multiorigin100-v2-g01-abcdef123456",
                "class_study_successor_sha256": "a" * 64,
            },
        ),
        (
            "qcsd-class-study-research-defense-bundle",
            {
                "study_id": "classifier-multiorigin100-v2-g01-0123456789ab",
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
        class_study_id="classifier-multiorigin100-v2-g01-0123456789ab",
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
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
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
                    "study_id": "classifier-multiorigin100-v2-g01-0123456789ab",
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
        name="classifier-multiorigin100-v2-g01-0123456789ab-formal-01-1200",
        workloads=(workload,),
        defenses=(defense,),
        class_study_id="classifier-multiorigin100-v2-g01-0123456789ab",
        class_study_cohort_sha256="c" * 64,
        class_study_cohort_assembly_sha256="d" * 64,
        class_study_successor_sha256="a" * 64,
        class_study_launch_namespace=(
            ".classifier-multiorigin100-v2-g01-0123456789ab-launches"
        ),
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
    from tests.test_buflo_study import _write_schema5_build_pair

    campaign = replace(
        _campaign(tuple(_workload(index) for index in range(100))),
        name="classifier-multiorigin100-v1-pilot-fitting-1200",
        evidence_role="pilot-fitting",
        class_study_cohort_sha256="a" * 64,
        class_study_cohort_assembly_sha256="b" * 64,
    )
    receipt_path = tmp_path / "build-execution-v47.json"
    receipt, completion_path, completion = _write_schema5_build_pair(
        receipt_path,
        cohort_version=47,
    )
    collection_image = receipt["images"]["collection"]["id"]
    environment = _study_environment(collection_image)
    environment["schema_version"] = 3
    environment["build_inputs"] = dict(receipt["build_inputs"])
    environment["build_execution"] = {
        "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "receipt": receipt,
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v47.json",
        "completion_sha256": hashlib.sha256(completion_path.read_bytes()).hexdigest(),
        "completion_payload_sha256": completion["payload_sha256"],
        "completion": completion,
    }
    validated_environment = buflo_study.validate_study_environment_receipt(
        environment,
        expected_image_digest=collection_image,
    )
    environment_build = validated_environment["build_execution"]
    build_identity = {
        key: environment_build[key]
        for key in (
            "cohort_version",
            "sha256",
            "completion_path",
            "completion_sha256",
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
        json.dumps(
            {"name": "classifier-multiorigin100-v2-g01-0123456789ab-formal-01-1200"}
        )
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


def test_successor_durable_campaign_recognition_uses_the_exact_generated_name() -> None:
    successor = "classifier-multiorigin100-v2-g01-0123456789ab"
    assert orchestrator._has_durable_attempt_name(
        f"{successor}-formal-01-1200"
    )
    for malformed in (
        "classifier-multiorigin100-v2-0123456789ab-formal-01-1200",
        "classifier-multiorigin100-v2-g00-0123456789ab-formal-01-1200",
        f"{successor}-formal-11-1200",
        f"{successor}-formal-01-1200-extra",
    ):
        assert not orchestrator._has_durable_attempt_name(malformed)


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
