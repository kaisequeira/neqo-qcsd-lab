from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
    TARGET_EGRESS_APIS,
    target_egress_apis,
)
from qcsd_lab.capture import ObserverPacket
from qcsd_lab.cdp_targets import (
    EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
    NORMAL_SHUTDOWN_DISPOSAL_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
)
from qcsd_lab.discovery_evidence import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
    REQUEST_STAGE_OBSERVATION_POLICY,
    RENDER_OBSERVATION_SCHEMA_VERSION,
    evidence_sha256,
    passive_render_contract,
)
from qcsd_lab.class_handoff import (
    _DIMENSIONS,
    CLASS_STUDY_HISTORICAL_POST_INPUT,
    CLASSIFIER_FIELDS,
    SCHEMA_VERSION,
    _export_class_handoff as _production_export_class_handoff,
    _dimensions_for_study,
    _read_classifier_trace,
    _StudyDimensions,
    _validate_sealed_workloads,
    _validate_source_results,
    _verify_class_handoff as _production_verify_class_handoff,
    _write_checksums,
)
from qcsd_lab.class_study import class_study_launch_identity, class_study_launch_key
from qcsd_lab.experiment import (
    KERNEL_TX_EVIDENCE_DIRECTORY,
    KERNEL_TX_EVIDENCE_FILES,
    KERNEL_TX_EVIDENCE_RECEIPT_KEY,
    KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
)
from qcsd_lab.manifest import canonical_bytes, runtime_manifest
from qcsd_lab.util import source_metadata
from qcsd_lab.verification import VerifiedResult
from tests.scheduler_fixtures import install_scheduler_runtime_receipt


def test_handoff_dimensions_reject_prefix_only_successor_identities() -> None:
    successor = "classifier-multiorigin100-v2-g01-0123456789ab"
    assert _dimensions_for_study(successor).study_id == successor
    for malformed in (
        "classifier-multiorigin100-v2-0123456789ab",
        "classifier-multiorigin100-v2-g00-0123456789ab",
        "classifier-multiorigin100-v2-g01-0123456789ab-extra",
    ):
        with pytest.raises(ValueError, match="study identity"):
            _dimensions_for_study(malformed)


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
            "worker": copy.deepcopy(worker_summary),
            "shared_worker": copy.deepcopy(worker_summary),
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


def _terminal_internal_document_lifecycle_summary() -> dict[str, object]:
    return {
        "schema_version": SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": SRCDOC_PSEUDO_DOCUMENT_POLICY,
        "enabled": True,
        "total": 0,
        "resolved": 0,
        "pending": 0,
        "aborted": 0,
        "open_candidates": 0,
        "network_history_saturated": False,
        "fetch_history_saturated": False,
        "candidate_limit_saturated": False,
        "terminal_outcome_counts": {
            "Network.loadingFailed": 0,
            "Network.loadingFinished": 0,
        },
        "diagnostics": [],
    }


_DIGEST = "a" * 64
_CLASSES = ("class-a", "class-b")
_MODES = ("undefended", "front")
_TINY = _StudyDimensions(
    study_id="classifier-tiny-v1",
    result_names=tuple(f"classifier-tiny-v1-formal-{block:02d}-1200" for block in range(1, 4)),
    modes=_MODES,
    runtime_kinds={"undefended": "none", "front": "front"},
    class_count=2,
    visits_per_block=1,
    require_immutable_source=False,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _value_sha256(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _prepared_workload(workload_id: str, origin_count: int) -> dict:
    origins = [f"https://origin-{index}.{workload_id}.example" for index in range(origin_count)]
    resources = [
        {
            "id": index,
            "url": f"{resource_origin}/resource-{index}",
            "type": "Document" if index == 0 else "Script",
            "depends_on": [] if index == 0 else [0],
            "headers": [],
        }
        for index, resource_origin in enumerate(origins)
    ]
    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
    }
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
                    "initiator_type": "other",
                    "initiator_request_id": None,
                    "safe_request_headers": resource["headers"],
                    "interception_required": True,
                    "redirected": False,
                    "redirect_from_occurrence_id": None,
                    "mapping": {"kind": "resource", "resource_id": resource_id},
                    "response_observed": True,
                    "interception_exception": None,
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
                    "failure": None,
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
        "internal_document_lifecycle_summary": (
            _terminal_internal_document_lifecycle_summary()
        ),
        "non_replayable_egress_summary": _non_replayable_egress_summary(),
        "browser_context_service_worker_count": 0,
        "cutoff_reason": "quiescent",
    }
    render_observation_sha256 = evidence_sha256(render_observation)
    discovery_event_audit = {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "request_stage_observation_policy": REQUEST_STAGE_OBSERVATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": render_observation_sha256,
        "normal_shutdown_disposal_summary": {
            "schema_version": NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
            "policy": NORMAL_SHUTDOWN_DISPOSAL_POLICY,
            "started": True,
            "terminal": True,
            "network_total": 0,
            "fetch_total": 0,
            "matched_total": 0,
            "network_only_synthetic_total": 0,
            "fetch_only_context_disposal_total": 0,
            "pending_network_total": 0,
            "pending_fetch_total": 0,
            "terminal_outcomes": {
                "Network.loadingFinished": 0,
                "Network.loadingFailed": 0,
                "Network.redirectResponse": 0,
                "qcsd-shutdown": 0,
            },
        },
        "events": events,
        "summary": {
            "event_count": len(events),
            "target_event_count": 0,
            "browser_internal_document_count": 0,
            "network_request_count": len(resources),
            "fetch_request_count": len(resources),
            "fetch_internal_restart_count": 0,
            "terminal_event_count": len(resources),
            "resource_occurrence_count": len(resources),
            "exclusion_occurrence_count": 0,
            "blocked_preflight_dependent_count": 0,
        },
    }
    discovery_event_audit_sha256 = evidence_sha256(discovery_event_audit)
    origin_ip_pins = {value: "1.1.1.1" for value in sorted(origins)}
    browser_request_headers = [
        {"resource_id": resource["id"], "headers": resource["headers"]}
        for resource in resources
    ]
    return {
        "preparation": {
            "source_url": resources[0]["url"],
            "final_url": resources[0]["url"],
            "chromium_version": "test-chromium",
            "settle_ms": 10_000,
            "observed_request_count": len(resources),
            "observed_origins": origins,
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
            "max_response_bytes": 1_048_576,
            "timeout_seconds": 30,
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
                    "bytes": 100 + resource["id"],
                    "body_sha256": f"{resource['id'] + 1:064x}",
                }
                for resource in resources
            ],
            "lab_source": source,
            "prepare_image_digest": source["image_digest"],
            "coverage_admission": {
                "schema_version": 3,
                "policy": "all-approved-origins-and-rendered-resources",
                "required_origins": origins,
                "required_resources": [
                    {"id": resource["id"], "url": resource["url"]} for resource in resources
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


def _run_graph_evidence(manifest: dict) -> dict:
    resources = manifest["resources"]
    expected = manifest["preparation"]["expected_responses"]
    origins = tuple(dict.fromkeys(resource["url"].rsplit("/", 1)[0] for resource in resources))
    return {
        "endpoints": [{"origin": value + "/"} for value in origins],
        "responses": [
            {
                **response,
                "complete": True,
                "outcome": "succeeded",
            }
            for response in expected
        ],
    }


def _source_receipt(root: Path, block: int) -> VerifiedResult:
    root.mkdir()
    (root / "inputs/workloads").mkdir(parents=True)
    _write(root / "inputs/campaign.yml", b"schema: 2\n")
    cohort = {"payload_sha256": "f" * 64, "fixture": True}
    _write(
        root / "inputs/class-study-cohort.json",
        (json.dumps(cohort, sort_keys=True) + "\n").encode(),
    )
    workloads = []
    for workload_id in _CLASSES:
        workload_path = root / f"inputs/workloads/{workload_id}.json"
        runtime_path = root / f"inputs/runtime-workloads/{workload_id}.json"
        qualification_path = root / f"inputs/chaff-qualifications/{workload_id}.json"
        chaff_path = root / f"inputs/chaff-manifests/{workload_id}.json"
        origin_count = 1 if workload_id == "class-a" else 3
        manifest = _prepared_workload(workload_id, origin_count)
        resources = manifest["resources"]
        _write(
            workload_path,
            (json.dumps(manifest, sort_keys=True) + "\n").encode(),
        )
        _write(runtime_path, canonical_bytes(runtime_manifest(manifest)))
        _write(
            qualification_path,
            (json.dumps({"workload_id": workload_id, "qualified": True}) + "\n").encode(),
        )
        _write(
            chaff_path,
            (json.dumps({"workload_id": workload_id, "responses": []}) + "\n").encode(),
        )
        workloads.append(
            {
                "id": workload_id,
                "visits": 1,
                "manifest": f"inputs/workloads/{workload_id}.json",
                "sha256": _sha256(workload_path),
                "runtime_manifest": f"inputs/runtime-workloads/{workload_id}.json",
                "runtime_manifest_sha256": _sha256(runtime_path),
                "chaff_qualification": f"inputs/chaff-qualifications/{workload_id}.json",
                "chaff_qualification_sha256": _sha256(qualification_path),
                "chaff_manifest": f"inputs/chaff-manifests/{workload_id}.json",
                "chaff_manifest_sha256": _sha256(chaff_path),
                "resource_count": len(resources),
                "origin_count": origin_count,
            }
        )
    assembly = {
        "payload_sha256": "e" * 64,
        "candidates": [
            {
                "candidate_id": record["id"],
                "eligible": True,
                "prepared_workload": {"sha256": record["sha256"]},
            }
            for record in workloads
        ],
    }
    _write(
        root / "inputs/class-study-cohort-assembly.json",
        (json.dumps(assembly, sort_keys=True) + "\n").encode(),
    )
    authority_inputs = {
        "inputs/class-study-foundation.json": b"sealed foundation authority\n",
        "inputs/class-study-readiness.json": b"sealed readiness authority\n",
        "inputs/class-study-historical-pre-snapshot.json": (b"sealed historical-pre authority\n"),
    }
    for relative, value in authority_inputs.items():
        _write(root / relative, value)

    samples = []
    checksums = {
        "inputs/campaign.yml": _sha256(root / "inputs/campaign.yml"),
        "inputs/class-study-cohort.json": _sha256(root / "inputs/class-study-cohort.json"),
        "inputs/class-study-cohort-assembly.json": _sha256(
            root / "inputs/class-study-cohort-assembly.json"
        ),
        **{relative: _sha256(root / relative) for relative in authority_inputs},
        **{
            str(record[key]): _sha256(root / str(record[key]))
            for record in workloads
            for key in ("manifest", "runtime_manifest", "chaff_qualification", "chaff_manifest")
        },
    }
    for class_index, workload_id in enumerate(_CLASSES):
        for mode_index, mode in enumerate(_MODES):
            sample_id = f"b{block:02d}-{workload_id}-{mode}"
            relative_root = f"samples/{workload_id}/as-defined/visit-000/{mode}"
            sample_root = root / relative_root
            workload = next(record for record in workloads if record["id"] == workload_id)
            manifest = json.loads((root / workload["manifest"]).read_text(encoding="utf-8"))
            baseline = mode == "undefended"
            runtime_kind = "none" if baseline else "front"
            seed = block * 100 + class_index * 10 + mode_index
            _write(sample_root / "capture.pcapng", b"pcapng fixture\n")
            run = {
                "completion_status": "complete",
                "error": None,
                **_run_graph_evidence(manifest),
                "seed": seed,
                "request_policy": "as-defined",
                "workload_hash_sha256": workload["runtime_manifest_sha256"],
                "max_response_bytes": 1_048_576,
                "resolved_configuration": {
                    "max_udp_payload_size": 1_200,
                    "defense": {"kind": runtime_kind},
                },
                "application_workload_source_hash_sha256": (
                    None if baseline else workload["sha256"]
                ),
                "chaff_manifest_hash_sha256": (
                    None if baseline else workload["chaff_manifest_sha256"]
                ),
                "defense_parameters": None,
            }
            diagnostics: dict = {}
            install_scheduler_runtime_receipt(run, diagnostics)
            _write(
                sample_root / "neqo/run.json",
                (json.dumps(run, sort_keys=True) + "\n").encode(),
            )
            _write(sample_root / "neqo/schedule.csv", b"schedule\n")
            _write(sample_root / "neqo/events.csv", b"events\n")
            _write(sample_root / "neqo/packets.csv", b"packets\n")
            artifacts = {
                f"{relative_root}/{relative}": _sha256(sample_root / relative)
                for relative in (
                    "capture.pcapng",
                    "neqo/run.json",
                    "neqo/schedule.csv",
                    "neqo/events.csv",
                    "neqo/packets.csv",
                )
            }
            checksums.update(artifacts)
            samples.append(
                {
                    "sample_id": sample_id,
                    "workload_id": workload_id,
                    "request_policy": "as-defined",
                    "visit": 0,
                    "defense": mode,
                    "runtime_kind": runtime_kind,
                    "baseline": baseline,
                    "seed": seed,
                    "path": relative_root,
                    "state": "accepted",
                    "attempts": 1,
                    "eligible": True,
                    "failure": None,
                    "diagnostics": diagnostics,
                    "artifacts": artifacts,
                }
            )

    _write(root / "evidence.sha256", b"sealed fixture\n")
    configuration = {
        "campaign_sha256": _sha256(root / "inputs/campaign.yml"),
        "profile": "research-1200",
        "request_policies": ["as-defined"],
        "workloads": workloads,
        "defenses": [
            {"name": "undefended", "kind": "none", "baseline": True},
            {"name": "front", "kind": "front", "baseline": False},
        ],
        "limits": {"max_attempts": 3, "max_response_bytes": 1_048_576},
        "defense_order": {"scheme": "cyclic-latin-square", "block": block - 1},
        "evidence_role": "formal",
        "class_study_foundation_sha256": _sha256(root / "inputs/class-study-foundation.json"),
        "class_study_readiness_sha256": _sha256(root / "inputs/class-study-readiness.json"),
        "class_study_historical_pre_snapshot_sha256": _sha256(
            root / "inputs/class-study-historical-pre-snapshot.json"
        ),
        "defense_runtime_inputs": {
            "undefended": {
                "identity_type": "source-bound-no-defense",
                "runtime_kind": "none",
            },
            "front": {
                "identity_type": "source-bound-built-in",
                "runtime_kind": "front",
            },
        },
        "chaff_qualification_set": "fixture-final-qualification-v1",
        "chaff_qualification_set_manifest_sha256": "d" * 64,
        "class_study_cohort_sha256": _sha256(root / "inputs/class-study-cohort.json"),
        "class_study_cohort_assembly_sha256": _sha256(
            root / "inputs/class-study-cohort-assembly.json"
        ),
    }
    started_at = f"2026-08-{block:02d}T00:00:00+00:00"
    source = source_metadata()
    launch_identity = class_study_launch_identity(
        study_id=_TINY.study_id,
        campaign_name=_TINY.result_names[block - 1],
        evidence_role="formal",
        cohort_sha256=configuration["class_study_cohort_sha256"],
        cohort_assembly_sha256=configuration["class_study_cohort_assembly_sha256"],
    )
    launch_payload = {
        "study_id": _TINY.study_id,
        "launch_key": class_study_launch_key(**launch_identity),
        "campaign_name": _TINY.result_names[block - 1],
        "campaign_sha256": configuration["campaign_sha256"],
        "evidence_role": "formal",
        "class_study_cohort_sha256": configuration["class_study_cohort_sha256"],
        "class_study_cohort_assembly_sha256": configuration["class_study_cohort_assembly_sha256"],
        "result_root": str(root.resolve()),
        "created_at": started_at,
        "source": source,
        "policy": "one-result-root-per-campaign-and-cohort-assembly",
    }
    launch = {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-first-launch-claim",
        "payload_sha256": _value_sha256(launch_payload),
        "payload": launch_payload,
    }
    launch_path = root / "inputs/class-study-launch.json"
    _write(launch_path, (json.dumps(launch, indent=2, sort_keys=True) + "\n").encode())
    checksums["inputs/class-study-launch.json"] = _sha256(launch_path)
    configuration["class_study_launch_sha256"] = _sha256(launch_path)
    experiment = {
        "schema_version": 1,
        "name": _TINY.result_names[block - 1],
        "purpose": "evaluation",
        "status": "complete",
        "started_at": started_at,
        "completed_at": f"2026-08-{block:02d}T00:30:00+00:00",
        "input_digest": _DIGEST,
        "source": source,
        "configuration": configuration,
        "execution_order": [sample["sample_id"] for sample in samples],
        "samples": samples,
        "summary": {
            "planned": 4,
            "accepted": 4,
            "failed": 0,
            "eligible": 4,
            "passed": True,
        },
    }
    return VerifiedResult(
        root=root.resolve(),
        experiment=experiment,
        checksums=checksums,
        accepted_samples={sample["sample_id"]: sample["artifacts"] for sample in samples},
    )


def _cohort_loader(_path: Path):
    return (
        {"payload_sha256": "f" * 64},
        SimpleNamespace(final=tuple(SimpleNamespace(candidate_id=value) for value in _CLASSES)),
    )


def _assembly_validator(value, **_kwargs):
    return value


def _trace(_path: Path, _endpoints) -> list[ObserverPacket]:
    return [
        ObserverPacket(10, 0, "outgoing", 120, 120, 78),
        ObserverPacket(20, 10, "incoming", 140, -140, 98),
    ]


def _classic_writer(_source: Path, destination: Path) -> None:
    destination.write_bytes(b"classic fixture\n")


def _correctness_validator(*_args, **_kwargs) -> None:
    return None


def _performance_extractor(_run, trace) -> dict:
    return {
        "schema_version": 1,
        "application_duration_ns": 1_000_000,
        "application_response_bytes": 100,
        "wire_bytes": {
            direction: sum(packet.frame_len for packet in trace if packet.direction == direction)
            for direction in ("outgoing", "incoming")
        },
        "packet_count": {
            direction: sum(packet.direction == direction for packet in trace)
            for direction in ("outgoing", "incoming")
        },
        "udp_payload_bytes": {
            direction: sum(
                packet.udp_payload_len
                for packet in trace
                if packet.direction == direction and packet.udp_payload_len is not None
            )
            for direction in ("outgoing", "incoming")
        },
        "udp_payload_lengths_missing": {"outgoing": 0, "incoming": 0},
        "client_resource_usage": {
            "schema_version": 1,
            "source": "fixture",
            "user_cpu_seconds": 0.1,
            "system_cpu_seconds": 0.1,
            "wall_time_seconds": 0.2,
            "maximum_rss_bytes": 1024,
            "voluntary_context_switches": 1,
            "involuntary_context_switches": 0,
            "timer_wakeups": None,
            "timer_wakeups_unavailable_reason": "fixture unavailable",
            "rapl_energy_joules": None,
            "rapl_unavailable_reason": "fixture unavailable",
        },
        "transport_retransmissions": 0,
    }


def _fixture(tmp_path: Path):
    receipts = tuple(
        _source_receipt(tmp_path / f"result-{block:02d}", block) for block in range(1, 4)
    )
    by_root = {receipt.root: receipt for receipt in receipts}

    def verify(path: Path) -> VerifiedResult:
        return by_root[Path(path).resolve()]

    return receipts, verify


def _fixture_post_snapshot(
    receipts: tuple[VerifiedResult, ...],
    dimensions: _StudyDimensions,
) -> Path:
    """Write the exact post-formal authority expected by the handoff seam."""

    formal_results = []
    for receipt in receipts:
        configuration = receipt.experiment["configuration"]
        binding = {
            "root": str(receipt.root.resolve()),
            "evidence_sha256": _sha256(receipt.root / "evidence.sha256"),
            "class_study_launch_sha256": configuration["class_study_launch_sha256"],
            "class_study_foundation_sha256": configuration[
                "class_study_foundation_sha256"
            ],
            "class_study_readiness_sha256": configuration[
                "class_study_readiness_sha256"
            ],
            "class_study_historical_pre_snapshot_sha256": configuration[
                "class_study_historical_pre_snapshot_sha256"
            ],
        }
        successor_sha256 = configuration.get("class_study_successor_sha256")
        if successor_sha256 is not None:
            binding.update(
                class_study_id=configuration["class_study_id"],
                class_study_successor_sha256=successor_sha256,
            )
        formal_results.append(binding)
    payload = {
        "phase": "post-formal",
        "study_id": dimensions.study_id,
        "recorded_at": "2026-09-30T00:00:00+00:00",
        "source": receipts[0].experiment["source"],
        "readiness": {
            "sha256": receipts[0].experiment["configuration"][
                "class_study_readiness_sha256"
            ]
        },
        "pre_formal_snapshot": {
            "sha256": receipts[0].experiment["configuration"][
                "class_study_historical_pre_snapshot_sha256"
            ]
        },
        "formal_results": formal_results,
        "payload_sha256": "9" * 64,
    }
    path = receipts[0].root.parent / f"{dimensions.study_id}-historical-post.json"
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _fixture_post_validator(path: Path, *, expected_phase: str) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert expected_phase == "post-formal"
    return {"path": str(path.resolve()), "sha256": _sha256(path), **payload}


def _export_class_handoff(result_roots, destination, **kwargs):
    """Exercise the production seam with exact compact-fixture post authority."""

    verifier = kwargs["source_verifier"]
    dimensions = kwargs["dimensions"]
    receipts = tuple(verifier(Path(root)) for root in result_roots)
    kwargs.setdefault(
        "historical_post_snapshot",
        _fixture_post_snapshot(receipts, dimensions),
    )
    kwargs.setdefault("historical_post_validator", _fixture_post_validator)
    return _production_export_class_handoff(result_roots, destination, **kwargs)


def _verify_class_handoff(path, **kwargs):
    """Exercise the production verifier with the compact receipt validator."""

    kwargs.setdefault("historical_post_validator", _fixture_post_validator)
    return _production_verify_class_handoff(path, **kwargs)


def _bind_fixture_run(receipt: VerifiedResult, sample: dict) -> None:
    configuration = receipt.experiment["configuration"]
    workload = next(
        record for record in configuration["workloads"] if record["id"] == sample["workload_id"]
    )
    defense = next(
        record for record in configuration["defenses"] if record["name"] == sample["defense"]
    )
    run_path = receipt.root / sample["path"] / "neqo/run.json"
    run = json.loads(run_path.read_text(encoding="utf-8"))
    resolved = run.get("resolved_configuration")
    manifest = json.loads((receipt.root / workload["manifest"]).read_text(encoding="utf-8"))
    run.update(
        **_run_graph_evidence(manifest),
        completion_status="complete",
        error=None,
        seed=sample["seed"],
        request_policy=sample["request_policy"],
        workload_hash_sha256=workload["runtime_manifest_sha256"],
        max_response_bytes=configuration["limits"]["max_response_bytes"],
        resolved_configuration={
            **(resolved if isinstance(resolved, dict) else {}),
            "max_udp_payload_size": 1_200,
            "defense": {"kind": sample["runtime_kind"]},
        },
        application_workload_source_hash_sha256=(
            None if sample["baseline"] else workload["sha256"]
        ),
        chaff_manifest_hash_sha256=(
            None if sample["baseline"] else workload["chaff_manifest_sha256"]
        ),
        defense_parameters=(
            None
            if defense.get("parameters_sha256") is None
            else {
                "kind": sample["runtime_kind"],
                "sha256": defense["parameters_sha256"],
            }
        ),
    )
    install_scheduler_runtime_receipt(run, sample["diagnostics"])
    run_path.write_text(json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")


def _candidate_fixture(
    tmp_path: Path,
    *,
    mode: str,
    runtime_kind: str,
    install_evidence,
):
    dimensions = _StudyDimensions(
        study_id=_TINY.study_id,
        result_names=_TINY.result_names,
        modes=("undefended", mode),
        runtime_kinds={"undefended": "none", mode: runtime_kind},
        class_count=_TINY.class_count,
        visits_per_block=_TINY.visits_per_block,
        require_immutable_source=False,
    )
    receipts, _ = _fixture(tmp_path)
    for receipt in receipts:
        configuration = receipt.experiment["configuration"]
        parameter_relative = f"inputs/defense-parameters/{mode}/parameters.json"
        provenance_relative = f"inputs/defense-parameters/{mode}/provenance.json"
        parameter_path = receipt.root / parameter_relative
        provenance_path = receipt.root / provenance_relative
        _write(parameter_path, (json.dumps({"mode": mode}, sort_keys=True) + "\n").encode())
        _write(
            provenance_path,
            (json.dumps({"mode": mode, "provenance": "fixture"}, sort_keys=True) + "\n").encode(),
        )
        parameter_sha256 = _sha256(parameter_path)
        provenance_sha256 = _sha256(provenance_path)
        receipt.checksums[parameter_relative] = parameter_sha256
        receipt.checksums[provenance_relative] = provenance_sha256
        configuration["defenses"][1] = {
            "name": mode,
            "kind": runtime_kind,
            "baseline": False,
            "parameters": parameter_relative,
            "parameters_sha256": parameter_sha256,
            "provenance": provenance_relative,
            "provenance_sha256": provenance_sha256,
            "input_policy": "fixture-current-candidate",
        }
        configuration["defense_runtime_inputs"].pop("front")
        configuration["defense_runtime_inputs"][mode] = {
            "identity_type": "hash-bound-parameter-artifact",
            "runtime_kind": runtime_kind,
            "parameters_sha256": parameter_sha256,
            "provenance_sha256": provenance_sha256,
            "input_policy": "fixture-current-candidate",
        }
        for sample in receipt.experiment["samples"]:
            if sample["defense"] != "front":
                continue
            sample["defense"] = mode
            sample["runtime_kind"] = runtime_kind
            sample_root = receipt.root / sample["path"]
            install_evidence(sample_root)
            _bind_fixture_run(receipt, sample)
            if runtime_kind == "buflo":
                _install_kernel_tx_sidecar(receipt, sample)
            for name in ("run.json", "schedule.csv", "events.csv", "packets.csv"):
                path = sample_root / "neqo" / name
                relative = path.relative_to(receipt.root).as_posix()
                digest = _sha256(path)
                sample["artifacts"][relative] = digest
                receipt.checksums[relative] = digest
                receipt.accepted_samples[sample["sample_id"]][relative] = digest

    by_root = {receipt.root: receipt for receipt in receipts}

    def verify(path: Path) -> VerifiedResult:
        return by_root[Path(path).resolve()]

    return dimensions, receipts, verify


def _install_kernel_tx_sidecar(receipt: VerifiedResult, sample: dict) -> None:
    directory = f"{KERNEL_TX_EVIDENCE_DIRECTORY}/{sample['sample_id']}"
    artifacts: dict[str, str] = {}
    for name in sorted(KERNEL_TX_EVIDENCE_FILES):
        path = receipt.root / directory / name
        _write(path, f"{sample['sample_id']}:{name}\n".encode())
        digest = _sha256(path)
        artifacts[name] = digest
        receipt.checksums[f"{directory}/{name}"] = digest
    sample["diagnostics"][KERNEL_TX_EVIDENCE_RECEIPT_KEY] = {
        "schema_version": KERNEL_TX_EVIDENCE_RECEIPT_SCHEMA_VERSION,
        "source": KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
        "directory": directory,
        "artifacts": artifacts,
    }


def _write_runner_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _candidate_schedule_schema(fields: tuple[str, ...]) -> str:
    assert "terminal_defense_elapsed_us" in fields
    return "3"


def _install_buflo_candidate_evidence(sample_root: Path) -> None:
    from qcsd_lab import buflo_handoff
    from qcsd_lab.fidelity import SCHEDULE_QCSD_FIELDS
    from tests.test_buflo_handoff import _complete_buflo_run

    run = _complete_buflo_run(scheduled_outgoing=1, scheduled_incoming=1)
    run["endpoints"] = [{"fixture": True}]
    (sample_root / "neqo/run.json").write_text(
        json.dumps(run, sort_keys=True) + "\n", encoding="utf-8"
    )
    schedule_fields = (*buflo_handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    schedule_schema = _candidate_schedule_schema(schedule_fields)
    outgoing = {field: "" for field in schedule_fields}
    outgoing.update(
        target_time_us="0",
        direction="outgoing",
        size="1200",
        connection="0",
        action_time_us="4999",
        satisfaction="satisfied",
        observed_size="1200",
        slot_id="1",
        qcsd_outcome_schema_version=schedule_schema,
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        terminal_defense_elapsed_us="4999",
    )
    incoming = {field: "" for field in schedule_fields}
    incoming.update(
        target_time_us="0",
        direction="incoming",
        size="1200",
        connection="0",
        action_time_us="0",
        satisfaction="satisfied",
        slot_id="2",
        qcsd_outcome_schema_version=schedule_schema,
        send_policy="exact",
        desired_udp_bytes="1200",
        credit_advertised_at_us="0",
        credit_advertisement_delay_us="0",
        credit_consumed_at_us="10000000",
        credit_consumption_delay_us="10000000",
        terminal_defense_elapsed_us="10000000",
    )
    _write_runner_rows(sample_root / "neqo/schedule.csv", schedule_fields, [outgoing, incoming])
    _write_runner_rows(
        sample_root / "neqo/events.csv",
        (*buflo_handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS),
        [],
    )
    packet_fields = (*buflo_handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    packet = {field: "" for field in packet_fields}
    packet.update(
        direction="outgoing",
        monotonic_us="4999",
        connection="0",
        observed_udp_length="1200",
        scheduled_target="1200",
        satisfaction="satisfied",
        slot_id="1",
        qcsd_outcome_schema_version="2",
        send_policy="exact",
        desired_udp_bytes="1200",
        observed_udp_bytes="1200",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="1200",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="0",
    )
    _write_runner_rows(sample_root / "neqo/packets.csv", packet_fields, [packet])


def _install_cs_buflo_candidate_evidence(sample_root: Path) -> None:
    from qcsd_lab import buflo_handoff
    from qcsd_lab.fidelity import SCHEDULE_QCSD_FIELDS
    from tests.test_buflo_handoff import _complete_cs_buflo_run

    run = _complete_cs_buflo_run()
    run["endpoints"] = [{"fixture": True}]
    (sample_root / "neqo/run.json").write_text(
        json.dumps(run, sort_keys=True) + "\n", encoding="utf-8"
    )
    schedule_fields = (*buflo_handoff.SCHEDULE_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    schedule_schema = _candidate_schedule_schema(schedule_fields)
    outgoing = {field: "" for field in schedule_fields}
    outgoing.update(
        target_time_us="50",
        direction="outgoing",
        size="600",
        connection="0",
        action_time_us="150",
        satisfaction="full",
        observed_size="600",
        slot_id="1",
        qcsd_outcome_schema_version=schedule_schema,
        send_policy="congestion_sensitive",
        desired_udp_bytes="600",
        observed_udp_bytes="600",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="600",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="100",
        terminal_defense_elapsed_us="150",
    )
    incoming = {field: "" for field in schedule_fields}
    incoming.update(
        target_time_us="50",
        direction="incoming",
        size="600",
        connection="0",
        action_time_us="50",
        satisfaction="satisfied",
        slot_id="2",
        qcsd_outcome_schema_version=schedule_schema,
        send_policy="exact",
        desired_udp_bytes="600",
        credit_advertised_at_us="150",
        credit_advertisement_delay_us="100",
        credit_consumed_at_us="250",
        credit_consumption_delay_us="200",
        terminal_defense_elapsed_us="250",
    )
    _write_runner_rows(sample_root / "neqo/schedule.csv", schedule_fields, [outgoing, incoming])
    _write_runner_rows(
        sample_root / "neqo/events.csv",
        (*buflo_handoff._EVENT_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS),
        [],
    )
    packet_fields = (*buflo_handoff._PACKET_PREFIX_FIELDS, *SCHEDULE_QCSD_FIELDS)
    packet = {field: "" for field in packet_fields}
    packet.update(
        direction="outgoing",
        monotonic_us="150",
        connection="0",
        observed_udp_length="600",
        scheduled_target="600",
        satisfaction="full",
        slot_id="1",
        qcsd_outcome_schema_version="2",
        send_policy="congestion_sensitive",
        desired_udp_bytes="600",
        observed_udp_bytes="600",
        application_stream_bytes="0",
        retransmission_stream_bytes="0",
        chaff_stream_bytes="600",
        defense_control_bytes="0",
        quic_padding_bytes="0",
        other_quic_bytes="0",
        lateness_us="100",
    )
    _write_runner_rows(sample_root / "neqo/packets.csv", packet_fields, [packet])


def _reseal_source_sample_file(receipt: VerifiedResult, sample: dict, path: Path) -> None:
    relative = path.relative_to(receipt.root).as_posix()
    digest = _sha256(path)
    sample["artifacts"][relative] = digest
    receipt.checksums[relative] = digest
    receipt.accepted_samples[sample["sample_id"]][relative] = digest


def _export_candidate_fixture(
    destination: Path,
    *,
    dimensions: _StudyDimensions,
    receipts: tuple[VerifiedResult, ...],
    verify,
) -> Path:
    return _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        historical_post_snapshot=_fixture_post_snapshot(receipts, dimensions),
        dimensions=dimensions,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
        historical_post_validator=_fixture_post_validator,
    )


def _verify_candidate_fixture(
    destination: Path,
    *,
    dimensions: _StudyDimensions,
    verify,
    deep: bool,
) -> Path:
    return _verify_class_handoff(
        destination,
        dimensions=dimensions,
        deep=deep,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
        historical_post_validator=_fixture_post_validator,
    )


def test_default_contract_is_exactly_ten_blocks_and_16000_samples() -> None:
    assert SCHEMA_VERSION == 3
    assert _DIMENSIONS.block_count == 10
    assert _DIMENSIONS.class_count == 100
    assert _DIMENSIONS.visits_per_block == 2
    assert len(_DIMENSIONS.modes) == 8
    assert _DIMENSIONS.sample_count == 16_000
    assert _DIMENSIONS.result_names[0] == "classifier-multiorigin100-v1-formal-01-1200"
    assert _DIMENSIONS.result_names[-1] == "classifier-multiorigin100-v1-formal-10-1200"


def test_compact_export_is_create_only_closed_and_deeply_verifiable(tmp_path: Path) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"

    result = _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )

    assert result == destination.resolve()
    assert (
        _verify_class_handoff(
            result,
            dimensions=_TINY,
            deep=True,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )
        == result
    )
    dataset = json.loads((result / "dataset.json").read_text(encoding="utf-8"))
    assert dataset["schema_version"] == 3
    post_snapshot = result / CLASS_STUDY_HISTORICAL_POST_INPUT
    assert dataset["historical_post_snapshot"] == {
        "path": CLASS_STUDY_HISTORICAL_POST_INPUT,
        "sha256": _sha256(post_snapshot),
        "payload_sha256": "9" * 64,
    }
    assert dataset["sample_count"] == 12
    assert dataset["counts_by_mode"] == {"front": 6, "undefended": 6}
    assert dataset["counts_by_split"] == {
        "train": 4,
        "validation": 4,
        "test": 4,
    }
    assert dataset["role_exclusion"]["excluded_modes"] == ["static"]
    assert dataset["resource_origin_profile"] == {
        "policy": {
            "single_origin_allowed": True,
            "multi_origin_allowed": True,
            "selection_uses_origin_count": False,
            "minimum_multi_origin_classes": 0,
        },
        "single_origin_class_count": 1,
        "multi_origin_class_count": 1,
        "minimum_origin_count": 1,
        "maximum_origin_count": 3,
        "classes_by_origin_count": {"1": 1, "3": 1},
        "class_origin_counts": [
            {"class_id": "class-a", "origin_count": 1},
            {"class_id": "class-b", "origin_count": 3},
        ],
    }
    assert dataset["observation"]["classifier_fields"] == list(CLASSIFIER_FIELDS)
    assert [block["sha256"] for block in dataset["class_study_launches"]["blocks"]] == [
        receipt.experiment["configuration"]["class_study_launch_sha256"] for receipt in receipts
    ]
    assert dataset["capture_authority"] == {
        "foundation": {
            "path": "inputs/class-study-foundation.json",
            "sha256": receipts[0].experiment["configuration"]["class_study_foundation_sha256"],
        },
        "readiness": {
            "path": "inputs/class-study-readiness.json",
            "sha256": receipts[0].experiment["configuration"]["class_study_readiness_sha256"],
        },
        "historical_pre_snapshot": {
            "path": "inputs/class-study-historical-pre-snapshot.json",
            "sha256": receipts[0].experiment["configuration"][
                "class_study_historical_pre_snapshot_sha256"
            ],
        },
    }
    assert (
        dataset["runtime_contract"]["defense_runtime_inputs"]
        == (receipts[0].experiment["configuration"]["defense_runtime_inputs"])
    )
    assert (
        dataset["runtime_contract"]["chaff_qualification_set_manifest_sha256"]
        == receipts[0].experiment["configuration"]["chaff_qualification_set_manifest_sha256"]
    )
    assert len(list((result / "inputs/class-study-launches").glob("block-*.json"))) == 3
    trace_path = next((result / "traces").rglob("*.csv"))
    assert trace_path.read_text(encoding="utf-8").splitlines()[0] == ",".join(CLASSIFIER_FIELDS)
    assert len(list((result / "raw").rglob("capture.pcapng"))) == 12
    assert len(list((result / "raw").rglob("run.json"))) == 12
    assert len(list((result / "raw").rglob("schedule.csv"))) == 12
    assert len(list((result / "raw").rglob("events.csv"))) == 12
    assert len(list((result / "raw").rglob("packets.csv"))) == 12
    assert len(list((result / "raw").rglob("capture.pcap"))) == 12
    first_row = json.loads((result / "samples.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert first_row["schema_version"] == 3
    assert first_row["kernel_tx_evidence"] is None
    assert set(first_row["input_bindings"]) == {
        "campaign_sha256",
        "application_workload_sha256",
        "runtime_workload_sha256",
        "chaff_qualification_sha256",
        "chaff_manifest_sha256",
        "defense_parameters_sha256",
        "defense_parameters_provenance_sha256",
        "max_response_bytes",
        "max_udp_payload_size",
    }
    assert "Schema 3" in (result / "README.md").read_text(encoding="utf-8")
    assert first_row["correctness"]["passed"] is True
    assert first_row["performance"]["udp_payload_lengths_missing"] == {
        "outgoing": 0,
        "incoming": 0,
    }

    with pytest.raises(FileExistsError, match="already exists"):
        _export_class_handoff(
            [receipt.root for receipt in receipts],
            destination,
            dimensions=_TINY,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


def test_export_requires_a_verified_post_formal_snapshot(tmp_path: Path) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"

    with pytest.raises(ValueError, match="historical-post snapshot"):
        _production_export_class_handoff(
            [receipt.root for receipt in receipts],
            destination,
            historical_post_snapshot=tmp_path / "missing-post.json",
            dimensions=_TINY,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
            historical_post_validator=_fixture_post_validator,
        )
    assert not destination.exists()


def test_verifier_rejects_resealed_post_snapshot_block_substitution(tmp_path: Path) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = _export_class_handoff(
        [receipt.root for receipt in receipts],
        tmp_path / "handoff",
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    post_path = destination / CLASS_STUDY_HISTORICAL_POST_INPUT
    post = json.loads(post_path.read_text(encoding="utf-8"))
    post["formal_results"][0]["root"] = str(receipts[1].root)
    post_path.write_text(json.dumps(post, sort_keys=True) + "\n", encoding="utf-8")
    dataset_path = destination / "dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    dataset["historical_post_snapshot"]["sha256"] = _sha256(post_path)
    dataset_path.write_text(json.dumps(dataset, sort_keys=True) + "\n", encoding="utf-8")
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match="exact source blocks"):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=False,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


@pytest.mark.parametrize(
    ("mode", "runtime_kind", "installer"),
    [
        ("buflo", "buflo", _install_buflo_candidate_evidence),
        ("cs-buflo", "cs_buflo", _install_cs_buflo_candidate_evidence),
    ],
)
def test_direct_deep_verifier_reopens_current_candidate_algorithm_evidence(
    tmp_path: Path, mode: str, runtime_kind: str, installer
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode=mode,
        runtime_kind=runtime_kind,
        install_evidence=installer,
    )
    destination = _export_candidate_fixture(
        tmp_path / "handoff",
        dimensions=dimensions,
        receipts=receipts,
        verify=verify,
    )

    assert (
        _verify_candidate_fixture(
            destination,
            dimensions=dimensions,
            verify=verify,
            deep=True,
        )
        == destination.resolve()
    )


def test_buflo_kernel_tx_sidecars_are_separate_and_fully_bound(tmp_path: Path) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode="buflo",
        runtime_kind="buflo",
        install_evidence=_install_buflo_candidate_evidence,
    )
    destination = _export_candidate_fixture(
        tmp_path / "handoff",
        dimensions=dimensions,
        receipts=receipts,
        verify=verify,
    )
    rows = [
        json.loads(line)
        for line in (destination / "samples.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    buflo_rows = [row for row in rows if row["runtime_kind"] == "buflo"]
    assert len(buflo_rows) == 6
    assert all(row["kernel_tx_evidence"] is None for row in rows if row not in buflo_rows)
    assert not list((destination / "raw").rglob("router-capture.pcapng"))
    for row in buflo_rows:
        run = json.loads((destination / row["products"]["run"]["path"]).read_text())
        assert run["runner_wakeup_metrics"]["schema_version"] == 15
        assert set(row["source"]["artifacts"]) == {
            "pcapng",
            "run",
            "schedule",
            "events",
            "packets",
        }
        binding = row["kernel_tx_evidence"]
        assert binding["schema_version"] == 1
        assert binding["source_receipt"]["diagnostics_key"] == (
            KERNEL_TX_EVIDENCE_RECEIPT_KEY
        )
        assert set(binding["artifacts"]) == KERNEL_TX_EVIDENCE_FILES
        for artifact in binding["artifacts"].values():
            copied = destination / artifact["path"]
            assert copied.is_file()
            assert artifact["path"].startswith("kernel-tx-evidence/block-")
            assert _sha256(copied) == artifact["sha256"]


@pytest.mark.parametrize("mutation", ["directory", "hash", "missing"])
def test_export_rejects_invalid_buflo_kernel_tx_source_binding(
    tmp_path: Path,
    mutation: str,
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode="buflo",
        runtime_kind="buflo",
        install_evidence=_install_buflo_candidate_evidence,
    )
    receipt = receipts[0]
    sample = next(item for item in receipt.experiment["samples"] if item["defense"] == "buflo")
    retained = sample["diagnostics"][KERNEL_TX_EVIDENCE_RECEIPT_KEY]
    if mutation == "directory":
        retained["directory"] = f"{KERNEL_TX_EVIDENCE_DIRECTORY}/substituted"
    else:
        name = sorted(KERNEL_TX_EVIDENCE_FILES)[0]
        if mutation == "hash":
            retained["artifacts"][name] = "9" * 64
        else:
            (receipt.root / retained["directory"] / name).unlink()

    destination = tmp_path / "handoff"
    with pytest.raises(ValueError, match="BuFLO kernel-TX source"):
        _export_candidate_fixture(
            destination,
            dimensions=dimensions,
            receipts=receipts,
            verify=verify,
        )
    assert not destination.exists()


@pytest.mark.parametrize("mutation", ["missing", "tampered", "substituted", "extra"])
def test_verifier_rejects_coherently_resealed_kernel_tx_inventory_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode="buflo",
        runtime_kind="buflo",
        install_evidence=_install_buflo_candidate_evidence,
    )
    destination = _export_candidate_fixture(
        tmp_path / "handoff",
        dimensions=dimensions,
        receipts=receipts,
        verify=verify,
    )
    rows = [
        json.loads(line)
        for line in (destination / "samples.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    buflo_rows = [row for row in rows if row["runtime_kind"] == "buflo"]
    name = "kernel-tx-evidence.json"
    first = destination / buflo_rows[0]["kernel_tx_evidence"]["artifacts"][name]["path"]
    if mutation == "missing":
        first.unlink()
    elif mutation == "tampered":
        first.write_bytes(b"tampered kernel evidence\n")
    elif mutation == "substituted":
        second = destination / buflo_rows[1]["kernel_tx_evidence"]["artifacts"][name]["path"]
        first.write_bytes(second.read_bytes())
    else:
        _write(destination / KERNEL_TX_EVIDENCE_DIRECTORY / "unbound.json", b"extra\n")
    _reseal_handoff(destination)

    with pytest.raises(ValueError):
        _verify_candidate_fixture(
            destination,
            dimensions=dimensions,
            verify=verify,
            deep=False,
        )


def test_verifier_rejects_unbound_fifo_without_opening_it(tmp_path: Path) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = _export_class_handoff(
        [receipt.root for receipt in receipts],
        tmp_path / "handoff",
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    fifo = destination / KERNEL_TX_EVIDENCE_DIRECTORY / "unbound.fifo"
    os.mkfifo(fifo)
    try:
        with pytest.raises(ValueError, match="special filesystem entry"):
            _verify_class_handoff(
                destination,
                dimensions=_TINY,
                deep=False,
                source_verifier=verify,
                trace_extractor=_trace,
                classic_pcap_writer=_classic_writer,
                correctness_validator=_correctness_validator,
                performance_extractor=_performance_extractor,
                cohort_loader=_cohort_loader,
                assembly_validator=_assembly_validator,
            )
    finally:
        fifo.unlink()


def test_verifier_rejects_non_buflo_kernel_tx_claim(tmp_path: Path) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode="buflo",
        runtime_kind="buflo",
        install_evidence=_install_buflo_candidate_evidence,
    )
    destination = _export_candidate_fixture(
        tmp_path / "handoff",
        dimensions=dimensions,
        receipts=receipts,
        verify=verify,
    )
    rows_path = destination / "samples.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    claimed = next(row["kernel_tx_evidence"] for row in rows if row["runtime_kind"] == "buflo")
    next(row for row in rows if row["runtime_kind"] != "buflo")["kernel_tx_evidence"] = claimed
    _write_handoff_rows(rows_path, rows)
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match="differs from its source identity"):
        _verify_candidate_fixture(
            destination,
            dimensions=dimensions,
            verify=verify,
            deep=False,
        )


@pytest.mark.parametrize(
    ("mode", "runtime_kind", "installer", "terminal_time"),
    [
        ("buflo", "buflo", _install_buflo_candidate_evidence, "10000002"),
        ("cs-buflo", "cs_buflo", _install_cs_buflo_candidate_evidence, "301"),
    ],
)
def test_export_is_atomic_for_coherently_sealed_candidate_chronology_mutation(
    tmp_path: Path,
    mode: str,
    runtime_kind: str,
    installer,
    terminal_time: str,
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode=mode,
        runtime_kind=runtime_kind,
        install_evidence=installer,
    )
    receipt = receipts[0]
    sample = next(item for item in receipt.experiment["samples"] if item["defense"] == mode)
    schedule = receipt.root / sample["path"] / "neqo/schedule.csv"
    with schedule.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fields = tuple(reader.fieldnames or ())
    rows[0]["terminal_defense_elapsed_us"] = terminal_time
    _write_runner_rows(schedule, fields, rows)
    _reseal_source_sample_file(receipt, sample, schedule)
    destination = tmp_path / "handoff"
    with pytest.raises(ValueError, match="invalid current terminal/schedule chronology"):
        _export_candidate_fixture(
            destination,
            dimensions=dimensions,
            receipts=receipts,
            verify=verify,
        )
    assert not destination.exists()


@pytest.mark.parametrize(
    ("mode", "runtime_kind", "installer"),
    [
        ("buflo", "buflo", _install_buflo_candidate_evidence),
        ("cs-buflo", "cs_buflo", _install_cs_buflo_candidate_evidence),
    ],
)
def test_export_is_atomic_for_coherently_sealed_candidate_outcome_mutation(
    tmp_path: Path,
    mode: str,
    runtime_kind: str,
    installer,
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode=mode,
        runtime_kind=runtime_kind,
        install_evidence=installer,
    )
    receipt = receipts[0]
    sample = next(item for item in receipt.experiment["samples"] if item["defense"] == mode)
    schedule = receipt.root / sample["path"] / "neqo/schedule.csv"
    with schedule.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        fields = tuple(reader.fieldnames or ())
    incoming = rows[1]
    incoming.update(
        satisfaction="missed",
        miss_reason="DeadlineExpired",
        qcsd_outcome_schema_version="3",
    )
    for field in (
        "send_policy",
        "desired_udp_bytes",
        "observed_udp_bytes",
        "credit_advertised_at_us",
        "credit_advertisement_delay_us",
        "credit_consumed_at_us",
        "credit_consumption_delay_us",
    ):
        incoming[field] = ""
    _write_runner_rows(schedule, fields, rows)
    _reseal_source_sample_file(receipt, sample, schedule)
    destination = tmp_path / "handoff"
    with pytest.raises(ValueError, match="invalid current terminal/schedule chronology"):
        _export_candidate_fixture(
            destination,
            dimensions=dimensions,
            receipts=receipts,
            verify=verify,
        )
    assert not destination.exists()


def test_export_is_atomic_for_cs_buflo_missing_packet_transcript(
    tmp_path: Path,
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode="cs-buflo",
        runtime_kind="cs_buflo",
        install_evidence=_install_cs_buflo_candidate_evidence,
    )
    receipt = receipts[0]
    sample = next(item for item in receipt.experiment["samples"] if item["defense"] == "cs-buflo")
    packets = receipt.root / sample["path"] / "neqo/packets.csv"
    with packets.open(newline="", encoding="utf-8") as source:
        fields = tuple(csv.DictReader(source).fieldnames or ())
    _write_runner_rows(packets, fields, [])
    _reseal_source_sample_file(receipt, sample, packets)
    destination = tmp_path / "handoff"
    with pytest.raises(ValueError, match="invalid current terminal/schedule chronology"):
        _export_candidate_fixture(
            destination,
            dimensions=dimensions,
            receipts=receipts,
            verify=verify,
        )
    assert not destination.exists()


@pytest.mark.parametrize(
    ("mode", "runtime_kind", "installer", "summary_key"),
    [
        ("buflo", "buflo", _install_buflo_candidate_evidence, "buflo_summary"),
        (
            "cs-buflo",
            "cs_buflo",
            _install_cs_buflo_candidate_evidence,
            "cs_buflo_summary",
        ),
    ],
)
def test_export_is_atomic_for_coherently_sealed_historical_candidate_schema(
    tmp_path: Path,
    mode: str,
    runtime_kind: str,
    installer,
    summary_key: str,
) -> None:
    dimensions, receipts, verify = _candidate_fixture(
        tmp_path,
        mode=mode,
        runtime_kind=runtime_kind,
        install_evidence=installer,
    )
    receipt = receipts[0]
    sample = next(item for item in receipt.experiment["samples"] if item["defense"] == mode)
    run_path = receipt.root / sample["path"] / "neqo/run.json"
    run = json.loads(run_path.read_text(encoding="utf-8"))
    run[summary_key]["schema_version"] = 3
    run_path.write_text(json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")
    _reseal_source_sample_file(receipt, sample, run_path)
    destination = tmp_path / "handoff"
    with pytest.raises(ValueError, match="invalid current terminal/schedule chronology"):
        _export_candidate_fixture(
            destination,
            dimensions=dimensions,
            receipts=receipts,
            verify=verify,
        )
    assert not destination.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda receipt: receipt.experiment["samples"][0].update(attempts=4), "retry budget"),
        (
            lambda receipt: receipt.experiment["configuration"].update(
                evidence_role="pilot-compatibility"
            ),
            "configuration",
        ),
        (
            lambda receipt: receipt.experiment["configuration"].pop("class_study_launch_sha256"),
            "first-launch",
        ),
    ],
)
def test_source_contract_rejects_nonformal_or_retried_samples(
    tmp_path: Path, mutation, message: str
) -> None:
    receipts, _verify = _fixture(tmp_path)
    changed = copy.deepcopy(receipts[0])
    mutation(changed)

    with pytest.raises(ValueError, match=message):
        _validate_source_results(
            (changed, *receipts[1:]),
            dimensions=_TINY,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


def test_source_contract_accepts_preserved_retry_success(tmp_path: Path) -> None:
    receipts, _verify = _fixture(tmp_path)
    changed = copy.deepcopy(receipts[0])
    changed.experiment["samples"][0]["attempts"] = 2

    _validate_source_results(
        (changed, *receipts[1:]),
        dimensions=_TINY,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )


@pytest.mark.parametrize(
    "identity",
    ("readiness", "qualification-set", "qualification-manifest"),
)
def test_source_contract_rejects_cross_block_capture_authority_mismatch(
    tmp_path: Path, identity: str
) -> None:
    receipts, _verify = _fixture(tmp_path)
    changed = copy.deepcopy(receipts[1])
    configuration = changed.experiment["configuration"]
    if identity == "readiness":
        relative = "inputs/class-study-readiness.json"
        path = changed.root / relative
        path.write_bytes(b"different sealed readiness authority\n")
        digest = _sha256(path)
        changed.checksums[relative] = digest
        configuration["class_study_readiness_sha256"] = digest
    elif identity == "qualification-set":
        configuration["chaff_qualification_set"] = "different-final-set-v1"
    else:
        configuration["chaff_qualification_set_manifest_sha256"] = "9" * 64

    with pytest.raises(ValueError, match="one frozen class/source contract"):
        _validate_source_results(
            (receipts[0], changed, receipts[2]),
            dimensions=_TINY,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


@pytest.mark.parametrize("field", ["resource_count", "origin_count"])
def test_source_contract_recomputes_workload_cardinality_from_sealed_manifest(
    tmp_path: Path, field: str
) -> None:
    receipts, _verify = _fixture(tmp_path)
    changed = copy.deepcopy(receipts[0])
    changed.experiment["configuration"]["workloads"][1][field] += 1

    with pytest.raises(ValueError, match="counts differ from its manifest"):
        _validate_source_results(
            (changed, *receipts[1:]),
            dimensions=_TINY,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda manifest: manifest["preparation"].pop("coverage_admission"),
            "requires a complete-coverage admission",
        ),
        (
            lambda manifest: manifest["preparation"]["coverage_admission"]["required_resources"][
                0
            ].update(url="https://substituted.example/resource"),
            "must bind every rendered resource",
        ),
    ],
)
def test_sealed_workload_boundary_rejects_missing_or_tampered_complete_coverage(
    tmp_path: Path, mutation, message: str
) -> None:
    receipts, _verify = _fixture(tmp_path)
    changed = copy.deepcopy(receipts[0])
    workload = changed.experiment["configuration"]["workloads"][0]
    relative = workload["manifest"]
    path = changed.root / relative
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutation(manifest)
    path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    workload["sha256"] = _sha256(path)
    changed.checksums[relative] = workload["sha256"]

    with pytest.raises(ValueError, match=message):
        _validate_sealed_workloads(changed, (workload,))


def test_trace_reader_rejects_any_identifier_feature(tmp_path: Path) -> None:
    path = tmp_path / "trace.csv"
    path.write_text(
        "relative_time_ns,direction,observer_frame_length_bytes,port\n0,outgoing,120,443\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outside the classifier contract"):
        _read_classifier_trace(path)


def test_deep_verifier_detects_rewritten_product_bytes(tmp_path: Path) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    trace = next((destination / "traces").rglob("*.csv"))
    trace.write_text(trace.read_text(encoding="utf-8") + "20,incoming,140\n", encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=True,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


def _reseal_handoff(root: Path) -> None:
    (root / "SHA256SUMS").unlink()
    _write_checksums(root)


def _write_handoff_rows(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


def test_export_rejects_coherently_resealed_multi_origin_baseline_graph_substitution(
    tmp_path: Path,
) -> None:
    receipts, verify = _fixture(tmp_path)
    receipt = receipts[0]
    sample = next(
        item
        for item in receipt.experiment["samples"]
        if item["workload_id"] == "class-b" and item["defense"] == "undefended"
    )
    assert (
        next(
            record["origin_count"]
            for record in receipt.experiment["configuration"]["workloads"]
            if record["id"] == "class-b"
        )
        == 3
    )
    run_path = receipt.root / sample["path"] / "neqo/run.json"
    run = json.loads(run_path.read_text(encoding="utf-8"))
    run["workload_hash_sha256"] = "9" * 64
    run_path.write_text(json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")
    _reseal_source_sample_file(receipt, sample, run_path)

    destination = tmp_path / "handoff"
    with pytest.raises(ValueError, match="run is not bound to its accepted sample"):
        _export_class_handoff(
            [item.root for item in receipts],
            destination,
            dimensions=_TINY,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )
    assert not destination.exists()


def test_deep_verify_rejects_coherently_resealed_multi_origin_defended_graph_substitution(
    tmp_path: Path,
) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    receipt = receipts[0]
    sample = next(
        item
        for item in receipt.experiment["samples"]
        if item["workload_id"] == "class-b" and item["defense"] == "front"
    )
    assert (
        next(
            record["origin_count"]
            for record in receipt.experiment["configuration"]["workloads"]
            if record["id"] == "class-b"
        )
        == 3
    )
    source_run = receipt.root / sample["path"] / "neqo/run.json"
    run = json.loads(source_run.read_text(encoding="utf-8"))
    run["chaff_manifest_hash_sha256"] = "9" * 64
    source_run.write_text(json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")
    _reseal_source_sample_file(receipt, sample, source_run)

    rows_path = destination / "samples.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    row = next(item for item in rows if item["sample_id"] == sample["sample_id"])
    copied_run = destination / row["products"]["run"]["path"]
    copied_run.write_bytes(source_run.read_bytes())
    changed_digest = _sha256(copied_run)
    row["products"]["run"]["sha256"] = changed_digest
    row["source"]["artifacts"]["run"]["sha256"] = changed_digest
    rows_path.write_text(
        "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in rows),
        encoding="utf-8",
    )
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match="defended run graph binding is invalid"):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=True,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


@pytest.mark.parametrize("replacement", [2, True])
def test_verifier_rejects_coherently_resealed_attempt_count_substitution(
    tmp_path: Path,
    replacement: object,
) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    rows_path = destination / "samples.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["attempts"] == 1
    rows[0]["attempts"] = replacement
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match="differs from its source identity"):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=False,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


def test_deep_verifier_rejects_coherently_resealed_classic_pcap_substitution(
    tmp_path: Path,
) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    rows_path = destination / "samples.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    classic = destination / rows[0]["products"]["classic_pcap"]["path"]
    classic.write_bytes(b"coherently substituted classic fixture\n")
    rows[0]["products"]["classic_pcap"]["sha256"] = _sha256(classic)
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match="classic PCAP differs from regenerated"):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=True,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda dataset: dataset["observation"].update(layer="forged observer"),
            "feature restriction",
        ),
        (
            lambda dataset: dataset.update(exporter_source={"fixture": "substitute"}),
            "exporter source differs",
        ),
        (
            lambda dataset: dataset["resource_origin_profile"].update(multi_origin_class_count=0),
            "resource-origin profile",
        ),
        (
            lambda dataset: dataset["capture_authority"]["readiness"].update(sha256="9" * 64),
            "capture authority",
        ),
        (
            lambda dataset: dataset["runtime_contract"].update(
                chaff_qualification_set_manifest_sha256="9" * 64
            ),
            "runtime contract",
        ),
    ],
)
def test_verifier_rejects_coherently_resealed_dataset_contract_substitution(
    tmp_path: Path, mutate, message: str
) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    dataset_path = destination / "dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    mutate(dataset)
    dataset_path.write_text(
        json.dumps(dataset, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match=message):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=False,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


def test_verifier_rejects_coherently_resealed_first_launch_substitution(
    tmp_path: Path,
) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    launch = destination / "inputs/class-study-launches/block-01.json"
    launch.write_text('{"coherently":"substituted"}\n', encoding="utf-8")
    dataset_path = destination / "dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    digest = _sha256(launch)
    dataset["class_study_launches"]["blocks"][0]["sha256"] = digest
    dataset["blocks"][0]["class_study_launch_sha256"] = digest
    dataset_path.write_text(
        json.dumps(dataset, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match="frozen input bindings|source block lineage"):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=False,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda row: row["correctness"].update(passed=False),
            "correctness receipt",
        ),
        (
            lambda row: row["performance"]["wire_bytes"].update(
                outgoing=row["performance"]["wire_bytes"]["outgoing"] + 1
            ),
            "performance does not match",
        ),
    ],
)
def test_verifier_rejects_coherently_resealed_sample_evidence_substitution(
    tmp_path: Path, mutate, message: str
) -> None:
    receipts, verify = _fixture(tmp_path)
    destination = tmp_path / "handoff"
    _export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=_TINY,
        source_verifier=verify,
        trace_extractor=_trace,
        classic_pcap_writer=_classic_writer,
        correctness_validator=_correctness_validator,
        performance_extractor=_performance_extractor,
        cohort_loader=_cohort_loader,
        assembly_validator=_assembly_validator,
    )
    rows_path = destination / "samples.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    mutate(rows[0])
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    _reseal_handoff(destination)

    with pytest.raises(ValueError, match=message):
        _verify_class_handoff(
            destination,
            dimensions=_TINY,
            deep=False,
            source_verifier=verify,
            trace_extractor=_trace,
            classic_pcap_writer=_classic_writer,
            correctness_validator=_correctness_validator,
            performance_extractor=_performance_extractor,
            cohort_loader=_cohort_loader,
            assembly_validator=_assembly_validator,
        )
