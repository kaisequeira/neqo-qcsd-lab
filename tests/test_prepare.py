from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest

import qcsd_lab.prepare as prepare
from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
    TARGET_EGRESS_APIS,
    target_egress_apis,
)
from qcsd_lab.cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
    NORMAL_SHUTDOWN_DISPOSAL_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
)
from qcsd_lab.discover import DiscoveryResult
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
    REQUEST_STAGE_OBSERVATION_POLICY,
    RENDER_OBSERVATION_SCHEMA_VERSION,
    evidence_sha256,
    passive_render_contract,
)
from qcsd_lab.manifest import runtime_manifest, validate_manifest


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


def discovered() -> DiscoveryResult:
    resources = [
        {
            "id": 0,
            "url": "https://page.test/",
            "type": "Document",
            "content_length": None,
            "data_length": 0,
            "chaff_priority": False,
            "known_valid": False,
            "depends_on": [],
            "headers": [["accept", "text/html"]],
        },
        {
            "id": 1,
            "url": "https://cdn.test/app.js",
            "type": "Script",
            "content_length": None,
            "data_length": 0,
            "chaff_priority": False,
            "known_valid": False,
            "depends_on": [0],
            "headers": [
                ["accept", "*/*"],
                ["referer", "https://page.test/"],
            ],
        },
    ]
    source = {
        "session_path": [],
        "target_id": "root-page",
        "target_type": "page",
        "generation": 0,
        "parent_session_path": None,
        "parent_frame_id": None,
    }
    render = {
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
    events = []
    for resource in resources:
        occurrence = f"request-{resource['id']:08d}"
        dependency_evidence = (
            []
            if resource["id"] == 0
            else [
                {
                    "kind": "document-url",
                    "value": "https://page.test/",
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
                    "source": source,
                    "network_id": f"network-{resource['id']}",
                    "occurrence_id": occurrence,
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
                    "mapping": {"kind": "resource", "resource_id": resource["id"]},
                    "response_observed": True,
                    "interception_exception": None,
                    "dependency_evidence": dependency_evidence,
                    "resolved_dependency_resource_ids": resource["depends_on"],
                },
                {
                    "sequence": len(events) + 2,
                    "monotonic_ms": 0,
                    "kind": "fetch-request",
                    "source": source,
                    "fetch_id": f"fetch-{resource['id']}",
                    "network_id": f"network-{resource['id']}",
                    "redirected_fetch_id": None,
                    "network_occurrence_id": occurrence,
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
                    "source": source,
                    "network_id": f"network-{resource['id']}",
                    "outcome": "finished",
                    "failure": None,
                    "network_occurrence_ids": [occurrence],
                },
            ]
        )
    audit = {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "request_stage_observation_policy": REQUEST_STAGE_OBSERVATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": evidence_sha256(render),
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
            "network_request_count": 2,
            "fetch_request_count": 2,
            "fetch_internal_restart_count": 0,
            "terminal_event_count": 2,
            "resource_occurrence_count": 2,
            "exclusion_occurrence_count": 0,
            "blocked_preflight_dependent_count": 0,
        },
    }
    return DiscoveryResult(
        source_url="https://page.test/",
        final_url="https://page.test/",
        chromium_version="test-chromium",
        settle_ms=10_000,
        observed_request_count=2,
        observed_origins=["https://cdn.test", "https://page.test"],
        approved_origins=["https://cdn.test", "https://page.test"],
        exclusions=[],
        resources=resources,
        origin_ip_pins={
            "https://cdn.test": "1.1.1.1",
            "https://page.test": "8.8.8.8",
        },
        expandable_origins=["https://cdn.test", "https://page.test"],
        passive_render_contract=passive_render_contract(),
        passive_render_contract_sha256=PASSIVE_RENDER_CONTRACT_SHA256,
        render_observation=render,
        render_observation_sha256=evidence_sha256(render),
        discovery_event_audit=audit,
        discovery_event_audit_sha256=evidence_sha256(audit),
    )


def install_fake_preparation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    changing_resource: int | None = None,
    packet_rows: list[tuple[str, str, str]] | None = None,
    resolved_ceiling: object = 1_200,
    outgoing_ceiling: object = 1_200,
    incoming_limit: object = 65_527,
    probe_lengths: dict[int, tuple[int, int]] | None = None,
    stable_bytes: dict[int, int] | None = None,
) -> list[list[str]]:
    discovery = discovered()
    monkeypatch.setattr(prepare, "discover_page", lambda *_args, **_kwargs: discovery)
    monkeypatch.setattr(
        prepare,
        "source_metadata",
        lambda: {
            "image_digest": None,
            "lab_commit": "lab",
            "lab_dirty": False,
            "lab_patch_sha256": "0" * 64,
            "neqo_commit": "neqo",
            "neqo_pinned_commit": "neqo",
            "neqo_dirty": False,
            "neqo_patch_sha256": "0" * 64,
        },
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_options) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        configured_timeout = int(command[command.index("--timeout-seconds") + 1])
        assert _options["timeout"] == prepare.neqo_host_timeout(configured_timeout)
        assert _options["check"] is False
        operation = command[1]
        if operation == "probe":
            source = json.loads(Path(command[command.index("--input-manifest") + 1]).read_text())
            assert set(source) == {"resources"}
            resolved = deepcopy(source)
            for resource in resolved["resources"]:
                content_length, data_length = (probe_lengths or {}).get(
                    resource["id"],
                    (100 + resource["id"], 100 + resource["id"]),
                )
                resource["known_valid"] = True
                resource["content_length"] = content_length
                resource["data_length"] = data_length
            Path(command[command.index("--output") + 1]).write_text(
                json.dumps(resolved), encoding="utf-8"
            )
        elif operation == "run":
            workload = json.loads(Path(command[command.index("--workload") + 1]).read_text())
            output = Path(command[command.index("--output-dir") + 1])
            output.mkdir()
            run_index = int(output.name.rsplit("-", 1)[1])
            responses = []
            for resource in workload["resources"]:
                marker = (
                    f"changed-{run_index}"
                    if resource["id"] == changing_resource
                    else f"stable-{resource['id']}"
                )
                responses.append(
                    {
                        "resource_id": resource["id"],
                        "url": resource["url"],
                        "request_headers": resource["headers"],
                        "status": 200,
                        "bytes": (stable_bytes or {}).get(resource["id"], 100 + resource["id"]),
                        "body_sha256": (marker.encode().hex() + "0" * 64)[:64],
                        "complete": True,
                        "outcome": "succeeded",
                    }
                )
            (output / "run.json").write_text(
                json.dumps(
                    {
                        "neqo_version": "0.1.0",
                        "neqo_base_commit": "base",
                        "published_qcsd_commit": "published",
                        "migration_commit": "migration",
                        "completion_status": "complete",
                        "outgoing_udp_payload_ceiling": outgoing_ceiling,
                        "incoming_udp_payload_limit": incoming_limit,
                        "resolved_configuration": {
                            "max_udp_payload_size": resolved_ceiling,
                        },
                        "responses": responses,
                    }
                ),
                encoding="utf-8",
            )
            rows = packet_rows or [
                ("outgoing", "0", "1200"),
                ("incoming", "0", "1199"),
            ]
            packet_text = (
                "direction,monotonic_us,connection,observed_udp_length,"
                "scheduled_target,satisfaction,slot_id\n"
                + "".join(
                    f"{direction},1,{connection},{length},,unshaped,\n"
                    for direction, connection, length in rows
                )
            )
            (output / "packets.csv").write_text(packet_text, encoding="utf-8")
        else:  # pragma: no cover - protects the mock contract
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, "")

    monkeypatch.setattr(prepare, "run", fake_run)
    return commands


@pytest.mark.parametrize("phase", ["probe", "stability"])
def test_prepare_treats_rust_exit_101_as_nonrecoverable_internal_failure(
    phase, tmp_path, monkeypatch
):
    panic = "thread 'main' panicked at neqo-bin/src/qcsd/mod.rs:1:1:"
    monkeypatch.setattr(
        prepare,
        "_run_neqo",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 101, panic),
    )
    manifest = {"resources": discovered().resources}

    with pytest.raises(prepare.PreparationError) as raised:
        if phase == "probe":
            prepare._probe(
                manifest,
                tmp_path,
                max_response_bytes=1_024,
                timeout_seconds=1,
            )
        else:
            prepare._probe_response_stability(
                manifest,
                tmp_path,
                max_response_bytes=1_024,
                timeout_seconds=1,
                stability_runs=2,
                stability_interval_seconds=0,
            )

    assert type(raised.value) is prepare.PreparationError
    assert "failed (101)" in str(raised.value)
    assert panic in str(raised.value)


def test_prepare_retains_non_panic_nonzero_exit_as_explicitly_recoverable():
    result = subprocess.CompletedProcess([], 7, "transient transport failure")

    with pytest.raises(prepare.RecoverablePreparationError, match=r"failed \(7\)"):
        prepare._raise_neqo_execution_failure("Neqo test", result)


def test_prepare_writes_one_policy_free_frozen_workload(tmp_path, monkeypatch):
    commands = install_fake_preparation(monkeypatch)

    result = prepare.prepare_workload(
        "example-page",
        "https://page.test/",
        ["https://page.test", "https://cdn.test"],
        output_root=tmp_path,
        stability_interval_seconds=0,
    )

    assert result.path == tmp_path / "example-page.json"
    assert len(result.sha256) == 64
    assert result.resource_count == 2
    assert result.origin_count == 2
    assert [command[1] for command in commands] == ["probe", "run", "run", "run"]
    value = json.loads(result.path.read_text())
    validate_manifest(value)
    assert set(value) == {"preparation", "resources"}
    assert runtime_manifest(value) == {"resources": value["resources"]}
    assert value["resources"][1]["headers"] == [
        ["accept", "*/*"],
        ["referer", "https://page.test/"],
    ]
    assert value["preparation"]["stability_runs"] == 3
    assert value["preparation"]["stability_profile"] == "live"
    assert value["preparation"]["stability_defense"] == "none"
    assert value["preparation"]["timeout_seconds"] == 120
    assert "coverage_admission" not in value["preparation"]
    qualification = value["preparation"]["udp_payload_qualification"]
    assert qualification == {
        "schema_version": 2,
        "outgoing_udp_payload_ceiling": 1_200,
        "incoming_udp_payload_limit": 65_527,
        "runs": [
            {
                "run_index": index,
                "packets_sha256": hashlib.sha256(
                    (
                        "direction,monotonic_us,connection,observed_udp_length,"
                        "scheduled_target,satisfaction,slot_id\n"
                        "outgoing,1,0,1200,,unshaped,\n"
                        "incoming,1,0,1199,,unshaped,\n"
                    ).encode()
                ).hexdigest(),
                "total": {
                    "packet_count": 2,
                    "observed_udp_payload_max": 1_200,
                    "oversized_packet_count": 0,
                },
                "incoming": {
                    "packet_count": 1,
                    "observed_udp_payload_max": 1_199,
                    "oversized_packet_count": 0,
                },
                "outgoing": {
                    "packet_count": 1,
                    "observed_udp_payload_max": 1_200,
                    "oversized_packet_count": 0,
                },
            }
            for index in range(3)
        ],
    }
    assert [response["resource_id"] for response in value["preparation"]["expected_responses"]] == [
        0,
        1,
    ]
    assert not list(tmp_path.glob(".*-prepare-*"))


def test_prepare_freezes_approved_origin_chaff_policy_with_complete_graph(tmp_path, monkeypatch):
    from qcsd_lab.application_response_policy import APPROVED_ORIGINS_CHAFF_POLICY
    install_fake_preparation(monkeypatch)
    result = prepare.prepare_workload(
        "approved-chaff-origins", "https://page.test/",
        ["https://page.test", "https://cdn.test"],
        output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
        qualified_chaff_origin_policy=APPROVED_ORIGINS_CHAFF_POLICY,
    )
    value = json.loads(result.path.read_text())
    validate_manifest(value)
    assert value["preparation"]["qualified_chaff_origin_policy"] == APPROVED_ORIGINS_CHAFF_POLICY
    assert [r["id"] for r in value["resources"]] == [0, 1]
    assert value["preparation"]["coverage_admission"]["required_origins"] == [
        "https://cdn.test", "https://page.test",
    ]
    assert value["preparation"]["coverage_admission"]["required_resources"] == [
        {"id": r["id"], "url": r["url"]} for r in value["resources"]
    ]


def test_prepare_approved_origin_chaff_policy_requires_complete_coverage(tmp_path, monkeypatch):
    from qcsd_lab.application_response_policy import APPROVED_ORIGINS_CHAFF_POLICY
    def unexpected_discovery(*args, **kwargs):
        raise AssertionError("policy must be checked before discovery")
    monkeypatch.setattr(prepare, "discover_page", unexpected_discovery)
    with pytest.raises(ValueError, match="complete graph coverage"):
        prepare.prepare_workload(
            "incomplete-chaff-origins", "https://page.test/", ["https://page.test"],
            output_root=tmp_path, qualified_chaff_origin_policy=APPROVED_ORIGINS_CHAFF_POLICY,
        )
    assert not list(tmp_path.iterdir())


def test_prepare_complete_coverage_freezes_multi_origin_admission(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch)

    result = prepare.prepare_workload(
        "complete-coverage",
        "https://page.test/",
        ["https://page.test", "https://cdn.test"],
        output_root=tmp_path,
        stability_interval_seconds=0,
        require_complete_coverage=True,
    )

    value = json.loads(result.path.read_text())
    validate_manifest(value)
    assert value["preparation"]["coverage_admission"] == {
        "schema_version": 3,
        "policy": "all-approved-origins-and-rendered-resources",
        "required_origins": ["https://cdn.test", "https://page.test"],
        "required_resources": [
            {"id": 0, "url": "https://page.test/"},
            {"id": 1, "url": "https://cdn.test/app.js"},
        ],
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": value["preparation"][
            "render_observation_sha256"
        ],
        "discovery_event_audit_sha256": value["preparation"][
            "discovery_event_audit_sha256"
        ],
        "origin_ip_pins_sha256": evidence_sha256(
            value["preparation"]["origin_ip_pins"]
        ),
        "browser_request_headers_sha256": evidence_sha256(
            value["preparation"]["browser_request_headers"]
        ),
        "network_request_count": 2,
        "resource_occurrence_count": 2,
        "exclusion_occurrence_count": 0,
    }
    assert result.resource_count == 2
    assert result.origin_count == 2


def test_prepare_complete_coverage_requires_a_rendered_get_from_every_approved_origin(
    tmp_path,
    monkeypatch,
):
    discovery = discovered()
    discovery.resources = discovery.resources[:1]
    monkeypatch.setattr(prepare, "discover_page", lambda *_args, **_kwargs: discovery)
    monkeypatch.setattr(
        prepare,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("probe used")),
    )

    with pytest.raises(
        prepare.PreparationError,
        match=r"browser-rendered HTTPS GET.*missing origins: https://cdn\.test",
    ):
        prepare.prepare_workload(
            "missing-approved-origin",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            require_complete_coverage=True,
        )

    assert not (tmp_path / "missing-approved-origin.json").exists()


def test_prepare_complete_coverage_rejects_final_discovery_origin_drift(
    tmp_path,
    monkeypatch,
):
    discovery = discovered()
    discovery.observed_origins.append("https://tracker.test")
    assert discovery.expandable_origins is not None
    discovery.expandable_origins.append("https://tracker.test")
    discovery.exclusions.append(
        {"url": "https://tracker.test/a.js", "reason": "origin not approved"}
    )
    monkeypatch.setattr(prepare, "discover_page", lambda *_args, **_kwargs: discovery)
    monkeypatch.setattr(
        prepare,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("probe used")),
    )

    with pytest.raises(
        prepare.PreparationError,
        match=r"observed new HTTPS GET origins.*https://tracker\.test",
    ):
        prepare.prepare_workload(
            "late-origin-drift",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            require_complete_coverage=True,
        )

    assert not (tmp_path / "late-origin-drift.json").exists()


@pytest.mark.parametrize(
    ("expandable_origins", "message"),
    [
        (None, "requires the final browser discovery"),
        (["https://page.test/"], "canonical HTTPS origins"),
        (
            ["https://page.test", "https://cdn.test"],
            "sorted unique final browser expandable-origin ledger",
        ),
        (["https://page.test"], "omits approved HTTPS GET origins"),
    ],
)
def test_prepare_complete_coverage_requires_a_canonical_final_get_origin_ledger(
    tmp_path,
    monkeypatch,
    expandable_origins,
    message,
):
    discovery = discovered()
    discovery.expandable_origins = expandable_origins
    monkeypatch.setattr(prepare, "discover_page", lambda *_args, **_kwargs: discovery)
    monkeypatch.setattr(
        prepare,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("probe used")),
    )

    with pytest.raises(prepare.PreparationError, match=message):
        prepare.prepare_workload(
            "invalid-final-origin-ledger",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            require_complete_coverage=True,
        )

    assert not (tmp_path / "invalid-final-origin-ledger.json").exists()


def test_prepare_canonicalizes_stale_probe_lengths_from_stable_get_evidence(
    tmp_path,
    monkeypatch,
):
    install_fake_preparation(
        monkeypatch,
        probe_lengths={0: (14_576, 14_576), 1: (999, 999)},
        stable_bytes={0: 2_922, 1: 0},
    )

    result = prepare.prepare_workload(
        "canonical-lengths",
        "https://page.test/",
        ["https://page.test", "https://cdn.test"],
        output_root=tmp_path,
        stability_interval_seconds=0,
    )

    value = json.loads(result.path.read_text())
    assert [
        (resource["content_length"], resource["data_length"]) for resource in value["resources"]
    ] == [(2_922, 2_922), (0, 0)]
    assert [response["bytes"] for response in value["preparation"]["expected_responses"]] == [
        2_922,
        0,
    ]
    assert runtime_manifest(value) == {"resources": value["resources"]}


def test_prepare_rejects_a_missing_stable_response_length_map(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch)
    monkeypatch.setattr(
        prepare,
        "response_stability_evidence",
        lambda _runs: {
            "runs": 3,
            "stable_resource_ids": [0, 1],
            "expected_responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 100,
                    "body_sha256": "0" * 64,
                }
            ],
        },
    )

    with pytest.raises(
        prepare.PreparationError,
        match="stable response length map must match resources exactly",
    ):
        prepare.prepare_workload(
            "missing-length",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            stability_interval_seconds=0,
        )

    assert not (tmp_path / "missing-length.json").exists()


def test_prepare_refuses_existing_id_before_network_work(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch)
    prepare.prepare_workload(
        "immutable",
        "https://page.test/",
        ["https://page.test", "https://cdn.test"],
        output_root=tmp_path,
        stability_interval_seconds=0,
    )
    monkeypatch.setattr(
        prepare,
        "discover_page",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network used")),
    )

    with pytest.raises(FileExistsError, match="choose a new workload ID"):
        prepare.prepare_workload(
            "immutable",
            "https://page.test/",
            ["https://page.test"],
            output_root=tmp_path,
            stability_interval_seconds=0,
        )


def test_prepare_rejects_changing_response_identity_without_output(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch, changing_resource=1)

    with pytest.raises(prepare.PreparationError, match="resource IDs: 1"):
        prepare.prepare_workload(
            "changing",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            stability_interval_seconds=0,
        )

    assert not (tmp_path / "changing.json").exists()


@pytest.mark.parametrize("incoming_length", [1_452, 65_527])
def test_prepare_accepts_standard_large_incoming_udp_payloads(
    incoming_length, tmp_path, monkeypatch
):
    install_fake_preparation(
        monkeypatch,
        packet_rows=[("incoming", "0", str(incoming_length)), ("outgoing", "1", "1200")],
    )

    prepared = prepare.prepare_workload(
        "large-incoming",
        "https://page.test/",
        ["https://page.test", "https://cdn.test"],
        output_root=tmp_path,
        stability_interval_seconds=0,
    )
    receipt = json.loads(prepared.path.read_text())["preparation"]["udp_payload_qualification"]
    assert receipt["schema_version"] == 2
    for run in receipt["runs"]:
        assert run["total"]["observed_udp_payload_max"] == incoming_length
        assert run["incoming"]["observed_udp_payload_max"] == incoming_length
        assert run["incoming"]["oversized_packet_count"] == 0
        assert run["outgoing"]["oversized_packet_count"] == 0


@pytest.mark.parametrize(
    ("direction", "length"),
    [("outgoing", 1_201), ("incoming", 65_528)],
)
def test_prepare_rejects_directional_udp_limit_violation(
    direction, length, tmp_path, monkeypatch
):
    other = "outgoing" if direction == "incoming" else "incoming"
    install_fake_preparation(
        monkeypatch,
        packet_rows=[(direction, "0", str(length)), (other, "1", "1200")],
    )

    with pytest.raises(
        prepare.PreparationError,
        match=rf"stability run 1 observed 1 UDP payload.*above the directional limits.*{direction} 1 above",
    ):
        prepare.prepare_workload(
            "oversized",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            stability_interval_seconds=0,
        )

    assert not (tmp_path / "oversized.json").exists()


def test_prepare_rejects_a_runner_ceiling_mismatch(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch, resolved_ceiling=1_201)

    with pytest.raises(prepare.PreparationError, match="did not resolve the 1200-byte"):
        prepare.prepare_workload(
            "wrong-ceiling",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            stability_interval_seconds=0,
        )


@pytest.mark.parametrize(
    ("directional_field", "wrong_value"),
    [
        ("outgoing_ceiling", 1_201),
        ("incoming_limit", 1_200),
        ("outgoing_ceiling", 1_200.0),
        ("incoming_limit", 65_527.0),
    ],
)
def test_prepare_rejects_a_runner_directional_limit_mismatch(
    directional_field, wrong_value, tmp_path, monkeypatch
):
    install_fake_preparation(monkeypatch, **{directional_field: wrong_value})

    with pytest.raises(prepare.PreparationError, match="directional UDP-payload limits"):
        prepare.prepare_workload(
            "wrong-directional-limit",
            "https://page.test/",
            ["https://page.test", "https://cdn.test"],
            output_root=tmp_path,
            stability_interval_seconds=0,
        )


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (("sideways", "0", "1200"), "invalid direction"),
        (("incoming", "connection-zero", "1200"), "invalid connection"),
        (("incoming", "00", "1200"), "invalid connection"),
        (("incoming", str(2**64), "1200"), "invalid connection"),
        (("incoming", "0", "0"), "invalid observed_udp_length"),
        (("incoming", "0", ""), "invalid observed_udp_length"),
        (("incoming", "0", "١٢٠٠"), "invalid observed_udp_length"),
        (("incoming", "0", "9" * 10_000), "invalid observed_udp_length"),
    ],
)
def test_udp_qualification_rejects_malformed_semantic_packet_fields(row, message, tmp_path):
    path = tmp_path / "packets.csv"
    rows = [row, ("outgoing", "1", "1200")]
    path.write_text(
        "direction,connection,observed_udp_length,future_column\n"
        + "".join(",".join((*item, "future")) + "\n" for item in rows),
        encoding="utf-8",
    )

    with pytest.raises(prepare.PreparationError, match=message):
        prepare._qualify_udp_payloads(
            {
                "resolved_configuration": {"max_udp_payload_size": 1_200},
                "outgoing_udp_payload_ceiling": 1_200,
                "incoming_udp_payload_limit": 65_527,
            },
            path,
            run_index=0,
            expected_ceiling=1_200,
        )


def test_udp_qualification_requires_both_directions_and_required_columns(tmp_path):
    path = tmp_path / "packets.csv"
    path.write_text(
        "direction,connection,observed_udp_length\noutgoing,0,1200\n",
        encoding="utf-8",
    )
    with pytest.raises(prepare.PreparationError, match="no incoming packets"):
        prepare._qualify_udp_payloads(
            {
                "resolved_configuration": {"max_udp_payload_size": 1_200},
                "outgoing_udp_payload_ceiling": 1_200,
                "incoming_udp_payload_limit": 65_527,
            },
            path,
            run_index=0,
            expected_ceiling=1_200,
        )

    path.write_text("direction,connection\nincoming,0\n", encoding="utf-8")
    with pytest.raises(prepare.PreparationError, match="missing required columns"):
        prepare._qualify_udp_payloads(
            {
                "resolved_configuration": {"max_udp_payload_size": 1_200},
                "outgoing_udp_payload_ceiling": 1_200,
                "incoming_udp_payload_limit": 65_527,
            },
            path,
            run_index=0,
            expected_ceiling=1_200,
        )


@pytest.mark.parametrize("incomplete_status", ["partial", "error"])
def test_response_stability_preserves_successes_from_incomplete_runs(incomplete_status):
    def response(resource_id: int, *, succeeded: bool = True) -> dict[str, object]:
        return {
            "resource_id": resource_id,
            "status": 200,
            "bytes": 100 + resource_id,
            "body_sha256": str(resource_id) * 64,
            "request_headers": [["accept", "*/*"]],
            "complete": succeeded,
            "outcome": "succeeded" if succeeded else "failed",
        }

    runs = [
        {
            "completion_status": "complete",
            "responses": [response(0), response(1)],
        },
        {
            "completion_status": incomplete_status,
            "responses": [response(0), response(1, succeeded=False)],
        },
        {
            "completion_status": "complete",
            "responses": [response(0), response(1)],
        },
    ]

    evidence = prepare.response_stability_evidence(runs)

    assert evidence["stable_resource_ids"] == [0]
    assert [item["resource_id"] for item in evidence["expected_responses"]] == [0]


def test_probe_filter_prunes_unavailable_dependency_closure_without_rewriting_edges():
    discovery = discovered()
    discovery.resources.append(
        {
            "id": 2,
            "url": "https://cdn.test/image.png",
            "type": "Image",
            "content_length": None,
            "data_length": 0,
            "chaff_priority": False,
            "known_valid": False,
            "depends_on": [1],
            "headers": [["accept", "image/png"]],
        }
    )
    resolved = {"resources": deepcopy(discovery.resources)}
    resolved["resources"][0].update({"known_valid": True, "content_length": 100})
    resolved["resources"][1].update({"known_valid": False, "content_length": None})
    resolved["resources"][2].update({"known_valid": True, "content_length": 102})

    resources, exclusions = prepare.resolve_probe_output(discovery, resolved)

    assert [resource["id"] for resource in resources] == [0]
    assert resources[0]["depends_on"] == []
    assert {
        "url": "https://cdn.test/app.js",
        "reason": "HTTP/3 preflight unavailable",
    } in exclusions
    assert {
        "url": "https://cdn.test/image.png",
        "reason": "HTTP/3 dependency unavailable",
    } in exclusions

    with pytest.raises(
        prepare.PreparationError,
        match=r"every browser-rendered resource.*1 \(https://cdn\.test/app\.js\)",
    ):
        prepare.resolve_probe_output(
            discovery,
            resolved,
            require_complete_coverage=True,
        )


def test_probe_filter_rejects_an_unavailable_navigation_document():
    discovery = discovered()
    resolved = {"resources": deepcopy(discovery.resources)}
    resolved["resources"][0].update({"known_valid": False, "content_length": None})
    resolved["resources"][1].update({"known_valid": True, "content_length": 101})

    with pytest.raises(
        prepare.PreparationError,
        match="dependency-root Document.*source/final navigation",
    ):
        prepare.resolve_probe_output(discovery, resolved)


@pytest.mark.parametrize("workload_id", ["Upper", "two--hyphens", "../escape", "trailing-"])
def test_prepare_rejects_noncanonical_workload_ids(workload_id, tmp_path):
    with pytest.raises(ValueError, match="workload ID"):
        prepare.prepare_workload(
            workload_id,
            "https://page.test/",
            ["https://page.test"],
            output_root=tmp_path,
        )


def _actual_policy_failure(tmp_path, monkeypatch, *, stage="full-graph-h3"):
    install_fake_preparation(
        monkeypatch, changing_resource=1 if stage == "response-stability" else None,
    )
    fake_run = prepare.run

    def actual_run(command, **options):
        result = fake_run(command, **options)
        if stage == "full-graph-h3" and command[1] == "probe":
            path = Path(command[command.index("--output") + 1])
            value = json.loads(path.read_bytes())
            value["resources"][1]["known_valid"] = False
            path.write_text(json.dumps(value))
        return result

    monkeypatch.setattr(prepare, "run", actual_run)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
    kind = (prepare.FullGraphH3PolicyError if stage == "full-graph-h3"
            else prepare.ResponseStabilityPolicyError)
    with pytest.raises(kind) as raised:
        prepare.prepare_workload(
            "typed-failure", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
        )
    return raised.value


def _replace_failure_artifact(evidence, name, raw):
    evidence["artifacts"][name] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content_base64": base64.b64encode(raw).decode("ascii"),
    }


def _actual_peer_probe_failure(tmp_path, monkeypatch, *, stage="head", mutation=None,
                               require_complete_coverage=True):
    install_fake_preparation(monkeypatch)
    metadata = prepare.source_metadata()
    metadata.update({"neqo_commit": "f" * 40, "neqo_pinned_commit": "f" * 40})
    monkeypatch.setattr(prepare, "source_metadata", lambda: deepcopy(metadata))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)

    def actual_run(command, **options):
        assert command[1] == "probe"  # No replay follows a failed complete graph.
        manifest = json.loads(Path(command[command.index("--input-manifest") + 1]).read_bytes())
        directory = Path(command[command.index("--output") + 1]).parent
        original = manifest["resources"]
        failed_id = 0
        detail = f"HTTP/3 endpoint {failed_id} closed before accepted run completion: Transport(Peer(296))"
        stdout = f'Error: RunAborted("{detail}")\n'
        if mutation == "stdout-only":
            options["log"].write_text(stdout)
            return subprocess.CompletedProcess(command, 1, stdout)
        for current_stage in (["head", "get"] if stage == "get" else ["head"]):
            failed = current_stage == stage
            resources = original if current_stage == "head" else [original[1]]
            started = time.time_ns()
            responses = []
            for row in resources:
                closed = failed and row["id"] == 1
                responses.append({
                    "resource_id": row["id"], "url": row["url"],
                    "request_headers": row["headers"], "response_headers": [],
                    "status": None if closed else 200,
                    "content_length": None if (closed or row["id"] == 1) else 100,
                    "bytes": 0, "body_sha256": hashlib.sha256(b"").hexdigest(),
                    "request_stream_bytes": 0, "complete": not closed,
                    "outcome": "endpoint_closed" if closed else "succeeded",
                })
            run_data = {
                "neqo_version": "0.1.0", "neqo_base_commit": "b" * 40,
                "published_qcsd_commit": "c" * 40, "migration_commit": "f" * 40,
                "resolved_configuration": {"defense": {"kind": "none"}, "max_udp_payload_size": 1450},
                "incoming_udp_payload_limit": 65527, "outgoing_udp_payload_ceiling": 1450,
                "defense_parameters": None, "seed": 0,
                "method": "HEAD" if current_stage == "head" else "GET",
                "request_policy": "as-defined",
                "workload_hash_sha256": prepare._probe_runtime_manifest_hash(resources),
                "application_workload_source_hash_sha256": None, "chaff_manifest_hash_sha256": None,
                "max_response_bytes": 0 if current_stage == "head" else int(command[command.index("--max-bytes") + 1]),
                "time_anchor_unix_ns": started, "started_unix_ns": started, "ended_unix_ns": time.time_ns(),
                "completion_status": "error" if failed else "complete",
                "error": f"run aborted: {detail}" if failed else None,
                "error_class": "runner-execution-v1" if failed else None,
                "terminal_evidence_render_errors": [],
                "endpoints": [{"id": 0, "origin": "https://cdn.test/"}] + (
                    [{"id": 1, "origin": "https://page.test/"}] if current_stage == "head" else []
                ),
                "responses": responses,
            }
            if failed:
                if mutation == "other-peer-code":
                    run_data["error"] = run_data["error"].replace("Peer(296)", "Peer(297)")
                    stdout = stdout.replace("Peer(296)", "Peer(297)")
                elif mutation == "wrong-client":
                    run_data["migration_commit"] = "e" * 40
                elif mutation == "generic-error":
                    run_data["error"] = "run timed out after 120 seconds"
                    run_data["error_class"] = "timeout-v1"
                    stdout = "Error: Timeout(120)\n"
            output = directory / f"probe-output.probe-{current_stage}"
            output.mkdir()
            (output / "run.json").write_text(json.dumps(run_data))
            if mutation != "missing-packets":
                (output / "packets.csv").write_text(
                    "direction,monotonic_us,connection,observed_udp_length\n"
                    "outgoing,1,0,1200\nincoming,2,0,1000\n"
                )
        options["log"].write_text(stdout)
        return subprocess.CompletedProcess(command, 101 if mutation == "panic" else 1, stdout)

    monkeypatch.setattr(prepare, "run", actual_run)
    kind = (prepare.PreparationError if mutation == "panic" else
            prepare.RecoverablePreparationError if mutation is not None or not require_complete_coverage else
            prepare.FullGraphH3PolicyError)
    with pytest.raises(kind) as raised:
        prepare.prepare_workload(
            "peer-probe-failure", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0,
            require_complete_coverage=require_complete_coverage,
        )
    return raised.value


@pytest.mark.parametrize("stage", ["head", "get"])
def test_actual_peer_probe_failure_keeps_whole_graph_and_actual_child_proof(stage, tmp_path, monkeypatch):
    error = _actual_peer_probe_failure(tmp_path, monkeypatch, stage=stage)
    assert type(error) is prepare.FullGraphH3PolicyError
    value = prepare.validate_preparation_policy_failure_evidence(error.evidence, source_url="https://page.test/")
    assert value["schema_version"] == 2
    assert value["stage"] == "full-graph-h3"
    assert value["resolved_probe"] is None  # An aborted probe produced no manifest.
    assert [row["id"] for row in value["discovery"]["resources"]] == [0, 1]
    assert value["discovery"]["resources"][1]["depends_on"] == [0]
    assert value["probe_failure"]["resource_ids"] == [1]
    assert value["probe_failure"]["origin"] == "https://cdn.test"
    assert value["probe_failure"]["probe_stage"] == stage
    raw = prepare._failure_artifact_bytes(value["artifacts"])
    assert json.loads(raw["probe.log.execution.json"])["returncode"] == 1
    assert f"probe-output.probe-{stage}/packets.csv" in raw
    assert raw["probe.log"].startswith(b'Error: RunAborted("HTTP/3 endpoint 0')
    assert error.capture_source["neqo_commit"] == "f" * 40
    assert not list(tmp_path.glob(".*-prepare-*"))
    assert not (tmp_path / "peer-probe-failure.json").exists()


@pytest.mark.parametrize("mutation", [
    "stdout-only", "other-peer-code", "missing-packets", "wrong-client", "generic-error", "panic",
])
def test_non_h3_or_unproved_probe_error_stays_operational(mutation, tmp_path, monkeypatch):
    error = _actual_peer_probe_failure(tmp_path, monkeypatch, mutation=mutation)
    assert type(error) is (prepare.PreparationError if mutation == "panic" else prepare.RecoverablePreparationError)


def test_peer_probe_error_does_not_change_historical_subset_preparation(tmp_path, monkeypatch):
    error = _actual_peer_probe_failure(tmp_path, monkeypatch, require_complete_coverage=False)
    assert type(error) is prepare.RecoverablePreparationError


@pytest.mark.parametrize("mutation", [
    "descriptor", "origin", "resource-url", "child-exit", "command", "run-hash", "future-time",
    "error-code", "error-class", "missing-packets", "wrong-packet-endpoint", "resolved-manifest",
])
def test_peer_probe_verifier_rejects_resealed_invalid_raw_evidence(mutation, tmp_path, monkeypatch):
    evidence = deepcopy(_actual_peer_probe_failure(tmp_path, monkeypatch).evidence)
    raw = prepare._failure_artifact_bytes(evidence["artifacts"])
    run_name = "probe-output.probe-head/run.json"
    run_data = json.loads(raw[run_name])
    if mutation == "descriptor":
        evidence["probe_failure"]["resource_ids"] = [0]
    elif mutation == "origin":
        run_data["endpoints"][0]["origin"] = "https://unrelated.test"
    elif mutation == "resource-url":
        run_data["responses"][1]["url"] = "https://unrelated.test/app.js"
    elif mutation in ("child-exit", "command"):
        execution = json.loads(raw["probe.log.execution.json"])
        if mutation == "child-exit":
            execution["returncode"] = 2
        else:
            execution["command"][-1] = "999"
        _replace_failure_artifact(evidence, "probe.log.execution.json", json.dumps(execution).encode())
    elif mutation == "run-hash":
        run_data["workload_hash_sha256"] = "0" * 64
    elif mutation == "future-time":
        run_data["ended_unix_ns"] = 999999999999999999999
    elif mutation == "error-code":
        run_data["error"] = run_data["error"].replace("Peer(296)", "Peer(297)")
    elif mutation == "error-class":
        run_data["error_class"] = "client-defense-fidelity-v1"
    elif mutation == "missing-packets":
        del evidence["artifacts"]["probe-output.probe-head/packets.csv"]
    elif mutation == "wrong-packet-endpoint":
        _replace_failure_artifact(evidence, "probe-output.probe-head/packets.csv",
                                  raw["probe-output.probe-head/packets.csv"].replace(b",0,", b",1,"))
    else:
        _replace_failure_artifact(evidence, "probe-output.json", b'{"resources": []}')
    _replace_failure_artifact(evidence, run_name, json.dumps(run_data).encode())
    with pytest.raises(ValueError):
        prepare.validate_preparation_policy_failure_evidence(evidence, source_url="https://page.test/")


@pytest.mark.parametrize("mutation", ["failed-head", "different-missing-resource"])
def test_peer_get_fallback_requires_actual_complete_head_selection(mutation, tmp_path, monkeypatch):
    evidence = deepcopy(_actual_peer_probe_failure(tmp_path, monkeypatch, stage="get").evidence)
    raw = prepare._failure_artifact_bytes(evidence["artifacts"])
    name = "probe-output.probe-head/run.json"
    head = json.loads(raw[name])
    if mutation == "failed-head":
        head["completion_status"] = "partial"
    else:
        head["responses"][1]["content_length"] = 100
        head["responses"][0]["content_length"] = None
    _replace_failure_artifact(evidence, name, json.dumps(head).encode())
    with pytest.raises(ValueError):
        prepare.validate_preparation_policy_failure_evidence(evidence)


def test_typed_preparation_failures_keep_historical_exception_identity():
    from qcsd_lab import acquisition_errors

    assert prepare.PreparationError is acquisition_errors.PreparationError
    assert prepare.RecoverablePreparationError is acquisition_errors.RecoverablePreparationError
    for kind in (prepare.FullGraphH3PolicyError, prepare.ResponseStabilityPolicyError):
        assert issubclass(kind, prepare.RecoverablePreparationError)
        assert issubclass(kind, acquisition_errors.RecoverableAcquisitionError)


@pytest.mark.parametrize("stage", ["full-graph-h3", "response-stability"])
def test_actual_policy_failure_retains_raw_files_after_cleanup(stage, tmp_path, monkeypatch):
    error = _actual_policy_failure(tmp_path, monkeypatch, stage=stage)
    value = prepare.validate_preparation_policy_failure_evidence(
        error.evidence, source_url="https://page.test/",
    )
    assert value == error.evidence
    assert value["stage"] == stage
    assert [resource["id"] for resource in value["discovery"]["resources"]] == [0, 1]
    assert [resource["id"] for resource in value["resolved_probe"]["resources"]] == [0, 1]
    assert error.capture_source["image_digest"] == "sha256:" + "a" * 64
    assert datetime.fromisoformat(error.capture_started_at) <= datetime.fromisoformat(error.capture_completed_at)
    assert not list(tmp_path.glob(".*-prepare-*"))
    assert not (tmp_path / "typed-failure.json").exists()
    assert "probe-input.json" in value["artifacts"]
    if stage == "response-stability":
        assert len(value["response_runs"]) == 3
        assert all(f"stability-{index}/run.json" in value["artifacts"] for index in range(3))
        assert all(f"stability-{index}/packets.csv" in value["artifacts"] for index in range(3))
        assert len({run["responses"][1]["body_sha256"] for run in value["response_runs"]}) == 3


@pytest.mark.parametrize("stage", ["full-graph-h3", "response-stability"])
@pytest.mark.parametrize("mutation", ["wrong-page", "legacy-subset", "corrupt-bytes", "nonzero-child", "bad-child-time", "changed-graph"])
def test_policy_failure_verifier_rejects_resealed_invalid_stage(stage, mutation, tmp_path, monkeypatch):
    evidence = deepcopy(_actual_policy_failure(tmp_path, monkeypatch, stage=stage).evidence)
    expected_page = "https://page.test/"
    if mutation == "wrong-page":
        expected_page = "https://page.test/other"
    elif mutation == "legacy-subset":
        evidence["require_complete_coverage"] = False
    elif mutation == "corrupt-bytes":
        evidence["artifacts"]["probe-output.json"]["content_base64"] = base64.b64encode(b"{}").decode()
    elif mutation in ("nonzero-child", "bad-child-time"):
        raw = prepare._failure_artifact_bytes(evidence["artifacts"])["probe.log.execution.json"]
        execution = json.loads(raw)
        execution["returncode" if mutation == "nonzero-child" else "started_at"] = (
            1 if mutation == "nonzero-child" else "2099-01-01T00:00:00+00:00"
        )
        _replace_failure_artifact(evidence, "probe.log.execution.json", json.dumps(execution).encode())
    else:
        evidence["resolved_probe"]["resources"][1]["depends_on"] = []
        _replace_failure_artifact(evidence, "probe-output.json", json.dumps(evidence["resolved_probe"]).encode())
    with pytest.raises(ValueError):
        prepare.validate_preparation_policy_failure_evidence(evidence, source_url=expected_page)


def test_full_graph_policy_failure_verifier_requires_actual_unavailable_resource(tmp_path, monkeypatch):
    evidence = deepcopy(_actual_policy_failure(tmp_path, monkeypatch).evidence)
    evidence["resolved_probe"]["resources"][1]["known_valid"] = True
    _replace_failure_artifact(evidence, "probe-output.json", json.dumps(evidence["resolved_probe"]).encode())
    with pytest.raises(ValueError, match="does not prove unavailable"):
        prepare.validate_preparation_policy_failure_evidence(evidence)


@pytest.mark.parametrize("mutation", ["stable", "missing-run", "missing-resource", "duplicate-resource", "invalid-body-hash", "errored-run", "invalid-packets", "unbound-raw-run"])
def test_response_policy_failure_verifier_rederives_actual_drift(mutation, tmp_path, monkeypatch):
    evidence = deepcopy(_actual_policy_failure(tmp_path, monkeypatch, stage="response-stability").evidence)
    runs = evidence["response_runs"]
    if mutation == "stable":
        for run in runs:
            run["responses"][1]["body_sha256"] = runs[0]["responses"][1]["body_sha256"]
    elif mutation == "missing-run":
        runs.pop()
    elif mutation == "missing-resource":
        runs[1]["responses"].pop()
    elif mutation == "duplicate-resource":
        runs[1]["responses"].append(deepcopy(runs[1]["responses"][0]))
    elif mutation == "invalid-body-hash":
        runs[1]["responses"][1]["body_sha256"] = "unavailable"
    elif mutation == "errored-run":
        runs[1]["error"] = "some operational failure"
    elif mutation == "invalid-packets":
        raw = prepare._failure_artifact_bytes(evidence["artifacts"])["stability-1/packets.csv"]
        _replace_failure_artifact(evidence, "stability-1/packets.csv", raw.replace(b",1200,", b",1201,"))
    else:
        runs[1]["responses"][1]["bytes"] += 1
    if mutation != "unbound-raw-run":
        for index, run in enumerate(runs):
            _replace_failure_artifact(evidence, f"stability-{index}/run.json", json.dumps(run).encode())
    with pytest.raises(ValueError):
        prepare.validate_preparation_policy_failure_evidence(evidence)


@pytest.mark.parametrize("operational", ["nonzero", "panic", "timeout", "missing-response", "errored-run"])
def test_actual_operational_failure_never_becomes_typed_policy_deferral(operational, tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch, changing_resource=1)
    fake_run = prepare.run

    def actual_run(command, **options):
        if command[1] == "run":
            if operational in ("nonzero", "panic"):
                return subprocess.CompletedProcess(command, 101 if operational == "panic" else 1, "failure")
            if operational == "timeout":
                from qcsd_lab.util import ProcessTimeoutError
                raise ProcessTimeoutError(subprocess.CompletedProcess(command, -9, "timeout"), options["timeout"], killed=True)
        result = fake_run(command, **options)
        if command[1] == "run" and operational in ("missing-response", "errored-run"):
            path = Path(command[command.index("--output-dir") + 1]) / "run.json"
            value = json.loads(path.read_bytes())
            if operational == "missing-response":
                value["responses"].pop()
            else:
                value["error"] = "operational"
            path.write_text(json.dumps(value))
        return result

    monkeypatch.setattr(prepare, "run", actual_run)
    with pytest.raises(prepare.PreparationError) as raised:
        prepare.prepare_workload(
            "operational", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
        )
    assert type(raised.value) is (prepare.PreparationError if operational == "panic" else prepare.RecoverablePreparationError)


def test_unexpected_live_failure_retains_actual_bytes_and_original_error(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch)
    actual_run = prepare.run
    source = prepare.source_metadata()
    raw_source = json.dumps(source, indent=2).encode()
    source_path = tmp_path / "runtime-source.json"
    source_path.write_bytes(raw_source)
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(source_path))
    error = OSError("unexpected external runner failure")
    original_directory = None
    actual_bytes = {}

    def fail_live_run(command, **options):
        nonlocal original_directory, actual_bytes
        if command[1] != "run":
            return actual_run(command, **options)
        output = Path(command[command.index("--output-dir") + 1])
        output.mkdir()
        (output / "run.json").write_bytes(b'{"actual":"incomplete"}\n')
        (output / "packets.csv").write_bytes(b"actual partial packet bytes\x00\xff\n")
        (output / "schedule.csv").write_bytes(b"actual partial schedule\n")
        options["log"].write_bytes(b"actual child log before failure\n")
        original_directory = output.parent
        actual_bytes = {path.relative_to(original_directory).as_posix(): path.read_bytes()
                        for path in original_directory.rglob("*") if path.is_file()}
        raise error

    monkeypatch.setattr(prepare, "run", fail_live_run)
    with pytest.raises(OSError) as raised:
        prepare.prepare_workload(
            "unexpected-live-failure", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
        )
    assert raised.value is error
    destination = tmp_path / "unexpected-live-failure-failure-evidence"
    assert error.preparation_failure_diagnostics == {"state": "retained", "path": str(destination)}
    assert original_directory is not None and not original_directory.exists()
    for relative, raw in actual_bytes.items():
        assert (destination / "artifacts" / relative).read_bytes() == raw
    metadata = json.loads((destination / "diagnostics.json").read_bytes())
    assert metadata["files"] == {relative: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
                                 for relative, raw in actual_bytes.items()}
    assert metadata["capture_source_before"] == metadata["capture_source_after"] == source
    assert metadata["runtime_source_raw_sha256"] == hashlib.sha256(raw_source).hexdigest()
    assert (destination / "runtime-source.json").read_bytes() == raw_source
    assert (destination / "producer-prepare.py").read_bytes() == Path(prepare.__file__).read_bytes()
    assert json.loads((destination / "discovery.json").read_bytes())["source_url"] == "https://page.test/"
    assert datetime.fromisoformat(metadata["started_at"]) <= datetime.fromisoformat(metadata["completed_at"])
    assert metadata["scientific_credit"] is False and metadata["failure_classification"] == "none-diagnostic-only"
    assert not hasattr(error, "evidence") and not (tmp_path / "unexpected-live-failure.json").exists()


def test_diagnostic_storage_failure_preserves_original_directory_and_exception(tmp_path, monkeypatch):
    original = RuntimeError("original live action failed")

    def cannot_retain(*args, **kwargs):
        raise OSError("diagnostic storage unavailable")

    monkeypatch.setattr(prepare, "_retain_preparation_diagnostics", cannot_retain)
    with pytest.raises(RuntimeError) as raised:
        with prepare._retained_preparation_directory(
            tmp_path, workload_id="storage-failure", source_url="https://page.test/", discovery=discovered(),
            capture_source={"actual": "source"}, started_at=datetime.now().isoformat(),
        ) as directory:
            (directory / "actual.log").write_bytes(b"retained original runner bytes\n")
            raise original
    assert raised.value is original
    state = original.preparation_failure_diagnostics
    assert state["state"] == "original-directory-preserved-retention-incomplete"
    assert (Path(state["path"]) / "actual.log").read_bytes() == b"retained original runner bytes\n"
    assert state["retention_exception_type"] == "OSError"
    assert state["retention_message"] == "diagnostic storage unavailable"
    assert any("raw directory preserved" in note for note in original.__notes__)


def test_preflight_argument_failure_produces_no_live_diagnostic_authority(tmp_path):
    with pytest.raises(ValueError, match="source URL is not absolute HTTPS"):
        prepare.prepare_workload("invalid-workload", "http://page.test/", ["https://page.test"], output_root=tmp_path)
    assert not list(tmp_path.iterdir())


def _actual_render_failure_evidence():
    discovery = discovered()
    render = deepcopy(discovery.render_observation)
    render.update(cutoff_ms=30_000, cutoff_reason="hard-cap-non-quiescent")
    return {
        "passive_render_contract": discovery.passive_render_contract,
        "passive_render_contract_sha256": discovery.passive_render_contract_sha256,
        "render_observation": render,
        "render_observation_sha256": evidence_sha256(render),
    }


def test_passive_render_failure_validator_requires_valid_actual_hard_cap():
    evidence = _actual_render_failure_evidence()
    assert prepare.validate_passive_render_policy_failure_evidence(evidence) == evidence
    evidence["render_observation"]["cutoff_ms"] = 29_999
    evidence["render_observation_sha256"] = evidence_sha256(evidence["render_observation"])
    with pytest.raises(ValueError, match="outside its boundary"):
        prepare.validate_passive_render_policy_failure_evidence(evidence)


def test_actual_passive_render_failure_keeps_raw_evidence_and_runtime_interval(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch)
    evidence = _actual_render_failure_evidence()

    def failure(*args, **kwargs):
        raise prepare.PassiveRenderPolicyError("bounded render reached its actual hard cap", evidence=evidence)

    monkeypatch.setattr(prepare, "discover_page", failure)
    with pytest.raises(prepare.PassiveRenderPolicyError) as raised:
        prepare.prepare_workload(
            "render-failure", "https://page.test/", ["https://page.test", "https://cdn.test"], output_root=tmp_path,
        )
    assert raised.value.evidence == evidence
    assert raised.value.capture_source["lab_commit"] == "lab"
    assert datetime.fromisoformat(raised.value.capture_started_at) <= datetime.fromisoformat(raised.value.capture_completed_at)
