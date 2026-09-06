from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
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
)
from qcsd_lab.discover import DiscoveryResult
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
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
                    "safe_request_headers": resource["headers"],
                    "interception_required": True,
                    "redirected": False,
                    "redirect_from_occurrence_id": None,
                    "mapping": {"kind": "resource", "resource_id": resource["id"]},
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
                    "network_occurrence_ids": [occurrence],
                },
            ]
        )
    audit = {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": evidence_sha256(render),
        "events": events,
        "summary": {
            "event_count": len(events),
            "target_event_count": 0,
            "network_request_count": 2,
            "fetch_request_count": 2,
            "fetch_internal_restart_count": 0,
            "terminal_event_count": 2,
            "resource_occurrence_count": 2,
            "exclusion_occurrence_count": 0,
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
        "schema_version": 1,
        "configured_udp_payload_ceiling": 1_200,
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


@pytest.mark.parametrize("direction", ["incoming", "outgoing"])
def test_prepare_rejects_any_absolute_udp_ceiling_violation(direction, tmp_path, monkeypatch):
    other = "outgoing" if direction == "incoming" else "incoming"
    install_fake_preparation(
        monkeypatch,
        packet_rows=[(direction, "0", "1280"), (other, "1", "1200")],
    )

    with pytest.raises(
        prepare.PreparationError,
        match=r"stability run 1 observed 1 UDP payload.*above the 1200-byte ceiling",
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
            {"resolved_configuration": {"max_udp_payload_size": 1_200}},
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
            {"resolved_configuration": {"max_udp_payload_size": 1_200}},
            path,
            run_index=0,
            expected_ceiling=1_200,
        )

    path.write_text("direction,connection\nincoming,0\n", encoding="utf-8")
    with pytest.raises(prepare.PreparationError, match="missing required columns"):
        prepare._qualify_udp_payloads(
            {"resolved_configuration": {"max_udp_payload_size": 1_200}},
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
