from __future__ import annotations

import copy
import hashlib
import http.client
import json
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import pinned_cdp
from qcsd_lab.acquisition_errors import NonReplayableEgressPolicyError
from qcsd_lab.browser_egress import (
    BROWSER_EGRESS_DISABLED_BASE_FEATURES,
    BROWSER_EGRESS_DISABLED_BLINK_FEATURES,
    BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES,
    BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES,
    BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES,
    BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
    NON_REPLAYABLE_EGRESS_POLICY,
    NonReplayableEgressGuard,
    build_fail_closed_host_resolver_argument,
    target_egress_apis,
    validate_browser_egress_command_line,
)
from qcsd_lab.cdp_targets import EGRESS_PREARM_SUMMARY_SCHEMA_VERSION
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes
from qcsd_lab.playwright_driver import DEFAULT_CONFIGURED_EXECUTABLE

COLLECTION_IMAGE = "sha256:" + "1" * 64
PREPARE_IMAGE = "sha256:" + "2" * 64
BUILD_SHA256 = "3" * 64
BUILD_PAYLOAD_SHA256 = "4" * 64
BUILD_COMPLETION_SHA256 = "8" * 64
LAB_COMMIT = "5" * 40
NEQO_COMMIT = "6" * 40
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _driver_binding() -> dict[str, object]:
    return copy.deepcopy(pinned_cdp.EXPECTED_PLAYWRIGHT_DRIVER_BINDING)


def _browser_egress_command_line_projection() -> dict[str, object]:
    return validate_browser_egress_command_line(
        {
            "arguments": [
                str(DEFAULT_CONFIGURED_EXECUTABLE),
                *BROWSER_EGRESS_REQUIRED_CHROMIUM_SWITCHES,
                BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
                "--disable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_DISABLED_FEATURES),
                "--disable-features=" + ",".join(BROWSER_EGRESS_DISABLED_BASE_FEATURES),
                "--disable-blink-features=" + ",".join(BROWSER_EGRESS_DISABLED_BLINK_FEATURES),
                "--enable-features=" + ",".join(BROWSER_EGRESS_PLAYWRIGHT_ENABLED_FEATURES),
                build_fail_closed_host_resolver_argument(
                    approved_origins=pinned_cdp._PINNED_CDP_APPROVED_ORIGINS,
                    origin_ip_pins=pinned_cdp._PINNED_CDP_ORIGIN_IP_PINS,
                ),
            ]
        }
    )


def _target_activity() -> dict[str, object]:
    by_target_type: dict[str, object] = {}
    for target_type in pinned_cdp._TARGET_ACTIVITY_TYPES:
        attached = 0 if target_type == "page" else 1
        by_target_type[target_type] = {
            "total": attached,
            "max_source_generation": 0 if attached else None,
            "event_counts": {
                event: attached if event == "target-attached" else 0
                for event in pinned_cdp._TARGET_ACTIVITY_EVENTS
            },
        }
    return {
        "schema_version": pinned_cdp.TARGET_ACTIVITY_SCHEMA_VERSION,
        "generation": 3,
        "by_target_type": by_target_type,
    }


def _srcdoc_pseudo_document_summary() -> dict[str, object]:
    loader_digest = hashlib.sha256(b"fixture-srcdoc-loader").hexdigest()
    return {
        "schema_version": pinned_cdp.SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": pinned_cdp.SRCDOC_PSEUDO_DOCUMENT_POLICY,
        "enabled": True,
        "total": 1,
        "resolved": 1,
        "pending": 0,
        "aborted": 0,
        "open_candidates": 0,
        "network_history_saturated": False,
        "fetch_history_saturated": False,
        "candidate_limit_saturated": False,
        "diagnostics": [
            {
                "schema_version": 2,
                "source_role": "root-page",
                "frame_id_sha256": hashlib.sha256(b"fixture-srcdoc-frame").hexdigest(),
                "loader_id_sha256": loader_digest,
                "request_id_sha256": loader_digest,
                "requested_event_ordinal": 1,
                "started_navigating_event_ordinal": 2,
                "started_event_ordinal": 3,
                "terminal_event_ordinal": 4,
                "stopped_event_ordinal": 5,
                "navigation_reason": "initialFrameNavigation",
                "navigation_type": "differentDocument",
                "disposition": "currentTab",
                "url_kind": "about:srcdoc",
                "loader_binding": "Page.frameStartedNavigating.loaderId",
                "request_id_matches_loader": True,
                "terminal_method": "Network.loadingFailed",
                "terminal_fields": [
                    "canceled",
                    "errorText",
                    "requestId",
                    "timestamp",
                    "type",
                ],
                "resource_type": "Document",
                "error_text": "net::ERR_ABORTED",
                "canceled": True,
                "network_request_seen": False,
                "fetch_pause_seen": False,
                "frame_stopped_after_terminal": True,
            }
        ],
    }


def _egress_prearm_summary() -> dict[str, object]:
    by_type = {}
    for target_type in ("page", "iframe", "worker", "shared_worker"):
        by_type[target_type] = {
            "target_count": 1,
            "installed_count": 1,
            "pending_count": 0,
            "protected_api_observations": len(target_egress_apis(target_type)),
            "unavailable_api_observations": 0,
            "popup_guard_required_count": int(target_type in {"page", "iframe"}),
            "popup_guard_installed_count": int(target_type in {"page", "iframe"}),
        }
    return {
        "schema_version": EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "target_total": 4,
        "installed_total": 4,
        "pending_total": 0,
        "popup_guard_required_total": 2,
        "popup_guard_installed_total": 2,
        "by_target_type": by_type,
    }


def _non_replayable_egress_summary() -> dict[str, object]:
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    return guard.success_summary()


def _successful_egress_guard() -> NonReplayableEgressGuard:
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    return guard


def _source(image: str) -> dict[str, object]:
    return {
        "image_digest": image,
        "lab_commit": LAB_COMMIT,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": NEQO_COMMIT,
        "neqo_pinned_commit": NEQO_COMMIT,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }


def _observation(uid: int = 1000, gid: int = 1000) -> dict[str, object]:
    return {
        "playwright_version": "1.57.0",
        "chromium_version": "143.0.7499.4",
        "chromium_executable": "/usr/local/bin/qcsd-chromium",
        "playwright_driver": _driver_binding(),
        "isolation": {
            "real_uid": uid,
            "effective_uid": uid,
            "saved_uid": uid,
            "filesystem_uid": uid,
            "real_gid": gid,
            "effective_gid": gid,
            "saved_gid": gid,
            "filesystem_gid": gid,
            "expected_uid": uid,
            "expected_gid": gid,
            "supplementary_groups": [gid],
            "inheritable_capabilities": "0000000000000000",
            "permitted_capabilities": "0000000000000000",
            "effective_capabilities": "0000000000000000",
            "bounding_capabilities": "0000000000000000",
            "ambient_capabilities": "0000000000000000",
            "no_new_privileges": True,
            "observed_interfaces": ["lo"],
        },
        "topology": {
            "observed_target_types": ["iframe", "page", "shared_worker", "worker"],
            "event_count": 42,
            "event_method_counts": {
                "Fetch.requestPaused": 2,
                "Network.loadingFailed": 0,
                "Network.loadingFinished": 11,
                "Network.requestServedFromCache": 0,
                "Network.requestWillBeSent": 11,
                "Network.requestWillBeSentExtraInfo": 7,
                "Network.responseReceived": 11,
            },
            "cross_site_iframe_request": True,
            "duplicate_request_occurrences": 2,
            "redirect_target_request": True,
            "worker_network_target_types": ["shared_worker", "worker"],
            "dedicated_worker_network_request": True,
            "shared_worker_network_request": True,
            "dedicated_worker_fetch_paused_on_page": True,
            "shared_worker_fetch_paused_on_shared_worker": True,
            "http_status_counts": copy.deepcopy(pinned_cdp._EXPECTED_HTTP_STATUS_COUNTS),
            "server_request_counts": copy.deepcopy(pinned_cdp._EXPECTED_SERVER_REQUEST_COUNTS),
            "bootstrap_prearm_summary": copy.deepcopy(
                pinned_cdp._EXPECTED_PINNED_BOOTSTRAP_PREARM_SUMMARY
            ),
            "egress_prearm_summary": _egress_prearm_summary(),
            "srcdoc_pseudo_document_summary": _srcdoc_pseudo_document_summary(),
            "non_replayable_egress_summary": _non_replayable_egress_summary(),
            "browser_egress_command_line": _browser_egress_command_line_projection(),
            "browser_context_service_worker_count": 0,
            "worker_response_consumption": copy.deepcopy(
                pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
            ),
            "worker_webtransport_probe": copy.deepcopy(
                pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_PROBE
            ),
            "quiescent_target_activity": _target_activity(),
            "router_closed": True,
            "browser_guard_closed": True,
            "ledger_closed": True,
            "extra_info_closed": True,
            "browser_closed": True,
            "server_thread_stopped": True,
        },
    }


@pytest.fixture
def fake_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "build-execution-v59.json"
    path.write_bytes(canonical_json_bytes({"payload_sha256": BUILD_PAYLOAD_SHA256}))
    build = {
        "path": str(path.resolve()),
        "sha256": BUILD_SHA256,
        "cohort_version": 59,
        "completion_path": str((tmp_path / "build-completion-v59.json").resolve()),
        "completion_sha256": BUILD_COMPLETION_SHA256,
        "collection_image": COLLECTION_IMAGE,
        "images": {
            "collection": {"id": COLLECTION_IMAGE},
            "prepare": {"id": PREPARE_IMAGE},
            "reference": {"id": "sha256:" + "7" * 64},
        },
        "source": _source(COLLECTION_IMAGE),
        "started_at": "2020-01-01T00:00:00+00:00",
        "finished_at": "2020-01-01T00:01:00+00:00",
        "passed": True,
    }

    def validate(path_arg, *, expected_cohort_version=None, allow_historical=None, **_kwargs):
        assert Path(path_arg).resolve() == path.resolve()
        assert expected_cohort_version in {None, 59}
        assert allow_historical is False
        return copy.deepcopy(build)

    monkeypatch.setattr(pinned_cdp, "validate_build_execution_receipt", validate)
    monkeypatch.setattr(pinned_cdp, "source_metadata", lambda: _source(PREPARE_IMAGE))
    monkeypatch.setattr(
        pinned_cdp,
        "validate_default_playwright_driver_once",
        lambda: {"validated": True},
    )
    monkeypatch.setattr(
        pinned_cdp,
        "_driver_binding",
        lambda _receipt: _driver_binding(),
    )
    monkeypatch.setattr(
        pinned_cdp,
        "run_pinned_cdp_probe",
        lambda **_kwargs: _observation(),
    )
    return path


def _create(tmp_path: Path, fake_build: Path) -> Path:
    return pinned_cdp.create_pinned_cdp_receipt(
        tmp_path / "pinned-cdp-execution-v59.json",
        build_execution_receipt=fake_build,
        cohort_version=59,
        expected_uid=1000,
        expected_gid=1000,
    )


def test_receipt_is_create_only_and_binds_build_source_prepare_image_and_cohort(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    output = _create(tmp_path, fake_build)

    validated = pinned_cdp.validate_pinned_cdp_receipt(
        output,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        runtime_role="prepare",
    )
    assert validated["result"] == "pass"
    assert validated["cohort_version"] == 59
    assert validated["prepare_image_digest"] == PREPARE_IMAGE
    assert validated["prepare_source"] == _source(PREPARE_IMAGE)
    assert validated["collection_source"] == _source(COLLECTION_IMAGE)
    assert validated["observation"]["playwright_driver"] == _driver_binding()
    assert validated["build_execution"] == {
        "path": "/lab/artifacts/buflo-study/build-execution-v59.json",
        "sha256": BUILD_SHA256,
        "payload_sha256": BUILD_PAYLOAD_SHA256,
    }
    assert validated["build_execution_identity"]["completion_path"] == (
        "/lab/artifacts/buflo-study/build-completion-v59.json"
    )
    assert validated["build_execution_identity"]["completion_sha256"] == (BUILD_COMPLETION_SHA256)
    assert output.read_bytes() == canonical_json_bytes(json.loads(output.read_text()))

    with pytest.raises(FileExistsError, match="create-only"):
        _create(tmp_path, fake_build)


def test_schema8_receipt_is_historical_only_and_round_trips(
    tmp_path: Path,
    fake_build: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = pinned_cdp.HISTORICAL_PROBE_SCHEMA_VERSION
    payload["probe_contract"] = copy.deepcopy(pinned_cdp._HISTORICAL_PROBE_CONTRACT)
    payload["probe_contract_sha256"] = pinned_cdp._HISTORICAL_PROBE_CONTRACT_SHA256
    payload["observation"]["playwright_driver"] = copy.deepcopy(
        pinned_cdp.LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    payload["observation"]["topology"]["browser_egress_command_line"][
        "host_resolver_policy"
    ] = copy.deepcopy(pinned_cdp._HISTORICAL_PINNED_CDP_RESOLVER_PROJECTION)
    payload["build_execution_identity"].pop("completion_path")
    payload["build_execution_identity"].pop("completion_sha256")
    payload["observation"]["topology"].pop("worker_response_consumption")
    payload["observation"]["topology"].pop("worker_webtransport_probe")
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema8.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="identity or result"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )

    build = pinned_cdp.validate_build_execution_receipt(
        fake_build,
        expected_cohort_version=59,
        allow_historical=False,
    )

    def validate_historical(*_args, **kwargs):
        assert kwargs["allow_historical"] is True
        return copy.deepcopy(build)

    monkeypatch.setattr(pinned_cdp, "validate_build_execution_receipt", validate_historical)
    validated = pinned_cdp.validate_pinned_cdp_receipt(
        historical,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        allow_historical=True,
    )
    assert validated["probe_schema_version"] == 8
    assert set(validated["build_execution_identity"]) == {
        "cohort_version",
        "sha256",
        "collection_image",
        "started_at",
        "finished_at",
    }
    assert "worker_response_consumption" not in validated["observation"]["topology"]


def test_schema9_receipt_is_historical_only_and_keeps_current_build_identity(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 9
    payload["probe_contract"] = copy.deepcopy(pinned_cdp._HISTORICAL_PROBE_CONTRACT)
    payload["probe_contract_sha256"] = pinned_cdp._HISTORICAL_PROBE_CONTRACT_SHA256
    payload["observation"]["playwright_driver"] = copy.deepcopy(
        pinned_cdp.LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    payload["observation"]["topology"]["browser_egress_command_line"][
        "host_resolver_policy"
    ] = copy.deepcopy(pinned_cdp._HISTORICAL_PINNED_CDP_RESOLVER_PROJECTION)
    payload["observation"]["topology"].pop("worker_response_consumption")
    payload["observation"]["topology"].pop("worker_webtransport_probe")
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema9.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="identity or result"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )

    validated = pinned_cdp.validate_pinned_cdp_receipt(
        historical,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        allow_historical=True,
    )
    assert validated["probe_schema_version"] == 9
    assert set(validated["build_execution_identity"]) == {
        "cohort_version",
        "sha256",
        "completion_path",
        "completion_sha256",
        "collection_image",
        "started_at",
        "finished_at",
    }
    assert "worker_response_consumption" not in validated["observation"]["topology"]


def test_schema11_receipt_is_historical_only_with_v7_driver(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 11
    payload["probe_contract"] = copy.deepcopy(pinned_cdp._HISTORICAL_PROBE_CONTRACT_V11)
    payload["probe_contract_sha256"] = pinned_cdp._HISTORICAL_PROBE_CONTRACT_V11_SHA256
    payload["observation"]["playwright_driver"] = copy.deepcopy(
        pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    payload["observation"]["topology"]["browser_egress_command_line"][
        "host_resolver_policy"
    ] = copy.deepcopy(pinned_cdp._HISTORICAL_PINNED_CDP_RESOLVER_PROJECTION)
    payload["observation"]["topology"].pop("worker_webtransport_probe")
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema11.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="identity or result"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )

    validated = pinned_cdp.validate_pinned_cdp_receipt(
        historical,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        allow_historical=True,
    )
    assert validated["probe_schema_version"] == 11
    assert validated["observation"]["playwright_driver"] == (
        pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert "completion_path" in validated["build_execution_identity"]
    assert "worker_response_consumption" in validated["observation"]["topology"]
    assert "worker_webtransport_probe" not in validated["observation"]["topology"]


def test_schema12_receipt_is_historical_only_with_v7_driver(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 12
    payload["probe_contract"] = copy.deepcopy(pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12)
    payload["probe_contract_sha256"] = pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12_SHA256
    payload["observation"]["playwright_driver"] = copy.deepcopy(
        pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema12.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="identity or result"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )

    validated = pinned_cdp.validate_pinned_cdp_receipt(
        historical,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        allow_historical=True,
    )
    assert validated["probe_schema_version"] == 12
    assert validated["observation"]["playwright_driver"] == (
        pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert validated["observation"]["topology"]["browser_egress_command_line"][
        "host_resolver_policy"
    ] == pinned_cdp._PINNED_CDP_RESOLVER_PROJECTION
    assert "worker_webtransport_probe" in validated["observation"]["topology"]


def test_schema12_receipt_still_requires_worker_webtransport_probe(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 12
    payload["probe_contract"] = copy.deepcopy(pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12)
    payload["probe_contract_sha256"] = pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12_SHA256
    payload["observation"]["playwright_driver"] = copy.deepcopy(
        pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    payload["observation"]["topology"].pop("worker_webtransport_probe")
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema12-without-worker-probe.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="topology fields"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
            allow_historical=True,
        )


def test_schema13_receipt_is_historical_only_with_v8_driver(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 13
    payload["probe_contract"] = copy.deepcopy(
        pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13
    )
    payload["probe_contract_sha256"] = (
        pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13_SHA256
    )
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema13.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="identity or result"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )

    validated = pinned_cdp.validate_pinned_cdp_receipt(
        historical,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        allow_historical=True,
    )
    assert validated["probe_schema_version"] == 13
    assert validated["observation"]["playwright_driver"] == _driver_binding()
    assert "worker_webtransport_probe" in validated["observation"]["topology"]


def test_schema13_receipt_still_requires_worker_webtransport_probe(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 13
    payload["probe_contract"] = copy.deepcopy(
        pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13
    )
    payload["probe_contract_sha256"] = (
        pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13_SHA256
    )
    payload["observation"]["topology"].pop("worker_webtransport_probe")
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema13-without-worker-probe.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="topology fields"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
            allow_historical=True,
        )


def test_schema14_receipt_is_historical_only_without_srcdoc_summary(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["probe_schema_version"] = 14
    payload["probe_contract"] = copy.deepcopy(
        pinned_cdp._HISTORICAL_PROBE_CONTRACT_V14
    )
    payload["probe_contract_sha256"] = (
        pinned_cdp._HISTORICAL_PROBE_CONTRACT_V14_SHA256
    )
    payload["observation"]["topology"].pop("srcdoc_pseudo_document_summary")
    historical = tmp_path / "pinned-cdp-schema14.json"
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="identity or result"):
        pinned_cdp.validate_pinned_cdp_receipt(
            historical,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )

    validated = pinned_cdp.validate_pinned_cdp_receipt(
        historical,
        build_execution_receipt=fake_build,
        expected_cohort_version=59,
        allow_historical=True,
    )
    assert validated["probe_schema_version"] == 14
    assert "srcdoc_pseudo_document_summary" not in validated["observation"]["topology"]


def test_current_receipt_rejects_frozen_historical_resolver_projection(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    current = _create(tmp_path, fake_build)
    envelope = json.loads(current.read_text(encoding="utf-8"))
    payload = copy.deepcopy(envelope["payload"])
    payload["observation"]["topology"]["browser_egress_command_line"][
        "host_resolver_policy"
    ] = copy.deepcopy(pinned_cdp._HISTORICAL_PINNED_CDP_RESOLVER_PROJECTION)
    altered = tmp_path / "pinned-cdp-current-with-historical-resolver.json"
    altered.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match="host-resolver policy"):
        pinned_cdp.validate_pinned_cdp_receipt(
            altered,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: payload.update(cohort_version=60), "cohort version"),
        (
            lambda payload: payload.update(prepare_image_digest="sha256:" + "8" * 64),
            "source/build/prepare image",
        ),
        (
            lambda payload: payload["build_execution"].update(sha256="a" * 64),
            "source/build/prepare image",
        ),
        (
            lambda payload: payload["build_execution_identity"].update(completion_sha256="a" * 64),
            "source/build/prepare image",
        ),
        (
            lambda payload: payload["build_execution_identity"].pop("completion_path"),
            "source/build/prepare image",
        ),
        (
            lambda payload: payload["build_execution_identity"].update(
                completion_path="/other/build-completion-v59.json"
            ),
            "source/build/prepare image",
        ),
        (
            lambda payload: payload["prepare_source"].update(lab_commit="9" * 40),
            "source/build/prepare image",
        ),
        (
            lambda payload: payload["observation"]["isolation"].update(
                observed_interfaces=["eth0", "lo"]
            ),
            "isolation evidence",
        ),
        (
            lambda payload: payload["observation"]["topology"].update(
                duplicate_request_occurrences=1
            ),
            "topology evidence",
        ),
        (
            lambda payload: payload["observation"]["topology"].update(
                shared_worker_fetch_paused_on_shared_worker=False
            ),
            "topology evidence",
        ),
        (
            lambda payload: payload["observation"]["playwright_driver"].update(
                content_sha256="b" * 63
            ),
            "Playwright driver evidence",
        ),
        (
            lambda payload: payload.update(probe_contract_sha256="a" * 64),
            "source/build/prepare image",
        ),
    ],
)
def test_validator_rejects_resealed_semantic_tampering(
    tmp_path: Path,
    fake_build: Path,
    mutation,
    message: str,
) -> None:
    output = _create(tmp_path, fake_build)
    value = json.loads(output.read_text())
    payload = copy.deepcopy(value["payload"])
    mutation(payload)
    output.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=pinned_cdp.RECEIPT_TYPE))
    )

    with pytest.raises(ValueError, match=message):
        pinned_cdp.validate_pinned_cdp_receipt(
            output,
            build_execution_receipt=fake_build,
            expected_cohort_version=59,
        )


def test_probe_failure_or_interruption_publishes_no_receipt(
    tmp_path: Path,
    fake_build: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_kwargs):
        raise RuntimeError("topology did not close")

    monkeypatch.setattr(pinned_cdp, "run_pinned_cdp_probe", fail)
    destination = tmp_path / "pinned-cdp-execution-v59.json"

    with pytest.raises(RuntimeError, match="did not close"):
        pinned_cdp.create_pinned_cdp_receipt(
            destination,
            build_execution_receipt=fake_build,
            cohort_version=59,
            expected_uid=1000,
            expected_gid=1000,
        )
    assert not destination.exists()
    assert not list(tmp_path.glob(f".{destination.name}.*.qcsd-tmp"))


def test_validator_rejects_noncanonical_or_symlink_receipt(
    tmp_path: Path,
    fake_build: Path,
) -> None:
    output = _create(tmp_path, fake_build)
    value = json.loads(output.read_text())
    output.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="canonically encoded"):
        pinned_cdp.validate_pinned_cdp_receipt(
            output,
            build_execution_receipt=fake_build,
        )

    output.unlink()
    output.symlink_to(fake_build)
    with pytest.raises(ValueError, match="regular file"):
        pinned_cdp.validate_pinned_cdp_receipt(output)


def test_validator_rejects_wrong_runtime_role_source(
    tmp_path: Path,
    fake_build: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _create(tmp_path, fake_build)
    monkeypatch.setattr(pinned_cdp, "source_metadata", lambda: _source(COLLECTION_IMAGE))

    with pytest.raises(ValueError, match="validation runtime"):
        pinned_cdp.validate_pinned_cdp_receipt(
            output,
            build_execution_receipt=fake_build,
            runtime_role="prepare",
        )
    pinned_cdp.validate_pinned_cdp_receipt(
        output,
        build_execution_receipt=fake_build,
        runtime_role="collection",
    )


def test_prepare_role_revalidates_playwright_driver_binding(
    tmp_path: Path,
    fake_build: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _create(tmp_path, fake_build)
    changed_binding = _driver_binding()
    changed_binding["content_sha256"] = "b" * 64
    monkeypatch.setattr(
        pinned_cdp,
        "_driver_binding",
        lambda _receipt: changed_binding,
    )

    with pytest.raises(ValueError, match="differs from the prepare runtime"):
        pinned_cdp.validate_pinned_cdp_receipt(
            output,
            build_execution_receipt=fake_build,
            runtime_role="prepare",
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda observation: observation["isolation"].update(
                effective_capabilities="0000000000000001"
            ),
            "isolation evidence",
        ),
        (
            lambda observation: observation["isolation"].update(no_new_privileges=False),
            "isolation evidence",
        ),
        (
            lambda observation: observation["isolation"].update(effective_uid=0),
            "isolation evidence",
        ),
        (
            lambda observation: observation["isolation"].update(saved_uid=2000),
            "isolation evidence",
        ),
        (
            lambda observation: observation["isolation"].update(
                bounding_capabilities="0000000000000001"
            ),
            "isolation evidence",
        ),
        (
            lambda observation: observation["topology"].update(
                observed_target_types=["iframe", "page", "worker"]
            ),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"].update(router_closed=False),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"].update(browser_guard_closed=False),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"].update(
                worker_response_consumption={
                    "dedicated_worker": "qcsd-dedicated-response-consumed",
                    "shared_worker": "qcsd-shared-response-error",
                }
            ),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"].pop("worker_response_consumption"),
            "topology fields",
        ),
        (
            lambda observation: observation["topology"].pop("worker_webtransport_probe"),
            "topology fields",
        ),
        (
            lambda observation: observation["topology"].pop(
                "srcdoc_pseudo_document_summary"
            ),
            "topology fields",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(frame_id="raw-frame-id"),
            "diagnostic fields",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(frame_id_sha256="raw-frame-id"),
            "diagnostic hash",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(stopped_event_ordinal=3),
            "event ordering",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(started_navigating_event_ordinal=3),
            "event ordering",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(loader_id_sha256="e" * 64),
            "diagnostic is inconsistent",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(
                loader_binding="Page.frameStartedLoading.loaderId"
            ),
            "diagnostic strings are invalid",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ]["diagnostics"][0].update(request_id_matches_loader=False),
            "diagnostic is inconsistent",
        ),
        (
            lambda observation: observation["topology"].update(
                srcdoc_pseudo_document_summary={
                    **_srcdoc_pseudo_document_summary(),
                    "total": 0,
                    "resolved": 0,
                    "diagnostics": [],
                }
            ),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"].update(
                srcdoc_pseudo_document_summary={
                    **_srcdoc_pseudo_document_summary(),
                    "resolved": 0,
                    "pending": 1,
                    "diagnostics": [],
                }
            ),
            "lifecycle is not terminal",
        ),
        (
            lambda observation: observation["topology"][
                "srcdoc_pseudo_document_summary"
            ].update(network_history_saturated=True),
            "lifecycle is not terminal",
        ),
        (
            lambda observation: observation["topology"]["worker_webtransport_probe"][
                "by_target_type"
            ]["worker"]["measurement"].update(action_succeeded=True),
            "WebTransport action or telemetry",
        ),
        (
            lambda observation: observation["topology"]["worker_webtransport_probe"][
                "by_target_type"
            ]["shared_worker"]["guard_telemetry"].update(mechanism="cdp-network-tripwire"),
            "WebTransport action or telemetry",
        ),
        (
            lambda observation: observation["topology"]["http_status_counts"]["/"].update(
                {"200": 2}
            ),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"]["http_status_counts"]["/"].update(
                {"200": True}
            ),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"]["server_request_counts"].update({"/": 2}),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"]["server_request_counts"].update(
                {"/": True}
            ),
            "topology evidence",
        ),
        (
            lambda observation: observation["topology"]["event_method_counts"].update(
                {"Network.loadingFailed": 1, "Network.loadingFinished": 10}
            ),
            "event-method aggregate",
        ),
        (
            lambda observation: observation["topology"]["bootstrap_prearm_summary"].update(
                release_before_setup_envelopes_total=1
            ),
            "prearm",
        ),
        (
            lambda observation: observation["topology"]["bootstrap_prearm_summary"].update(
                schema_version=True
            ),
            "prearm",
        ),
        (
            lambda observation: observation["topology"]["quiescent_target_activity"].update(
                generation=4
            ),
            "target-activity generation",
        ),
        (
            lambda observation: observation["topology"]["quiescent_target_activity"].update(
                schema_version=True
            ),
            "target-activity aggregate",
        ),
        (
            lambda observation: observation["topology"]["quiescent_target_activity"][
                "by_target_type"
            ]["iframe"]["event_counts"].update({"target-attached": 0, "target-info-changed": 1}),
            "topology evidence",
        ),
        (
            lambda observation: observation["playwright_driver"]["policy"].update(
                activation_value="0"
            ),
            "Playwright driver evidence",
        ),
        (
            lambda observation: observation["playwright_driver"].update(receipt_sha256="b" * 64),
            "Playwright driver evidence",
        ),
        (
            lambda observation: observation.update(playwright_version="1.53.0"),
            "browser evidence",
        ),
    ],
)
def test_observation_validator_rejects_resealed_isolation_and_topology_claims(
    mutation,
    message: str,
) -> None:
    observation = _observation()
    mutation(observation)

    with pytest.raises(ValueError, match=message):
        pinned_cdp._validate_observation(observation)


def _required_topology_events() -> list[tuple[str, str, str]]:
    return [
        ("page", "Network.requestWillBeSent", "http://a.test/"),
        ("iframe", "Network.requestWillBeSent", "http://b.test/frame-data"),
        ("page", "Network.requestWillBeSent", "http://a.test/duplicate"),
        ("page", "Network.requestWillBeSent", "http://a.test/duplicate"),
        ("page", "Network.requestWillBeSent", "http://a.test/redirected"),
        ("worker", "Network.requestWillBeSent", "http://a.test/dedicated-data"),
        ("shared_worker", "Network.requestWillBeSent", "http://a.test/shared-data"),
        ("page", "Fetch.requestPaused", "http://a.test/dedicated-data"),
        ("shared_worker", "Fetch.requestPaused", "http://a.test/shared-data"),
    ]


def _required_target_activity() -> pinned_cdp._TargetActivityLedger:
    activity = pinned_cdp._TargetActivityLedger()
    for target_type in ("iframe", "shared_worker", "worker"):
        activity.record(
            SimpleNamespace(target_type=target_type, generation=0),
            "target-attached",
        )
    return activity


def _completed_worker_webtransport_collector() -> pinned_cdp._WorkerWebTransportGuardCollector:
    collector = pinned_cdp._WorkerWebTransportGuardCollector()
    collector.arm()
    for target_type in pinned_cdp._WORKER_WEBTRANSPORT_TARGET_TYPES:
        assert collector.consume(
            source=SimpleNamespace(target_type=target_type),
            api="WebTransport",
            mechanism="paused-target-runtime-shim",
            url=None,
        )
    return collector


def test_worker_fixtures_consume_exact_success_responses_and_emit_exact_sentinels() -> None:
    server = pinned_cdp._ProbeServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    fixtures = (
        (
            "/dedicated-worker.js",
            "/dedicated-data",
            "self.postMessage",
            "dedicated_worker",
            "qcsd-dedicated-response-consumed",
            "qcsd-dedicated-response-invalid",
            "qcsd-dedicated-response-error",
        ),
        (
            "/shared-worker.js",
            "/shared-data",
            "port.postMessage",
            "shared_worker",
            "qcsd-shared-response-consumed",
            "qcsd-shared-response-invalid",
            "qcsd-shared-response-error",
        ),
    )
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        root_fixture = response.read().decode("utf-8")
        assert response.status == 200
        assert response.getheader("Content-Type") == "text/html"
        assert root_fixture.count("<iframe srcdoc=") == 1
        assert "qcsd-root-srcdoc-lifecycle" in root_fixture

        for (
            script_path,
            data_path,
            emitter,
            worker_type,
            success_sentinel,
            invalid_sentinel,
            error_sentinel,
        ) in fixtures:
            connection.request("GET", script_path)
            response = connection.getresponse()
            script = response.read().decode("utf-8")
            assert response.status == 200
            assert response.getheader("Content-Type") == "text/javascript"
            assert f"await fetch('{data_path}')" in script
            assert script.count("await response.text()") == 1
            assert "response.status === 200 && value === 'ok'" in script
            assert script.count(success_sentinel) == 1
            assert script.count(invalid_sentinel) == 1
            assert script.count(error_sentinel) == 1
            assert script.count(emitter) == 2
            assert script.count("new globalThis.WebTransport") == 1
            assert "action_succeeded: actionSucceeded" in script
            assert "measurement: qcsdWebTransportMeasurement" in script
            assert pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION[worker_type] == (
                success_sentinel
            )

            connection.request("GET", data_path)
            response = connection.getresponse()
            assert response.status == 200
            assert response.read() == b"ok"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert not thread.is_alive()


def test_required_topology_wait_condition_is_event_driven() -> None:
    events = _required_topology_events()

    assert pinned_cdp._required_event_topology_observed(events) is True
    assert pinned_cdp._required_event_topology_observed(events[:-1]) is False
    assert pinned_cdp._event_topology(events) == {
        "observed_target_types": ["iframe", "page", "shared_worker", "worker"],
        "event_count": 9,
        "event_method_counts": {
            "Fetch.requestPaused": 2,
            "Network.loadingFailed": 0,
            "Network.loadingFinished": 0,
            "Network.requestServedFromCache": 0,
            "Network.requestWillBeSent": 7,
            "Network.requestWillBeSentExtraInfo": 0,
            "Network.responseReceived": 0,
        },
        "cross_site_iframe_request": True,
        "duplicate_request_occurrences": 2,
        "redirect_target_request": True,
        "worker_network_target_types": ["shared_worker", "worker"],
        "dedicated_worker_network_request": True,
        "shared_worker_network_request": True,
        "dedicated_worker_fetch_paused_on_page": True,
        "shared_worker_fetch_paused_on_shared_worker": True,
    }
    assert pinned_cdp.PROBE_SCHEMA_VERSION == 15
    assert pinned_cdp.HISTORICAL_PROBE_SCHEMA_VERSIONS == frozenset(
        {8, 9, 11, 12, 13, 14}
    )
    assert pinned_cdp.PROBE_CONTRACT["schema_version"] == 14
    assert pinned_cdp.PROBE_CONTRACT["policy"] == (
        "pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v14"
    )
    assert pinned_cdp.PROBE_CONTRACT["instrumentation_policy"] == (
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v17"
    )
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V11["schema_version"] == 10
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V11["instrumentation_policy"].endswith("-v12")
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12["schema_version"] == 11
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12["instrumentation_policy"].endswith("-v13")
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12_SHA256 == (
        "0fc670bdaf43dd1bcb7745f9931f99f8910989291fe1dfb5d7856414161042e9"
    )
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13["schema_version"] == 12
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13["instrumentation_policy"].endswith(
        "-v15"
    )
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V13_SHA256 == (
        "6f688dfc91ef63ca096a1d2ed1df9b5d87053cdb46ef604467d6a8f723f395ac"
    )
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V14["schema_version"] == 13
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V14["instrumentation_policy"].endswith(
        "-v16"
    )
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V14_SHA256 == (
        "92dddabdd9b2ab9476d89fe97d5e3b7f084c3d7a409b07452b62fd3da3c57733"
    )
    assert pinned_cdp.PROBE_CONTRACT["worker_webtransport_probe_schema_version"] == 1
    assert pinned_cdp.PROBE_CONTRACT["chromium_version"] == "143.0.7499.4"
    assert pinned_cdp.PROBE_CONTRACT["chromium_executable"] == ("/usr/local/bin/qcsd-chromium")
    assert pinned_cdp.PROBE_CONTRACT["observation_timeout_ms"] == 10_000
    assert pinned_cdp.PROBE_CONTRACT["required_quiet_interval_ms"] == 250
    assert pinned_cdp.PROBE_CONTRACT["target_activity_schema_version"] == 1
    assert pinned_cdp.PROBE_CONTRACT[
        "srcdoc_pseudo_document_summary_schema_version"
    ] == pinned_cdp.SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION
    assert pinned_cdp.SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION == 2
    assert pinned_cdp.PROBE_CONTRACT["srcdoc_pseudo_document_policy"] == (
        pinned_cdp.SRCDOC_PSEUDO_DOCUMENT_POLICY
    )
    assert pinned_cdp.SRCDOC_PSEUDO_DOCUMENT_POLICY == (
        "chromium-143-root-about-srcdoc-loader-bound-orphan-abort-v1"
    )
    assert pinned_cdp.PROBE_CONTRACT["required_srcdoc_pseudo_document_count"] == 1
    assert pinned_cdp.PROBE_CONTRACT["playwright_driver_binding"] == (
        pinned_cdp.EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert pinned_cdp.PROBE_CONTRACT["playwright_driver_binding"] != (
        pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V11[
        "playwright_driver_binding"
    ] == pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT_V12[
        "playwright_driver_binding"
    ] == pinned_cdp.PREVIOUS_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    assert pinned_cdp._HISTORICAL_PROBE_CONTRACT["playwright_driver_binding"] == (
        pinned_cdp.LEGACY_EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
    assert (
        "document-only-playwright-route-with-recursive-cdp-subresource-ownership"
        in pinned_cdp.PROBE_CONTRACT["required_observations"]
    )
    assert (
        "shared-worker-guardian-real-detach-ordered-before-final-proof"
        in pinned_cdp.PROBE_CONTRACT["required_observations"]
    )
    assert (
        "dedicated-and-shared-worker-webtransport-blocked-after-prearm-with-exact-telemetry"
        in pinned_cdp.PROBE_CONTRACT["required_observations"]
    )
    assert (
        "root-about-srcdoc-loader-bound-orphan-abort-lifecycle"
        in pinned_cdp.PROBE_CONTRACT["required_observations"]
    )


def test_target_only_activity_resets_probe_quiescence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _required_topology_events()
    activity = _required_target_activity()

    class Router:
        active_request_identities: tuple[object, ...] = ()
        shutdown_ready = True

        def raise_if_failed(self) -> None:
            return None

    clock = [0.0]

    class Page:
        waits = 0

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 25
            self.waits += 1
            clock[0] += milliseconds / 1_000
            if self.waits == 6:
                activity.record(
                    SimpleNamespace(target_type="worker", generation=0),
                    "target-info-changed",
                )

        def evaluate(self, expression: str) -> dict[str, object | None]:
            if expression == "() => window.qcsdWorkerWebTransportResults":
                return {
                    target_type: copy.deepcopy(pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT)
                    for target_type in pinned_cdp._WORKER_WEBTRANSPORT_TARGET_TYPES
                }
            if self.waits < 10:
                return {"dedicated_worker": None, "shared_worker": None}
            return copy.deepcopy(pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION)

    monkeypatch.setattr(pinned_cdp.time, "monotonic", lambda: clock[0])
    page = Page()
    generation, worker_responses, worker_probe = pinned_cdp._wait_for_required_observations(
        page,
        Router(),
        events,
        activity,
        _successful_egress_guard(),
        _completed_worker_webtransport_collector(),
        deadline=2.0,
    )

    assert generation == 4
    assert worker_responses == pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
    assert worker_probe == pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_PROBE
    assert page.waits >= 20
    assert clock[0] >= 0.5
    assert activity.snapshot()["by_target_type"]["worker"] == {
        "total": 2,
        "max_source_generation": 0,
        "event_counts": {
            "target-attached": 1,
            "target-info-changed": 1,
            "target-detached": 0,
            "target-destroyed": 0,
        },
    }


@pytest.mark.parametrize(
    ("worker_responses", "active_requests", "shutdown_ready"),
    [
        (
            {"dedicated_worker": None, "shared_worker": "qcsd-shared-response-consumed"},
            (),
            True,
        ),
        (
            {"dedicated_worker": "qcsd-dedicated-response-consumed", "shared_worker": None},
            (),
            True,
        ),
        (copy.deepcopy(pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION), (object(),), True),
        (copy.deepcopy(pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION), (), False),
    ],
)
def test_convergence_requires_both_worker_sentinels_and_router_terminal_state(
    monkeypatch: pytest.MonkeyPatch,
    worker_responses: dict[str, str | None],
    active_requests: tuple[object, ...],
    shutdown_ready: bool,
) -> None:
    clock = [0.0]

    class Page:
        evaluations = 0

        def wait_for_timeout(self, milliseconds: int) -> None:
            clock[0] += milliseconds / 1_000

        def evaluate(self, expression: str) -> dict[str, str | None]:
            assert expression == "() => window.qcsdWorkerResponses"
            self.evaluations += 1
            return copy.deepcopy(worker_responses)

    class Router:
        def __init__(self) -> None:
            self.active_request_identities = active_requests
            self.shutdown_ready = shutdown_ready

        def raise_if_failed(self) -> None:
            return None

    monkeypatch.setattr(pinned_cdp.time, "monotonic", lambda: clock[0])
    page = Page()

    with pytest.raises(RuntimeError, match="did not converge"):
        pinned_cdp._wait_for_required_observations(
            page,
            Router(),
            _required_topology_events(),
            _required_target_activity(),
            _successful_egress_guard(),
            _completed_worker_webtransport_collector(),
            deadline=0.4,
        )

    if active_requests or not shutdown_ready:
        assert page.evaluations == 0
    else:
        assert page.evaluations > 0


@pytest.mark.parametrize("router_gate", ["active_request", "shutdown_ready"])
def test_convergence_quiet_interval_starts_only_after_router_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
    router_gate: str,
) -> None:
    clock = [0.0]

    class Page:
        waits = 0
        evaluation_waits: list[int] = []

        def wait_for_timeout(self, milliseconds: int) -> None:
            self.waits += 1
            clock[0] += milliseconds / 1_000

        def evaluate(self, expression: str) -> dict[str, object]:
            self.evaluation_waits.append(self.waits)
            if expression == "() => window.qcsdWorkerWebTransportResults":
                return {
                    target_type: copy.deepcopy(pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT)
                    for target_type in pinned_cdp._WORKER_WEBTRANSPORT_TARGET_TYPES
                }
            assert expression == "() => window.qcsdWorkerResponses"
            return copy.deepcopy(pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION)

    page = Page()

    class Router:
        @property
        def active_request_identities(self) -> tuple[object, ...]:
            if router_gate == "active_request" and page.waits < 5:
                return (object(),)
            return ()

        @property
        def shutdown_ready(self) -> bool:
            return router_gate != "shutdown_ready" or page.waits >= 5

        def raise_if_failed(self) -> None:
            return None

    monkeypatch.setattr(pinned_cdp.time, "monotonic", lambda: clock[0])
    generation, worker_responses, worker_probe = pinned_cdp._wait_for_required_observations(
        page,
        Router(),
        _required_topology_events(),
        _required_target_activity(),
        _successful_egress_guard(),
        _completed_worker_webtransport_collector(),
        deadline=1.0,
    )

    assert generation == 3
    assert worker_responses == pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
    assert worker_probe == pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_PROBE
    assert page.evaluation_waits[0] == 5
    assert page.waits >= 15


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"dedicated_worker": None, "shared_worker": None, "extra": None},
    ],
)
def test_worker_response_consumption_fails_closed_on_malformed_state(value: object) -> None:
    page = SimpleNamespace(evaluate=lambda _expression: value)

    with pytest.raises(RuntimeError, match="worker-response state is malformed"):
        pinned_cdp._worker_response_consumption(page)


@pytest.mark.parametrize(
    ("worker_type", "sentinel"),
    [
        ("dedicated_worker", "qcsd-dedicated-response-invalid"),
        ("dedicated_worker", "qcsd-dedicated-response-error"),
        ("shared_worker", "qcsd-shared-response-invalid"),
        ("shared_worker", "qcsd-shared-response-error"),
        ("shared_worker", 1),
    ],
)
def test_worker_response_consumption_fails_closed_on_noncompletion_sentinel(
    worker_type: str,
    sentinel: object,
) -> None:
    value: dict[str, object] = {
        "dedicated_worker": None,
        "shared_worker": None,
    }
    value[worker_type] = sentinel
    page = SimpleNamespace(evaluate=lambda _expression: value)

    with pytest.raises(RuntimeError, match="failed to consume its exact response"):
        pinned_cdp._worker_response_consumption(page)


def test_worker_webtransport_collector_consumes_only_two_exact_armed_notifications() -> None:
    collector = pinned_cdp._WorkerWebTransportGuardCollector()
    worker = SimpleNamespace(target_type="worker")
    shared = SimpleNamespace(target_type="shared_worker")
    exact = {
        "api": "WebTransport",
        "mechanism": "paused-target-runtime-shim",
        "url": None,
    }

    assert collector.consume(source=worker, **exact) is False
    collector.arm()
    assert collector.consume(source=SimpleNamespace(target_type="page"), **exact) is False
    assert collector.consume(source=worker, **{**exact, "api": "WebSocket"}) is False
    assert (
        collector.consume(
            source=worker,
            **{**exact, "mechanism": "context-init-script-shim"},
        )
        is False
    )
    assert collector.consume(source=worker, **exact) is True
    assert collector.consume(source=worker, **exact) is False
    assert collector.consume(source=shared, **{**exact, "url": "https://redacted.test"}) is False
    assert collector.consume(source=shared, **exact) is True

    measurements = {
        target_type: copy.deepcopy(pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT)
        for target_type in pinned_cdp._WORKER_WEBTRANSPORT_TARGET_TYPES
    }
    assert collector.receipt_if_complete(measurements) == (
        pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_PROBE
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["worker"].update(action_succeeded=True),
        lambda value: value["shared_worker"].update(exception_name="SyntaxError"),
        lambda value: value["worker"].update(resolved_type="undefined"),
    ),
)
def test_worker_webtransport_measurements_fail_closed_on_nonblocking_result(mutation) -> None:
    value = {
        target_type: copy.deepcopy(pinned_cdp._EXPECTED_WORKER_WEBTRANSPORT_MEASUREMENT)
        for target_type in pinned_cdp._WORKER_WEBTRANSPORT_TARGET_TYPES
    }
    mutation(value)
    page = SimpleNamespace(evaluate=lambda _expression: value)

    with pytest.raises(RuntimeError, match="action was not blocked exactly"):
        pinned_cdp._worker_webtransport_measurements(page)


def test_http_status_aggregate_records_redirect_and_terminal_responses() -> None:
    counts = {}
    pinned_cdp._record_http_status(
        counts,
        {"url": "http://a.test:123/redirect", "status": 302.0},
    )
    pinned_cdp._record_http_status(
        counts,
        {"url": "http://a.test:123/redirected", "status": 200},
    )
    pinned_cdp._record_http_status(
        counts,
        {"url": "data:,", "status": 200},
    )
    assert {path: dict(value) for path, value in counts.items()} == {
        "/redirect": {"302": 1},
        "/redirected": {"200": 1},
    }

    with pytest.raises(ValueError, match="status is malformed"):
        pinned_cdp._record_http_status(
            counts,
            {"url": "http://a.test:123/", "status": True},
        )


def test_page_load_wait_surfaces_router_failure_before_waiting() -> None:
    class FailedRouter:
        def raise_if_failed(self) -> None:
            raise RuntimeError("instrumentation failed")

    class Page:
        def wait_for_timeout(self, _milliseconds: int) -> None:
            pytest.fail("page wait ran after the router had already failed")

    with pytest.raises(RuntimeError, match="instrumentation failed"):
        pinned_cdp._wait_for_page_load(
            Page(),
            FailedRouter(),
            [False],
            _successful_egress_guard(),
            deadline=time.monotonic() + 1,
        )


def test_page_load_wait_pumps_until_real_load_event() -> None:
    load_seen = [False]

    class Router:
        checks = 0

        def raise_if_failed(self) -> None:
            self.checks += 1

    class Page:
        waits = 0

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 25
            self.waits += 1
            load_seen[0] = True

    router = Router()
    page = Page()
    pinned_cdp._wait_for_page_load(
        page,
        router,
        load_seen,
        _successful_egress_guard(),
        deadline=time.monotonic() + 1,
    )
    assert router.checks == 2
    assert page.waits == 1


def test_probe_delegates_executable_selection_to_pinned_path_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pinned_cdp, "_observe_isolation", lambda **_kwargs: {})
    monkeypatch.setattr(
        pinned_cdp,
        "validate_default_playwright_driver_once",
        dict,
    )
    monkeypatch.setattr(
        pinned_cdp.importlib.metadata,
        "version",
        lambda _package: pinned_cdp.EXPECTED_PLAYWRIGHT_VERSION,
    )

    def reject_override() -> str:
        raise ValueError("non-default executable override")

    monkeypatch.setattr(
        pinned_cdp,
        "pinned_chromium_executable_path",
        reject_override,
    )

    with pytest.raises(ValueError, match="non-default executable override"):
        pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)


def test_probe_creates_browser_session_for_shared_worker_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GuardReached(RuntimeError):
        pass

    browser_session = object()
    page_session = object()
    guard_sessions: list[tuple[object, object]] = []
    router_options: list[dict[str, object]] = []
    start_order: list[str] = []
    cleanup_order: list[str] = []

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            return None

        def set_default_navigation_timeout(self, _timeout: int) -> None:
            return None

    page = Page()

    class Context:
        def __init__(self) -> None:
            self.service_workers: list[object] = []
            self.closed = False

        def new_page(self) -> Page:
            return page

        def new_cdp_session(self, requested_page: Page) -> object:
            assert requested_page is page
            return page_session

        def close(self) -> None:
            self.closed = True
            cleanup_order.append("context-close")

    context = Context()

    class Browser:
        version = "test-chromium"

        def __init__(self) -> None:
            self.browser_session_calls = 0
            self.closed = False

        def new_context(self, **options: object) -> Context:
            assert options == {"service_workers": "block"}
            return context

        def new_browser_cdp_session(self) -> object:
            self.browser_session_calls += 1
            return browser_session

        def close(self) -> None:
            self.closed = True

    browser = Browser()

    class DriverSession:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    class EgressGuard:
        def bind_root_page(self, requested_page: Page) -> None:
            assert requested_page is page

        def raise_if_failed(self) -> None:
            return None

        def record(self, **_kwargs: object) -> None:
            return None

    class Router:
        def __init__(self, requested_session: object, **kwargs: object) -> None:
            assert requested_session is page_session
            router_options.append(dict(kwargs))

        def start(self) -> None:
            start_order.append("router")

        def raise_if_failed(self) -> None:
            return None

        def begin_abort(self) -> None:
            cleanup_order.append("router-begin-abort")

        def finish_abort(self) -> None:
            cleanup_order.append("router-finish-abort")

    class BrowserGuard:
        def __init__(self, requested_session: object, router: object) -> None:
            guard_sessions.append((requested_session, router))

        def start(self) -> None:
            start_order.append("browser-guard")
            raise GuardReached("browser guard received its browser-level session")

        def begin_abort(self) -> None:
            cleanup_order.append("guard-begin-abort")

        def finish_abort(self) -> None:
            cleanup_order.append("guard-finish-abort")

    executable = tmp_path / "qcsd-chromium"
    executable.write_bytes(b"fixture")
    executable.chmod(0o755)
    monkeypatch.setattr(pinned_cdp, "_observe_isolation", lambda **_kwargs: {})
    monkeypatch.setattr(
        pinned_cdp,
        "validate_default_playwright_driver_once",
        lambda: {"validated": True},
    )
    monkeypatch.setattr(
        pinned_cdp.importlib.metadata,
        "version",
        lambda _package: pinned_cdp.EXPECTED_PLAYWRIGHT_VERSION,
    )
    monkeypatch.setattr(pinned_cdp, "EXPECTED_CHROMIUM_EXECUTABLE", str(executable))
    monkeypatch.setattr(
        pinned_cdp,
        "pinned_chromium_executable_path",
        lambda: str(executable),
    )
    monkeypatch.setattr(
        pinned_cdp,
        "playwright_driver_session",
        lambda _factory, *, exclusive: DriverSession(),
    )
    monkeypatch.setattr(
        pinned_cdp,
        "launch_pinned_cdp_probe_browser",
        lambda _playwright, **_kwargs: (browser, {}),
    )
    monkeypatch.setattr(pinned_cdp, "NonReplayableEgressGuard", EgressGuard)
    monkeypatch.setattr(
        pinned_cdp,
        "install_context_egress_guards",
        lambda _context, _guard: None,
    )
    monkeypatch.setattr(pinned_cdp, "RecursiveCdpTargetRouter", Router)
    monkeypatch.setattr(pinned_cdp, "BrowserSharedWorkerGuard", BrowserGuard)

    with pytest.raises(
        GuardReached,
        match="browser guard received its browser-level session",
    ):
        pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)

    assert browser.browser_session_calls == 1
    assert len(guard_sessions) == 1
    assert guard_sessions[0][0] is browser_session
    assert isinstance(guard_sessions[0][1], Router)
    assert router_options[0]["track_root_srcdoc_lifecycle"] is True
    assert start_order == ["router", "browser-guard"]
    assert cleanup_order == [
        "router-begin-abort",
        "guard-begin-abort",
        "context-close",
        "guard-finish-abort",
        "router-finish-abort",
    ]
    assert context.closed is True
    assert browser.closed is True


@pytest.mark.parametrize(
    "failure_kind",
    [
        "exception-abort-cleanup",
        "keyboard-interrupt-browser-close",
        "normal-shutdown-summary",
        "egress-priority",
        "router-priority",
        "server-cleanup",
    ],
)
def test_probe_preserves_primary_across_lifecycle_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    lifecycle: list[str] = []

    class ProbeFailure(RuntimeError):
        pass

    class ShutdownFailure(RuntimeError):
        pass

    keyboard_primary = KeyboardInterrupt("synthetic probe interrupt")
    egress_primary = NonReplayableEgressPolicyError("synthetic retained egress failure")
    router_primary = RuntimeError("synthetic retained router failure")
    router_post_close_checks = [0]

    class Page:
        def __init__(self) -> None:
            self.handlers: dict[str, object] = {}

        def set_default_timeout(self, _timeout: int) -> None:
            return None

        def set_default_navigation_timeout(self, _timeout: int) -> None:
            return None

        def on(self, event: str, handler: object) -> None:
            self.handlers[event] = handler

        def goto(self, *_args: object, **_kwargs: object) -> None:
            return None

    page = Page()

    class Context:
        def __init__(self) -> None:
            self.closed = False
            self.service_workers: list[object] = []

        def new_page(self) -> Page:
            return page

        def new_cdp_session(self, requested_page: Page) -> object:
            assert requested_page is page
            return object()

        def close(self) -> None:
            self.closed = True
            lifecycle.append("context-close")

    context = Context()

    class Browser:
        version = "test-chromium"

        def __init__(self) -> None:
            self.closed = False

        def new_context(self, **options: object) -> Context:
            assert options == {"service_workers": "block"}
            return context

        def new_browser_cdp_session(self) -> object:
            return object()

        def close(self) -> None:
            self.closed = True
            lifecycle.append("browser-close")
            if failure_kind == "keyboard-interrupt-browser-close":
                raise LookupError("synthetic browser close failure")

    browser = Browser()

    class DriverSession:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    class EgressGuard:
        def __init__(self) -> None:
            return None

        def bind_root_page(self, requested_page: Page) -> None:
            assert requested_page is page

        def raise_if_failed(self) -> None:
            if failure_kind == "egress-priority" and browser.closed:
                raise egress_primary
            return None

        def success_summary(self) -> dict[str, object]:
            return _non_replayable_egress_summary()

        def record(self, **_kwargs: object) -> None:
            return None

    class Router:
        def __init__(self, _session: object, **_kwargs: object) -> None:
            return None

        def start(self) -> None:
            lifecycle.append("router-start")

        def begin_abort(self) -> None:
            lifecycle.append("router-begin-abort")

        def finish_abort(self) -> None:
            lifecycle.append("router-finish-abort")
            if failure_kind == "exception-abort-cleanup":
                raise LookupError("synthetic router cleanup failure")

        def raise_if_failed(self) -> None:
            if failure_kind in {"egress-priority", "router-priority"} and browser.closed:
                router_post_close_checks[0] += 1
                raise router_primary
            return None

        def begin_shutdown(self) -> None:
            lifecycle.append("router-begin-shutdown")

        @property
        def bootstrap_prearm_summary(self) -> dict[str, object]:
            if failure_kind == "normal-shutdown-summary":
                raise ShutdownFailure("synthetic post-transition summary failure")
            return {}

        @property
        def egress_prearm_summary(self) -> dict[str, object]:
            return _egress_prearm_summary()

        def finish(self) -> None:
            lifecycle.append("router-finish")

    class BrowserGuard:
        def __init__(self, _session: object, _router: Router) -> None:
            return None

        def start(self) -> None:
            lifecycle.append("guard-start")

        def begin_abort(self) -> None:
            lifecycle.append("guard-begin-abort")

        def finish_abort(self) -> None:
            lifecycle.append("guard-finish-abort")

        def begin_shutdown(self) -> None:
            lifecycle.append("guard-begin-shutdown")

        def finish(self) -> None:
            lifecycle.append("guard-finish")

    class WorkerCollector:
        def arm(self) -> None:
            lifecycle.append("collector-arm")
            if failure_kind == "normal-shutdown-summary":
                return
            if failure_kind == "keyboard-interrupt-browser-close":
                raise keyboard_primary
            raise ProbeFailure("synthetic probe timeout")

    if failure_kind == "server-cleanup":

        class ProbeServer:
            server_port = 8080

            def __init__(self, _address: object) -> None:
                return None

            def serve_forever(self) -> None:
                return None

            def shutdown(self) -> None:
                lifecycle.append("server-shutdown")

            def server_close(self) -> None:
                lifecycle.append("server-close")
                raise OSError("synthetic server close failure")

        class ProbeThread:
            def __init__(self, *, target: object, daemon: bool) -> None:
                assert target
                assert daemon is True
                self.alive = False

            def start(self) -> None:
                self.alive = True

            def is_alive(self) -> bool:
                return self.alive

            def join(self, *, timeout: int) -> None:
                assert timeout == 2
                lifecycle.append("server-thread-join")
                self.alive = False

        monkeypatch.setattr(pinned_cdp, "_ProbeServer", ProbeServer)
        monkeypatch.setattr(pinned_cdp.threading, "Thread", ProbeThread)

    executable = tmp_path / "qcsd-chromium"
    executable.write_bytes(b"fixture")
    executable.chmod(0o755)
    monkeypatch.setattr(pinned_cdp, "_observe_isolation", lambda **_kwargs: {})
    monkeypatch.setattr(
        pinned_cdp,
        "validate_default_playwright_driver_once",
        lambda: {"validated": True},
    )
    monkeypatch.setattr(
        pinned_cdp.importlib.metadata,
        "version",
        lambda _package: pinned_cdp.EXPECTED_PLAYWRIGHT_VERSION,
    )
    monkeypatch.setattr(pinned_cdp, "EXPECTED_CHROMIUM_EXECUTABLE", str(executable))
    monkeypatch.setattr(
        pinned_cdp,
        "pinned_chromium_executable_path",
        lambda: str(executable),
    )
    monkeypatch.setattr(
        pinned_cdp,
        "playwright_driver_session",
        lambda _factory, *, exclusive: DriverSession(),
    )
    monkeypatch.setattr(
        pinned_cdp,
        "launch_pinned_cdp_probe_browser",
        lambda _playwright, **_kwargs: (browser, {}),
    )
    monkeypatch.setattr(pinned_cdp, "NonReplayableEgressGuard", EgressGuard)
    monkeypatch.setattr(
        pinned_cdp,
        "install_context_egress_guards",
        lambda _context, _guard: None,
    )
    monkeypatch.setattr(pinned_cdp, "RecursiveCdpTargetRouter", Router)
    monkeypatch.setattr(pinned_cdp, "BrowserSharedWorkerGuard", BrowserGuard)
    monkeypatch.setattr(pinned_cdp, "_WorkerWebTransportGuardCollector", WorkerCollector)
    monkeypatch.setattr(pinned_cdp, "_wait_for_page_load", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        pinned_cdp,
        "_wait_for_required_observations",
        lambda *_args, **_kwargs: (0, {}, {}),
    )

    if failure_kind in {"exception-abort-cleanup", "server-cleanup"}:
        with pytest.raises(ProbeFailure, match="synthetic probe timeout") as caught:
            pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)
        expected_notes = (
            ["pinned-CDP probe cleanup router-finish-abort failed with LookupError"]
            if failure_kind == "exception-abort-cleanup"
            else ["pinned-CDP probe cleanup server-close failed with OSError"]
        )
        assert getattr(caught.value, "__notes__", []) == expected_notes
    elif failure_kind == "keyboard-interrupt-browser-close":
        with pytest.raises(KeyboardInterrupt) as caught:
            pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)
        assert caught.value is keyboard_primary
        assert getattr(caught.value, "__notes__", []) == [
            "pinned-CDP probe cleanup browser-close failed with LookupError"
        ]
    elif failure_kind == "normal-shutdown-summary":
        with pytest.raises(ShutdownFailure, match="synthetic post-transition summary failure"):
            pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)
    elif failure_kind == "egress-priority":
        with pytest.raises(NonReplayableEgressPolicyError) as caught:
            pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)
        assert caught.value is egress_primary
        assert router_post_close_checks == [0]
    else:
        assert failure_kind == "router-priority"
        with pytest.raises(RuntimeError, match="synthetic retained router failure") as caught:
            pinned_cdp.run_pinned_cdp_probe(expected_uid=1000, expected_gid=1000)
        assert caught.value is router_primary
        assert router_post_close_checks == [1]

    assert context.closed is True
    assert browser.closed is True
    if failure_kind == "normal-shutdown-summary":
        assert lifecycle == [
            "router-start",
            "guard-start",
            "collector-arm",
            "router-begin-shutdown",
            "guard-begin-shutdown",
            "context-close",
            "guard-finish",
            "router-finish",
            "browser-close",
        ]
    else:
        expected_lifecycle = [
            "router-start",
            "guard-start",
            "collector-arm",
            "router-begin-abort",
            "guard-begin-abort",
            "context-close",
            "guard-finish-abort",
            "router-finish-abort",
            "browser-close",
        ]
        if failure_kind == "server-cleanup":
            expected_lifecycle.extend(
                ["server-shutdown", "server-close", "server-thread-join"]
            )
        assert lifecycle == expected_lifecycle


def test_main_fails_closed_without_wrapper_identity_environment(
    tmp_path: Path,
    fake_build: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("QCSD_PINNED_CDP_EXPECTED_UID", raising=False)
    monkeypatch.delenv("QCSD_PINNED_CDP_EXPECTED_GID", raising=False)
    destination = tmp_path / "pinned-cdp-execution-v59.json"

    status = pinned_cdp.main(
        [
            "--cohort-version",
            "59",
            "--build-execution-receipt",
            str(fake_build),
            "--destination",
            str(destination),
        ]
    )

    assert status == 1
    assert not destination.exists()
    assert "pinned CDP probe failed" in capsys.readouterr().err


def test_launcher_rejects_malformed_requests_before_docker() -> None:
    launcher = Path(__file__).parents[1] / "qcsd-lab"
    valid_destination = "artifacts/buflo-study/pinned-cdp-execution-v59.json"
    valid_build = "artifacts/buflo-study/build-execution-v59.json"
    requests = (
        ([], "requires --cohort-version"),
        (["--unknown"], "rejects unknown argument"),
        (
            [
                "--cohort-version",
                "59",
                "--cohort-version",
                "60",
                "--build-execution-receipt",
                valid_build,
                "--destination",
                valid_destination,
            ],
            "exactly one --cohort-version",
        ),
        (
            [
                "--cohort-version",
                "0",
                "--build-execution-receipt",
                valid_build,
                "--destination",
                valid_destination,
            ],
            "positive integer",
        ),
        (
            [
                "--cohort-version",
                "59",
                "--build-execution-receipt",
                "artifacts/buflo-study/build-execution-v58.json",
                "--destination",
                valid_destination,
            ],
            "build receipt must be",
        ),
        (
            [
                "--cohort-version",
                "59",
                "--build-execution-receipt",
                valid_build,
                "--destination",
                "artifacts/pinned-cdp-execution-v59.json",
            ],
            "destination must be",
        ),
    )
    for arguments, message in requests:
        result = subprocess.run(
            [launcher, "test", "pinned-cdp", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=5,
        )
        assert result.returncode == 2
        assert result.stdout == ""
        assert message in result.stderr


def test_launcher_pinned_probe_is_receipt_bound_and_least_privilege() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert (
        "artifacts/buflo-study/pinned-cdp-execution-v${pinned_cdp_cohort_version}.json"
    ) in launcher
    assert 'network_mode="none"' in launcher
    assert 'runtime+=(--user "$(id -u):$(id -g)" --cap-drop ALL)' in launcher
    assert "--entrypoint /usr/bin/tini" in launcher
    assert "/usr/bin/timeout --signal=TERM --kill-after=10s 120s" in launcher
    assert "/opt/qcsd-venv/bin/python3 -m qcsd_lab.pinned_cdp" in launcher
    assert 'verify_qualification_checkout "test pinned-cdp"' in launcher
    assert '--expected-cohort "${pinned_cdp_cohort_version}"' in launcher
    assert (
        "--build-execution-receipt|--pinned-cdp-receipt|"
        "--browser-egress-qualification-root|--reference-receipt"
    ) in launcher
    assert (
        '"${pinned_cdp_destination_parent}:${pinned_cdp_destination_parent_container}:rw"'
    ) in launcher
    assert '"${pinned_cdp_existing_child}:${pinned_cdp_existing_container}:ro"' in launcher
    assert "pinned_cdp_build_overlay" in launcher
