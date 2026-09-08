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
            "non_replayable_egress_summary": _non_replayable_egress_summary(),
            "browser_egress_command_line": _browser_egress_command_line_projection(),
            "browser_context_service_worker_count": 0,
            "worker_response_consumption": copy.deepcopy(
                pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
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
    payload["build_execution_identity"].pop("completion_path")
    payload["build_execution_identity"].pop("completion_sha256")
    payload["observation"]["topology"].pop("worker_response_consumption")
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
    payload["observation"]["topology"].pop("worker_response_consumption")
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
    assert pinned_cdp.PROBE_SCHEMA_VERSION == 11
    assert pinned_cdp.HISTORICAL_PROBE_SCHEMA_VERSIONS == frozenset({8, 9})
    assert pinned_cdp.PROBE_CONTRACT["schema_version"] == 10
    assert pinned_cdp.PROBE_CONTRACT["policy"] == (
        "pinned-playwright-chromium-exclusive-target-topology-egress-and-argv-v10"
    )
    assert pinned_cdp.PROBE_CONTRACT["instrumentation_policy"] == (
        "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v12"
    )
    assert pinned_cdp.PROBE_CONTRACT["chromium_version"] == "143.0.7499.4"
    assert pinned_cdp.PROBE_CONTRACT["chromium_executable"] == ("/usr/local/bin/qcsd-chromium")
    assert pinned_cdp.PROBE_CONTRACT["observation_timeout_ms"] == 10_000
    assert pinned_cdp.PROBE_CONTRACT["required_quiet_interval_ms"] == 250
    assert pinned_cdp.PROBE_CONTRACT["target_activity_schema_version"] == 1
    assert pinned_cdp.PROBE_CONTRACT["playwright_driver_binding"] == (
        pinned_cdp.EXPECTED_PLAYWRIGHT_DRIVER_BINDING
    )
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

        def evaluate(self, _expression: str) -> dict[str, str | None]:
            if self.waits < 10:
                return {"dedicated_worker": None, "shared_worker": None}
            return copy.deepcopy(pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION)

    monkeypatch.setattr(pinned_cdp.time, "monotonic", lambda: clock[0])
    page = Page()
    generation, worker_responses = pinned_cdp._wait_for_required_observations(
        page,
        Router(),
        events,
        activity,
        _successful_egress_guard(),
        deadline=2.0,
    )

    assert generation == 4
    assert worker_responses == pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
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

        def evaluate(self, expression: str) -> dict[str, str]:
            assert expression == "() => window.qcsdWorkerResponses"
            self.evaluation_waits.append(self.waits)
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
    generation, worker_responses = pinned_cdp._wait_for_required_observations(
        page,
        Router(),
        _required_topology_events(),
        _required_target_activity(),
        _successful_egress_guard(),
        deadline=1.0,
    )

    assert generation == 3
    assert worker_responses == pinned_cdp._EXPECTED_WORKER_RESPONSE_CONSUMPTION
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
    start_order: list[str] = []

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            return None

        def set_default_navigation_timeout(self, _timeout: int) -> None:
            return None

    page = Page()

    class Context:
        service_workers: list[object] = []

        def new_page(self) -> Page:
            return page

        def new_cdp_session(self, requested_page: Page) -> object:
            assert requested_page is page
            return page_session

    class Browser:
        version = "test-chromium"

        def __init__(self) -> None:
            self.browser_session_calls = 0
            self.closed = False

        def new_context(self, **options: object) -> Context:
            assert options == {"service_workers": "block"}
            return Context()

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
        def __init__(self, requested_session: object, **_kwargs: object) -> None:
            assert requested_session is page_session

        def start(self) -> None:
            start_order.append("router")

        def raise_if_failed(self) -> None:
            return None

    class BrowserGuard:
        def __init__(self, requested_session: object, router: object) -> None:
            guard_sessions.append((requested_session, router))

        def start(self) -> None:
            start_order.append("browser-guard")
            raise GuardReached("browser guard received its browser-level session")

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
    assert start_order == ["router", "browser-guard"]
    assert browser.closed is True


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
