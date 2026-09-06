from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from qcsd_lab import pinned_cdp
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

COLLECTION_IMAGE = "sha256:" + "1" * 64
PREPARE_IMAGE = "sha256:" + "2" * 64
BUILD_SHA256 = "3" * 64
BUILD_PAYLOAD_SHA256 = "4" * 64
LAB_COMMIT = "5" * 40
NEQO_COMMIT = "6" * 40
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


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
        "playwright_version": "1.52.0",
        "chromium_version": "Chromium 136.0.7103.25",
        "chromium_executable": "/usr/bin/chromium",
        "isolation": {
            "real_uid": uid,
            "effective_uid": uid,
            "real_gid": gid,
            "effective_gid": gid,
            "expected_uid": uid,
            "expected_gid": gid,
            "effective_capabilities": "0000000000000000",
            "no_new_privileges": True,
            "observed_interfaces": ["lo"],
        },
        "topology": {
            "observed_target_types": ["iframe", "page", "shared_worker", "worker"],
            "event_count": 42,
            "cross_site_iframe_request": True,
            "duplicate_request_occurrences": 2,
            "redirect_terminal_request": True,
            "worker_network_target_types": ["shared_worker", "worker"],
            "worker_fetch_paused_on_page": True,
            "router_closed": True,
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

    def validate(path_arg, *, expected_cohort_version=None, **_kwargs):
        assert Path(path_arg).resolve() == path.resolve()
        assert expected_cohort_version in {None, 59}
        return copy.deepcopy(build)

    monkeypatch.setattr(pinned_cdp, "validate_build_execution_receipt", validate)
    monkeypatch.setattr(pinned_cdp, "source_metadata", lambda: _source(PREPARE_IMAGE))
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
    assert validated["build_execution"] == {
        "path": "/lab/artifacts/buflo-study/build-execution-v59.json",
        "sha256": BUILD_SHA256,
        "payload_sha256": BUILD_PAYLOAD_SHA256,
    }
    assert output.read_bytes() == canonical_json_bytes(json.loads(output.read_text()))

    with pytest.raises(FileExistsError, match="create-only"):
        _create(tmp_path, fake_build)


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
                worker_fetch_paused_on_page=False
            ),
            "topology evidence",
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
            lambda observation: observation["isolation"].update(
                no_new_privileges=False
            ),
            "isolation evidence",
        ),
        (
            lambda observation: observation["isolation"].update(effective_uid=0),
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


def test_required_topology_wait_condition_is_event_driven() -> None:
    events = [
        ("page", "Network.requestWillBeSent", "http://a.test/"),
        ("iframe", "Network.requestWillBeSent", "http://b.test/frame-data"),
        ("page", "Network.requestWillBeSent", "http://a.test/duplicate"),
        ("page", "Network.requestWillBeSent", "http://a.test/duplicate"),
        ("page", "Network.requestWillBeSent", "http://a.test/redirected"),
        ("worker", "Network.requestWillBeSent", "http://a.test/worker-data"),
        ("shared_worker", "Network.requestWillBeSent", "http://a.test/worker-data"),
        ("page", "Fetch.requestPaused", "http://a.test/worker-data"),
    ]

    assert pinned_cdp._required_event_topology_observed(events) is True
    assert pinned_cdp._required_event_topology_observed(events[:-1]) is False
    assert pinned_cdp.PROBE_CONTRACT["observation_timeout_ms"] == 10_000
    assert pinned_cdp.PROBE_CONTRACT["required_quiet_interval_ms"] == 250


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
        "artifacts/buflo-study/"
        "pinned-cdp-execution-v${pinned_cdp_cohort_version}.json"
    ) in launcher
    assert 'network_mode="none"' in launcher
    assert 'runtime+=(--user "$(id -u):$(id -g)" --cap-drop ALL)' in launcher
    assert '--entrypoint /usr/bin/tini' in launcher
    assert '/usr/bin/timeout --signal=TERM --kill-after=10s 120s' in launcher
    assert "/opt/qcsd-venv/bin/python3 -m qcsd_lab.pinned_cdp" in launcher
    assert 'verify_qualification_checkout "test pinned-cdp"' in launcher
    assert '--expected-cohort "${pinned_cdp_cohort_version}"' in launcher
    assert "--build-execution-receipt|--pinned-cdp-receipt|--reference-receipt" in launcher
    assert (
        '"${pinned_cdp_destination_parent}:'
        '${pinned_cdp_destination_parent_container}:rw"'
    ) in launcher
    assert '"${pinned_cdp_existing_child}:${pinned_cdp_existing_container}:ro"' in launcher
    assert "pinned_cdp_build_overlay" in launcher
