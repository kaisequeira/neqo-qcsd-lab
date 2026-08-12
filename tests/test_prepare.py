from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import qcsd_lab.prepare as prepare
from qcsd_lab.discover import DiscoveryResult
from qcsd_lab.manifest import runtime_manifest, validate_manifest


def discovered() -> DiscoveryResult:
    return DiscoveryResult(
        source_url="https://page.test/",
        final_url="https://page.test/",
        chromium_version="test-chromium",
        settle_ms=3_000,
        observed_request_count=3,
        observed_origins=["https://cdn.test", "https://page.test"],
        approved_origins=["https://cdn.test", "https://page.test"],
        exclusions=[{"url": "https://tracker.test/a.js", "reason": "origin not approved"}],
        resources=[
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
        ],
    )


def install_fake_preparation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    changing_resource: int | None = None,
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
                resource["known_valid"] = True
                resource["content_length"] = 100 + resource["id"]
                resource["data_length"] = 100 + resource["id"]
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
                        "bytes": 100 + resource["id"],
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
                        "responses": responses,
                    }
                ),
                encoding="utf-8",
            )
        else:  # pragma: no cover - protects the mock contract
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, "")

    monkeypatch.setattr(prepare, "run", fake_run)
    return commands


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
    assert [response["resource_id"] for response in value["preparation"]["expected_responses"]] == [
        0,
        1,
    ]
    assert not list(tmp_path.glob(".*-prepare-*"))


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


def test_probe_filter_retains_descendant_and_records_exclusion():
    discovery = discovered()
    resolved = {"resources": deepcopy(discovery.resources)}
    resolved["resources"][0].update(
        {"known_valid": False, "content_length": None, "data_length": 0}
    )
    resolved["resources"][1].update(
        {"known_valid": True, "content_length": 101, "data_length": 101}
    )

    resources, exclusions = prepare.resolve_probe_output(discovery, resolved)

    assert [resource["id"] for resource in resources] == [1]
    assert resources[0]["depends_on"] == []
    assert {
        "url": "https://page.test/",
        "reason": "HTTP/3 preflight unavailable",
    } in exclusions


@pytest.mark.parametrize("workload_id", ["Upper", "two--hyphens", "../escape", "trailing-"])
def test_prepare_rejects_noncanonical_workload_ids(workload_id, tmp_path):
    with pytest.raises(ValueError, match="workload ID"):
        prepare.prepare_workload(
            workload_id,
            "https://page.test/",
            ["https://page.test"],
            output_root=tmp_path,
        )
