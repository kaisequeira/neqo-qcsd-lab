from __future__ import annotations

import hashlib
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
    packet_rows: list[tuple[str, str, str]] | None = None,
    resolved_ceiling: object = 1_200,
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
        (("incoming", "0", "0"), "invalid observed_udp_length"),
        (("incoming", "0", ""), "invalid observed_udp_length"),
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
