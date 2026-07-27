import json
from pathlib import Path

import pytest

from qcsd_lab.campaign import (
    _compare_visit,
    _runner_result_complete,
    create_splits,
    load_campaign,
    plan_campaign,
    resolve_workload,
    stable_digest,
)
from qcsd_lab.capture import split_endpoint, tuple_filter
from qcsd_lab.util import atomic_json


def test_endpoint_parser_and_exact_filter_support_both_ip_versions():
    assert split_endpoint("172.17.0.2:50000") == ("172.17.0.2", 50000)
    assert split_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)
    display_filter = tuple_filter(
        [
            {
                "id": 0,
                "local_address": "172.17.0.2:50000",
                "remote_address": "203.0.113.1:443",
            },
            {
                "id": 1,
                "local_address": "[2001:db8::2]:50001",
                "remote_address": "[2001:db8::1]:443",
            },
        ]
    )
    assert "udp.srcport==50000" in display_filter
    assert "ip.src==172.17.0.2" in display_filter
    assert "ipv6.src==2001:db8::2" in display_filter


def test_runner_requires_complete_successful_application_resources():
    response = {"resource_id": 0, "complete": True, "outcome": "succeeded"}
    assert _runner_result_complete(
        {"completion_status": "complete", "responses": [response]}
    )
    assert not _runner_result_complete(
        {"completion_status": "partial", "responses": [response]}
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [{**response, "complete": False, "outcome": "failed"}],
        }
    )


def test_one_campaign_resolves_both_capture_modes():
    path = Path(__file__).parents[1] / "config/campaigns/single-resource-pilot.yml"
    wireguard = load_campaign(path, capture="wireguard")
    direct = load_campaign(path, capture="direct")
    assert wireguard.purpose == "classification"
    assert [view.id for view in wireguard.views] == ["wireguard-outer", "direct-quic"]
    outer, inner = wireguard.views
    assert (outer.interface, outer.link_type, outer.length_basis, outer.primary) == (
        "eth0",
        "Ethernet",
        "udp.length",
        True,
    )
    assert (inner.interface, inner.link_type, inner.length_basis, inner.primary) == (
        "wg0",
        "Raw IP",
        "frame.len",
        False,
    )
    assert direct.purpose == "diagnostics"
    assert [(view.id, view.interface) for view in direct.views] == [("direct-quic", "eth0")]
    assert sum(workload["visits"] for workload in direct.workloads) == 24
    assert [defense.name for defense in direct.defenses] == ["undefended", "front", "tamaraw"]


def test_outer_only_and_invalid_capture_combinations():
    path = Path(__file__).parents[1] / "config/campaigns/single-resource-pilot.yml"
    outer = load_campaign(path, capture="wireguard", outer_only=True)
    assert [view.id for view in outer.views] == ["wireguard-outer"]
    with pytest.raises(ValueError, match="outer-only"):
        load_campaign(path, capture="direct", outer_only=True)


def test_old_layered_configuration_is_rejected(tmp_path):
    path = _controlled_configuration(tmp_path)
    path.write_text(path.read_text() + "purpose: diagnostics\n", encoding="utf-8")
    with pytest.raises(ValueError, match="purpose"):
        load_campaign(path, capture="direct")


def test_static_is_opt_in_and_requires_a_real_schedule(tmp_path):
    path = _controlled_configuration(
        tmp_path,
        defenses=(
            "  - name: static\n"
            "    kind: static\n"
            "    baseline: true\n"
            "    schedule: schedule.csv\n"
            "    mode: chaff-only\n"
        ),
    )
    with pytest.raises(ValueError, match="does not exist"):
        load_campaign(path, capture="direct")
    (tmp_path / "schedule.csv").write_text("0.0,1200\n", encoding="utf-8")
    campaign = load_campaign(path, capture="direct")
    assert campaign.defenses[0].schedule_sha256


def test_live_workloads_require_review_and_safe_cooldown(tmp_path):
    path = _controlled_configuration(tmp_path)
    source = path.read_text().replace("source: controlled", "source: live")
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="reviewed"):
        load_campaign(path, capture="direct")
    path.write_text(source.replace("reviewed: false", "reviewed: true"), encoding="utf-8")
    with pytest.raises(ValueError, match="30-second"):
        load_campaign(path, capture="direct")


def test_visit_ids_and_splits_are_stable_across_capture_conditions():
    path = Path(__file__).parents[1] / "config/campaigns/single-resource-pilot.yml"
    local = load_campaign(path, capture="wireguard", network_condition="local")
    remote = load_campaign(path, capture="wireguard", network_condition="remote")
    direct = load_campaign(path, capture="direct")
    local_visits, local_samples, local_splits = plan_campaign(local)
    remote_visits, remote_samples, remote_splits = plan_campaign(remote)
    direct_visits, direct_samples, direct_splits = plan_campaign(direct)
    assert [visit["visit_id"] for visit in local_visits] == [
        visit["visit_id"] for visit in remote_visits
    ] == [visit["visit_id"] for visit in direct_visits]
    assert local_splits == remote_splits == direct_splits
    assert [sample["sample_id"] for sample in local_samples] != [
        sample["sample_id"] for sample in remote_samples
    ]
    assert [sample["sample_id"] for sample in local_samples] != [
        sample["sample_id"] for sample in direct_samples
    ]
    assert set(local_splits["assignments"].values()) == {"train", "test"}
    assert stable_digest("a", "bc") != stable_digest("ab", "c")


def test_auxiliary_failure_does_not_invalidate_primary_evidence(tmp_path):
    path = _controlled_configuration(tmp_path)
    campaign = load_campaign(path, capture="wireguard")
    visits, samples, _splits = plan_campaign(campaign)
    sample = samples[0]
    sample_path = tmp_path / sample["path"]
    (sample_path / "neqo").mkdir(parents=True)
    atomic_json(
        sample_path / "neqo/run.json",
        {
            "responses": [{"status": 200, "bytes": 10, "body_sha256": "same"}],
            "resolved_configuration": {"defense": "none"},
        },
    )
    atomic_json(
        sample_path / "sample.json",
        {
            "state": "captured",
            "views": [
                {"id": "wireguard-outer", "primary": True, "valid": True},
                {"id": "direct-quic", "primary": False, "valid": False},
            ],
        },
    )
    defenses = {defense.name: defense for defense in campaign.defenses}
    first_visit_samples = [sample for sample in samples if sample["visit_id"] == visits[0]["visit_id"]]
    _compare_visit(tmp_path, first_visit_samples, defenses, campaign)
    metadata = json.loads((sample_path / "sample.json").read_text())
    assert metadata["eligible"] is True
    assert metadata["views"][0]["eligible"] is True
    assert metadata["views"][1]["eligible"] is False


def test_repository_has_three_campaign_recipes_and_no_synthetic_schedule():
    root = Path(__file__).parents[1]
    assert not list((root / "config").glob("*.yml"))
    assert {path.name for path in (root / "config/campaigns").glob("*.yml")} == {
        "single-resource-pilot.yml",
        "dconn-replay-pilot.yml",
        "dmc-replay-pilot.yml",
    }
    assert not list((root / "config").rglob("*schedule*"))
    assert (root / "docker/collection-entrypoint").is_file()
    assert (root / "docker/wireguard-client-up").is_file()
    assert (root / "docker/wireguard-gateway-entrypoint").is_file()
    assert not (root / "src/qcsd_lab/experiment.py").exists()
    assert not (root / "src/qcsd_lab/corpus.py").exists()
    assert not (root / "src/qcsd_lab/runtime.py").exists()


def test_checked_in_replay_recipes_resolve_only_qualified_graphs():
    root = Path(__file__).parents[1]
    expected = {"chromium-quic-page", "chromium-projects-page"}
    for name, model in (
        ("dconn-replay-pilot.yml", "Dconn"),
        ("dmc-replay-pilot.yml", "Dmc"),
    ):
        campaign = load_campaign(root / "config/campaigns" / name, capture="wireguard")
        assert {workload["workload_id"] for workload in campaign.workloads} == expected
        assert {workload["workload_model"] for workload in campaign.workloads} == {model}


def test_shared_graph_resolves_dconn_and_dmc_without_split_leakage(tmp_path):
    graph = _replay_graph()
    dconn, dconn_details = resolve_workload(graph, "primary-origin")
    dmc, dmc_details = resolve_workload(graph, "all-reviewed-origins")
    assert len(dconn["resources"]) == 2
    assert dconn_details == {
        "workload_model": "Dconn",
        "resource_count": 2,
        "origin_count": 1,
        "expected_endpoint_count": 1,
    }
    assert len(dmc["resources"]) == 4
    assert dmc_details["origin_count"] == dmc_details["expected_endpoint_count"] == 2

    dconn_path = _replay_configuration(tmp_path, "primary-origin")
    dmc_path = _replay_configuration(tmp_path, "all-reviewed-origins")
    dconn_campaign = load_campaign(dconn_path, capture="wireguard")
    dmc_campaign = load_campaign(dmc_path, capture="wireguard")
    dconn_visits, dconn_samples, dconn_splits = plan_campaign(dconn_campaign)
    dmc_visits, dmc_samples, dmc_splits = plan_campaign(dmc_campaign)
    assert [visit["visit_id"] for visit in dconn_visits] == [
        visit["visit_id"] for visit in dmc_visits
    ]
    assert dconn_splits == dmc_splits
    assert [sample["sample_id"] for sample in dconn_samples] != [
        sample["sample_id"] for sample in dmc_samples
    ]


def test_scope_removes_dependencies_to_filtered_resources_and_rejects_small_dmc():
    graph = _replay_graph()
    graph["resources"][1]["depends_on"] = [0, 2]
    dconn, _details = resolve_workload(graph, "primary-origin")
    assert dconn["resources"][1]["depends_on"] == [0]
    graph["resources"] = graph["resources"][:2]
    graph["resources"][1]["depends_on"] = [0]
    with pytest.raises(ValueError, match="two retained HTTP/3 origins"):
        resolve_workload(graph, "all-reviewed-origins")


def test_replay_scope_rejects_resources_without_stability_preflight():
    graph = _replay_graph()
    graph["replay"].pop("response_stability")
    with pytest.raises(ValueError, match="response-stability preflight"):
        resolve_workload(graph, "all-reviewed-origins")


def _controlled_configuration(tmp_path: Path, *, defenses: str | None = None) -> Path:
    workloads = tmp_path / "workloads"
    workloads.mkdir()
    (workloads / "site.json").write_text(
        json.dumps(
            {
                "header_policy": {},
                "resources": [
                    {
                        "id": 0,
                        "url": "https://example.test/",
                        "headers": [],
                        "depends_on": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    path = tmp_path / "campaign.yml"
    path.write_text(
        "name: test\nseed: 7\nqcsd_profile: live\n"
        "workloads:\n  source: controlled\n  reviewed: false\n"
        "  monitored:\n    site: 1\n  unmonitored: {}\n"
        "limits:\n  per_origin_cooldown_seconds: 0\n  inter_sample_seconds: 0\n"
        "defenses:\n"
        + (defenses or "  - undefended\n"),
        encoding="utf-8",
    )
    return path


def _replay_configuration(tmp_path: Path, scope: str) -> Path:
    directory = tmp_path / scope
    (directory / "workloads").mkdir(parents=True)
    (directory / "workloads/site.json").write_text(
        json.dumps(_replay_graph()), encoding="utf-8"
    )
    path = directory / "campaign.yml"
    path.write_text(
        "name: replay-test\nseed: 7\nqcsd_profile: live\n"
        f"workloads:\n  root: workloads\n  scope: {scope}\n"
        "  source: controlled\n  reviewed: false\n"
        "  monitored:\n    site: 3\n  unmonitored: {}\n"
        "limits:\n  per_origin_cooldown_seconds: 0\n  inter_sample_seconds: 0\n"
        "defenses:\n  - undefended\n  - front\n",
        encoding="utf-8",
    )
    return path


def _replay_graph():
    resources = [
        {"id": 0, "url": "https://page.test/", "depends_on": [], "headers": []},
        {"id": 1, "url": "https://page.test/app.js", "depends_on": [0], "headers": []},
        {"id": 2, "url": "https://cdn.test/lib.js", "depends_on": [0], "headers": []},
        {"id": 3, "url": "https://cdn.test/image.png", "depends_on": [2], "headers": []},
    ]
    return {
        "header_policy": {},
        "resources": resources,
        "replay": {
            "source_url": "https://page.test/",
            "final_url": "https://page.test/",
            "chromium_version": "test",
            "settle_ms": 3000,
            "observed_request_count": 4,
            "observed_origins": ["https://page.test", "https://cdn.test"],
            "reviewed_origins": ["https://page.test", "https://cdn.test"],
            "exclusions": [],
            "response_stability": {
                "runs": 3,
                "stable_resource_ids": [0, 1, 2, 3],
            },
        },
    }
