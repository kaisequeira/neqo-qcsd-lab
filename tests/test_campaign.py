import json
from pathlib import Path

import pytest

import qcsd_lab.parameters as parameters_module
from qcsd_lab.campaign import (
    PARAMETER_ARTIFACT_NAME,
    PARAMETER_FLAG_BY_KIND,
    PARAMETER_PROVENANCE_ARTIFACT_NAME,
    _client_command,
    _compare_visit,
    _copy_defense_parameter_artifacts,
    _runner_result_complete,
    create_splits,
    load_campaign,
    plan_campaign,
    resolve_workload,
    stable_digest,
    visit_plan_for_workloads,
)
from qcsd_lab.capture import split_endpoint, tuple_filter
from qcsd_lab.parameters import REVIEWED_PARAMETER_INPUT_POLICY
from qcsd_lab.util import LAB_ROOT, atomic_json, sha256_file


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
    assert _runner_result_complete({"completion_status": "complete", "responses": [response]})
    assert not _runner_result_complete({"completion_status": "partial", "responses": [response]})
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [{**response, "complete": False, "outcome": "failed"}],
        }
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [response],
            "defense_diagnostics": {
                "padding_event_guard_triggered": True,
            },
        }
    )


def test_campaign_uses_one_direct_classification_capture_surface():
    path = Path(__file__).parents[1] / "config/campaigns/single-resource-pilot.yml"
    campaign = load_campaign(path)
    assert campaign.purpose == "classification"
    assert campaign.udp_payload_ceiling == 1_200
    assert campaign.reviewed is True
    assert [view.id for view in campaign.views] == ["direct-quic"]
    view = campaign.primary_view
    assert (view.interface, view.link_type, view.length_basis, view.primary) == (
        "eth0",
        "Ethernet",
        "frame.len",
        True,
    )
    assert view.as_dict() == {
        "id": "direct-quic",
        "kind": "direct-quic",
        "interface": "eth0",
        "link_type": "Ethernet",
        "length_basis": "frame.len",
        "primary": True,
    }
    assert sum(workload["visits"] for workload in campaign.workloads) == 24
    assert [defense.name for defense in campaign.defenses] == [
        "undefended",
        "front",
        "tamaraw",
    ]


def test_research_campaign_requires_canonical_seven_defenses(tmp_path):
    path = _controlled_configuration(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "stage: acceptance",
            "stage: research",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="canonical seven defenses"):
        load_campaign(path)


def test_research_campaign_rejects_canonical_names_bound_to_wrong_runtime_kinds(tmp_path):
    defenses = "".join(
        (
            f"  - name: {name}\n"
            "    kind: none\n"
            f"    baseline: {'true' if name == 'undefended' else 'false'}\n"
        )
        for name in (
            "undefended",
            "static",
            "front",
            "tamaraw",
            "traffic-morphing",
            "wtf-pad",
            "walkie-talkie",
        )
    )
    path = _controlled_configuration(tmp_path, defenses=defenses)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "stage: acceptance",
            "stage: research",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="fixed runtime kinds"):
        load_campaign(path)


def test_old_layered_configuration_is_rejected(tmp_path):
    path = _controlled_configuration(tmp_path)
    path.write_text(path.read_text() + "purpose: diagnostics\n", encoding="utf-8")
    with pytest.raises(ValueError, match="purpose"):
        load_campaign(path)


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
        load_campaign(path)
    (tmp_path / "schedule.csv").write_text("0.0,1200\n", encoding="utf-8")
    campaign = load_campaign(path)
    defense = campaign.defenses[0]
    assert defense.schedule_sha256
    command = _client_command(
        tmp_path / "workload.json",
        "test-workload",
        defense,
        42,
        campaign,
        tmp_path / "output",
    )
    index = command.index("--static-mode")
    assert command[index : index + 2] == ["--static-mode", "chaff-only"]
    assert command.count("--static-mode") == 1


@pytest.mark.parametrize(
    ("kind", "flag", "fixture"),
    [
        ("traffic_morphing", "--morphing-matrix", "traffic-morphing-live.json"),
        ("wtf_pad", "--wtf-pad-histograms", "wtfpad-live.json"),
        ("walkie_talkie", "--walkie-talkie-molded", "walkie-talkie-live.json"),
    ],
)
def test_parameterized_defenses_resolve_hash_and_runner_flag(tmp_path, kind, flag, fixture):
    parameters = LAB_ROOT / "config/defense-params" / fixture
    path = _controlled_configuration(
        tmp_path,
        defenses=(
            "  - name: selected\n"
            f"    kind: {kind}\n"
            "    baseline: true\n"
            f"    parameters: {parameters}\n"
            "    allow_reviewed_fixture: true\n"
        ),
    )
    campaign = load_campaign(path)
    defense = campaign.defenses[0]
    assert defense.kind == kind
    assert defense.parameters_sha256
    assert defense.parameters_input_policy == REVIEWED_PARAMETER_INPUT_POLICY
    assert defense.parameters_provenance_sha256
    assert "parameters_path" not in defense.as_dict()
    assert defense.as_dict(internal=True)["parameters_path"] == str(parameters.resolve())
    command = _client_command(
        tmp_path / "workload.json",
        "test-workload",
        defense,
        42,
        campaign,
        tmp_path / "output",
    )
    assert command[command.index("--defense") + 1] == kind.replace("_", "-")
    assert command[command.index(flag) + 1] == str(parameters.resolve())
    assert PARAMETER_FLAG_BY_KIND[kind] == flag
    if kind in {"traffic_morphing", "walkie_talkie"}:
        assert command[command.index("--workload-id") + 1] == "test-workload"
    else:
        assert "--workload-id" not in command

    neqo = tmp_path / "sample-neqo"
    neqo.mkdir()
    _copy_defense_parameter_artifacts(defense, neqo)
    assert sha256_file(neqo / PARAMETER_ARTIFACT_NAME) == defense.parameters_sha256
    assert (
        sha256_file(neqo / PARAMETER_PROVENANCE_ARTIFACT_NAME)
        == defense.parameters_provenance_sha256
    )


def test_parameter_files_are_required_and_rejected_for_other_defenses(tmp_path):
    missing = _controlled_configuration(
        tmp_path,
        defenses=("  - name: morph\n    kind: traffic_morphing\n    baseline: true\n"),
    )
    with pytest.raises(ValueError, match="requires a parameter file"):
        load_campaign(missing)

    parameter = tmp_path / "parameter.json"
    parameter.write_text("{}\n", encoding="utf-8")
    missing_root = tmp_path / "missing-sidecar"
    missing_root.mkdir()
    missing_sidecar = _controlled_configuration(
        missing_root,
        defenses=(
            f"  - name: morph\n    kind: traffic_morphing\n"
            f"    baseline: true\n    parameters: {parameter}\n"
        ),
    )
    with pytest.raises(ValueError, match="adjacent provenance sidecar"):
        load_campaign(missing_sidecar)

    foreign_root = tmp_path / "foreign"
    foreign_root.mkdir()
    foreign = _controlled_configuration(
        foreign_root,
        defenses=(
            f"  - name: front\n    kind: front\n    baseline: true\n    parameters: {parameter}\n"
        ),
    )
    with pytest.raises(ValueError, match="parameters .* only valid"):
        load_campaign(foreign)


def test_unknown_defense_kind_is_rejected_at_campaign_load(tmp_path):
    path = _controlled_configuration(
        tmp_path,
        defenses=("  - name: unknown\n    kind: imaginary_defense\n    baseline: true\n"),
    )
    with pytest.raises(ValueError, match="unsupported defense kind"):
        load_campaign(path)


def test_reviewed_parameter_fixture_requires_explicit_opt_in(tmp_path, monkeypatch):
    monkeypatch.setattr(parameters_module, "LAB_ROOT", tmp_path)
    fixture_root = tmp_path / "config/defense-params"
    fixture_root.mkdir(parents=True)
    parameters = fixture_root / "traffic_morphing.json"
    parameters.write_text("{}\n", encoding="utf-8")
    _write_reviewed_parameter_provenance(parameters)
    relative_parameters = parameters.relative_to(tmp_path)
    defenses = (
        "  - name: selected\n"
        "    kind: traffic_morphing\n"
        "    baseline: true\n"
        f"    parameters: {relative_parameters}\n"
    )
    path = _controlled_configuration(tmp_path, defenses=defenses)
    with pytest.raises(ValueError, match="allow_reviewed_fixture"):
        load_campaign(path)

    path.write_text(
        path.read_text().replace(
            f"    parameters: {relative_parameters}\n",
            f"    parameters: {relative_parameters}\n    allow_reviewed_fixture: true\n",
        ),
        encoding="utf-8",
    )
    campaign = load_campaign(path)
    assert campaign.defenses[0].parameters_input_policy == REVIEWED_PARAMETER_INPUT_POLICY
    assert campaign.purpose == "classification"

    path.write_text(path.read_text().replace("stage: acceptance", "stage: research"))
    with pytest.raises(ValueError, match="restricted to acceptance"):
        load_campaign(path)


def test_reviewed_parameter_fixture_outside_checked_in_root_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(parameters_module, "LAB_ROOT", tmp_path)
    parameters = tmp_path / "traffic_morphing.json"
    parameters.write_text("{}\n", encoding="utf-8")
    _write_reviewed_parameter_provenance(parameters)
    path = _controlled_configuration(
        tmp_path,
        defenses=(
            "  - name: selected\n"
            "    kind: traffic_morphing\n"
            "    baseline: true\n"
            f"    parameters: {parameters.name}\n"
            "    allow_reviewed_fixture: true\n"
        ),
    )
    with pytest.raises(ValueError, match="must be checked in under"):
        load_campaign(path)


def test_live_workloads_require_review_and_safe_cooldown(tmp_path):
    path = _controlled_configuration(tmp_path)
    source = path.read_text().replace("source: controlled", "source: live")
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="reviewed"):
        load_campaign(path)
    path.write_text(source.replace("reviewed: false", "reviewed: true"), encoding="utf-8")
    with pytest.raises(ValueError, match="30-second"):
        load_campaign(path)


def test_capture_limit_must_cover_runner_timeout_and_settle_tail(tmp_path):
    path = _controlled_configuration(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "  inter_sample_seconds: 0\n",
            "  inter_sample_seconds: 0\n"
            "  timeout_seconds: 45\n"
            "  settle_seconds: 1\n"
            "  capture_seconds: 46\n",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="collector startup margin"):
        load_campaign(path)


def test_visit_ids_and_splits_are_stable_across_network_conditions():
    path = Path(__file__).parents[1] / "config/campaigns/single-resource-pilot.yml"
    local = load_campaign(path, network_condition="local")
    remote = load_campaign(path, network_condition="remote")
    local_visits, local_samples, local_splits = plan_campaign(local)
    remote_visits, remote_samples, remote_splits = plan_campaign(remote)
    assert [visit["visit_id"] for visit in local_visits] == [
        visit["visit_id"] for visit in remote_visits
    ]
    assert local_splits == remote_splits
    assert [sample["sample_id"] for sample in local_samples] != [
        sample["sample_id"] for sample in remote_samples
    ]
    assert set(local_splits["assignments"].values()) == {
        "train",
        "validation",
        "test",
    }
    assert local_splits["ratios"] == {
        "train": 0.70,
        "validation": 0.15,
        "test": 0.15,
    }
    assert stable_digest("a", "bc") != stable_digest("ab", "c")


def test_split_groups_are_stable_across_cohort_policy_scope_and_workload_alias():
    source_sha256 = "a" * 64
    base = _planning_workload("site", source_sha256)
    other = _planning_workload("other", "b" * 64)
    alias = _planning_workload("renamed-site", source_sha256)

    _study, [base_visit] = visit_plan_for_workloads(
        campaign_seed=7,
        request_policy="as-defined",
        workload_scope="as-defined",
        workload_root="workloads",
        workloads=[base],
    )
    _cohort_study, cohort_visits = visit_plan_for_workloads(
        campaign_seed=7,
        request_policy="as-defined",
        workload_scope="as-defined",
        workload_root="workloads",
        workloads=[base, other],
    )
    _alias_study, [alias_visit] = visit_plan_for_workloads(
        campaign_seed=7,
        request_policy="as-defined",
        workload_scope="as-defined",
        workload_root="workloads",
        workloads=[alias],
    )
    _policy_study, [policy_visit] = visit_plan_for_workloads(
        campaign_seed=7,
        request_policy="half-duplex",
        workload_scope="as-defined",
        workload_root="workloads",
        workloads=[base],
    )
    _scope_study, [scope_visit] = visit_plan_for_workloads(
        campaign_seed=7,
        request_policy="as-defined",
        workload_scope="primary-origin",
        workload_root="workloads",
        workloads=[base],
    )

    cohort_visit = next(visit for visit in cohort_visits if visit["workload_id"] == "site")
    assert cohort_visit["visit_id"] == base_visit["visit_id"]
    variants = [base_visit, cohort_visit, alias_visit, policy_visit, scope_visit]
    assert {visit["split_group_id"] for visit in variants} == {base_visit["split_group_id"]}
    assert len({base_visit["visit_id"], alias_visit["visit_id"]}) == 2
    assert len({base_visit["visit_id"], policy_visit["visit_id"]}) == 2
    assert len({base_visit["visit_id"], scope_visit["visit_id"]}) == 2
    assert {
        next(iter(create_splits([visit], 7)["assignments"].values())) for visit in variants
    } == {next(iter(create_splits([base_visit], 7)["assignments"].values()))}


def test_split_groups_are_independent_of_stage_and_defense_selection(tmp_path):
    path = _controlled_configuration(tmp_path)
    acceptance = load_campaign(path)
    acceptance_visits, _samples, acceptance_splits = plan_campaign(acceptance)
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("stage: acceptance", "stage: parameter-fitting")
        .replace("defenses:\n  - undefended", "defenses:\n  - undefended\n  - front"),
        encoding="utf-8",
    )
    fitting = load_campaign(path)
    fitting_visits, _samples, fitting_splits = plan_campaign(fitting)

    assert [visit["visit_id"] for visit in acceptance_visits] == [
        visit["visit_id"] for visit in fitting_visits
    ]
    assert [visit["split_group_id"] for visit in acceptance_visits] == [
        visit["split_group_id"] for visit in fitting_visits
    ]
    assert acceptance_splits == fitting_splits


def test_research_campaign_rejects_ambiguous_source_manifest_aliases(tmp_path):
    path = _controlled_configuration(tmp_path)
    workload_root = tmp_path / "workloads"
    (workload_root / "alias.json").write_bytes((workload_root / "site.json").read_bytes())
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("stage: acceptance", "stage: research")
        .replace("    site: 1", "    site: 1\n    alias: 1"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="same source manifest"):
        load_campaign(path)


def test_acceptance_campaign_keeps_source_aliases_in_one_split_group(tmp_path):
    path = _controlled_configuration(tmp_path)
    workload_root = tmp_path / "workloads"
    (workload_root / "alias.json").write_bytes((workload_root / "site.json").read_bytes())
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "    site: 1",
            "    site: 1\n    alias: 1",
        ),
        encoding="utf-8",
    )
    campaign = load_campaign(path)
    visits, _samples, splits = plan_campaign(campaign)

    assert len({visit["split_group_id"] for visit in visits}) == 1
    assert len(splits["assignments"]) == 1


def test_padding_guard_invalidates_sample_even_when_response_and_capture_match(tmp_path):
    path = _controlled_configuration(tmp_path)
    campaign = load_campaign(path)
    visits, samples, _splits = plan_campaign(campaign)
    sample = samples[0]
    sample_path = tmp_path / sample["path"]
    (sample_path / "neqo").mkdir(parents=True)
    atomic_json(
        sample_path / "neqo/run.json",
        {
            "responses": [{"status": 200, "bytes": 10, "body_sha256": "same"}],
            "resolved_configuration": {"defense": "wtf_pad"},
            "defense_diagnostics": {
                "padding_events": 10,
                "padding_event_guard_triggered": True,
            },
        },
    )
    atomic_json(
        sample_path / "sample.json",
        {
            "state": "captured",
            "defense": sample["defense"],
            "runtime_kind": sample["runtime_kind"],
            "views": [
                {"id": "direct-quic", "primary": True, "valid": True},
            ],
        },
    )
    defenses = {defense.name: defense for defense in campaign.defenses}
    _compare_visit(tmp_path, [sample], defenses, campaign)
    metadata = json.loads((sample_path / "sample.json").read_text())
    assert metadata["response_match"] is True
    assert metadata["operationally_valid"] is False
    assert metadata["eligible"] is False
    assert metadata["views"][0]["eligible"] is False


def test_failed_guard_diagnostics_survive_visit_comparison(tmp_path):
    path = _controlled_configuration(tmp_path)
    campaign = load_campaign(path)
    _visits, samples, _splits = plan_campaign(campaign)
    sample = samples[0]
    sample.update(
        state="failed",
        operationally_valid=False,
        defense_diagnostics={
            "padding_events": 10,
            "padding_event_guard_triggered": True,
        },
    )
    sample_path = tmp_path / sample["path"]
    sample_path.mkdir(parents=True)
    atomic_json(
        sample_path / "sample.json",
        {
            "state": "failed",
            "defense": sample["defense"],
            "runtime_kind": sample["runtime_kind"],
            "views": [],
            "operationally_valid": False,
            "defense_diagnostics": sample["defense_diagnostics"],
        },
    )
    defenses = {defense.name: defense for defense in campaign.defenses}
    _compare_visit(tmp_path, [sample], defenses, campaign)
    metadata = json.loads((sample_path / "sample.json").read_text())
    assert metadata["operationally_valid"] is False
    assert metadata["defense_diagnostics"]["padding_event_guard_triggered"] is True
    assert metadata["eligible"] is False


def test_repository_has_migration_recipe_and_versioned_parameter_fixtures():
    root = Path(__file__).parents[1]
    assert not list((root / "config").glob("*.yml"))
    assert {path.name for path in (root / "config/campaigns").glob("*.yml")} == {
        "single-resource-pilot.yml",
        "dconn-replay-pilot.yml",
        "dmc-replay-pilot.yml",
        "defense-migration-pilot.yml",
    }
    parameters = root / "config/defense-params"
    assert {path.name for path in parameters.iterdir()} == {
        "static-migration.csv",
        "traffic-morphing-live.json",
        "traffic-morphing-live.json.provenance.json",
        "walkie-talkie-live.json",
        "walkie-talkie-live.json.provenance.json",
        "wtfpad-live.json",
        "wtfpad-live.json.provenance.json",
    }
    assert {path.name for path in (root / "docker").iterdir()} == {"collection-entrypoint"}
    assert not (root / "src/qcsd_lab/experiment.py").exists()
    assert not (root / "src/qcsd_lab/corpus.py").exists()
    assert not (root / "src/qcsd_lab/runtime.py").exists()
    for removed in (
        "morphing.py",
        "wtfpad.py",
        "walkietalkie.py",
        "parameter_cli.py",
        "parameter_trace.py",
        "parameter_inputs.py",
        "morphing_reconciliation.py",
    ):
        assert not (root / "src/qcsd_lab" / removed).exists()
    assert (root / "src/qcsd_lab/parameters.py").is_file()


def test_migration_recipe_resolves_all_seven_defenses_and_one_baseline():
    root = Path(__file__).parents[1]
    campaign = load_campaign(root / "config/campaigns/defense-migration-pilot.yml")
    workloads = {item["workload_id"]: item for item in campaign.workloads}
    assert campaign.source == "live"
    assert campaign.reviewed is True
    assert set(workloads) == {"cloudflare-quiche", "chromium-quic-page"}
    assert workloads["cloudflare-quiche"]["resource_count"] == 1
    assert workloads["chromium-quic-page"]["origin_count"] > 1
    assert all(item["visits"] == 1 for item in workloads.values())
    assert [defense.kind for defense in campaign.defenses] == [
        "none",
        "static",
        "front",
        "tamaraw",
        "traffic_morphing",
        "wtf_pad",
        "walkie_talkie",
    ]
    assert sum(defense.baseline for defense in campaign.defenses) == 1
    assert all(
        defense.parameters_sha256
        for defense in campaign.defenses
        if defense.kind in PARAMETER_FLAG_BY_KIND
    )
    assert all(
        defense.parameters_input_policy == REVIEWED_PARAMETER_INPUT_POLICY
        and defense.parameters_provenance_sha256
        for defense in campaign.defenses
        if defense.kind in PARAMETER_FLAG_BY_KIND
    )
    assert campaign.purpose == "classification"


def test_checked_in_parameter_fixtures_match_frozen_schemas():
    root = Path(__file__).parents[1] / "config/defense-params"
    morphing = json.loads((root / "traffic-morphing-live.json").read_text())
    assert set(morphing) == {
        "adaptation",
        "paper_equivalent",
        "schema_version",
        "generated_by",
        "buckets",
        "udp_payload_ceiling",
        "profiles",
    }
    assert all(
        set(profile) == {"source", "target", "outgoing", "incoming"}
        and all(
            set(profile[direction])
            == {
                "expected_added_bytes",
                "l1_distance",
                "realized_distribution",
                "rows",
                "source_distribution",
                "target_distribution",
            }
            for direction in ("outgoing", "incoming")
        )
        for profile in morphing["profiles"]
    )
    assert morphing["adaptation"] == "qcsd-client-only"
    assert morphing["paper_equivalent"] is False
    count = len(morphing["buckets"])
    identity = [[1.0 if row == column else 0.0 for column in range(count)] for row in range(count)]
    assert {profile["source"] for profile in morphing["profiles"]} == {
        "cloudflare-quiche",
        "chromium-quic-page",
        "simple",
        "complex",
    }
    assert all(profile["outgoing"]["rows"] != identity for profile in morphing["profiles"])
    assert all(
        max(range(count), key=profile["outgoing"]["rows"][0].__getitem__) == count - 1
        for profile in morphing["profiles"]
    )
    wtfpad = json.loads((root / "wtfpad-live.json").read_text())
    assert set(wtfpad) == {
        "schema_version",
        "adaptation",
        "paper_equivalent",
        "fitted_from",
        "generated_by",
        "fitting",
        "outgoing",
        "incoming",
    }
    assert wtfpad["schema_version"] == 2
    assert wtfpad["adaptation"] == "qcsd-client-only"
    assert wtfpad["paper_equivalent"] is False
    assert wtfpad["fitting"]["instantaneous_bandwidth_window_packets"] == 2
    assert wtfpad["fitting"]["histogram_bin_count"] == 20
    assert "gap_threshold_us" not in wtfpad

    walkie_talkie = json.loads((root / "walkie-talkie-live.json").read_text())
    assert set(walkie_talkie) == {
        "adaptation",
        "burst_definition",
        "cell_byte_domain",
        "schema_version",
        "generated_by",
        "matching_algorithm",
        "paper_equivalent",
        "packet_size",
        "training_split",
        "profiles",
    }
    assert walkie_talkie["schema_version"] == 2
    assert walkie_talkie["adaptation"] == "qcsd-client-only"
    assert walkie_talkie["paper_equivalent"] is False
    assert walkie_talkie["burst_definition"] == "global-application-batch-direction-transitions"
    assert walkie_talkie["cell_byte_domain"] == "http3-request-stream-offset.bytes"
    assert walkie_talkie["matching_algorithm"] == "minimum-cost-one-to-one"
    assert walkie_talkie["training_split"] == "reviewed-acceptance-fixture"
    assert {
        identity
        for profile in walkie_talkie["profiles"]
        for identity in (profile["real"], profile["decoy"])
    } == {
        "cloudflare-quiche",
        "acceptance-decoy-simple",
        "chromium-quic-page",
        "acceptance-decoy-complex",
        "simple",
        "acceptance-decoy-local-simple",
        "complex",
        "acceptance-decoy-local-complex",
    }
    assert all(
        profile["total_scheduled_bytes"]
        == sum(
            (burst["outgoing"] + burst["incoming"]) * walkie_talkie["packet_size"]
            for burst in profile["bursts"]
        )
        for profile in walkie_talkie["profiles"]
    )
    complex_profile = next(
        profile for profile in walkie_talkie["profiles"] if profile["real"] == "chromium-quic-page"
    )
    assert complex_profile["bursts"][-2:] == [
        {"outgoing": 0, "incoming": 128},
        {"outgoing": 2, "incoming": 32},
    ]


def test_checked_in_replay_recipes_resolve_only_qualified_graphs():
    root = Path(__file__).parents[1]
    expected = {"chromium-quic-page", "chromium-projects-page"}
    for name, model in (
        ("dconn-replay-pilot.yml", "Dconn"),
        ("dmc-replay-pilot.yml", "Dmc"),
    ):
        campaign = load_campaign(root / "config/campaigns" / name)
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
    dconn_campaign = load_campaign(dconn_path)
    dmc_campaign = load_campaign(dmc_path)
    dconn_visits, dconn_samples, dconn_splits = plan_campaign(dconn_campaign)
    dmc_visits, dmc_samples, dmc_splits = plan_campaign(dmc_campaign)
    assert [visit["visit_id"] for visit in dconn_visits] != [
        visit["visit_id"] for visit in dmc_visits
    ]
    assert [visit["split_group_id"] for visit in dconn_visits] == [
        visit["split_group_id"] for visit in dmc_visits
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


def _planning_workload(workload_id: str, source_sha256: str) -> dict[str, object]:
    return {
        "workload_id": workload_id,
        "manifest": f"workloads/{workload_id}.json",
        "manifest_path": f"/tmp/{workload_id}.json",
        "manifest_sha256": source_sha256,
        "source_manifest_sha256": source_sha256,
        "resolved_manifest_sha256": source_sha256,
        "class_label": workload_id,
        "role": "monitored",
        "visits": 1,
        "workload_model": "as-defined",
        "resource_count": 1,
        "origin_count": 1,
        "expected_endpoint_count": 1,
    }


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
        "name: test\nseed: 7\nstage: acceptance\nqcsd_profile: live\n"
        "workloads:\n  source: controlled\n  reviewed: false\n"
        "  request_policy: as-defined\n"
        "  monitored:\n    site: 1\n  unmonitored: {}\n"
        "limits:\n  per_origin_cooldown_seconds: 0\n  inter_sample_seconds: 0\n"
        "defenses:\n" + (defenses or "  - undefended\n"),
        encoding="utf-8",
    )
    return path


def _write_reviewed_parameter_provenance(parameter: Path) -> Path:
    atomic_json(
        parameter,
        {
            "schema_version": 2,
            "adaptation": "qcsd-client-only",
            "paper_equivalent": False,
            "buckets": [1200],
            "udp_payload_ceiling": 1200,
            "profiles": [],
        },
    )
    provenance = parameter.with_suffix(parameter.suffix + ".provenance.json")
    atomic_json(
        provenance,
        {
            "schema_version": 1,
            "generator": "test-fixture",
            "input_policy": REVIEWED_PARAMETER_INPUT_POLICY,
            "unsealed_engineering_opt_in": True,
            "parameter_file": {
                "path": parameter.name,
                "sha256": sha256_file(parameter),
            },
            "inputs": {},
        },
    )
    return provenance


def _replay_configuration(tmp_path: Path, scope: str) -> Path:
    directory = tmp_path / scope
    (directory / "workloads").mkdir(parents=True)
    (directory / "workloads/site.json").write_text(json.dumps(_replay_graph()), encoding="utf-8")
    path = directory / "campaign.yml"
    path.write_text(
        "name: replay-test\nseed: 7\nstage: acceptance\nqcsd_profile: live\n"
        f"workloads:\n  root: workloads\n  scope: {scope}\n"
        "  source: controlled\n  reviewed: false\n  request_policy: as-defined\n"
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
