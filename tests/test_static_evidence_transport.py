"""HOST transport regressions; synthetic emitter fixtures give no study credit."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_supplied_static_preparation import fixed_graph, POLICIES
from tests.test_supplied_static_get import actual_contract_fixture
from qcsd_lab import supplied_static_preparation as preparation
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab import rapid_rolling_readiness as readiness


def static_manifest(fixture):
    root, arguments, _ = fixture
    return preparation.build_preparation(root, **arguments, policies=POLICIES)


def test_static_roots_reopen_real_raw_contract_and_context(fixed_graph):
    root, _, context = fixed_graph
    assert transport.manifest_roots(static_manifest(fixed_graph)) == sorted([root, context.root])


def test_changed_raw_get_cannot_gain_transport(fixed_graph):
    manifest = static_manifest(fixed_graph)
    (fixed_graph[0] / "native/packets.csv").write_bytes(b"changed raw GET bytes\n")
    with pytest.raises(ValueError):
        transport.manifest_roots(manifest)


def test_changed_prospective_context_cannot_gain_transport(fixed_graph):
    manifest = static_manifest(fixed_graph)
    profile = fixed_graph[2].root / "profile.json"
    profile.chmod(0o600)
    profile.write_bytes(b"{}\n")
    with pytest.raises(ValueError):
        transport.manifest_roots(manifest)


@pytest.mark.parametrize("manifest", [{}, {"preparation": {}}, {"preparation": {"browser_version": "synthetic"}}])
def test_browser_preparation_adds_no_transport(manifest):
    assert transport.manifest_roots(manifest) == []


def test_unknown_preparation_role_rejected():
    with pytest.raises(ValueError, match="unknown preparation role"):
        transport.manifest_roots({"preparation": {"data_role": "caller-invented"}})


@pytest.mark.parametrize("unsafe", ["relative", "parent", "symlink", "colon"])
def test_mount_paths_must_be_regular_canonical_and_safe(tmp_path, unsafe):
    target = tmp_path / "retained"
    target.mkdir()
    path = target
    if unsafe == "relative": path = Path("retained")
    elif unsafe == "parent": path = tmp_path / "retained/.."
    elif unsafe == "symlink":
        path = tmp_path / "alias"
        path.symlink_to(target, target_is_directory=True)
    else:
        path = tmp_path / "retained:caller"
        path.mkdir()
    with pytest.raises(ValueError, match="canonical regular absolute"):
        transport._path(path, directory=True)


def test_run_and_resume_derive_only_authenticated_workload_roots(fixed_graph, tmp_path):
    manifest = static_manifest(fixed_graph)
    execution = tmp_path / "execution"
    workloads = execution / "config/workloads"
    campaigns = execution / "config/campaigns"
    workloads.mkdir(parents=True)
    campaigns.mkdir()
    (workloads / "poki.json").write_text(json.dumps(manifest))
    campaign = campaigns / "actual.yml"
    campaign.write_text("schema: 1\nworkloads:\n  poki: 1\n")
    expected = transport.manifest_roots(manifest)
    assert transport.campaign_roots(execution, "run", campaign) == expected
    result = execution / "results/actual/001"
    result.mkdir(parents=True)
    (result / "original.json").write_text(json.dumps(manifest))
    (result / "experiment.json").write_text(json.dumps({"configuration": {"workloads": [{"manifest": "original.json"}]}}))
    assert transport.campaign_roots(execution, "resume", result) == expected
    (result / "experiment.json").write_text(json.dumps({"configuration": {"workloads": [{"manifest": "../caller.json"}]}}))
    with pytest.raises(ValueError, match="unsafe"):
        transport.campaign_roots(execution, "resume", result)


def test_browser_custom_campaign_location_and_existing_slug_remain_legal(tmp_path):
    execution = tmp_path / "execution"
    config = execution / "custom-config"
    campaigns, workloads = config / "campaigns", config / "workloads"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    (workloads / "Workload_1.v2.json").write_text(json.dumps({"preparation": {}, "resources": []}))
    campaign = campaigns / "browser.yml"
    campaign.write_text("schema: 1\nworkloads:\n  Workload_1.v2: 1\n")
    assert transport.campaign_roots(execution, "run", campaign) == []


def test_static_custom_campaign_location_preserves_existing_config_resolution(fixed_graph, tmp_path):
    execution = tmp_path / "execution"
    config = execution / "custom-config"
    campaigns, workloads = config / "campaigns", config / "workloads"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    manifest = static_manifest(fixed_graph)
    (workloads / "Poki_1.v2.json").write_text(json.dumps(manifest))
    campaign = campaigns / "static.yml"
    campaign.write_text("schema: 1\nworkloads:\n  Poki_1.v2: 1\n")
    assert transport.campaign_roots(execution, "run", campaign) == transport.manifest_roots(manifest)


def deep_inputs(tmp_path, manifest):
    directory = tmp_path / "canary"
    (directory / "lineage").mkdir(parents=True)
    raw = readiness._encoded(manifest)
    (directory / "lineage/original-manifest.json").write_bytes(raw)
    recipe = tmp_path / "recipe.py"
    helper = tmp_path / "helper.py"
    recipe.write_bytes(b"# held recipe\n")
    helper.write_bytes(b"# held helper\n")
    plan = {"name": "static-poki", "recipe_sha256": readiness._sha(recipe.read_bytes()),
        "helper_sha256": readiness._sha(helper.read_bytes()), "original_workload_sha256": readiness._sha(raw),
        "clean_runtime_root": str(tmp_path / "clean"), "execution_root": str(tmp_path / "execution"),
        "canonical_runtime": {"collection_image_digest": "sha256:" + "a" * 64}}
    command = ["docker", "run", "--user", "1000:1000", "--volume", str(recipe) + ":/recipe.py:ro",
               "--volume", str(helper) + ":/helpers.py:ro"]
    return directory, plan, command


def test_deep_command_static_mounts_are_derived_and_read_only(fixed_graph, tmp_path):
    manifest = static_manifest(fixed_graph)
    directory, plan, command = deep_inputs(tmp_path, manifest)
    # A caller-declared extra mount has no authority to enter the expected argv.
    plan["static_preparation_roots"] = ["/caller/arbitrary"]
    result = readiness._deep_command(plan, directory, "b" * 64, "undefended", "/lab/results/a/001", command)
    for root in transport.manifest_roots(manifest):
        assert result.count(f"{root}:{root}:ro") == 1
        assert f"{root}:{root}:rw" not in result
    assert all("/caller/arbitrary" not in value for value in result)


def test_browser_deep_command_keeps_exact_original_transport(tmp_path):
    directory, plan, command = deep_inputs(tmp_path, {"preparation": {}, "resources": []})
    result = readiness._deep_command(plan, directory, "b" * 64, "undefended", "/lab/results/a/001", command)
    mounts = [result[i + 1] for i, value in enumerate(result) if value == "--volume"]
    assert mounts == [f'{plan["clean_runtime_root"]}:/runtime-src:ro',
                      f'{plan["execution_root"]}:/lab:ro', f"{directory}:/diagnostic:rw",
                      command[command.index("--volume") + 1], command[-1]]


def test_readiness_reopening_transports_original_get_context(fixed_graph, tmp_path, monkeypatch):
    manifest = static_manifest(fixed_graph)
    directory, plan, command = deep_inputs(tmp_path, manifest)
    for role in ("clean", "execution"):
        (tmp_path / role).mkdir()
    for name in ("source.json", "client", "launcher"):
        (tmp_path / name).write_bytes(b"immutable input")
    plan_path = directory / "plan.json"
    plan_path.write_bytes(readiness._encoded(plan))
    started = directory / "deep-started.json"
    started.write_bytes(readiness._encoded({"command": command}))
    def reference(path): return {"path": str(path), "sha256": readiness._sha(path.read_bytes())}
    canary = {"schema_version": 1, "plan": reference(plan_path), "deep": {"started": reference(started)}}
    runtime = {"runtime_source_root": str(tmp_path / "clean"), "module_root": str(tmp_path / "clean"),
        "execution_root": str(tmp_path / "execution"), "source_manifest": str(tmp_path / "source.json"),
        "client_binary": str(tmp_path / "client"), "base_launcher": str(tmp_path / "launcher"),
        "host_launcher": str(tmp_path / "launcher"), "collection_image_digest": "sha256:" + "a" * 64}
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: {})
    roots = readiness.readiness_mount_roots(canary, runtime=runtime, mode="undefended")
    assert set(transport.manifest_roots(manifest)).issubset(roots)
