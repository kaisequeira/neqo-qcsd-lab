"""Focused host selector checks without starting Docker or acquiring evidence."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import orchestrator
from qcsd_lab.rapid_capture_plan import Site, plan_lanes, render_lane_campaign


LAUNCHER = Path(__file__).resolve().parents[1] / "qcsd-lab"


def _selector_script(root: Path, *, include_binding: bool = False) -> str:
    source = LAUNCHER.read_text(encoding="utf-8")
    selector = source.split(
        "# A prospective rapid campaign uses the existing ETF-capable collection image", 1
    )[1].split("\nstudy_build_execution_path=\"\"", 1)[0]
    return (
        "set -euo pipefail\n"
        f"ROOT={shlex.quote(str(root))}\n"
        'study_campaign_name="${2##*/}"\n'
        'study_resume_root="${2:-}"\n'
        'study_resume_name=""\n'
        'if [[ "${1:-}" == resume ]]; then\n'
        "  study_resume_name=$(/usr/bin/python3 -I -c "
        "'import json,sys; print(json.load(open(sys.argv[1]))[\"name\"])' "
        '"${study_resume_root}/experiment.json")\n'
        "fi\n"
        "rapid_capture=0\n"
        "rapid_capture_name=\n"
        "rapid_capture_target=\n"
        "rapid_capture_role=\n"
        "rapid_capture_mode=\n"
        "rapid_capture_version=\n"
        "rapid_capture_args=()\n"
        f"# A prospective rapid campaign uses the existing ETF-capable collection image{selector}\n"
        'printf "%s\\n" "${rapid_capture}" "${rapid_capture_name}" '
        '"${rapid_capture_target}" "${rapid_capture_args[@]}"\n'
        + ('printf "%s\\n" "${rapid_capture_role}" "${rapid_capture_mode}" '
           '"${rapid_capture_version}"\n' if include_binding else "")
    )


def _select(
    root: Path, action: str, target: Path, *, include_binding: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", _selector_script(root, include_binding=include_binding),
         "rapid-test", action, str(target)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_rapid_run_selects_canonical_campaign_path(tmp_path: Path) -> None:
    campaign = tmp_path / "artifacts/rapid-curated-tranco50-v2-diagnostic-block01.yml"
    campaign.parent.mkdir()
    campaign.write_text(
        "schema: 1\nname: rapid-curated-tranco50-v2-diagnostic-block01\npurpose: smoke\n",
        encoding="utf-8",
    )
    selected = _select(tmp_path, "run", campaign)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines() == [
        "1", "rapid-curated-tranco50-v2-diagnostic-block01",
        "/lab/artifacts/rapid-curated-tranco50-v2-diagnostic-block01.yml",
        "run", "/lab/artifacts/rapid-curated-tranco50-v2-diagnostic-block01.yml",
    ]

    linked = campaign.with_name("rapid-curated-tranco50-v2-diagnostic-linked.yml")
    linked.symlink_to(campaign)
    rejected = _select(tmp_path, "run", linked)
    assert rejected.returncode != 0
    assert "regular file" in rejected.stderr


def test_rapid_resume_requires_matching_frozen_identity(tmp_path: Path) -> None:
    name = "rapid-curated-tranco50-v2-diagnostic-block01"
    result = tmp_path / "results" / name / "20261002T120000Z"
    inputs = result / "inputs"
    inputs.mkdir(parents=True)
    (result / "experiment.json").write_text(
        json.dumps({"name": name}), encoding="utf-8"
    )
    frozen = inputs / "campaign.yml"
    frozen.write_text(f"schema: 1\nname: {name}\n", encoding="utf-8")
    selected = _select(tmp_path, "resume", result)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines() == [
        "1", name, f"/lab/results/{name}/20261002T120000Z",
        "resume", f"/lab/results/{name}/20261002T120000Z",
    ]

    frozen.unlink()
    missing = _select(tmp_path, "resume", result)
    assert missing.returncode != 0
    assert "regular frozen campaign" in missing.stderr


@pytest.mark.parametrize("name", [
    "rapid-curated-tranco50-v2-diagnostic-block01",
    "rapid-curated-tranco50-v4-formal-b01-s01-front-1200",
    "rapid-curated-tranco50-v5-diagnostic-b01-s02-cs-buflo-1200-g02",
    "rapid-curated-tranco50-v5-formal-b16-s10-buflo-1200",
])
def test_direct_rapid_resume_preserves_evidence_before_docker(
    tmp_path: Path, name: str,
) -> None:
    if os.getuid() == 0 or os.getgid() == 0:
        pytest.skip("the launcher requires a non-root host identity")
    project = tmp_path / "lab"
    tools = project / "tools"
    tools.mkdir(parents=True)
    (project / "neqo-qcsd").mkdir()
    (project / "neqo-qcsd" / "Cargo.lock").write_text("# fixture checkout\n")
    sentinel = project / "docker-preflight-reached"
    source = LAUNCHER.read_text(encoding="utf-8")
    assert source.count("require_docker() {\n") == 1
    launcher = project / "qcsd-lab"
    launcher.write_text(source.replace(
        "require_docker() {\n",
        f"require_docker() {{\n  touch {shlex.quote(str(sentinel))}\n  exit 99\n",
        1,
    ), encoding="utf-8")
    launcher.chmod(0o755)
    helper = tools / "docker_signal_supervisor.sh"
    shutil.copyfile(LAUNCHER.parent / "tools" / helper.name, helper)
    helper.chmod(0o644)
    result = project / "results" / name / "run-001"
    (result / "inputs").mkdir(parents=True)
    (result / "samples" / "attempt-003").mkdir(parents=True)
    (result / "experiment.json").write_text(json.dumps({
        "name": name, "accepted": 2, "attempts": 3, "complete": False,
    }), encoding="utf-8")
    (result / "inputs" / "campaign.yml").write_text(
        f"schema: 1\nname: {name}\n", encoding="utf-8",
    )
    (result / "samples" / "attempt-003" / "partial.pcap").write_bytes(
        b"preserved incomplete packet evidence",
    )

    def snapshot() -> dict[str, tuple[bytes, int, int, int]]:
        return {
            str(path.relative_to(result)): (
                path.read_bytes(), path.stat().st_mtime_ns,
                path.stat().st_mode, path.stat().st_ino,
            )
            for path in result.rglob("*") if path.is_file()
        }

    original = snapshot()
    rejected = subprocess.run(
        [str(launcher), "resume", str(result)], cwd=project,
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert rejected.returncode == 2, rejected.stderr
    assert "direct rapid capture resume is disabled" in rejected.stderr
    assert "retain the original result root unchanged" in rejected.stderr
    assert str(result) in rejected.stderr
    assert "successor lane through the bound rapid adapter" in rejected.stderr
    assert not sentinel.exists()
    assert snapshot() == original


def test_rapid_capture_reuses_etf_router_and_deep_preflight() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    assert 'if (( rapid_capture )); then\n  study_capture_scheduler_contract=' in source
    assert 'if (( rapid_capture )); then\n  container+=(--env "QCSD_STUDY_NETWORK_CONDITION=' in source
    assert '"${class_study_action}" == "resume" ) ]] ||\n   (( rapid_capture )); then' in source
    assert '"${rapid_capture_args[@]}"' in source
    assert "validate_resume_fingerprints(" in source
    assert "validate_frozen_experiment_contract(target, experiment)" in source
    assert "campaign.name != expected_name" in source
    assert "campaign.schema_version != 1" in source
    assert "rapid v4 formal profile differs from the frozen receipt" in source
    assert "rapid v4 formal lane differs from the frozen five-site plan" in source
    build_gate = source.split("if [[ ( \"${1:-}\" == \"run\" &&", 1)[1].split(
        "select_study_capture_cpus", 1
    )[0]
    assert "rapid_capture" not in build_gate


def test_rapid_dns_sink_preserves_exact_input_and_rejects_reuse(tmp_path: Path) -> None:
    source = LAUNCHER.read_text()
    block = source.split(
        "# A bound rapid launch persists the exact DNS input before starting capture.", 1
    )[1].split("\n  mapfile -t rapid_public_hosts", 1)[0]
    sink = tmp_path / "dns.json"
    payload = json.dumps({
        "schema_version": 1, "campaign": "rapid-example",
        "hosts": [["example.com", "1.1.1.1"]],
    })
    script = (
        "set -euo pipefail\n"
        f"QCSD_RAPID_DNS_RECEIPT_PATH={shlex.quote(str(sink))}\n"
        f"QCSD_DOCKER_OUTPUT_RAPID_DNS_PINS={shlex.quote(payload)}\n"
        "rapid_capture_name=rapid-example\n" + block
    )
    written = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert written.returncode == 0, written.stderr
    assert sink.read_bytes() == (payload + "\n").encode()
    rejected = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "FileExistsError" in rejected.stderr
    assert sink.read_bytes() == (payload + "\n").encode()

    for name, changed in (
        ("private", payload.replace("1.1.1.1", "127.0.0.1")),
        ("wrong-campaign", payload.replace("rapid-example", "another-campaign")),
        ("boolean-schema", payload.replace('"schema_version": 1', '"schema_version": true')),
    ):
        candidate_sink = tmp_path / f"{name}.json"
        candidate_script = script.replace(shlex.quote(str(sink)), shlex.quote(str(candidate_sink)))
        candidate_script = candidate_script.replace(shlex.quote(payload), shlex.quote(changed))
        failed = subprocess.run(["bash", "-c", candidate_script], capture_output=True, text=True)
        assert failed.returncode != 0
        assert not candidate_sink.exists()

    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path, target_is_directory=True)
    linked_script = script.replace(shlex.quote(str(sink)), shlex.quote(str(linked / "new.json")))
    failed = subprocess.run(["bash", "-c", linked_script], capture_output=True, text=True)
    assert failed.returncode != 0
    assert not (tmp_path / "new.json").exists()


def test_v4_formal_selector_is_narrower_than_historical_diagnostics(tmp_path: Path) -> None:
    campaigns = tmp_path / "artifacts"
    campaigns.mkdir()
    formal_name = "rapid-curated-tranco50-v4-formal-b01-s01-undefended-1200"
    formal = campaigns / f"{formal_name}.yml"
    formal.write_text(f"schema: 1\nname: {formal_name}\npurpose: evaluation\n")
    selected = _select(tmp_path, "run", formal)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines()[:2] == ["1", formal_name]

    for generation in ("g02", "g99"):
        successor_name = f"{formal_name}-{generation}"
        successor = campaigns / f"{successor_name}.yml"
        successor.write_text(f"schema: 1\nname: {successor_name}\npurpose: evaluation\n")
        selected = _select(tmp_path, "run", successor)
        assert selected.returncode == 0, selected.stderr
        assert selected.stdout.splitlines()[:2] == ["1", successor_name]

    for invalid_name in (
        "rapid-curated-tranco50-v2-formal-b01-s01-undefended-1200",
        "rapid-curated-tranco50-v4-formal-b17-s01-undefended-1200",
        "rapid-curated-tranco50-v4-formal-b01-s11-undefended-1200",
        f"{formal_name}-g01",
        f"{formal_name}-g100",
        f"{formal_name}-g2",
    ):
        invalid = campaigns / f"{invalid_name}.yml"
        invalid.write_text(f"schema: 1\nname: {invalid_name}\n")
        rejected = _select(tmp_path, "run", invalid)
        assert rejected.returncode == 0, rejected.stderr
        assert rejected.stdout.splitlines()[0] == "0"


def test_v5_formal_selector_keeps_its_own_name_and_resume_root(tmp_path: Path) -> None:
    campaigns = tmp_path / "artifacts"
    campaigns.mkdir()
    name = "rapid-curated-tranco50-v5-formal-b16-s10-cs-buflo-1200"
    campaign = campaigns / f"{name}.yml"
    campaign.write_text(f"schema: 1\nname: {name}\npurpose: evaluation\n")
    selected = _select(tmp_path, "run", campaign)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines() == [
        "1", name, f"/lab/artifacts/{name}.yml", "run", f"/lab/artifacts/{name}.yml",
    ]
    successor = campaigns / f"{name}-g02.yml"
    successor.write_text(f"schema: 1\nname: {name}-g02\npurpose: evaluation\n")
    assert _select(tmp_path, "run", successor).stdout.splitlines()[:2] == [
        "1", f"{name}-g02",
    ]
    result = tmp_path / "results" / name / "run-001"
    (result / "inputs").mkdir(parents=True)
    (result / "experiment.json").write_text(json.dumps({"name": name}))
    (result / "inputs" / "campaign.yml").write_text(f"schema: 1\nname: {name}\n")
    resumed = _select(tmp_path, "resume", result)
    assert resumed.returncode == 0, resumed.stderr
    assert resumed.stdout.splitlines()[:3] == ["1", name, f"/lab/results/{name}/run-001"]
    for invalid_name in (
        name.replace("-b16-", "-b17-"),
        name.replace("-s10-", "-s11-"),
        f"{name}-g01",
        name.replace("-v5-", "-v6-"),
    ):
        invalid = campaigns / f"{invalid_name}.yml"
        invalid.write_text(f"schema: 1\nname: {invalid_name}\n")
        assert _select(tmp_path, "run", invalid).stdout.splitlines()[0] == "0"


def test_v5_formal_preflight_uses_only_the_v5_frozen_profile() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    assert "QCSD_RAPID_V5_PROFILE_PATH" in source
    assert "crux73-tranco600-rapid-v5.profile.json" in source
    assert "f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60" in source
    assert '"${rapid_capture_role}" "${rapid_capture_mode}" "${rapid_capture_version}"' in source
    assert "rapid formal lane has another study version" in source
    assert "rapid v5 formal lane differs from the frozen five-site plan" in source
    assert "rapid v5 formal lane needs one named qualification manifest" in source


@pytest.mark.parametrize("generation", ["", "-g02"])
def test_epoch_selector_requires_explicit_authority_and_disables_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generation: str,
) -> None:
    name = f"rapid-curated-tranco50-v5-formal-b01-s01-front-1200{generation}-e0001"
    campaign = tmp_path / f"{name}.yml"
    campaign.write_text(f"schema: 1\nname: {name}\npurpose: evaluation\n")
    monkeypatch.delenv("QCSD_RAPID_EPOCH_LAUNCH_INPUT", raising=False)
    absent = _select(tmp_path, "run", campaign, include_binding=True)
    assert absent.returncode == 1
    assert "explicit hash-bound block launch authority" in absent.stderr
    # Routing itself does not trust this value: a second, actual image check
    # independently reopens the hash-bound intent before capture topology.
    monkeypatch.setenv("QCSD_RAPID_EPOCH_LAUNCH_INPUT", "routing fixture only")
    selected = _select(tmp_path, "run", campaign, include_binding=True)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines()[:2] == ["1", name]
    assert selected.stdout.splitlines()[-3:] == ["formal", "front", "v5"]
    result = tmp_path / "results" / name / "run-001"
    (result / "inputs").mkdir(parents=True)
    (result / "experiment.json").write_text(json.dumps({"name": name}))
    (result / "inputs/campaign.yml").write_bytes(campaign.read_bytes())
    resumed = _select(tmp_path, "resume", result)
    assert resumed.returncode == 2
    assert "generic resume is disabled" in resumed.stderr


def test_epoch_image_preflight_reopens_authority_before_public_dns() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    preflight = source.split('if (( rapid_capture_epoch )); then', 1)[1].split(
        "# Docker's isolated client bridge", 1)[0]
    assert 'org.qcsd.role=rapid-epoch-preflight' in preflight
    assert 'validate_host_epoch_launch(json.loads(sys.argv[1])' in preflight
    assert '--network none --read-only' in preflight
    assert 'PYTHONPATH=${rapid_epoch_module_host}/src' in preflight
    assert '${rapid_epoch_mount_root}:${rapid_epoch_mount_root}:ro' in preflight
    assert 'actual_image=sys.argv[3]' in preflight


def _shakedown_sites() -> tuple[Site, ...]:
    return tuple(Site(
        candidate_id=f"site-{index:02d}", workload_id=f"workload-{index:02d}",
        workload_sha256=f"{index + 1:064x}", primary_origin=f"https://site{index}.example",
        qualification_set=f"rapid-v5-shard-{index // 5 + 1:02d}",
        qualification_set_manifest_sha256=f"{index // 5 + 1:064x}",
    ) for index in range(10))


def test_v5_planned_shakedown_grid_routes_as_zero_credit_diagnostics(tmp_path: Path) -> None:
    sites = _shakedown_sites()
    lanes = plan_lanes(sites, final=False, study_version=5)
    assert len(lanes) == 10
    assert sum(lane.sample_count for lane in lanes) == 50
    campaigns = tmp_path / "config/campaigns"
    campaigns.mkdir(parents=True)
    for lane in lanes:
        campaign = campaigns / f"{lane.campaign_name}.yml"
        campaign.write_bytes(render_lane_campaign(lane, sites))
        selected = _select(tmp_path, "run", campaign, include_binding=True)
        assert selected.returncode == 0, selected.stderr
        assert selected.stdout.splitlines()[-3:] == ["diagnostic", lane.mode, "v5"]
        assert selected.stdout.splitlines()[:2] == ["1", lane.campaign_name]
        document = yaml.safe_load(campaign.read_bytes())
        assert document["purpose"] == "smoke"
        assert sum(document["workloads"].values()) == 5


def test_v5_shakedown_resume_and_successor_keep_diagnostic_binding(tmp_path: Path) -> None:
    name = "rapid-curated-tranco50-v5-diagnostic-b01-s02-cs-buflo-1200-g02"
    result = tmp_path / "results" / name / "run-001"
    (result / "inputs").mkdir(parents=True)
    (result / "experiment.json").write_text(json.dumps({"name": name}))
    (result / "inputs/campaign.yml").write_text(f"schema: 1\nname: {name}\n")
    selected = _select(tmp_path, "resume", result, include_binding=True)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines()[-3:] == ["diagnostic", "cs-buflo", "v5"]
    assert selected.stdout.splitlines()[:3] == ["1", name, f"/lab/results/{name}/run-001"]


@pytest.mark.parametrize("name", [
    "rapid-curated-tranco50-v5-diagnostic-anything",
    "rapid-curated-tranco50-v5-diagnostic-front-flight-1-001",
    "rapid-curated-tranco50-v5-diagnostic-b02-s01-front-1200",
    "rapid-curated-tranco50-v5-diagnostic-b01-s03-front-1200",
    "rapid-curated-tranco50-v5-diagnostic-b01-s01-wtfpad-1200",
    "rapid-curated-tranco50-v5-diagnostic-b01-s01-front-1200-g01",
    "rapid-curated-tranco50-v5-diagnostic-b01-s01-front-1200-g100",
])
def test_v5_arbitrary_diagnostics_get_no_rapid_route(tmp_path: Path, name: str) -> None:
    campaign = tmp_path / f"{name}.yml"
    campaign.write_text(f"schema: 1\nname: {name}\npurpose: smoke\n")
    selected = _select(tmp_path, "run", campaign)
    assert selected.returncode == 0, selected.stderr
    assert selected.stdout.splitlines()[0] == "0"


def _embedded_preflight() -> str:
    source = LAUNCHER.read_text(encoding="utf-8")
    block = source.split('--label "org.qcsd.role=rapid-capture-preflight"', 1)[1]
    return block.split(" -I -c '\n", 1)[1].split("\n' \"${1}\"", 1)[0]


def _preflight_campaign(lane, sites) -> SimpleNamespace:
    document = yaml.safe_load(render_lane_campaign(lane, sites))
    return SimpleNamespace(
        name=document["name"], schema_version=document["schema"],
        purpose=document["purpose"], profile=document["profile"],
        request_policies=tuple(document["request_policies"]),
        workloads=tuple(SimpleNamespace(
            id=workload_id, visits=visits,
            qualification_set_manifest_sha256=("a" * 64 if lane.mode != "undefended" else None),
        ) for workload_id, visits in document["workloads"].items()),
        defenses=tuple(SimpleNamespace(name=lane.mode) for _ in document["defenses"]),
        chaff_qualification_set=document.get("chaff_qualification_set"),
    )


def _run_preflight(monkeypatch: pytest.MonkeyPatch, campaign, mode: str) -> None:
    monkeypatch.setattr(orchestrator, "load_campaign", lambda _: campaign)
    monkeypatch.setattr(sys, "argv", [
        "preflight", "run", "/unused.yml", campaign.name, "diagnostic", mode, "v5",
    ])
    exec(compile(_embedded_preflight(), str(LAUNCHER), "exec"), {})


def test_v5_planned_grid_passes_installed_runtime_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    sites = _shakedown_sites()
    for lane in plan_lanes(sites, final=False, study_version=5):
        _run_preflight(monkeypatch, _preflight_campaign(lane, sites), lane.mode)


@pytest.mark.parametrize("change", [
    "formal-purpose", "formal-visits", "wrong-mode", "wrong-count",
    "no-named-manifest", "mixed-manifests", "malformed-manifest", "no-qualification",
    "arbitrary-name",
])
def test_v5_shakedown_preflight_rejects_repurposed_campaigns(
    monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    sites = _shakedown_sites()
    lane = next(item for item in plan_lanes(sites, final=False, study_version=5)
                if item.mode == "front")
    campaign = _preflight_campaign(lane, sites)
    if change == "formal-purpose":
        campaign.purpose = "evaluation"
    elif change == "formal-visits":
        campaign.workloads[0].visits = 4
    elif change == "wrong-mode":
        campaign.defenses[0].name = "tamaraw"
    elif change == "wrong-count":
        campaign.workloads = campaign.workloads[:4]
    elif change == "no-named-manifest":
        campaign.workloads[0].qualification_set_manifest_sha256 = None
    elif change == "mixed-manifests":
        campaign.workloads[0].qualification_set_manifest_sha256 = "b" * 64
    elif change == "malformed-manifest":
        for workload in campaign.workloads:
            workload.qualification_set_manifest_sha256 = "invalid"
    elif change == "no-qualification":
        campaign.chaff_qualification_set = None
    else:
        campaign.name = "rapid-curated-tranco50-v5-diagnostic-anything"
    with pytest.raises(SystemExit, match="rapid v5 diagnostic"):
        _run_preflight(monkeypatch, campaign, lane.mode)


def test_v5_shakedown_checks_frozen_profile_bytes_before_capture(tmp_path: Path) -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    body = source.split('elif [[ "${rapid_capture_version}" == "v5" ]]; then\n', 1)[1]
    body = body.split("\n  fi", 1)[0]
    profile = tmp_path / "profile.json"
    original = LAUNCHER.parent / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
    profile.write_bytes(original.read_bytes())
    script = (
        "set -euo pipefail\n"
        f"ROOT={shlex.quote(str(tmp_path))}\n"
        f"QCSD_RAPID_V5_PROFILE_PATH={shlex.quote(str(profile))}\n"
        + body
    )
    valid = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert valid.returncode == 0, valid.stderr
    profile.write_bytes(profile.read_bytes() + b"\n")
    changed = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert changed.returncode != 0
    assert "profile differs from the frozen receipt" in changed.stderr


def test_launcher_shell_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(LAUNCHER)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
