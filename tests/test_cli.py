from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import qcsd_lab.cli as cli
from qcsd_lab.orchestrator import CampaignIncomplete
from qcsd_lab.util import atomic_text, sha256_file


def test_internal_cli_contains_only_container_workflow_boundaries():
    choices = set(cli.parser()._subparsers._group_actions[0].choices)
    assert choices == {"prepare", "run", "resume", "verify", "analyze", "fit", "test"}


@pytest.mark.parametrize(
    "removed",
    [
        "discover",
        "probe",
        "collect",
        "dataset",
        "doctor",
        "plot",
        "report",
    ],
)
def test_removed_or_deferred_commands_are_rejected(removed):
    with pytest.raises(SystemExit) as exit_status:
        cli.parser().parse_args([removed])
    assert exit_status.value.code == 2


def test_run_resume_and_verify_have_no_mode_flags():
    command_parsers = cli.parser()._subparsers._group_actions[0].choices
    assert {action.dest for action in command_parsers["run"]._actions} == {
        "help",
        "campaign",
    }
    assert {action.dest for action in command_parsers["resume"]._actions} == {
        "help",
        "result",
    }
    assert {action.dest for action in command_parsers["verify"]._actions} == {
        "help",
        "target",
    }


def test_launcher_routes_only_consolidated_public_commands():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert "{build|prepare|run|resume|verify|analyze|fit|test}" in launcher
    assert 'run|resume|verify|analyze|fit|test) image="${COLLECTION_IMAGE}"' in launcher
    assert launcher.count("start_capture_acceptance_server") == 3
    assert "ethtool -K eth0 gro off gso off tso off tx-udp-segmentation off" in launcher
    assert "--cap-drop ALL" in launcher
    assert 'network_mode="none"' in launcher
    assert '--network "${network_mode}"' in launcher
    for removed in ("discover", "probe", "collect", "dataset", "--dev", "--dry-run"):
        token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(token, launcher) is None


def test_collection_image_builds_offline_validator_with_exact_neqo_commit():
    root = Path(__file__).parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --from=source-metadata /source-metadata.json" in dockerfile
    assert 'test "${#neqo_commit}" -eq 40' in dockerfile
    assert 'NEQO_QCSD_GIT_COMMIT="${neqo_commit}" cargo build --locked --release' in dockerfile
    assert "--bin qcsd-validate-parameters" in dockerfile
    assert "target/release/qcsd-validate-parameters /out/bin/" in dockerfile
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    assert "artifacts/*" in dockerignore


def test_incomplete_run_exits_cleanly_with_one_result_path(monkeypatch, capsys):
    root = Path("/lab/results/campaign/20260719T061311Z")

    def incomplete(_campaign, _results):
        raise CampaignIncomplete(root)

    monkeypatch.setattr(cli, "run_campaign", incomplete)
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["run", "campaign.yml"])
    assert exit_status.value.code == 1
    captured = capsys.readouterr()
    assert captured.err == f"campaign incomplete; evidence retained at {root}\n"
    assert captured.out == f"{root}\n"


def test_verify_routes_yaml_to_preflight(monkeypatch, capsys, tmp_path):
    campaign = tmp_path / "campaign.yml"
    campaign.write_text("schema: 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "preflight_campaign", lambda path: {"valid": path == campaign})

    cli.main(["verify", str(campaign)])

    assert json.loads(capsys.readouterr().out) == {"valid": True}


def test_verify_reports_partial_artifact_bundle_as_a_bundle_error(capsys, tmp_path):
    partial = tmp_path / "research-1200"
    partial.mkdir()
    atomic_text(partial / "traffic-morphing.json", "{}\n")

    with pytest.raises(SystemExit) as exit_status:
        cli.main(["verify", str(partial)])

    assert exit_status.value.code == 1
    assert "artifact bundle file set mismatch" in capsys.readouterr().err


def test_verify_routes_missing_fixed_artifact_path_to_bundle_verification(capsys, tmp_path):
    missing = tmp_path / "research-1200"
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["verify", str(missing)])
    assert exit_status.value.code == 1
    assert "artifact bundle is not a regular directory" in capsys.readouterr().err


def test_fit_prints_bundle_root_and_receipt_sha256(monkeypatch, capsys, tmp_path):
    import qcsd_lab.fitting as fitting

    bundle = tmp_path / "artifacts/research-1200"
    bundle.mkdir(parents=True)
    atomic_text(bundle / "provenance.json", "sealed receipt\n")
    monkeypatch.setattr(fitting, "fit_result", lambda _result, artifacts_root: bundle)

    cli.main(["fit", str(tmp_path / "result")])

    assert json.loads(capsys.readouterr().out) == {
        "root": str(bundle),
        "provenance_sha256": sha256_file(bundle / "provenance.json"),
    }


def test_test_live_sets_acceptance_environment(monkeypatch):
    observed = {}

    def run(command, *, cwd, env, check):
        observed.update(command=command, cwd=cwd, env=env, check=check)
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr(cli.subprocess, "run", run)
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["test", "live"])
    assert exit_status.value.code == 0
    assert observed["env"]["QCSD_RUN_CAPTURE_ACCEPTANCE"] == "1"
    assert observed["command"][-3:] == ["pytest", "-p", "no:cacheprovider"]
