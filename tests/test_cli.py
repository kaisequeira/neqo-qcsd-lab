from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import qcsd_lab.cli as cli
from qcsd_lab.orchestrator import CampaignIncomplete
from qcsd_lab.util import atomic_text, sha256_file


def _embedded_python(launcher: str, function: str) -> str:
    body = launcher.split(f"{function}() {{", 1)[1]
    return body.split("python3 -c '\n", 1)[1].split('\n\' "$1"', 1)[0]


def _run_embedded_python(
    tmp_path: Path,
    code: str,
    before: dict,
    after: dict,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-c", code, str(before_path), str(after_path), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_internal_cli_contains_only_container_workflow_boundaries():
    choices = set(cli.parser()._subparsers._group_actions[0].choices)
    assert choices == {
        "prepare",
        "derive-chaff-prefix-specs",
        "qualify-chaff",
        "run",
        "resume",
        "verify",
        "analyze",
        "fit",
        "test",
    }


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
    assert (
        "{build|prepare|derive-chaff-prefix-specs|qualify-chaff|run|resume|verify|analyze|fit|test}"
        in launcher
    )
    assert 'run|resume|verify|analyze|fit|test) image="${COLLECTION_IMAGE}"' in launcher
    assert launcher.count("start_capture_acceptance_server") == 3
    assert "ethtool -K eth0 gro off gso off tso off tx-udp-segmentation off" in launcher
    assert "--cap-drop ALL" in launcher
    assert 'network_mode="none"' in launcher
    assert '--network "${network_mode}"' in launcher
    assert "verify_fit_neqo_checkout" in launcher
    assert 'git -C "${ROOT}" rev-parse HEAD:neqo-qcsd' in launcher
    assert 'git -C "${ROOT}" ls-files --stage -- neqo-qcsd' in launcher
    assert 'git -C "${ROOT}/neqo-qcsd" status --porcelain --untracked-files=all' in launcher
    assert 'if [[ "${1:-}" == "fit" ]]' in launcher
    fit_preflight = launcher.split("verify_fit_neqo_checkout() {", 1)[1].split("\n}", 1)[0]
    assert 'v["neqo_dirty"]' in fit_preflight
    assert 'v["neqo_patch_sha256"]' in fit_preflight
    assert 'git -C "${ROOT}" status' not in fit_preflight
    assert 'git -C "${ROOT}/neqo-qcsd" status' in fit_preflight
    assert '"${head_gitlink}" != "${image_neqo}"' in fit_preflight
    assert '"${index_gitlink}" != "${image_neqo}"' in fit_preflight
    assert '"${image_neqo_dirty}" != "false"' in fit_preflight
    for removed in ("discover", "probe", "collect", "dataset", "--dev", "--dry-run"):
        token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(token, launcher) is None


def test_launcher_grants_results_write_access_only_to_result_writers():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    mount = '--volume "${ROOT}/results:/lab/results:rw"'
    assert launcher.count(mount) == 1
    results_gate = launcher.split(
        'if [[ "${1:-}" == "run" || "${1:-}" == "resume" || "${1:-}" == "analyze" ]]',
        1,
    )[1].split("\nfi", 1)[0]
    assert mount in results_gate
    base_container = launcher.split("container=(", 1)[1].split("\n)", 1)[0]
    assert mount not in base_container


def test_launcher_never_creates_qualification_evidence_and_mounts_least_privilege():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert 'mkdir -p "${ROOT}/config/chaff-prefix-specs"' not in launcher
    assert 'mkdir -p "${ROOT}/config/chaff-qualification-store"' not in launcher
    assert 'if [[ "${1:-}" == "qualify-chaff" ]]' in launcher
    assert '"${ROOT}/config/chaff-prefix-specs"' in launcher
    assert '"${ROOT}/config/chaff-qualification-store"' in launcher
    assert '[[ ! -d "${required_directory}" || -L "${required_directory}" ]]' in launcher
    qualification_mounts = launcher.rsplit('if [[ "${1:-}" == "qualify-chaff" ]]; then', 1)[
        -1
    ].split("\nfi", 1)[0]
    assert '--volume "${ROOT}/config/workloads:/lab/config/workloads:ro"' in qualification_mounts
    assert (
        '--volume "${ROOT}/config/chaff-prefix-specs:/lab/config/chaff-prefix-specs:ro"'
        in qualification_mounts
    )
    assert (
        '--volume "${ROOT}/config/chaff-qualification-store:'
        '/lab/config/chaff-qualification-store:rw"' in qualification_mounts
    )


def test_launcher_audits_the_exact_prefix_derivation_config_delta():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert 'guarded_root="${ROOT}/config"' in launcher
    assert '[[ ! -d "${guarded_root}" || -L "${guarded_root}" ]]' in launcher
    assert launcher.index('[[ ! -d "${guarded_root}" || -L "${guarded_root}" ]]') < (
        launcher.index('mkdir -p "${ROOT}/results"')
    )
    common_mkdir = 'mkdir -p "${ROOT}/results" "${ROOT}/artifacts" "${ROOT}/config/workloads"'
    assert launcher.count(common_mkdir) == 1
    assert f"else\n  {common_mkdir}\nfi" in launcher
    assert '[[ -e "${ROOT}/config/chaff-prefix-specs"' in launcher
    assert "snapshot_regular_tree" in launcher
    assert "validate_prefix_derivation_delta" in launcher
    assert 'snapshot_regular_tree "${ROOT}/config"' in launcher
    assert "changed a pre-existing config input" in launcher
    assert "changed files outside the exact-six output" in launcher
    assert "output type is invalid" in launcher
    assert 'raise SystemExit(f"{label} rejects symlink: {relative}")' in launcher
    assert 'raise SystemExit(f"{label} rejects special entry: {relative}")' in launcher
    for workload_id in (
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    ):
        assert workload_id in launcher


def test_launcher_protects_preexisting_artifacts_during_fit_and_audits_delta():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    fit_mount = launcher.split('container+=(--volume "${ROOT}/artifacts:/lab/artifacts:rw")', 1)[
        1
    ].split("\nfi", 1)[0]
    fit_mount = 'container+=(--volume "${ROOT}/artifacts:/lab/artifacts:rw")' + fit_mount
    assert '--volume "${ROOT}/artifacts:/lab/artifacts:rw"' in fit_mount
    assert '--volume "${artifact_child}:/lab/artifacts/${artifact_name}:ro"' in fit_mount
    assert '[[ ! "${artifact_name}" =~ ^[A-Za-z0-9._-]+$ ]]' in fit_mount
    assert 'find "${ROOT}/artifacts" -mindepth 1 -maxdepth 1 -print0' in fit_mount
    assert "snapshot_regular_tree" in launcher
    assert "validate_fit_artifact_delta" in launcher
    assert "fit changed a pre-existing artifact" in launcher
    assert "fit changed files outside the exact four-file bundle" in launcher
    assert "idempotent fit changed the pre-existing artifact tree" in launcher
    assert "fit_canonical_preexisting=1" in launcher
    for filename in (
        "provenance.json",
        "traffic-morphing.json",
        "walkie-talkie.json",
        "wtf-pad.json",
    ):
        assert f'"research-1200/{filename}": "file"' in launcher


def test_fit_artifact_delta_validator_executes_all_publication_states(tmp_path):
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_fit_artifact_delta")
    existing = {"README.md": {"type": "file", "sha256": "a" * 64}}
    bundle = {
        "research-1200": {"type": "directory"},
        "research-1200/provenance.json": {"type": "file", "sha256": "b" * 64},
        "research-1200/traffic-morphing.json": {
            "type": "file",
            "sha256": "c" * 64,
        },
        "research-1200/walkie-talkie.json": {
            "type": "file",
            "sha256": "d" * 64,
        },
        "research-1200/wtf-pad.json": {"type": "file", "sha256": "e" * 64},
    }

    created = _run_embedded_python(tmp_path, validator, existing, existing | bundle, "0", "0")
    assert created.returncode == 0, created.stderr

    failed_without_delta = _run_embedded_python(tmp_path, validator, existing, existing, "0", "7")
    assert failed_without_delta.returncode == 0, failed_without_delta.stderr

    preexisting = existing | bundle
    idempotent = _run_embedded_python(tmp_path, validator, preexisting, preexisting, "1", "0")
    assert idempotent.returncode == 0, idempotent.stderr

    unauthorized = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | bundle | {"unexpected": {"type": "directory"}},
        "0",
        "0",
    )
    assert unauthorized.returncode != 0
    assert "outside the exact four-file bundle" in unauthorized.stderr

    failed_with_delta = _run_embedded_python(
        tmp_path, validator, existing, existing | bundle, "0", "7"
    )
    assert failed_with_delta.returncode != 0
    assert "failed fit changed the artifact tree" in failed_with_delta.stderr


def test_collection_image_builds_offline_validator_with_exact_neqo_commit():
    root = Path(__file__).parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --from=source-metadata /source-metadata.json" in dockerfile
    assert 'test "${#neqo_commit}" -eq 40' in dockerfile
    assert 'NEQO_QCSD_GIT_COMMIT="${neqo_commit}" cargo build --locked --release' in dockerfile
    assert "--bin qcsd-validate-parameters" in dockerfile
    assert "target/release/qcsd-validate-parameters /out/bin/" in dockerfile
    # A persistent target cache can reuse a feature-specific dependency artifact
    # after its source changes, producing two binaries from different revisions.
    assert "qcsd-cargo-target" not in dockerfile
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
