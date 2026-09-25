from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import os
import re
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.cli as cli
from qcsd_lab.class_acquisition import (
    CHECKPOINT_SCHEMA_VERSION as CLASS_ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
    COMPLETION_SCHEMA_VERSION as CLASS_ACQUISITION_COMPLETION_SCHEMA_VERSION,
    SCHEMA_VERSION as CLASS_ACQUISITION_SCHEMA_VERSION,
)
from qcsd_lab.orchestrator import CampaignIncomplete
from qcsd_lab.util import atomic_text, sha256_file


def _embedded_python(launcher: str, function: str) -> str:
    body = launcher.split(f"{function}() {{", 1)[1]
    return body.split("python3 -I -c '\n", 1)[1].split('\n\' "$1"', 1)[0]


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
        "qualify-response-chaff",
        "run",
        "resume",
        "verify",
        "analyze",
        "fit",
        "buflo-study",
        "class-study",
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
    response = command_parsers["qualify-response-chaff"]
    workload_ids = next(action for action in response._actions if action.dest == "workload_ids")
    assert workload_ids.nargs == 5
    qualification_set = next(
        action for action in response._actions if action.dest == "qualification_set"
    )
    assert qualification_set.option_strings == ["--set"]


def test_prepare_complete_coverage_is_explicit_and_opt_in():
    legacy = cli.parser().parse_args(
        ["prepare", "example", "https://page.test/", "https://page.test"]
    )
    strict = cli.parser().parse_args(
        [
            "prepare",
            "example-r2",
            "https://page.test/",
            "https://page.test",
            "https://cdn.test",
            "--require-complete-coverage",
        ]
    )

    assert legacy.require_complete_coverage is False
    assert strict.require_complete_coverage is True
    assert strict.approved_origins == ["https://page.test", "https://cdn.test"]


def test_buflo_cohort_version_is_positive_unique_and_defaults_to_one():
    assert cli.parser().parse_args(["buflo-study", "reference"]).cohort_version == 1
    assert (
        cli.parser().parse_args(["buflo-study", "reference", "--cohort-version=2"]).cohort_version
        == 2
    )
    for arguments in (
        ["buflo-study", "reference", "--cohort-version", "0"],
        ["buflo-study", "reference", "--cohort-version=-1"],
        ["buflo-study", "reference", "--cohort-version", "01"],
        [
            "buflo-study",
            "reference",
            "--cohort-version",
            "2",
            "--cohort-version=3",
        ],
    ):
        with pytest.raises(SystemExit) as exit_status:
            cli.parser().parse_args(arguments)
        assert exit_status.value.code == 2


def test_class_acquisition_batch_size_defaults_to_two_and_is_bounded() -> None:
    parser = cli.parser()
    assert parser.parse_args(["class-study", "acquisition-run"]).acquisition_max_candidates == 2
    assert (
        parser.parse_args(
            ["class-study", "acquisition-run", "--acquisition-max-candidates", "1"]
        ).acquisition_max_candidates
        == 1
    )
    for value in ("0", "3"):
        with pytest.raises(SystemExit) as exit_status:
            parser.parse_args(
                ["class-study", "acquisition-run", "--acquisition-max-candidates", value]
            )
        assert exit_status.value.code == 2


def test_class_foundation_cli_forwards_pinned_cdp_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    pinned = tmp_path / "pinned-cdp-execution-v23.json"
    browser_egress = tmp_path / "browser-egress-qualification-v23"
    observed: dict[str, object] = {}

    def run(action: str, **kwargs: object) -> SimpleNamespace:
        observed.update(action=action, **kwargs)
        return SimpleNamespace(
            status="complete",
            as_dict=lambda: {"action": action, "status": "complete"},
        )

    monkeypatch.setattr(pipeline, "run_class_study_action", run)

    cli.main(
        [
            "class-study",
            "foundation",
            "--pinned-cdp-receipt",
            str(pinned),
            "--browser-egress-qualification-root",
            str(browser_egress),
        ]
    )

    assert observed["action"] == "foundation"
    assert observed["pinned_cdp_receipt"] == pinned.absolute()
    assert observed["browser_egress_qualification_root"] == browser_egress.absolute()
    capsys.readouterr()


def test_class_status_cli_preserves_pilot_and_authoritative_fitting_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    observed: dict[str, object] = {}

    def run(action: str, **kwargs: object) -> SimpleNamespace:
        observed.update(action=action, **kwargs)
        return SimpleNamespace(
            status="complete",
            as_dict=lambda: {"action": action, "status": "complete"},
        )

    monkeypatch.setattr(pipeline, "run_class_study_action", run)
    artifacts = {
        "numeric": tuple(tmp_path / f"numeric-{stage}" for stage in ("pilot", "authoritative")),
        "prefix": tuple(tmp_path / f"prefix-{stage}" for stage in ("pilot", "authoritative")),
        "qualification": tuple(
            tmp_path / f"qualification-{stage}.json" for stage in ("pilot", "authoritative")
        ),
        "final": tuple(tmp_path / f"final-{stage}" for stage in ("pilot", "authoritative")),
    }
    arguments = ["class-study", "status"]
    for option, key in (
        ("--numeric-bundle", "numeric"),
        ("--prefix-spec-root", "prefix"),
        ("--qualification-manifest", "qualification"),
        ("--final-bundle", "final"),
    ):
        for path in artifacts[key]:
            arguments.extend((option, str(path)))

    cli.main(arguments)

    assert observed["action"] == "status"
    assert observed["numeric_bundle_roots"] == tuple(
        path.absolute() for path in artifacts["numeric"]
    )
    assert observed["prefix_spec_roots"] == tuple(path.absolute() for path in artifacts["prefix"])
    assert observed["qualification_manifests"] == tuple(
        path.absolute() for path in artifacts["qualification"]
    )
    assert observed["final_bundle_roots"] == tuple(path.absolute() for path in artifacts["final"])
    assert observed["numeric_bundle_root"] is None
    assert observed["prefix_spec_root"] is None
    assert observed["qualification_manifest"] is None
    assert observed["final_bundle_root"] is None
    capsys.readouterr()


def test_class_non_status_cli_rejects_repeated_singular_fitting_artifact(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as captured:
        cli.main(
            [
                "class-study",
                "prefix-specs",
                "--numeric-bundle",
                str(tmp_path / "one"),
                "--numeric-bundle",
                str(tmp_path / "two"),
            ]
        )

    assert captured.value.code == 1
    assert "accepts --numeric-bundle at most once" in capsys.readouterr().err


@pytest.mark.parametrize("action", ("prefix-specs", "qualify-prefix", "verify"))
def test_class_fitting_consumers_forward_explicit_capture_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    action: str,
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    source = tmp_path / "fitting-result"
    observed: dict[str, object] = {}

    def run(selected_action: str, **kwargs: object) -> SimpleNamespace:
        observed.update(action=selected_action, **kwargs)
        return SimpleNamespace(
            status="complete",
            as_dict=lambda: {"action": selected_action, "status": "complete"},
        )

    monkeypatch.setattr(pipeline, "run_class_study_action", run)
    arguments = [
        "class-study",
        action,
        "--stage",
        "pilot",
        "--capture-result",
        str(source),
    ]
    if action == "verify":
        arguments.extend(("--target", str(tmp_path / "numeric")))
    cli.main(arguments)

    assert observed["action"] == action
    assert observed["stage"] == "pilot"
    assert observed["capture_result"] == source.absolute()
    capsys.readouterr()


def test_launcher_routes_only_consolidated_public_commands():
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    assert (
        "{lifecycle-recover|build|prepare|derive-chaff-prefix-specs|qualify-chaff|qualify-response-chaff|run|resume|verify|analyze|fit|buflo-study|class-study|etf-probe|etf-veth-probe|test}"
        in launcher
    )
    assert (
        "run|resume|verify|analyze|fit|buflo-study|class-study|test) "
        'image="${COLLECTION_IMAGE}"' in launcher
    )
    assert launcher.count("start_capture_acceptance_server") == 3
    assert "ethtool -K eth0 gro off gso off tso off tx-udp-segmentation off" in launcher
    assert "--cap-drop ALL" in launcher
    assert 'network_mode="none"' in launcher
    assert '--network "${network_mode}"' in launcher
    assert "verify_fit_neqo_checkout" in launcher
    acquisition_watch = launcher.split(
        'if [[ "${1:-}" == "class-study" && "${2:-}" == "acquisition-watch" ]]', 1
    )[1].split("\nfi", 1)[0]
    assert (
        'exec /usr/bin/python3 -I "${ROOT}/tools/class_acquisition_watch.py"' in acquisition_watch
    )
    assert ".venv/bin/python" not in acquisition_watch
    assert 'git -C "${ROOT}" rev-parse HEAD:neqo-qcsd' in launcher
    assert 'git -C "${ROOT}" ls-files --stage -- neqo-qcsd' in launcher
    assert 'git -C "${ROOT}/neqo-qcsd" status --porcelain --untracked-files=all' in launcher
    assert 'if [[ "${1:-}" == "fit" ]]' in launcher
    pinned_cdp = launcher.rsplit(
        'if [[ "${1:-}" == "test" && "${2:-}" == "pinned-cdp" ]]; then', 1
    )[-1].split("\nfi", 1)[0]
    assert 'image="${PREPARE_IMAGE}"' not in pinned_cdp
    assert "QCSD_PINNED_CDP_EXPECTED_UID=${qcsd_invoking_uid}" in pinned_cdp
    assert "QCSD_PINNED_CDP_EXPECTED_GID=${qcsd_invoking_gid}" in pinned_cdp
    assert "--entrypoint /usr/bin/tini" in pinned_cdp
    assert "/opt/qcsd-venv/bin/python3 -m qcsd_lab.pinned_cdp" in pinned_cdp
    assert "/usr/bin/timeout --signal=TERM --kill-after=10s 120s" in pinned_cdp
    assert '--build-execution-receipt "${pinned_cdp_build_container}"' in pinned_cdp
    assert '--destination "${pinned_cdp_destination_container}"' in pinned_cdp
    assert "pytest" not in pinned_cdp
    assert 'qcsd_run_attached_docker "${container[@]}"' in pinned_cdp


def _current_pilot_resume_fixture(
    root: Path,
    admitted: object,
    build: Path,
    foundation: Path,
    *,
    run_id: str,
) -> Path:
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    def publish(path: Path, receipt_type: str, payload: dict[str, object]) -> Path:
        path.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=receipt_type)))
        return path

    campaign_name = "classifier-multiorigin100-v1-pilot-fitting-1200"
    result = root / "results" / campaign_name / run_id
    inputs = result / "inputs"
    inputs.mkdir(parents=True)
    workload_ids = [f"class-{index:03d}" for index in range(120)]
    workloads = inputs / "workloads"
    workloads.mkdir()
    for workload_id in workload_ids:
        (workloads / f"{workload_id}.json").write_bytes(canonical_json_bytes({}))
    (inputs / "defense-parameters").mkdir()
    environment = inputs / "study-environment.json"
    environment.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": 3,
                "artifact_type": "qcsd-buflo-study-environment",
                "docker": {
                    "client_version": "fixture",
                    "server_version": "fixture",
                    "server_os": "linux",
                    "server_arch": "amd64",
                    "ncpu": 12,
                    "mem_total_bytes": 1,
                    "storage_driver": "fixture",
                },
                "collection_image": {"id": admitted.collection_image, "repo_digests": []},
                "build_inputs": {
                    "schema_version": 1,
                    "artifact_type": "qcsd-study-build-inputs",
                    "rust_base_image": "fixture",
                    "debian_base_image": "fixture",
                    "uv_lock_sha256": "0" * 64,
                    "cargo_lock_sha256": "0" * 64,
                },
                "build_execution": {
                    "receipt": json.loads(build.read_bytes()),
                    "sha256": admitted.receipt_sha256,
                    "completion_path": admitted.identity["completion_path"],
                    "completion_sha256": admitted.completion_sha256,
                    "completion_payload_sha256": admitted.completion_payload_sha256,
                    "completion": json.loads(admitted.completion_path.read_bytes()),
                },
                "clock_status": {
                    "relationship": "container-shares-host-kernel-realtime-clock",
                    "host": {},
                    "container": {},
                },
                "capture_scheduler": {},
            }
        )
    )
    (inputs / "source.json").write_bytes(canonical_json_bytes(admitted.source))
    (inputs / "class-study-foundation.json").write_bytes(foundation.read_bytes())
    cohort = publish(
        inputs / "class-study-cohort.json",
        "qcsd-class-study-cohort",
        {
            "artifact_type": "qcsd-class-study-cohort",
            "study_id": "classifier-multiorigin100-v1",
            "inventories": {"pilot": workload_ids, "final": workload_ids[:100]},
        },
    )
    cohort_envelope = json.loads(cohort.read_bytes())
    assembly = publish(
        inputs / "class-study-cohort-assembly.json",
        "qcsd-class-study-cohort-assembly",
        {
            "study_id": "classifier-multiorigin100-v1",
            "assembly_schema_version": 3,
            "eligibility_policy": {},
            "candidate_catalogue": {},
            "acquisition_completion": {"fixture_build": admitted.receipt_sha256},
            "final_selection": None,
            "stability_root": "stability",
            "workload_root": "workloads",
            "candidates": [],
            "eligible_count": 0,
            "selected_evidence_count": 0,
            "cohort": {
                "receipt_type": cohort_envelope["receipt_type"],
                "payload_sha256": cohort_envelope["payload_sha256"],
                "canonical_file_sha256": sha256_file(cohort),
            },
        },
    )
    campaign = inputs / "campaign.yml"
    campaign.write_text(
        "schema: 2\n"
        f"name: {campaign_name}\n"
        "evidence_role: pilot-fitting\n"
        "class_study_cohort: class-study-cohort.json\n"
        "class_study_cohort_assembly: class-study-cohort-assembly.json\n"
        "workloads:\n" + "".join(f"  {workload_id}: 2\n" for workload_id in workload_ids),
        encoding="utf-8",
    )
    cohort_sha256 = sha256_file(cohort)
    assembly_sha256 = sha256_file(assembly)
    launch_identity = {
        "study_id": "classifier-multiorigin100-v1",
        "campaign_name": campaign_name,
        "evidence_role": "pilot-fitting",
        "class_study_cohort_sha256": cohort_sha256,
        "class_study_cohort_assembly_sha256": assembly_sha256,
        "uniqueness_policy": "canonical-role-block-and-cohort-assembly-v1",
    }
    launch_key = hashlib.sha256(
        json.dumps(launch_identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    launch_payload = {
        "study_id": "classifier-multiorigin100-v1",
        "launch_key": launch_key,
        "campaign_name": campaign_name,
        "campaign_sha256": sha256_file(campaign),
        "evidence_role": "pilot-fitting",
        "class_study_cohort_sha256": cohort_sha256,
        "class_study_cohort_assembly_sha256": assembly_sha256,
        "result_root": f"/lab/results/{campaign_name}/{run_id}",
        "created_at": "2026-09-07T00:00:00+00:00",
        "source": admitted.source,
        "policy": "one-result-root-per-campaign-and-cohort-assembly",
    }
    launch = {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-first-launch-claim",
        "payload_sha256": hashlib.sha256(
            json.dumps(launch_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "payload": launch_payload,
    }
    launch_path = inputs / "class-study-launch.json"
    launch_path.write_bytes(canonical_json_bytes(launch))
    registry = root / "results/.classifier-multiorigin100-v1-launches"
    registry.mkdir(exist_ok=True)
    (registry / f"{launch_key}.json").write_bytes(launch_path.read_bytes())
    (result / "experiment.json").write_bytes(
        canonical_json_bytes(
            {
                "name": campaign_name,
                "purpose": "fitting",
                "status": "incomplete",
                "source": admitted.source,
                "configuration": {
                    "evidence_role": "pilot-fitting",
                    "profile": "research-1200",
                    "request_policies": ["as-defined", "half-duplex"],
                    "limits": {
                        "timeout_seconds": 120,
                        "max_response_bytes": 1_048_576,
                        "capture_seconds": 180,
                        "capture_megabytes": 64,
                        "max_attempts": 3,
                        "per_origin_cooldown_seconds": 30,
                        "settle_seconds": 1,
                    },
                    "sample_order": {
                        "scheme": "origin-aware-windowed",
                        "window_size": 16,
                    },
                    "public_origin_policy": {
                        "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
                        "required_value": "1",
                        "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
                    },
                    "defenses": [{"name": "undefended", "kind": "none", "baseline": True}],
                    "workloads": [
                        {
                            "id": workload_id,
                            "visits": 2,
                            "manifest": f"inputs/workloads/{workload_id}.json",
                            "sha256": sha256_file(workloads / f"{workload_id}.json"),
                            "resource_count": 0,
                            "origin_count": 1,
                        }
                        for workload_id in workload_ids
                    ],
                    "class_study_id": "classifier-multiorigin100-v1",
                    "study_environment_sha256": sha256_file(environment),
                    "campaign_sha256": sha256_file(campaign),
                    "class_study_foundation_sha256": sha256_file(
                        inputs / "class-study-foundation.json"
                    ),
                    "class_study_cohort_sha256": cohort_sha256,
                    "class_study_cohort_assembly_sha256": assembly_sha256,
                    "class_study_launch_sha256": sha256_file(launch_path),
                },
            }
        )
    )
    return result


def _class_build_admission_fixture(tmp_path: Path):
    from qcsd_lab.class_build_admission import BuildAdmission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes, canonical_json_sha256

    root = tmp_path / "lab"
    build = root / "artifacts/buflo-study/build-execution-v62.json"
    completion = root / "artifacts/buflo-study/build-completion-v62.json"
    build.parent.mkdir(parents=True)
    build.write_bytes(canonical_json_bytes({"cohort_version": 62}))
    completion.write_bytes(canonical_json_bytes({"schema_version": 1, "payload_sha256": "f" * 64}))
    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "a" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_commit": "b" * 40,
        "neqo_pinned_commit": "b" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
    }
    identity = {
        "cohort_version": 62,
        "sha256": sha256_file(build),
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v62.json",
        "completion_sha256": sha256_file(completion),
        "collection_image": source["image_digest"],
        "started_at": "2026-09-07T00:00:00+00:00",
        "finished_at": "2026-09-07T00:01:00+00:00",
    }
    admitted = BuildAdmission(
        receipt_path=build,
        receipt_sha256=sha256_file(build),
        cohort_version=62,
        collection_image=source["image_digest"],
        prepare_image="sha256:" + "2" * 64,
        reference_image="sha256:" + "3" * 64,
        completion_path=completion,
        completion_sha256=sha256_file(completion),
        completion_payload_sha256="f" * 64,
        source=source,
        identity=identity,
    )

    def publish(path: Path, receipt_type: str, payload: dict[str, object]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=receipt_type)))
        return path

    def binding(path: Path) -> dict[str, str]:
        return {"path": str(path), "sha256": sha256_file(path)}

    foundation = publish(
        root / "artifacts/classifier-multiorigin100-v1/class-study-foundation-v62.json",
        "qcsd-class-study-foundation-attestation",
        {
            "attestation_schema_version": 4,
            "artifact_type": "qcsd-class-study-foundation-attestation",
            "cohort_version": 62,
            "source": source,
            "build_execution_identity": identity,
            "evidence": {"build_execution": binding(build)},
        },
    )
    readiness = publish(
        root / "artifacts/classifier-multiorigin100-v1/readiness.json",
        "qcsd-class-study-readiness-attestation",
        {
            "attestation_schema_version": 3,
            "artifact_type": "qcsd-class-study-readiness-attestation",
            "study_id": "classifier-multiorigin100-v1",
            "cohort_version": 62,
            "source": source,
            "build_execution_identity": identity,
            "evidence": {
                "foundation": binding(foundation),
                "build_execution": binding(build),
            },
        },
    )
    historical = publish(
        root / "artifacts/classifier-multiorigin100-v1/historical-post.json",
        "qcsd-class-study-historical-snapshot",
        {
            "snapshot_schema_version": 1,
            "artifact_type": "qcsd-class-study-historical-snapshot",
            "source": source,
            "readiness": binding(readiness),
        },
    )
    handoff = root / "handoffs/classifier-multiorigin100-v1"
    handoff_snapshot = handoff / "inputs/class-study-historical-post-snapshot.json"
    handoff_snapshot.parent.mkdir(parents=True)
    handoff_snapshot.write_bytes(historical.read_bytes())
    (handoff / "SHA256SUMS").write_text("fixture\n", encoding="ascii")

    acquisition = root / "artifacts/classifier-multiorigin100-v1-acquisition"
    acquisition_provenance = publish(
        acquisition / "provenance.json",
        "qcsd-class-study-acquisition-provenance",
        {
            "acquisition_schema_version": CLASS_ACQUISITION_SCHEMA_VERSION,
            "acquisition_authority": binding(foundation),
            "image_digest": admitted.prepare_image,
            "source": {**source, "image_digest": admitted.prepare_image},
        },
    )
    acquisition_completion = publish(
        acquisition / "completion.json",
        "qcsd-class-study-acquisition-completion",
        {
            "acquisition_schema_version": CLASS_ACQUISITION_SCHEMA_VERSION,
            "completion_schema_version": CLASS_ACQUISITION_COMPLETION_SCHEMA_VERSION,
            "checkpoint_schema_version": CLASS_ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
            "provenance_sha256": sha256_file(acquisition_provenance),
        },
    )
    reference = root / "artifacts/classifier-multiorigin100-v1/reference.json"
    reference.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": 2,
                "artifact_type": "qcsd-buflo-csbuflo-reference-execution",
                "build_execution": {
                    "receipt": json.loads(build.read_bytes()),
                    "sha256": admitted.receipt_sha256,
                    "completion_path": identity["completion_path"],
                    "completion_sha256": admitted.completion_sha256,
                    "completion_payload_sha256": admitted.completion_payload_sha256,
                    "completion": json.loads(completion.read_bytes()),
                },
                "reference_image": {"id": admitted.reference_image},
            }
        )
    )
    decision = publish(
        root / "artifacts/classifier-multiorigin100-v1/decision.json",
        "qcsd-class-study-successor-decision",
        {
            "decision_schema_version": 3,
            "evidence": {"predecessor_foundation": binding(foundation)},
        },
    )
    decision_binding = binding(decision)
    decision_binding["payload_sha256"] = json.loads(decision.read_bytes())["payload_sha256"]
    successor_identity_sha256 = "0123456789ab" + "c" * 52
    successor_study_id = f"classifier-multiorigin100-v2-g01-{successor_identity_sha256[:12]}"
    successor_plan = root / f"artifacts/{successor_study_id}/plan"
    successor_campaigns = successor_plan / "campaigns"
    successor_campaigns.mkdir(parents=True)
    successor_files: dict[str, Path] = {}
    for successor_name in (
        "successor-cohort.json",
        "successor-compatible-cohort.json",
        "successor-compatible-cohort-assembly.json",
        "successor-final-selection.json",
        "final-qualification-plan.json",
    ):
        successor_path = successor_plan / successor_name
        successor_path.write_bytes(canonical_json_bytes({}))
        successor_files[successor_name] = successor_path
    successor_roles = {
        f"{successor_study_id}-authoritative-fitting-2000-1200.yml": ("authoritative-fitting"),
        f"{successor_study_id}-certification-900-1200.yml": "certification",
    }
    for successor_block in range(1, 11):
        successor_roles[f"{successor_study_id}-canary-{successor_block:02d}-1200.yml"] = "canary"
        successor_roles[f"{successor_study_id}-formal-{successor_block:02d}-1200.yml"] = "formal"
    for successor_name, successor_role in successor_roles.items():
        successor_path = successor_campaigns / successor_name
        successor_path.write_text(
            "schema: 2\n"
            f"evidence_role: {successor_role}\n"
            "class_study_successor: ../successor-restart.json\n"
            "class_study_cohort_assembly: "
            "../successor-compatible-cohort-assembly.json\n",
            encoding="utf-8",
        )
        successor_files[f"campaigns/{successor_name}"] = successor_path
    restart = publish(
        successor_plan / "successor-restart.json",
        "qcsd-class-study-successor-restart",
        {
            "restart_schema_version": 2,
            "artifact_type": "qcsd-class-study-successor-restart",
            "study_id": successor_study_id,
            "predecessor_study_id": "classifier-multiorigin100-v1",
            "replacement_generation": 1,
            "cumulative_failed_class_ids": [],
            "successor_identity_sha256": successor_identity_sha256,
            "successor_decision": decision_binding,
            "predecessor_foundation_sha256": sha256_file(foundation),
            "source_sha256": canonical_json_sha256(source),
            "build_execution_identity_sha256": canonical_json_sha256(identity),
            "selection_sha256": "0" * 64,
            "namespace": {
                "restart_root_name": successor_study_id,
                "launch_namespace": f".{successor_study_id}-launches",
                "results_root": "results",
                "authoritative_numeric_root": (
                    "artifacts/classifier-multiorigin100-v1-authoritative-fitting-numeric"
                ),
                "authoritative_prefix_root": (
                    "artifacts/classifier-multiorigin100-v1-authoritative-fitting-prefix-specs"
                ),
                "authoritative_final_root": (
                    "artifacts/classifier-multiorigin100-v1-authoritative-fitting"
                ),
                "final_qualification_root": (f"qualification/{successor_study_id}-final-full"),
            },
            "immutable_plan_artifacts": {
                name: {"path": name, "sha256": sha256_file(path)}
                for name, path in successor_files.items()
            },
            "required_restart_gates": [],
            "downstream_restart": {},
            "readiness": {},
            "predecessor_downstream_artifact_reuse_permitted": False,
        },
    )
    evaluation = publish(
        root / "artifacts/classifier-multiorigin100-v1/evaluation.json",
        "qcsd-class-study-evaluation",
        {
            "schema_version": 2,
            "artifact_type": "qcsd-class-study-evaluation",
            "handoff": {"root": str(handoff)},
        },
    )
    comparison = publish(
        root / "artifacts/classifier-multiorigin100-v1/comparison.json",
        "qcsd-class-study-comparison-review",
        {
            "artifact_type": "qcsd-class-study-comparison-review",
            "handoff": {"root": str(handoff)},
            "evaluation": binding(evaluation),
        },
    )
    validation = publish(
        root / "artifacts/classifier-multiorigin100-v1/validation.json",
        "qcsd-class-study-validation-attestation",
        {
            "attestation_schema_version": 1,
            "artifact_type": "qcsd-class-study-validation-attestation",
            "source": source,
            "evidence": {
                "readiness": binding(readiness),
                "evaluation": binding(evaluation),
            },
        },
    )
    policy = publish(
        root / "artifacts/classifier-multiorigin100-v1/policy.json",
        "qcsd-class-study-successor-policy",
        {"policy_schema_version": 1},
    )
    resume_campaign_name = "classifier-multiorigin100-v1-pilot-fitting-1200"
    resume = root / "results" / resume_campaign_name / "20260907T000000.000000Z"
    resume_inputs = resume / "inputs"
    environment = resume_inputs / "study-environment.json"
    resume_inputs.mkdir(parents=True)
    resume_workload_ids = [f"class-{index:03d}" for index in range(120)]
    environment.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": 3,
                "artifact_type": "qcsd-buflo-study-environment",
                "docker": {
                    "client_version": "fixture",
                    "server_version": "fixture",
                    "server_os": "linux",
                    "server_arch": "amd64",
                    "ncpu": 12,
                    "mem_total_bytes": 1,
                    "storage_driver": "fixture",
                },
                "collection_image": {"id": admitted.collection_image, "repo_digests": []},
                "build_inputs": {
                    "schema_version": 1,
                    "artifact_type": "qcsd-study-build-inputs",
                    "rust_base_image": "fixture",
                    "debian_base_image": "fixture",
                    "uv_lock_sha256": "0" * 64,
                    "cargo_lock_sha256": "0" * 64,
                },
                "build_execution": {
                    "receipt": json.loads(build.read_bytes()),
                    "sha256": admitted.receipt_sha256,
                    "completion_path": identity["completion_path"],
                    "completion_sha256": admitted.completion_sha256,
                    "completion_payload_sha256": admitted.completion_payload_sha256,
                    "completion": json.loads(completion.read_bytes()),
                },
                "clock_status": {
                    "relationship": "container-shares-host-kernel-realtime-clock",
                    "host": {},
                    "container": {},
                },
                "capture_scheduler": {},
            }
        )
    )
    (resume_inputs / "source.json").write_bytes(canonical_json_bytes(source))
    (resume_inputs / "class-study-foundation.json").write_bytes(foundation.read_bytes())
    resume_cohort = publish(
        resume_inputs / "class-study-cohort.json",
        "qcsd-class-study-cohort",
        {
            "artifact_type": "qcsd-class-study-cohort",
            "study_id": "classifier-multiorigin100-v1",
            "inventories": {
                "pilot": resume_workload_ids,
                "final": resume_workload_ids[:100],
            },
        },
    )
    resume_cohort_envelope = json.loads(resume_cohort.read_bytes())
    resume_assembly = publish(
        resume_inputs / "class-study-cohort-assembly.json",
        "qcsd-class-study-cohort-assembly",
        {
            "study_id": "classifier-multiorigin100-v1",
            "assembly_schema_version": 3,
            "eligibility_policy": {},
            "candidate_catalogue": {},
            "acquisition_completion": {"fixture_build": admitted.receipt_sha256},
            "final_selection": None,
            "stability_root": "stability",
            "workload_root": "workloads",
            "candidates": [],
            "eligible_count": 0,
            "selected_evidence_count": 0,
            "cohort": {
                "receipt_type": resume_cohort_envelope["receipt_type"],
                "payload_sha256": resume_cohort_envelope["payload_sha256"],
                "canonical_file_sha256": sha256_file(resume_cohort),
            },
        },
    )
    frozen_campaign = resume_inputs / "campaign.yml"
    resume_workloads = resume_inputs / "workloads"
    resume_workloads.mkdir()
    for workload_id in resume_workload_ids:
        (resume_workloads / f"{workload_id}.json").write_bytes(canonical_json_bytes({}))
    (resume_inputs / "defense-parameters").mkdir()
    frozen_campaign.write_text(
        "schema: 2\n"
        f"name: {resume_campaign_name}\n"
        "evidence_role: pilot-fitting\n"
        "class_study_cohort: class-study-cohort.json\n"
        "class_study_cohort_assembly: class-study-cohort-assembly.json\n"
        "workloads:\n" + "".join(f"  {workload_id}: 2\n" for workload_id in resume_workload_ids),
        encoding="utf-8",
    )
    resume_cohort_sha256 = sha256_file(resume_cohort)
    resume_assembly_sha256 = sha256_file(resume_assembly)
    resume_launch_identity = {
        "study_id": "classifier-multiorigin100-v1",
        "campaign_name": resume_campaign_name,
        "evidence_role": "pilot-fitting",
        "class_study_cohort_sha256": resume_cohort_sha256,
        "class_study_cohort_assembly_sha256": resume_assembly_sha256,
        "uniqueness_policy": "canonical-role-block-and-cohort-assembly-v1",
    }
    resume_launch_key = hashlib.sha256(
        json.dumps(resume_launch_identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    resume_launch_payload = {
        "study_id": "classifier-multiorigin100-v1",
        "launch_key": resume_launch_key,
        "campaign_name": resume_campaign_name,
        "campaign_sha256": sha256_file(frozen_campaign),
        "evidence_role": "pilot-fitting",
        "class_study_cohort_sha256": resume_cohort_sha256,
        "class_study_cohort_assembly_sha256": resume_assembly_sha256,
        "result_root": (f"/lab/results/{resume_campaign_name}/{resume.name}"),
        "created_at": "2026-09-07T00:00:00+00:00",
        "source": source,
        "policy": "one-result-root-per-campaign-and-cohort-assembly",
    }
    resume_launch = {
        "schema_version": 1,
        "artifact_type": "qcsd-class-study-first-launch-claim",
        "payload_sha256": hashlib.sha256(
            json.dumps(resume_launch_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "payload": resume_launch_payload,
    }
    resume_launch_path = resume_inputs / "class-study-launch.json"
    resume_launch_path.write_bytes(canonical_json_bytes(resume_launch))
    resume_registry = root / "results/.classifier-multiorigin100-v1-launches"
    resume_registry.mkdir()
    (resume_registry / f"{resume_launch_key}.json").write_bytes(resume_launch_path.read_bytes())
    (resume / "experiment.json").write_bytes(
        canonical_json_bytes(
            {
                "name": resume_campaign_name,
                "purpose": "fitting",
                "status": "incomplete",
                "source": source,
                "configuration": {
                    "evidence_role": "pilot-fitting",
                    "profile": "research-1200",
                    "request_policies": ["as-defined", "half-duplex"],
                    "limits": {
                        "timeout_seconds": 120,
                        "max_response_bytes": 1_048_576,
                        "capture_seconds": 180,
                        "capture_megabytes": 64,
                        "max_attempts": 3,
                        "per_origin_cooldown_seconds": 30,
                        "settle_seconds": 1,
                    },
                    "sample_order": {
                        "scheme": "origin-aware-windowed",
                        "window_size": 16,
                    },
                    "public_origin_policy": {
                        "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
                        "required_value": "1",
                        "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
                    },
                    "defenses": [{"name": "undefended", "kind": "none", "baseline": True}],
                    "workloads": [
                        {
                            "id": workload_id,
                            "visits": 2,
                            "manifest": f"inputs/workloads/{workload_id}.json",
                            "sha256": sha256_file(resume_workloads / f"{workload_id}.json"),
                            "resource_count": 0,
                            "origin_count": 1,
                        }
                        for workload_id in resume_workload_ids
                    ],
                    "class_study_id": "classifier-multiorigin100-v1",
                    "study_environment_sha256": sha256_file(environment),
                    "campaign_sha256": sha256_file(frozen_campaign),
                    "class_study_foundation_sha256": sha256_file(
                        resume_inputs / "class-study-foundation.json"
                    ),
                    "class_study_cohort_sha256": resume_cohort_sha256,
                    "class_study_cohort_assembly_sha256": resume_assembly_sha256,
                    "class_study_launch_sha256": sha256_file(resume_launch_path),
                },
            }
        )
    )
    campaign = root / "config/classifier-multiorigin100-v1/campaigns/pilot.yaml"
    campaign.parent.mkdir(parents=True)
    campaign.write_text("schema_version: 2\nevidence_role: pilot-fitting\n", encoding="utf-8")

    def load(path: Path, *, expected_cohort: int | None = None):
        assert path == build
        if expected_cohort is not None:
            assert expected_cohort == 62
        return admitted

    return SimpleNamespace(
        root=root,
        admitted=admitted,
        load=load,
        build=build,
        foundation=foundation,
        readiness=readiness,
        historical=historical,
        handoff=handoff,
        acquisition=acquisition,
        acquisition_completion=acquisition_completion,
        reference=reference,
        decision=decision,
        restart=restart,
        comparison=comparison,
        validation=validation,
        policy=policy,
        evaluation=evaluation,
        resume=resume,
        campaign=campaign,
    )


def _second_class_build_admission_fixture(fixture):
    from qcsd_lab.class_build_admission import BuildAdmission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    root = fixture.root
    build = root / "artifacts/buflo-study/build-execution-v63.json"
    completion = root / "artifacts/buflo-study/build-completion-v63.json"
    build.write_bytes(canonical_json_bytes({"cohort_version": 63}))
    completion.write_bytes(canonical_json_bytes({"schema_version": 1, "payload_sha256": "e" * 64}))
    source = {**dict(fixture.admitted.source), "image_digest": "sha256:" + "4" * 64}
    identity = {
        "cohort_version": 63,
        "sha256": sha256_file(build),
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v63.json",
        "completion_sha256": sha256_file(completion),
        "collection_image": source["image_digest"],
        "started_at": "2026-09-07T00:02:00+00:00",
        "finished_at": "2026-09-07T00:03:00+00:00",
    }
    admitted = BuildAdmission(
        receipt_path=build,
        receipt_sha256=sha256_file(build),
        cohort_version=63,
        collection_image=source["image_digest"],
        prepare_image="sha256:" + "5" * 64,
        reference_image="sha256:" + "6" * 64,
        completion_path=completion,
        completion_sha256=sha256_file(completion),
        completion_payload_sha256="e" * 64,
        source=source,
        identity=identity,
    )

    def publish(path: Path, receipt_type: str, payload: dict[str, object]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=receipt_type)))
        return path

    def binding(path: Path) -> dict[str, str]:
        return {"path": str(path), "sha256": sha256_file(path)}

    base = root / "artifacts/classifier-multiorigin100-v1-conflict"
    foundation = publish(
        base / "foundation.json",
        "qcsd-class-study-foundation-attestation",
        {
            "attestation_schema_version": 4,
            "artifact_type": "qcsd-class-study-foundation-attestation",
            "cohort_version": 63,
            "source": source,
            "build_execution_identity": identity,
            "evidence": {"build_execution": binding(build)},
        },
    )
    readiness = publish(
        base / "readiness.json",
        "qcsd-class-study-readiness-attestation",
        {
            "attestation_schema_version": 3,
            "artifact_type": "qcsd-class-study-readiness-attestation",
            "study_id": "classifier-multiorigin100-v1",
            "cohort_version": 63,
            "source": source,
            "build_execution_identity": identity,
            "evidence": {
                "foundation": binding(foundation),
                "build_execution": binding(build),
            },
        },
    )
    historical = publish(
        base / "historical-pre.json",
        "qcsd-class-study-historical-snapshot",
        {
            "snapshot_schema_version": 1,
            "artifact_type": "qcsd-class-study-historical-snapshot",
            "source": source,
            "readiness": binding(readiness),
        },
    )
    handoff = root / "handoffs/classifier-multiorigin100-v1-conflict"
    handoff_snapshot = handoff / "inputs/class-study-historical-post-snapshot.json"
    handoff_snapshot.parent.mkdir(parents=True)
    handoff_snapshot.write_bytes(historical.read_bytes())
    evaluation = publish(
        base / "evaluation.json",
        "qcsd-class-study-evaluation",
        {
            "schema_version": 2,
            "artifact_type": "qcsd-class-study-evaluation",
            "handoff": {"root": str(handoff)},
        },
    )
    acquisition = base / "acquisition"
    provenance = publish(
        acquisition / "provenance.json",
        "qcsd-class-study-acquisition-provenance",
        {
            "acquisition_schema_version": CLASS_ACQUISITION_SCHEMA_VERSION,
            "acquisition_authority": binding(foundation),
            "image_digest": admitted.prepare_image,
            "source": {**source, "image_digest": admitted.prepare_image},
        },
    )
    acquisition_completion = publish(
        acquisition / "completion.json",
        "qcsd-class-study-acquisition-completion",
        {
            "acquisition_schema_version": CLASS_ACQUISITION_SCHEMA_VERSION,
            "completion_schema_version": CLASS_ACQUISITION_COMPLETION_SCHEMA_VERSION,
            "checkpoint_schema_version": CLASS_ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
            "provenance_sha256": sha256_file(provenance),
        },
    )
    qualification_authority = {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            **binding(foundation),
            "payload_sha256": json.loads(foundation.read_bytes())["payload_sha256"],
        },
        "build_execution": binding(build),
        "build_execution_identity": identity,
        "collection_source": source,
        "prepare_source": {**source, "image_digest": admitted.prepare_image},
        "prepare_image_digest": admitted.prepare_image,
    }
    final_selection = publish(
        base / "final-selection.json",
        "qcsd-class-study-final-selection-input",
        {
            "selection_schema_version": 2,
            "qualification_authority": qualification_authority,
        },
    )
    final_cohort_assembly = publish(
        base / "final-cohort-assembly.json",
        "qcsd-class-study-cohort-assembly",
        {
            "assembly_schema_version": 3,
            "qualification_authority": qualification_authority,
        },
    )
    result = _current_pilot_resume_fixture(
        root,
        admitted,
        build,
        foundation,
        run_id="20260907T000200.000000Z",
    )
    campaign = root / "config/classifier-multiorigin100-v1/campaigns/formal-conflict.yaml"
    campaign.write_text("schema_version: 2\nevidence_role: formal\n", encoding="utf-8")

    def load(path: Path, *, expected_cohort: int | None = None):
        if path == fixture.build:
            return fixture.load(path, expected_cohort=expected_cohort)
        assert path == build
        if expected_cohort is not None:
            assert expected_cohort == 63
        return admitted

    return SimpleNamespace(
        admitted=admitted,
        load=load,
        build=build,
        foundation=foundation,
        readiness=readiness,
        historical=historical,
        handoff=handoff,
        evaluation=evaluation,
        acquisition=acquisition,
        acquisition_completion=acquisition_completion,
        qualification_authority=qualification_authority,
        final_selection=final_selection,
        final_cohort_assembly=final_cohort_assembly,
        result=result,
        campaign=campaign,
    )


def test_class_build_admission_loads_exact_build_storage_module() -> None:
    from qcsd_lab.class_build_admission import _load_build_storage

    root = Path(__file__).parents[1].resolve()
    module = _load_build_storage(root)

    assert Path(module.__file__).resolve() == root / "src/qcsd_lab/build_storage.py"
    assert module.BUILD_COMPLETION_SCHEMA_VERSION == 1
    assert callable(module.load_validated_build_execution)


def test_class_build_admission_rejects_schema_five_without_completion(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import _current_build

    root = tmp_path / "lab"
    receipt = root / "artifacts/buflo-study/build-execution-v1.json"
    probe = root / "tools/windows_docker_storage_probe.ps1"
    receipt.parent.mkdir(parents=True)
    probe.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="ascii")
    probe.write_text("fixture\n", encoding="ascii")

    class PrecompletionStorage:
        @staticmethod
        def load_validated_build_execution(*_args, **_kwargs):
            return receipt, b"{}\n", {}, {"schema_version": 5}, None

    with pytest.raises(ValueError, match="schema 5 and completion schema 1"):
        _current_build(root, receipt, storage=PrecompletionStorage())


def test_class_build_admission_projects_timestamps_from_the_validated_receipt(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import _current_build

    root = tmp_path / "lab"
    receipt = root / "artifacts/buflo-study/build-execution-v7.json"
    completion_path = receipt.with_name("build-completion-v7.json")
    probe = root / "tools/windows_docker_storage_probe.ps1"
    receipt.parent.mkdir(parents=True)
    probe.parent.mkdir(parents=True)
    receipt.write_text("fixture\n", encoding="ascii")
    completion_path.write_text("fixture\n", encoding="ascii")
    probe.write_text("fixture\n", encoding="ascii")

    started_at = "2026-09-08T00:00:00+00:00"
    finished_at = "2026-09-08T00:01:00+00:00"
    value = {"started_at": started_at, "finished_at": finished_at}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    images = {
        "collection": "sha256:" + "1" * 64,
        "prepare": "sha256:" + "2" * 64,
        "reference": "sha256:" + "3" * 64,
    }
    validated = {
        "schema_version": 5,
        "cohort_version": 7,
        "image_ids": images,
        "source": {"lab_commit": "a" * 40},
    }
    completion = {"schema_version": 1, "payload_sha256": "4" * 64}
    completion_raw = json.dumps(completion, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    class CurrentStorage:
        @staticmethod
        def load_validated_build_execution(*_args, **_kwargs):
            # The validation projection intentionally omits receipt timestamps.
            return receipt, raw, value, validated, completion

        @staticmethod
        def build_completion_path(resolved: Path, cohort: int) -> Path:
            assert resolved == receipt
            assert cohort == 7
            return completion_path

        @staticmethod
        def load_stable_build_completion(path: Path):
            assert path == completion_path
            return completion_path, completion_raw, completion

    admitted = _current_build(root, receipt, storage=CurrentStorage())

    assert admitted.receipt_sha256 == hashlib.sha256(raw).hexdigest()
    assert admitted.completion_sha256 == hashlib.sha256(completion_raw).hexdigest()
    assert admitted.identity == {
        "cohort_version": 7,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "completion_path": "/lab/artifacts/buflo-study/build-completion-v7.json",
        "completion_sha256": hashlib.sha256(completion_raw).hexdigest(),
        "collection_image": images["collection"],
        "started_at": started_at,
        "finished_at": finished_at,
    }


def test_class_build_admission_accepts_real_canonical_receipt_envelopes(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    fixture = _class_build_admission_fixture(tmp_path)
    observed = resolve_action_admission(
        fixture.root,
        action="qualify-prefix",
        options={"foundation": str(fixture.foundation)},
        build_loader=fixture.load,
    )

    assert observed == fixture.admitted


def test_class_build_admission_rejects_malformed_frozen_image_object(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    environment_path = fixture.resume / "inputs/study-environment.json"
    environment = json.loads(environment_path.read_bytes())
    environment["collection_image"] = []
    environment_path.write_bytes(canonical_json_bytes(environment))

    with pytest.raises(ValueError, match="frozen environment has no current completed build"):
        resolve_action_admission(
            fixture.root,
            action="resume",
            execute=True,
            options={
                "foundation": str(fixture.foundation),
                "capture_result": str(fixture.resume),
            },
            build_loader=fixture.load,
        )


@pytest.mark.parametrize(
    ("action", "stage"),
    (
        ("stability", ""),
        ("successor-policy", ""),
        ("status", ""),
    ),
)
def test_class_build_admission_preserves_v1_no_build_actions(
    tmp_path: Path, action: str, stage: str
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    assert resolve_action_admission(tmp_path, action=action, stage=stage, options={}) is None


@pytest.mark.parametrize(
    ("action", "stage", "execute"),
    (
        ("foundation", "", False),
        ("readiness", "", False),
        ("successor-decision", "", False),
        ("successor-restart", "", False),
        ("successor-verify", "", False),
        ("acquisition-init", "", False),
        ("acquisition-run", "", False),
        ("acquisition-status", "", False),
        ("acquisition-complete", "", False),
        ("cohort", "pilot", False),
        ("cohort", "authoritative", False),
        ("campaigns", "pilot", False),
        ("campaigns", "authoritative", False),
        ("fit-numeric", "pilot", False),
        ("prefix-specs", "pilot", False),
        ("qualify-prefix", "pilot", False),
        ("finalize-fitting", "pilot", False),
        ("capture", "", False),
        ("capture", "", True),
        ("resume", "", False),
        ("resume", "", True),
        ("historical-snapshot", "", False),
        ("export", "", False),
        ("evaluate", "", False),
        ("comparison-review", "", False),
        ("attest", "", False),
        ("verify", "", False),
    ),
)
def test_class_build_admission_required_actions_fail_without_anchor(
    tmp_path: Path, action: str, stage: str, execute: bool
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    with pytest.raises(ValueError):
        resolve_action_admission(
            tmp_path,
            action=action,
            stage=stage,
            execute=execute,
            options={},
        )


@pytest.mark.parametrize(
    ("action", "stage", "missing_option"),
    (
        ("cohort", "pilot", "--acquisition-completion"),
        ("campaigns", "pilot", "--acquisition-completion"),
        ("fit-numeric", "pilot", "--capture-result"),
        ("prefix-specs", "pilot", "--capture-result"),
    ),
)
def test_class_build_admission_rejects_missing_build_carrier_before_docker(
    tmp_path: Path, action: str, stage: str, missing_option: str
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    with pytest.raises(ValueError, match=rf"{re.escape(missing_option)} before Docker"):
        resolve_action_admission(
            tmp_path,
            action=action,
            stage=stage,
            options={},
        )


def test_class_build_admission_resolves_all_transitive_authority_routes(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    fixture = _class_build_admission_fixture(tmp_path)
    cases = (
        ("foundation", "", False, {"build": str(fixture.build)}, 62),
        (
            "readiness",
            "",
            False,
            {"build": str(fixture.build), "foundation": str(fixture.foundation)},
            62,
        ),
        ("acquisition-init", "", False, {"foundation": str(fixture.foundation)}, None),
        ("acquisition-run", "", False, {"acquisition_root": str(fixture.acquisition)}, None),
        ("acquisition-status", "", False, {"acquisition_root": str(fixture.acquisition)}, None),
        ("acquisition-complete", "", False, {"acquisition_root": str(fixture.acquisition)}, None),
        (
            "cohort",
            "pilot",
            False,
            {"acquisition_completion": str(fixture.acquisition_completion)},
            None,
        ),
        (
            "cohort",
            "authoritative",
            False,
            {
                "foundation": str(fixture.foundation),
                "acquisition_completion": str(fixture.acquisition_completion),
            },
            None,
        ),
        (
            "campaigns",
            "pilot",
            False,
            {"acquisition_completion": str(fixture.acquisition_completion)},
            None,
        ),
        (
            "campaigns",
            "authoritative",
            False,
            {
                "foundation": str(fixture.foundation),
                "acquisition_completion": str(fixture.acquisition_completion),
            },
            None,
        ),
        (
            "fit-numeric",
            "pilot",
            False,
            {"capture_result": str(fixture.resume)},
            None,
        ),
        (
            "prefix-specs",
            "pilot",
            False,
            {"capture_result": str(fixture.resume)},
            None,
        ),
        ("finalize-fitting", "pilot", False, {"foundation": str(fixture.foundation)}, None),
        (
            "capture",
            "",
            False,
            {"foundation": str(fixture.foundation), "campaign": str(fixture.campaign)},
            None,
        ),
        (
            "capture",
            "",
            True,
            {
                "foundation": str(fixture.foundation),
                "build": str(fixture.build),
                "campaign": str(fixture.campaign),
            },
            None,
        ),
        (
            "resume",
            "",
            False,
            {
                "foundation": str(fixture.foundation),
                "capture_result": str(fixture.resume),
            },
            None,
        ),
        (
            "resume",
            "",
            True,
            {
                "foundation": str(fixture.foundation),
                "capture_result": str(fixture.resume),
            },
            None,
        ),
        ("historical-snapshot", "", False, {"readiness": str(fixture.readiness)}, None),
        ("export", "", False, {"historical_post": str(fixture.historical)}, None),
        ("evaluate", "", False, {"handoff": str(fixture.handoff)}, None),
        (
            "comparison-review",
            "",
            False,
            {
                "handoff": str(fixture.handoff),
                "evaluation": str(fixture.evaluation),
            },
            None,
        ),
        (
            "attest",
            "",
            False,
            {
                "readiness": str(fixture.readiness),
                "evaluation": str(fixture.evaluation),
            },
            None,
        ),
        ("successor-decision", "", False, {"foundation": str(fixture.foundation)}, None),
        ("successor-restart", "", False, {"successor_decision": str(fixture.decision)}, None),
        ("successor-verify", "", False, {"target": str(fixture.restart)}, None),
        (
            "fit-numeric",
            "authoritative",
            False,
            {
                "successor_restart": str(fixture.restart),
                "capture_result": str(fixture.resume),
            },
            None,
        ),
        (
            "prefix-specs",
            "authoritative",
            False,
            {
                "successor_restart": str(fixture.restart),
                "capture_result": str(fixture.resume),
            },
            None,
        ),
        ("status", "", False, {"comparison": str(fixture.comparison)}, None),
        ("status", "", False, {"validation": str(fixture.validation)}, None),
        ("verify", "", False, {"target": str(fixture.validation)}, None),
        (
            "verify",
            "",
            False,
            {"target": str(fixture.evaluation), "handoff": str(fixture.handoff)},
            None,
        ),
    )
    for action, stage, execute, options, cohort in cases:
        assert (
            resolve_action_admission(
                fixture.root,
                action=action,
                stage=stage,
                execute=execute,
                cohort_version=cohort,
                options=options,
                build_loader=fixture.load,
            )
            == fixture.admitted
        ), action
    assert (
        resolve_action_admission(
            fixture.root,
            action="successor-verify",
            options={"target": str(fixture.policy)},
            build_loader=fixture.load,
        )
        is None
    )


def test_class_build_admission_reference_uses_raw_schema_five_receipt_cohort(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    fixture = _class_build_admission_fixture(tmp_path)

    assert (
        resolve_action_admission(
            fixture.root,
            action="foundation",
            cohort_version=62,
            options={"build": str(fixture.build), "reference": str(fixture.reference)},
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


def _class_build_pinned_cdp_receipt(fixture, *, schema: object) -> Path:
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    destination = fixture.root / f"artifacts/pinned-cdp-schema-{schema!s}.json"
    payload = {
        "probe_schema_version": schema,
        "artifact_type": "qcsd-class-study-pinned-cdp-probe",
        "cohort_version": fixture.admitted.cohort_version,
        "build_execution": {
            "path": str(fixture.build),
            "sha256": sha256_file(fixture.build),
        },
        "build_execution_identity": fixture.admitted.identity,
        "collection_source": fixture.admitted.source,
        "prepare_image_digest": fixture.admitted.prepare_image,
        "prepare_source": {
            **dict(fixture.admitted.source),
            "image_digest": fixture.admitted.prepare_image,
        },
    }
    destination.write_bytes(
        canonical_json_bytes(
            bind_receipt(payload, receipt_type="qcsd-class-study-pinned-cdp-probe")
        )
    )
    return destination


def test_class_build_admission_accepts_current_pinned_cdp_schema(tmp_path: Path) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.pinned_cdp import PROBE_SCHEMA_VERSION

    fixture = _class_build_admission_fixture(tmp_path)
    pinned = _class_build_pinned_cdp_receipt(fixture, schema=PROBE_SCHEMA_VERSION)

    assert (
        resolve_action_admission(
            fixture.root,
            action="foundation",
            cohort_version=62,
            options={"build": str(fixture.build), "pinned_cdp": str(pinned)},
            build_loader=fixture.load,
        )
        == fixture.admitted
    )


@pytest.mark.parametrize("schema", (14.0, "14", True))
def test_class_build_admission_rejects_current_pinned_cdp_schema_aliases(
    tmp_path: Path,
    schema: object,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    fixture = _class_build_admission_fixture(tmp_path)
    pinned = _class_build_pinned_cdp_receipt(fixture, schema=schema)

    with pytest.raises(ValueError, match="not current build authority"):
        resolve_action_admission(
            fixture.root,
            action="foundation",
            cohort_version=62,
            options={"build": str(fixture.build), "pinned_cdp": str(pinned)},
            build_loader=fixture.load,
        )


@pytest.mark.parametrize("schema", (8, 9, 11, 12, 13))
def test_class_build_admission_classifies_old_pinned_cdp_schemas_as_historical(
    tmp_path: Path,
    schema: int,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    fixture = _class_build_admission_fixture(tmp_path)
    pinned = _class_build_pinned_cdp_receipt(fixture, schema=schema)

    with pytest.raises(ValueError, match="pinned CDP receipt is historical"):
        resolve_action_admission(
            fixture.root,
            action="foundation",
            cohort_version=62,
            options={"build": str(fixture.build), "pinned_cdp": str(pinned)},
            build_loader=fixture.load,
        )


def test_class_build_admission_rejects_unknown_pinned_cdp_schema(tmp_path: Path) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    fixture = _class_build_admission_fixture(tmp_path)
    pinned = _class_build_pinned_cdp_receipt(fixture, schema=10)

    with pytest.raises(ValueError, match="not current build authority"):
        resolve_action_admission(
            fixture.root,
            action="foundation",
            cohort_version=62,
            options={"build": str(fixture.build), "pinned_cdp": str(pinned)},
            build_loader=fixture.load,
        )


@pytest.mark.parametrize(
    ("action", "options"),
    (
        (
            "attest",
            lambda first, second: {
                "readiness": str(first.readiness),
                "historical_pre": str(second.historical),
                "evaluation": str(first.evaluation),
            },
        ),
        (
            "capture",
            lambda first, second: {
                "foundation": str(first.foundation),
                "readiness": str(second.readiness),
                "historical_pre": str(second.historical),
                "campaign": str(second.campaign),
            },
        ),
        (
            "resume",
            lambda first, second: {
                "foundation": str(first.foundation),
                "readiness": str(second.readiness),
                "historical_pre": str(second.historical),
                "capture_result": str(second.result),
            },
        ),
        (
            "historical-snapshot",
            lambda first, second: {
                "readiness": str(first.readiness),
                "historical_pre": str(second.historical),
                "formal_results": [str(second.result)],
            },
        ),
        (
            "status",
            lambda first, second: {
                "foundation": str(first.foundation),
                "acquisition_root": str(second.acquisition),
                "acquisition_completion": str(second.acquisition_completion),
            },
        ),
        (
            "foundation",
            lambda first, second: {
                "build": str(first.build),
                "regression_results": [str(second.result)],
            },
        ),
    ),
)
def test_class_build_admission_rejects_conflicting_current_authority_chains(
    tmp_path: Path,
    action: str,
    options,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)

    with pytest.raises(
        ValueError,
        match="resolve to different completed builds|differs from external resume authority",
    ):
        resolve_action_admission(
            first.root,
            action=action,
            stage="authoritative" if action == "foundation" else "",
            options=options(first, second),
            build_loader=second.load,
        )


def test_class_build_admission_completion_binds_exact_sibling_provenance(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    completion = json.loads(fixture.acquisition_completion.read_bytes())["payload"]
    completion["provenance_sha256"] = "0" * 64
    fixture.acquisition_completion.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                completion,
                receipt_type="qcsd-class-study-acquisition-completion",
            )
        )
    )

    with pytest.raises(ValueError, match="binds another provenance"):
        resolve_action_admission(
            fixture.root,
            action="cohort",
            stage="pilot",
            options={"acquisition_completion": str(fixture.acquisition_completion)},
            build_loader=fixture.load,
        )


@pytest.mark.parametrize("kind", ("comparison", "validation"))
def test_class_build_admission_rejects_conflicting_mandatory_evaluation(
    tmp_path: Path,
    kind: str,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    source = first.comparison if kind == "comparison" else first.validation
    value = json.loads(source.read_bytes())
    payload = value["payload"]
    evaluation_binding = {
        "path": str(second.evaluation),
        "sha256": sha256_file(second.evaluation),
    }
    if kind == "comparison":
        payload["evaluation"] = evaluation_binding
    else:
        payload["evidence"]["evaluation"] = evaluation_binding
    target = source.with_name(f"conflicting-{kind}.json")
    target.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=value["receipt_type"]))
    )

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action="status",
            options={kind: str(target)},
            build_loader=second.load,
        )


@pytest.mark.parametrize(
    ("action", "options"),
    (
        (
            "comparison-review",
            lambda first, second: {
                "handoff": str(first.handoff),
                "evaluation": str(second.evaluation),
            },
        ),
        (
            "attest",
            lambda first, second: {
                "readiness": str(first.readiness),
                "evaluation": str(second.evaluation),
            },
        ),
        (
            "status",
            lambda first, second: {
                "foundation": str(first.foundation),
                "evaluation": str(second.evaluation),
            },
        ),
    ),
)
def test_class_build_admission_rejects_conflicting_direct_evaluation(
    tmp_path: Path,
    action: str,
    options,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action=action,
            stage="pilot" if action == "verify" else "",
            options=options(first, second),
            build_loader=second.load,
        )


@pytest.mark.parametrize(
    ("action", "stage", "base_options"),
    (
        ("evaluate", "", lambda first: {"handoff": str(first.handoff)}),
        ("verify", "pilot", lambda first: {"target": str(first.foundation)}),
    ),
)
def test_class_actions_ignore_unconsumed_evaluation_and_final_inputs(
    tmp_path: Path,
    action: str,
    stage: str,
    base_options,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    options = {
        **base_options(first),
        "evaluation": str(second.evaluation),
        "final_selection": str(second.final_selection),
        "final_cohort_assembly": str(second.final_cohort_assembly),
    }

    assert (
        resolve_action_admission(
            first.root,
            action=action,
            stage=stage,
            options=options,
            build_loader=second.load,
        )
        == first.admitted
    )


def test_class_status_allows_explicit_historical_evaluation(tmp_path: Path) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    value = json.loads(fixture.evaluation.read_bytes())
    payload = value["payload"]
    payload["schema_version"] = 1
    historical = fixture.evaluation.with_name("historical-evaluation.json")
    historical.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=value["receipt_type"]))
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"evaluation": str(historical)},
            build_loader=fixture.load,
        )
        is None
    )


def test_class_build_admission_rejects_successor_identity_projection_changes(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    decision_value = json.loads(fixture.decision.read_bytes())
    decision = decision_value["payload"]
    decision["predecessor"] = {
        "source": fixture.admitted.source,
        "source_sha256": "0" * 64,
        "build_execution_identity": fixture.admitted.identity,
        "build_execution_identity_sha256": "0" * 64,
    }
    changed = fixture.decision.with_name("changed-decision.json")
    changed.write_bytes(
        canonical_json_bytes(bind_receipt(decision, receipt_type=decision_value["receipt_type"]))
    )

    with pytest.raises(ValueError, match="predecessor identity differs"):
        resolve_action_admission(
            fixture.root,
            action="successor-restart",
            options={"successor_decision": str(changed)},
            build_loader=fixture.load,
        )

    restart_value = json.loads(fixture.restart.read_bytes())
    restart = restart_value["payload"]
    restart["source_sha256"] = "0" * 64
    fixture.restart.write_bytes(
        canonical_json_bytes(bind_receipt(restart, receipt_type=restart_value["receipt_type"]))
    )
    with pytest.raises(ValueError, match="differs from its decision"):
        resolve_action_admission(
            fixture.root,
            action="successor-verify",
            options={"target": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_class_status_rejects_current_readiness_with_historical_nested_foundation(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    foundation_value = json.loads(fixture.foundation.read_bytes())
    foundation_payload = foundation_value["payload"]
    foundation_payload["attestation_schema_version"] = 3
    historical_foundation = fixture.foundation.with_name("historical-foundation-status.json")
    historical_foundation.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                foundation_payload,
                receipt_type=foundation_value["receipt_type"],
            )
        )
    )
    readiness_value = json.loads(fixture.readiness.read_bytes())
    readiness_payload = readiness_value["payload"]
    readiness_payload["evidence"]["foundation"] = {
        "path": str(historical_foundation),
        "sha256": sha256_file(historical_foundation),
    }
    current_outer = fixture.readiness.with_name("current-outer-historical-nested.json")
    current_outer.write_bytes(
        canonical_json_bytes(
            bind_receipt(readiness_payload, receipt_type=readiness_value["receipt_type"])
        )
    )

    with pytest.raises(ValueError, match="historical"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"readiness": str(current_outer)},
            build_loader=fixture.load,
        )


def test_class_validation_requires_mandatory_evaluation(tmp_path: Path) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    value = json.loads(fixture.validation.read_bytes())
    payload = value["payload"]
    del payload["evidence"]["evaluation"]
    changed = fixture.validation.with_name("validation-without-evaluation.json")
    changed.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=value["receipt_type"]))
    )

    with pytest.raises(ValueError, match="mandatory evaluation"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"validation": str(changed)},
            build_loader=fixture.load,
        )


def test_class_validation_cannot_remove_successor_restart_from_both_wrappers(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    readiness_value = json.loads(fixture.readiness.read_bytes())
    readiness_payload = readiness_value["payload"]
    readiness_payload["study_id"] = "classifier-multiorigin100-v2-g01-0123456789ab"
    successor_readiness = fixture.readiness.with_name("successor-without-restart.json")
    successor_readiness.write_bytes(
        canonical_json_bytes(
            bind_receipt(readiness_payload, receipt_type=readiness_value["receipt_type"])
        )
    )
    validation_value = json.loads(fixture.validation.read_bytes())
    validation_payload = validation_value["payload"]
    validation_payload["evidence"]["readiness"] = {
        "path": str(successor_readiness),
        "sha256": sha256_file(successor_readiness),
    }
    changed = fixture.validation.with_name("successor-validation-without-restart.json")
    changed.write_bytes(
        canonical_json_bytes(
            bind_receipt(validation_payload, receipt_type=validation_value["receipt_type"])
        )
    )

    with pytest.raises(ValueError, match="successor authority is incomplete"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"validation": str(changed)},
            build_loader=fixture.load,
        )


def test_class_campaign_admission_follows_successor_restart_authority(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    campaign = first.campaign.with_name("successor-authority.yaml")
    restart = "/lab/" + str(first.restart.relative_to(first.root))
    campaign.write_text(
        f"schema: 2\nevidence_role: pilot-fitting\nclass_study_successor: {restart}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action="capture",
            options={
                "foundation": str(second.foundation),
                "campaign": str(campaign),
            },
            build_loader=second.load,
        )


def test_class_campaign_admission_follows_flow_style_parameter_authority(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import canonical_json_bytes

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    bundle = first.root / "artifacts/conflicting-fitted-bundle"
    bundle.mkdir()
    authority = {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            "path": str(second.foundation),
            "sha256": sha256_file(second.foundation),
            "payload_sha256": json.loads(second.foundation.read_bytes())["payload_sha256"],
        },
        "build_execution": {
            "path": str(second.build),
            "sha256": sha256_file(second.build),
        },
        "build_execution_identity": second.admitted.identity,
        "collection_source": second.admitted.source,
        "prepare_source": {
            **dict(second.admitted.source),
            "image_digest": second.admitted.prepare_image,
        },
        "prepare_image_digest": second.admitted.prepare_image,
    }
    (bundle / "provenance.json").write_bytes(
        canonical_json_bytes({"qualification_authority": authority})
    )
    parameter = "/lab/" + str(bundle.relative_to(first.root) / "traffic-morphing.json")
    campaign = first.campaign.with_name("flow-parameter-authority.yaml")
    campaign.write_text(
        "schema: 2\nevidence_role: pilot-fitting\n"
        f"defenses: [{{name: traffic-morphing, parameters: {parameter}}}]\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action="capture",
            options={
                "foundation": str(first.foundation),
                "campaign": str(campaign),
            },
            build_loader=second.load,
        )


@pytest.mark.parametrize(
    ("action", "stage", "base_options"),
    (
        (
            "campaigns",
            "pilot",
            lambda first: {"acquisition_completion": str(first.acquisition_completion)},
        ),
        ("fit-numeric", "authoritative", lambda first: {"capture_result": str(first.resume)}),
        ("prefix-specs", "authoritative", lambda first: {"capture_result": str(first.resume)}),
        (
            "qualify-prefix",
            "authoritative",
            lambda first: {
                "foundation": str(first.foundation),
                "capture_result": str(first.resume),
            },
        ),
        (
            "finalize-fitting",
            "authoritative",
            lambda first: {"foundation": str(first.foundation), "results": [str(first.resume)]},
        ),
        (
            "capture",
            "",
            lambda first: {
                "foundation": str(first.foundation),
                "campaign": str(first.campaign),
            },
        ),
        (
            "resume",
            "",
            lambda first: {
                "foundation": str(first.foundation),
                "capture_result": str(first.resume),
            },
        ),
        ("export", "", lambda first: {"historical_post": str(first.historical)}),
        ("status", "", lambda first: {"foundation": str(first.foundation)}),
    ),
)
def test_class_actions_reject_conflicting_final_admission_carriers(
    tmp_path: Path,
    action: str,
    stage: str,
    base_options,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    options = {
        **base_options(first),
        "final_selection": str(second.final_selection),
        "final_cohort_assembly": str(second.final_cohort_assembly),
    }

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action=action,
            stage=stage,
            options=options,
            build_loader=second.load,
        )


def test_class_campaign_scalar_parser_supports_safe_dump_block_and_flow_forms() -> None:
    from qcsd_lab.class_build_admission import _campaign_carrier_scalars

    values = _campaign_carrier_scalars(
        "'evidence_role': \"pilot-fitting\" # inline comment\n"
        "defenses:\n"
        "- name: traffic-morphing\n"
        "  parameters: '/lab/artifacts/final/traffic-morphing.json'\n"
        '- {name: wtf-pad, "parameters": /lab/artifacts/final/wtf-pad.json}\n'
        "description: 'parameters: /lab/ignored/walkie-talkie.json'\n"
        "# class_study_successor: /lab/ignored.json\n"
        "chaff_qualification_set: final-full\n"
    )

    assert values["evidence_role"] == ["pilot-fitting"]
    assert values["parameters"] == [
        "/lab/artifacts/final/traffic-morphing.json",
        "/lab/artifacts/final/wtf-pad.json",
    ]
    assert values["chaff_qualification_set"] == ["final-full"]
    assert values["class_study_successor"] == []


@pytest.mark.parametrize(
    "fragment",
    (
        "evidence_role: formal\n",
        "parameters:\n",
        "parameters: [value]\n",
        "parameters: null\n",
        "description: &anchor value\n",
        "description: *anchor\n",
        "<<: *anchor\n",
        "description: !tag value\n",
        "description: |\n  folded\n",
        "---\n",
        "%YAML 1.2\n",
        "? [complex, key]\n",
        "description:\tvalue\n",
    ),
)
def test_class_campaign_scalar_parser_rejects_ambiguous_yaml(fragment: str) -> None:
    from qcsd_lab.class_build_admission import _campaign_carrier_scalars

    with pytest.raises(ValueError):
        _campaign_carrier_scalars("evidence_role: pilot-fitting\n" + fragment)


@pytest.mark.parametrize(
    "document",
    (
        "{schema: 2, evidence_role: pilot-fitting, ? class_study_cohort_assembly : ../B/a.json}\n",
        "evidence_role: pilot-fitting\n"
        "defenses: [{? parameters : /lab/B/traffic-morphing.json, name: x}]\n",
        "evidence_role: pilot-fitting\ndefenses: [parameters: ../B/value.json]\n",
        "evidence_role: pilot-fitting\nparameters: unsafe#fragment\n",
        "evidence_role: pilot-fitting\nparameters: first\n  second\n",
    ),
)
def test_class_campaign_scalar_parser_rejects_flow_bypasses(document: str) -> None:
    from qcsd_lab.class_build_admission import _campaign_carrier_scalars

    with pytest.raises(ValueError):
        _campaign_carrier_scalars(document)


@pytest.mark.parametrize(
    ("action", "stage", "base_options"),
    (
        (
            "campaigns",
            "pilot",
            lambda first: {"acquisition_completion": str(first.acquisition_completion)},
        ),
        ("fit-numeric", "authoritative", lambda first: {"capture_result": str(first.resume)}),
        ("prefix-specs", "authoritative", lambda first: {"capture_result": str(first.resume)}),
        (
            "qualify-prefix",
            "authoritative",
            lambda first: {
                "foundation": str(first.foundation),
                "capture_result": str(first.resume),
            },
        ),
        (
            "finalize-fitting",
            "authoritative",
            lambda first: {"foundation": str(first.foundation)},
        ),
        (
            "capture",
            "",
            lambda first: {
                "foundation": str(first.foundation),
                "campaign": str(first.campaign),
            },
        ),
        (
            "resume",
            "",
            lambda first: {
                "foundation": str(first.foundation),
                "capture_result": str(first.resume),
            },
        ),
        ("export", "", lambda first: {"historical_post": str(first.historical)}),
        ("status", "", lambda first: {"foundation": str(first.foundation)}),
    ),
)
def test_class_build_admission_rejects_conflicting_final_admission_carriers(
    tmp_path: Path,
    action: str,
    stage: str,
    base_options,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission

    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    options = {
        **base_options(first),
        "final_selection": str(second.final_selection),
        "final_cohort_assembly": str(second.final_cohort_assembly),
    }

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            first.root,
            action=action,
            stage=stage,
            options=options,
            build_loader=second.load,
        )


def test_class_build_admission_rejects_historical_foundation_before_build_load(
    tmp_path: Path,
) -> None:
    from qcsd_lab.class_build_admission import resolve_action_admission
    from qcsd_lab.class_study import bind_receipt, canonical_json_bytes

    fixture = _class_build_admission_fixture(tmp_path)
    value = json.loads(fixture.foundation.read_bytes())
    payload = value["payload"]
    payload["attestation_schema_version"] = 3
    historical = fixture.foundation.with_name("historical-foundation.json")
    historical.write_bytes(
        canonical_json_bytes(
            bind_receipt(payload, receipt_type="qcsd-class-study-foundation-attestation")
        )
    )
    called = False

    def load(*_args, **_kwargs):
        nonlocal called
        called = True
        return fixture.admitted

    with pytest.raises(ValueError, match="not current build authority"):
        resolve_action_admission(
            fixture.root,
            action="qualify-prefix",
            options={"foundation": str(historical)},
            build_loader=load,
        )
    assert called is False


def test_class_build_admission_precedes_first_class_docker_mutation() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    invocation = launcher.index(
        '/src/qcsd_lab/class_build_admission.py"',
        launcher.index('class_resume_environment=""'),
    )
    admission = launcher.rindex("class_build_admission_args=(", 0, invocation)
    class_docker = launcher.index("\n  require_docker\n", admission)

    assert admission < class_docker
    assert "reconcile_stale_docker_supervisors" not in launcher[admission:class_docker]
    assert "_qcsd_docker_api" not in launcher[admission:class_docker]
    expected_options = {
        "build:--build-execution-receipt",
        "foundation:--foundation-attestation",
        "acquisition-authority:--acquisition-authority",
        "readiness:--readiness-attestation",
        "historical-pre:--historical-pre-snapshot",
        "historical-post:--historical-post-snapshot",
        "handoff:--handoff",
        "evaluation:--evaluation-receipt",
        "comparison:--comparison-review",
        "validation:--validation-attestation",
        "acquisition-root:--acquisition-root",
        "capture-result:--capture-result",
        "successor-decision:--successor-decision",
        "successor-restart:--successor-restart",
        "target:--target",
        "final-selection:--final-selection",
        "pinned-cdp:--pinned-cdp-receipt",
        "browser-egress:--browser-egress-qualification-root",
        "reference:--reference-receipt",
        "code-gate:--code-gate-receipt",
        "controlled-qualification:--controlled-qualification-receipt",
        "pilot-fitting-result:--pilot-fitting-result",
        "pilot-compatibility-result:--pilot-compatibility-result",
        "authoritative-fitting-result:--authoritative-fitting-result",
        "certification-result:--certification-result",
        "acquisition-completion:--acquisition-completion",
        "qualification-checkpoint:--qualification-checkpoint",
        "qualification-sidecar-root:--qualification-sidecar-root",
        "qualification-publication-root:--qualification-publication-root",
        "final-cohort-assembly:--final-cohort-assembly",
        "pilot-cohort-assembly:--pilot-cohort-assembly",
        "campaign-root:--campaign-root",
        "campaign:--campaign",
    }
    option_block = (
        launcher[admission:class_docker]
        .split("for class_build_admission_option in", maxsplit=1)[1]
        .split("; do", maxsplit=1)[0]
    )
    observed_options = re.findall(r"[a-z][a-z-]*:--[a-z][a-z-]*", option_block)
    assert set(observed_options) == expected_options
    assert len(observed_options) == len(expected_options)

    expected_repeatables = {
        "result:class_result_hosts",
        "regression-result:class_regression_result_hosts",
        "controlled-result:class_controlled_result_hosts",
        "canary-result:class_canary_result_hosts",
        "formal-result:class_formal_result_hosts",
        "numeric-bundle:class_numeric_bundle_hosts",
        "prefix-spec-root:class_prefix_spec_root_hosts",
        "qualification-manifest:class_qualification_manifest_hosts",
        "final-bundle:class_final_bundle_hosts",
    }
    repeatable_block = (
        launcher[admission:class_docker]
        .split("for class_build_admission_repeatable in", maxsplit=1)[1]
        .split("; do", maxsplit=1)[0]
    )
    observed_repeatables = re.findall(r"[a-z][a-z-]*:class_[a-z_]+_hosts", repeatable_block)
    assert set(observed_repeatables) == expected_repeatables
    assert len(observed_repeatables) == len(expected_repeatables)


def test_launcher_rejects_root_split_ids_and_dac_override_before_helper_load() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    admission = launcher.split("qcsd_status_uid=()", maxsplit=1)[1].split(
        "readonly qcsd_invoking_uid qcsd_invoking_gid", maxsplit=1
    )[0]

    assert "done </proc/self/status" in admission
    assert "${#qcsd_status_uid[@]} != 4" in admission
    assert "${#qcsd_status_gid[@]} != 4" in admission
    assert '"${qcsd_invoking_uid}" == 0' in admission
    assert '"${qcsd_invoking_gid}" == 0' in admission
    for capability in ("CapInh:", "CapPrm:", "CapEff:", "CapAmb:"):
        assert capability in admission
    assert "[2367aAbBeEfF]$" in admission
    assert "without CAP_DAC_OVERRIDE" in admission
    assert launcher.index("qcsd_status_uid=()") < launcher.index('source "${DOCKER_SUPERVISOR}"')


def test_lifecycle_recover_is_host_only_guarded_reconciliation() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    branch = launcher.split('elif [[ "${1:-}" == "lifecycle-recover" ]]; then', 1)[1].split(
        'elif [[ "${1:-}" != "class-study"', 1
    )[0]
    assert branch.count("require_docker") == 1
    assert "require_submodule" not in branch
    assert "qcsd_run_" not in branch
    assert "docker " not in branch
    assert "exit 0" in branch
    assert branch.index("require_docker") < branch.index("exit 0")

    rejected = subprocess.run(
        [launcher_path, "lifecycle-recover", "unexpected"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert rejected.stderr == "lifecycle-recover accepts no arguments\n"


def test_launcher_selects_prepare_image_only_for_pinned_cdp_test() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    selection = launcher.split('case "${1:-}" in', 1)[1].split(
        "if ! _qcsd_docker_api image inspect", 1
    )[0]
    assert 'test) image="${COLLECTION_IMAGE}"' in selection
    assert '"${2:-}" == "pinned-cdp"' in selection
    assert 'image="${PREPARE_IMAGE}"' in selection
    fit_preflight = launcher.split("verify_fit_neqo_checkout() {", 1)[1].split("\n}", 1)[0]
    assert 'v["neqo_dirty"]' in fit_preflight
    assert 'v["neqo_patch_sha256"]' in fit_preflight
    assert 'git -C "${ROOT}" status' not in fit_preflight
    assert 'git -C "${ROOT}/neqo-qcsd" status' in fit_preflight
    assert '"${head_gitlink}" != "${image_neqo}"' in fit_preflight
    assert '"${index_gitlink}" != "${image_neqo}"' in fit_preflight

    help_result = subprocess.run(
        [launcher_path, "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0
    assert "Usage: qcsd-lab" in help_result.stderr
    assert '"${image_neqo_dirty}" != "false"' in fit_preflight
    usage_contract = launcher.split("usage() {", 1)[1].split("\n}", 1)[0]
    public_command_guards = set(re.findall(r'\[\[ "\$\{1:-\}" == "([a-z][a-z0-9-]*)"', launcher))
    for removed in ("discover", "probe", "collect", "dataset"):
        token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(token, usage_contract) is None
        assert removed not in public_command_guards
    for removed in ("--dev", "--dry-run"):
        token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(token, launcher) is None


def test_browser_egress_launcher_contract_is_canonical_and_prepare_bound() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")

    assert '"${2:-}" == "browser-egress"' in launcher
    assert "create|resume|verify)" in launcher
    assert (
        'browser_egress_result_relative="artifacts/buflo-study/'
        'browser-egress-qualification-v${browser_egress_cohort_version}"'
    ) in launcher
    assert (
        'browser_egress_build_relative="artifacts/buflo-study/'
        'build-execution-v${browser_egress_cohort_version}.json"'
    ) in launcher
    assert 'PREPARE_IMAGE="${browser_egress_prepare_image}"' in launcher
    assert (
        'verify_qualification_checkout "test browser-egress ${browser_egress_action}"' in launcher
    )
    assert "test browser-egress create requires an absent create-only result root" in launcher
    assert "test browser-egress resume rejects a finalized qualification" not in launcher
    assert "test browser-egress verify requires final.json" not in launcher
    assert "browser_egress_reconcile_filesystem" in launcher
    assert 'admit-resume --cohort-version "${browser_egress_cohort_version}"' in launcher
    # Python's bool is an int subclass, and integer 0/1 compare equal to
    # False/True. Both shell-side publication boundaries must nevertheless
    # require the producer's exact JSON Boolean and integer schema types.
    assert launcher.count('type(value.get("assembled")) is not bool') == 2
    assert launcher.count('type(value.get("schema_version")) is not int') >= 2

    help_result = subprocess.run(
        [launcher_path, "test", "browser-egress", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert help_result.returncode == 0
    assert help_result.stderr == ""
    assert "{create|resume|verify}" in help_result.stdout

    rejected = subprocess.run(
        [launcher_path, "test", "browser-egress", "invented"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert "requires exactly one action" in rejected.stderr


def _browser_egress_shell_parser(marker: str, end_marker: str) -> str:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    return launcher.split(marker, maxsplit=1)[1].split(end_marker, maxsplit=1)[0]


def _run_browser_egress_shell_parser(
    tmp_path: Path, code: str, value: dict
) -> subprocess.CompletedProcess[str]:
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(value), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-I", "-c", code, str(receipt)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


def test_browser_egress_shell_prevalidation_parser_requires_exact_json_types(
    tmp_path: Path,
) -> None:
    code = _browser_egress_shell_parser(
        "browser_egress_prevalidate_fields_output=\"$(python3 -I -c '\n",
        '\n\' "${browser_egress_attempt_scratch}/prevalidate.json")"',
    )

    accepted = _run_browser_egress_shell_parser(
        tmp_path, code, {"schema_version": 1, "assembled": True}
    )
    assert accepted.returncode == 0
    assert accepted.stdout == "passed\n"
    assert accepted.stderr == ""

    for malformed in (
        {"schema_version": 1, "assembled": 1},
        {"schema_version": True, "assembled": True},
        {"schema_version": 1, "assembled": True, "unexpected": None},
    ):
        rejected = _run_browser_egress_shell_parser(tmp_path, code, malformed)
        assert rejected.returncode != 0
        assert rejected.stdout == ""
        assert "result is malformed" in rejected.stderr


def test_browser_egress_shell_mutating_parser_requires_discriminated_ack(
    tmp_path: Path,
) -> None:
    code = _browser_egress_shell_parser(
        "browser_egress_assemble_fields_output=\"$(python3 -I -c '\n",
        '\n\' "${browser_egress_attempt_scratch}/assemble.json")"',
    )
    accepted = _run_browser_egress_shell_parser(
        tmp_path,
        code,
        {"schema_version": 1, "assembled": True, "checkpoint": {}},
    )
    assert accepted.returncode == 0
    assert accepted.stdout == "passed\n"
    assert accepted.stderr == ""

    failed = _run_browser_egress_shell_parser(
        tmp_path,
        code,
        {
            "schema_version": 1,
            "assembled": False,
            "failure_code": "packet-policy-failed",
        },
    )
    assert failed.returncode == 0
    assert failed.stdout == "failed\npacket-policy-failed\n"
    assert failed.stderr == ""

    for malformed in (
        {"schema_version": 1, "assembled": True},
        {"schema_version": 1, "assembled": True, "checkpoint": None},
        {"schema_version": 1, "assembled": True, "failure_code": "wrong-branch"},
        {"schema_version": 1, "assembled": False, "checkpoint": {}},
        {"schema_version": 1, "assembled": 1, "checkpoint": {}},
        {"schema_version": True, "assembled": True, "checkpoint": {}},
        {
            "schema_version": 1,
            "assembled": True,
            "checkpoint": {},
            "unexpected": None,
        },
    ):
        rejected = _run_browser_egress_shell_parser(tmp_path, code, malformed)
        assert rejected.returncode != 0
        assert rejected.stdout == ""
        assert "result is malformed" in rejected.stderr


def test_browser_egress_launcher_freezes_five_role_packet_topology() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    block = launcher.split(
        'if [[ "${1:-}" == "test" && "${2:-}" == "browser-egress" &&\n'
        '      ( "${browser_egress_action}" == "create" ||',
        maxsplit=1,
    )[1].split(
        'if [[ "${1:-}" == "test" && "${2:-}" == "pinned-cdp" ]]; then',
        maxsplit=1,
    )[0]

    assert "--internal --ipv6" in block
    assert "--subnet 172.30.98.0/24" in block
    assert "--subnet fd00:71:63:73:64:98::/96" in block
    assert "--dns 172.30.98.53 --dns fd00:71:63:73:64:98:0:53" in block
    for role in ("browser", "observer", "fixture", "forbidden_sink", "dns_sink"):
        assert block.count(f"--label org.qcsd.role={role}") == 1
    assert "tcp-sink" not in block
    assert "udp-sink" not in block
    assert "forbidden-sink --vector-id" in block
    assert '--network "container:${browser_egress_browser_id}" --user 0:0' in block
    assert "--cap-drop ALL --cap-add NET_RAW" in block
    assert '--user "${qcsd_invoking_uid}:${qcsd_invoking_gid}"' in block
    assert "requires a numeric non-root invoking UID and GID" in block
    assert "browser_egress_cleanup_topology" in block


def test_browser_egress_signal_coordinated_roles_are_direct_tini_children() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    role_common = launcher.split("browser_egress_role_common=(", maxsplit=1)[1].split(
        "\n    )", maxsplit=1
    )[0]
    observer = launcher.split(
        'docker run --name "${browser_egress_name_prefix}-observer"', maxsplit=1
    )[1].split('docker run --name "${browser_egress_name_prefix}-fixture"', maxsplit=1)[0]

    assert "/usr/bin/timeout" not in role_common
    assert '"${browser_egress_tool}"' in role_common
    assert "/usr/bin/timeout" not in observer
    assert '"${browser_egress_tool}" observer' in observer
    assert "_qcsd_docker_api wait" not in launcher
    exit_wait = launcher.split("browser_egress_wait_exit_code() {", maxsplit=1)[1].split(
        "\n}", maxsplit=1
    )[0]
    role_deadline = int(
        re.search(
            r"^readonly browser_egress_role_deadline_seconds=([0-9]+)$",
            launcher,
            re.MULTILINE,
        ).group(1)
    )
    observation_grace = int(
        re.search(
            r"^readonly browser_egress_role_exit_observation_grace_seconds=([0-9]+)$",
            launcher,
            re.MULTILINE,
        ).group(1)
    )
    assert role_deadline == 300
    assert observation_grace == 15
    assert role_deadline > 2 * 120
    assert (
        "browser_egress_role_exit_wait_seconds=$((\n"
        "  browser_egress_role_deadline_seconds +\n"
        "  browser_egress_role_exit_observation_grace_seconds\n"
        "))" in launcher
    )
    assert "deadline=$((SECONDS + browser_egress_role_exit_wait_seconds))" in exit_wait
    assert "_qcsd_docker_api container inspect --format" in exit_wait
    assert "exited|dead)" in exit_wait
    assert "exit code is invalid" in exit_wait
    assert launcher.count('--role-deadline-seconds "${browser_egress_role_deadline_seconds}"') == 5

    tool = (Path(__file__).parents[1] / "tools/browser_egress_qualification.py").read_text(
        encoding="utf-8"
    )
    assert "deadline = time.monotonic() + float(timeout_seconds)" in tool
    assert "os._exit(SIGNAL_COORDINATED_ROLE_TIMEOUT_EXIT_CODE)" in tool
    assert 'parser.add_argument("--role-deadline-seconds", type=int, required=True)' in tool
    assert 'observer.add_argument("--role-deadline-seconds", type=int, required=True)' in tool
    assert "timeout_seconds=args.role_deadline_seconds" in tool


def test_browser_egress_same_build_comparison_anchors_relative_binding_to_lab_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_path = Path(__file__).parents[1] / "tools/browser_egress_qualification.py"
    namespace = runpy.run_path(str(tool_path), run_name="qcsd_browser_egress_build_test")
    require_same_build = namespace["_require_same_current_build"]
    lab_root = namespace["LAB_ROOT"]
    cohort = 47
    receipt_relative = f"artifacts/buflo-study/build-execution-v{cohort}.json"
    completion_relative = f"artifacts/buflo-study/build-completion-v{cohort}.json"
    binding = {
        "path": receipt_relative,
        "sha256": "a" * 64,
        "completion_path": f"/lab/{completion_relative}",
        "completion_sha256": "b" * 64,
    }
    expected = {
        "path": str((lab_root / receipt_relative).resolve()),
        "sha256": "a" * 64,
        "completion_path": str((lab_root / completion_relative).resolve()),
        "completion_sha256": "b" * 64,
    }

    # The installed tool runs from /opt/qcsd-lab while evidence is mounted at
    # /lab.  Matching must therefore be independent of the process CWD.
    monkeypatch.chdir(tmp_path)
    require_same_build(binding, expected, cohort_version=cohort, operation="resume")

    for field, forged in (
        ("path", f"/lab/{receipt_relative}"),
        ("completion_path", "/lab/artifacts/buflo-study/build-completion-v48.json"),
    ):
        changed = dict(binding)
        changed[field] = forged
        with pytest.raises(ValueError, match="different build execution"):
            require_same_build(
                changed,
                expected,
                cohort_version=cohort,
                operation="resume",
            )


def test_browser_egress_internal_role_watchdog_cancels_or_exits_124() -> None:
    tool_path = Path(__file__).parents[1] / "tools/browser_egress_qualification.py"
    namespace = runpy.run_path(str(tool_path), run_name="qcsd_browser_egress_watchdog_test")
    run_role = namespace["_run_signal_coordinated_role"]
    called: list[bool] = []
    run_role(lambda _args: called.append(True), SimpleNamespace(), timeout_seconds=1)
    assert called == [True]
    for malformed in (0, -1, float("nan"), float("inf"), 10**20, 10**10_000):
        with pytest.raises(ValueError, match="finite positive bound"):
            run_role(lambda _args: None, SimpleNamespace(), timeout_seconds=malformed)
    with pytest.raises(TypeError, match="must be numeric"):
        run_role(lambda _args: None, SimpleNamespace(), timeout_seconds=True)

    role_parser = namespace["parser"]()
    parsed = role_parser.parse_args(
        [
            "actor",
            "--vector-id",
            "constructor--page--websocket",
            "--role-deadline-seconds",
            "300",
        ]
    )
    assert parsed.role_deadline_seconds == 300
    with pytest.raises(SystemExit):
        role_parser.parse_args(["actor", "--vector-id", "constructor--page--websocket"])

    expired = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy,time; "
                f"v=runpy.run_path({str(tool_path)!r},run_name='qcsd_watchdog_expiry'); "
                "v['_run_signal_coordinated_role'](lambda _: time.sleep(10),None,"
                "timeout_seconds=0.05)"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    assert expired.returncode == 124, (expired.stdout, expired.stderr)
    assert expired.stdout == ""
    assert expired.stderr == "browser-egress role exceeded its monotonic hard deadline\n"


def test_real_docker_tini_direct_child_receives_all_browser_egress_phase_signals() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    probe = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Docker daemon is unavailable")
    image = os.environ.get("QCSD_BROWSER_EGRESS_SIGNAL_TEST_IMAGE", "neqo-qcsd-lab-prepare:local")
    image_probe = subprocess.run(
        [docker, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if image_probe.returncode != 0:
        pytest.skip(f"browser-egress signal-test image is unavailable: {image}")

    name = f"qcsd-browser-egress-signal-test-{os.getpid()}-{uuid.uuid4().hex}"
    program = (
        "import json,signal,time\n"
        "seen=[]\n"
        "def receive(number, _frame):\n"
        "    name=signal.Signals(number).name\n"
        "    seen.append(name)\n"
        "    print('SIGNAL '+name,flush=True)\n"
        "for item in (signal.SIGUSR1,signal.SIGUSR2,signal.SIGHUP,signal.SIGALRM,signal.SIGTERM):\n"
        "    signal.signal(item,receive)\n"
        "print('READY',flush=True)\n"
        "deadline=time.monotonic()+15\n"
        "while len(seen)<5 and time.monotonic()<deadline:\n"
        "    time.sleep(0.01)\n"
        "print(json.dumps({'signals':seen},sort_keys=True),flush=True)\n"
        "raise SystemExit(0 if len(seen)==5 else 124)\n"
    )
    try:
        launched = subprocess.run(
            [
                docker,
                "run",
                "--detach",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "/usr/bin/tini",
                image,
                "--",
                "/usr/bin/python3",
                "-c",
                program,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )
        assert launched.returncode == 0, (launched.stdout, launched.stderr)
        deadline = time.monotonic() + 10
        logs = ""
        while time.monotonic() < deadline:
            logs = subprocess.run(
                [docker, "logs", name], capture_output=True, text=True, check=False
            ).stdout
            if "READY\n" in logs:
                break
            time.sleep(0.05)
        assert "READY\n" in logs

        for phase_signal in ("USR1", "USR2", "HUP", "ALRM", "TERM"):
            delivered = subprocess.run(
                [docker, "kill", "--signal", phase_signal, name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
            )
            assert delivered.returncode == 0, (delivered.stdout, delivered.stderr)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                logs = subprocess.run(
                    [docker, "logs", name], capture_output=True, text=True, check=False
                ).stdout
                if f"SIGNAL SIG{phase_signal}\n" in logs:
                    break
                time.sleep(0.05)
            assert f"SIGNAL SIG{phase_signal}\n" in logs

        waited = subprocess.run(
            [docker, "wait", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
        assert waited.returncode == 0 and waited.stdout == "0\n", (
            waited.stdout,
            waited.stderr,
        )
        final_logs = subprocess.run(
            [docker, "logs", name], capture_output=True, text=True, check=False
        ).stdout.splitlines()
        assert json.loads(final_logs[-1]) == {
            "signals": ["SIGUSR1", "SIGUSR2", "SIGHUP", "SIGALRM", "SIGTERM"]
        }
    finally:
        subprocess.run(
            [docker, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )


def _browser_egress_extraction_shell_function() -> str:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    return (
        "browser_egress_extract_observer_pcap() {"
        + launcher.split("browser_egress_extract_observer_pcap() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_wait_container_marker()", maxsplit=1
        )[0]
        + "\n}\n"
    )


def _browser_egress_shell_function(name: str, next_name: str) -> str:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    return (
        f"{name}() {{"
        + launcher.split(f"{name}() {{", maxsplit=1)[1].split(
            f"\n}}\n\n{next_name}()", maxsplit=1
        )[0]
        + "\n}\n"
    )


def _browser_egress_extraction_receipt(tmp_path: Path, payload: bytes) -> tuple[Path, str]:
    evidence_relative = "evidence/001--constructor--page--websocket/attempt-1/capture.pcapng"
    receipt = tmp_path / "capture.json"
    receipt.write_text(
        json.dumps(
            {
                "role": "observer",
                "receipt": {
                    "pcap": {
                        "path": evidence_relative,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size_bytes": len(payload),
                    }
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return receipt, evidence_relative


def _browser_egress_capture_closure(tmp_path: Path, payload: bytes) -> tuple[Path, str]:
    evidence_relative = "evidence/001--constructor--page--websocket/attempt-1/capture.pcapng"
    vector_id = "constructor--page--websocket"
    closure = tmp_path / "capture-closure.json"
    closure.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "role": "observer",
                "vector_id": vector_id,
                "capture_closure": {
                    "schema_version": 1,
                    "artifact_type": "qcsd-browser-egress-capture-closure",
                    "vector_id": vector_id,
                    "pcap": {
                        "path": evidence_relative,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size_bytes": len(payload),
                    },
                    "observer": {
                        "network_namespace": "browser",
                        "interface": "any",
                        "capture_filter": None,
                        "privileged": False,
                        "cap_drop": ["ALL"],
                        "cap_add": ["CAP_NET_RAW"],
                        "separate_container": True,
                    },
                    "capture_process_terminal": {
                        "exit_code": 0,
                        "stderr": (
                            "Packets captured: 1\n"
                            "Packets received/dropped on interface 'any': "
                            "1/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n"
                        ),
                    },
                    "capture_tool": {
                        "path": "/usr/bin/dumpcap",
                        "sha256": "a" * 64,
                        "version_first_line": "Dumpcap 4.0",
                        "argv": [
                            "/usr/bin/dumpcap",
                            "-q",
                            "-i",
                            "any",
                            "-w",
                            "<PCAP>",
                        ],
                    },
                    "chronology": {
                        "observer_started_ns": 1,
                        "observer_ready_ns": 2,
                        "subject_started_ns": 3,
                        "subject_exited_ns": 4,
                        "reporting_grace_finished_ns": 5_000_000_004,
                        "observer_stopped_ns": 5_000_000_005,
                    },
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    closure.chmod(0o600)
    return closure, evidence_relative


def test_browser_egress_observer_protocol_extracts_closed_pcap_before_exit() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    measured = launcher.split(
        '_qcsd_docker_api kill --signal USR2 "${browser_egress_observer_id}"',
        maxsplit=1,
    )[1].split(
        '_qcsd_docker_api logs "${browser_egress_browser_id}"',
        maxsplit=1,
    )[0]

    grace = measured.index("qcsd-browser-egress-grace.ready")
    fixture_stop = measured.index('for browser_egress_role_id in "${browser_egress_fixture_id}"')
    finish = measured.index('kill --signal HUP "${browser_egress_observer_id}"')
    closed = measured.index("qcsd-browser-egress-capture-closed.ready")
    closure = measured.index("browser_egress_fetch_observer_capture_closure")
    extract = measured.index('browser_egress_extract_observer_pcap "${browser_egress_observer_id}"')
    acknowledge = measured.index('kill --signal ALRM "${browser_egress_observer_id}"')
    finalise = measured.index("browser_egress_wait_observer_finalisation")
    receipt = measured.index("browser_egress_wait_observer_receipt")
    stop = measured.index('kill --signal TERM "${browser_egress_observer_id}"')
    wait = measured.index('browser_egress_observer_exit="$(browser_egress_wait_exit_code')
    assert (
        grace
        < fixture_stop
        < finish
        < closed
        < closure
        < extract
        < acknowledge
        < finalise
        < receipt
        < stop
        < wait
    )
    assert '"${browser_egress_evidence_relative}" || false' in measured
    assert 'cp "${browser_egress_observer_id}:/tmp/capture.pcapng"' not in measured


@pytest.mark.parametrize(
    ("analysis_fails", "policy_failure"), [(False, False), (True, False), (True, True)]
)
def test_browser_egress_observer_two_phase_close_survives_analysis_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    analysis_fails: bool,
    policy_failure: bool,
) -> None:
    tool_path = Path(__file__).parents[1] / "tools/browser_egress_qualification.py"
    namespace = runpy.run_path(str(tool_path), run_name="qcsd_browser_egress_observer_test")
    observer_function = namespace["_observer"]
    role_globals = observer_function.__globals__
    payload = b"closed capture bytes"
    source_root = tmp_path / "closure-source"
    source_root.mkdir(mode=0o700)
    closure_path, _evidence_relative = _browser_egress_capture_closure(source_root, payload)
    closure = json.loads(closure_path.read_text(encoding="utf-8"))["capture_closure"]
    sequence: list[str] = []
    emitted: list[dict] = []

    class FakeObserver:
        def __init__(self, *, pcap_path: Path) -> None:
            assert pcap_path == tmp_path / "capture.pcapng"

        def start(self) -> None:
            sequence.append("start")

        def mark_subject_started(self) -> None:
            sequence.append("subject-started")

        def mark_subject_exited(self) -> None:
            sequence.append("subject-exited")

        def mark_reporting_grace_finished(self) -> None:
            sequence.append("grace-finished")

        def close_capture(self, **_kwargs: object) -> dict:
            sequence.append("close")
            return closure

        def finish_closed_capture(self, **_kwargs: object) -> dict:
            sequence.append("analyse")
            if analysis_fails:
                if policy_failure:
                    raise role_globals["PacketPolicyError"]("synthetic packet policy failure")
                raise ValueError("synthetic post-capture analysis failure")
            return {"schema_version": 2, "pcap": closure["pcap"]}

    closure_destination = tmp_path / "published-closure.json"
    closed_marker = tmp_path / "capture-closed.ready"
    failed_marker = tmp_path / "analysis-failed.ready"
    policy_marker = tmp_path / "policy-failed.ready"
    receipt_marker = tmp_path / "receipt.ready"
    monkeypatch.setitem(role_globals, "LivePacketObserver", FakeObserver)
    monkeypatch.setitem(role_globals, "CAPTURE_CLOSURE_PATH", closure_destination)
    monkeypatch.setitem(role_globals, "CAPTURE_CLOSED_READY_PATH", closed_marker)
    monkeypatch.setitem(role_globals, "CAPTURE_ANALYSIS_FAILED_READY_PATH", failed_marker)
    monkeypatch.setitem(role_globals, "CAPTURE_POLICY_FAILED_READY_PATH", policy_marker)
    monkeypatch.setitem(role_globals, "RECEIPT_READY_PATH", receipt_marker)
    monkeypatch.setitem(role_globals, "SUBJECT_STARTED_READY_PATH", tmp_path / "subject.ready")
    monkeypatch.setitem(role_globals, "GRACE_READY_PATH", tmp_path / "grace.ready")
    monkeypatch.setitem(role_globals, "_ready", lambda: sequence.append("ready"))
    monkeypatch.setitem(role_globals, "_wait", lambda _event: sequence.append("wait"))
    monkeypatch.setitem(role_globals, "_install_stop_event", lambda: object())
    monkeypatch.setitem(role_globals, "_emit", lambda value: emitted.append(dict(value)))
    monkeypatch.setattr(role_globals["time"], "sleep", lambda _seconds: None)
    monkeypatch.setattr(role_globals["signal"], "signal", lambda *_args: None)
    args = SimpleNamespace(
        vector_id="constructor--page--websocket",
        pcap=tmp_path / "capture.pcapng",
        evidence_relative=closure["pcap"]["path"],
    )

    if analysis_fails:
        with pytest.raises(SystemExit) as error:
            observer_function(args)
        assert error.value.code == 1
        selected_marker = policy_marker if policy_failure else failed_marker
        unselected_marker = failed_marker if policy_failure else policy_marker
        assert selected_marker.read_text(encoding="ascii") == "failed\n"
        assert not unselected_marker.exists()
        assert not receipt_marker.exists()
        assert emitted == []
        assert sequence[-2:] == ["analyse", "wait"]
    else:
        observer_function(args)
        assert not failed_marker.exists()
        assert not policy_marker.exists()
        assert receipt_marker.read_text(encoding="ascii") == "ready\n"
        assert len(emitted) == 1 and emitted[0]["role"] == "observer"
        assert sequence[-3:] == ["wait", "analyse", "wait"]
    published = json.loads(closure_destination.read_text(encoding="utf-8"))
    assert published["capture_closure"] == closure
    assert closed_marker.read_text(encoding="ascii") == "ready\n"
    assert sequence.index("close") < sequence.index("analyse")


@pytest.mark.parametrize(
    ("marker", "expected_status"),
    [("receipt", 0), ("analysis-failed", 1), ("policy-failed", 1)],
)
def test_browser_egress_observer_finalisation_distinguishes_analysis_failure(
    tmp_path: Path,
    marker: str,
    expected_status: int,
) -> None:
    finalisation = _browser_egress_shell_function(
        "browser_egress_wait_observer_finalisation",
        "browser_egress_wait_exit_code",
    )
    script = tmp_path / f"finalisation-{marker}.sh"
    script.write_text(
        "set -euo pipefail\n"
        + finalisation
        + f"MARKER={marker!r}\n"
        + "browser_egress_failure_verdict=operational-failure\n"
        + "browser_egress_failure_code=capture-process-failed\n"
        + "browser_egress_failure_stage=capture-finalization\n"
        + "_qcsd_docker_api() {\n"
        + '  if [[ "$1" == exec && "$5" == /tmp/qcsd-browser-egress-receipt.ready ]]; '
        + 'then [[ "$MARKER" == receipt ]]; return; fi\n'
        + '  if [[ "$1" == exec && "$5" == '
        + '/tmp/qcsd-browser-egress-capture-policy-failed.ready ]]; '
        + 'then [[ "$MARKER" == policy-failed ]]; return; fi\n'
        + '  if [[ "$1" == exec && "$5" == '
        + '/tmp/qcsd-browser-egress-capture-analysis-failed.ready ]]; '
        + 'then [[ "$MARKER" == analysis-failed ]]; return; fi\n'
        + '  if [[ "$1 $2" == "container inspect" ]]; then echo running; return; fi\n'
        + "  return 90\n"
        + "}\n"
        + "if browser_egress_wait_observer_finalisation observer; then result=0; "
        + "else result=$?; fi\n"
        + 'printf "%s %s %s\\n" "$browser_egress_failure_verdict" '
        + '"$browser_egress_failure_code" "$browser_egress_failure_stage"\n'
        + 'exit "$result"\n',
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == expected_status
    if marker == "analysis-failed":
        assert "rejected the closed capture during analysis" in completed.stderr
    elif marker == "policy-failed":
        assert "rejected the closed capture packet policy" in completed.stderr
    else:
        assert completed.stderr == ""
    assert completed.stdout.strip() == (
        "semantic-failure packet-policy-failed packet-policy"
        if marker == "policy-failed"
        else "operational-failure capture-process-failed capture-finalization"
    )


def test_browser_egress_runtime_projection_declares_stdout_destination() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    projection = launcher.split(
        "    browser_egress_failure_stage=runtime-projection\n", maxsplit=1
    )[1].split(
        "    printf '%s\\n' \"${QCSD_DOCKER_OUTPUT_BROWSER_EGRESS_RUNTIME}\"",
        maxsplit=1,
    )[0]

    initialise = projection.index('    QCSD_DOCKER_OUTPUT_BROWSER_EGRESS_RUNTIME=""\n')
    capture = projection.index(
        "    qcsd_capture_attached_docker_output QCSD_DOCKER_OUTPUT_BROWSER_EGRESS_RUNTIME"
    )
    assert initialise < capture


def test_browser_egress_runtime_projection_uses_live_and_terminal_snapshots() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    vector_loop = launcher.split('browser_egress_policy_volume_name=""', maxsplit=1)[1].split(
        "    browser_egress_finished_at=", maxsplit=1
    )[0]
    final_readiness = vector_loop.index('browser_egress_wait_healthy "${browser_egress_dns_id}"')
    network_snapshot = vector_loop.index("network inspect --format '{{json .}}'", final_readiness)
    topology_snapshot = vector_loop.index(
        '"${browser_egress_attempt_scratch}/topology-containers.json"',
        network_snapshot,
    )
    first_action = vector_loop.index(
        'kill --signal USR1 "${browser_egress_observer_id}"', topology_snapshot
    )
    observer_exit = vector_loop.index(
        'browser_egress_observer_exit="$(browser_egress_wait_exit_code', first_action
    )
    terminal_snapshot = vector_loop.index(
        '"${browser_egress_attempt_scratch}/terminal-containers.json"', observer_exit
    )
    runtime_projection = vector_loop.index("project-runtime", terminal_snapshot)

    assert final_readiness < network_snapshot < topology_snapshot < first_action
    assert first_action < observer_exit < terminal_snapshot < runtime_projection
    assert '"${browser_egress_network_id}"' in vector_loop[network_snapshot:topology_snapshot]
    assert (
        '>"${browser_egress_attempt_scratch}/network.json"'
        in vector_loop[network_snapshot:topology_snapshot]
    )
    assert (
        "--topology-container-inspect-json /qcsd-input/topology-containers.json"
        in vector_loop[terminal_snapshot:]
    )
    assert (
        "--terminal-container-inspect-json /qcsd-input/terminal-containers.json"
        in vector_loop[terminal_snapshot:]
    )
    assert "--container-inspect-json /qcsd-input/containers.json" not in vector_loop


def test_browser_egress_observer_pcap_extraction_streams_tmpfs_privately(
    tmp_path: Path,
) -> None:
    extraction = _browser_egress_extraction_shell_function()
    payload = bytes.fromhex("0a0d0d0a0000001c1a2b3c4d00000000ff")
    receipt, evidence_relative = _browser_egress_extraction_receipt(tmp_path, payload)
    destination = tmp_path / "capture.pcapng"
    script = tmp_path / "extract.sh"
    script.write_text(
        "set -euo pipefail\n"
        + extraction
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + "_qcsd_docker_api() {\n"
        + '  [[ "$1" == exec && "$2" == observer && "$3" == /bin/cat && '
        + '"$4" == -- && "$5" == /tmp/capture.pcapng ]]\n'
        + "  /usr/bin/python3 -I -c "
        + f"'import sys;sys.stdout.buffer.write(bytes.fromhex(\"{payload.hex()}\"))'\n"
        + "}\n"
        + "browser_egress_extract_observer_pcap observer "
        + f"{str(destination)!r} {str(receipt)!r} {evidence_relative!r}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert destination.read_bytes() == payload
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.stat().st_nlink == 1


def test_browser_egress_fetches_create_only_canonical_capture_closure(
    tmp_path: Path,
) -> None:
    fetch = _browser_egress_shell_function(
        "browser_egress_fetch_observer_capture_closure",
        "browser_egress_extract_observer_pcap",
    )
    payload = b"closed capture bytes"
    source_root = tmp_path / "source"
    destination_root = tmp_path / "scratch"
    source_root.mkdir(mode=0o700)
    destination_root.mkdir(mode=0o700)
    source, evidence_relative = _browser_egress_capture_closure(source_root, payload)
    destination = destination_root / "capture-closure.json"
    script = tmp_path / "fetch-closure.sh"
    script.write_text(
        "set -euo pipefail\n"
        + fetch
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + "_qcsd_docker_api() {\n"
        + '  [[ "$1" == exec && "$2" == observer && "$3" == /bin/cat && '
        + '"$4" == -- && "$5" == /tmp/qcsd-browser-egress-capture-closure.json ]]\n'
        + f"  /bin/cat -- {str(source)!r}\n"
        + "}\n"
        + "browser_egress_fetch_observer_capture_closure observer "
        + f"{str(destination)!r} {evidence_relative!r} "
        + "constructor--page--websocket\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert destination.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.stat().st_nlink == 1

    repeated = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert repeated.returncode != 0
    assert "destination is unsafe" in repeated.stderr
    assert destination.read_bytes() == source.read_bytes()


def test_browser_egress_observer_pcap_extraction_accepts_capture_closure(
    tmp_path: Path,
) -> None:
    extraction = _browser_egress_extraction_shell_function()
    payload = b"closed capture bytes"
    closure, evidence_relative = _browser_egress_capture_closure(tmp_path, payload)
    evidence_parent = tmp_path / "attempt"
    evidence_parent.mkdir(mode=0o700)
    destination = evidence_parent / "capture.pcapng"
    script = tmp_path / "extract-from-closure.sh"
    script.write_text(
        "set -euo pipefail\n"
        + extraction
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + "_qcsd_docker_api() {\n"
        + '  [[ "$1" == exec && "$2" == observer && "$3" == /bin/cat && '
        + '"$4" == -- && "$5" == /tmp/capture.pcapng ]]\n'
        + "  printf %s 'closed capture bytes'\n"
        + "}\n"
        + "browser_egress_extract_observer_pcap observer "
        + f"{str(destination)!r} {str(closure)!r} {evidence_relative!r}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert destination.read_bytes() == payload
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_browser_egress_capture_closure_is_failure_only_and_idempotently_preserved(
    tmp_path: Path,
) -> None:
    preserve = _browser_egress_shell_function(
        "browser_egress_preserve_capture_closure",
        "browser_egress_preserve_causal_evidence",
    )
    payload = b"closed capture bytes"
    scratch = tmp_path / "scratch"
    attempt = tmp_path / "attempt"
    scratch.mkdir(mode=0o700)
    attempt.mkdir(mode=0o700)
    closure, evidence_relative = _browser_egress_capture_closure(scratch, payload)
    capture = attempt / "capture.pcapng"
    capture.write_bytes(payload)
    capture.chmod(0o600)
    destination = attempt / "capture-closure.json"
    script = tmp_path / "preserve-closure.sh"
    script.write_text(
        "set -euo pipefail\n"
        + preserve
        + f"browser_egress_attempt_scratch={str(scratch)!r}\n"
        + f"browser_egress_attempt_evidence_host={str(attempt)!r}\n"
        + f"browser_egress_evidence_host={str(capture)!r}\n"
        + f"browser_egress_evidence_relative={evidence_relative!r}\n"
        + "browser_egress_vector_id=constructor--page--websocket\n"
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + "browser_egress_preserve_capture_closure\n",
        encoding="utf-8",
    )
    for _ in range(2):
        completed = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
        )
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert destination.read_bytes() == closure.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.stat().st_nlink == 1

    destination.write_bytes(b"conflicting evidence")
    destination.chmod(0o600)
    conflict = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert conflict.returncode != 0
    assert "conflicts" in conflict.stderr
    assert destination.read_bytes() == b"conflicting evidence"


def test_real_docker_browser_egress_extractor_streams_tmpfs_bytes(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    probe = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Docker daemon is unavailable")
    image = os.environ.get("QCSD_BROWSER_EGRESS_SIGNAL_TEST_IMAGE", "neqo-qcsd-lab-prepare:local")
    image_probe = subprocess.run(
        [docker, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if image_probe.returncode != 0:
        pytest.skip(f"browser-egress extraction-test image is unavailable: {image}")

    extraction = _browser_egress_extraction_shell_function()
    payload = bytes.fromhex("0a0d0d0a0000001c1a2b3c4d00ff807f0000001c")
    receipt, evidence_relative = _browser_egress_extraction_receipt(tmp_path, payload)
    destination = tmp_path / "capture.pcapng"
    name = f"qcsd-browser-egress-tmpfs-test-{os.getpid()}-{uuid.uuid4().hex}"
    program = (
        "from pathlib import Path\n"
        "import time\n"
        f"Path('/tmp/capture.pcapng').write_bytes(bytes.fromhex('{payload.hex()}'))\n"
        "print('READY', flush=True)\n"
        "time.sleep(30)\n"
    )
    try:
        launched = subprocess.run(
            [
                docker,
                "run",
                "--detach",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "/usr/bin/python3",
                image,
                "-c",
                program,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )
        assert launched.returncode == 0, (launched.stdout, launched.stderr)
        deadline = time.monotonic() + 10
        logs = ""
        while time.monotonic() < deadline:
            logs = subprocess.run(
                [docker, "logs", name], capture_output=True, text=True, check=False
            ).stdout
            if logs == "READY\n":
                break
            time.sleep(0.05)
        assert logs == "READY\n"
        filesystem = subprocess.run(
            [docker, "exec", name, "/usr/bin/findmnt", "-n", "-o", "FSTYPE", "/tmp"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert filesystem.returncode == 0, (filesystem.stdout, filesystem.stderr)
        assert filesystem.stdout.strip() == "tmpfs"
        script = tmp_path / "real-extract.sh"
        script.write_text(
            "set -euo pipefail\n"
            + extraction
            + f"qcsd_invoking_uid={os.getuid()}\n"
            + f"qcsd_invoking_gid={os.getgid()}\n"
            + f'_qcsd_docker_api() {{ {shlex.quote(docker)} "$@"; }}\n'
            + "browser_egress_extract_observer_pcap "
            + f"{shlex.quote(name)} {str(destination)!r} {str(receipt)!r} "
            + f"{evidence_relative!r}\n",
            encoding="utf-8",
        )
        extracted = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        assert extracted.returncode == 0, (extracted.stdout, extracted.stderr)
        assert destination.read_bytes() == payload
        assert (
            hashlib.sha256(destination.read_bytes()).hexdigest()
            == hashlib.sha256(payload).hexdigest()
        )
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        state = subprocess.run(
            [docker, "container", "inspect", "--format", "{{.State.Status}}", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert state.returncode == 0 and state.stdout == "running\n"
    finally:
        subprocess.run(
            [docker, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )


def test_real_docker_network_container_inspection_has_two_phase_shape() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    probe = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Docker daemon is unavailable")
    image = os.environ.get("QCSD_BROWSER_EGRESS_SIGNAL_TEST_IMAGE", "neqo-qcsd-lab-prepare:local")
    image_probe = subprocess.run(
        [docker, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if image_probe.returncode != 0:
        pytest.skip(f"browser-egress topology-test image is unavailable: {image}")

    token = uuid.uuid4().hex
    network_name = f"qcsd-network-mode-test-{token}"
    owner_name = f"qcsd-network-mode-owner-{token}"
    observer_name = f"qcsd-network-mode-observer-{token}"
    program = (
        "import signal\n"
        "def stop(*_args):\n"
        "    raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "print('READY', flush=True)\n"
        "signal.pause()\n"
    )

    def checked_docker(*arguments: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [docker, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
        assert completed.returncode == 0, (arguments, completed.stdout, completed.stderr)
        return completed

    try:
        checked_docker("network", "create", "--internal", network_name)
        owner_id = checked_docker(
            "run",
            "--detach",
            "--name",
            owner_name,
            "--network",
            network_name,
            "--entrypoint",
            "/usr/bin/python3",
            image,
            "-c",
            program,
        ).stdout.strip()
        observer_id = checked_docker(
            "run",
            "--detach",
            "--name",
            observer_name,
            "--network",
            f"container:{owner_id}",
            "--entrypoint",
            "/usr/bin/python3",
            image,
            "-c",
            program,
        ).stdout.strip()
        for container_name in (owner_name, observer_name):
            deadline = time.monotonic() + 10
            logs = ""
            while time.monotonic() < deadline:
                logs = checked_docker("container", "logs", container_name).stdout
                if logs == "READY\n":
                    break
                time.sleep(0.05)
            assert logs == "READY\n"

        live_network = json.loads(
            checked_docker("network", "inspect", "--format", "{{json .}}", network_name).stdout
        )
        live_containers = json.loads(
            checked_docker("container", "inspect", owner_id, observer_id).stdout
        )
        assert isinstance(live_network, dict)
        assert set(live_network["Containers"]) == {owner_id}
        assert [container["State"]["Status"] for container in live_containers] == [
            "running",
            "running",
        ]
        assert [container["State"]["Running"] for container in live_containers] == [
            True,
            True,
        ]
        owner, observer = live_containers
        assert owner["HostConfig"]["NetworkMode"] == network_name
        assert observer["HostConfig"]["NetworkMode"] == f"container:{owner_id}"
        assert set(owner["NetworkSettings"]["Networks"]) == {network_name}
        assert observer["NetworkSettings"]["Networks"] == {}
        owner_namespace = checked_docker(
            "container", "exec", owner_id, "/usr/bin/readlink", "/proc/1/ns/net"
        ).stdout.strip()
        observer_namespace = checked_docker(
            "container", "exec", observer_id, "/usr/bin/readlink", "/proc/1/ns/net"
        ).stdout.strip()
        assert owner_namespace.startswith("net:[") and owner_namespace.endswith("]")
        assert observer_namespace == owner_namespace
        owner_attachment = owner["NetworkSettings"]["Networks"][network_name]
        live_member = live_network["Containers"][owner_id]
        assert owner_attachment["NetworkID"] == live_network["Id"]
        assert owner_attachment["EndpointID"] == live_member["EndpointID"] != ""
        assert owner_attachment["IPAddress"] != ""
        assert live_member["IPv4Address"].startswith(owner_attachment["IPAddress"] + "/")

        checked_docker("container", "stop", "--time", "5", observer_id, owner_id, timeout=20)
        terminal_network = json.loads(
            checked_docker("network", "inspect", "--format", "{{json .}}", network_name).stdout
        )
        terminal_containers = json.loads(
            checked_docker("container", "inspect", owner_id, observer_id).stdout
        )
        assert terminal_network["Containers"] == {}
        for live, terminal in zip(live_containers, terminal_containers, strict=True):
            assert terminal["State"]["Running"] is False
            assert terminal["State"]["Status"] == "exited"
            assert terminal["State"]["ExitCode"] == 0
            for field in ("Id", "Name", "Image", "Config", "HostConfig", "Mounts"):
                assert live[field] == terminal[field]
        terminal_owner, terminal_observer = terminal_containers
        terminal_attachment = terminal_owner["NetworkSettings"]["Networks"][network_name]
        assert terminal_attachment["NetworkID"] == live_network["Id"]
        assert terminal_attachment["EndpointID"] == ""
        assert terminal_attachment["IPAddress"] == ""
        assert terminal_observer["NetworkSettings"]["Networks"] == {}
    finally:
        cleanup_commands = (
            ([docker, "container", "rm", "--force", observer_name], 10),
            ([docker, "container", "rm", "--force", owner_name], 10),
            ([docker, "network", "rm", network_name], 10),
        )
        for command, timeout in cleanup_commands:
            try:
                subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                continue


@pytest.mark.parametrize(
    "docker_body",
    ("printf partial; return 23", "printf complete-capturf"),
)
def test_browser_egress_observer_pcap_extraction_rejects_invalid_stream(
    tmp_path: Path,
    docker_body: str,
) -> None:
    extraction = _browser_egress_extraction_shell_function()
    expected = b"complete-capture"
    receipt, evidence_relative = _browser_egress_extraction_receipt(tmp_path, expected)
    destination = tmp_path / "capture.pcapng"
    script = tmp_path / "extract-failure.sh"
    script.write_text(
        "set -euo pipefail\n"
        + extraction
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + f"_qcsd_docker_api() {{ {docker_body}; }}\n"
        + "if browser_egress_extract_observer_pcap observer "
        + f"{str(destination)!r} {str(receipt)!r} {evidence_relative!r}; "
        + "then exit 99; fi\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert "PCAP stream extraction failed" in completed.stderr
    assert not destination.exists()


@pytest.mark.parametrize(
    "unsafe_case",
    ("receipt-symlink", "existing-destination", "wrong-parent-mode", "wrong-relative"),
)
def test_browser_egress_observer_pcap_extraction_rejects_unsafe_paths(
    tmp_path: Path,
    unsafe_case: str,
) -> None:
    extraction = _browser_egress_extraction_shell_function()
    payload = b"complete-capture"
    receipt, evidence_relative = _browser_egress_extraction_receipt(tmp_path, payload)
    evidence_parent = tmp_path / "evidence-parent"
    evidence_parent.mkdir(mode=0o700)
    destination = evidence_parent / "capture.pcapng"
    if unsafe_case == "receipt-symlink":
        linked_receipt = tmp_path / "linked-capture.json"
        linked_receipt.symlink_to(receipt)
        receipt = linked_receipt
    elif unsafe_case == "existing-destination":
        destination.write_bytes(b"prior-evidence")
        destination.chmod(0o600)
    elif unsafe_case == "wrong-parent-mode":
        evidence_parent.chmod(0o755)
    else:
        evidence_relative = "evidence/attempt-1/not-capture.pcapng"
    script = tmp_path / f"extract-{unsafe_case}.sh"
    script.write_text(
        "set -euo pipefail\n"
        + extraction
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + f"_qcsd_docker_api() {{ printf %s {shlex.quote(payload.decode())}; }}\n"
        + "if browser_egress_extract_observer_pcap observer "
        + f"{str(destination)!r} {str(receipt)!r} {evidence_relative!r}; "
        + "then exit 99; fi\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert "extraction" in completed.stderr
    if unsafe_case == "existing-destination":
        assert destination.read_bytes() == b"prior-evidence"
    else:
        assert not destination.exists()


def test_browser_egress_extraction_failure_reaches_production_err_boundary_once(
    tmp_path: Path,
) -> None:
    extraction = _browser_egress_extraction_shell_function()
    expected = b"complete-capture"
    receipt, evidence_relative = _browser_egress_extraction_receipt(tmp_path, expected)
    destination = tmp_path / "capture.pcapng"
    sealed = tmp_path / "sealed.log"
    script = tmp_path / "extract-err-boundary.sh"
    script.write_text(
        "set -euo pipefail\n"
        + extraction
        + f"qcsd_invoking_uid={os.getuid()}\n"
        + f"qcsd_invoking_gid={os.getgid()}\n"
        + "browser_egress_failure_code=capture-process-failed\n"
        + "browser_egress_failure_stage=capture-finalization\n"
        + "nested_docker_failure() { printf partial; return 23; }\n"
        + "_qcsd_docker_api() { nested_docker_failure; }\n"
        + "seal_failure() {\n"
        + "  status=$?\n"
        + "  trap - ERR\n"
        + "  printf '%s:%s:%s\\n' \"$browser_egress_failure_code\" "
        + f'"$browser_egress_failure_stage" "$status" >>{str(sealed)!r}\n'
        + '  exit "$status"\n'
        + "}\n"
        + "trap seal_failure ERR\n"
        + "browser_egress_extract_observer_pcap observer "
        + f"{str(destination)!r} {str(receipt)!r} {evidence_relative!r} || false\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert sealed.read_text(encoding="utf-8").splitlines() == [
        "capture-process-failed:capture-finalization:1"
    ]
    assert not destination.exists()


def test_browser_egress_staged_readiness_and_subject_ack_are_ordered(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    vector_loop = launcher.split('browser_egress_policy_volume_name=""', maxsplit=1)[1].split(
        "    browser_egress_finished_at=", maxsplit=1
    )[0]
    cursor = 0
    for role, variable in (
        ("browser", "browser_egress_browser_id"),
        ("observer", "browser_egress_observer_id"),
        ("fixture", "browser_egress_fixture_id"),
        ("forbidden_sink", "browser_egress_forbidden_id"),
        ("dns_sink", "browser_egress_dns_id"),
    ):
        launch = vector_loop.index(f"--label org.qcsd.role={role}", cursor)
        ready = vector_loop.index(f'browser_egress_wait_healthy "${{{variable}}}"', launch)
        assert launch < ready
        cursor = ready
    observer_signal = vector_loop.index(
        'kill --signal USR1 "${browser_egress_observer_id}"', cursor
    )
    subject_ack = vector_loop.index(
        "/tmp/qcsd-browser-egress-subject-started.ready", observer_signal
    )
    action_failure = vector_loop.index(
        "browser_egress_failure_code=browser-action-failed", subject_ack
    )
    action_stage = vector_loop.index(
        "browser_egress_failure_stage=browser-action", action_failure
    )
    browser_signal = vector_loop.index(
        'kill --signal USR1 "${browser_egress_browser_id}"', action_stage
    )
    assert (
        cursor
        < observer_signal
        < subject_ack
        < action_failure
        < action_stage
        < browser_signal
    )

    healthy = (
        "browser_egress_wait_healthy() {"
        + launcher.split("browser_egress_wait_healthy() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_cleanup_topology()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    marker = (
        "browser_egress_wait_container_marker() {"
        + launcher.split("browser_egress_wait_container_marker() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_wait_exit_code()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    log = tmp_path / "barriers.log"
    script = tmp_path / "barriers.sh"
    script.write_text(
        "set -euo pipefail\n"
        + healthy
        + marker
        + f"LOG={str(log)!r}\n"
        + "_qcsd_docker_api() {\n"
        + '  if [[ "$1 $2" == "container inspect" ]]; then\n'
        + '    if [[ "$3" == "--format" && "$4" == *Health* ]]; then\n'
        + "      sleep 0.15; echo healthy\n"
        + "    else echo running; fi\n"
        + '  elif [[ "$1" == exec ]]; then\n'
        + "    sleep 0.15; return 0\n"
        + "  else return 2; fi\n"
        + "}\n"
        + "for role in browser observer fixture forbidden dns; do\n"
        + '  browser_egress_wait_healthy "$role"\n'
        + '  echo "ready-$role" >>"$LOG"\n'
        + "done\n"
        + 'echo observer-signal >>"$LOG"\n'
        + "browser_egress_wait_container_marker observer /tmp/marker subject\n"
        + 'echo subject-ack >>"$LOG"\n'
        + 'echo browser-signal >>"$LOG"\n',
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        "ready-browser",
        "ready-observer",
        "ready-fixture",
        "ready-forbidden",
        "ready-dns",
        "observer-signal",
        "subject-ack",
        "browser-signal",
    ]


def test_browser_egress_policy_volume_and_fixture_tls_shell_contract_is_exact() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    vector_loop = launcher.split('browser_egress_policy_volume_name=""', maxsplit=1)[1].split(
        "    browser_egress_finished_at=", maxsplit=1
    )[0]
    mask = "--tmpfs /opt/qcsd-lab/config/class-study/v1:ro,nosuid,nodev,noexec,mode=000"

    assert "_qcsd_docker_api volume create" in vector_loop
    assert vector_loop.index("QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES+=(") < (
        vector_loop.index("_qcsd_docker_api volume create")
    )
    assert "--label org.qcsd.role=policy_volume" in vector_loop
    assert "--network none" in vector_loop
    assert "--label org.qcsd.role=policy_seed" in vector_loop
    assert "--user 0:0" in vector_loop
    assert "--cap-drop ALL --security-opt no-new-privileges:true --read-only" in vector_loop
    assert '--volume "${browser_egress_policy_volume_name}:/qcsd-policy:rw"' in vector_loop
    assert (
        '--volume "${browser_egress_policy_volume_name}:${browser_egress_policy_directory}:ro"'
    ) in vector_loop
    assert "install -o 0 -g 0 -m 0444" in vector_loop
    assert 'sync -f "$target"' in vector_loop
    assert vector_loop.count(mask) == 5

    fixture_launch = vector_loop.split("--label org.qcsd.role=fixture", maxsplit=1)[0].rsplit(
        "qcsd_run_detached_docker", maxsplit=1
    )[1]
    assert mask not in fixture_launch
    for role in ("browser", "observer", "forbidden_sink", "dns_sink"):
        role_marker = f"--label org.qcsd.role={role}"
        role_launch = vector_loop.split(role_marker, maxsplit=1)[0].rsplit(
            "qcsd_run_detached_docker", maxsplit=1
        )[1]
        assert mask in role_launch

    volume_inspect = vector_loop.index(
        '_qcsd_docker_api volume inspect "${browser_egress_policy_volume_name}"'
    )
    runtime_projection = vector_loop.index("project-runtime")
    assert volume_inspect < runtime_projection

    cleanup = launcher.split("browser_egress_cleanup_topology() {", maxsplit=1)[1].split(
        "\n}\n\nbrowser_egress_exit_cleanup()", maxsplit=1
    )[0]
    assert cleanup.index("network rm") < cleanup.index("volume rm")
    assert "volume ls --quiet" in cleanup
    assert '--filter "name=^${volume_name}$"' in cleanup


def test_browser_egress_live_daemon_is_admitted_at_every_evidence_boundary() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")

    projection = launcher.split("browser_egress_live_docker_binding() {", maxsplit=1)[1].split(
        "\n}", maxsplit=1
    )[0]
    assert "_qcsd_docker_api version --format '{{json .}}'" in projection
    assert "_qcsd_docker_api_with_timeout" in projection
    assert '"${_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS}" info --format' in projection
    assert "info --format '{{json .}}'" in projection
    assert "live-docker-binding" in projection
    assert '"${_QCSD_DOCKER_PINNED_CONTEXT}"' in projection
    assert '"${_QCSD_DOCKER_PINNED_HOST}"' in projection
    assert '"${_QCSD_DOCKER_PINNED_SERVER_ID}"' in projection
    assert (
        'browser_egress_live_docker_json="${QCSD_DOCKER_OUTPUT_BROWSER_EGRESS_DAEMON}"'
        in projection
    )

    assert launcher.count('--live-docker-json "${browser_egress_live_docker_json}"') == 7
    assert "browser_egress_live_docker_binding || exit 1" in launcher
    assert '"$(browser_egress_live_docker_binding)"' not in launcher


def test_browser_egress_live_daemon_projection_stays_in_supervisor_process(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = (
        "browser_egress_live_docker_binding() {"
        + launcher.split("browser_egress_live_docker_binding() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_reconcile_filesystem()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    script = tmp_path / "live-docker-binding.sh"
    script.write_text(
        "set -euo pipefail\n"
        + function
        + "supervisor_pid=$BASHPID\n"
        + "browser_egress_live_docker_json=''\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\nimage_id=image\n"
        + "_QCSD_DOCKER_PINNED_CONTEXT=default\n"
        + "_QCSD_DOCKER_PINNED_HOST=unix:///var/run/docker.sock\n"
        + "_QCSD_DOCKER_PINNED_SERVER_ID=server\n"
        + "_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS=10\n"
        + '_qcsd_docker_api() { printf \'{"probe":"%s"}\\n\' "$1"; }\n'
        + '_qcsd_docker_api_with_timeout() { [[ "$1" == 10 && "$2" == info ]] || return 92; shift; _qcsd_docker_api "$@"; }\n'
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n output=$1\n"
        + '  [[ "$BASHPID" == "$supervisor_pid" ]] || return 91\n'
        + '  output=\'{"daemon":"bound"}\'\n'
        + "}\n"
        + "browser_egress_live_docker_binding\n"
        + '[[ "$browser_egress_live_docker_json" == \'{"daemon":"bound"}\' ]]\n',
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == ""


def test_browser_egress_stale_topology_wrapper_retires_only_validated_ids(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = (
        "browser_egress_retire_stale_topology() {"
        + launcher.split("browser_egress_retire_stale_topology() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_record_failed_attempt()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    observer = "1" * 64
    browser = "2" * 64
    network = "3" * 64
    state = tmp_path / "state"
    state.mkdir()
    (state / observer).touch()
    (state / browser).touch()
    (state / network).touch()
    log = tmp_path / "removed.log"
    script = tmp_path / "stale-wrapper.sh"
    script.write_text(
        "set -euo pipefail\n"
        + function
        + f"STATE={str(state)!r}\nLOG={str(log)!r}\n"
        + f"OBSERVER={observer!r}\nBROWSER={browser!r}\nNETWORK={network!r}\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\nimage_id=image\n"
        + "_qcsd_docker_api() {\n"
        + '  if [[ "$1 $2" == "ps --all" ]]; then\n'
        + '    [[ ! -e "$STATE/$OBSERVER" ]] || echo "$OBSERVER"\n'
        + '    [[ ! -e "$STATE/$BROWSER" ]] || echo "$BROWSER"\n'
        + '  elif [[ "$1 $2" == "container inspect" ]]; then echo \'[]\'\n'
        + '  elif [[ "$1 $2" == "container rm" && "$3" == "--force" ]]; then\n'
        + '    [[ "$4" == "$OBSERVER" || "$4" == "$BROWSER" ]]\n'
        + '    echo "container $4" >>"$LOG"; rm "$STATE/$4"\n'
        + '  elif [[ "$1 $2" == "network ls" ]]; then\n'
        + '    [[ ! -e "$STATE/$NETWORK" ]] || echo "$NETWORK"\n'
        + '  elif [[ "$1 $2" == "network inspect" ]]; then\n'
        + "    [[ -e \"$STATE/$NETWORK\" ]] || return 1; echo '[{}]'\n"
        + '  elif [[ "$1 $2" == "network rm" ]]; then\n'
        + '    [[ "$3" == "$NETWORK" ]]; echo "network $3" >>"$LOG"; rm "$STATE/$3"\n'
        + '  elif [[ "$1 $2" == "volume ls" ]]; then :\n'
        + "  else return 2; fi\n"
        + "}\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n output=$1\n"
        + '  output="{\\"schema_version\\":1,\\"container_ids\\":[\\"$OBSERVER\\",\\"$BROWSER\\"],\\"network_id\\":\\"$NETWORK\\",\\"volume_name\\":null}"\n'
        + "}\n"
        + "qcsd_run_attached_docker() { return 99; }\n"
        + "browser_egress_retire_stale_topology '{\"schema_version\":1}'\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"container {observer}",
        f"container {browser}",
        f"network {network}",
    ]
    assert "prune" not in function


def test_browser_egress_stale_topology_wrapper_retires_bound_policy_volume_last(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = (
        "browser_egress_retire_stale_topology() {"
        + launcher.split("browser_egress_retire_stale_topology() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_record_failed_attempt()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    container = "1" * 64
    network = "2" * 64
    volume = f"qcsd-be-{'3' * 32}-policy0"
    state = tmp_path / "state"
    state.mkdir()
    for name in (container, network, volume):
        (state / name).touch()
    log = tmp_path / "removed.log"
    script = tmp_path / "stale-volume-wrapper.sh"
    script.write_text(
        "set -euo pipefail\n"
        + function
        + f"STATE={str(state)!r}\nLOG={str(log)!r}\n"
        + f"CONTAINER={container!r}\nNETWORK={network!r}\nVOLUME={volume!r}\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\nimage_id=image\n"
        + "_qcsd_docker_api() {\n"
        + '  if [[ "$1 $2" == "ps --all" ]]; then\n'
        + '    [[ ! -e "$STATE/$CONTAINER" ]] || echo "$CONTAINER"\n'
        + '  elif [[ "$1 $2" == "container inspect" ]]; then echo \'[]\'\n'
        + '  elif [[ "$1 $2" == "container rm" && "$3" == "--force" ]]; then\n'
        + '    [[ "$4" == "$CONTAINER" ]]; echo "container $4" >>"$LOG"; rm "$STATE/$4"\n'
        + '  elif [[ "$1 $2" == "network ls" ]]; then\n'
        + '    [[ ! -e "$STATE/$NETWORK" ]] || echo "$NETWORK"\n'
        + '  elif [[ "$1 $2" == "network inspect" ]]; then echo \'[{}]\'\n'
        + '  elif [[ "$1 $2" == "network rm" ]]; then\n'
        + '    echo "network $3" >>"$LOG"; rm "$STATE/$3"\n'
        + '  elif [[ "$1 $2" == "volume ls" ]]; then\n'
        + '    [[ ! -e "$STATE/$VOLUME" ]] || echo "$VOLUME"\n'
        + '  elif [[ "$1 $2" == "volume inspect" ]]; then echo \'[{}]\'\n'
        + '  elif [[ "$1 $2" == "volume rm" ]]; then\n'
        + '    echo "volume $3" >>"$LOG"; rm "$STATE/$3"\n'
        + "  else return 2; fi\n"
        + "}\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n output=$1\n"
        + '  output="{\\"schema_version\\":1,\\"container_ids\\":[\\"$CONTAINER\\"],\\"network_id\\":\\"$NETWORK\\",\\"volume_name\\":\\"$VOLUME\\"}"\n'
        + "}\n"
        + "browser_egress_retire_stale_topology '{\"schema_version\":1}'\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"container {container}",
        f"network {network}",
        f"volume {volume}",
    ]


def _browser_egress_cleanup_lifetime_shell() -> str:
    """Compose the production lifetime handler and both cleanup entry paths."""

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    start = launcher.index("_QCSD_LIFETIME_SIGNAL_STATUS=0\n")
    end = launcher.index("\nrequire_submodule()", start)
    transport_state = "\nstudy_environment_transport_dir=''\nstudy_environment_host_path=''\n"
    return launcher[start:end] + transport_state + "".join(
        _launcher_shell_function(launcher, name)
        for name in (
            "remove_study_environment_transport",
            "_qcsd_begin_latched_cleanup",
            "_qcsd_cleanup_terminal_hook",
            "_qcsd_finish_latched_cleanup",
            "browser_egress_cleanup_topology",
            "browser_egress_exit_cleanup",
        )
    )


@pytest.mark.parametrize("prior_active,pending_status", [(0, 0), (1, 0), (1, 143)])
@pytest.mark.parametrize("retirement_fails", [False, True])
def test_browser_egress_cleanup_restores_prior_latch_on_return(
    tmp_path: Path, prior_active: int, pending_status: int, retirement_fails: bool,
) -> None:
    script = tmp_path / "cleanup-latch-return.sh"
    script.write_text(
        "set -euo pipefail\n"
        + _browser_egress_cleanup_lifetime_shell()
        + f"_QCSD_LIFETIME_CLEANUP_ACTIVE={prior_active}\n"
        + f"_QCSD_LIFETIME_SIGNAL_STATUS={pending_status}\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(c1)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=()\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=()\n"
        + "_qcsd_docker_api() { :; }\n"
        + f"qcsd_retire_docker_handoff() {{ return {int(retirement_fails)}; }}\n"
        + "status=0\nbrowser_egress_cleanup_topology || status=$?\n"
        + "printf '%s %s %s %s\\n' \"$status\" \"$_QCSD_LIFETIME_CLEANUP_ACTIVE\" "
        + '"$_QCSD_LIFETIME_SIGNAL_STATUS" "${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[*]}"\n',
        encoding="utf-8",
    )
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    retained = "c1" if retirement_fails else ""
    assert result.stdout == f"{int(retirement_fails)} {prior_active} {pending_status} {retained}\n"


@pytest.mark.parametrize("retain_failure", [False, True])
def test_browser_egress_cleanup_term_after_retirement_does_not_retry_retired_ids(
    tmp_path: Path, retain_failure: bool,
) -> None:
    script = tmp_path / "cleanup-term.sh"
    log = tmp_path / "retirements.log"
    script.write_text(
        "set -euo pipefail\n"
        + _browser_egress_cleanup_lifetime_shell()
        + f"LOG={shlex.quote(str(log))}\nRETAIN_FAILURE={int(retain_failure)}\n"
        + r'''
QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(c1 c2)
QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=()
QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=()
declare -A retired=()
_qcsd_docker_api() { :; }
qcsd_retire_docker_handoff() {
  local object_id="$2"
  if [[ -v 'retired[$object_id]' ]]; then
    echo "duplicate $object_id" >>"$LOG"
    return 1
  fi
  if [[ "$object_id" == c1 && "$RETAIN_FAILURE" == 1 ]]; then
    echo "unproved $object_id" >>"$LOG"
    return 1
  fi
  retired["$object_id"]=1
  echo "retired $object_id" >>"$LOG"
  if [[ "$object_id" == c2 ]]; then kill -TERM "$BASHPID"; fi
  return 0
}
_qcsd_cleanup_terminal_hook() {
  printf 'containers=%s\n' "${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[*]}"
}
trap browser_egress_exit_cleanup EXIT
browser_egress_cleanup_topology || false
echo publication-must-not-run
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 143, (result.stdout, result.stderr)
    assert result.stderr == ""
    assert result.stdout == f"containers={'c1' if retain_failure else ''}\n"
    assert log.read_text(encoding="utf-8").splitlines() == (
        ["retired c2", "unproved c1", "unproved c1"]
        if retain_failure else ["retired c2", "retired c1"]
    )


def test_browser_egress_cleanup_returns_and_err_path_seals_after_cleanup(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    cleanup = (
        "browser_egress_cleanup_topology() {"
        + launcher.split("browser_egress_cleanup_topology() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_exit_cleanup()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    record = (
        "browser_egress_record_failed_attempt() {"
        + launcher.split("browser_egress_record_failed_attempt() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_live_docker_json=", maxsplit=1
        )[0]
        + "\n}\n"
    )

    normal = tmp_path / "normal-cleanup.sh"
    normal.write_text(
        "set -euo pipefail\n"
        + cleanup
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(c1)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=(n1)\n"
        + "_qcsd_docker_api() { :; }\n"
        + "qcsd_retire_docker_handoff() { :; }\n"
        + "browser_egress_cleanup_topology\n"
        + "echo vector-2-proceeded\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(normal)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "vector-2-proceeded\n"

    result_root = tmp_path / "result"
    attempt = result_root / "evidence/001--constructor--page--websocket/attempt-1"
    attempts = result_root / "attempts"
    scratch = tmp_path / "scratch"
    attempt.mkdir(parents=True)
    attempts.mkdir()
    scratch.mkdir()
    (scratch / "next.json").write_text("{}\n", encoding="utf-8")
    log = tmp_path / "failure-order.log"
    failed = tmp_path / "err-cleanup.sh"
    failed.write_text(
        "set -euo pipefail\n"
        + cleanup
        + record
        + f"LOG={str(log)!r}\nROOT=/lab\nimage_id=image\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + f"browser_egress_result_host={str(result_root)!r}\n"
        + "browser_egress_result_container=/lab/result\n"
        + f"browser_egress_attempt_evidence_host={str(attempt)!r}\n"
        + f"browser_egress_evidence_host={str(attempt / 'capture.pcapng')!r}\n"
        + f"browser_egress_scratch={str(scratch)!r}\n"
        + f"browser_egress_attempt_scratch={str(scratch)!r}\n"
        + "browser_egress_causal_inputs_ready=0\n"
        + "browser_egress_vector_ordinal=1\n"
        + "browser_egress_vector_id=constructor--page--websocket\n"
        + "browser_egress_attempt_number=1\n"
        + "browser_egress_started_at=2026-09-06T00:00:00Z\n"
        + "browser_egress_failure_verdict=operational-failure\n"
        + "browser_egress_failure_code=docker-start-failed\n"
        + "browser_egress_failure_stage=network-create\n"
        + "browser_egress_tool=/tool\n"
        + "browser_egress_browser_id=\n"
        + "browser_egress_observer_id=\n"
        + "browser_egress_fixture_id=\n"
        + "browser_egress_forbidden_id=\n"
        + "browser_egress_dns_id=\n"
        + "browser_egress_network_id=\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(stale)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=()\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=()\n"
        + '_qcsd_docker_api() { echo cleanup >>"$LOG"; }\n'
        + "qcsd_retire_docker_handoff() { :; }\n"
        + "browser_egress_preserve_capture_closure() { :; }\n"
        + "browser_egress_preserve_causal_evidence() { :; }\n"
        + 'qcsd_run_attached_docker() { echo record-failure >>"$LOG"; }\n'
        + "trap browser_egress_record_failed_attempt ERR\n"
        + "false\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(failed)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        "cleanup",
        "record-failure",
    ]

    no_seal = tmp_path / "err-cleanup-no-seal.sh"
    no_seal_text = failed.read_text(encoding="utf-8").replace(
        "qcsd_retire_docker_handoff() { :; }",
        "qcsd_retire_docker_handoff() { return 1; }",
    )
    assert no_seal_text != failed.read_text(encoding="utf-8")
    no_seal.write_text(no_seal_text, encoding="utf-8")
    log.unlink()
    completed = subprocess.run(
        ["bash", str(no_seal)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == ["cleanup"]
    assert "left its attempt outstanding after teardown failed" in completed.stderr


def test_browser_egress_cleanup_retains_every_unproved_docker_identity(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    cleanup = (
        "browser_egress_cleanup_topology() {"
        + launcher.split("browser_egress_cleanup_topology() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_exit_cleanup()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    script = tmp_path / "retained-cleanup.sh"
    script.write_text(
        "set -euo pipefail\n"
        + cleanup
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(c1 c2)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=(n1)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=(v1)\n"
        + "_qcsd_docker_api() {\n"
        + '  if [[ "$1 $2" == "volume ls" ]]; then echo v1; return 0; fi\n'
        + "  return 1\n"
        + "}\n"
        + 'qcsd_retire_docker_handoff() { [[ "$2" == c2 ]]; }\n'
        + "if browser_egress_cleanup_topology; then exit 90; fi\n"
        + "printf 'containers=%s\\n' \"${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[*]}\"\n"
        + "printf 'networks=%s\\n' \"${QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS[*]}\"\n"
        + "printf 'volumes=%s\\n' \"${QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES[*]}\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout.splitlines() == [
        "containers=c1",
        "networks=n1",
        "volumes=v1",
    ]


def test_browser_egress_causal_promotion_is_idempotent_and_rejects_substitution(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    preserve = (
        "browser_egress_preserve_causal_evidence() {"
        + launcher.split("browser_egress_preserve_causal_evidence() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_record_failed_attempt()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    vector_id = "constructor--page--websocket"
    source = tmp_path / "attempt-input"
    evidence = tmp_path / "attempt-evidence"
    source.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    for name in ("actor", "capture", "dns", "fixture", "forbidden", "runtime"):
        value = {"schema_version": 1, "name": name}
        if name != "runtime":
            value["vector_id"] = vector_id
        (source / f"{name}.json").write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    # Model death after the first create-only publication.  The exact matching
    # file is accepted and the remaining finite inventory is completed.
    first = (source / "actor.json").read_bytes()
    (evidence / "causal-actor.json").write_bytes(first)
    (evidence / "causal-actor.json").chmod(0o600)
    script = tmp_path / "promote.sh"
    script.write_text(
        "set -euo pipefail\n"
        + preserve
        + "browser_egress_causal_inputs_ready=1\n"
        + f"browser_egress_attempt_scratch={str(source)!r}\n"
        + f"browser_egress_attempt_evidence_host={str(evidence)!r}\n"
        + f"browser_egress_vector_id={vector_id!r}\n"
        + "browser_egress_preserve_causal_evidence\n",
        encoding="utf-8",
    )
    for _ in range(2):
        completed = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
        )
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert sorted(path.name for path in evidence.iterdir()) == [
        "causal-actor.json",
        "causal-capture.json",
        "causal-dns.json",
        "causal-fixture.json",
        "causal-forbidden.json",
        "causal-runtime.json",
    ]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in evidence.iterdir())

    (evidence / "causal-actor.json").unlink()
    (evidence / "causal-actor.json").symlink_to(source / "actor.json")
    rejected = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert rejected.returncode != 0
    assert "causal evidence conflicts" in rejected.stderr
    assert (source / "actor.json").exists()


def test_browser_egress_resume_chronology_and_phase_mounts_are_fail_closed() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    block = launcher.split("browser_egress_coordinator_prefix=(", maxsplit=1)[1].split(
        'if [[ "${1:-}" == "test" && "${2:-}" == "pinned-cdp" ]]', maxsplit=1
    )[0]
    prefix = block.split("browser_egress_coordinator_suffix=(", maxsplit=1)[0]
    assert "browser_egress_result_host" not in prefix
    assert "browser_egress_coordinator_base" not in block
    assert '--volume "${browser_egress_result_host}:${browser_egress_result_container}:ro"' in block
    assert (
        '--volume "${browser_egress_result_host}/attempt-intents:'
        '${browser_egress_result_container}/attempt-intents:rw"' in block
    )
    assert "browser_egress_prior_intent" in block
    assert "browser_egress_recovery_mounts" in block
    assert "browser_egress_recovery_attempt_host" in block
    assert "browser_egress_recovery_result" in block

    reconcile = block.index("browser_egress_reconcile_filesystem")
    admit = block.index("admit-resume --cohort-version")
    retire = block.index("browser_egress_retire_stale_topology")
    recover = block.index("recover-resume --cohort-version")
    next_vector = block.index('"${browser_egress_coordinator_suffix[@]}" next')
    begin = block.index("begin-attempt --result-root")
    network = block.index("docker network create")
    runtime = block.index("project-runtime")
    prevalidate = block.index('"${browser_egress_tool}" assemble', runtime)
    teardown = block.index("browser_egress_cleanup_topology || false", runtime)
    assemble = block.index('"${browser_egress_tool}" assemble', prevalidate + 1)
    assert reconcile < admit < retire < recover < next_vector < begin < network
    assert runtime < prevalidate < teardown < assemble
    assert "--validate-only" in block[runtime:teardown]
    assert "attempt-status" in block[assemble:]
    assert (
        block.index("browser_egress_causal_inputs_ready=0", assemble)
        < block.index("attempt-status", assemble)
        < block.index("browser_egress_causal_inputs_ready=1", assemble)
    )
    assert "qcsd_run_attached_docker docker container rm" not in launcher
    assert "_qcsd_docker_api container rm --force" in launcher


@pytest.mark.parametrize("residue_kind", ("none", "intent", "recovery"))
def test_browser_egress_reconcile_mounts_are_phase_minimal(
    tmp_path: Path, residue_kind: str
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = (
        "browser_egress_reconcile_filesystem() {"
        + launcher.split("browser_egress_reconcile_filesystem() {", maxsplit=1)[1].split(
            "\n}\n\nbrowser_egress_retire_stale_topology()", maxsplit=1
        )[0]
        + "\n}\n"
    )
    root = tmp_path / "qualification"
    for directory in (root, root / "attempts", root / "attempt-intents", root / "evidence"):
        directory.mkdir(mode=0o700)
    (root / "foundation.json").write_text("{}\n", encoding="utf-8")
    (root / "experiment.json").write_text("{}\n", encoding="utf-8")
    if residue_kind == "intent":
        (root / "attempt-intents/.intent-0001.json.deadbeef.qcsd-tmp").write_text(
            "{}\n", encoding="utf-8"
        )
    elif residue_kind == "recovery":
        recovery = root / (
            "evidence/001--constructor--page--websocket/attempt-1/"
            ".resume-recovery.json.deadbeef.qcsd-tmp"
        )
        recovery.parent.mkdir(mode=0o700, parents=True)
        recovery.write_text("{}\n", encoding="utf-8")
    log = tmp_path / "argv.log"
    script = (
        "set -euo pipefail\n"
        + function
        + f"browser_egress_result_host={str(root)!r}\n"
        + "browser_egress_result_container=/lab/result\n"
        + "browser_egress_cohort_version=71\n"
        + "browser_egress_build_container=/lab/build.json\n"
        + "browser_egress_live_docker_json='{}'\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + "image_id=sha256:test\nROOT=/lab\n"
        + f"LOG={str(log)!r}\n"
        + 'qcsd_run_attached_docker() { printf \'%s\\n\' "$@" >"$LOG"; }\n'
        + "browser_egress_reconcile_filesystem\n"
    )
    completed = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, completed.stderr
    arguments = log.read_text(encoding="utf-8").splitlines()
    if residue_kind == "none":
        assert f"{root}:/lab/result:ro" in arguments
        assert f"{root}:/lab/result:rw" not in arguments
    else:
        assert f"{root}:/lab/result:rw" in arguments
        assert f"{root / 'evidence'}:/lab/result/evidence:ro" in arguments
        assert f"{root / 'attempts'}:/lab/result/attempts:ro" in arguments
        if residue_kind == "intent":
            assert f"{root / 'attempt-intents'}:/lab/result/attempt-intents:ro" not in arguments
        else:
            assert f"{root / 'attempt-intents'}:/lab/result/attempt-intents:ro" in arguments
            assert (
                f"{recovery.parent}:"
                "/lab/result/evidence/001--constructor--page--websocket/attempt-1:rw" in arguments
            )
        assert f"{root / 'foundation.json'}:/lab/result/foundation.json:ro" in arguments
        assert f"{root / 'experiment.json'}:/lab/result/experiment.json:ro" in arguments


def test_browser_egress_ledger_writes_protect_prior_evidence() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")

    assert "browser_egress_foundation_mounts" in launcher
    assert 'find "${browser_egress_result_parent}" -mindepth 1 -maxdepth 1 -print0' in launcher
    assert "browser_egress_append_mounts" in launcher
    assert (
        '"${browser_egress_result_host}/foundation.json:'
        '${browser_egress_result_container}/foundation.json:ro"'
    ) in launcher
    assert (
        '"${browser_egress_result_host}/evidence:${browser_egress_result_container}/evidence:ro"'
    ) in launcher
    assert "browser_egress_finalize_mounts" in launcher
    assert "browser_egress_record_failed_attempt" in launcher
    assert "browser_egress_preserve_capture_closure" in launcher
    assert '"${browser_egress_attempt_evidence_host}/capture-closure.json"' in launcher
    assert '"${browser_egress_attempt_evidence_host}:' in launcher
    assert "record-failure" in launcher
    assert "trap browser_egress_record_failed_attempt ERR" in launcher
    assert "umask 077" in launcher
    assert 'mkdir --mode=0700 -- "${browser_egress_attempt_evidence_host}"' in launcher
    assert "os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW" in launcher
    assert "os.fchmod(output_descriptor, 0o600)" in launcher
    assert "if written <= 0:" in launcher
    assert "os.fsync(output_descriptor)" in launcher
    assert "os.fsync(parent_descriptor)" in launcher


def test_browser_egress_tool_freezes_execution_verification_and_role_phases() -> None:
    tool = (Path(__file__).parents[1] / "tools/browser_egress_qualification.py").read_text(
        encoding="utf-8"
    )

    assert tool.count("FoundationVerificationMode.EXECUTION") >= 2
    assert "FoundationVerificationMode.PORTABLE_REPLAY" not in tool
    assert 'commands.add_parser("record-failure")' in tool
    assert 'commands.add_parser("reconcile-filesystem")' in tool
    assert 'GRACE_READY_PATH.write_text("ready\\n"' in tool
    assert "_publish_private_canonical_json(" in tool
    assert 'CAPTURE_CLOSED_READY_PATH.write_text("ready\\n"' in tool
    assert 'CAPTURE_ANALYSIS_FAILED_READY_PATH.write_text("failed\\n"' in tool
    assert 'RECEIPT_READY_PATH.write_text("ready\\n"' in tool
    observer = tool.split("def _observer(", maxsplit=1)[1].split("\ndef _foundation(", maxsplit=1)[
        0
    ]
    assert (
        observer.index("observer.mark_reporting_grace_finished()")
        < observer.index("_wait(finish_capture)")
        < observer.index("observer.close_capture(")
        < observer.index("_publish_private_canonical_json(")
        < observer.index("_wait(capture_extracted)")
        < observer.index("observer.finish_closed_capture(")
        < observer.index("_wait(stopped)")
    )
    assert "BrowserFixtureServer(" in tool and "vector=vector" in tool
    assert "combine_sink_receipt(" in tool
    assert '"role": "fixture"' in tool
    assert '"dns_servers": host.get("Dns") or []' in tool
    assert 'expected_raw_cap_add = ["CAP_NET_RAW"] if role == "observer" else []' in tool
    assert "raw_cap_add != expected_raw_cap_add" in tool
    assert "~NOTFOUND" not in tool
    assert tool.count("launch_qualification_browser(") == 1
    tree = ast.parse(tool)
    forbidden_launch_attributes = {
        "launch",
        "launch_persistent_context",
        "connect",
        "connect_over_cdp",
    }
    assert not [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_launch_attributes
    ]
    assert '"arguments": effective_arguments["arguments"]' not in tool
    assert '"--no-sandbox",' not in tool
    assert "_BROWSER_SERVICE_EXPRESSION" not in tool
    assert "execute_live_browser_action(vector=vector, realm=realm)" in tool
    assert "['fixture_http']" not in tool
    assert 'page.goto(f"{primary}/", wait_until="load")' in tool
    actor = tool.split("def _actor(", maxsplit=1)[1].split("\nclass _PlaywrightRealm", maxsplit=1)[
        0
    ]
    assert actor.index("_launch_vector_browser(") < actor.index("browser.new_context(")
    assert "browser_configuration_observation" in tool
    assert 'projection["observed_required_switches"].count(' in tool
    assert 'vector.surface == "reporting-nel-live"' in tool
    assert 'output["reporting_live_dwell_finished_ns"]' in tool
    assert 'times["browser-started"] = actor["browser_started_ns"]' in tool
    assert 'times["browser-exited"] = actor["browser_exited_ns"]' in tool


@pytest.mark.parametrize(
    ("published", "verdict"),
    ((False, None), (True, "passed"), (True, "operational-failure")),
)
def test_browser_egress_attempt_status_reports_only_the_exact_ledger_head(
    monkeypatch: pytest.MonkeyPatch,
    published: bool,
    verdict: str | None,
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_attempt_status_test",
    )
    function = namespace["_attempt_status"]
    globals_ = function.__globals__
    vector = globals_["vector_by_id"]("constructor--page--websocket")
    plan = {
        "schema_version": 1,
        "complete": False,
        "vector": vector.as_dict(),
        "global_ordinal": 1,
        "attempt_number": 1,
        "previous_result_sha256": "0" * 64,
    }
    attempts = []
    if published:
        attempts.append(
            {
                "global_ordinal": 1,
                "attempt_number": 1,
                "vector_id": vector.vector_id,
                "verdict": verdict,
            }
        )
    checkpoint = {
        "status": "running",
        "next_vector_ordinal": 1 if not published else 2,
        "chain_head_sha256": "0" * 64,
        "attempts": attempts,
    }
    monkeypatch.setitem(globals_, "_object", lambda *args, **kwargs: plan)
    monkeypatch.setitem(globals_, "load_checkpoint", lambda *args, **kwargs: checkpoint)
    emitted: list[dict] = []
    monkeypatch.setitem(globals_, "_emit", emitted.append)
    function(
        SimpleNamespace(
            result_root=Path("/result"),
            next_json=Path("/next.json"),
            vector_id=vector.vector_id,
        )
    )
    assert emitted == [
        {
            "schema_version": 1,
            "published": published,
            "verdict": verdict,
            "checkpoint": checkpoint,
        }
    ]


def test_browser_egress_lost_append_and_status_output_cannot_contaminate_evidence(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    flow = (
        "browser_egress_assemble_command_status=0"
        + launcher.split("browser_egress_assemble_command_status=0", maxsplit=1)[1].split(
            "    trap - ERR\n    rm -rf", maxsplit=1
        )[0]
        + "    trap - ERR\n"
    )
    scratch = tmp_path / "attempt"
    scratch.mkdir()
    (scratch / "next.json").write_text("{}\n", encoding="utf-8")
    err_marker = tmp_path / "err-handler-ran"
    causal_state = tmp_path / "causal-state"
    script = tmp_path / "lost-output.sh"
    script.write_text(
        "set -Eeuo pipefail\n"
        + f"ERR_MARKER={str(err_marker)!r}\nCAUSAL_STATE={str(causal_state)!r}\n"
        + "trap 'touch \"$ERR_MARKER\"' ERR\n"
        + 'trap \'printf "%s\\n" "$browser_egress_causal_inputs_ready" >"$CAUSAL_STATE"\' EXIT\n'
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + "image_id=image\nROOT=/lab\nbrowser_egress_tool=/tool\n"
        + "browser_egress_result_container=/lab/result\n"
        + f"browser_egress_attempt_scratch={str(scratch)!r}\n"
        + "browser_egress_append_mounts=()\n"
        + "browser_egress_vector_id=constructor--page--websocket\n"
        + "browser_egress_started_at=2026-09-06T00:00:00Z\n"
        + "browser_egress_finished_at=2026-09-06T00:00:01Z\n"
        + "browser_egress_causal_inputs_ready=1\n"
        + "browser_egress_failure_verdict=semantic-failure\n"
        + "browser_egress_failure_code=semantic-observation-failed\n"
        + "browser_egress_failure_stage=result-assembly\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n captured=$1; shift; captured=''\n"
        + "  [[ \" $* \" != *' attempt-status '* ]] || return 73\n"
        + "  return 72\n"
        + "}\n"
        + flow,
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert not err_marker.exists()
    assert causal_state.read_text(encoding="utf-8") == "0\n"
    assert not list(tmp_path.rglob("causal-*.json"))
    assert "could not reconcile ambiguous result publication" in completed.stderr


def test_browser_egress_success_ack_skips_ambiguous_reconciliation(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    flow = (
        "browser_egress_assemble_command_status=0"
        + launcher.split("browser_egress_assemble_command_status=0", maxsplit=1)[1].split(
            "    trap - ERR\n    rm -rf", maxsplit=1
        )[0]
        + "    trap - ERR\n"
    )
    scratch = tmp_path / "attempt"
    scratch.mkdir()
    reconciliation_marker = tmp_path / "attempt-status-called"
    script = tmp_path / "successful-output.sh"
    script.write_text(
        "set -Eeuo pipefail\n"
        + f"RECONCILIATION_MARKER={str(reconciliation_marker)!r}\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + "image_id=image\nROOT=/lab\nbrowser_egress_tool=/tool\n"
        + "browser_egress_result_container=/lab/result\n"
        + f"browser_egress_attempt_scratch={str(scratch)!r}\n"
        + "browser_egress_append_mounts=()\n"
        + "browser_egress_vector_id=constructor--page--websocket\n"
        + "browser_egress_started_at=2026-09-06T00:00:00Z\n"
        + "browser_egress_finished_at=2026-09-06T00:00:01Z\n"
        + "browser_egress_causal_inputs_ready=1\n"
        + "browser_egress_failure_verdict=semantic-failure\n"
        + "browser_egress_failure_code=semantic-observation-failed\n"
        + "browser_egress_failure_stage=result-assembly\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n captured=$1; shift\n"
        + "  if [[ \" $* \" == *' attempt-status '* ]]; then\n"
        + '    touch "$RECONCILIATION_MARKER"\n'
        + "    return 73\n"
        + "  fi\n"
        + '  captured=\'{"schema_version":1,"assembled":true,"checkpoint":{}}\'\n'
        + "  return 0\n"
        + "}\n"
        + flow,
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert not reconciliation_marker.exists()


def test_browser_egress_projection_accepts_only_real_docker_capability_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_tool_test",
    )
    project = namespace["_docker_projection"]
    image_id = "sha256:" + "a" * 64
    vector_id = "browser-service--browser--dns-prefetch"
    attempt_topology = {
        "cohort_version": 71,
        "foundation_payload_sha256": "b" * 64,
        "global_ordinal": 1,
        "attempt_number": 1,
        "topology_token": "c" * 32,
    }
    labels = {
        "org.qcsd.owner": "qcsd-lab",
        "org.qcsd.study": "classifier-multiorigin100-v1",
        "org.qcsd.qualification": "browser-egress-qualification-v1",
        "org.qcsd.vector": vector_id,
        "org.qcsd.cohort-version": "71",
        "org.qcsd.foundation": "b" * 64,
        "org.qcsd.global-ordinal": "1",
        "org.qcsd.attempt-number": "1",
        "org.qcsd.topology-token": "c" * 32,
    }
    supervised_labels = {
        **labels,
        "org.qcsd.supervisor.instance": "e" * 32,
    }
    network = {
        "Id": "f" * 64,
        "Name": "qcsd-browser-egress-v1",
        "Driver": "bridge",
        "Internal": True,
        "Attachable": False,
        "EnableIPv6": True,
        "IPAM": {
            "Config": [
                {"Subnet": "172.30.98.0/24"},
                {"Subnet": "fd00:71:63:73:64:98::/96"},
            ]
        },
        "Labels": supervised_labels,
    }
    addresses = {
        "browser": ("172.30.98.10", "fd00:71:63:73:64:98:0:10"),
        "fixture": ("172.30.98.11", "fd00:71:63:73:64:98:0:11"),
        "forbidden_sink": ("172.30.98.20", "fd00:71:63:73:64:98:0:20"),
        "dns_sink": ("172.30.98.53", "fd00:71:63:73:64:98:0:53"),
    }
    roles = ("browser", "observer", "fixture", "forbidden_sink", "dns_sink")
    endpoint_ids = {
        role: str(index + 5) * 64 for index, role in enumerate(roles) if role != "observer"
    }
    topology_containers = []
    for index, role in enumerate(roles, 1):
        attachment = {}
        if role != "observer":
            ipv4, ipv6 = addresses[role]
            attachment = {
                "qcsd-browser-egress-v1": {
                    "NetworkID": network["Id"],
                    "EndpointID": endpoint_ids[role],
                    "IPAddress": ipv4,
                    "GlobalIPv6Address": ipv6,
                }
            }
        topology_containers.append(
            {
                "Id": str(index) * 64,
                "Name": f"/qcsd-be-{'c' * 32}-{ {'forbidden_sink': 'forbidden', 'dns_sink': 'dns'}.get(role, role) }",
                "Image": image_id,
                "Config": {
                    "User": "1000:1000" if role == "browser" else "0:0",
                    "Labels": {**supervised_labels, "org.qcsd.role": role},
                },
                "HostConfig": {
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "CapAdd": ["CAP_NET_RAW"] if role == "observer" else None,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "NetworkMode": (
                        "container:" + "1" * 64 if role == "observer" else "qcsd-browser-egress-v1"
                    ),
                    "Tmpfs": {
                        "/tmp": "rw,nosuid,nodev,mode=1777",
                        **(
                            {
                                "/opt/qcsd-lab/config/class-study/v1": (
                                    "ro,nosuid,nodev,noexec,mode=000"
                                )
                            }
                            if role != "fixture"
                            else {}
                        ),
                    },
                    "Dns": (
                        ["172.30.98.53", "fd00:71:63:73:64:98:0:53"] if role == "browser" else None
                    ),
                },
                "NetworkSettings": {"Networks": attachment},
                "Mounts": [],
                "State": {"Running": True, "ExitCode": 0, "Status": "running"},
            }
        )
    network["Containers"] = {
        container["Id"]: {
            "EndpointID": endpoint_ids[role],
            "IPv4Address": f"{addresses[role][0]}/24",
            "IPv6Address": f"{addresses[role][1]}/96",
        }
        for role, container in zip(roles, topology_containers, strict=True)
        if role != "observer"
    }

    def terminal_snapshot(value: list[dict]) -> list[dict]:
        terminal = copy.deepcopy(value)
        for container in terminal:
            container["State"] = {"Running": False, "ExitCode": 0, "Status": "exited"}
            for attachment in container["NetworkSettings"]["Networks"].values():
                attachment["EndpointID"] = ""
                attachment["IPAddress"] = ""
                attachment["GlobalIPv6Address"] = ""
        return terminal

    terminal_containers = terminal_snapshot(topology_containers)

    value = project(
        network,
        topology_containers,
        terminal_containers,
        None,
        vector_id=vector_id,
        prepare_image_id=image_id,
        browser_uid=1000,
        browser_gid=1000,
        attempt_topology=attempt_topology,
        docker_root_dir="/var/lib/docker",
        policy_file_inventory=None,
    )
    assert value["containers"]["observer"]["cap_add"] == ["CAP_NET_RAW"]
    assert set(value["network"]["members"]) == {
        "browser",
        "fixture",
        "forbidden_sink",
        "dns_sink",
    }
    assert value["snapshot_model"] == {
        "schema_version": 1,
        "topology_source": "pre-action-live",
        "terminal_state_source": "post-exit",
        "immutable_container_fields_cross_checked": True,
    }
    assert value["containers"]["browser"]["running"] is False
    assert value["containers"]["browser"]["exit_code"] == 0
    assert value["containers"]["browser"]["ipv4_address"] == "172.30.98.10"

    immutable_mismatch = copy.deepcopy(terminal_containers)
    immutable_mismatch[0]["Name"] += "-replaced"
    with pytest.raises(ValueError, match="immutable fields differ"):
        project(
            network,
            topology_containers,
            immutable_mismatch,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    for snapshot_name, field in (
        ("live-topology", "Id"),
        ("live-topology", "HostConfig"),
        ("live-topology", "Mounts"),
        ("live-topology", "NetworkSettings"),
        ("terminal-state", "Image"),
        ("terminal-state", "Config"),
        ("terminal-state", "State"),
        ("terminal-state", "NetworkSettings"),
    ):
        incomplete_topology = copy.deepcopy(topology_containers)
        incomplete_terminal = copy.deepcopy(terminal_containers)
        selected = incomplete_topology if snapshot_name == "live-topology" else incomplete_terminal
        selected[1 if field == "NetworkSettings" else 0].pop(field)
        with pytest.raises(ValueError, match=f"Docker {snapshot_name} inspection"):
            project(
                network,
                incomplete_topology,
                incomplete_terminal,
                None,
                vector_id=vector_id,
                prepare_image_id=image_id,
                browser_uid=1000,
                browser_gid=1000,
                attempt_topology=attempt_topology,
                docker_root_dir="/var/lib/docker",
                policy_file_inventory=None,
            )

    malformed_mounts = copy.deepcopy(topology_containers)
    malformed_mounts[0]["Mounts"] = {}
    with pytest.raises(ValueError, match="live-topology inspection mounts"):
        project(
            network,
            malformed_mounts,
            terminal_containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    malformed_networks = copy.deepcopy(terminal_containers)
    malformed_networks[1]["NetworkSettings"].pop("Networks")
    with pytest.raises(ValueError, match="terminal-state inspection network settings"):
        project(
            network,
            topology_containers,
            malformed_networks,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    duplicate_terminal_role = copy.deepcopy(terminal_containers)
    duplicate_terminal_role[0]["Config"]["Labels"]["org.qcsd.role"] = "observer"
    with pytest.raises(ValueError, match="duplicate browser-egress role"):
        project(
            network,
            topology_containers,
            duplicate_terminal_role,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    terminal_running = copy.deepcopy(terminal_containers)
    terminal_running[0]["State"] = {
        "Running": True,
        "ExitCode": 0,
        "Status": "running",
    }
    with pytest.raises(ValueError, match="terminal state"):
        project(
            network,
            topology_containers,
            terminal_running,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    terminal_failed = copy.deepcopy(terminal_containers)
    terminal_failed[0]["State"]["ExitCode"] = 23
    with pytest.raises(ValueError, match="terminal state"):
        project(
            network,
            topology_containers,
            terminal_failed,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    terminal_boolean_exit = copy.deepcopy(terminal_containers)
    terminal_boolean_exit[0]["State"]["ExitCode"] = False
    with pytest.raises(ValueError, match="terminal state"):
        project(
            network,
            topology_containers,
            terminal_boolean_exit,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    live_stopped = copy.deepcopy(topology_containers)
    live_stopped[0]["State"] = {"Running": False, "ExitCode": 0, "Status": "exited"}
    with pytest.raises(ValueError, match="live-topology state"):
        project(
            network,
            live_stopped,
            terminal_containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    with pytest.raises(ValueError, match="terminal-state inspection must contain five roles"):
        project(
            network,
            topology_containers,
            terminal_containers[:-1],
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    stale = namespace["_stale_topology_cleanup_plan"]
    stale(
        SimpleNamespace(
            resume_plan_json=json.dumps(
                {
                    "schema_version": 1,
                    "checkpoint_publish_lag": False,
                    "checkpoint_status": "running",
                    "prepare_image_id": image_id,
                    "docker_root_dir": "/var/lib/docker",
                    "cleanup": {
                        "vector_id": vector_id,
                        "global_ordinal": 1,
                        "attempt_number": 1,
                        "evidence_directory": (
                            "evidence/083--browser-service--browser--dns-prefetch/attempt-1"
                        ),
                        "topology_token": "c" * 32,
                        "cohort_version": 71,
                        "foundation_payload_sha256": "b" * 64,
                        "outstanding": True,
                    },
                }
            ),
            network_inspect_json=json.dumps([network]),
            container_inspect_json=json.dumps(topology_containers),
            volume_inspect_json="null",
        )
    )
    cleanup = json.loads(capsys.readouterr().out)
    assert cleanup["container_ids"][0] == "2" * 64
    assert cleanup["network_id"] == network["Id"]

    completed_plan = {
        "schema_version": 1,
        "checkpoint_publish_lag": False,
        "checkpoint_status": "running",
        "prepare_image_id": image_id,
        "docker_root_dir": "/var/lib/docker",
        "cleanup": {
            "vector_id": vector_id,
            "global_ordinal": 1,
            "attempt_number": 1,
            "evidence_directory": (
                "evidence/083--browser-service--browser--dns-prefetch/attempt-1"
            ),
            "topology_token": "c" * 32,
            "cohort_version": 71,
            "foundation_payload_sha256": "b" * 64,
            "outstanding": False,
        },
    }
    stale(
        SimpleNamespace(
            resume_plan_json=json.dumps(completed_plan),
            network_inspect_json="null",
            container_inspect_json="[]",
            volume_inspect_json="null",
        )
    )
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 1,
        "container_ids": [],
        "network_id": None,
        "volume_name": None,
    }
    with pytest.raises(ValueError, match="outstanding attempt"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(completed_plan),
                network_inspect_json=json.dumps([network]),
                container_inspect_json=json.dumps(topology_containers),
                volume_inspect_json="null",
            )
        )

    mixed_token = copy.deepcopy(topology_containers)
    mixed_token[0]["Config"]["Labels"]["org.qcsd.topology-token"] = "d" * 32
    with pytest.raises(ValueError, match="labels"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(
                    {
                        **completed_plan,
                        "cleanup": {**completed_plan["cleanup"], "outstanding": True},
                    }
                ),
                network_inspect_json=json.dumps([network]),
                container_inspect_json=json.dumps(mixed_token),
                volume_inspect_json="null",
            )
        )

    extra_attachment = copy.deepcopy(topology_containers)
    extra_attachment[0]["NetworkSettings"]["Networks"]["unrelated"] = {
        "NetworkID": "e" * 64,
        "EndpointID": "d" * 64,
        "IPAddress": "192.0.2.2",
        "GlobalIPv6Address": "2001:db8::2",
    }
    with pytest.raises(ValueError, match="network attachment"):
        project(
            network,
            extra_attachment,
            terminal_containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    extra_member = copy.deepcopy(network)
    extra_member["Containers"]["c" * 64] = {
        "EndpointID": "b" * 64,
        "IPv4Address": "192.0.2.3/24",
        "IPv6Address": "2001:db8::3/96",
    }
    with pytest.raises(ValueError, match="exact four roles"):
        project(
            extra_member,
            topology_containers,
            terminal_containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    npo0_vector = "browser-service-control--off-the-record--speculation-prefetch-enabled"
    npo0_labels = {**labels, "org.qcsd.vector": npo0_vector}
    npo0_supervised_labels = {
        **npo0_labels,
        "org.qcsd.supervisor.instance": "e" * 32,
    }
    npo0_network = copy.deepcopy(network)
    npo0_network["Labels"] = npo0_supervised_labels
    npo0_topology_containers = copy.deepcopy(topology_containers)
    for container in npo0_topology_containers:
        role = container["Config"]["Labels"]["org.qcsd.role"]
        container["Config"]["Labels"] = {
            **npo0_supervised_labels,
            "org.qcsd.role": role,
        }
    volume_name = f"qcsd-be-{'c' * 32}-policy0"
    npo0_topology_containers[0]["Mounts"] = [
        {
            "Type": "volume",
            "Name": volume_name,
            "Destination": "/etc/chromium/policies/managed",
            "RW": False,
        }
    ]
    npo0_terminal_containers = terminal_snapshot(npo0_topology_containers)
    policy_inventory = [
        {
            "path": "/etc/chromium/policies/managed/qcsd-network-prediction.json",
            "name": "qcsd-network-prediction.json",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "mode": "0o444",
            "nlink": 1,
            "size_bytes": 56,
            "sha256": "4566be4f014df0cfd45cf8bdeb4333b341bf4c666139e364992306c12873df03",
        }
    ]
    raw_volume = [
        {
            "Name": volume_name,
            "Driver": "local",
            "Scope": "local",
            "Labels": {**npo0_labels, "org.qcsd.role": "policy_volume"},
            "Options": {},
            "Mountpoint": f"/var/lib/docker/volumes/{volume_name}/_data",
        }
    ]
    npo0_projection = project(
        npo0_network,
        npo0_topology_containers,
        npo0_terminal_containers,
        raw_volume,
        vector_id=npo0_vector,
        prepare_image_id=image_id,
        browser_uid=1000,
        browser_gid=1000,
        attempt_topology=attempt_topology,
        docker_root_dir="/var/lib/docker",
        policy_file_inventory=policy_inventory,
    )
    assert npo0_projection["policy_volume"]["name"] == volume_name
    assert "Mountpoint" not in json.dumps(npo0_projection)
    npo0_resume = {
        "schema_version": 1,
        "checkpoint_publish_lag": False,
        "checkpoint_status": "running",
        "prepare_image_id": image_id,
        "docker_root_dir": "/var/lib/docker",
        "cleanup": {
            "vector_id": npo0_vector,
            "global_ordinal": 1,
            "attempt_number": 1,
            "evidence_directory": f"evidence/097--{npo0_vector}/attempt-1",
            "topology_token": "c" * 32,
            "cohort_version": 71,
            "foundation_payload_sha256": "b" * 64,
            "outstanding": True,
        },
    }
    stale(
        SimpleNamespace(
            resume_plan_json=json.dumps(npo0_resume),
            network_inspect_json=json.dumps([npo0_network]),
            container_inspect_json=json.dumps(npo0_topology_containers),
            volume_inspect_json=json.dumps(raw_volume),
        )
    )
    npo0_cleanup = json.loads(capsys.readouterr().out)
    assert npo0_cleanup["volume_name"] == volume_name

    hostile_volume = copy.deepcopy(raw_volume)
    hostile_volume[0]["Labels"]["org.qcsd.topology-token"] = "d" * 32
    with pytest.raises(ValueError, match="safely attributable"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(npo0_resume),
                network_inspect_json=json.dumps([npo0_network]),
                container_inspect_json=json.dumps(npo0_topology_containers),
                volume_inspect_json=json.dumps(hostile_volume),
            )
        )
    with pytest.raises(ValueError, match="no bound policy volume"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(npo0_resume),
                network_inspect_json=json.dumps([npo0_network]),
                container_inspect_json=json.dumps(npo0_topology_containers),
                volume_inspect_json="null",
            )
        )

    topology_containers[1]["HostConfig"]["CapAdd"] = ["NET_RAW"]
    terminal_containers[1]["HostConfig"]["CapAdd"] = ["NET_RAW"]
    with pytest.raises(ValueError, match="raw Docker capabilities"):
        project(
            network,
            topology_containers,
            terminal_containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )


@pytest.mark.parametrize(
    ("failure_stage", "expected_code"),
    (
        ("success", None),
        ("runtime", "runtime-binding-failed"),
        ("sink", "sink-reconciliation-failed"),
        ("fixture", "fixture-observation-failed"),
        ("capture", "capture-process-failed"),
        ("packet", "packet-policy-failed"),
        ("semantic", "semantic-observation-failed"),
        ("validate-only", None),
    ),
)
def test_browser_egress_assemble_classifies_exact_failure_stage(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    expected_code: str | None,
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_classifier_test",
    )
    assemble = namespace["_assemble"]
    globals_ = assemble.__globals__
    vector_id = "browser-service--browser--dns-prefetch"
    actor = {
        "schema_version": 1,
        "role": "actor",
        "vector_id": vector_id,
        "browser_started_ns": 3,
        "browser_exited_ns": 7,
        "prearm_verified_ns": 4,
        "actor_result": {"started_ns": 5, "finished_ns": 6, "measurement": {}},
        "effective_argv": {},
        "driver_runtime": {},
        "policy_volume_file_inventory": None,
        "child_environment": {},
    }
    forbidden = {
        "schema_version": 1,
        "role": "forbidden-sink",
        "vector_id": vector_id,
        "ready_ns": 1,
        "stopped_ns": 8,
        "tcp": {},
        "udp": {},
    }
    dns = {
        "schema_version": 1,
        "role": "dns-sink",
        "vector_id": vector_id,
        "ready_ns": 2,
        "stopped_ns": 8,
        "receipt": {},
    }
    fixture = {
        "schema_version": 1,
        "role": "fixture",
        "vector_id": vector_id,
        "tls_material": {},
        "receipt": {"chronology": {"ready_ns": 1, "stopped_ns": 8}},
    }
    capture = {
        "schema_version": 1,
        "role": "observer",
        "vector_id": vector_id,
        "receipt": {
            "capture_process": {
                "exit_code": 0,
                "packets_dropped_by_kernel": 0,
                "packets_dropped_by_interface": 0,
            },
            "chronology": {
                "observer_ready_ns": 1,
                "subject_started_ns": 3,
                "subject_exited_ns": 7,
                "reporting_grace_finished_ns": 8,
                "observer_stopped_ns": 9,
            },
            "analysis": {},
        },
    }
    roles = {
        "actor role": actor,
        "forbidden sink role": forbidden,
        "DNS sink role": dns,
        "fixture role": fixture,
        "observer role": capture,
    }
    monkeypatch.setitem(
        globals_,
        "_object",
        lambda path, label: (
            {"global_ordinal": 1, "attempt_number": 1} if label == "next-vector plan" else {}
        ),
    )
    monkeypatch.setitem(globals_, "validate_hash_bound_receipt", lambda *args, **kwargs: {})
    monkeypatch.setitem(globals_, "_sole_stdout_object", lambda path, label: roles[label])
    monkeypatch.setitem(
        globals_,
        "validate_runtime_binding",
        lambda *args, **kwargs: (
            (_ for _ in ()).throw(ValueError("runtime")) if failure_stage == "runtime" else {}
        ),
    )
    monkeypatch.setitem(
        globals_,
        "combine_sink_receipt",
        lambda **kwargs: (
            (_ for _ in ()).throw(ValueError("sink"))
            if failure_stage == "sink"
            else {
                "chronology": {
                    "forbidden_ready_ns": 1,
                    "dns_ready_ns": 2,
                    "forbidden_stopped_ns": 8,
                    "dns_stopped_ns": 8,
                }
            }
        ),
    )
    monkeypatch.setitem(globals_, "validate_sink_receipt", lambda *args, **kwargs: {})
    monkeypatch.setitem(
        globals_,
        "assemble_live_semantic_observation",
        lambda **kwargs: (
            (_ for _ in ()).throw(ValueError("semantic")) if failure_stage == "semantic" else {}
        ),
    )
    monkeypatch.setitem(
        globals_,
        "validate_fixture_observation",
        lambda *args, **kwargs: (
            (_ for _ in ()).throw(ValueError("fixture")) if failure_stage == "fixture" else {}
        ),
    )
    if failure_stage == "capture":
        capture["role"] = "wrong"

    def validate_capture(*args, **kwargs):
        if failure_stage == "packet":
            raise ValueError("browser-egress packet policy failed at forbidden_tcp_initial_syn")
        return {}

    monkeypatch.setitem(globals_, "validate_capture_receipt", validate_capture)
    monkeypatch.setitem(globals_, "reconcile_sink_and_packet_evidence", lambda **kwargs: None)
    passed_receipt = {"receipt": "passed"}
    monkeypatch.setitem(globals_, "build_passed_result_receipt", lambda **kwargs: passed_receipt)
    appended: list[tuple[Path, dict]] = []

    checkpoint = {"checkpoint": "publication-ack"}

    def append_result(root: Path, receipt: dict) -> dict:
        if failure_stage == "validate-only":
            raise AssertionError("validate-only assembly mutated the ledger")
        appended.append((root, receipt))
        return checkpoint

    monkeypatch.setitem(globals_, "append_result", append_result)
    emitted: list[dict] = []
    monkeypatch.setitem(globals_, "_emit", emitted.append)
    args = SimpleNamespace(
        result_root=Path("/result"),
        next_json=Path("/next"),
        actor_json=Path("/actor"),
        forbidden_json=Path("/forbidden"),
        dns_json=Path("/dns"),
        fixture_json=Path("/fixture"),
        capture_json=Path("/capture"),
        runtime_json=Path("/runtime"),
        vector_id=vector_id,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        validate_only=failure_stage == "validate-only",
    )
    assemble(args)
    if failure_stage == "success":
        assert emitted == [{"schema_version": 1, "assembled": True, "checkpoint": checkpoint}]
        assert appended == [(Path("/result"), passed_receipt)]
    elif failure_stage == "validate-only":
        assert emitted == [{"schema_version": 1, "assembled": True}]
        assert appended == []
    else:
        assert emitted == [{"schema_version": 1, "assembled": False, "failure_code": expected_code}]
        assert appended == []


def test_launcher_raw_index_verifier_rejects_clean_filter_forgery(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.name", "test"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "user.email", "test@example.invalid"], check=True
    )
    (checkout / "payload").write_bytes(b"clean")
    (checkout / ".gitattributes").write_text("payload filter=hide\n", encoding="ascii")
    subprocess.run(["git", "-C", checkout, "add", "."], check=True)
    subprocess.run(["git", "-C", checkout, "commit", "-qm", "initial"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "filter.hide.clean", "printf clean"],
        check=True,
    )
    # Keep the size equal to the committed payload so Git consults the clean
    # filter instead of rejecting the cached entry from size metadata alone.
    (checkout / "payload").write_bytes(b"evil!")
    status = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
    )
    assert status.stdout == b"", "the fixture must reproduce Git clean-filter hiding"

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split('if [[ "${1:-}" == "-h"', 1)[0]
    command = "_qcsd_trusted_git() {" + functions + '\n_qcsd_verify_git_index_bytes "$1"\n'
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_checkout_binding_rejects_local_worktree_redirect(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    alternate = tmp_path / "alternate"
    checkout.mkdir()
    alternate.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "core.worktree", str(alternate)],
        check=True,
    )
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split(
        "_qcsd_verify_git_index_bytes() {", 1
    )[0]
    command = (
        "_qcsd_trusted_git() {" + functions + '\n_qcsd_verify_git_checkout_binding "$1" "$1/.git"\n'
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_checkout_binding_rejects_hidden_untracked_source(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    exclude = checkout / ".git/info/exclude"
    exclude.write_text("hidden.py\n", encoding="ascii")
    (checkout / "hidden.py").write_text("raise RuntimeError('in build context')\n")
    status = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
    )
    assert status.stdout == b"", "the fixture must hide the untracked source from Git"
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split(
        "_qcsd_verify_git_index_bytes() {", 1
    )[0]
    command = (
        "_qcsd_trusted_git() {" + functions + '\n_qcsd_verify_git_checkout_binding "$1" "$1/.git"\n'
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_raw_index_verifier_rejects_intermediate_symlink(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.name", "test"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "user.email", "test@example.invalid"], check=True
    )
    nested = checkout / "nested"
    nested.mkdir()
    (nested / "payload").write_bytes(b"clean")
    subprocess.run(["git", "-C", checkout, "add", "."], check=True)
    subprocess.run(["git", "-C", checkout, "commit", "-qm", "initial"], check=True)
    moved = tmp_path / "moved"
    nested.rename(moved)
    nested.symlink_to(moved, target_is_directory=True)

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split('if [[ "${1:-}" == "-h"', 1)[0]
    command = "_qcsd_trusted_git() {" + functions + '\n_qcsd_verify_git_index_bytes "$1"\n'
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_trusted_git_ignores_replace_refs(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.name", "test"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "user.email", "test@example.invalid"], check=True
    )
    payload = checkout / "payload"
    payload.write_text("original\n")
    subprocess.run(["git", "-C", checkout, "add", "payload"], check=True)
    subprocess.run(["git", "-C", checkout, "commit", "-qm", "original"], check=True)
    original = subprocess.check_output(
        ["git", "-C", checkout, "rev-parse", "HEAD"], text=True
    ).strip()
    payload.write_text("replacement\n")
    subprocess.run(["git", "-C", checkout, "commit", "-qam", "replacement"], check=True)
    replacement = subprocess.check_output(
        ["git", "-C", checkout, "rev-parse", "HEAD"], text=True
    ).strip()
    subprocess.run(["git", "-C", checkout, "reset", "--soft", original], check=True)
    subprocess.run(["git", "-C", checkout, "replace", original, replacement], check=True)
    forged = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain"],
        check=True,
        capture_output=True,
    )
    assert forged.stdout == b"", "the fixture must reproduce replace-ref clean forgery"

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    trusted = launcher.split("_qcsd_trusted_git() {", 1)[1].split("\n}", 1)[0]
    command = (
        "_qcsd_trusted_git() {" + trusted + '\n}\n_qcsd_trusted_git -C "$1" status --porcelain\n'
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=True,
        capture_output=True,
    )
    assert result.stdout != b""


def test_acquisition_actions_repeat_exact_scoped_validation_across_go() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    scope_call = '"${class_watch_scope_recovery[@]}" >/dev/null'
    assert launcher.count(scope_call) == 2
    scope_setup = launcher.index("class_watch_scope_recovery=(")
    first_call = launcher.index(scope_call, scope_setup)
    admission_branch = launcher.index(
        '"${class_study_action}" == "acquisition-admission" ]]; then', first_call
    )
    guardian = launcher.index("\n  require_docker\n", admission_branch)
    assert first_call < guardian
    require_body = launcher.split("require_docker() {", 1)[1].split("\n}", 1)[0]
    assert require_body.index("_qcsd_require_lifecycle_guardian_entry") < require_body.index(
        scope_call
    )
    assert "--recover-stale-scopes-internal" in launcher[scope_setup:first_call]
    assert "_qcsd_docker_api" not in launcher[scope_setup:first_call]
    assert "qcsd_run_" not in launcher[scope_setup:first_call]


def _launcher_shell_function(
    launcher: str,
    function: str,
    *,
    following_function: str | None = None,
) -> str:
    start = launcher.index(f"{function}() {{")
    if following_function is None:
        end = launcher.index("\n}", start) + 2
    else:
        end = (
            launcher.index(
                f"\n}}\n\n{following_function}() {{",
                start,
            )
            + 2
        )
    return launcher[start:end] + "\n"


def _cohort_ledger_path(root: Path) -> Path:
    return root / "config" / "buflo-study" / "v1" / "consumed-cohorts.json"


def _write_cohort_ledger_bytes(root: Path, payload: bytes) -> Path:
    path = _cohort_ledger_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def _write_cohort_ledger(root: Path, payload: object) -> Path:
    return _write_cohort_ledger_bytes(
        root,
        (json.dumps(payload, sort_keys=True) + "\n").encode(),
    )


def _valid_cohort_ledger() -> dict[str, object]:
    return {
        "artifact_type": "qcsd-buflo-study-consumed-cohorts",
        "consumed_versions": list(range(1, 62)),
        "policy": "dense-prefix-durable-publications-consume-v1",
        "schema_version": 1,
    }


def _run_test_git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-C",
            str(root),
            *arguments,
        ],
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit_test_git(root: Path, message: str, *, allow_empty: bool = False) -> str:
    arguments = [
        "-c",
        "user.name=QCSD test",
        "-c",
        "user.email=qcsd-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "--message",
        message,
    ]
    if allow_empty:
        arguments.append("--allow-empty")
    _run_test_git(root, *arguments)
    return _run_test_git(root, "rev-parse", "--verify", "HEAD^{commit}")


def _cohort_git_repository(
    tmp_path: Path,
    *,
    payload: object | None = None,
    raw_payload: bytes | None = None,
) -> tuple[Path, Path]:
    assert (payload is None) != (raw_payload is None)
    root = tmp_path / "lab"
    root.mkdir(mode=0o700)
    _run_test_git(root, "init", "--quiet", "--object-format=sha1")

    neqo = root / "neqo-qcsd"
    neqo.mkdir(mode=0o700)
    _run_test_git(neqo, "init", "--quiet", "--object-format=sha1")
    (neqo / "Cargo.lock").write_text("nested lock\n", encoding="utf-8")
    _run_test_git(neqo, "add", "--", "Cargo.lock")
    _commit_test_git(neqo, "nested source")

    ledger = (
        _write_cohort_ledger(root, payload)
        if payload is not None
        else _write_cohort_ledger_bytes(root, raw_payload or b"")
    )
    _run_test_git(root, "add", "--", "config/buflo-study/v1/consumed-cohorts.json")
    _run_test_git(root, "add", "--", "neqo-qcsd")
    _commit_test_git(root, "cohort authority")
    return root, ledger


def _run_cohort_ledger_validator(
    root: Path,
    requested: str,
    *,
    after_open_injection: str = "",
) -> subprocess.CompletedProcess[str]:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    trusted_git = _launcher_shell_function(launcher, "_qcsd_trusted_git")
    validator = _launcher_shell_function(
        launcher,
        "_qcsd_validate_consumed_cohort_ledger",
        following_function="_qcsd_reprove_build_cohort_authority",
    )
    if after_open_injection:
        marker = '    index_entry = os.stat("index", dir_fd=git_fd, follow_symlinks=False)\n'
        assert validator.count(marker) == 1
        validator = validator.replace(
            marker,
            marker + "\n" + after_open_injection + "\n",
        )
    command = (
        "set -euo pipefail\n"
        + trusted_git
        + validator
        + 'ROOT="$1"\n_qcsd_validate_consumed_cohort_ledger "$2"\n'
    )
    return subprocess.run(
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            command,
            "ledger",
            str(root),
            requested,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )


def test_consumed_cohort_ledger_authenticates_any_fresh_claim_candidate(
    tmp_path: Path,
) -> None:
    root, ledger = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())

    accepted = _run_cohort_ledger_validator(root, "62")
    assert accepted.returncode == 0, accepted.stderr
    authority = json.loads(accepted.stdout)
    assert set(authority) == {
        "schema_version",
        "artifact_type",
        "git",
        "filesystem",
        "receipt",
    }
    assert authority["schema_version"] == 2
    assert authority["artifact_type"] == ("qcsd-buflo-study-cohort-allocation-authority")
    git = authority["git"]
    receipt = authority["receipt"]
    assert git["object_format"] == "sha1"
    assert git["lab_head"] == _run_test_git(root, "rev-parse", "HEAD")
    assert git["neqo_head"] == _run_test_git(root / "neqo-qcsd", "rev-parse", "HEAD")
    assert git["head_gitlink"] == git["neqo_head"] == git["index_gitlink"]
    assert git["head_blob_oid"] == git["index_blob_oid"] == git["worktree_blob_oid"]
    proof = receipt["lab_commit_ledger_proof"]
    assert set(proof) == {
        "schema_version",
        "artifact_type",
        "commit_payload_base64",
        "tree_payloads_base64",
    }
    assert proof["schema_version"] == 1
    assert proof["artifact_type"] == "qcsd-buflo-study-cohort-ledger-git-proof"
    assert len(proof["tree_payloads_base64"]) == 4
    receipt_without_proof = dict(receipt)
    receipt_without_proof.pop("lab_commit_ledger_proof")
    assert receipt_without_proof == {
        "schema_version": 1,
        "artifact_type": "qcsd-buflo-study-cohort-allocation",
        "policy": "dense-prefix-durable-publications-consume-v1",
        "ledger_path": "config/buflo-study/v1/consumed-cohorts.json",
        "ledger_sha256": sha256_file(ledger),
        "ledger_payload_base64": base64.b64encode(ledger.read_bytes()).decode(),
        "git_object_format": "sha1",
        "ledger_git_blob_oid": git["worktree_blob_oid"],
        "lab_commit": git["lab_head"],
        "neqo_commit": git["neqo_head"],
        "neqo_gitlink": git["head_gitlink"],
        "last_consumed_version": 61,
        "allocated_version": 62,
    }
    assert set(authority["filesystem"]["directories"]) == {
        "repository-root",
        "config",
        "buflo-study",
        "v1",
        "git",
    }
    assert set(authority["filesystem"]["ledger"]) == {
        "dev",
        "inode",
        "uid",
        "gid",
        "mode",
        "nlink",
        "size",
        "mtime_ns",
        "ctime_ns",
    }
    assert set(authority["filesystem"]["directories"]["git"]) == {
        "type",
        "dev",
        "inode",
        "uid",
        "gid",
        "mode",
    }
    assert authority["filesystem"]["directories"]["git"]["type"] == stat.S_IFDIR
    for name in ("repository-root", "config", "buflo-study", "v1"):
        assert set(authority["filesystem"]["directories"][name]) == {
            "dev",
            "inode",
            "uid",
            "gid",
            "mode",
            "nlink",
            "size",
            "mtime_ns",
            "ctime_ns",
        }

    later = _run_cohort_ledger_validator(root, "63")
    assert later.returncode == 0, later.stderr
    assert json.loads(later.stdout)["receipt"]["allocated_version"] == 63

    for requested in ("1", "60", "61", "01", "0", "-1", "true"):
        rejected = _run_cohort_ledger_validator(root, requested)
        assert rejected.returncode != 0, requested


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(schema_version=True),
        lambda value: value.update(schema_version=2),
        lambda value: value.update(policy="unknown"),
        lambda value: value.update(artifact_type="unknown"),
        lambda value: value.update(extra="forbidden"),
        lambda value: value.update(consumed_versions=[]),
        lambda value: value.update(consumed_versions=[1, 2, 4]),
        lambda value: value.update(consumed_versions=[1, 2, 2]),
        lambda value: value.update(consumed_versions=[1, True, 3]),
    ],
    ids=(
        "boolean-schema",
        "future-schema",
        "unknown-policy",
        "unknown-artifact",
        "unknown-key",
        "empty-prefix",
        "gap",
        "duplicate-version",
        "boolean-version",
    ),
)
def test_consumed_cohort_ledger_rejects_malformed_contract(tmp_path: Path, mutate) -> None:
    value = _valid_cohort_ledger()
    mutate(value)
    root, _ledger = _cohort_git_repository(tmp_path, payload=value)

    result = _run_cohort_ledger_validator(root, "62")

    assert result.returncode != 0


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            b'{"artifact_type":"a","artifact_type":"b",'
            b'"consumed_versions":[1],"policy":"p","schema_version":1}\n',
            "duplicate JSON key",
        ),
        (
            b'{"artifact_type":"qcsd-buflo-study-consumed-cohorts",'
            b'"consumed_versions":[1],"policy":"dense-prefix-durable-publications-consume-v1",'
            b'"schema_version":NaN}\n',
            "invalid JSON constant",
        ),
        (b" " * 16385, "too large"),
    ],
    ids=("duplicate-key", "nan", "oversize"),
)
def test_consumed_cohort_ledger_rejects_noncanonical_bytes(
    tmp_path: Path, payload: bytes, expected_error: str
) -> None:
    root, _path = _cohort_git_repository(tmp_path, raw_payload=payload)

    result = _run_cohort_ledger_validator(root, "2")

    assert result.returncode != 0
    assert expected_error in result.stderr


@pytest.mark.parametrize(
    "variant",
    ["missing", "symlink", "directory", "fifo", "hardlink", "writable"],
)
def test_consumed_cohort_ledger_rejects_unsafe_filesystem_identity(
    tmp_path: Path, variant: str
) -> None:
    root, path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    if variant == "missing":
        path.unlink()
    elif variant == "symlink":
        target = tmp_path / "outside-ledger.json"
        target.write_text(json.dumps(_valid_cohort_ledger()), encoding="utf-8")
        path.unlink()
        path.symlink_to(target)
    elif variant == "directory":
        path.unlink()
        path.mkdir()
    elif variant == "fifo":
        path.unlink()
        os.mkfifo(path, mode=0o600)
    else:
        if variant == "hardlink":
            os.link(path, root / "second-ledger-link")
        else:
            path.chmod(0o622)

    result = _run_cohort_ledger_validator(root, "62")

    assert result.returncode != 0


def test_consumed_cohort_ledger_rejects_worktree_byte_drift(tmp_path: Path) -> None:
    root, path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    before = _run_cohort_ledger_validator(root, "62")
    assert before.returncode == 0, before.stderr
    path.write_text(
        json.dumps(_valid_cohort_ledger(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    after = _run_cohort_ledger_validator(root, "62")

    assert after.returncode != 0
    assert "worktree bytes differ from the checked-in Git blob" in after.stderr


def test_consumed_cohort_ledger_rejects_index_drift(tmp_path: Path) -> None:
    root, path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    value = _valid_cohort_ledger()
    value["consumed_versions"] = list(range(1, 63))
    _write_cohort_ledger(root, value)
    _run_test_git(root, "add", "--", str(path.relative_to(root)))

    result = _run_cohort_ledger_validator(root, "62")

    assert result.returncode != 0
    assert "consumed-cohort Git blob identity is invalid" in result.stderr


def test_consumed_cohort_authority_pins_clean_head_drift(tmp_path: Path) -> None:
    root, _path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    before = _run_cohort_ledger_validator(root, "62")
    assert before.returncode == 0, before.stderr
    _commit_test_git(root, "new clean head", allow_empty=True)

    after = _run_cohort_ledger_validator(root, "62")

    assert after.returncode == 0, after.stderr
    before_authority = json.loads(before.stdout)
    after_authority = json.loads(after.stdout)
    assert before_authority != after_authority
    assert before_authority["git"]["lab_head"] != after_authority["git"]["lab_head"]
    assert (
        before_authority["git"]["worktree_blob_oid"] == after_authority["git"]["worktree_blob_oid"]
    )


def test_consumed_cohort_ledger_rejects_nested_head_drift(tmp_path: Path) -> None:
    root, _path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    neqo = root / "neqo-qcsd"
    (neqo / "Cargo.lock").write_text("changed nested lock\n", encoding="utf-8")
    _run_test_git(neqo, "add", "--", "Cargo.lock")
    _commit_test_git(neqo, "nested head drift")

    result = _run_cohort_ledger_validator(root, "62")

    assert result.returncode != 0
    assert "consumed-cohort Git commit identity is invalid" in result.stderr


def test_consumed_cohort_ledger_rejects_ancestor_symlink(tmp_path: Path) -> None:
    root, _path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    config = root / "config"
    target = root / "config-target"
    config.rename(target)
    config.symlink_to(target.name, target_is_directory=True)

    result = _run_cohort_ledger_validator(root, "62")

    assert result.returncode != 0


def test_consumed_cohort_ledger_allows_benign_directory_child_churn(
    tmp_path: Path,
) -> None:
    root, _path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())

    result = _run_cohort_ledger_validator(
        root,
        "62",
        after_open_injection=(
            '    os.mkdir(".qcsd-benign-churn", 0o700, dir_fd=root_fd)\n'
            '    os.rmdir(".qcsd-benign-churn", dir_fd=root_fd)'
        ),
    )

    assert result.returncode == 0, result.stderr


def test_consumed_cohort_authority_ignores_cross_boundary_git_child_churn(
    tmp_path: Path,
) -> None:
    root, _path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    before_stat = (root / ".git").stat()
    before = _run_cohort_ledger_validator(root, "62")
    assert before.returncode == 0, before.stderr

    transient = root / ".git/qcsd-benign-transient"
    transient.write_text("transient\n", encoding="ascii")
    transient.unlink()

    after_stat = (root / ".git").stat()
    after = _run_cohort_ledger_validator(root, "62")
    assert after.returncode == 0, after.stderr
    assert (before_stat.st_mtime_ns, before_stat.st_ctime_ns) != (
        after_stat.st_mtime_ns,
        after_stat.st_ctime_ns,
    )
    assert before.stdout == after.stdout


@pytest.mark.parametrize(
    "after_open_injection",
    (
        '    os.chmod("config", 0o777, dir_fd=root_fd)',
        (
            '    config_mode = stat.S_IMODE(os.stat("config", dir_fd=root_fd, '
            "follow_symlinks=False).st_mode)\n"
            '    os.rename("config", "config-moved", src_dir_fd=root_fd, '
            "dst_dir_fd=root_fd)\n"
            '    os.mkdir("config", config_mode, dir_fd=root_fd)'
        ),
    ),
    ids=("mode-drift", "replacement"),
)
def test_consumed_cohort_ledger_rejects_unsafe_directory_identity_drift(
    tmp_path: Path,
    after_open_injection: str,
) -> None:
    root, _path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())

    result = _run_cohort_ledger_validator(
        root,
        "62",
        after_open_injection=after_open_injection,
    )

    assert result.returncode != 0
    assert "consumed-cohort config identity changed while read" in result.stderr


def test_consumed_cohort_authority_pins_same_content_inode_drift(
    tmp_path: Path,
) -> None:
    root, path = _cohort_git_repository(tmp_path, payload=_valid_cohort_ledger())
    before = _run_cohort_ledger_validator(root, "62")
    assert before.returncode == 0, before.stderr
    replacement = tmp_path / "replacement-ledger.json"
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, path)

    after = _run_cohort_ledger_validator(root, "62")

    assert after.returncode == 0, after.stderr
    before_authority = json.loads(before.stdout)
    after_authority = json.loads(after.stdout)
    assert before_authority != after_authority
    assert (
        before_authority["receipt"]["ledger_sha256"] == after_authority["receipt"]["ledger_sha256"]
    )
    assert (
        before_authority["filesystem"]["ledger"]["inode"]
        != after_authority["filesystem"]["ledger"]["inode"]
    )


def test_build_checks_exact_cohort_authority_before_every_mutation_boundary() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    build = launcher.split('if [[ "${1:-}" == "build" ]]; then', 1)[1].split(
        'elif [[ "${1:-}" == "lifecycle-recover" ]]', 1
    )[0]
    guardian_entry = build.index("_qcsd_require_lifecycle_guardian_entry")
    first = build.index("build_cohort_ledger_snapshot")
    preclaim_reproof = build.index('_qcsd_reprove_build_cohort_authority "before-cohort-claim"')
    claim_publish = build.index("_qcsd_invoke_cohort_allocator publish")
    chain_capture = build.index("_qcsd_invoke_cohort_allocator chain")
    first_reproof = build.index('"after-cohort-claim-before-docker-recovery"')
    assert (
        build.index("reject_docker_endpoint_overrides")
        < guardian_entry
        < build.index('mkdir -p -- "${build_receipt_parent}"')
        < first
        < preclaim_reproof
        < claim_publish
        < chain_capture
        < first_reproof
        < build.index("\n  require_docker\n")
    )
    assert (
        '_qcsd_reprove_build_cohort_authority "after-evidence-build-lock"'
        in build[build.index("acquire_evidence_build_lock") :]
    )
    recovery_body = launcher.split("reconcile_stale_docker_supervisors() {", 1)[1].split("\n}", 1)[
        0
    ]
    recovery_reproof = recovery_body.index(
        '_qcsd_reprove_build_cohort_authority "immediately-before-docker-recovery"'
    )
    first_recovery_read = recovery_body.index(
        "# Validate the durable namespace before legacy recovery can mutate anything"
    )
    assert recovery_reproof < first_recovery_read
    second_build = launcher.split('if [[ "${1:-}" == "build" ]]; then', 2)[2]
    recheck = second_build.index(
        '_qcsd_reprove_build_cohort_authority "immediately-before-build-transaction"'
    )
    transaction = second_build.index("begin_evidence_build_transaction")
    assert recheck < transaction
    assert (
        '_qcsd_reprove_build_cohort_authority "immediately-after-build-transaction"'
        in second_build[transaction:]
    )
    final_recorded_reproof = second_build.index(
        '_qcsd_reprove_build_cohort_authority "after-reference-build-before-receipt"'
    )
    assert (
        second_build.rfind("validate_local_docker_build_endpoint", 0, final_recorded_reproof)
        < final_recorded_reproof
        < second_build.index("build_cohort_reproofs_json", final_recorded_reproof)
        < second_build.index("build_finished_unix_ns", final_recorded_reproof)
    )
    reproof = _launcher_shell_function(
        launcher,
        "_qcsd_reprove_build_cohort_authority",
        following_function=None,
    )
    assert (
        reproof.index("_qcsd_verify_clean_build_checkout")
        < reproof.index("_qcsd_validate_consumed_cohort_ledger")
        < reproof.index('"${recheck}" != "${build_cohort_ledger_snapshot:-}"')
    )
    allocator = _launcher_shell_function(
        launcher,
        "_qcsd_invoke_cohort_allocator",
        following_function="_qcsd_open_cohort_chain_channel",
    )
    assert "< <(" in allocator
    assert "exec /usr/bin/python3 -I" in allocator
    assert "$(" not in allocator
    assert " | " not in allocator
    for option in (
        "--held-lock-owner-pid",
        "--held-lock-owner-start",
        "--held-lock-guardian-pid",
        "--held-lock-guardian-start",
        "--held-lock-guardian-fd",
        "--held-lock-path",
        "--held-lock-device",
        "--held-lock-inode",
        "--held-lock-parent-device",
        "--held-lock-parent-inode",
        "--held-lock-cohort-version",
    ):
        assert option in allocator
    chain_channel = _launcher_shell_function(
        launcher,
        "_qcsd_open_cohort_chain_channel",
        following_function="_qcsd_verify_saved_build_cohort_claim",
    )
    assert "< <(" in chain_channel
    assert "printf '%s\\n'" in chain_channel
    assert "exec /usr/bin/printf" not in chain_channel
    assert 'BUILD_COHORT_CLAIM_CHAIN="' not in launcher
    assert 'BUILD_COHORT_CLAIM_CHAIN_FD="${build_cohort_chain_fd}"' in launcher
    saved_claim = _launcher_shell_function(
        launcher,
        "_qcsd_verify_saved_build_cohort_claim",
        following_function="_qcsd_verify_saved_build_cohort_authority",
    )
    assert "_qcsd_invoke_cohort_allocator verify" in saved_claim
    assert "_qcsd_invoke_cohort_allocator chain" in saved_claim
    assert '"${claim_recheck}" != "${build_cohort_claim_snapshot}"' in saved_claim
    assert '"${chain_recheck}" != "${build_cohort_claim_chain}"' in saved_claim
    saved_authority = _launcher_shell_function(
        launcher,
        "_qcsd_verify_saved_build_cohort_authority",
        following_function="_qcsd_reprove_build_cohort_authority",
    )
    assert "_qcsd_verify_clean_build_checkout" in saved_authority
    assert "_qcsd_validate_consumed_cohort_ledger" in saved_authority
    assert '"${recheck}" != "${build_cohort_ledger_snapshot:-}"' in saved_authority
    assert "_qcsd_verify_saved_build_cohort_claim" in saved_authority
    receipt_tail = second_build[second_build.index("BUILD_RECEIPT_STAGE=") :]
    pre_publication = receipt_tail.index("immediately-before-receipt-publication")
    publication = receipt_tail.index("linkat(")
    post_publication = receipt_tail.index("immediately-after-receipt-publication")
    transaction_completion = receipt_tail.index("complete_evidence_build_transaction")
    iid_cleanup = receipt_tail.index("complete_build_iid_cleanup_before_success")
    post_transaction = receipt_tail.index("_qcsd_reprove_build_completion_authority")
    completion_publication = receipt_tail.index("publish-completion")
    final_exit = receipt_tail.index("exit 0", completion_publication)
    assert (
        pre_publication
        < publication
        < post_publication
        < transaction_completion
        < iid_cleanup
        < post_transaction
        < completion_publication
        < final_exit
    )
    completion_command = receipt_tail[completion_publication:final_exit]
    for option in (
        "--receipt-binding-json",
        "--transaction-binding-json",
        "--held-lock-owner-pid",
        "--held-lock-guardian-pid",
        "--held-lock-guardian-fd",
        "--lifecycle-lock-path",
        "--lifecycle-lease-nonce",
        "--retired-transaction-root",
    ):
        assert option in completion_command


def test_cohort_chain_channel_carries_payload_larger_than_exec_arg_max(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    channel = _launcher_shell_function(
        launcher,
        "_qcsd_open_cohort_chain_channel",
        following_function="_qcsd_verify_saved_build_cohort_claim",
    )
    payload = b"{" + b'"chain":"' + b"a" * (3 * 1024 * 1024) + b'"}'
    payload_path = tmp_path / "large-chain.json"
    payload_path.write_bytes(payload)
    expected_sha256 = hashlib.sha256(payload + b"\n").hexdigest()
    script = (
        "set -euo pipefail\n"
        + channel
        + 'chain="$(<"$1")"\n'
        + 'descriptor=""\nproducer=""\n'
        + '_qcsd_open_cohort_chain_channel "$chain" descriptor producer\n'
        + "reader_status=0\n"
        + 'if BUILD_COHORT_CLAIM_CHAIN_FD="$descriptor" '
        + "/usr/bin/python3 -I -c "
        + shlex.quote(
            "import hashlib,os,sys; "
            "fd=int(os.environ['BUILD_COHORT_CLAIM_CHAIN_FD']); "
            "raw=os.fdopen(os.dup(fd),'rb').read(); "
            "raise SystemExit(0 if hashlib.sha256(raw).hexdigest()==sys.argv[1] "
            "and raw.endswith(b'\\n') and raw.count(b'\\n')==1 else 1)"
        )
        + ' "$2"; then :; else reader_status=$?; fi\n'
        + 'producer_status=0\nwait "$producer" || producer_status=$?\n'
        + 'close_status=0\neval "exec ${descriptor}<&-" || close_status=$?\n'
        + "(( reader_status == 0 && producer_status == 0 && close_status == 0 ))\n"
    )

    result = subprocess.run(
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            script,
            "chain-channel",
            str(payload_path),
            expected_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("version", ["60", "61"])
def test_real_build_rejects_genesis_consumed_cohort_before_docker(
    version: str,
) -> None:
    launcher = Path(__file__).parents[1] / "qcsd-lab"
    environment = dict(os.environ)
    for key in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_DEFAULT_PLATFORM",
        "BUILDX_BUILDER",
        "BUILDX_CONFIG",
        "BUILDKIT_HOST",
        "DOCKER_BUILDKIT",
        "QCSD_LAB_COLLECTION_IMAGE",
        "QCSD_LAB_PREPARE_IMAGE",
        "QCSD_LAB_REFERENCE_IMAGE",
    ):
        environment.pop(key, None)

    result = subprocess.run(
        [str(launcher), "build", "--cohort-version", version],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    # The guardian maps any pre-final-admission child failure to its closed
    # status 125; the diagnostic proves allocation failed before Docker.
    assert result.returncode == 125
    assert "build cohort allocation is not authorised" in result.stderr
    assert "evidence build rejects Docker endpoint" not in result.stderr


def test_real_build_rejects_omitted_cohort_before_docker() -> None:
    launcher = Path(__file__).parents[1] / "qcsd-lab"
    environment = {**os.environ, "DOCKER_HOST": "tcp://127.0.0.1:1"}

    result = subprocess.run(
        [str(launcher), "build"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert "build requires exactly one explicit --cohort-version N" in result.stderr
    assert "Docker endpoint overrides are not allowed" not in result.stderr


def test_launcher_privileged_startup_ignores_hostile_bash_hooks_and_path(
    tmp_path: Path,
) -> None:
    launcher = Path(__file__).parents[1] / "qcsd-lab"
    marker = tmp_path / "bash-environment-ran"
    path_marker = tmp_path / "hostile-path-ran"
    bash_environment = tmp_path / "hostile-bash-environment"
    bash_environment.write_text(
        f"printf ran > {shlex.quote(str(marker))}\n"
        "set -p\n"
        "set -T\n"
        "trap '_QCSD_LIFECYCLE_ENTRY_VALIDATED=1' DEBUG RETURN\n",
        encoding="utf-8",
    )
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    hostile_commands = (
        "awk",
        "dirname",
        "env",
        "id",
        "readlink",
        "sha256sum",
        "stat",
    )
    for command in hostile_commands:
        system_command = shutil.which(command, path="/usr/bin:/bin")
        assert system_command is not None
        wrapper = hostile_bin / command
        wrapper.write_text(
            "#!/bin/sh\n"
            f"printf ran > {shlex.quote(str(path_marker))}\n"
            f'exec {shlex.quote(system_command)} "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
    environment = {
        **os.environ,
        "BASH_ENV": str(bash_environment),
        "ENV": str(bash_environment),
        "PATH": str(hostile_bin),
        "_QCSD_LIFECYCLE_ENTRY_VALIDATED": "1",
    }

    direct = subprocess.run(
        [str(launcher), "--help"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert direct.returncode == 0
    assert "Usage: qcsd-lab" in direct.stderr
    assert not marker.exists()
    assert not path_marker.exists()

    explicit_unprivileged_bash = subprocess.run(
        ["/bin/bash", str(launcher), "--help"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert explicit_unprivileged_bash.returncode == 125
    assert marker.read_text(encoding="utf-8") == "ran"
    assert not path_marker.exists()
    assert "must be executed directly by its privileged-mode Bash shebang" in (
        explicit_unprivileged_bash.stderr
    )
    assert "Usage: qcsd-lab" not in explicit_unprivileged_bash.stderr


@pytest.mark.parametrize(
    ("payload", "accepted"),
    [
        (b"a" * 64 + b"\n", True),
        (b"b" * 64 + b"\n", False),
        (b"a" * 63 + b"\n", False),
        (b"a" * 65 + b"\n", False),
        (b"a" * 64, False),
        (b"a" * 64 + b"\n\n", False),
        (b"a" * 64 + b"\nextra\n", False),
        (b"a" * 64 + b"\ntrailing", False),
    ],
    ids=(
        "exact",
        "wrong",
        "short",
        "long",
        "unterminated",
        "empty-extra-line",
        "extra-line",
        "unterminated-trailing-bytes",
    ),
)
def test_lifecycle_frame_reader_accepts_only_exact_closed_frame(
    payload: bytes, accepted: bool
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    body = launcher.split("_qcsd_read_exact_lifecycle_frame() {", 1)[1].split("\n}", 1)[0]
    command = (
        "_qcsd_read_exact_lifecycle_frame() {"
        + body
        + '\n}\n_qcsd_read_exact_lifecycle_frame 0 "$1"\n'
    )
    result = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", command, "frame", "a" * 64],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert (result.returncode == 0) is accepted, result.stderr


def _run_lifecycle_recovery_completion(
    tmp_path: Path, final_payload: bytes
) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    recovery_nonce = "a" * 64
    final_nonce = "b" * 64
    recovery_path = tmp_path / "recovery-frame"
    final_path = tmp_path / "final-frame"
    final_path.write_bytes(final_payload)
    command = (
        _launcher_shell_function(launcher, "_qcsd_read_exact_lifecycle_frame")
        + _launcher_shell_function(launcher, "_qcsd_complete_lifecycle_recovery")
        + 'exec 8>"$1"\n'
        + 'exec 9<"$2"\n'
        + "_QCSD_LIFECYCLE_RECOVERY_READY_FD=8\n"
        + "_QCSD_LIFECYCLE_FINAL_GO_FD=9\n"
        + f"_QCSD_LIFECYCLE_RECOVERY_NONCE={recovery_nonce}\n"
        + f"_QCSD_LIFECYCLE_FINAL_GO_NONCE={final_nonce}\n"
        + "_QCSD_LIFECYCLE_RECOVERY_STATE=armed\n"
        + "_qcsd_complete_lifecycle_recovery\n"
        + 'first_status="$?"\n'
        + 'first_state="${_QCSD_LIFECYCLE_RECOVERY_STATE}"\n'
        # Make the recovery channel writable again so the retry assertion is
        # testing the state latch rather than merely relying on a closed FD.
        + 'exec 8>>"$1"\n'
        + "_qcsd_complete_lifecycle_recovery\n"
        + 'second_status="$?"\n'
        + "printf '%s %s %s %s\\n' "
        + '"${first_status}" "${first_state}" "${second_status}" '
        + '"${_QCSD_LIFECYCLE_RECOVERY_STATE}"\n'
    )
    result = subprocess.run(
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            command,
            "recovery",
            str(recovery_path),
            str(final_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result, recovery_path.read_bytes()


def test_lifecycle_recovery_completion_succeeds_only_once(tmp_path: Path) -> None:
    result, recovery_frames = _run_lifecycle_recovery_completion(tmp_path, b"b" * 64 + b"\n")

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"0 complete 1 complete\n"
    assert result.stderr == b""
    assert recovery_frames == b"a" * 64 + b"\n"


@pytest.mark.parametrize(
    "final_payload",
    [
        b"c" * 64 + b"\n",
        b"",
        b"b" * 64 + b"\ntrailing",
    ],
    ids=("wrong", "eof", "trailing"),
)
def test_lifecycle_recovery_completion_failure_is_terminal(
    tmp_path: Path, final_payload: bytes
) -> None:
    result, recovery_frames = _run_lifecycle_recovery_completion(tmp_path, final_payload)

    assert result.returncode == 0, result.stderr
    assert result.stdout == b"1 consuming 1 consuming\n"
    assert result.stderr == b""
    assert recovery_frames == b"a" * 64 + b"\n"


def test_docker_metadata_reads_have_separate_bounded_setup_allowance() -> None:
    root = Path(__file__).parents[1]
    launcher = (root / "qcsd-lab").read_text(encoding="utf-8")
    helper = (root / "tools/docker_signal_supervisor.sh").read_text(encoding="utf-8")
    assert "\n_QCSD_DOCKER_API_TIMEOUT_SECONDS=3\n" in helper
    assert "\n_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS=10\n" in helper
    assert "\n_QCSD_DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS=120\n" in helper
    # Every use of the longer metadata allowance is an explicit info read;
    # control/mutation paths must not silently inherit it.
    flattened = re.sub(r"\\\n\s*", " ", launcher)
    metadata_reads = re.findall(
        r'_qcsd_docker_api_with_timeout\s+"\$\{_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS\}"'
        r'\s+(?:--context "\$\{[a-z_]+\}"\s+)?info\s+--format',
        flattened,
    )
    assert len(metadata_reads) == 7  # Includes the separate ETF/veth provenance read.
    assert launcher.count('"${_QCSD_DOCKER_METADATA_TIMEOUT_SECONDS}"') == 7
    assert launcher.count("$(_qcsd_read_docker_daemon_id ") == 4


def test_docker_recovery_precedes_reproof_and_final_admission() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    body = launcher.split("require_docker() {", 1)[1].split("\n}", 1)[0]
    guardian = body.index("_qcsd_require_lifecycle_guardian_entry")
    recovery = body.index("reconcile_stale_docker_supervisors")
    daemon_reproof = body.index('observed_server_id="$(_qcsd_read_docker_daemon_id', recovery)
    boot_reproof = body.index(
        "IFS= read -r observed_boot_id </proc/sys/kernel/random/boot_id",
        daemon_reproof,
    )
    final_admission = body.index("_qcsd_complete_lifecycle_recovery")

    assert guardian < recovery < daemon_reproof < boot_reproof < final_admission


def test_acquisition_scope_digest_binds_current_argv_before_recovery() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    digest = launcher.index('class_watch_current_action_sha256="$(')
    comparison = launcher.index(
        "scoped request action does not match current argv",
        digest,
    )
    recovery = launcher.index("class_watch_scope_recovery=(", comparison)

    assert "command = list(sys.argv[1:])" in launcher[digest:comparison]
    assert '"${ROOT}/qcsd-lab" "${QCSD_ORIGINAL_ARGV[@]}"' in launcher[digest:comparison]
    assert '"${QCSD_CLASS_WATCH_ACTION_SHA256}"' in launcher[digest:comparison]
    assert comparison < recovery


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
    assert '"${ROOT}/config/chaff-prefix-specs/v2"' in launcher
    assert '"${ROOT}/config/chaff-qualification-store"' in launcher
    assert '[[ ! -d "${required_directory}" || -L "${required_directory}" ]]' in launcher
    qualification_mounts = launcher.split(
        'if [[ "${1:-}" == "qualify-chaff" ]]; then\n  container+=(', 1
    )[-1].split("\nfi", 1)[0]
    assert '--volume "${ROOT}/config/workloads:/lab/config/workloads:ro"' in qualification_mounts
    assert (
        '--volume "${ROOT}/config/chaff-prefix-specs:/lab/config/chaff-prefix-specs:ro"'
        in qualification_mounts
    )
    assert (
        '--volume "${ROOT}/config/chaff-qualification-store:'
        '/lab/config/chaff-qualification-store:rw"' in qualification_mounts
    )
    assert (
        '--volume "${qualification_child}:'
        '/lab/config/chaff-qualification-store/${qualification_name}:ro"' in qualification_mounts
    )
    assert "validate_qualification_store_delta" in launcher
    assert "changed pre-existing qualification evidence" in launcher
    assert "outside the exact schema-two cohort" in launcher
    assert "outside one hidden candidate" in launcher


def test_qualification_store_delta_validator_executes_publication_states(tmp_path):
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_qualification_store_delta")
    existing = {
        ".gitkeep": {"type": "file", "sha256": "a" * 64},
        "v1": {"type": "directory"},
        "v1/historical.json": {"type": "file", "sha256": "b" * 64},
    }
    ids = (
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    )
    cohort = {"v2": {"type": "directory"}} | {
        f"v2/{workload}.json": {"type": "file", "sha256": "c" * 64} for workload in ids
    }
    published = _run_embedded_python(tmp_path, validator, existing, existing | cohort, "0")
    assert published.returncode == 0, published.stderr

    unchanged_failure = _run_embedded_python(tmp_path, validator, existing, existing, "7")
    assert unchanged_failure.returncode == 0, unchanged_failure.stderr

    candidate = {
        ".v2.qcsd-batch-proof": {"type": "directory"},
        ".v2.qcsd-batch-proof/run.log": {"type": "file", "sha256": "d" * 64},
    }
    retained_failure = _run_embedded_python(
        tmp_path, validator, existing, existing | candidate, "7"
    )
    assert retained_failure.returncode == 0, retained_failure.stderr

    mutated = dict(existing)
    mutated["v1/historical.json"] = {"type": "file", "sha256": "e" * 64}
    changed_history = _run_embedded_python(tmp_path, validator, existing, mutated, "7")
    assert changed_history.returncode != 0
    assert "pre-existing qualification evidence" in changed_history.stderr

    unauthorized = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | {"unexpected": {"type": "directory"}},
        "7",
    )
    assert unauthorized.returncode != 0
    assert "outside one hidden candidate" in unauthorized.stderr


def test_launcher_response_qualification_is_exact_five_and_least_privilege() -> None:
    root = Path(__file__).parents[1]
    launcher = (root / "qcsd-lab").read_text(encoding="utf-8")
    sets_marker = root / "config/chaff-response-qualification-store/sets/.gitkeep"
    assert sets_marker.is_file() and not sets_marker.is_symlink()
    assert "qualify-response-chaff requires exactly five workload IDs" in launcher
    assert '"${ROOT}/config/chaff-response-qualification-store"' in launcher
    assert "config/chaff-response-qualification-store/v2" in launcher
    mounts = launcher.split(
        'if [[ "${1:-}" == "qualify-response-chaff" ]]; then\n  container+=(', 1
    )[-1].split('if [[ "${1:-}" == "fit" ]]; then', 1)[0]
    assert '--volume "${ROOT}/config/workloads:/lab/config/workloads:ro"' in mounts
    assert (
        '--volume "${ROOT}/config/chaff-response-qualification-store:'
        '/lab/config/chaff-response-qualification-store:rw"' in mounts
    )
    assert (
        '--volume "${ROOT}/config/chaff-response-qualification-store:'
        '/lab/config/chaff-response-qualification-store:ro"' in mounts
    )
    assert (
        '--volume "${response_qualification_sets_root}:'
        '/lab/config/chaff-response-qualification-store/sets:rw"' in mounts
    )
    assert (
        '--volume "${response_qualification_child}:'
        '/lab/config/chaff-response-qualification-store/${response_qualification_name}:ro"'
        in mounts
    )
    assert (
        '--volume "${existing_response_set}:'
        '/lab/config/chaff-response-qualification-store/sets/${existing_response_set_name}:ro"'
        in mounts
    )
    assert "response_qualification_set_explicit" in launcher
    assert "requires absent set target" in launcher
    assert "validate_response_qualification_store_delta" in launcher


def test_response_qualification_delta_validator_enforces_dynamic_exact_five(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_response_qualification_store_delta")
    existing = {".gitkeep": {"type": "file", "sha256": "a" * 64}}
    ids = ("alpha", "bravo", "charlie", "delta", "echo")
    cohort = {"v2": {"type": "directory"}} | {
        f"v2/{workload}.json": {"type": "file", "sha256": "b" * 64} for workload in ids
    }

    published = _run_embedded_python(
        tmp_path, validator, existing, existing | cohort, "0", "legacy", "", *ids
    )
    assert published.returncode == 0, published.stderr

    candidate = {
        ".v2.qcsd-batch-proof": {"type": "directory"},
        ".v2.qcsd-batch-proof/response-0.log": {
            "type": "file",
            "sha256": "c" * 64,
        },
    }
    retained = _run_embedded_python(
        tmp_path, validator, existing, existing | candidate, "7", "legacy", "", *ids
    )
    assert retained.returncode == 0, retained.stderr

    partial = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | {"v2": {"type": "directory"}},
        "0",
        "legacy",
        "",
        *ids,
    )
    assert partial.returncode != 0
    assert "outside the exact schema-two cohort" in partial.stderr

    duplicate_ids = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing,
        "7",
        "legacy",
        "",
        *ids[:4],
        ids[0],
    )
    assert duplicate_ids.returncode != 0
    assert "workload cohort is invalid" in duplicate_ids.stderr

    named_existing = existing | {"sets": {"type": "directory"}}
    named_target = {"sets/cohort-v1": {"type": "directory"}} | {
        f"sets/cohort-v1/{workload}.json": {"type": "file", "sha256": "d" * 64} for workload in ids
    }
    named_published = _run_embedded_python(
        tmp_path,
        validator,
        named_existing,
        named_existing | named_target,
        "0",
        "set",
        "cohort-v1",
        *ids,
    )
    assert named_published.returncode == 0, named_published.stderr

    named_candidate = {
        "sets/.cohort-v1.qcsd-batch-proof": {"type": "directory"},
        "sets/.cohort-v1.qcsd-batch-proof/response-0.log": {
            "type": "file",
            "sha256": "e" * 64,
        },
    }
    named_retained = _run_embedded_python(
        tmp_path,
        validator,
        named_existing,
        named_existing | named_candidate,
        "7",
        "set",
        "cohort-v1",
        *ids,
    )
    assert named_retained.returncode == 0, named_retained.stderr

    mixed_target = dict(named_target)
    mixed_target["sets/other-v1/alpha.json"] = {"type": "file", "sha256": "f" * 64}
    mixed = _run_embedded_python(
        tmp_path,
        validator,
        named_existing,
        named_existing | mixed_target,
        "0",
        "set",
        "cohort-v1",
        *ids,
    )
    assert mixed.returncode != 0
    assert "outside the exact schema-two cohort" in mixed.stderr


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
    assert '[[ -e "${ROOT}/config/chaff-prefix-specs/v2"' in launcher
    derivation_mounts = launcher.split(
        'if [[ "${1:-}" == "derive-chaff-prefix-specs" ]]; then\n  container+=(', 1
    )[-1].split("\nfi", 1)[0]
    assert (
        '--volume "${ROOT}/config/chaff-prefix-specs:'
        '/lab/config/chaff-prefix-specs:rw"' in derivation_mounts
    )
    assert '--volume "${ROOT}/config:/lab/config:rw"' not in launcher
    assert (
        '--volume "${prefix_spec_child}:'
        '/lab/config/chaff-prefix-specs/${prefix_spec_name}:ro"' in derivation_mounts
    )
    assert '"chaff-prefix-specs/v2": "directory"' in launcher
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


def test_prefix_derivation_delta_validator_executes_publication_states(tmp_path):
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_prefix_derivation_delta")
    existing = {
        "workloads": {"type": "directory"},
        "workloads/historical.json": {"type": "file", "sha256": "a" * 64},
        "chaff-prefix-specs": {"type": "directory"},
        "chaff-prefix-specs/v1.json": {"type": "file", "sha256": "b" * 64},
    }
    ids = (
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    )
    cohort = {"chaff-prefix-specs/v2": {"type": "directory"}} | {
        f"chaff-prefix-specs/v2/{workload}.json": {
            "type": "file",
            "sha256": "c" * 64,
        }
        for workload in ids
    }
    published = _run_embedded_python(tmp_path, validator, existing, existing | cohort, "0")
    assert published.returncode == 0, published.stderr

    unchanged_failure = _run_embedded_python(tmp_path, validator, existing, existing, "7")
    assert unchanged_failure.returncode == 0, unchanged_failure.stderr

    partial_failure = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | {"chaff-prefix-specs/v2": {"type": "directory"}},
        "7",
    )
    assert partial_failure.returncode != 0
    assert "failed derive-chaff-prefix-specs changed" in partial_failure.stderr

    mutated = dict(existing)
    mutated["workloads/historical.json"] = {"type": "file", "sha256": "d" * 64}
    changed_input = _run_embedded_python(tmp_path, validator, existing, mutated, "7")
    assert changed_input.returncode != 0
    assert "pre-existing config input" in changed_input.stderr


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
    assert (
        "install -m 0755 /opt/qcsd-venv/bin/qcsd-lab-internal /usr/local/bin/qcsd-lab-internal"
    ) in dockerfile
    assert "ln -s /opt/qcsd-venv/bin/qcsd-lab-internal" not in dockerfile
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


def test_response_qualification_cli_forwards_named_set(monkeypatch, capsys):
    import qcsd_lab.chaff_qualification as qualification

    observed = {}

    def qualify(workload_ids, **kwargs):
        observed["workload_ids"] = tuple(workload_ids)
        observed.update(kwargs)
        return ()

    monkeypatch.setattr(qualification, "qualify_all_response_chaff", qualify)
    workload_ids = ("alpha", "bravo", "charlie", "delta", "echo")

    cli.main(
        [
            "qualify-response-chaff",
            "--set",
            "classifier-multiorigin5-v1",
            *workload_ids,
        ]
    )

    assert observed["workload_ids"] == workload_ids
    assert observed["qualification_set"] == "classifier-multiorigin5-v1"
    assert json.loads(capsys.readouterr().out) == {}


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
