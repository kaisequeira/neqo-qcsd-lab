from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.class_build_admission import (
    _MAX_FROZEN_INPUT_ENTRIES,
    BuildAdmission,
    resolve_action_admission,
)
from qcsd_lab.class_study import canonical_json_bytes
from qcsd_lab.util import sha256_file
from tests.test_class_build_admission_source_projection import _numeric_bundle
from tests.test_class_build_admission_successor import (
    _binding,
    _publish,
    _successor_fixture,
)
from tests.test_cli import (
    _class_build_admission_fixture,
    _second_class_build_admission_fixture,
)


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))
    return path


def _resolve_base_resume(fixture: object, *, build_loader=None):
    return resolve_action_admission(
        fixture.root,
        action="resume",
        options={
            "foundation": str(fixture.foundation),
            "capture_result": str(fixture.resume),
        },
        build_loader=build_loader or fixture.load,
    )


def _result(
    root: Path,
    admission: BuildAdmission,
    *,
    name: str,
    role: str,
) -> Path:
    result = root / "results/action-semantics" / name
    _write_json(
        result / "inputs/study-environment.json",
        {
            "schema_version": 3,
            "artifact_type": "qcsd-buflo-study-environment",
            "docker": {
                "client_version": "fixture",
                "server_version": "fixture",
                "server_os": "linux",
                "server_arch": "amd64",
                "ncpu": 1,
                "mem_total_bytes": 1,
                "storage_driver": "fixture",
            },
            "collection_image": {
                "id": admission.collection_image,
                "repo_digests": [],
            },
            "build_inputs": {
                "schema_version": 1,
                "artifact_type": "qcsd-build-inputs",
                "rust_base_image": "fixture",
                "debian_base_image": "fixture",
                "uv_lock_sha256": "0" * 64,
                "cargo_lock_sha256": "0" * 64,
            },
            "build_execution": {
                "receipt": json.loads(admission.receipt_path.read_bytes()),
                "sha256": admission.receipt_sha256,
                "completion_path": admission.identity["completion_path"],
                "completion_sha256": admission.completion_sha256,
                "completion_payload_sha256": admission.completion_payload_sha256,
                "completion": json.loads(admission.completion_path.read_bytes()),
            },
            "clock_status": {
                "relationship": "fixture",
                "host": {},
                "container": {},
            },
            "capture_scheduler": {},
        },
    )
    _write_json(
        result / "experiment.json",
        {
            "name": name,
            "configuration": {"evidence_role": role},
        },
    )
    return result


def _evidence(
    root: Path,
    admission: BuildAdmission,
    foundation: Path,
    *,
    name: str,
    successor_restart: Path | None = None,
    study_id: str = "classifier-multiorigin100-v1",
) -> SimpleNamespace:
    base = root / "artifacts/action-semantics" / name
    evidence: dict[str, object] = {
        "foundation": _binding(foundation),
        "build_execution": _binding(admission.receipt_path),
    }
    if successor_restart is not None:
        evidence["successor_restart"] = _binding(successor_restart)
    readiness = _publish(
        base / "readiness.json",
        "qcsd-class-study-readiness-attestation",
        {
            "attestation_schema_version": 3,
            "artifact_type": "qcsd-class-study-readiness-attestation",
            "study_id": study_id,
            "cohort_version": admission.cohort_version,
            "source": admission.source,
            "build_execution_identity": admission.identity,
            "evidence": evidence,
        },
    )
    historical = _publish(
        base / "historical-post.json",
        "qcsd-class-study-historical-snapshot",
        {
            "snapshot_schema_version": 1,
            "artifact_type": "qcsd-class-study-historical-snapshot",
            "source": admission.source,
            "readiness": _binding(readiness),
        },
    )
    handoff = base / "handoff"
    frozen = handoff / "inputs/class-study-historical-post-snapshot.json"
    frozen.parent.mkdir(parents=True)
    frozen.write_bytes(historical.read_bytes())
    (handoff / "SHA256SUMS").write_text("fixture\n", encoding="ascii")
    evaluation = _publish(
        base / "evaluation.json",
        "qcsd-class-study-evaluation",
        {
            "schema_version": 2,
            "artifact_type": "qcsd-class-study-evaluation",
            "handoff": {"root": str(handoff)},
        },
    )
    comparison = _publish(
        base / "comparison.json",
        "qcsd-class-study-comparison-review",
        {
            "artifact_type": "qcsd-class-study-comparison-review",
            "handoff": {"root": str(handoff)},
            "evaluation": _binding(evaluation),
        },
    )
    return SimpleNamespace(
        readiness=readiness,
        historical=historical,
        handoff=handoff,
        evaluation=evaluation,
        comparison=comparison,
    )


def _successor_evidence(fixture: SimpleNamespace) -> SimpleNamespace:
    payload = json.loads(fixture.restart.read_bytes())["payload"]
    foundation = Path(fixture.first_authority["foundation_attestation"]["path"])
    return _evidence(
        fixture.root,
        fixture.first,
        foundation,
        name="successor-current",
        successor_restart=fixture.restart,
        study_id=payload["study_id"],
    )


def _second_evidence(fixture: SimpleNamespace) -> SimpleNamespace:
    foundation = Path(fixture.second_authority["foundation_attestation"]["path"])
    return _evidence(
        fixture.root,
        fixture.second,
        foundation,
        name="unrelated-second-build",
    )


def _rewrite_runtime_authority(
    fixture: SimpleNamespace,
    names: tuple[str, ...],
    authority: Mapping[str, object],
) -> None:
    for name in names:
        _write_json(
            fixture.runtime[name],
            {"qualification_authority": dict(authority)},
        )


def _successor_action_options(
    action: str,
    evidence: SimpleNamespace,
) -> dict[str, object]:
    if action == "status":
        return {}
    if action == "evaluate":
        return {"handoff": str(evidence.handoff)}
    if action == "comparison-review":
        return {
            "handoff": str(evidence.handoff),
            "evaluation": str(evidence.evaluation),
        }
    if action == "attest":
        return {
            "readiness": str(evidence.readiness),
            "evaluation": str(evidence.evaluation),
        }
    if action == "historical-snapshot":
        return {"readiness": str(evidence.readiness)}
    if action == "export":
        return {"historical_post": str(evidence.historical)}
    raise AssertionError(f"unhandled successor action: {action}")


@pytest.mark.parametrize(
    "action",
    (
        "status",
        "evaluate",
        "comparison-review",
        "attest",
        "historical-snapshot",
        "export",
    ),
)
def test_successor_nonfitting_action_fixture_has_matching_current_authority(
    tmp_path: Path,
    action: str,
) -> None:
    fixture = _successor_fixture(tmp_path)
    evidence = _successor_evidence(fixture)

    assert (
        resolve_action_admission(
            fixture.root,
            action=action,
            options={
                "successor_restart": str(fixture.restart),
                **_successor_action_options(action, evidence),
            },
            build_loader=fixture.load,
        )
        == fixture.first
    )


@pytest.mark.parametrize(
    "action",
    (
        "status",
        "evaluate",
        "comparison-review",
        "attest",
        "historical-snapshot",
        "export",
    ),
)
def test_successor_nonfitting_actions_ignore_unrelated_existing_fitting_workspace(
    tmp_path: Path,
    action: str,
) -> None:
    fixture = _successor_fixture(tmp_path)
    evidence = _successor_evidence(fixture)
    _rewrite_runtime_authority(
        fixture,
        tuple(fixture.runtime),
        fixture.second_authority,
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action=action,
            options={
                "successor_restart": str(fixture.restart),
                **_successor_action_options(action, evidence),
            },
            build_loader=fixture.load,
        )
        == fixture.first
    )


def test_successor_prefix_specs_admits_numeric_input_only(
    tmp_path: Path,
) -> None:
    fixture = _successor_fixture(tmp_path)
    source_result = _result(
        fixture.root,
        fixture.first,
        name="successor-authoritative-fitting",
        role="authoritative-fitting",
    )
    _write_json(
        fixture.runtime["numeric"],
        {
            "schema_version": 1,
            "artifact_type": "qcsd-class-study-numeric-fitting-bundle",
            "source_result": {"source_fingerprints": fixture.first.source},
        },
    )
    _rewrite_runtime_authority(
        fixture,
        (
            "prefix",
            "checkpoint",
            "work",
            "published",
            "published_sidecar",
            "published_prefix",
            "final",
        ),
        fixture.second_authority,
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="prefix-specs",
            stage="authoritative",
            options={
                "successor_restart": str(fixture.restart),
                "capture_result": str(source_result),
            },
            build_loader=fixture.load,
        )
        == fixture.first
    )


def test_successor_finalize_ignores_checkpoint_work_and_existing_output(
    tmp_path: Path,
) -> None:
    fixture = _successor_fixture(tmp_path)
    foundation = Path(fixture.first_authority["foundation_attestation"]["path"])
    source_result = _result(
        fixture.root,
        fixture.first,
        name="successor-finalize-fitting",
        role="authoritative-fitting",
    )
    _write_json(
        fixture.runtime["numeric"],
        {
            "schema_version": 1,
            "artifact_type": "qcsd-class-study-numeric-fitting-bundle",
            "source_result": {"source_fingerprints": fixture.first.source},
        },
    )
    _rewrite_runtime_authority(
        fixture,
        ("checkpoint", "work", "final"),
        fixture.second_authority,
    )

    assert (
        resolve_action_admission(
            fixture.root,
            action="finalize-fitting",
            stage="authoritative",
            options={
                "successor_restart": str(fixture.restart),
                "foundation": str(foundation),
                "results": [str(source_result)],
            },
            build_loader=fixture.load,
        )
        == fixture.first
    )


def _cross_build_extras(first: object, second: object) -> tuple[Path, Path]:
    qualification = _write_json(
        first.root / "artifacts/action-semantics/unrelated-qualification.json",
        {"qualification_authority": second.qualification_authority},
    )
    final = first.root / "artifacts/action-semantics/unrelated-final"
    _write_json(
        final / "provenance.json",
        {"qualification_authority": second.qualification_authority},
    )
    return qualification, final


@pytest.mark.parametrize("action", ("capture", "resume"))
def test_root_capture_and_resume_ignore_direct_fitting_extras(
    tmp_path: Path,
    action: str,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    qualification, final = _cross_build_extras(first, second)
    options: dict[str, object] = {
        "foundation": str(first.foundation),
        "qualification_manifest": [str(qualification)],
        "final_bundle": [str(final)],
    }
    if action == "capture":
        options["campaign"] = str(first.campaign)
    else:
        options["capture_result"] = str(first.resume)

    assert (
        resolve_action_admission(
            first.root,
            action=action,
            options=options,
            build_loader=second.load,
        )
        == first.admitted
    )


def test_root_readiness_ignores_direct_qualification_manifest(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    qualification, _final = _cross_build_extras(first, second)

    assert (
        resolve_action_admission(
            first.root,
            action="readiness",
            cohort_version=62,
            options={
                "build": str(first.build),
                "foundation": str(first.foundation),
                "qualification_manifest": [str(qualification)],
            },
            build_loader=second.load,
        )
        == first.admitted
    )


def test_resume_rejects_missing_frozen_workload(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    (fixture.resume / "inputs/workloads/class-000.json").unlink()

    with pytest.raises(ValueError, match="class-000 manifest"):
        _resolve_base_resume(fixture)


def test_resume_rejects_symlinked_frozen_workload_directory(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    inputs = fixture.resume / "inputs"
    workloads = inputs / "workloads"
    relocated = inputs / "relocated-workloads"
    workloads.rename(relocated)
    workloads.symlink_to(relocated, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        _resolve_base_resume(fixture)


def test_resume_rejects_changed_frozen_workload_hash(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    experiment_path = fixture.resume / "experiment.json"
    experiment = json.loads(experiment_path.read_bytes())
    experiment["configuration"]["workloads"][0]["sha256"] = "0" * 64
    _write_json(experiment_path, experiment)

    with pytest.raises(ValueError, match="class-000 manifest hash changed"):
        _resolve_base_resume(fixture)


def test_resume_rejects_unexpected_defense_parameter_entry(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    _write_json(fixture.resume / "inputs/defense-parameters/unexpected.json", {})

    with pytest.raises(ValueError, match="defense-parameter inventory"):
        _resolve_base_resume(fixture)


def test_resume_rejects_symlinked_unknown_frozen_input_directory(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    (fixture.resume / "inputs/unexpected-link").symlink_to(
        fixture.root / "artifacts",
        target_is_directory=True,
    )

    with pytest.raises(ValueError, match="unsafe entry"):
        _resolve_base_resume(fixture)


def test_resume_bounds_non_json_frozen_input_inventory(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    unexpected = fixture.resume / "inputs/unexpected"
    unexpected.mkdir()
    for index in range(_MAX_FROZEN_INPUT_ENTRIES):
        (unexpected / f"{index:04d}.txt").touch()

    with pytest.raises(ValueError, match="too many filesystem entries"):
        _resolve_base_resume(fixture)


def test_resume_accepts_experiment_checkpoint_larger_than_authority_limit(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    experiment_path = fixture.resume / "experiment.json"
    experiment = json.loads(experiment_path.read_bytes())
    experiment["samples"] = [{"diagnostics": "x" * (17 * 1024 * 1024)}]
    _write_json(experiment_path, experiment)

    assert experiment_path.stat().st_size > 16 * 1024 * 1024
    assert _resolve_base_resume(fixture) == fixture.admitted


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("chaff_qualification_set", None),
        ("class_study_successor_sha256", None),
    ),
)
def test_base_resume_rejects_explicit_null_for_omitted_authority_fields(
    tmp_path: Path,
    key: str,
    value: object,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    experiment_path = fixture.resume / "experiment.json"
    experiment = json.loads(experiment_path.read_bytes())
    experiment["configuration"][key] = value
    _write_json(experiment_path, experiment)

    with pytest.raises(ValueError):
        _resolve_base_resume(fixture)


def test_resume_rejects_changed_public_origin_policy(tmp_path: Path) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    experiment_path = fixture.resume / "experiment.json"
    experiment = json.loads(experiment_path.read_bytes())
    experiment["configuration"]["public_origin_policy"]["required_value"] = "0"
    _write_json(experiment_path, experiment)

    with pytest.raises(ValueError, match="role execution contract"):
        _resolve_base_resume(fixture)


def test_resume_rejects_same_build_but_different_external_foundation(
    tmp_path: Path,
) -> None:
    fixture = _class_build_admission_fixture(tmp_path)
    foundation = json.loads(fixture.foundation.read_bytes())
    payload = foundation["payload"]
    payload["evidence"]["unconsumed_note"] = "same build, different authority object"
    alternate = _publish(
        fixture.root / "artifacts/action-semantics/alternate-foundation.json",
        "qcsd-class-study-foundation-attestation",
        payload,
    )

    with pytest.raises(ValueError, match="differs from external resume authority"):
        resolve_action_admission(
            fixture.root,
            action="resume",
            options={
                "foundation": str(alternate),
                "capture_result": str(fixture.resume),
            },
            build_loader=fixture.load,
        )


def test_resume_scans_unknown_experiment_configuration_authority(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    experiment_path = first.resume / "experiment.json"
    experiment = json.loads(experiment_path.read_bytes())
    experiment["configuration"]["unexpected"] = second.qualification_authority
    _write_json(experiment_path, experiment)

    with pytest.raises(ValueError, match="configuration schema"):
        _resolve_base_resume(first, build_loader=second.load)


def test_resume_scans_unknown_frozen_campaign_authority(tmp_path: Path) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    campaign = first.resume / "inputs/campaign.yml"
    campaign.write_text(
        campaign.read_text(encoding="utf-8")
        + "unexpected: "
        + json.dumps(second.qualification_authority, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    launch_path = first.resume / "inputs/class-study-launch.json"
    launch = json.loads(launch_path.read_bytes())
    launch["payload"]["campaign_sha256"] = sha256_file(campaign)
    launch["payload_sha256"] = hashlib.sha256(
        json.dumps(launch["payload"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    _write_json(launch_path, launch)
    registry = (
        first.root
        / "results/.classifier-multiorigin100-v1-launches"
        / f"{launch['payload']['launch_key']}.json"
    )
    registry.write_bytes(launch_path.read_bytes())
    experiment_path = first.resume / "experiment.json"
    experiment = json.loads(experiment_path.read_bytes())
    experiment["configuration"]["campaign_sha256"] = sha256_file(campaign)
    experiment["configuration"]["class_study_launch_sha256"] = sha256_file(launch_path)
    _write_json(experiment_path, experiment)

    with pytest.raises(ValueError, match="qualification authority"):
        _resolve_base_resume(first, build_loader=second.load)


def test_prefix_specs_ignores_generic_result_roots(
    tmp_path: Path,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    numeric = _numeric_bundle(
        first.root,
        "prefix-action-numeric",
        source=first.admitted.source,
        stage="pilot",
    )

    assert (
        resolve_action_admission(
            first.root,
            action="prefix-specs",
            stage="pilot",
            options={
                "capture_result": str(first.resume),
                "numeric_bundle": [str(numeric)],
                "results": [str(second.result)],
            },
            build_loader=second.load,
        )
        == first.admitted
    )


@pytest.mark.parametrize(
    "target_name",
    ("foundation", "readiness", "historical", "comparison", "validation"),
)
def test_verify_promotion_target_ignores_unrelated_options_before_generic_routing(
    tmp_path: Path,
    target_name: str,
) -> None:
    first = _class_build_admission_fixture(tmp_path)
    second = _second_class_build_admission_fixture(first)
    qualification, final = _cross_build_extras(first, second)
    numeric = _numeric_bundle(
        first.root,
        f"unrelated-verify-numeric-{target_name}",
        source=second.admitted.source,
        stage="authoritative",
    )

    assert (
        resolve_action_admission(
            first.root,
            action="verify",
            options={
                "target": str(getattr(first, target_name)),
                "foundation": str(second.foundation),
                "evaluation": str(second.evaluation),
                "capture_result": str(second.result),
                "numeric_bundle": [str(numeric)],
                "qualification_manifest": [str(qualification)],
                "final_bundle": [str(final)],
            },
            build_loader=second.load,
        )
        == first.admitted
    )


def test_successor_prefix_specs_rejects_cross_build_numeric_input(
    tmp_path: Path,
) -> None:
    fixture = _successor_fixture(tmp_path)
    source_result = _result(
        fixture.root,
        fixture.first,
        name="successor-prefix-cross-build",
        role="authoritative-fitting",
    )
    _write_json(
        fixture.runtime["numeric"],
        {
            "schema_version": 1,
            "artifact_type": "qcsd-class-study-numeric-fitting-bundle",
            "source_result": {"source_fingerprints": fixture.second.source},
        },
    )

    with pytest.raises(ValueError, match=r"source fingerprints|different completed builds"):
        resolve_action_admission(
            fixture.root,
            action="prefix-specs",
            stage="authoritative",
            options={
                "successor_restart": str(fixture.restart),
                "capture_result": str(source_result),
            },
            build_loader=fixture.load,
        )


def test_successor_finalize_rejects_cross_build_published_qualification(
    tmp_path: Path,
) -> None:
    fixture = _successor_fixture(tmp_path)
    foundation = Path(fixture.first_authority["foundation_attestation"]["path"])
    source_result = _result(
        fixture.root,
        fixture.first,
        name="successor-finalize-cross-build",
        role="authoritative-fitting",
    )
    _write_json(
        fixture.runtime["numeric"],
        {
            "schema_version": 1,
            "artifact_type": "qcsd-class-study-numeric-fitting-bundle",
            "source_result": {"source_fingerprints": fixture.first.source},
        },
    )
    _rewrite_runtime_authority(
        fixture,
        ("published",),
        fixture.second_authority,
    )

    with pytest.raises(ValueError, match="different completed builds"):
        resolve_action_admission(
            fixture.root,
            action="finalize-fitting",
            stage="authoritative",
            options={
                "successor_restart": str(fixture.restart),
                "foundation": str(foundation),
                "results": [str(source_result)],
            },
            build_loader=fixture.load,
        )


@pytest.mark.parametrize(
    "action",
    (
        "evaluate",
        "comparison-review",
        "attest",
        "historical-snapshot",
        "export",
    ),
)
def test_successor_actions_reject_cross_build_inputs_the_action_consumes(
    tmp_path: Path,
    action: str,
) -> None:
    fixture = _successor_fixture(tmp_path)
    evidence = _second_evidence(fixture)

    with pytest.raises(ValueError, match="different completed builds"):
        resolve_action_admission(
            fixture.root,
            action=action,
            options={
                "successor_restart": str(fixture.restart),
                **_successor_action_options(action, evidence),
            },
            build_loader=fixture.load,
        )
