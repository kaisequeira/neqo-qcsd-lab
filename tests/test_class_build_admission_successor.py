from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.class_build_admission import BuildAdmission, resolve_action_admission
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes, canonical_json_sha256
from qcsd_lab.util import sha256_file

BASE_STUDY = "classifier-multiorigin100-v1"


def _publish(path: Path, receipt_type: str, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=receipt_type)))
    return path


def _binding(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": sha256_file(path)}


def _build(root: Path, cohort: int, digit: str) -> tuple[BuildAdmission, Path, Path]:
    build = root / f"artifacts/buflo-study/build-execution-v{cohort}.json"
    completion = root / f"artifacts/buflo-study/build-completion-v{cohort}.json"
    build.parent.mkdir(parents=True, exist_ok=True)
    build.write_bytes(canonical_json_bytes({"cohort_version": cohort}))
    completion.write_bytes(
        canonical_json_bytes({"schema_version": 1, "payload_sha256": digit * 64})
    )
    source = {
        "image_digest": "sha256:" + digit * 64,
        "lab_commit": digit * 40,
        "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_commit": digit * 40,
        "neqo_pinned_commit": digit * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
    }
    identity = {
        "cohort_version": cohort,
        "sha256": sha256_file(build),
        "completion_path": f"/lab/artifacts/buflo-study/build-completion-v{cohort}.json",
        "completion_sha256": sha256_file(completion),
        "collection_image": source["image_digest"],
        "started_at": f"2026-09-07T00:{cohort % 60:02d}:00+00:00",
        "finished_at": f"2026-09-07T00:{(cohort + 1) % 60:02d}:00+00:00",
    }
    admission = BuildAdmission(
        receipt_path=build,
        receipt_sha256=sha256_file(build),
        cohort_version=cohort,
        collection_image=source["image_digest"],
        prepare_image="sha256:" + str((int(digit) + 1) % 10) * 64,
        reference_image="sha256:" + str((int(digit) + 2) % 10) * 64,
        completion_path=completion,
        completion_sha256=sha256_file(completion),
        completion_payload_sha256=digit * 64,
        source=source,
        identity=identity,
    )
    foundation = _publish(
        root / f"artifacts/foundations/foundation-v{cohort}.json",
        "qcsd-class-study-foundation-attestation",
        {
            "attestation_schema_version": 4,
            "artifact_type": "qcsd-class-study-foundation-attestation",
            "cohort_version": cohort,
            "source": source,
            "build_execution_identity": identity,
            "evidence": {"build_execution": _binding(build)},
        },
    )
    return admission, build, foundation


def _authority(admission: BuildAdmission, build: Path, foundation: Path) -> dict[str, object]:
    foundation_binding = _binding(foundation)
    foundation_binding["payload_sha256"] = json.loads(foundation.read_bytes())["payload_sha256"]
    return {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": foundation_binding,
        "build_execution": _binding(build),
        "build_execution_identity": admission.identity,
        "collection_source": admission.source,
        "prepare_source": {
            **dict(admission.source),
            "image_digest": admission.prepare_image,
        },
        "prepare_image_digest": admission.prepare_image,
    }


def _capture_result(root: Path, admission: BuildAdmission) -> Path:
    result = root / "results/successor-authoritative-fitting"
    inputs = result / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "study-environment.json").write_bytes(
        canonical_json_bytes(
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
            }
        )
    )
    return result


def _successor_fixture(tmp_path: Path) -> SimpleNamespace:
    root = tmp_path / "lab"
    root.mkdir()
    first, first_build, first_foundation = _build(root, 62, "1")
    second, second_build, second_foundation = _build(root, 63, "4")
    first_authority = _authority(first, first_build, first_foundation)
    second_authority = _authority(second, second_build, second_foundation)

    decision = _publish(
        root / "artifacts/decisions/successor-decision.json",
        "qcsd-class-study-successor-decision",
        {
            "decision_schema_version": 3,
            "predecessor": {
                "source": first.source,
                "source_sha256": canonical_json_sha256(first.source),
                "build_execution_identity": first.identity,
                "build_execution_identity_sha256": canonical_json_sha256(first.identity),
            },
            "evidence": {"predecessor_foundation": _binding(first_foundation)},
        },
    )
    identity_sha256 = "a1b2c3d4e5f6" + "7" * 52
    study_id = f"classifier-multiorigin100-v2-g01-{identity_sha256[:12]}"
    successor_root = root / "artifacts/successors" / study_id
    plan = successor_root / "plan"
    campaigns = plan / "campaigns"
    campaigns.mkdir(parents=True)

    plan_documents = {
        "successor-cohort.json": {},
        "successor-compatible-cohort.json": {},
        "successor-compatible-cohort-assembly.json": {"qualification_authority": first_authority},
        "successor-final-selection.json": {"qualification_authority": first_authority},
        "final-qualification-plan.json": {},
    }
    files: dict[str, Path] = {}
    for relative, value in plan_documents.items():
        path = plan / relative
        path.write_bytes(canonical_json_bytes(value))
        files[relative] = path

    roles = {
        f"{study_id}-authoritative-fitting-2000-1200.yml": "authoritative-fitting",
        f"{study_id}-certification-900-1200.yml": "certification",
    }
    for block in range(1, 11):
        roles[f"{study_id}-canary-{block:02d}-1200.yml"] = "canary"
        roles[f"{study_id}-formal-{block:02d}-1200.yml"] = "formal"
    for filename, role in roles.items():
        extra = ""
        if role in {"certification", "formal"}:
            extra = (
                "defenses:\n"
                "- name: traffic-morphing\n"
                f"  parameters: ../../artifacts/{BASE_STUDY}-authoritative-fitting/"
                "traffic-morphing.json\n"
                f"chaff_qualification_set: {study_id}-final-full\n"
            )
        path = campaigns / filename
        path.write_text(
            "schema: 2\n"
            f"evidence_role: {role}\n"
            "class_study_successor: ../successor-restart.json\n"
            "class_study_cohort_assembly: "
            "../successor-compatible-cohort-assembly.json\n" + extra,
            encoding="utf-8",
        )
        files[f"campaigns/{filename}"] = path

    decision_binding = _binding(decision)
    decision_binding["payload_sha256"] = json.loads(decision.read_bytes())["payload_sha256"]
    restart = _publish(
        plan / "successor-restart.json",
        "qcsd-class-study-successor-restart",
        {
            "restart_schema_version": 2,
            "artifact_type": "qcsd-class-study-successor-restart",
            "study_id": study_id,
            "predecessor_study_id": BASE_STUDY,
            "replacement_generation": 1,
            "cumulative_failed_class_ids": [],
            "successor_identity_sha256": identity_sha256,
            "successor_decision": decision_binding,
            "predecessor_foundation_sha256": sha256_file(first_foundation),
            "source_sha256": canonical_json_sha256(first.source),
            "build_execution_identity_sha256": canonical_json_sha256(first.identity),
            "selection_sha256": "0" * 64,
            "namespace": {
                "restart_root_name": study_id,
                "launch_namespace": f".{study_id}-launches",
                "results_root": "results",
                "authoritative_numeric_root": (
                    f"artifacts/{BASE_STUDY}-authoritative-fitting-numeric"
                ),
                "authoritative_prefix_root": (
                    f"artifacts/{BASE_STUDY}-authoritative-fitting-prefix-specs"
                ),
                "authoritative_final_root": (f"artifacts/{BASE_STUDY}-authoritative-fitting"),
                "final_qualification_root": f"qualification/{study_id}-final-full",
            },
            "immutable_plan_artifacts": {
                relative: {"path": relative, "sha256": sha256_file(path)}
                for relative, path in files.items()
            },
            "required_restart_gates": [],
            "downstream_restart": {},
            "readiness": {},
            "predecessor_downstream_artifact_reuse_permitted": False,
        },
    )

    runtime = {
        "numeric": successor_root
        / "artifacts"
        / f"{BASE_STUDY}-authoritative-fitting-numeric"
        / "numeric-provenance.json",
        "prefix": successor_root
        / "artifacts"
        / f"{BASE_STUDY}-authoritative-fitting-prefix-specs"
        / "one.json",
        "checkpoint": successor_root / "qualification/checkpoint.json",
        "work": successor_root / "qualification/work/one.json",
        "published": successor_root
        / "qualification"
        / f"{study_id}-final-full"
        / "_qualification-set.json",
        "published_sidecar": successor_root
        / "qualification"
        / f"{study_id}-final-full"
        / "one.json",
        "published_prefix": successor_root
        / "qualification"
        / f"{study_id}-final-full"
        / "_prefix-specs/one.json",
        "final": successor_root
        / "artifacts"
        / f"{BASE_STUDY}-authoritative-fitting"
        / "provenance.json",
    }
    for path in runtime.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes({"qualification_authority": first_authority}))

    admissions = {first_build: first, second_build: second}

    def load(path: Path, *, expected_cohort: int | None = None) -> BuildAdmission:
        admission = admissions[path]
        if expected_cohort is not None and expected_cohort != admission.cohort_version:
            raise AssertionError("unexpected fixture cohort")
        return admission

    return SimpleNamespace(
        root=root,
        first=first,
        second=second,
        first_authority=first_authority,
        second_authority=second_authority,
        restart=restart,
        plan=plan,
        files=files,
        runtime=runtime,
        load=load,
    )


def _rewrite_restart(fixture: SimpleNamespace, mutate) -> None:
    value = json.loads(fixture.restart.read_bytes())
    payload = value["payload"]
    mutate(payload)
    fixture.restart.write_bytes(
        canonical_json_bytes(bind_receipt(payload, receipt_type=value["receipt_type"]))
    )


def test_canonical_successor_restart_admits_all_self_referencing_campaigns(
    tmp_path: Path,
) -> None:
    fixture = _successor_fixture(tmp_path)

    admission = resolve_action_admission(
        fixture.root,
        action="status",
        options={"successor_restart": str(fixture.restart)},
        build_loader=fixture.load,
    )

    assert admission == fixture.first


def test_successor_prospective_outputs_remain_create_only(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    for path in fixture.runtime.values():
        path.unlink()
    capture_result = _capture_result(fixture.root, fixture.first)

    admission = resolve_action_admission(
        fixture.root,
        action="fit-numeric",
        options={
            "successor_restart": str(fixture.restart),
            "capture_result": str(capture_result),
        },
        build_loader=fixture.load,
    )

    assert admission == fixture.first


@pytest.mark.parametrize(
    "runtime_name",
    (
        "numeric",
        "prefix",
        "checkpoint",
        "work",
        "published",
        "published_sidecar",
        "published_prefix",
        "final",
    ),
)
def test_successor_status_ignores_prospective_runtime_outputs(
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = _successor_fixture(tmp_path)
    fixture.runtime[runtime_name].write_bytes(
        canonical_json_bytes({"qualification_authority": fixture.second_authority})
    )

    admission = resolve_action_admission(
        fixture.root,
        action="status",
        options={"successor_restart": str(fixture.restart)},
        build_loader=fixture.load,
    )

    assert admission == fixture.first


def test_successor_plan_rejects_tampered_hashed_artifact(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    campaign = next(
        path for relative, path in fixture.files.items() if relative.startswith("campaigns/")
    )
    campaign.write_text(campaign.read_text(encoding="utf-8") + "description: changed\n")

    with pytest.raises(ValueError, match="artifact changed"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_successor_restart_rejects_unknown_embedded_build_authority(
    tmp_path: Path,
) -> None:
    fixture = _successor_fixture(tmp_path)
    _rewrite_restart(
        fixture,
        lambda payload: payload.update(unexpected=fixture.second_authority),
    )

    with pytest.raises(ValueError, match="schema is invalid"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_successor_plan_scans_every_json_build_carrier(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    relative = "successor-cohort.json"
    artifact = fixture.files[relative]
    artifact.write_bytes(canonical_json_bytes({"unexpected": fixture.second_authority}))
    _rewrite_restart(
        fixture,
        lambda payload: payload["immutable_plan_artifacts"][relative].update(
            sha256=sha256_file(artifact)
        ),
    )

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_successor_plan_scans_unknown_yaml_build_carrier(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    relative = next(name for name in fixture.files if name.startswith("campaigns/"))
    artifact = fixture.files[relative]
    artifact.write_text(
        artifact.read_text(encoding="utf-8")
        + "unexpected: "
        + json.dumps(fixture.second_authority, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    _rewrite_restart(
        fixture,
        lambda payload: payload["immutable_plan_artifacts"][relative].update(
            sha256=sha256_file(artifact)
        ),
    )

    with pytest.raises(ValueError):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_successor_plan_parses_every_rehashed_campaign(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    relative = max(name for name in fixture.files if name.startswith("campaigns/"))
    campaign = fixture.files[relative]
    campaign.write_text("%YAML 1.2\nevidence_role: formal\n", encoding="utf-8")
    _rewrite_restart(
        fixture,
        lambda payload: payload["immutable_plan_artifacts"][relative].update(
            sha256=sha256_file(campaign)
        ),
    )

    with pytest.raises(ValueError, match="unsupported YAML syntax"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


@pytest.mark.parametrize("mutation", ("missing", "path", "extra"))
def test_successor_plan_rejects_noncanonical_inventory(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _successor_fixture(tmp_path)
    relative = "successor-final-selection.json"
    if mutation == "extra":
        (fixture.plan / "unreceipted.json").write_text("{}\n", encoding="utf-8")
    elif mutation == "missing":
        _rewrite_restart(
            fixture,
            lambda payload: payload["immutable_plan_artifacts"].pop(relative),
        )
    else:
        _rewrite_restart(
            fixture,
            lambda payload: payload["immutable_plan_artifacts"][relative].update(
                path="../outside.json"
            ),
        )

    with pytest.raises(ValueError, match="inventory|binding|unexpected"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_successor_hashed_plan_carrier_rejects_cross_build_authority(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    relative = "successor-final-selection.json"
    artifact = fixture.files[relative]
    artifact.write_bytes(
        canonical_json_bytes({"qualification_authority": fixture.second_authority})
    )
    _rewrite_restart(
        fixture,
        lambda payload: payload["immutable_plan_artifacts"][relative].update(
            sha256=sha256_file(artifact)
        ),
    )

    with pytest.raises(ValueError, match="resolve to different completed builds"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={"successor_restart": str(fixture.restart)},
            build_loader=fixture.load,
        )


def test_successor_explicit_alternate_derived_path_is_rejected(tmp_path: Path) -> None:
    fixture = _successor_fixture(tmp_path)
    alternate = fixture.root / "artifacts/alternate-numeric"
    alternate.mkdir()

    with pytest.raises(ValueError, match="successor numeric bundle must use"):
        resolve_action_admission(
            fixture.root,
            action="status",
            options={
                "successor_restart": str(fixture.restart),
                "numeric_bundle": [str(alternate)],
            },
            build_loader=fixture.load,
        )
