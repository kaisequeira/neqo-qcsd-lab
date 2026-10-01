"""The 20-site launch gate admits only the exact deep-verified prior ledger."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from qcsd_lab import class_capture20, util
from qcsd_lab.class_layout import class_study_layout
from qcsd_lab.class_study import CLASS20_PROFILE, FORMAL_MODES
from qcsd_lab.util import sha256_file


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, block: int):
    lab = tmp_path / "lab"
    lab.mkdir()
    monkeypatch.setattr(util, "LAB_ROOT", lab)
    layout = class_study_layout(profile=CLASS20_PROFILE)
    layout.study_config_root.mkdir(parents=True)
    source_profile = Path(class_capture20.__file__).resolve().parents[2] / "config/class-study/v2/study.json"
    shutil.copyfile(source_profile, layout.study_config_root / "study.json")
    profile_sha = sha256_file(layout.study_config_root / "study.json")
    layout.campaign_root.mkdir()
    name = f"{CLASS20_PROFILE.study_id}-{role}-{block:02d}-1200"
    campaign = layout.campaign_root / f"{name}.yml"
    campaign.write_text(yaml.safe_dump({"name": name, "evidence_role": role}))
    cohort = layout.study_config_root / f"{CLASS20_PROFILE.study_id}-cohort.json"
    assembly = layout.study_config_root / f"{CLASS20_PROFILE.study_id}-cohort-assembly.json"
    cohort.write_text("cohort")
    assembly.write_text("assembly")
    foundation = lab / "foundation.json"
    readiness = lab / "readiness.json"
    snapshot = lab / "pre.json"
    for path in (foundation, readiness, snapshot):
        path.write_text(path.name)
    source = {"lab_commit": "same-source"}
    runtime = {mode: {"identity_type": mode} for mode in ("undefended", *FORMAL_MODES)}
    required = class_capture20._required_stages(role, block)
    roots = []
    records = {}
    for index, (prior_role, prior_block) in enumerate(required):
        root = lab / f"result-{index:02d}"
        root.mkdir()
        root.joinpath("experiment.json").write_text(
            '{"source":{"lab_commit":"same-source"},'
            f'"started_at":"2026-09-01T{index * 2:02d}:00:00+00:00",'
            f'"completed_at":"2026-09-01T{index * 2 + 1:02d}:00:00+00:00"}}'
        )
        roots.append(root)
        records[root] = {
            "valid": True,
            "root": str(root),
            "evidence_role": prior_role,
            "block": prior_block,
            "class_study_id": CLASS20_PROFILE.study_id,
            "class_study_profile_sha256": profile_sha,
            "class_study_foundation_sha256": sha256_file(foundation),
            "cohort_sha256": sha256_file(cohort),
            "cohort_assembly_sha256": sha256_file(assembly),
            "evidence_sha256": f"{index + 1:064x}",
            "class_study_readiness_sha256": (
                sha256_file(readiness) if prior_role in {"canary", "formal"} else None
            ),
            "class_study_historical_pre_snapshot_sha256": (
                sha256_file(snapshot) if prior_role in {"canary", "formal"} else None
            ),
            "defense_runtime_inputs": {
                mode: runtime[mode]
                for mode in (("undefended",) if prior_role == "canary" else FORMAL_MODES)
            } if prior_role in {"canary", "formal"} else {},
            "chaff_qualification_set_manifest_sha256": (
                "f" * 64 if prior_role == "formal" else None
            ),
        }
    foundation_value = {
        "study_id": CLASS20_PROFILE.study_id,
        "study_profile_sha256": profile_sha,
        "source": source,
    }
    readiness_value = {
        "study_id": CLASS20_PROFILE.study_id,
        "study_profile_sha256": profile_sha,
        "source": source,
        "evidence": {
            "foundation": {"path": str(foundation), "sha256": sha256_file(foundation)},
            "final_cohort": {"path": str(cohort), "sha256": sha256_file(cohort)},
            "final_cohort_assembly": {"path": str(assembly), "sha256": sha256_file(assembly)},
            "authoritative_fitting_result": {
                "root": str(roots[0]), "evidence_sha256": records[roots[0]]["evidence_sha256"],
            },
            "certification_result": {
                "root": str(roots[1]), "evidence_sha256": records[roots[1]]["evidence_sha256"],
            },
        },
        "summary": {
            "certification_defense_runtime_inputs": runtime,
            "final_qualification_set_manifest_sha256": "f" * 64,
        },
    }
    snapshot_value = {
        "study_id": CLASS20_PROFILE.study_id,
        "study_profile_sha256": profile_sha,
        "phase": "pre-formal",
        "source": source,
        "readiness": {"path": str(readiness), "sha256": sha256_file(readiness)},
        "recorded_at": "2026-09-01T03:30:00+00:00",
    }
    calls = []

    def deep_result(root, **kwargs):
        calls.append((root, kwargs["expected_role"], kwargs["expected_block"]))
        assert kwargs["profile"] == CLASS20_PROFILE
        assert kwargs["cohort_receipt"] == cohort
        assert kwargs["cohort_assembly"] == assembly
        return records[root]

    monkeypatch.setattr(class_capture20, "load_validated_profile_cohort", lambda *a, **kw: (
        tuple(f"pilot-{index}" for index in range(30)),
        tuple(f"final-{index}" for index in range(20)),
    ))
    monkeypatch.setattr(class_capture20, "validate_campaign_document", lambda *a, **kw: campaign.name)
    monkeypatch.setattr(class_capture20.class_attestation, "validate_class_foundation_attestation", lambda *a, **kw: foundation_value)
    monkeypatch.setattr(class_capture20.class_attestation, "validate_class_readiness_attestation", lambda *a, **kw: readiness_value)
    monkeypatch.setattr(class_capture20.class_attestation, "validate_class_historical_snapshot", lambda *a, **kw: snapshot_value)
    monkeypatch.setattr(class_capture20, "verify_profile_class_result", deep_result)
    inputs = {
        "campaign_path": campaign,
        "final_cohort_receipt": cohort,
        "final_cohort_assembly": assembly,
        "prerequisite_roots": roots,
        "foundation_attestation": foundation,
        "readiness_attestation": readiness,
        "historical_pre_snapshot": snapshot,
    }
    return inputs, records, readiness_value, snapshot_value, calls


@pytest.mark.parametrize(("role", "block", "roles", "samples"), (
    ("canary", 1, ("authoritative-fitting", "certification"), 20),
    ("formal", 1, ("authoritative-fitting", "certification", "canary"), 1600),
    ("canary", 2, ("authoritative-fitting", "certification", "canary", "formal"), 20),
    ("formal", 2, ("authoritative-fitting", "certification", "canary", "formal", "canary"), 1600),
))
def test_capture_launch_requires_exact_preceding_deep_results(
    tmp_path, monkeypatch, role, block, roles, samples,
):
    inputs, _records, _readiness, _snapshot, calls = _case(tmp_path, monkeypatch, role, block)
    plan = class_capture20.verify_profile_capture_prerequisites(**inputs)
    assert plan["valid"] is True
    assert plan["planned_samples"] == samples
    assert tuple(record["evidence_role"] for record in plan["prerequisite_ledger"]) == roles
    assert [item[0] for item in calls] == inputs["prerequisite_roots"]
    assert plan["campaign_sha256"] == sha256_file(inputs["campaign_path"])


def test_capture_launch_blocks_missing_snapshot_and_unverified_snapshot(tmp_path, monkeypatch):
    inputs, _records, _readiness, _snapshot, _calls = _case(tmp_path, monkeypatch, "canary", 1)
    inputs["historical_pre_snapshot"].unlink()
    with pytest.raises(ValueError, match="pre snapshot is not a regular file"):
        class_capture20.verify_profile_capture_prerequisites(**inputs)
    inputs["historical_pre_snapshot"].write_text("pending")

    def pending(*args, **kwargs):
        raise ValueError("v2 pre snapshot validator pending")

    monkeypatch.setattr(class_capture20.class_attestation, "validate_class_historical_snapshot", pending)
    with pytest.raises(ValueError, match="validator pending"):
        class_capture20.verify_profile_capture_prerequisites(**inputs)


def test_capture_launch_blocks_gap_reorder_and_mixed_authority(tmp_path, monkeypatch):
    inputs, records, _readiness, _snapshot, _calls = _case(tmp_path, monkeypatch, "formal", 2)
    with pytest.raises(ValueError, match="exact preceding result ledger"):
        class_capture20.verify_profile_capture_prerequisites(**{
            **inputs, "prerequisite_roots": inputs["prerequisite_roots"][:-1],
        })
    roots = list(inputs["prerequisite_roots"])
    roots[-1], roots[-2] = roots[-2], roots[-1]
    with pytest.raises(ValueError, match="another identity or authority"):
        class_capture20.verify_profile_capture_prerequisites(**{
            **inputs, "prerequisite_roots": roots,
        })
    last = inputs["prerequisite_roots"][-1]
    records[last]["class_study_readiness_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="another readiness or runtime"):
        class_capture20.verify_profile_capture_prerequisites(**inputs)


def test_capture_launch_rejects_snapshot_before_certification_and_prior_capture(tmp_path, monkeypatch):
    inputs, _records, _readiness, snapshot, _calls = _case(tmp_path, monkeypatch, "formal", 1)
    snapshot["recorded_at"] = "2026-09-01T02:00:00+00:00"
    with pytest.raises(ValueError, match="predates certification completion"):
        class_capture20.verify_profile_capture_prerequisites(**inputs)
    snapshot["recorded_at"] = "2026-09-01T04:30:00+00:00"
    with pytest.raises(ValueError, match="prior capture predates"):
        class_capture20.verify_profile_capture_prerequisites(**inputs)
