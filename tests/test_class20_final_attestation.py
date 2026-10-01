"""Prospective post-export comparison and final-attestation boundaries."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import class_attestation as att
from qcsd_lab import class_validation20
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    CLASS20_STUDY_ID,
    _CLASS20_OVERLAY_SHA256,
    bind_receipt,
    canonical_json_bytes,
)
from tests.test_class_attestation import _evaluation
from tests.test_class_history20 import _runtime
from qcsd_lab.util import sha256_file


def _profile_evaluation(*, full_replay: bool = False) -> dict:
    value = copy.deepcopy(_evaluation(full_replay=full_replay))
    classes = value["classes"][: CLASS20_PROFILE.final_count]
    value.update({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "class_count": CLASS20_PROFILE.final_count,
        "classes": classes,
    })
    value["correctness"]["coverage"].update({
        "class_count": CLASS20_PROFILE.final_count,
        "visits_per_class_mode_block": CLASS20_PROFILE.formal_visits_per_block,
    })
    value["performance"]["coverage"]["class_count"] = CLASS20_PROFILE.final_count
    candidate = value["candidate_algorithm"]
    candidate["coverage"].update({
        "class_count": CLASS20_PROFILE.final_count,
        "visits_per_class_mode_block": CLASS20_PROFILE.formal_visits_per_block,
    })
    breakdowns = candidate["breakdowns"]
    for field in (
        "strata", "buflo_terminal_tail_strata", "buflo_schedule_stop_strata",
        "cs_buflo_local_termination_strata",
    ):
        breakdowns[field] = [
            {**row, "samples": CLASS20_PROFILE.formal_visits_per_block}
            for row in breakdowns[field]
            if row["workload_id"] in classes
        ]
    return value


def test_profile_evaluation_completion_requires_20_site_profile_and_full_coverage() -> None:
    evaluation = _profile_evaluation()
    completed = att._require_evaluation_completion(evaluation, require_full_replay=False)
    assert completed["candidate_algorithm"]["sample_count"] == 4_000
    assert len(completed["candidate_algorithm"]["breakdowns"]["strata"]) == 800
    wrong = copy.deepcopy(evaluation)
    wrong["study_profile_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="another study profile"):
        att._require_evaluation_completion(wrong, require_full_replay=False)
    wrong = copy.deepcopy(evaluation)
    wrong["correctness"]["coverage"]["visits_per_class_mode_block"] = 2
    with pytest.raises(ValueError, match="client-correctness"):
        att._require_evaluation_completion(wrong, require_full_replay=False)


def test_profile_comparison_template_and_review_bind_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluation = _profile_evaluation()
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    (handoff / "dataset.json").write_bytes(canonical_json_bytes({
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "sample_count": CLASS20_PROFILE.formal_sample_count,
        "class_count": CLASS20_PROFILE.final_count,
        "modes": list(CLASS20_PROFILE.formal_modes),
    }))
    (handoff / "samples.jsonl").write_text("{}\n", encoding="utf-8")
    (handoff / "SHA256SUMS").write_text("synthetic handoff\n", encoding="utf-8")
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(att, "verify_class_handoff", lambda path, **_kwargs: Path(path))
    monkeypatch.setattr(
        att.class_evaluation, "verify_class_evaluation_receipt",
        lambda *_args, **_kwargs: evaluation,
    )
    template = att.build_class_comparison_review_template(
        handoff=handoff, evaluation_receipt=evaluation_path
    )
    assert template["template_schema_version"] == 2
    assert template["study_profile_sha256"] == _CLASS20_OVERLAY_SHA256
    assert "20-class" in template["comparison_rows"][0]["context"]["qcsd"]["dataset_size"]
    assert "ten paired visits" in template["comparison_rows"][0]["context"]["qcsd"]["visits"]
    reviews = []
    for pair in template["comparison_rows"]:
        qcsd = pair["qcsd_value"]
        numbers = (
            "QCSD unavailable under this registered attack inventory"
            if qcsd is None else
            f"published {att._comparison_number_token(pair['published_value'])} "
            f"and QCSD {att._comparison_number_token(qcsd)}"
        )
        reviews.append({
            "defense": pair["defense"],
            "anchor_id": pair["anchor_id"],
            "metric": pair["metric"],
            "pair_sha256": pair["pair_sha256"],
            "disposition": "not-comparable" if qcsd is None else "expected",
            "explanation": (
                f"For {pair['anchor_id']} metric {pair['metric']}, {numbers}; the "
                f"{pair['defense']} published and QCSD transport, endpoints, dataset, "
                "observer accounting, padding semantics, and classifier protocol differ "
                "materially across the two independently stated studies."
            ),
            "context_differences": pair["context_differences"],
        })
    output = att.create_class_comparison_review(
        tmp_path / "review.json", handoff=handoff, evaluation_receipt=evaluation_path,
        reviewer="Thesis researcher", reviewed_at="2026-10-02T00:00:00+10:00",
        reviews=reviews,
    )
    assert (
        att.validate_class_comparison_review(output)["study_profile_sha256"]
        == _CLASS20_OVERLAY_SHA256
    )
    evaluation["study_profile_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="another study profile"):
        att.validate_class_comparison_review(output)


def test_profile_validation_envelope_rejects_v1_schema_and_profile_swap() -> None:
    digests = {gate: ["a" * 64] for gate in att._CLASS20_FINAL_GATES}
    payload = {
        "attestation_schema_version": att.CLASS20_VALIDATION_SCHEMA_VERSION,
        "artifact_type": att.VALIDATION_RECEIPT_TYPE,
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "implementation_status": att.VALIDATED_STATUS,
        "implementation_status_description": att.VALIDATED_DESCRIPTION,
        "promotion_authority": True,
        "implementation_scope": att.IMPLEMENTATION_SCOPE,
        "paper_equivalent": False,
        "no_waivers": True,
        "all_validation_gates_passed": True,
        "hard_gates": att._hard_gate_records(att._CLASS20_FINAL_GATES, digests),
    }
    att._validate_validation_envelope(payload)
    for key, replacement in (
        ("attestation_schema_version", 1),
        ("study_profile_sha256", "0" * 64),
    ):
        wrong = {**payload, key: replacement}
        with pytest.raises(ValueError, match="promotion envelope"):
            att._validate_validation_envelope(wrong)
    wrong = {**payload, "study_id": att.STUDY_ID}
    with pytest.raises(ValueError, match="promotion envelope"):
        att._validate_validation_envelope(wrong)


def test_profile_result_binding_accepts_exact_snapshot_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "formal"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    (root / "evidence.sha256").write_text("sealed\n", encoding="utf-8")
    files = {
        att.CLASS_STUDY_LAUNCH_INPUT: "launch",
        att._CLASS_STUDY_FOUNDATION_INPUT: "foundation",
        att._CLASS_STUDY_READINESS_INPUT: "readiness",
        att._CLASS_STUDY_HISTORICAL_PRE_INPUT: "pre",
    }
    checksums = {}
    configuration = {
        "evidence_role": "formal", "class_study_id": CLASS20_STUDY_ID,
        "class_study_profile_sha256": _CLASS20_OVERLAY_SHA256,
    }
    for relative, content in files.items():
        path = root / relative
        path.write_text(content + "\n", encoding="utf-8")
        digest = sha256_file(path)
        checksums[relative] = digest
        key = {
            att.CLASS_STUDY_LAUNCH_INPUT: "class_study_launch_sha256",
            att._CLASS_STUDY_FOUNDATION_INPUT: "class_study_foundation_sha256",
            att._CLASS_STUDY_READINESS_INPUT: "class_study_readiness_sha256",
            att._CLASS_STUDY_HISTORICAL_PRE_INPUT:
            "class_study_historical_pre_snapshot_sha256",
        }[relative]
        configuration[key] = digest
    monkeypatch.setattr(att, "verify_result", lambda _root: SimpleNamespace(
        experiment={"configuration": configuration}, checksums=checksums,
    ))
    binding = att._class_result_binding(root)
    assert binding["class_study_id"] == CLASS20_STUDY_ID
    assert binding["class_study_profile_sha256"] == _CLASS20_OVERLAY_SHA256
    projection = {key: value for key, value in binding.items() if key not in {
        "class_study_id", "class_study_profile_sha256",
    }}
    assert att._root_from_result_binding(projection, label="v2 snapshot") == root
    projection["class_study_launch_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="authority binding changed"):
        att._root_from_result_binding(projection, label="v2 snapshot")


def test_profile_validation_public_dispatch_uses_v2_reconstructor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = tmp_path / "readiness.json"
    readiness.write_bytes(canonical_json_bytes(bind_receipt({
        "study_id": CLASS20_STUDY_ID,
        "attestation_schema_version": att.CLASS20_READINESS_SCHEMA_VERSION,
    }, receipt_type=att.READINESS_RECEIPT_TYPE)))
    calls: list[dict] = []
    marker = {"profile_validation": True, "study_id": CLASS20_STUDY_ID}

    def reconstruct(**kwargs):
        calls.append(kwargs)
        return marker

    monkeypatch.setattr(class_validation20, "profile_validation_value", reconstruct)
    monkeypatch.setattr(att, "_protected_final_inputs", lambda _inputs: ())
    monkeypatch.setattr(att, "write_create_only_json", lambda path, _value: Path(path))
    destination = tmp_path / "validation.json"
    assert att.create_class_validation_attestation(
        destination, readiness_attestation=readiness, _post_write_validate=False
    ) == destination
    assert calls == [{"readiness_attestation": readiness, "deep_code_gate": True}]
    destination.write_text("synthetic final attestation\n", encoding="utf-8")
    monkeypatch.setattr(att, "_load_bound_receipt", lambda *_args, **_kwargs: (
        destination, {"payload_sha256": "a" * 64},
        marker,
    ))
    monkeypatch.setattr(att, "_validate_validation_envelope", lambda _payload: None)
    monkeypatch.setattr(
        att, "_validation_kwargs", lambda _payload: {"readiness_attestation": readiness}
    )
    assert att.validate_class_validation_attestation(destination)["profile_validation"] is True
    assert len(calls) == 2


def test_profile_final_reconstructor_requires_all_twenty_ordered_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = CLASS20_PROFILE
    source = {"synthetic_source": "one-clean-build"}
    foundation_sha = "a" * 64
    qualification_sha = "f" * 64
    readiness_path = tmp_path / "readiness.json"
    readiness_path.write_text("readiness\n", encoding="utf-8")
    pre_path = tmp_path / "pre.json"
    pre_path.write_text("pre\n", encoding="utf-8")
    post_path = tmp_path / "post.json"
    post_path.write_text("post\n", encoding="utf-8")
    cohort_path = tmp_path / "cohort.json"
    cohort_path.write_text("cohort\n", encoding="utf-8")
    assembly_path = tmp_path / "assembly.json"
    assembly_path.write_text("assembly\n", encoding="utf-8")
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text("evaluation\n", encoding="utf-8")
    comparison_path = tmp_path / "comparison.json"
    comparison_path.write_text("comparison\n", encoding="utf-8")
    certification_root = tmp_path / "certification"
    certification_root.mkdir()
    (certification_root / "evidence.sha256").write_text("certification\n", encoding="utf-8")
    final_ids = tuple(f"site-{index:02d}" for index in range(profile.final_count))
    runtime = _runtime(tuple(att.COMPATIBILITY_MODES))
    readiness = {
        "study_id": CLASS20_STUDY_ID,
        "attestation_schema_version": att.CLASS20_READINESS_SCHEMA_VERSION,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "source": source,
        "cohort_version": 1,
        "build_execution_identity": {"build": "one"},
        "evidence": {
            "foundation": {"sha256": foundation_sha},
            "final_cohort": att._file_binding(cohort_path),
            "final_cohort_assembly": att._file_binding(assembly_path),
            "certification_result": att._result_binding(certification_root),
        },
        "summary": {
            "formal_expected_samples": profile.formal_sample_count,
            "canary_expected_samples": profile.final_count * profile.formal_block_count,
            "certification_defense_runtime_inputs": runtime,
            "certification_defense_parameter_sha256": {
                mode: "b" * 64 for mode in att._PARAMETER_MODES
            },
            "final_qualification_set_manifest_sha256": qualification_sha,
        },
    }
    base = datetime(2020, 1, 1, tzinfo=UTC)
    canary_roots, formal_roots = [], []
    records = {}
    sealed = {}
    bindings = {}
    for block in range(1, profile.formal_block_count + 1):
        for ordinal, role in enumerate(("canary", "formal")):
            root = tmp_path / f"{role}-{block:02d}"
            root.mkdir()
            (root / "evidence.sha256").write_text(
                f"{role} {block}\n", encoding="utf-8"
            )
            (canary_roots if role == "canary" else formal_roots).append(root)
            start = base + timedelta(hours=2 * block + ordinal)
            sealed[root] = SimpleNamespace(experiment={
                "source": source, "started_at": start.isoformat(),
                "completed_at": (start + timedelta(minutes=30)).isoformat(),
            })
            modes = ("undefended",) if role == "canary" else tuple(att.FORMAL_MODES)
            count = profile.final_count if role == "canary" else 1_600
            launch_sha = f"{2 * block + ordinal:064x}"
            records[root] = {
                "valid": True, "root": str(root), "class_study_id": CLASS20_STUDY_ID,
                "class_study_profile_sha256": _CLASS20_OVERLAY_SHA256,
                "class_study_foundation_sha256": foundation_sha,
                "class_study_readiness_sha256": sha256_file(readiness_path),
                "class_study_historical_pre_snapshot_sha256": sha256_file(pre_path),
                "cohort_sha256": sha256_file(cohort_path),
                "cohort_assembly_sha256": sha256_file(assembly_path),
                "samples": count, "accepted": count,
                "evidence_sha256": sha256_file(root / "evidence.sha256"),
                "class_study_launch_sha256": launch_sha,
                "defense_runtime_inputs": {mode: runtime[mode] for mode in modes},
                "defense_parameter_sha256": (
                    {} if role == "canary" else
                    {mode: "b" * 64 for mode in att.FORMAL_MODES if mode in att._PARAMETER_MODES}
                ),
                "chaff_qualification_set_manifest_sha256": (
                    None if role == "canary" else qualification_sha
                ),
            }
            bindings[root] = {
                "root": str(root),
                "evidence_sha256": records[root]["evidence_sha256"],
                "class_study_launch_sha256": launch_sha,
                "class_study_foundation_sha256": foundation_sha,
                "class_study_readiness_sha256": sha256_file(readiness_path),
                "class_study_historical_pre_snapshot_sha256": sha256_file(pre_path),
                "class_study_id": CLASS20_STUDY_ID,
                "class_study_profile_sha256": _CLASS20_OVERLAY_SHA256,
            }
    sealed[certification_root] = SimpleNamespace(experiment={
        "completed_at": base.isoformat(),
    })
    pre = {
        "snapshot_schema_version": 2, "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "source": source, "readiness": att._file_binding(readiness_path),
        "historical_corpus_guard_sha256": "9" * 64,
        "recorded_at": (base + timedelta(hours=1)).isoformat(),
    }
    post = {
        **pre,
        "pre_formal_snapshot": att._file_binding(pre_path),
        "formal_results": [
            {key: bindings[root][key] for key in (
                "root", "evidence_sha256", "class_study_launch_sha256",
                "class_study_foundation_sha256", "class_study_readiness_sha256",
                "class_study_historical_pre_snapshot_sha256",
            )} for root in formal_roots
        ],
        "recorded_at": (base + timedelta(hours=23)).isoformat(),
        "payload_sha256": "8" * 64,
    }
    handoff = tmp_path / "handoff"
    (handoff / "inputs").mkdir(parents=True)
    (handoff / att.CLASS_STUDY_HISTORICAL_POST_INPUT).write_bytes(post_path.read_bytes())
    (handoff / "SHA256SUMS").write_text("handoff\n", encoding="utf-8")
    (handoff / "samples.jsonl").write_text("{}\n", encoding="utf-8")
    dataset = {
        "schema_version": 4,
        "artifact_type": "qcsd-classifier-multiorigin20-formal-handoff",
        "study_id": CLASS20_STUDY_ID,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "sample_count": profile.formal_sample_count,
        "class_count": profile.final_count,
        "classes": list(final_ids),
        "modes": list(att.FORMAL_MODES),
        "blocks": [
            {"result_root": str(root), "result_evidence_sha256": records[root]["evidence_sha256"]}
            for root in formal_roots
        ],
        "execution_source": {"value": source},
        "exporter_source": source,
        "historical_post_snapshot": {
            "path": att.CLASS_STUDY_HISTORICAL_POST_INPUT,
            "sha256": sha256_file(post_path), "payload_sha256": post["payload_sha256"],
        },
    }
    (handoff / "dataset.json").write_bytes(canonical_json_bytes(dataset))
    evaluation = _profile_evaluation(full_replay=True)
    launch_blocks = [
        {"block": block, "path": f"{att.CLASS_STUDY_LAUNCHES_PATH}/block-{block:02d}.json",
         "sha256": records[root]["class_study_launch_sha256"]}
        for block, root in enumerate(formal_roots, start=1)
    ]
    launches = {
        "source_path": att.CLASS_STUDY_LAUNCH_INPUT,
        "blocks": launch_blocks,
        "bindings_sha256": att.canonical_json_sha256(launch_blocks),
    }
    evaluation["class_study_launches"] = launches
    evaluation["handoff"] = {
        "class_study_launches_sha256": att.canonical_json_sha256(launches)
    }
    comparison = {
        "study_id": CLASS20_STUDY_ID,
        "review_schema_version": att.CLASS20_COMPARISON_REVIEW_SCHEMA_VERSION,
        "study_profile_sha256": _CLASS20_OVERLAY_SHA256,
        "handoff": att._handoff_binding(handoff),
        "evaluation": att._file_binding(evaluation_path),
        "reviewed_metric_count": 42,
    }
    monkeypatch.setattr(att, "validate_class_readiness_attestation", lambda *_a, **_k: readiness)
    monkeypatch.setattr(class_validation20, "source_metadata", lambda: source)
    monkeypatch.setattr(att, "_validate_immutable_source", lambda *_a, **_k: None)
    monkeypatch.setattr(
        class_validation20, "load_validated_profile_cohort",
        lambda *_a, **_k: (tuple(f"pilot-{i}" for i in range(30)), final_ids),
    )
    monkeypatch.setattr(
        att, "validate_class_historical_snapshot",
        lambda path, **_kwargs: pre if Path(path) == pre_path else post,
    )
    monkeypatch.setattr(class_validation20, "verify_result", lambda root: sealed[Path(root)])
    monkeypatch.setattr(
        class_validation20, "verify_profile_class_result",
        lambda root, **_kwargs: records[Path(root)],
    )
    monkeypatch.setattr(att, "_validate_result_environment", lambda *_a, **_k: {"build": "one"})
    monkeypatch.setattr(
        att, "_one_class_build_execution_identity", lambda *_a, **_k: {"build": "one"}
    )
    monkeypatch.setattr(att, "_class_result_binding", lambda root: bindings[Path(root)])
    monkeypatch.setattr(class_validation20, "verify_class_handoff", lambda *_a, **_k: handoff)
    monkeypatch.setattr(
        class_validation20.class_evaluation,
        "verify_class_evaluation_receipt", lambda *_a, **_k: evaluation,
    )
    monkeypatch.setattr(att, "validate_class_comparison_review", lambda *_a, **_k: comparison)
    inputs = dict(
        readiness_attestation=readiness_path,
        canary_result_roots=canary_roots,
        formal_result_roots=formal_roots,
        historical_pre_snapshot=pre_path,
        historical_post_snapshot=post_path,
        handoff=handoff,
        evaluation_receipt=evaluation_path,
        comparison_review=comparison_path,
        deep_code_gate=True,
    )
    final = class_validation20.profile_validation_value(**inputs)
    assert final["summary"]["canary_samples"] == 200
    assert final["summary"]["formal_samples"] == 16_000
    assert len(final["evidence"]["formal_results"]) == 10
    assert final["study_profile_sha256"] == _CLASS20_OVERLAY_SHA256
    post["formal_results"][0]["class_study_launch_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="before/after evidence"):
        class_validation20.profile_validation_value(**inputs)
