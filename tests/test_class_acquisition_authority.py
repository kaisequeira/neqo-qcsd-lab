"""Acquisition authority is independent of, and cannot replace, defence proof."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from qcsd_lab import class_attestation as authority
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes
from qcsd_lab.util import load_json, sha256_file


@pytest.fixture
def acquisition_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Exercise real authority reconstruction around isolated lower-level proofs."""

    monkeypatch.setattr(authority, "LAB_ROOT", tmp_path)
    for relative in (
        *authority.ACQUISITION_CORRECTNESS_TESTS,
        "pyproject.toml",
        "uv.lock",
        "config/class-study/v1/study.json",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture: {relative}\n", encoding="utf-8")
    source = {
        "image_digest": "sha256:" + "1" * 64,
        "lab_commit": "2" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": authority._EMPTY_SHA256,
        "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": authority._EMPTY_SHA256,
    }
    state: dict[str, Any] = {"source": dict(source), "calls": [], "returncode": 0}
    monkeypatch.setattr(authority, "source_metadata", lambda: dict(state["source"]))
    build_path = tmp_path / "build-execution-v96.json"
    build_path.write_text("{}\n", encoding="utf-8")
    completion = tmp_path / "build-completion-v96.json"
    completion.write_text("{}\n", encoding="utf-8")
    build = {
        "path": str(build_path),
        "sha256": sha256_file(build_path),
        "payload_sha256": "4" * 64,
        "cohort_version": 96,
        "collection_image": source["image_digest"],
        "completion_path": str(completion),
        "completion_sha256": sha256_file(completion),
        "started_at": "2026-08-01T00:00:00+00:00",
        "finished_at": "2026-08-01T01:00:00+00:00",
        "source": source,
        "images": {
            "collection": {"id": source["image_digest"]},
            "prepare": {"id": "sha256:" + "5" * 64},
            "reference": {"id": "sha256:" + "6" * 64},
        },
    }

    def validate_build(path: Path, **kwargs: Any) -> dict[str, Any]:
        assert path == build_path
        assert kwargs == {
            "expected_collection_image": source["image_digest"],
            "expected_cohort_version": state.get("expected_cohort_version", 96),
            "allow_historical": False,
        }
        state["calls"].append("build")
        return copy.deepcopy(build)

    monkeypatch.setattr(authority, "validate_build_execution_receipt", validate_build)
    pinned_path = tmp_path / "pinned.json"
    pinned_path.write_text("{}\n", encoding="utf-8")
    pinned = {
        "probe_schema_version": authority.PINNED_CDP_PROBE_SCHEMA_VERSION,
        "path": str(pinned_path),
        "sha256": sha256_file(pinned_path),
        "payload_sha256": "7" * 64,
        "recorded_at": "2026-08-01T02:00:00+00:00",
        "build_execution": {
            "path": str(build_path),
            "sha256": build["sha256"],
            "payload_sha256": build["payload_sha256"],
        },
        "build_execution_identity": authority._build_identity(build),
        "probe_contract_sha256": "8" * 64,
    }

    def validate_pinned(path: Path, **kwargs: Any) -> dict[str, Any]:
        assert path == pinned_path
        historical = state.get("historical", False)
        assert kwargs == {
            "build_execution_receipt": build_path,
            "expected_cohort_version": state.get("expected_cohort_version", 96),
            "runtime_role": None if historical else state.get("role", "collection"),
            "allow_historical": historical,
        }
        state["calls"].append("pinned")
        return copy.deepcopy(pinned)

    monkeypatch.setattr(authority, "validate_pinned_cdp_receipt", validate_pinned)
    browser_root = tmp_path / "browser-egress-v96"
    browser_root.mkdir()
    final = browser_root / "final.json"
    final.write_text("{}\n", encoding="utf-8")
    browser = {
        "path": str(final),
        "sha256": sha256_file(final),
        "payload_sha256": "9" * 64,
        "qualification_id": authority.BROWSER_EGRESS_QUALIFICATION_ID,
        "cohort_version": 96,
        "qualification_started_at": "2026-08-01T02:10:00+00:00",
        "qualification_finished_at": "2026-08-01T02:20:00+00:00",
        "recorded_at": "2026-08-01T02:30:00+00:00",
        "prepare_image_id": build["images"]["prepare"]["id"],
        "build_execution": {
            "path": str(build_path),
            "sha256": build["sha256"],
            "size_bytes": build_path.stat().st_size,
            "payload_sha256": build["payload_sha256"],
            "cohort_version": 96,
            "completion_path": "/lab/artifacts/buflo-study/build-completion-v96.json",
            "completion_sha256": build["completion_sha256"],
            **{f"{role}_image_id": image["id"] for role, image in build["images"].items()},
        },
        "expanded_vectors_sha256": authority.browser_egress_vectors_sha256(),
        "passed_vector_count": authority.BROWSER_EGRESS_VECTOR_COUNT,
        "passed": True,
    }

    def verify_browser(root: Path, **kwargs: Any) -> dict[str, Any]:
        assert root == browser_root
        expected_kwargs = {
            "lab_root": tmp_path,
            "expected_cohort_version": state.get("expected_cohort_version", 96),
            "allow_historical": False,
        }
        if state.get("historical", False):
            expected_kwargs["allow_v96_historical_source_replay"] = True
        assert kwargs == expected_kwargs
        state["calls"].append("browser")
        return copy.deepcopy(browser)

    monkeypatch.setattr(authority, "verify_browser_egress_qualification", verify_browser)

    def run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        assert argv == authority._acquisition_correctness_spec()["argv"]
        assert kwargs["cwd"] == tmp_path
        assert kwargs["check"] is False
        state["calls"].append("tests")
        if state.get("change_source"):
            state["source"]["lab_commit"] = "f" * 40
        return SimpleNamespace(returncode=state["returncode"], stdout="25 passed\n")

    monkeypatch.setattr(authority.subprocess, "run", run)

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("acquisition authority must not require defence proof")

    for name in (
        "validate_reference_gate_receipt", "validate_code_gate_receipt",
        "validate_regression_results", "validate_qualification_receipt",
    ):
        monkeypatch.setattr(authority, name, forbidden)
    state.update(
        destination=tmp_path / "acquisition-authority.json",
        inputs={
            "cohort_version": 96,
            "build_execution_receipt": build_path,
            "pinned_cdp_receipt": pinned_path,
            "browser_egress_qualification_root": browser_root,
        },
        build=build,
        pinned=pinned,
        browser=browser,
    )
    return state


def _create(state: dict[str, Any]) -> Path:
    return authority.create_class_acquisition_authority(state["destination"], **state["inputs"])


def _reseal(path: Path, payload: dict[str, Any]) -> None:
    path.write_bytes(canonical_json_bytes(bind_receipt(
        payload, receipt_type=authority.ACQUISITION_AUTHORITY_RECEIPT_TYPE
    )))


def _rewrite_as_v96_historical_authority(state: dict[str, Any]) -> Path:
    path = _create(state)
    payload = load_json(path)["payload"]
    state["historical"] = True
    state["pinned"]["probe_schema_version"] = authority._V96_PINNED_CDP_PROBE_SCHEMA_VERSION
    correctness = payload["acquisition_correctness"]
    correctness.update(copy.deepcopy(authority._V96_ACQUISITION_CORRECTNESS_SPEC))
    correctness["study_contract"] = copy.deepcopy(authority._V96_STUDY_CONTRACT)
    context = authority._acquisition_authority_context(
        cohort_version=96,
        build_execution_receipt=state["inputs"]["build_execution_receipt"],
        pinned_cdp_receipt=state["inputs"]["pinned_cdp_receipt"],
        browser_egress_qualification_root=state["inputs"]["browser_egress_qualification_root"],
        evidence_source=payload["source"],
        runtime_role="collection",
        recorded_study_contract=authority._V96_STUDY_CONTRACT,
        allow_historical=True,
    )
    historical = authority._acquisition_authority_value(
        context,
        correctness=correctness,
        recorded_at=payload["recorded_at"],
    )
    _reseal(path, historical)
    return path


def test_creation_runs_only_focused_gate_once_and_verification_is_read_only(
    acquisition_evidence: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    state = acquisition_evidence
    path = _create(state)
    assert state["calls"].count("tests") == 1

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("receipt verification must never execute tests")

    monkeypatch.setattr(authority.subprocess, "run", forbidden)
    result = authority.validate_class_acquisition_authority(path)
    assert result["authority_scope"] == "public-page-acquisition-only"
    assert result["promotion_authority"] is False
    assert result["source"] == state["source"]
    assert result["prepare_source"] == {
        **state["source"], "image_digest": state["build"]["images"]["prepare"]["id"]
    }
    assert [gate["gate"] for gate in result["hard_gates"]] == list(
        authority._ACQUISITION_AUTHORITY_GATES
    )
    assert result["evidence"]["browser_egress_qualification"]["passed_vector_count"] == 110
    assert result["summary"]["browser_egress_vectors"] == 110
    assert result["acquisition_correctness"]["argv"][0] == "/opt/qcsd-venv/bin/python"
    assert "tests/test_acquisition_selection.py" in result["acquisition_correctness"]["argv"]
    assert result["acquisition_correctness"]["stdout_sha256"] == hashlib.sha256(
        b"25 passed\n"
    ).hexdigest()


def test_v96_authority_reconstructs_only_in_explicit_historical_verification(
    acquisition_evidence: dict[str, Any],
) -> None:
    state = acquisition_evidence
    path = _rewrite_as_v96_historical_authority(state)
    result = authority.validate_class_acquisition_authority(
        path,
        allow_historical=True,
    )
    assert result["verification_status"] == "historical-verify-only"
    assert (
        result["evidence"]["pinned_cdp_probe"]["build_execution_identity"]
        == result["build_execution_identity"]
    )

    state["historical"] = False
    with pytest.raises(ValueError, match="verify-only"):
        authority.validate_class_acquisition_authority(path)


def test_offline_runtime_none_validates_current_authority_without_ambient_source(
    acquisition_evidence: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = acquisition_evidence
    path = _create(state)
    state["role"] = None
    monkeypatch.setattr(
        authority,
        "source_metadata",
        lambda: pytest.fail("offline current validation read ambient source"),
    )

    result = authority.validate_class_acquisition_authority(
        path,
        runtime_role=None,
    )

    assert result["path"] == str(path.resolve())
    assert state["calls"][-3:] == ["build", "pinned", "browser"]
    assert "verification_status" not in result


def test_offline_runtime_none_does_not_admit_v96_authority_as_current(
    acquisition_evidence: dict[str, Any],
) -> None:
    state = acquisition_evidence
    path = _rewrite_as_v96_historical_authority(state)
    state["historical"] = False
    state["role"] = None

    with pytest.raises(ValueError, match="verify-only"):
        authority.validate_class_acquisition_authority(
            path,
            runtime_role=None,
        )


def test_schema14_non_v96_authority_cannot_select_the_frozen_v96_contract(
    acquisition_evidence: dict[str, Any],
) -> None:
    state = acquisition_evidence
    state["historical"] = True
    state["expected_cohort_version"] = 97
    state["pinned"]["probe_schema_version"] = authority._V96_PINNED_CDP_PROBE_SCHEMA_VERSION

    with pytest.raises(ValueError, match="exact v96 cohort"):
        authority._acquisition_authority_context(
            cohort_version=97,
            build_execution_receipt=state["inputs"]["build_execution_receipt"],
            pinned_cdp_receipt=state["inputs"]["pinned_cdp_receipt"],
            browser_egress_qualification_root=state["inputs"]["browser_egress_qualification_root"],
            evidence_source=state["source"],
            runtime_role="collection",
            recorded_study_contract=authority._V96_STUDY_CONTRACT,
            allow_historical=True,
        )


@pytest.mark.parametrize("mutation", ("correctness", "build-identity", "study"))
def test_v96_historical_authority_tampering_is_rejected(
    acquisition_evidence: dict[str, Any],
    mutation: str,
) -> None:
    state = acquisition_evidence
    path = _rewrite_as_v96_historical_authority(state)
    payload = load_json(path)["payload"]
    if mutation == "correctness":
        payload["acquisition_correctness"]["input_sha256"]["uv.lock"] = "e" * 64
    elif mutation == "build-identity":
        payload["build_execution_identity"]["sha256"] = "e" * 64
    else:
        payload["study_contract"]["sha256"] = "e" * 64
        payload["acquisition_correctness"]["study_contract"]["sha256"] = "e" * 64
    _reseal(path, payload)

    with pytest.raises(ValueError):
        authority.validate_class_acquisition_authority(
            path,
            allow_historical=True,
        )


@pytest.mark.parametrize("size_bytes", (None, True, 3.0, "3", 0, -1, 4))
def test_browser_build_size_must_match_real_file_before_correctness_execution(
    acquisition_evidence: dict[str, Any], size_bytes: object
) -> None:
    state = acquisition_evidence
    state["browser"]["build_execution"]["size_bytes"] = size_bytes
    with pytest.raises(ValueError, match="different source/build/image"):
        _create(state)
    assert "tests" not in state["calls"]
    assert not state["destination"].exists()


def test_browser_build_size_cannot_be_omitted(
    acquisition_evidence: dict[str, Any]
) -> None:
    state = acquisition_evidence
    del state["browser"]["build_execution"]["size_bytes"]
    with pytest.raises(ValueError, match="build binding is invalid"):
        _create(state)
    assert "tests" not in state["calls"]
    assert not state["destination"].exists()


@pytest.mark.parametrize("allow_historical", (False, True))
@pytest.mark.parametrize(
    "completion", ("both", "neither", "path-only", "hash-only", "wrong-path", "wrong-hash")
)
def test_browser_consumer_retains_deep_verified_completion_in_historical_replay(
    acquisition_evidence: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
    allow_historical: bool, completion: str,
) -> None:
    state = acquisition_evidence
    receipt = state["browser"]
    binding = receipt["build_execution"]
    if completion in {"neither", "hash-only"}:
        del binding["completion_path"]
    if completion in {"neither", "path-only"}:
        del binding["completion_sha256"]
    if completion == "wrong-path":
        binding["completion_path"] = "/lab/artifacts/buflo-study/build-completion-v24.json"
    if completion == "wrong-hash":
        binding["completion_sha256"] = "e" * 64

    # Isolate this projection reader. The producer separately proves that only
    # historical schema 2 may reach it without either completion field.
    def verified_projection(root: Path, **kwargs: Any) -> dict[str, Any]:
        assert root == state["inputs"]["browser_egress_qualification_root"]
        assert kwargs["allow_historical"] is allow_historical
        return receipt

    monkeypatch.setattr(authority, "verify_browser_egress_qualification", verified_projection)

    def consume() -> dict[str, Any]:
        return authority._validate_browser_egress_qualification(
            state["inputs"]["browser_egress_qualification_root"],
            cohort_version=96,
            build=state["build"],
            allow_historical=allow_historical,
        )

    if completion == "both" or (allow_historical and completion == "neither"):
        assert consume() == receipt
    else:
        with pytest.raises(ValueError, match="build binding is invalid|different source/build/image"):
            consume()
    assert "tests" not in state["calls"]


def test_prepare_validation_binds_exact_prepare_image_without_new_execution(
    acquisition_evidence: dict[str, Any]
) -> None:
    state = acquisition_evidence
    path = _create(state)
    state["source"]["image_digest"] = state["build"]["images"]["prepare"]["id"]
    state["role"] = "prepare"
    authority.validate_class_acquisition_authority(path, runtime_role="prepare")
    assert state["calls"].count("tests") == 1
    with pytest.raises(ValueError, match="runtime differs"):
        authority.validate_class_acquisition_authority(path)
    state["source"]["image_digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValueError, match="runtime differs"):
        authority.validate_class_acquisition_authority(path, runtime_role="prepare")


@pytest.mark.parametrize("field,value", (
    ("lab_dirty", True), ("neqo_dirty", True), ("lab_patch_sha256", "f" * 64),
    ("neqo_pinned_commit", "f" * 40), ("image_digest", "native"),
))
def test_creation_rejects_dirty_native_or_unpinned_runtime_before_tests(
    acquisition_evidence: dict[str, Any], field: str, value: object
) -> None:
    state = acquisition_evidence
    state["source"][field] = value
    with pytest.raises(ValueError, match="clean immutable"):
        _create(state)
    assert "tests" not in state["calls"]
    assert not state["destination"].exists()


@pytest.mark.parametrize("mutation", (
    lambda payload: payload.update(attestation_schema_version=True),
    lambda payload: payload.update(attestation_schema_version=0),
    lambda payload: payload.update(authority_scope="formal-capture"),
    lambda payload: payload.update(promotion_authority=True),
    lambda payload: payload.update(all_acquisition_gates_passed=False),
    lambda payload: payload["hard_gates"].pop(),
    lambda payload: payload["prepare_source"].update(image_digest="sha256:" + "e" * 64),
    lambda payload: payload["acquisition_correctness"].update(exit_code=False),
    lambda payload: payload["acquisition_correctness"].update(exit_code=1),
    lambda payload: payload["acquisition_correctness"].update(stdout="changed\n"),
    lambda payload: payload["acquisition_correctness"].update(stdout_bytes=1),
    lambda payload: payload["acquisition_correctness"].update(stdout_sha256="e" * 64),
    lambda payload: payload["acquisition_correctness"]["argv"].pop(),
    lambda payload: payload["acquisition_correctness"].update(cwd="/different"),
    lambda payload: payload["acquisition_correctness"]["input_sha256"].pop("uv.lock"),
    lambda payload: payload["acquisition_correctness"]["source"].update(lab_commit="e" * 40),
    lambda payload: payload["acquisition_correctness"]["build_execution_identity"].update(
        sha256="e" * 64
    ),
    lambda payload: payload["acquisition_correctness"].update(
        started_at="2026-01-01T00:00:00+00:00"
    ),
    lambda payload: payload["acquisition_correctness"].update(
        finished_at="2026-01-01T00:00:00+00:00"
    ),
))
def test_resealed_incomplete_or_changed_authority_is_rejected(
    acquisition_evidence: dict[str, Any], mutation: Any
) -> None:
    path = _create(acquisition_evidence)
    payload = load_json(path)["payload"]
    mutation(payload)
    _reseal(path, payload)
    with pytest.raises(ValueError):
        authority.validate_class_acquisition_authority(path)


@pytest.mark.parametrize("input_name", ("build_execution_receipt", "pinned_cdp_receipt"))
def test_changed_referenced_receipt_is_rejected(
    acquisition_evidence: dict[str, Any], input_name: str
) -> None:
    state = acquisition_evidence
    path = _create(state)
    state["inputs"][input_name].write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="digest changed"):
        authority.validate_class_acquisition_authority(path)


@pytest.mark.parametrize("relative", (
    "tests/test_acquisition_selection.py", "uv.lock", "config/class-study/v1/study.json",
))
def test_changed_correctness_or_protocol_input_is_rejected(
    acquisition_evidence: dict[str, Any], relative: str
) -> None:
    path = _create(acquisition_evidence)
    (authority.LAB_ROOT / relative).write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="pinned inputs"):
        authority.validate_class_acquisition_authority(path)


@pytest.mark.parametrize("mutation", (
    lambda browser: browser.update(passed_vector_count=109),
    lambda browser: browser.update(passed=False),
    lambda browser: browser.update(expanded_vectors_sha256="e" * 64),
    lambda browser: browser.update(prepare_image_id="sha256:" + "e" * 64),
    lambda browser: browser["build_execution"].update(completion_sha256="e" * 64),
))
def test_browser_gate_remains_complete_and_bound_to_exact_build(
    acquisition_evidence: dict[str, Any], mutation: Any
) -> None:
    state = acquisition_evidence
    mutation(state["browser"])
    with pytest.raises(ValueError, match="different source/build/image"):
        _create(state)
    assert "tests" not in state["calls"]


def test_explicit_gate_failure_or_source_drift_publishes_no_authority(
    acquisition_evidence: dict[str, Any]
) -> None:
    state = acquisition_evidence
    state["returncode"] = 1
    with pytest.raises(RuntimeError, match="correctness gate failed"):
        _create(state)
    assert not state["destination"].exists()
    state["returncode"] = 0
    state["change_source"] = True
    with pytest.raises(ValueError, match="source changed"):
        _create(state)
    assert not state["destination"].exists()


def test_create_only_rejection_occurs_before_reexecution(
    acquisition_evidence: dict[str, Any]
) -> None:
    state = acquisition_evidence
    path = _create(state)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        _create(state)
    assert state["calls"].count("tests") == 1
    assert path.read_bytes() == before


def test_acquisition_only_receipt_cannot_satisfy_full_foundation(
    acquisition_evidence: dict[str, Any]
) -> None:
    path = _create(acquisition_evidence)
    with pytest.raises(ValueError):
        authority.validate_class_foundation_attestation(path)


def test_readiness_join_accepts_prior_acquisition_but_requires_same_full_foundation(
    acquisition_evidence: dict[str, Any]
) -> None:
    state = acquisition_evidence
    path = _create(state)
    result = authority.validate_class_acquisition_authority(path)
    foundation_path = authority.LAB_ROOT / "foundation.json"
    foundation_path.write_bytes(b"full foundation independently verified\n")
    foundation = {
        "source": result["source"],
        "build_execution_identity": result["build_execution_identity"],
        "evidence": {**result["evidence"], "reference": {"sha256": "e" * 64}},
        "recorded_at": "2030-01-01T00:00:00+00:00",
    }
    provenance = {
        "acquisition_schema_version": authority.ACQUISITION_SCHEMA_VERSION,
        "acquisition_authority": {"path": str(path), "sha256": sha256_file(path)},
        "started_at": result["recorded_at"],
    }
    authority._validate_acquisition_foundation_join(
        provenance, foundation=foundation, foundation_attestation=foundation_path
    )
    foundation["source"] = {**foundation["source"], "lab_commit": "e" * 40}
    with pytest.raises(ValueError, match="differs from full foundation"):
        authority._validate_acquisition_foundation_join(
            provenance, foundation=foundation, foundation_attestation=foundation_path
        )


def test_readiness_join_retains_exact_legacy_foundation_and_time_binding(
    acquisition_evidence: dict[str, Any]
) -> None:
    path = authority.LAB_ROOT / "foundation.json"
    path.write_bytes(b"full foundation independently verified\n")
    foundation = {"recorded_at": "2026-08-01T00:00:00+00:00"}
    provenance = {
        "foundation_attestation": {"path": str(path), "sha256": sha256_file(path)},
        "started_at": "2026-08-01T01:00:00+00:00",
    }
    authority._validate_acquisition_foundation_join(
        provenance, foundation=foundation, foundation_attestation=path
    )
    provenance["started_at"] = "2026-07-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="predates"):
        authority._validate_acquisition_foundation_join(
            provenance, foundation=foundation, foundation_attestation=path
        )
