"""The 20-site result boundary must visit every accepted sealed run."""

from __future__ import annotations

from pathlib import Path

import pytest

from qcsd_lab import class_pipeline
from qcsd_lab.class_profile_result import (
    _validate_profile_non_fitting_samples,
    verify_profile_class_result,
)
from qcsd_lab.class_study import (
    CLASS20_PROFILE,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
)
from qcsd_lab.verification import VerifiedResult


def _result(role: str) -> VerifiedResult:
    sites = tuple(f"site-{index:02d}" for index in range(20))
    modes = (
        ("undefended",) if role == "canary"
        else FORMAL_MODES if role == "formal" else COMPATIBILITY_MODES
    )
    visits = 10 if role == "formal" else 1
    samples = []
    for site in sites:
        for mode in modes:
            for visit in range(visits):
                samples.append({
                    "sample_id": f"sample-{len(samples):04d}",
                    "workload_id": site,
                    "defense": mode,
                    "visit": visit,
                    "state": "accepted",
                    "eligible": True,
                    "request_policy": "as-defined",
                    "attempts": 1,
                })
    return VerifiedResult(
        root=Path("/synthetic/result"),
        experiment={
            "configuration": {
                "defenses": [{"name": mode} for mode in modes],
                "request_policies": ["as-defined"],
            },
            "samples": samples,
        },
        checksums={},
        accepted_samples={sample["sample_id"]: {} for sample in samples},
    )


@pytest.mark.parametrize(
    ("role", "expected_count", "expected_pairs", "expected_candidate_runs"),
    (
        ("certification", 180, 180, 40),
        ("canary", 20, None, 0),
        ("formal", 1600, None, 400),
    ),
)
def test_profile_result_replays_every_accepted_run_and_current_candidate(
    role: str,
    expected_count: int,
    expected_pairs: int | None,
    expected_candidate_runs: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _result(role)
    runs: list[str] = []
    candidates: list[str] = []
    monkeypatch.setattr(
        class_pipeline,
        "_validate_class_sample_run_receipt",
        lambda _verified, sample, *, role: runs.append(sample["sample_id"]),
    )
    monkeypatch.setattr(
        class_pipeline,
        "_validate_current_candidate_sample_receipt",
        lambda _verified, sample, *, role: candidates.append(sample["sample_id"]),
    )
    assert _validate_profile_non_fitting_samples(
        verified,
        role=role,
        selected_ids=tuple(f"site-{index:02d}" for index in range(20)),
        visits_per_formal_block=CLASS20_PROFILE.formal_visits_per_block,
    ) == (expected_count, expected_pairs)
    assert len(runs) == expected_count
    assert len(set(runs)) == expected_count
    assert len(candidates) == expected_candidate_runs


def test_profile_result_rejects_duplicate_cross_product_with_full_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _result("formal")
    verified.experiment["samples"][-1] = dict(verified.experiment["samples"][0])
    monkeypatch.setattr(
        class_pipeline, "_validate_class_sample_run_receipt",
        lambda _verified, _sample, *, role: None,
    )
    monkeypatch.setattr(
        class_pipeline, "_validate_current_candidate_sample_receipt",
        lambda _verified, _sample, *, role: None,
    )
    with pytest.raises(ValueError, match="exact site/mode/visit cross-product"):
        _validate_profile_non_fitting_samples(
            verified,
            role="formal",
            selected_ids=tuple(f"site-{index:02d}" for index in range(20)),
            visits_per_formal_block=10,
        )


def test_profile_certification_rejects_second_launch_and_deep_run_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _result("certification")
    verified.experiment["samples"][0]["attempts"] = 2
    with pytest.raises(ValueError, match="invalid attempt"):
        _validate_profile_non_fitting_samples(
            verified,
            role="certification",
            selected_ids=tuple(f"site-{index:02d}" for index in range(20)),
            visits_per_formal_block=10,
        )
    verified.experiment["samples"][0]["attempts"] = 1

    def fail_run(_verified, _sample, *, role):
        raise ValueError("deep run failed")

    monkeypatch.setattr(class_pipeline, "_validate_class_sample_run_receipt", fail_run)
    with pytest.raises(ValueError, match="deep run failed"):
        _validate_profile_non_fitting_samples(
            verified,
            role="certification",
            selected_ids=tuple(f"site-{index:02d}" for index in range(20)),
            visits_per_formal_block=10,
        )


def test_profile_result_rejects_malformed_unhashable_sample_identity() -> None:
    verified = _result("canary")
    verified.experiment["samples"][0]["workload_id"] = []
    with pytest.raises(ValueError, match="sample identity is malformed"):
        _validate_profile_non_fitting_samples(
            verified,
            role="canary",
            selected_ids=tuple(f"site-{index:02d}" for index in range(20)),
            visits_per_formal_block=10,
        )


def test_profile_result_rejects_unregistered_role_before_reading_result() -> None:
    with pytest.raises(ValueError, match="role is not registered"):
        verify_profile_class_result(
            Path("/no-result"), profile=CLASS20_PROFILE,
            cohort_receipt=Path("/no-cohort"),
            cohort_assembly=Path("/no-assembly"),
            expected_role="pilot-compatibility",
        )
