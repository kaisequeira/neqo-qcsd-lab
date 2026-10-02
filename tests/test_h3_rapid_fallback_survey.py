"""The rapid-v4 fallback survey is ordered, bounded, and zero credit."""

from __future__ import annotations

import json
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import h3_prebaseline, rapid_study_profile as rapid
from tools import h3_rapid_fallback_survey as survey


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _probe_detail(url: str, *, known_valid: bool = True) -> dict:
    output = json.dumps({"resources": [{
        "id": 0, "url": url, "type": "Unknown", "content_length": 42,
        "data_length": 42, "chaff_priority": False, "known_valid": known_valid,
        "depends_on": [], "headers": [],
    }]})
    return {
        "url": url,
        "started_at": datetime.now(UTC).isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "resolver_addresses": ["192.0.2.1"],
        "resolver_error": None,
        "exit_code": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_excerpt": "",
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_text": output,
        "known_valid": known_valid,
        "outcome": "known-valid" if known_valid else "ambiguous",
    }


def _verifier_inputs(monkeypatch: pytest.MonkeyPatch) -> tuple[dict, tuple[bytes, bytes, bytes]]:
    image_digest = "sha256:" + "d" * 64
    runtime = {
        "image_digest": image_digest,
        "lab_commit": "1" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_commit": "2" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_pinned_commit": "2" * 40,
    }
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", image_digest)
    monkeypatch.setattr(survey, "source_metadata", lambda: runtime)
    module_hashes = {
        "tools.h3_rapid_fallback_survey": hashlib.sha256(
            Path(survey.__file__).read_bytes()
        ).hexdigest(),
        "qcsd_lab.h3_prebaseline": hashlib.sha256(
            Path(h3_prebaseline.__file__).read_bytes()
        ).hexdigest(),
        "qcsd_lab.rapid_study_profile": hashlib.sha256(
            Path(rapid.__file__).read_bytes()
        ).hexdigest(),
    }
    args = {
        "execution_binding": {
            "source_manifest_sha256": "c" * 64,
            "admission_image_digest": image_digest,
        },
        "expected_runtime_source": runtime,
        "expected_mounted_module_hashes": module_hashes,
        "not_before_utc": datetime.now(UTC) - timedelta(seconds=1),
    }
    sources = (
        survey.DEFAULT_PROFILE.read_bytes(), survey.DEFAULT_SOURCE.read_bytes(),
        survey.DEFAULT_CATALOGUE.read_bytes(),
    )
    return args, sources


def _tamper(rows: list[dict], path: Path) -> Path:
    path.write_bytes(b"".join(
        json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows
    ))
    return path


def test_frozen_profile_first_fallback_positions() -> None:
    targets, identity = survey._targets(
        survey.DEFAULT_PROFILE, survey.DEFAULT_SOURCE, survey.DEFAULT_CATALOGUE, 0, 3
    )
    assert identity["profile_sha256"] == survey.FROZEN_PROFILE_SHA256
    assert identity["profile_candidate_count"] == 673
    assert identity["fallback_candidate_count"] == 600
    assert [(row["fallback_index"], row["candidate_order"], row["source_position"],
             row["candidate_id"], row["domain"]) for row in targets] == [
        (0, 74, 1, "tranco-0000697", "consultant.ru"),
        (1, 75, 2, "tranco-0000984", "elmundo.es"),
        (2, 76, 3, "tranco-0000837", "msftauth.net"),
    ]


def test_changed_profile_refuses_probe_before_output(tmp_path: Path) -> None:
    changed = tmp_path / "changed-profile.json"
    changed.write_bytes(survey.DEFAULT_PROFILE.read_bytes() + b"\n")
    output = tmp_path / "survey.jsonl"
    with pytest.raises(ValueError, match="frozen SHA-256"):
        survey.run_survey(
            profile=changed, output=output, start_index=0, count=1,
            probe=lambda _url: pytest.fail("probe must not start"),
        )
    assert not output.exists()


def test_control_brackets_order_and_safety_skip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(survey, "source_metadata", lambda: {"lab_commit": "test"})
    targets, _ = survey._targets(
        survey.DEFAULT_PROFILE, survey.DEFAULT_SOURCE, survey.DEFAULT_CATALOGUE, 25, 3
    )
    assert targets[1]["domain"] == "xnxx.com"
    assert targets[1]["pre_browser_safety_reason"] is not None
    calls: list[str] = []

    def probe(url: str) -> dict:
        calls.append(url)
        return {"url": url, "outcome": "known-valid", "known_valid": True}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(output=output, start_index=25, count=3, probe=probe)
    control = survey.rapid_study_profile.TRIAGE_POLICY["control_url"]
    assert calls == [
        control, f"https://{targets[0]['domain']}/",
        f"https://{targets[2]['domain']}/", control,
    ]
    assert result == {
        "status": "complete", "selected_targets": 3, "attempted_targets": 2,
        "skipped_unsafe_targets": 1, "completed_batches": 1,
        "outcomes": {"known-valid": 2}, "scientific_credit": False,
    }
    events = _events(output)
    assert [row["stage"] for row in events] == [
        "start", "control-before", "candidate", "candidate-skipped",
        "candidate", "control-after", "batch-complete", "complete",
    ]
    assert [row["candidate_order"] for row in events
            if row["stage"] in {"candidate", "candidate-skipped"}] == [99, 100, 101]
    assert all(row["record_type"] == survey.RECORD_TYPE
               and row["scientific_credit"] is False for row in events)
    assert events[-2]["controls_pass"] is True
    assert not (output.stat().st_mode & 0o077)


def test_failed_control_preserves_incomplete_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    control = survey.rapid_study_profile.TRIAGE_POLICY["control_url"]
    calls: list[str] = []
    outcomes = iter(("timeout", "known-valid"))

    def probe(url: str) -> dict:
        calls.append(url)
        return {"url": url, "outcome": next(outcomes)}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(output=output, start_index=0, count=2, probe=probe)
    assert result["status"] == "control-failed"
    assert result["attempted_targets"] == 0
    assert calls == [control, control]
    assert not any(row["stage"] == "candidate" for row in _events(output))
    assert _events(output)[-1]["stage"] == "complete"


def test_eleven_targets_use_two_control_brackets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    calls: list[str] = []

    def probe(url: str) -> dict:
        calls.append(url)
        return {"url": url, "outcome": "known-valid"}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(output=output, start_index=0, count=11, probe=probe)
    control = survey.rapid_study_profile.TRIAGE_POLICY["control_url"]
    assert result["completed_batches"] == 2
    assert result["attempted_targets"] == 11
    assert calls.count(control) == 4
    assert [row["attempted_targets"] for row in _events(output)
            if row["stage"] == "batch-complete"] == [10, 1]


def test_wall_deadline_preserves_incomplete_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    output = tmp_path / "survey.jsonl"

    def probe(_url: str) -> dict:
        raise survey.SurveyDeadlineExceeded("simulated deadline")

    result = survey.run_survey(output=output, start_index=0, count=1, probe=probe)
    assert result["status"] == "timed-out"
    assert result["attempted_targets"] == 0
    assert [row["stage"] for row in _events(output)][-2:] == ["run-timeout", "complete"]


def test_independent_verifier_reopens_first_screen_without_admission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args, sources = _verifier_inputs(monkeypatch)
    output = tmp_path / "survey.jsonl"

    def probe(url: str) -> dict:
        return _probe_detail(url, known_valid=url != "https://elmundo.es/")

    assert survey.run_survey(
        output=output, start_index=0, count=2, probe=probe
    )["status"] == "complete"
    decisions = rapid.verify_fallback_h3_survey_logs([output], *sources, **args)
    assert [row["fallback_index"] for row in decisions] == [0, 1]
    assert [row["candidate_order"] for row in decisions] == [74, 75]
    assert [row["root_screen"]["outcome"] for row in decisions] == [
        "known-valid", "ambiguous",
    ]
    assert decisions[1]["root_screen"]["detail"] == "response-known-invalid"
    assert decisions[0]["root_screen"]["receipt_sha256"] == hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    assert all("admission" not in row for row in decisions)
    with pytest.raises(ValueError, match="predates"):
        rapid.verify_fallback_h3_survey_log(
            output, *sources,
            **{**args, "not_before_utc": datetime.now(UTC) + timedelta(seconds=1)},
        )


def test_independent_verifier_requires_frozen_profile_and_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args, sources = _verifier_inputs(monkeypatch)
    output = tmp_path / "survey.jsonl"
    survey.run_survey(output=output, start_index=0, count=1, probe=_probe_detail)
    with pytest.raises(ValueError, match="frozen v4 bytes"):
        rapid.verify_fallback_h3_survey_log(
            output, sources[0] + b"\n", *sources[1:], **args
        )
    dirty = {**args["expected_runtime_source"], "lab_dirty": True}
    with pytest.raises(ValueError, match="expected runtime binding"):
        rapid.verify_fallback_h3_survey_log(
            output, *sources, **{**args, "expected_runtime_source": dirty}
        )


@pytest.mark.parametrize("mutation,match", [
    ("candidate-order", "candidate identity or order"),
    ("outcome", "outcome differs"),
    ("profile", "profile, source or runtime binding"),
    ("control", "control before candidate batch failed"),
])
def test_independent_verifier_rejects_tampered_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str, match: str
) -> None:
    args, sources = _verifier_inputs(monkeypatch)
    output = tmp_path / "survey.jsonl"
    survey.run_survey(
        output=output, start_index=0, count=1, probe=_probe_detail
    )
    rows = _events(output)
    if mutation == "candidate-order":
        next(row for row in rows if row["stage"] == "candidate")["candidate_order"] = 75
    elif mutation == "outcome":
        next(row for row in rows if row["stage"] == "candidate")["outcome"] = "ambiguous"
    elif mutation == "profile":
        rows[0]["profile_sha256"] = "0" * 64
    else:
        rows[1]["outcome"] = "timeout"
    tampered = _tamper(rows, tmp_path / "tampered.jsonl")
    with pytest.raises(ValueError, match=match):
        rapid.verify_fallback_h3_survey_log(tampered, *sources, **args)


def test_fallback_prefix_rejects_gap_duplicate_and_reordering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args, sources = _verifier_inputs(monkeypatch)
    first = tmp_path / "first.jsonl"
    gap = tmp_path / "gap.jsonl"
    duplicate = tmp_path / "duplicate.jsonl"
    survey.run_survey(output=first, start_index=0, count=2, probe=_probe_detail)
    survey.run_survey(output=gap, start_index=3, count=1, probe=_probe_detail)
    survey.run_survey(output=duplicate, start_index=1, count=2, probe=_probe_detail)
    assert len(rapid.verify_fallback_h3_survey_logs([first], *sources, **args)) == 2
    for paths in ([first, gap], [first, duplicate], [duplicate, first]):
        with pytest.raises(ValueError, match="gaps, reorder or repeat"):
            rapid.verify_fallback_h3_survey_logs(paths, *sources, **args)


def test_failed_after_control_cannot_promote_candidate_screen(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args, sources = _verifier_inputs(monkeypatch)
    output = tmp_path / "failed-control.jsonl"
    probe_count = 0

    def probe(url: str) -> dict:
        nonlocal probe_count
        probe_count += 1
        return _probe_detail(url, known_valid=probe_count != 3)

    assert survey.run_survey(
        output=output, start_index=0, count=1, probe=probe
    )["status"] == "control-failed"
    with pytest.raises(ValueError, match="control after candidate batch failed"):
        rapid.verify_fallback_h3_survey_log(output, *sources, **args)


def test_fallback_safety_skip_reopens_as_no_root_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args, sources = _verifier_inputs(monkeypatch)
    output = tmp_path / "unsafe.jsonl"
    survey.run_survey(output=output, start_index=26, count=1, probe=_probe_detail)
    (decision,) = rapid.verify_fallback_h3_survey_log(output, *sources, **args)
    assert decision["domain"] == "xnxx.com"
    assert decision["root_screen"] is None
    assert decision["automatic_safety_reason"] == (
        "domain-safety-policy-rejected:exact-domain"
    )


def test_live_probe_requires_public_origin_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("QCSD_PUBLIC_ORIGIN_ONLY", raising=False)
    output = tmp_path / "survey.jsonl"
    with pytest.raises(ValueError, match="QCSD_PUBLIC_ORIGIN_ONLY=1"):
        survey.run_survey(output=output, start_index=0, count=1)
    assert not output.exists()


@pytest.mark.parametrize("start,count", [(-1, 1), (0, 0), (0, 41), (600, 1)])
def test_slice_bounds(start: int, count: int) -> None:
    with pytest.raises(ValueError):
        survey._targets(
            survey.DEFAULT_PROFILE, survey.DEFAULT_SOURCE,
            survey.DEFAULT_CATALOGUE, start, count,
        )


def test_output_is_create_only_and_outside_lab(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    output = tmp_path / "survey.jsonl"
    output.write_text("preserve me", encoding="utf-8")
    with pytest.raises(FileExistsError):
        survey.run_survey(
            output=output, start_index=0, count=1,
            probe=lambda _url: {"outcome": "known-valid"},
        )
    assert output.read_text(encoding="utf-8") == "preserve me"
    with pytest.raises(ValueError, match="outside the Lab checkout"):
        survey._open_output(survey.LAB_ROOT / "survey.jsonl")
