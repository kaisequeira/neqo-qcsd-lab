"""The catalogue survey is bounded search telemetry, never acquisition evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import h3_catalogue_survey as survey


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_frozen_catalogue_slice_uses_each_stratum_in_order():
    targets, digest = survey._targets(8, 1)
    assert len(digest) == 64
    assert [row["candidate_id"] for row in targets] == [
        "tranco-0000280", "tranco-0008176", "tranco-0089465",
        "tranco-0290468", "tranco-0762962",
    ]
    assert all(row["catalogue_index"] == 8 for row in targets)


def test_hash_mismatch_refuses_probe(monkeypatch, tmp_path):
    study = json.loads(survey.STUDY_PATH.read_text())
    study["population"]["candidate_catalogue"]["sha256"] = "0" * 64
    changed = tmp_path / "study.json"
    changed.write_text(json.dumps(study))
    monkeypatch.setattr(survey, "STUDY_PATH", changed)
    with pytest.raises(ValueError, match="differs from the study digest"):
        survey._targets(0, 1)


def test_control_brackets_and_zero_credit_events(monkeypatch, tmp_path):
    monkeypatch.setattr(survey, "source_metadata", lambda: {"lab_commit": "test"})
    calls = []

    def probe(url):
        calls.append(url)
        return {
            "url": url, "outcome": "known-valid", "known_valid": True,
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
        }

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(
        output=output, start_index=8, count=1, probe=probe,
    )
    assert result["status"] == "complete"
    assert result["attempted_targets"] == 5
    assert len(calls) == 7
    assert calls[0] == calls[-1] == survey.PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    assert [row["domain"] for row in _events(output) if row["stage"] == "candidate"] == [
        "amplitude.com", "dagospia.com", "blankshirts.com",
        "buyzoxs.de", "astrolearn.co",
    ]
    assert next(row for row in _events(output) if row["stage"] == "batch-complete")[
        "controls_pass"
    ] is True
    assert all(row["scientific_credit"] is False for row in _events(output))
    assert not (output.stat().st_mode & 0o077)


def test_failed_control_skips_candidates_and_retains_failed_batch(monkeypatch, tmp_path):
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    outcomes = iter(("timeout", "known-valid"))

    def probe(url):
        assert url == survey.PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
        return {"url": url, "outcome": next(outcomes)}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(output=output, start_index=0, count=1, probe=probe)
    assert result["status"] == "control-failed"
    assert result["attempted_targets"] == 0
    assert not any(row["stage"] == "candidate" for row in _events(output))
    assert next(row for row in _events(output) if row["stage"] == "batch-complete")[
        "controls_pass"
    ] is False


def test_45_targets_have_separate_control_brackets(monkeypatch, tmp_path):
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    calls = []

    def probe(url):
        calls.append(url)
        return {"url": url, "outcome": "known-valid"}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(output=output, start_index=0, count=9, probe=probe)
    assert result["attempted_targets"] == 45
    assert result["completed_batches"] == 2
    assert len(calls) == 49
    assert [row["attempted_targets"] for row in _events(output)
            if row["stage"] == "batch-complete"] == [40, 5]


def test_timeout_is_retained_as_incomplete(monkeypatch, tmp_path):
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    output = tmp_path / "survey.jsonl"

    def probe(_url):
        raise survey.SurveyDeadlineExceeded("simulated wall deadline")

    result = survey.run_survey(output=output, start_index=0, count=1, probe=probe)
    assert result["status"] == "timed-out"
    assert any(row["stage"] == "run-timeout" for row in _events(output))
    assert _events(output)[-1]["stage"] == "complete"


def test_output_is_create_only_and_outside_lab(monkeypatch, tmp_path):
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    output = tmp_path / "survey.jsonl"
    output.write_text("preserve me")
    with pytest.raises(FileExistsError):
        survey.run_survey(output=output, start_index=0, count=1, probe=lambda _: {})
    assert output.read_text() == "preserve me"
    with pytest.raises(ValueError, match="outside the Lab checkout"):
        survey._open_output(survey.LAB_ROOT / "survey.jsonl")


@pytest.mark.parametrize("start,count", [(-1, 1), (0, 0), (0, 25), (119, 2)])
def test_slice_bounds(start, count):
    with pytest.raises(ValueError):
        survey._targets(start, count)
