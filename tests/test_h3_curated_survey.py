"""The curated H3 root survey is bounded diagnostic telemetry only."""

from __future__ import annotations

import json
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab.class_curated_source import build_curated_source_receipt
from qcsd_lab import h3_prebaseline, rapid_study_profile as rapid
from tools import h3_curated_survey as survey


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "curated.json"
    source.write_text(json.dumps([
        {"crUX_domain": "example.com", "resources": []},
        {"crUX_domain": "bookmark.xxx", "resources": []},
    ]), encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(build_curated_source_receipt(source.read_bytes())), encoding="utf-8")
    return source, receipt


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_tracked_source_and_receipt_agree() -> None:
    targets, identity = survey._targets(survey.DEFAULT_SOURCE, survey.DEFAULT_RECEIPT, 0, 1)
    assert identity["candidate_count"] == 73
    assert len(identity["source_sha256"]) == 64
    assert targets[0]["source_index"] == 1
    assert targets[0]["domain"] == "444.hu"


def test_source_mismatch_refuses_probe(tmp_path: Path) -> None:
    source, receipt = _fixture(tmp_path)
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="differs from its exact source bytes"):
        survey._targets(source, receipt, 0, 1)


def test_control_brackets_and_unsafe_domain_skip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source, receipt = _fixture(tmp_path)
    monkeypatch.setattr(survey, "source_metadata", lambda: {"lab_commit": "test"})
    calls: list[str] = []

    def probe(url: str) -> dict:
        calls.append(url)
        return {"url": url, "outcome": "known-valid", "known_valid": True}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(
        source=source, receipt=receipt, output=output,
        start_index=0, count=2, probe=probe,
    )
    assert result == {
        "status": "complete", "selected_targets": 2, "attempted_targets": 1,
        "skipped_unsafe_targets": 1, "completed_batches": 1,
        "outcomes": {"known-valid": 1}, "scientific_credit": False,
    }
    assert calls == [
        survey.PREBASELINE_H3_SCREEN_V3_CONTRACT["control_url"],
        "https://example.com/",
        survey.PREBASELINE_H3_SCREEN_V3_CONTRACT["control_url"],
    ]
    assert [row["stage"] for row in _events(output)] == [
        "start", "control-before", "candidate", "candidate-skipped",
        "control-after", "batch-complete", "complete",
    ]
    assert all(row["scientific_credit"] is False for row in _events(output))
    assert not (output.stat().st_mode & 0o077)


def test_failed_control_skips_candidate_probes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source, receipt = _fixture(tmp_path)
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    outcomes = iter(("timeout", "known-valid"))
    calls: list[str] = []

    def probe(url: str) -> dict:
        calls.append(url)
        return {"url": url, "outcome": next(outcomes)}

    output = tmp_path / "survey.jsonl"
    result = survey.run_survey(
        source=source, receipt=receipt, output=output,
        start_index=0, count=2, probe=probe,
    )
    assert result["status"] == "control-failed"
    assert result["attempted_targets"] == 0
    assert len(calls) == 2
    assert not any(row["stage"] == "candidate" for row in _events(output))


def test_live_probe_requires_public_origin_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source, receipt = _fixture(tmp_path)
    monkeypatch.delenv("QCSD_PUBLIC_ORIGIN_ONLY", raising=False)
    output = tmp_path / "survey.jsonl"
    with pytest.raises(ValueError, match="QCSD_PUBLIC_ORIGIN_ONLY=1"):
        survey.run_survey(
            source=source, receipt=receipt, output=output,
            start_index=0, count=1,
        )
    assert not output.exists()


@pytest.mark.parametrize("start,count", [(-1, 1), (0, 0), (0, 41), (1, 2)])
def test_slice_bounds(tmp_path: Path, start: int, count: int) -> None:
    source, receipt = _fixture(tmp_path)
    with pytest.raises(ValueError):
        survey._targets(source, receipt, start, count)


def test_output_is_create_only_and_outside_lab(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source, receipt = _fixture(tmp_path)
    monkeypatch.setattr(survey, "source_metadata", lambda: {})
    output = tmp_path / "survey.jsonl"
    output.write_text("preserve me", encoding="utf-8")
    with pytest.raises(FileExistsError):
        survey.run_survey(
            source=source, receipt=receipt, output=output,
            start_index=0, count=1,
            probe=lambda _url: {"outcome": "known-valid"},
        )
    assert output.read_text(encoding="utf-8") == "preserve me"
    with pytest.raises(ValueError, match="outside the Lab checkout"):
        survey._open_output(survey.LAB_ROOT / "survey.jsonl")


def test_v5_source_profile_binding_fails_before_probing(tmp_path: Path) -> None:
    output = tmp_path / "v5-never.jsonl"

    def no_probe(_url: str) -> dict:
        pytest.fail("invalid prospective identity must not reach the network")

    with pytest.raises(ValueError, match="study version"):
        survey.run_survey(output=output, start_index=0, count=1, study_version=6, probe=no_probe)
    with pytest.raises(ValueError, match="requires --study-version 5"):
        survey.run_survey(
            output=output, start_index=0, count=1,
            profile=survey.DEFAULT_V5_PROFILE, probe=no_probe,
        )
    with pytest.raises(ValueError, match="rapid-v5 profile differs"):
        survey.run_survey(
            output=output, start_index=0, count=1, study_version=5,
            profile=survey.LAB_ROOT / "config/curated-sources/crux73-tranco600-rapid-v4.profile.json",
            probe=no_probe,
        )
    assert not output.exists()


def test_v5_curated_inventory_reopens_and_rejects_historical_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    image = "sha256:" + "d" * 64
    empty = hashlib.sha256(b"").hexdigest()
    runtime = {
        "image_digest": image, "lab_commit": "1" * 40, "lab_dirty": False,
        "lab_patch_sha256": empty, "neqo_commit": "2" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": empty,
        "neqo_pinned_commit": "2" * 40,
    }
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", image)
    monkeypatch.setattr(survey, "source_metadata", lambda: runtime)

    def probe(url: str) -> dict:
        now = datetime.now(UTC).isoformat()
        output = json.dumps({"resources": [{
            "id": 0, "url": url, "type": "Unknown", "content_length": 42,
            "data_length": 42, "chaff_priority": False, "known_valid": True,
            "depends_on": [], "headers": [],
        }]})
        return {
            "url": url, "started_at": now, "completed_at": now,
            "resolver_addresses": ["104.18.26.14"], "resolver_error": None,
            "exit_code": 0, "stdout_sha256": empty, "stdout_excerpt": "",
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output_text": output, "known_valid": True, "outcome": "known-valid",
        }

    before = datetime.now(UTC) - timedelta(seconds=1)
    logs = [tmp_path / "v5-first40.jsonl", tmp_path / "v5-last33.jsonl"]
    for path, start, count in ((logs[0], 0, 40), (logs[1], 40, 33)):
        assert survey.run_survey(
            output=path, start_index=start, count=count, study_version=5, probe=probe,
        )["status"] == "complete"
        rows = _events(path)
        assert rows[0]["profile_sha256"] == rapid.FROZEN_V5_PROFILE_SHA256
        assert all(row["record_type"] == survey.V5_RECORD_TYPE for row in rows)

    hashes = {
        "tools.h3_curated_survey": hashlib.sha256(Path(survey.__file__).read_bytes()).hexdigest(),
        "qcsd_lab.h3_prebaseline": hashlib.sha256(Path(h3_prebaseline.__file__).read_bytes()).hexdigest(),
        "qcsd_lab.rapid_study_profile": hashlib.sha256(Path(rapid.__file__).read_bytes()).hexdigest(),
    }
    args = {
        "execution_binding": {"source_manifest_sha256": "c" * 64, "admission_image_digest": image},
        "expected_runtime_source": runtime,
        "expected_mounted_module_hashes": hashes,
        "not_before_utc": before,
    }
    profile = survey.DEFAULT_V5_PROFILE.read_bytes()
    source = survey.DEFAULT_SOURCE.read_bytes()
    receipt = survey.DEFAULT_RECEIPT.read_bytes()
    catalogue = survey.DEFAULT_CATALOGUE.read_bytes()
    decisions = rapid.verify_v5_curated_h3_survey_logs(
        logs, profile, source, receipt, catalogue, **args,
    )
    assert [row["source_position"] for row in decisions] == list(range(1, 74))
    assert sum(row["root_screen"] is not None for row in decisions) == 66
    assert all(
        row["root_screen"]["policy"] == rapid.V5_TRIAGE_POLICY["root_screen_policy"]
        for row in decisions if row["root_screen"] is not None
    )

    old = tmp_path / "historical-v4.jsonl"
    survey.run_survey(output=old, start_index=0, count=40, probe=probe)
    with pytest.raises(ValueError, match="record contract"):
        rapid.verify_v5_curated_h3_survey_logs(
            [old, logs[1]], profile, source, receipt, catalogue, **args,
        )
    altered = tmp_path / "wrong-profile.jsonl"
    rows = _events(logs[0])
    rows[0]["profile_sha256"] = "0" * 64
    altered.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="protocol binding differs"):
        rapid.verify_v5_curated_h3_survey_logs(
            [altered, logs[1]], profile, source, receipt, catalogue, **args,
        )
