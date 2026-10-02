"""Prospective exact-page H3 selection stays separate from the v4 cohort."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import rapid_study_profile as rapid
from tools import h3_rapid_fallback_survey


ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = (
    ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
).read_bytes()
BINDING = {
    "source_manifest_sha256": "c" * 64,
    "admission_image_digest": "sha256:" + "d" * 64,
}


def _source(monkeypatch: pytest.MonkeyPatch) -> bytes:
    raw = json.dumps([
        {"crUX_domain": f"site{i}.example", "resources": []}
        for i in range(60)
    ]).encode()
    monkeypatch.setattr(rapid, "SOURCE_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(rapid, "SOURCE_CANDIDATE_COUNT", 60)
    return raw


def _facts(candidates: tuple[dict, ...], count: int, *, reject: int = 2):
    records = {}
    digests = []
    for index, candidate in enumerate(candidates[:count]):
        digest = f"{index + 1:064x}"
        digests.append(digest)
        root = f"https://{candidate['domain']}/"
        proof = {
            "policy": rapid.V5_SELECTED_PAGE_H3_POLICY,
            "url": root,
            "selected_page_ordinal": 0,
            "navigation_receipt_sha256": "9" * 64,
            "outcome": "known-valid",
            "receipt_sha256": "a" * 64,
            "controls_passed": True,
        }
        records[digest] = {
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "source_kind": candidate["source_kind"],
            "outcome": "ineligible" if index < reject else "admitted",
            "execution_binding": BINDING,
            "root_screen": {
                "policy": rapid.V5_TRIAGE_POLICY["root_screen_policy"],
                "url": root,
                "outcome": "known-valid",
                "detail": "known-valid",
                "receipt_sha256": "e" * 64,
                "controls_passed": True,
            },
            "site_safety_review": {
                "policy": rapid.SITE_SAFETY_REVIEW_POLICY["policy"],
                "decision": "approved-public-page",
                "reason": None,
                "receipt_sha256": "f" * 64,
            },
            "selected_page_h3_proof": proof,
            "admission": None if index < reject else {
                "selected_page_url": root,
                "prepared_workload_sha256": "b" * 64,
                "cross_origin_resource_count": 1,
                "full_resource_graph_sha256": "1" * 64,
                "h3_proof_sha256": proof["receipt_sha256"],
            },
        }
    return digests, records


def test_v5_profile_preserves_16000_and_v4_validation(monkeypatch: pytest.MonkeyPatch):
    source = _source(monkeypatch)
    old = rapid.build_profile_receipt(source, CATALOGUE)
    new = rapid.build_v5_profile_receipt(source, CATALOGUE)
    assert len(rapid.validate_profile_receipt(old, source, CATALOGUE)) == 660
    assert len(rapid.validate_v5_profile_receipt(new, source, CATALOGUE)) == 660
    assert new["schema_version"] == 5
    assert new["receipt_type"] != old["receipt_type"]
    assert new["payload"]["formal_modes"] == [
        "undefended", "front", "tamaraw", "buflo", "cs-buflo"
    ]
    contracts = {item["generation"]: item for item in new["payload"]["cohort_contracts"]}
    assert contracts["final-50"]["planned_visit_count"] == 50 * 5 * 64 == 16_000
    assert contracts["launch-10"]["planned_visit_count"] == 10 * 5 == 50
    assert contracts["launch-10"]["formal_sample_target"] == 0
    with pytest.raises(ValueError, match="schema is unsupported"):
        rapid.validate_profile_receipt(new, source, CATALOGUE)
    with pytest.raises(ValueError, match="schema is unsupported"):
        rapid.validate_v5_profile_receipt(old, source, CATALOGUE)


def test_checked_in_v5_profile_is_frozen_and_full_graph_remains_required():
    source = (ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
    profile_bytes = (
        ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
    ).read_bytes()
    assert hashlib.sha256(profile_bytes).hexdigest() == rapid.FROZEN_V5_PROFILE_SHA256
    profile = json.loads(profile_bytes)
    assert len(rapid.validate_v5_profile_receipt(profile, source, CATALOGUE)) == 673
    assert "complete-live-graph" in profile["payload"]["admission_policy"]
    assert profile["payload"]["admission_minimum_cross_origin_resources"] == 1


def test_v5_fallback_survey_reopens_exact_dns_only_after_profile_freeze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    image = BINDING["admission_image_digest"]
    runtime = {
        "image_digest": image,
        "lab_commit": "1" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_commit": "2" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
        "neqo_pinned_commit": "2" * 40,
    }
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", image)
    monkeypatch.setattr(h3_rapid_fallback_survey, "source_metadata", lambda: runtime)

    def probe(url: str) -> dict:
        now = datetime.now(UTC).isoformat()
        if url == "https://msftauth.net/":
            return {
                "url": url, "started_at": now, "completed_at": now,
                "resolver_addresses": [],
                "resolver_error": "gaierror: [Errno -2] Name or service not known",
                "exit_code": None, "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stdout_excerpt": "", "output_sha256": None,
                "output_text": None, "known_valid": None, "outcome": "ambiguous",
            }
        output = json.dumps({"resources": [{
            "id": 0, "url": url, "type": "Unknown", "content_length": 42,
            "data_length": 42, "chaff_priority": False, "known_valid": True,
            "depends_on": [], "headers": [],
        }]})
        return {
            "url": url, "started_at": now, "completed_at": now,
            "resolver_addresses": ["192.0.2.1"], "resolver_error": None,
            "exit_code": 0, "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_excerpt": "", "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output_text": output, "known_valid": True, "outcome": "known-valid",
        }

    before = datetime.now(UTC) - timedelta(seconds=1)
    v5_log = tmp_path / "v5-synthetic.jsonl"
    assert h3_rapid_fallback_survey.run_survey(
        output=v5_log, start_index=0, count=3, probe=probe, study_version=5,
    )["status"] == "complete"
    rows = [json.loads(line) for line in v5_log.read_text().splitlines()]
    assert rows[0]["profile_sha256"] == rapid.FROZEN_V5_PROFILE_SHA256
    assert all(row["record_type"] == h3_rapid_fallback_survey.V5_RECORD_TYPE for row in rows)
    profile_bytes = (
        ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
    ).read_bytes()
    source = (ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
    args = {
        "execution_binding": BINDING,
        "expected_runtime_source": runtime,
        "expected_mounted_module_hashes": rows[0]["mounted_module_hashes"],
        "not_before_utc": before,
    }
    decisions = rapid.verify_v5_fallback_h3_survey_logs(
        [v5_log], profile_bytes, source, CATALOGUE, **args
    )
    assert [decision["fallback_index"] for decision in decisions] == [0, 1, 2]
    assert decisions[2]["root_screen"]["detail"] == "dns-name-not-found"
    old_log = tmp_path / "v4-synthetic.jsonl"
    assert h3_rapid_fallback_survey.run_survey(
        output=old_log, start_index=0, count=3, probe=probe,
    )["status"] == "complete"
    with pytest.raises(ValueError, match="record contract"):
        rapid.verify_v5_fallback_h3_survey_logs(
            [old_log], profile_bytes, source, CATALOGUE, **args
        )
    with pytest.raises(ValueError, match="predates"):
        rapid.verify_v5_fallback_h3_survey_logs(
            [v5_log], profile_bytes, source, CATALOGUE,
            **{**args, "not_before_utc": datetime.now(UTC) + timedelta(seconds=1)},
        )


def test_v5_runner_refuses_wrong_profile_and_preserves_output(tmp_path: Path):
    output = tmp_path / "survey.jsonl"
    def no_probe(_url: str) -> dict:
        pytest.fail("invalid profile or output must fail before live probing")

    with pytest.raises(ValueError, match="rapid-v5 profile differs"):
        h3_rapid_fallback_survey.run_survey(
            study_version=5, profile=h3_rapid_fallback_survey.DEFAULT_PROFILE,
            output=output, start_index=0, count=1, probe=no_probe,
        )
    assert not output.exists()
    altered = tmp_path / "altered-v5-profile.json"
    altered.write_bytes(h3_rapid_fallback_survey.DEFAULT_V5_PROFILE.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="rapid-v5 profile differs"):
        h3_rapid_fallback_survey.run_survey(
            study_version=5, profile=altered,
            output=output, start_index=0, count=1, probe=no_probe,
        )
    assert not output.exists()
    output.write_text("preserve existing evidence", encoding="utf-8")
    with pytest.raises(FileExistsError):
        h3_rapid_fallback_survey.run_survey(
            study_version=5, output=output, start_index=0, count=1, probe=no_probe,
        )
    assert output.read_text(encoding="utf-8") == "preserve existing evidence"
    with pytest.raises(ValueError, match="study version"):
        h3_rapid_fallback_survey.run_survey(
            study_version=6, output=tmp_path / "never.jsonl",
            start_index=0, count=1, probe=no_probe,
        )


def test_exact_dns_name_failure_is_operational_deferral_only():
    now = datetime.now(UTC).isoformat()
    detail = {
        "url": "https://site1.example/",
        "started_at": now,
        "completed_at": now,
        "resolver_addresses": [],
        "resolver_error": "gaierror: [Errno -2] Name or service not known",
        "exit_code": None,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_excerpt": "",
        "output_sha256": None,
        "output_text": None,
        "known_valid": None,
        "outcome": "ambiguous",
    }
    assert rapid._survey_probe_class_v5(detail, detail["url"]) == (
        "ambiguous", "dns-name-not-found"
    )
    with pytest.raises(ValueError, match="incomplete"):
        rapid._survey_probe_class(detail, detail["url"])
    for change in (
        {"resolver_error": "gaierror: [Errno -3] Temporary failure"},
        {"exit_code": 0},
        {"resolver_addresses": ["192.0.2.1"]},
        {"outcome": "known-valid"},
    ):
        with pytest.raises(ValueError, match="unclassified"):
            rapid._survey_probe_class_v5({**detail, **change}, detail["url"])


def test_v5_selected_page_can_rescue_ambiguous_root_without_retrocredit(
    monkeypatch: pytest.MonkeyPatch,
):
    source = _source(monkeypatch)
    profile = rapid.build_v5_profile_receipt(source, CATALOGUE)
    candidates = rapid.validate_v5_profile_receipt(profile, source, CATALOGUE)
    digests, records = _facts(candidates, 12)
    candidate = candidates[2]
    admitted = records[digests[2]]
    admitted["root_screen"].update({
        "outcome": "ambiguous", "detail": "dns-name-not-found"
    })
    selected_url = f"https://www.{candidate['domain']}/about"
    admitted["selected_page_h3_proof"].update({
        "url": selected_url, "selected_page_ordinal": 1
    })
    admitted["admission"]["selected_page_url"] = selected_url
    receipt = rapid.build_v5_cohort_receipt(
        profile, source, CATALOGUE, generation="launch-10",
        terminal_sha256s=digests[:12], execution_binding=BINDING,
        deep_verify_terminal=records.__getitem__,
    )
    assert len(rapid.validate_v5_cohort_receipt(
        receipt, profile, source, CATALOGUE, execution_binding=BINDING,
        deep_verify_terminal=records.__getitem__,
    )) == 10
    assert receipt["payload"]["formal_sample_target"] == 0
    with pytest.raises(ValueError, match="schema is unsupported"):
        rapid.validate_cohort_receipt(
            receipt, rapid.build_profile_receipt(source, CATALOGUE),
            source, CATALOGUE, execution_binding=BINDING,
            deep_verify_terminal=records.__getitem__,
        )

    page_proof = admitted["selected_page_h3_proof"]
    admitted["selected_page_h3_proof"] = None
    with pytest.raises(ValueError, match="controlled root and selected-page"):
        rapid.build_v5_cohort_receipt(
            profile, source, CATALOGUE, generation="launch-10",
            terminal_sha256s=digests, execution_binding=BINDING,
            deep_verify_terminal=records.__getitem__,
        )
    admitted["selected_page_h3_proof"] = page_proof
    admitted["root_screen"]["outcome"] = "known-valid"
    with pytest.raises(ValueError, match="controlled first probe"):
        rapid.build_v5_cohort_receipt(
            profile, source, CATALOGUE, generation="launch-10",
            terminal_sha256s=digests, execution_binding=BINDING,
            deep_verify_terminal=records.__getitem__,
        )
    admitted["root_screen"]["outcome"] = "ambiguous"
    admitted["root_screen"]["policy"] = rapid.TRIAGE_POLICY["root_screen_policy"]
    with pytest.raises(ValueError, match="controlled first probe"):
        rapid.build_v5_cohort_receipt(
            profile, source, CATALOGUE, generation="launch-10",
            terminal_sha256s=digests, execution_binding=BINDING,
            deep_verify_terminal=records.__getitem__,
        )
    admitted["root_screen"]["policy"] = rapid.V5_TRIAGE_POLICY["root_screen_policy"]

    for bad_url in ("https://evil.example/about", "http://www.site2.example/about"):
        admitted["selected_page_h3_proof"]["url"] = bad_url
        with pytest.raises(ValueError, match="outside the frozen page boundary"):
            rapid.build_v5_cohort_receipt(
                profile, source, CATALOGUE, generation="launch-10",
                terminal_sha256s=digests, execution_binding=BINDING,
                deep_verify_terminal=records.__getitem__,
            )
    admitted["selected_page_h3_proof"]["url"] = selected_url
    admitted["admission"]["cross_origin_resource_count"] = 0
    with pytest.raises(ValueError, match="multi-origin"):
        rapid.build_v5_cohort_receipt(
            profile, source, CATALOGUE, generation="launch-10",
            terminal_sha256s=digests[:12], execution_binding=BINDING,
            deep_verify_terminal=records.__getitem__,
        )


def test_v5_dns_deferral_does_not_become_ineligible_or_admitted(
    monkeypatch: pytest.MonkeyPatch,
):
    source = _source(monkeypatch)
    profile = rapid.build_v5_profile_receipt(source, CATALOGUE)
    candidates = rapid.validate_v5_profile_receipt(profile, source, CATALOGUE)
    digests, records = _facts(candidates, 13)
    digest = digests[0]
    record = records[digest]
    record["root_screen"].update({
        "outcome": "ambiguous", "detail": "dns-name-not-found"
    })
    record.update({
        "outcome": "screen-deferred", "selected_page_h3_proof": None,
        "site_safety_review": None,
        "triage": {
            "policy": rapid.V5_TRIAGE_POLICY["policy"],
            "reason": "operational-dns-name-not-found",
            "safety_reason": None,
        },
    })
    receipt = rapid.build_v5_cohort_receipt(
        profile, source, CATALOGUE, generation="launch-10",
        terminal_sha256s=digests[:12], execution_binding=BINDING,
        deep_verify_terminal=records.__getitem__,
    )
    assert receipt["payload"]["terminal_decisions"][0]["outcome"] == "screen-deferred"
    record["outcome"] = "ineligible"
    with pytest.raises(ValueError, match="full screened page decision"):
        rapid.build_v5_cohort_receipt(
            profile, source, CATALOGUE, generation="launch-10",
            terminal_sha256s=digests[:12], execution_binding=BINDING,
            deep_verify_terminal=records.__getitem__,
        )


def test_v5_profile_receipt_publication_is_create_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
):
    source = _source(monkeypatch)
    profile = rapid.build_v5_profile_receipt(source, CATALOGUE)
    path = tmp_path / "v5-profile.json"
    rapid.write_receipt_create_only(path, profile)
    assert json.loads(path.read_bytes()) == profile
    with pytest.raises(FileExistsError):
        rapid.write_receipt_create_only(path, profile)
