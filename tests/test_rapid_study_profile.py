from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import rapid_study_profile as rapid
from qcsd_lab import h3_prebaseline
from qcsd_lab.class_curated_source import (
    build_curated_source_receipt, validate_curated_source_receipt,
)
from qcsd_lab.class_catalogue import validate_candidate_catalogue_receipt
from tools import h3_curated_survey

LAB_ROOT = Path(__file__).resolve().parents[1]
CATALOGUE_BYTES = (
    LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
).read_bytes()

EXECUTION_BINDING = {
    "source_manifest_sha256": "c" * 64,
    "admission_image_digest": "sha256:" + "d" * 64,
}


def _fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, dict, list[dict]]:
    source = [
        {
            "crUX_domain": f"site{i}.example",
            "resources": [] if i == 0 else [{
                "resource_domain": f"cdn{i}.example",
                "resource_urls": [f"https://cdn{i}.example/resource.css"],
            }],
        }
        for i in range(60)
    ]
    source_bytes = json.dumps(source, separators=(",", ":")).encode()
    monkeypatch.setattr(rapid, "SOURCE_SHA256", hashlib.sha256(source_bytes).hexdigest())
    monkeypatch.setattr(rapid, "SOURCE_CANDIDATE_COUNT", 60)
    profile = rapid.build_profile_receipt(source_bytes, CATALOGUE_BYTES)
    candidates = list(rapid.validate_profile_receipt(profile, source_bytes, CATALOGUE_BYTES))
    return source_bytes, profile, candidates


def _terminal_inputs(
    candidates: list[dict], count: int, rejected: int = 2
) -> tuple[list[str], dict]:
    facts: dict[str, dict] = {}
    digests: list[str] = []
    for index, candidate in enumerate(candidates[:count]):
        digest = f"{index + 1:064x}"
        digests.append(digest)
        facts[digest] = {
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "source_kind": candidate["source_kind"],
            "outcome": "ineligible" if index < rejected else "admitted",
            "execution_binding": EXECUTION_BINDING,
            "root_screen": _root_screen(candidate),
            "site_safety_review": _approved_review(),
            "admission": None if index < rejected else {
                "cross_origin_resource_count": 1,
                "full_resource_graph_sha256": "a" * 64,
                "h3_proof_sha256": "b" * 64,
            },
        }
    return digests, facts


def _root_screen(
    candidate: dict, *, outcome: str = "known-valid", detail: str = "known-valid"
) -> dict:
    return {
        "policy": rapid.TRIAGE_POLICY["root_screen_policy"],
        "url": f"https://{candidate['domain']}/",
        "outcome": outcome,
        "detail": detail,
        "receipt_sha256": "e" * 64,
        "controls_passed": True,
    }


def _approved_review() -> dict:
    return {
        "policy": rapid.SITE_SAFETY_REVIEW_POLICY["policy"],
        "decision": "approved-public-page",
        "reason": None,
        "receipt_sha256": "f" * 64,
    }


def _defer_at_root(facts: dict, digest: str) -> None:
    screen = facts[digest]["root_screen"]
    facts[digest] = {
        **facts[digest],
        "outcome": "screen-deferred",
        "admission": None,
        "root_screen": {
            **screen, "outcome": "ambiguous", "detail": "response-known-invalid"
        },
        "site_safety_review": None,
        "triage": {
            "policy": rapid.TRIAGE_POLICY["policy"],
            "reason": "bounded-root-h3-no-known-valid",
            "safety_reason": None,
        },
    }


def test_launch_is_zero_credit_diagnostic_in_registered_hash_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    launch_digests, launch_facts = _terminal_inputs(candidates, 12)
    launch = rapid.build_cohort_receipt(
        profile, source, CATALOGUE_BYTES,
        generation="launch-10", terminal_sha256s=launch_digests,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=launch_facts.__getitem__,
    )
    selected = rapid.validate_cohort_receipt(
        launch, profile, source, CATALOGUE_BYTES, execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=launch_facts.__getitem__
    )
    assert len(selected) == 10
    assert launch["payload"]["study_id"] == "classifier-curated10-rapid-v4"
    assert launch["payload"]["cohort_role"] == "shakedown"
    assert launch["payload"]["visits_per_class_mode"] == 1
    assert launch["payload"]["planned_visit_count"] == 50
    assert launch["payload"]["formal_sample_target"] == 0
    assert launch["payload"]["sample_credit_policy"] == "zero-credit-diagnostic"
    assert launch["payload"]["formal_modes"] == [
        "undefended", "front", "tamaraw", "buflo", "cs-buflo"
    ]
    assert launch["payload"]["capture_authority"].startswith("none-")


def test_final_50_is_a_separate_16000_trace_corpus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 52)
    final = rapid.build_cohort_receipt(
        profile, source, CATALOGUE_BYTES,
        generation="final-50", terminal_sha256s=digests,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    )
    assert final["payload"]["study_id"] == "classifier-curated50-rapid-v4"
    assert final["payload"]["cohort_role"] == "final"
    assert final["payload"]["visits_per_class_mode"] == 64
    assert final["payload"]["planned_visit_count"] == 16_000
    assert final["payload"]["formal_sample_target"] == 16_000
    assert final["payload"]["sample_credit_policy"].startswith("formal-only")
    assert len(rapid.validate_cohort_receipt(
        final, profile, source, CATALOGUE_BYTES, execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    )) == 50


def test_ordered_bounded_screen_can_defer_expensive_browser_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 12)
    _defer_at_root(facts, digests[0])
    _defer_at_root(facts, digests[1])
    receipt = rapid.build_cohort_receipt(
        profile, source, CATALOGUE_BYTES,
        generation="launch-10", terminal_sha256s=digests,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    )
    assert receipt["payload"]["selection_policy"] == rapid.SELECTION_POLICY
    assert profile["payload"]["triage_policy"] == rapid.TRIAGE_POLICY
    assert profile["payload"]["site_safety_review_policy"] == rapid.SITE_SAFETY_REVIEW_POLICY
    assert [row["outcome"] for row in receipt["payload"]["terminal_decisions"][:2]] == [
        "screen-deferred", "screen-deferred"
    ]
    assert rapid.validate_cohort_receipt(
        receipt, profile, source, CATALOGUE_BYTES,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    ) == tuple(candidate["candidate_id"] for candidate in candidates[2:12])


@pytest.mark.parametrize(
    ("field", "change", "error"),
    [
        ("root_screen", {"outcome": "known-valid", "detail": "known-valid"}, "cannot defer"),
        ("root_screen", {"detail": "local-os-error"}, "controlled first probe"),
        ("root_screen", {"controls_passed": False}, "controlled first probe"),
        ("root_screen", {"receipt_sha256": None}, "controlled first probe"),
        ("triage", {"reason": "operator-skipped"}, "unregistered"),
    ],
)
def test_screen_deferral_requires_proven_nonclear_controlled_result(
    monkeypatch: pytest.MonkeyPatch, field: str, change: dict, error: str,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 12)
    _defer_at_root(facts, digests[0])
    facts[digests[0]][field].update(change)
    with pytest.raises(ValueError, match=error):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_automatic_safety_deferral_requires_policy_match() -> None:
    source = (LAB_ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
    profile = rapid.build_profile_receipt(source, CATALOGUE_BYTES)
    candidates = rapid.validate_profile_receipt(profile, source, CATALOGUE_BYTES)
    unsafe = next(row for row in candidates if row["domain"] == "bookmark.xxx")
    safe = next(row for row in candidates if row["domain"] == "www.bing.com")
    triage = {
        "policy": rapid.TRIAGE_POLICY["policy"],
        "reason": "automatic-safety-exclusion",
        "safety_reason": "domain-safety-policy-rejected:xxx",
    }
    assert rapid._validated_triage(triage, unsafe, None, None) == triage
    with pytest.raises(ValueError, match="not policy-derived"):
        rapid._validated_triage(triage, safe, None, None)


def test_narrow_manual_safety_exclusion_needs_review_receipt() -> None:
    candidate = {"domain": "chaturbate.com"}
    screen = rapid._validated_root_screen(_root_screen(candidate), candidate)
    review = rapid._validated_site_safety_review({
        "policy": rapid.SITE_SAFETY_REVIEW_POLICY["policy"],
        "decision": "excluded-public-page",
        "reason": "adult-explicit-content",
        "receipt_sha256": "f" * 64,
    })
    triage = {
        "policy": rapid.TRIAGE_POLICY["policy"],
        "reason": "manual-safety-exclusion",
        "safety_reason": "adult-explicit-content",
    }
    assert rapid._validated_triage(triage, candidate, screen, review) == triage
    with pytest.raises(ValueError, match="lacks verified review"):
        rapid._validated_triage(triage, candidate, screen, None)
    with pytest.raises(ValueError, match="lacks verified review"):
        rapid._validated_triage(
            {**triage, "safety_reason": "operator-preference"}, candidate, screen, review
        )


def test_admission_requires_approved_human_safety_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 12)
    facts[digests[2]]["site_safety_review"] = {
        "policy": rapid.SITE_SAFETY_REVIEW_POLICY["policy"],
        "decision": "excluded-public-page",
        "reason": "adult-explicit-content",
        "receipt_sha256": "f" * 64,
    }
    with pytest.raises(ValueError, match="approved human safety review"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_create_only_curated_survey_log_reopens_as_ordered_first_screen_facts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    source = [
        {"crUX_domain": f"site{i}.example", "resources": []}
        for i in range(10)
    ]
    source_bytes = rapid._canonical_json(source)
    monkeypatch.setattr(rapid, "SOURCE_SHA256", hashlib.sha256(source_bytes).hexdigest())
    monkeypatch.setattr(rapid, "SOURCE_CANDIDATE_COUNT", len(source))
    source_path = tmp_path / "raw.json"
    source_path.write_bytes(source_bytes)
    receipt_bytes = rapid._canonical_json(build_curated_source_receipt(source_bytes))
    receipt_path = tmp_path / "source.json"
    receipt_path.write_bytes(receipt_bytes)
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
    monkeypatch.setattr(h3_curated_survey, "source_metadata", lambda: runtime)

    def probe(url: str) -> dict:
        valid = url != "https://site5.example/"
        output = json.dumps({"resources": [{
            "id": 0, "url": url, "type": "Unknown", "content_length": 42,
            "data_length": 42, "chaff_priority": False, "known_valid": valid,
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
            "known_valid": valid,
            "outcome": "known-valid" if valid else "ambiguous",
        }

    log = tmp_path / "survey.jsonl"
    freeze = datetime.now(UTC) - timedelta(seconds=1)
    assert h3_curated_survey.run_survey(
        source=source_path, receipt=receipt_path, output=log,
        start_index=0, count=10, probe=probe,
    )["status"] == "complete"
    module_hashes = {
        "tools.h3_curated_survey": hashlib.sha256(
            Path(h3_curated_survey.__file__).read_bytes()
        ).hexdigest(),
        "qcsd_lab.h3_prebaseline": hashlib.sha256(
            Path(h3_prebaseline.__file__).read_bytes()
        ).hexdigest(),
    }
    args = {
        "execution_binding": {**EXECUTION_BINDING, "admission_image_digest": image_digest},
        "expected_runtime_source": runtime,
        "expected_mounted_module_hashes": module_hashes,
        "not_before_utc": freeze,
    }
    decisions = rapid.verify_curated_h3_survey_logs(
        [log], source_bytes, receipt_bytes, **args
    )
    assert len(decisions) == 10
    assert [row["source_position"] for row in decisions] == list(range(1, 11))
    assert decisions[5]["root_screen"]["detail"] == "response-known-invalid"
    assert decisions[5]["root_screen"]["receipt_sha256"] == hashlib.sha256(
        log.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="predates"):
        rapid.verify_curated_h3_survey_log(
            log, source_bytes, receipt_bytes,
            **{**args, "not_before_utc": datetime.now(UTC) + timedelta(seconds=1)},
        )

    rows = [json.loads(line) for line in log.read_text().splitlines()]
    next(row for row in rows if row.get("domain") == "site5.example")["outcome"] = "known-valid"
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_bytes(b"".join(
        json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows
    ))
    with pytest.raises(ValueError, match="outcome differs"):
        rapid.verify_curated_h3_survey_log(
            tampered, source_bytes, receipt_bytes, **args
        )


def test_unregistered_20_site_generation_cannot_inherit_formal_credit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 22)
    with pytest.raises(ValueError, match="unregistered"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="extension-20", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_real_imported_receipt_ids_map_exactly_to_hash_order() -> None:
    source_root = Path(__file__).resolve().parents[1] / "config/curated-sources"
    source = (source_root / "crux-73-v1.raw.json").read_bytes()
    imported = json.loads((source_root / "crux-73-v1.source.json").read_text())
    imported_domains = validate_curated_source_receipt(imported, source_bytes=source)
    profile = rapid.build_profile_receipt(source, CATALOGUE_BYTES)
    ordered = rapid.validate_profile_receipt(profile, source, CATALOGUE_BYTES)

    curated = [candidate for candidate in ordered if candidate["source_kind"] == "curated"]
    fallback = [candidate for candidate in ordered if candidate["source_kind"] == "tranco-fallback"]
    assert len(curated) == len(imported_domains) == 73
    assert len(fallback) == 600
    assert sorted(candidate["source_position"] for candidate in curated) == list(range(1, 74))
    for candidate in curated:
        source_candidate = imported["payload"]["candidates"][candidate["source_position"] - 1]
        assert candidate["candidate_id"] == source_candidate["candidate_id"]
        assert candidate["domain"] == source_candidate["domain"]
        assert candidate["listed_resource_url_count"] == source_candidate[
            "observed_resource_url_count"
        ]
    assert [candidate["candidate_order"] for candidate in ordered] == list(range(1, 674))
    assert [candidate["domain"] for candidate in curated] != list(imported_domains)
    tranco = json.loads(CATALOGUE_BYTES)["payload"]["candidates"]
    assert [candidate["candidate_id"] for candidate in fallback] == [
        candidate["candidate_id"] for candidate in tranco
    ]
    assert [candidate["source_position"] for candidate in fallback] == list(range(1, 601))
    assert profile["payload"]["fallback_overlaps"] == []


def test_published_v2_and_v3_profiles_stay_verify_only() -> None:
    source_root = LAB_ROOT / "config/curated-sources"
    source = (source_root / "crux-73-v1.raw.json").read_bytes()
    old_profile = json.loads(
        (source_root / "crux73-tranco600-rapid-v2.profile.json").read_text()
    )
    assert len(rapid.validate_historical_v2_profile_receipt(
        old_profile, source, CATALOGUE_BYTES
    )) == 673
    with pytest.raises(ValueError, match="schema is unsupported"):
        rapid.validate_profile_receipt(old_profile, source, CATALOGUE_BYTES)
    v3_profile = json.loads(
        (source_root / "crux73-tranco600-rapid-v3.profile.json").read_text()
    )
    assert len(rapid.validate_historical_v3_profile_receipt(
        v3_profile, source, CATALOGUE_BYTES
    )) == 673
    with pytest.raises(ValueError, match="schema is unsupported"):
        rapid.validate_profile_receipt(v3_profile, source, CATALOGUE_BYTES)


def test_final_selection_can_reach_tranco_fallback_without_reordering() -> None:
    source = (LAB_ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
    profile = rapid.build_profile_receipt(source, CATALOGUE_BYTES)
    candidates = list(rapid.validate_profile_receipt(profile, source, CATALOGUE_BYTES))
    digests, facts = _terminal_inputs(candidates, 124, rejected=73)
    unsafe_index = next(
        index for index, candidate in enumerate(candidates[73:124], start=73)
        if rapid.unsafe_catalogue_domain_reason(candidate["domain"]) is not None
    )
    facts[digests[unsafe_index]] = {
        **facts[digests[unsafe_index]],
        "outcome": "screen-deferred",
        "admission": None,
        "root_screen": None,
        "site_safety_review": None,
        "triage": {
            "policy": rapid.TRIAGE_POLICY["policy"],
            "reason": "automatic-safety-exclusion",
            "safety_reason": rapid.unsafe_catalogue_domain_reason(
                candidates[unsafe_index]["domain"]
            ),
        },
    }
    receipt = rapid.build_cohort_receipt(
        profile, source, CATALOGUE_BYTES,
        generation="final-50", terminal_sha256s=digests,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    )
    selected = rapid.validate_cohort_receipt(
        receipt, profile, source, CATALOGUE_BYTES,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    )
    assert selected == tuple(
        candidate["candidate_id"] for candidate in candidates[73:124]
        if rapid.unsafe_catalogue_domain_reason(candidate["domain"]) is None
    )
    assert len(receipt["payload"]["terminal_decisions"]) == 124
    assert all(
        candidate["source_kind"] == "tranco-fallback"
        for candidate in receipt["payload"]["selected_candidates"]
    )
    assert all(
        candidate["source_candidate_id"] == candidate["candidate_id"]
        and candidate["source_sha256"] == rapid.FALLBACK_CATALOGUE_SHA256
        and type(candidate["tranco_rank"]) is int
        for candidate in receipt["payload"]["selected_candidates"]
    )
    assert receipt["payload"]["fallback_catalogue_sha256"] == rapid.FALLBACK_CATALOGUE_SHA256


def test_fallback_domain_overlap_keeps_curated_id_and_records_tranco_provenance() -> None:
    source = (LAB_ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
    curated = rapid._source_candidates(source)
    tranco = validate_candidate_catalogue_receipt(json.loads(CATALOGUE_BYTES))
    first = replace(tranco[0], domain=curated[0]["domain"])
    combined, overlaps = rapid._merge_candidates(curated, (first, *tranco[1:]))
    assert len(combined) == 672
    assert len(overlaps) == 1
    assert overlaps[0] == {
        "domain": curated[0]["domain"],
        "tranco_candidate_id": first.candidate_id,
        "tranco_source_position": 1,
        "tranco_rank": first.rank,
        "tranco_stratum": first.stratum.id,
        "kept_curated_candidate_id": curated[0]["candidate_id"],
    }
    assert combined[0]["candidate_id"] == curated[0]["candidate_id"]
    assert combined[73]["candidate_id"] == tranco[1].candidate_id
    assert combined[73]["source_position"] == 2


def test_fallback_catalogue_corruption_fails_even_if_receipt_is_rehashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = (LAB_ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
    with pytest.raises(ValueError, match="registered SHA-256"):
        rapid.build_profile_receipt(source, CATALOGUE_BYTES + b" ")

    forged = json.loads(CATALOGUE_BYTES)
    forged["payload"]["candidates"][0]["domain"] = "forged.example"
    forged["payload_sha256"] = hashlib.sha256(
        rapid._canonical_json(forged["payload"])
    ).hexdigest()
    forged_bytes = rapid._canonical_json(forged)
    monkeypatch.setattr(
        rapid, "FALLBACK_CATALOGUE_SHA256", hashlib.sha256(forged_bytes).hexdigest()
    )
    with pytest.raises(ValueError, match="catalogue order"):
        rapid.build_profile_receipt(source, forged_bytes)


def test_old_curated_only_profile_cannot_gain_fallback_authority() -> None:
    source_root = LAB_ROOT / "config/curated-sources"
    # Construct the retired envelope here: the historical on-disk receipt is
    # preserved outside this prospective source and need not exist in a clone.
    old = {
        "schema_version": 1,
        "receipt_type": "qcsd-curated-rapid-profile",
        "payload_sha256": "0" * 64,
        "payload": {},
    }
    source = (source_root / "crux-73-v1.raw.json").read_bytes()
    with pytest.raises(ValueError, match="schema is unsupported"):
        rapid.validate_profile_receipt(old, source, CATALOGUE_BYTES)


def test_earlier_candidate_cannot_be_skipped_or_relabelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 12)
    facts[digests[0]] = {**facts[digests[0]], "candidate_id": candidates[1]["candidate_id"]}
    with pytest.raises(ValueError, match="candidate order"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_operational_error_and_resource_hint_do_not_admit_site(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 12)
    facts[digests[2]]["admission"]["cross_origin_resource_count"] = 0
    with pytest.raises(ValueError, match="live observed cross-origin"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )
    facts[digests[2]] = {
        "candidate_id": candidates[2]["candidate_id"],
        "domain": candidates[2]["domain"],
        "source_kind": candidates[2]["source_kind"],
        "outcome": "operational-error",
        "execution_binding": EXECUTION_BINDING,
        "admission": None,
        "root_screen": _root_screen(candidates[2]),
        "site_safety_review": _approved_review(),
    }
    with pytest.raises(ValueError, match="operational errors"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_mixed_source_or_image_terminals_cannot_enter_one_cohort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 12)
    facts[digests[4]]["execution_binding"] = {
        **EXECUTION_BINDING,
        "admission_image_digest": "sha256:" + "e" * 64,
    }
    with pytest.raises(ValueError, match="different source or image"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_incomplete_or_extended_prefix_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    digests, facts = _terminal_inputs(candidates, 13)
    with pytest.raises(ValueError, match="continues after"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )
    with pytest.raises(ValueError, match="incomplete"):
        rapid.build_cohort_receipt(
            profile, source, CATALOGUE_BYTES,
            generation="launch-10", terminal_sha256s=digests[:11],
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__,
        )


def test_rehashed_profile_or_cohort_tampering_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, profile, candidates = _fixture(monkeypatch)
    changed_profile = json.loads(json.dumps(profile))
    changed_profile["payload"]["candidates"][0]["domain"] = "wrong.example"
    changed_profile["payload_sha256"] = hashlib.sha256(
        rapid._canonical_json(changed_profile["payload"])
    ).hexdigest()
    with pytest.raises(ValueError, match="differs"):
        rapid.validate_profile_receipt(changed_profile, source, CATALOGUE_BYTES)

    digests, facts = _terminal_inputs(candidates, 12)
    cohort = rapid.build_cohort_receipt(
        profile, source, CATALOGUE_BYTES,
        generation="launch-10", terminal_sha256s=digests,
        execution_binding=EXECUTION_BINDING,
        deep_verify_terminal=facts.__getitem__,
    )
    changed_cohort = json.loads(json.dumps(cohort))
    changed_cohort["payload"]["terminal_decisions"][2]["admission"][
        "cross_origin_resource_count"
    ] = 2
    changed_cohort["payload_sha256"] = hashlib.sha256(
        rapid._canonical_json(changed_cohort["payload"])
    ).hexdigest()
    with pytest.raises(ValueError, match="differs"):
        rapid.validate_cohort_receipt(
            changed_cohort, profile, source, CATALOGUE_BYTES,
            execution_binding=EXECUTION_BINDING,
            deep_verify_terminal=facts.__getitem__
        )


def test_source_mutation_and_duplicate_json_keys_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    source, profile, _ = _fixture(monkeypatch)
    with pytest.raises(ValueError, match="registered SHA-256"):
        rapid.validate_profile_receipt(profile, source + b" ", CATALOGUE_BYTES)
    duplicate = b'[{"crUX_domain":"one.example","crUX_domain":"two.example","resources":[]}]'
    monkeypatch.setattr(rapid, "SOURCE_SHA256", hashlib.sha256(duplicate).hexdigest())
    monkeypatch.setattr(rapid, "SOURCE_CANDIDATE_COUNT", 1)
    with pytest.raises(ValueError, match="duplicate"):
        rapid.build_profile_receipt(duplicate, CATALOGUE_BYTES)


def test_checked_in_fixed_parameters_match_registered_hashes() -> None:
    rapid.validate_fixed_parameter_files(Path(__file__).resolve().parents[1])


def test_receipt_publication_is_create_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source, profile, _ = _fixture(monkeypatch)
    destination = tmp_path / "profile.json"
    rapid.write_receipt_create_only(destination, profile)
    assert json.loads(destination.read_text()) == profile
    assert rapid.validate_profile_receipt(profile, source, CATALOGUE_BYTES)
    with pytest.raises(FileExistsError):
        rapid.write_receipt_create_only(destination, profile)
