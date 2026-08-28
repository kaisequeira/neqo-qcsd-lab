from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab.class_catalogue import (
    MAX_HTML_BODY_BYTES,
    STABILITY_PROBE_WINDOWS,
    DiscoveredLink,
    PageCandidate,
    StabilityObservation,
    TrancoEntry,
    TrancoSnapshot,
    TrancoSnapshotMetadata,
    apply_stability_eligibility,
    build_stability_receipt,
    build_tranco_snapshot_receipt,
    canonical_query_free_html_url,
    choose_first_stable_page,
    collect_stability_observations,
    derive_stability_decision,
    load_stability_receipt,
    parse_tranco_csv,
    sample_tranco_candidates,
    select_page_candidates,
    tranco_entries_sha256,
    validate_stability_receipt,
    validate_tranco_snapshot,
    validate_tranco_snapshot_receipt,
    write_stability_receipt,
    write_tranco_snapshot_receipt,
)
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    deterministic_candidate_order,
)

LIST_SHA = "a" * 64
LIST_ID = "TEST-LIST-2026-08-28"
SOURCE_URL = "https://tranco-list.eu/list/TEST/full"
BASELINE = "2026-08-01T00:00:00Z"


def _small_tranco_bytes() -> bytes:
    return b"1,alpha.example\n2,beta.example\n3,gamma.example\n"


def _sparse_snapshot() -> TrancoSnapshot:
    entries = tuple(
        TrancoEntry(stratum.minimum_rank + offset, f"s{index}-{offset:02d}.example")
        for index, stratum in enumerate(TRANCO_RANK_STRATA)
        for offset in range(CANDIDATES_PER_STRATUM)
    )
    return TrancoSnapshot(
        TrancoSnapshotMetadata(
            list_id=LIST_ID,
            list_sha256=LIST_SHA,
            source_url=SOURCE_URL,
            retrieved_at="2026-07-31T12:00:00Z",
            row_count=len(entries),
            entries_sha256=tranco_entries_sha256(entries),
        ),
        entries,
    )


def _candidate() -> ClassCandidate:
    return ClassCandidate("tranco-0000001", "www.example.co.uk", 1, False)


def _pages() -> tuple[PageCandidate, ...]:
    return select_page_candidates(
        "www.example.co.uk",
        registrable_domain="example.co.uk",
        discovered_links=(
            DiscoveredLink("https://news.example.co.uk/article", "text/html; charset=utf-8"),
        ),
    )


def _timestamp(elapsed_ms: int) -> str:
    baseline = datetime.fromisoformat(BASELINE[:-1] + "+00:00")
    value = baseline + timedelta(milliseconds=elapsed_ms)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _observations(
    page: PageCandidate,
    *,
    body_hashes: tuple[str, str, str] = ("b" * 64,) * 3,
    elapsed: tuple[int, int, int] | None = None,
    status: int = 200,
    body_bytes: int = 1234,
) -> tuple[StabilityObservation, ...]:
    elapsed_values = elapsed or tuple(window.target_ms for window in STABILITY_PROBE_WINDOWS)
    return tuple(
        StabilityObservation(
            probe_id=window.probe_id,
            observed_at=_timestamp(elapsed_ms),
            elapsed_ms=elapsed_ms,
            final_url=page.url,
            status=status,
            content_type="text/html; charset=UTF-8",
            body_bytes=body_bytes,
            body_sha256=body_hash,
            resource_graph_sha256="c" * 64,
            prepared_workload_sha256="d" * 64,
        )
        for window, elapsed_ms, body_hash in zip(
            STABILITY_PROBE_WINDOWS, elapsed_values, body_hashes, strict=True
        )
    )


def _receipt(page: PageCandidate, observations=None):
    return build_stability_receipt(
        _candidate(),
        page,
        tranco_list_id=LIST_ID,
        tranco_list_sha256=LIST_SHA,
        baseline_started_at=BASELINE,
        observations=observations or _observations(page),
    )


def test_strict_tranco_parser_binds_raw_and_parsed_hashes() -> None:
    data = _small_tranco_bytes()
    snapshot = parse_tranco_csv(
        data,
        list_id=LIST_ID,
        expected_sha256=hashlib.sha256(data).hexdigest(),
        source_url=SOURCE_URL,
        retrieved_at="2026-08-01T00:00:00Z",
        expected_rows=3,
    )
    assert snapshot.entries == (
        TrancoEntry(1, "alpha.example"),
        TrancoEntry(2, "beta.example"),
        TrancoEntry(3, "gamma.example"),
    )
    assert snapshot.metadata.entries_sha256 == tranco_entries_sha256(snapshot.entries)
    validate_tranco_snapshot(snapshot)

    receipt = build_tranco_snapshot_receipt(snapshot)
    assert validate_tranco_snapshot_receipt(receipt) == snapshot.metadata


def test_tranco_parser_hashes_official_wildcard_tokens_but_never_samples_them() -> None:
    data = b"1,_wildcard_.ph\n2,safe.example\n"
    snapshot = parse_tranco_csv(
        data,
        list_id=LIST_ID,
        expected_sha256=hashlib.sha256(data).hexdigest(),
        source_url=SOURCE_URL,
        retrieved_at="2026-08-01T00:00:00Z",
        expected_rows=2,
    )

    assert snapshot.entries[0] == TrancoEntry(1, "_wildcard_.ph")
    assert snapshot.metadata.entries_sha256 == tranco_entries_sha256(snapshot.entries)


@pytest.mark.parametrize(
    "data, message",
    [
        (b"1,alpha.example\n3,gamma.example\n", "rank 2"),
        (b"1,alpha.example,extra\n", "two columns"),
        (b"01,alpha.example\n", "rank 1"),
        (b"1,Alpha.example\n", "not canonical"),
        (b"1,alpha.example\n2,alpha.example\n", "duplicate domain"),
        (b"\xef\xbb\xbf1,alpha.example\n", "byte-order mark"),
    ],
)
def test_tranco_parser_rejects_ambiguous_or_malicious_inputs(data: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_tranco_csv(
            data,
            list_id=LIST_ID,
            expected_sha256=hashlib.sha256(data).hexdigest(),
            source_url=SOURCE_URL,
            retrieved_at="2026-08-01T00:00:00Z",
            expected_rows=max(1, data.count(b"\n")),
        )


def test_tranco_parser_rejects_wrong_pin_and_metadata() -> None:
    data = _small_tranco_bytes()
    with pytest.raises(ValueError, match="does not match"):
        parse_tranco_csv(
            data,
            list_id=LIST_ID,
            expected_sha256="0" * 64,
            source_url=SOURCE_URL,
            retrieved_at="2026-08-01T00:00:00Z",
            expected_rows=3,
        )
    with pytest.raises(ValueError, match="HTTPS"):
        parse_tranco_csv(
            data,
            list_id=LIST_ID,
            expected_sha256=hashlib.sha256(data).hexdigest(),
            source_url="http://tranco.invalid/list.csv",
            retrieved_at="2026-08-01T00:00:00Z",
            expected_rows=3,
        )


def test_candidate_sampling_is_deterministic_and_enforces_five_stratum_quotas() -> None:
    snapshot = _sparse_snapshot()
    candidates = sample_tranco_candidates(snapshot)
    assert len(candidates) == CANDIDATE_COUNT
    assert all(not candidate.eligible for candidate in candidates)
    assert {
        stratum.id: sum(candidate.stratum == stratum for candidate in candidates)
        for stratum in TRANCO_RANK_STRATA
    } == {stratum.id: CANDIDATES_PER_STRATUM for stratum in TRANCO_RANK_STRATA}
    assert candidates == deterministic_candidate_order(candidates, tranco_list_sha256=LIST_SHA)
    assert candidates == sample_tranco_candidates(snapshot)

    short = replace(
        snapshot,
        entries=snapshot.entries[:-1],
        metadata=replace(
            snapshot.metadata,
            row_count=len(snapshot.entries) - 1,
            entries_sha256=tranco_entries_sha256(snapshot.entries[:-1]),
        ),
    )
    with pytest.raises(ValueError, match=f"only {CANDIDATES_PER_STRATUM - 1}"):
        sample_tranco_candidates(short)


def test_page_selection_is_homepage_first_filtered_bounded_and_order_stable() -> None:
    links = (
        DiscoveredLink("https://blog.example.co.uk/about", "text/html"),
        DiscoveredLink("https://news.example.co.uk/story", "application/xhtml+xml"),
        DiscoveredLink("https://www.example.co.uk/contact", "text/html; charset=utf-8"),
        DiscoveredLink("https://shop.example.co.uk/products", "text/html"),
        DiscoveredLink("https://docs.example.co.uk/guide", "text/html"),
        DiscoveredLink("https://accounts.example.co.uk/welcome", "text/html"),
        DiscoveredLink("https://www.example.co.uk/search", "text/html"),
        DiscoveredLink("https://www.example.co.uk/page?tracking=1", "text/html"),
        DiscoveredLink("https://evil-example.co.uk/page", "text/html"),
        DiscoveredLink("https://www.example.co.uk/report.pdf", "text/html"),
        DiscoveredLink("https://www.example.co.uk/image", "image/png"),
        DiscoveredLink("https://blog.example.co.uk/about", "text/html"),
    )
    selected = select_page_candidates(
        "www.example.co.uk",
        registrable_domain="example.co.uk",
        discovered_links=links,
    )
    assert selected[0].url == "https://www.example.co.uk/"
    assert selected[0].source == "canonical-homepage"
    assert len(selected) == 5
    assert all(page.ordinal == index for index, page in enumerate(selected))
    assert all("search" not in page.url and "accounts" not in page.url for page in selected)
    assert selected == select_page_candidates(
        "www.example.co.uk",
        registrable_domain="example.co.uk",
        discovered_links=reversed(links),
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://www.example.co.uk/page",
        "https://www.example.co.uk/page?q=1",
        "https://www.example.co.uk/page#fragment",
        "https://user:pass@www.example.co.uk/page",
        "https://www.example.co.uk:443/page",
        "https://www.example.co.uk/%2e%2e/account",
        "https://127.0.0.1/page",
        "https://example.co.uk.evil.example/page",
    ],
)
def test_page_url_validation_fails_closed(url: str) -> None:
    with pytest.raises(ValueError):
        canonical_query_free_html_url(url, registrable_domain="example.co.uk")


def test_stability_receipt_accepts_exact_three_probe_match() -> None:
    page = _pages()[0]
    observations = _observations(page)
    decision = derive_stability_decision(
        page,
        baseline_started_at=BASELINE,
        observations=observations,
    )
    assert decision.eligible
    assert decision.reasons == ()
    assert decision.stable_values == {
        "final_url": page.url,
        "status": 200,
        "content_type": "text/html",
        "body_bytes": 1234,
        "body_sha256": "b" * 64,
        "resource_graph_sha256": "c" * 64,
        "prepared_workload_sha256": "d" * 64,
    }
    receipt = _receipt(page, observations)
    assert validate_stability_receipt(receipt) == decision


def test_stability_rejects_timing_drift_and_every_bound_resource_drift() -> None:
    page = _pages()[0]
    drifted = _observations(
        page,
        body_hashes=("b" * 64, "e" * 64, "b" * 64),
        elapsed=(40_000, 86_400_000, 259_200_000),
    )
    decision = derive_stability_decision(
        page,
        baseline_started_at=BASELINE,
        observations=drifted,
    )
    assert not decision.eligible
    assert "t+30s-outside-schedule-window" in decision.reasons
    assert "body-sha256-drift" in decision.reasons
    assert decision.stable_values is None
    receipt = _receipt(page, drifted)
    assert not validate_stability_receipt(receipt).eligible

    resource_drift = list(_observations(page))
    resource_drift[2] = replace(resource_drift[2], resource_graph_sha256="f" * 64)
    assert "resource-graph-sha256-drift" in derive_stability_decision(
        page, baseline_started_at=BASELINE, observations=resource_drift
    ).reasons

    workload_evidence_drift = list(_observations(page))
    workload_evidence_drift[1] = replace(
        workload_evidence_drift[1], prepared_workload_sha256="f" * 64
    )
    workload_decision = derive_stability_decision(
        page,
        baseline_started_at=BASELINE,
        observations=workload_evidence_drift,
    )
    assert workload_decision.eligible
    assert workload_decision.stable_values["prepared_workload_sha256"] == "d" * 64


def test_stability_rejects_failed_or_oversized_acquisition() -> None:
    page = _pages()[0]
    failed = derive_stability_decision(
        page,
        baseline_started_at=BASELINE,
        observations=_observations(page, status=503, body_bytes=MAX_HTML_BODY_BYTES + 1),
    )
    assert not failed.eligible
    assert all(
        f"{window.probe_id}-status-not-200" in failed.reasons
        for window in STABILITY_PROBE_WINDOWS
    )
    assert all(
        f"{window.probe_id}-body-over-1mib" in failed.reasons
        for window in STABILITY_PROBE_WINDOWS
    )

    redirected = tuple(
        replace(observation, final_url="https://www.example.co.uk/login")
        for observation in _observations(page)
    )
    decision = derive_stability_decision(
        page, baseline_started_at=BASELINE, observations=redirected
    )
    assert all(
        f"{window.probe_id}-forbidden-final-page" in decision.reasons
        for window in STABILITY_PROBE_WINDOWS
    )


def test_receipt_semantics_cannot_be_bypassed_by_rehashing() -> None:
    page = _pages()[0]
    receipt = _receipt(page)
    payload = json.loads(json.dumps(receipt["payload"]))
    payload["decision"]["eligible"] = False
    forged = bind_receipt(payload, receipt_type=receipt["receipt_type"])
    with pytest.raises(ValueError, match="independently derived"):
        validate_stability_receipt(forged)

    payload = json.loads(json.dumps(receipt["payload"]))
    payload["probe_schedule"][0]["latest_ms"] += 1
    forged = bind_receipt(payload, receipt_type=receipt["receipt_type"])
    with pytest.raises(ValueError, match="probe schedule"):
        validate_stability_receipt(forged)


def test_injected_probe_callback_receives_only_the_fixed_schedule() -> None:
    page = _pages()[0]
    called = []

    def probe(observed_page, window):
        called.append((observed_page, window))
        return next(
            observation
            for observation in _observations(page)
            if observation.probe_id == window.probe_id
        )

    observations = collect_stability_observations(page, probe=probe)
    assert tuple(window for _, window in called) == STABILITY_PROBE_WINDOWS
    assert len(observations) == 3


def test_first_stable_page_selection_and_candidate_eligibility_are_exact() -> None:
    candidate = _candidate()
    pages = _pages()
    failed = _receipt(pages[0], _observations(pages[0], status=503))
    passed = _receipt(pages[1])
    receipts = {pages[0].url: failed, pages[1].url: passed}
    assert choose_first_stable_page(candidate, pages, receipts) == pages[1]
    eligible, selected = apply_stability_eligibility(candidate, pages, receipts)
    assert eligible.eligible
    assert selected == pages[1]

    ineligible, selected = apply_stability_eligibility(candidate, pages, {})
    assert not ineligible.eligible
    assert selected is None


def test_receipts_are_create_only_and_load_revalidates(tmp_path: Path) -> None:
    page = _pages()[0]
    stability = _receipt(page)
    stability_path = tmp_path / "stability.json"
    assert write_stability_receipt(stability_path, stability) == stability_path
    loaded, decision = load_stability_receipt(stability_path)
    assert loaded == stability
    assert decision.eligible
    original = stability_path.read_bytes()
    with pytest.raises(FileExistsError, match="create-only"):
        write_stability_receipt(stability_path, stability)
    assert stability_path.read_bytes() == original

    tranco = build_tranco_snapshot_receipt(_sparse_snapshot())
    tranco_path = tmp_path / "tranco.json"
    assert write_tranco_snapshot_receipt(tranco_path, tranco) == tranco_path
    with pytest.raises(FileExistsError, match="create-only"):
        write_tranco_snapshot_receipt(tranco_path, tranco)
