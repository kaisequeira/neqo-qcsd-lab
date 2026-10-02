"""Deterministic checks for the prospective exact-page H3 screen."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from qcsd_lab import h3_prebaseline as h3
from qcsd_lab.class_catalogue import DiscoveredLink, select_page_candidates
from qcsd_lab.class_study import bind_receipt
from qcsd_lab.util import sha256_bytes


def _attempt(url: str, outcome: str, sequence: int) -> dict:
    started = datetime(2026, 10, 1, tzinfo=UTC) + timedelta(seconds=2 * sequence)
    if outcome == "known-valid":
        output = json.dumps(
            {
                "resources": [{
                    "id": 0, "url": url, "type": "Unknown",
                    "content_length": 1, "data_length": 1,
                    "chaff_priority": False, "known_valid": True,
                    "depends_on": [], "headers": [],
                }],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        code, stdout, valid = 0, "", True
    elif outcome in {"timeout", "idle-timeout", "peer-tls-handshake-failure"}:
        output = None
        stdout = (
            "Error: Timeout(12)" if outcome == "timeout"
            else "Error: Transport(IdleTimeout)" if outcome == "idle-timeout"
            else h3.PREBASELINE_H3_SCREEN_V3_CONTRACT["peer_tls_handshake_failure_stdout"]
        )
        code, valid = 1, None
    elif outcome == "ambiguous":
        output = None
        code, stdout, valid = 1, "Error: Other", None
    else:
        raise AssertionError(outcome)
    return {
        "url": url,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": (started + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "resolver_addresses": ["1.1.1.1"],
        "resolver_error": None,
        "exit_code": code,
        "stdout_sha256": sha256_bytes(stdout.encode()),
        "stdout_excerpt": stdout,
        "output_sha256": sha256_bytes(output.encode()) if output is not None else None,
        "output_text": output,
        "known_valid": valid,
        "outcome": outcome,
    }


def _selected_pages(link_urls: tuple[str, ...] = ("https://example.com/guide",)):
    links = [{"url": url, "content_type": "text/html"} for url in link_urls]
    pages = select_page_candidates(
        "example.com",
        registrable_domain="example.com",
        discovered_links=tuple(DiscoveredLink(**link) for link in links),
    )
    selected = [
        {"url": page.url, "request_origin": h3._origin(page.url)} for page in pages
    ]
    return selected, links


def _receipt(
    page_outcomes: tuple[tuple[str, str], ...],
    *,
    before: str = "known-valid",
    after: str | None = "known-valid",
    link_urls: tuple[str, ...] = ("https://example.com/guide",),
    screen_version: int = 2,
) -> dict:
    selected, links = _selected_pages(link_urls)
    assert len(page_outcomes) == len(selected)
    control_url = h3.PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"]
    page_attempts = []
    if before == "known-valid":
        for page_index, (page, outcomes) in enumerate(zip(selected, page_outcomes)):
            page_attempts.append({
                "url": page["url"],
                "attempts": [
                    _attempt(page["url"], outcome, 1 + 2 * page_index + index)
                    for index, outcome in enumerate(outcomes)
                ],
            })
    builder = (
        h3.build_h3_screen_receipt_v3
        if screen_version == 3 else h3.build_h3_screen_receipt_v2
    )
    return builder(
        candidate_id="tranco-0000001",
        domain="example.com",
        selected_pages=selected,
        navigation_links=links,
        control_before=_attempt(control_url, before, 0),
        page_attempts=page_attempts,
        control_after=(
            _attempt(control_url, after, 1 + 2 * len(page_outcomes))
            if before == "known-valid" and after is not None else None
        ),
        image_digest="sha256:" + "1" * 64,
        source={"lab_commit": "test"},
    )


def _rebind(receipt: dict, mutation) -> dict:
    payload = deepcopy(receipt["payload"])
    mutation(payload)
    return bind_receipt(payload, receipt_type=h3.H3_SCREEN_RECEIPT_TYPE)


def test_v2_passes_with_one_exact_page_pair_and_retains_all_selected_pages():
    receipt = _receipt((("timeout", "idle-timeout"), ("known-valid", "known-valid")))
    payload = h3.validate_h3_screen_receipt(receipt)

    assert payload["screen_schema_version"] == 2
    assert payload["decision"] == "pass"
    assert len(payload["page_attempts"]) == len(payload["selected_pages"]) == 2
    assert [item["url"] for item in payload["page_attempts"]] == [
        page["url"] for page in payload["selected_pages"]
    ]
    assert payload["page_attempts"][1]["url"] == "https://example.com/guide"


@pytest.mark.parametrize(
    ("page_outcomes", "expected"),
    [
        ((("timeout", "idle-timeout"), ("idle-timeout", "timeout")), "site-rejection"),
        ((("timeout", "idle-timeout"), ("known-valid", "timeout")), "blocked"),
        ((("ambiguous", "idle-timeout"), ("timeout", "timeout")), "blocked"),
        ((("known-valid", "known-valid"), ("ambiguous", "timeout")), "pass"),
    ],
)
def test_v2_decision_uses_exact_page_pairs(page_outcomes, expected):
    assert h3.validate_h3_screen_receipt(_receipt(page_outcomes))["decision"] == expected


def test_v3_exact_peer_tls_failure_rejects_only_with_full_healthy_bracket():
    failures = (("peer-tls-handshake-failure", "peer-tls-handshake-failure"),
                ("timeout", "idle-timeout"))
    receipt = _receipt(failures, screen_version=3)
    payload = h3.validate_h3_screen_receipt(receipt)
    assert payload["screen_schema_version"] == 3
    assert payload["contract"] == h3.PREBASELINE_H3_SCREEN_V3_CONTRACT
    assert payload["decision"] == "site-rejection"
    assert h3.validate_h3_screen_receipt(
        _receipt(failures, screen_version=3, after="ambiguous")
    )["decision"] == "blocked"
    assert h3.validate_h3_screen_receipt(
        _receipt(failures, screen_version=3, before="ambiguous", after=None)
    )["decision"] == "blocked"


def test_v3_peer_tls_failure_near_misses_remain_ambiguous_and_tampering_fails():
    exact = h3.PREBASELINE_H3_SCREEN_V3_CONTRACT["peer_tls_handshake_failure_stdout"]
    assert h3._CLASSIFIED_ERRORS.get(exact) == "peer-tls-handshake-failure"
    assert h3._CLASSIFIED_ERRORS.get(exact.replace("Peer(296)", "Peer(297)")) is None
    assert h3._CLASSIFIED_ERRORS.get(exact.replace("RunAborted", "Transport")) is None
    receipt = _receipt((("peer-tls-handshake-failure", "peer-tls-handshake-failure"),
                        ("peer-tls-handshake-failure", "peer-tls-handshake-failure")),
                       screen_version=3)

    def change(payload):
        attempt = payload["page_attempts"][0]["attempts"][0]
        attempt["stdout_excerpt"] = attempt["stdout_excerpt"].replace("Peer(296)", "Peer(297)")
        attempt["stdout_sha256"] = sha256_bytes(attempt["stdout_excerpt"].encode())

    with pytest.raises(ValueError, match="classification is inconsistent"):
        h3.validate_h3_screen_receipt(_rebind(receipt, change))


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (h3.PREBASELINE_H3_SCREEN_V3_CONTRACT["peer_tls_handshake_failure_stdout"],
         "peer-tls-handshake-failure"),
        (h3.PREBASELINE_H3_SCREEN_V3_CONTRACT["peer_tls_handshake_failure_stdout"].replace(
            "Peer(296)", "Peer(297)"), "ambiguous"),
        ("Error: Transport(Peer(296))", "ambiguous"),
    ],
)
def test_v3_producer_classifies_only_exact_peer_tls_failure(monkeypatch, stdout, expected):
    monkeypatch.setattr(h3, "_resolver_addresses", lambda _url: (["1.1.1.1"], None))
    monkeypatch.setattr(h3, "capture_scheduler_launch_prefix", lambda: [])
    monkeypatch.setattr(
        h3, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=stdout)
    )
    attempt = h3._run_one("https://example.com/")
    assert attempt["outcome"] == expected
    assert attempt["stdout_sha256"] == sha256_bytes(stdout.encode())


def test_v2_peer_tls_failure_does_not_gain_v3_authority():
    receipt = _receipt((("timeout", "timeout"), ("timeout", "timeout")))

    def change(payload):
        attempt = payload["page_attempts"][0]["attempts"][0]
        attempt["outcome"] = "peer-tls-handshake-failure"
        attempt["stdout_excerpt"] = (
            h3.PREBASELINE_H3_SCREEN_V3_CONTRACT["peer_tls_handshake_failure_stdout"]
        )
        attempt["stdout_sha256"] = sha256_bytes(attempt["stdout_excerpt"].encode())

    with pytest.raises(ValueError, match="probe attempt is invalid"):
        h3.validate_h3_screen_receipt(_rebind(receipt, change))
    assert h3.validate_h3_screen_receipt(receipt)["screen_schema_version"] == 2


def test_v2_failed_control_skips_pages_and_later_control():
    receipt = _receipt((("timeout", "timeout"), ("timeout", "timeout")), before="ambiguous", after=None)
    payload = h3.validate_h3_screen_receipt(receipt)
    assert payload["decision"] == "blocked"
    assert payload["page_attempts"] == []
    assert payload["control_after"] is None


def test_v2_failed_later_control_blocks_even_when_page_passes():
    receipt = _receipt((("known-valid", "known-valid"), ("timeout", "timeout")), after="ambiguous")
    assert h3.validate_h3_screen_receipt(receipt)["decision"] == "blocked"


def test_production_screen_probes_exact_urls_twice_in_order(monkeypatch):
    selected, links = _selected_pages()
    control_url = h3.PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"]
    calls = []

    def fake_run_one(url):
        calls.append(url)
        return _attempt(url, "known-valid", len(calls) - 1)

    monkeypatch.setattr(h3, "_run_one", fake_run_one)
    monkeypatch.setattr(h3, "source_metadata", lambda: {"lab_commit": "test"})
    receipt = h3.screen_prebaseline_h3(
        candidate_id="tranco-0000001", domain="example.com",
        selected_pages=selected, navigation_links=links,
    )

    assert calls == [
        control_url,
        selected[0]["url"], selected[0]["url"],
        selected[1]["url"], selected[1]["url"],
        control_url,
    ]
    assert h3.validate_h3_screen_receipt(receipt)["decision"] == "pass"


@pytest.mark.parametrize(
    ("outcome", "expected_error"),
    [("timeout", h3.H3SiteUnavailable), ("ambiguous", h3.H3ScreenBlocked)],
)
def test_production_screen_classifies_unavailable_and_ambiguous_pages(
    monkeypatch, outcome, expected_error
):
    selected, links = _selected_pages(())
    control_url = h3.PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"]
    calls = []

    def fake_run_one(url):
        calls.append(url)
        return _attempt(url, "known-valid" if url == control_url else outcome, len(calls) - 1)

    monkeypatch.setattr(h3, "_run_one", fake_run_one)
    monkeypatch.setattr(h3, "source_metadata", lambda: {"lab_commit": "test"})
    with pytest.raises(expected_error) as error:
        h3.screen_prebaseline_h3(
            candidate_id="tranco-0000001", domain="example.com",
            selected_pages=selected, navigation_links=links,
        )
    assert h3.validate_h3_screen_receipt(error.value.receipt)["decision"] == (
        "site-rejection" if outcome == "timeout" else "blocked"
    )
    if outcome == "timeout":
        assert str(error.value) == h3.H3_SITE_V2_REASON


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("forged-decision", "decision differs"),
        ("wrong-page-url", "page attempt order differs"),
        ("reversed-pages", "page attempt order differs"),
        ("missing-attempt", "two attempts per selected page"),
        ("missing-page", "omitted a selected page"),
        ("wrong-probe-url", "probe attempt is invalid"),
        ("tampered-output", "output proof differs"),
        ("time-overlap", "out of order"),
        ("wrong-contract", "identity differs"),
        ("extra-field", "fields differ"),
    ],
)
def test_v2_rejects_rehashed_tampering(mutation, message):
    receipt = _receipt((("known-valid", "known-valid"), ("timeout", "timeout")))

    def change(payload):
        pages = payload["page_attempts"]
        if mutation == "forged-decision":
            payload["decision"] = "site-rejection"
        elif mutation == "wrong-page-url":
            pages[1]["url"] = "https://example.com/"
        elif mutation == "reversed-pages":
            pages.reverse()
        elif mutation == "missing-attempt":
            pages[0]["attempts"].pop()
        elif mutation == "missing-page":
            pages.pop()
        elif mutation == "wrong-probe-url":
            pages[0]["attempts"][0]["url"] = "https://example.com/other"
        elif mutation == "tampered-output":
            pages[0]["attempts"][0]["output_text"] += " "
        elif mutation == "time-overlap":
            pages[0]["attempts"][0]["started_at"] = "2026-09-30T23:59:59Z"
        elif mutation == "wrong-contract":
            payload["contract"]["policy"] = "other"
        else:
            payload["scientific_credit"] = True

    with pytest.raises(ValueError, match=message):
        h3.validate_h3_screen_receipt(_rebind(receipt, change))


def test_v2_rejects_more_than_five_selected_pages_before_network(monkeypatch):
    links = tuple(f"https://example.com/page-{index}" for index in range(5))
    selected, navigation = _selected_pages(links)
    assert len(selected) == 5
    selected.append({"url": "https://example.com/extra", "request_origin": "https://example.com"})
    control_url = h3.PREBASELINE_H3_SCREEN_V2_CONTRACT["control_url"]
    monkeypatch.setattr(h3, "_run_one", lambda _url: pytest.fail("unexpected network probe"))
    with pytest.raises(ValueError, match="selected page ledger"):
        h3.screen_prebaseline_h3(
            candidate_id="tranco-0000001", domain="example.com",
            selected_pages=selected, navigation_links=navigation,
        )
    with pytest.raises(ValueError, match="selected page ledger"):
        h3.build_h3_screen_receipt_v2(
            candidate_id="tranco-0000001", domain="example.com",
            selected_pages=selected, navigation_links=navigation,
            control_before=_attempt(control_url, "ambiguous", 0),
            page_attempts=[], control_after=None,
            image_digest="sha256:" + "1" * 64, source={"lab_commit": "test"},
        )


def test_historical_v1_receipt_validates_without_schema_conversion():
    selected, links = _selected_pages(())
    control_url = h3.PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    receipt = h3.build_h3_screen_receipt(
        candidate_id="tranco-0000001", domain="example.com",
        selected_pages=selected, navigation_links=links,
        control_before=_attempt(control_url, "known-valid", 0),
        origin_attempts=[{
            "origin": "https://example.com",
            "attempts": [
                _attempt("https://example.com/", "known-valid", 1),
                _attempt("https://example.com/", "known-valid", 2),
            ],
        }],
        control_after=_attempt(control_url, "known-valid", 3),
        image_digest="sha256:" + "1" * 64, source={"lab_commit": "test"},
    )
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    decoded = json.loads(encoded)
    payload = h3.validate_h3_screen_receipt(decoded)

    assert payload["screen_schema_version"] == 1
    assert payload["contract"] == h3.PREBASELINE_H3_SCREEN_CONTRACT
    assert json.dumps(decoded, sort_keys=True, separators=(",", ":")) == encoded
