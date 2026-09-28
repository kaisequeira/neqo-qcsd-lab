from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab.class_curated_source import (
    build_curated_source_receipt,
    import_curated_source,
    load_curated_source_receipt,
    validate_curated_source_receipt,
)
from qcsd_lab.class_study import bind_receipt


def _source() -> bytes:
    return json.dumps(
        [
            {
                "crUX_domain": "one.example",
                "resources": [
                    {
                        "resource_domain": "cdn.one.example",
                        "resource_urls": [
                            "https://cdn.one.example/a.js?version=1",
                            "https://cdn.one.example/a.js?version=1",
                        ],
                    }
                ],
            },
            {"crUX_domain": "bookmark.xxx", "resources": []},
        ]
    ).encode()


def test_import_preserves_domain_order_and_records_hints_without_resource_urls() -> None:
    raw = _source()
    receipt = build_curated_source_receipt(raw)
    payload = receipt["payload"]

    assert validate_curated_source_receipt(receipt, source_bytes=raw) == (
        "one.example",
        "bookmark.xxx",
    )
    assert payload["candidate_count"] == 2
    assert payload["source_byte_count"] == len(raw)
    assert payload["observed_resource_url_count"] == 2
    assert payload["candidates"][0]["origin_hints"][0]["url_count"] == 2
    assert payload["pre_browser_safety_matches"] == [
        {"domain": "bookmark.xxx", "reason": "domain-safety-policy-rejected:xxx"}
    ]
    assert b"a.js" not in json.dumps(receipt).encode()
    assert all(
        "eligible" not in candidate and "rank" not in candidate
        for candidate in payload["candidates"]
    )


def test_create_only_receipt_and_exact_source_binding(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    destination = tmp_path / "receipt.json"
    source.write_bytes(_source())

    summary = import_curated_source(source, destination)
    receipt, domains = load_curated_source_receipt(destination, source_path=source)
    assert domains == ("one.example", "bookmark.xxx")
    assert summary["receipt_sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert summary["pre_browser_safety_match_count"] == 1
    assert receipt == build_curated_source_receipt(source.read_bytes())
    with pytest.raises(FileExistsError, match="create-only"):
        import_curated_source(source, destination)

    source.write_bytes(_source().replace(b"version=1", b"version=2"))
    with pytest.raises(ValueError, match="exact source bytes"):
        load_curated_source_receipt(destination, source_path=source)


def test_rejects_duplicate_fields_domains_and_resource_origins() -> None:
    with pytest.raises(ValueError, match="repeats JSON field"):
        build_curated_source_receipt(
            b'[{"crUX_domain":"one.example","crUX_domain":"two.example","resources":[]}]'
        )
    with pytest.raises(ValueError, match="repeats domain"):
        build_curated_source_receipt(
            b'[{"crUX_domain":"one.example","resources":[]},'
            b'{"crUX_domain":"one.example","resources":[]}]'
        )
    with pytest.raises(ValueError, match="repeats resource origin"):
        build_curated_source_receipt(
            b'[{"crUX_domain":"one.example","resources":['
            b'{"resource_domain":"cdn.one.example","resource_urls":[]},'
            b'{"resource_domain":"cdn.one.example","resource_urls":[]}]}]'
        )


def test_canonicalizes_source_domains_and_rejects_alias_duplicates() -> None:
    raw = json.dumps(
        [{"crUX_domain": "ONE.EXAMPLE.", "resources": [
            {"resource_domain": "CDN.ONE.EXAMPLE.",
             "resource_urls": ["https://cdn.one.example/a"]}
        ]}]
    ).encode()
    receipt = build_curated_source_receipt(raw)
    assert validate_curated_source_receipt(receipt) == ("one.example",)
    assert receipt["payload"]["candidates"][0]["origin_hints"][0]["origin"] == (
        "https://cdn.one.example"
    )

    duplicate = b'[{"crUX_domain":"ONE.EXAMPLE.","resources":[]},' \
        b'{"crUX_domain":"one.example","resources":[]}]'
    with pytest.raises(ValueError, match="repeats domain"):
        build_curated_source_receipt(duplicate)


@pytest.mark.parametrize(
    "url, message",
    [
        ("http://cdn.one.example/a", "default-port HTTPS"),
        ("https://user@cdn.one.example/a", "default-port HTTPS"),
        ("https://cdn.one.example:8443/a", "default-port HTTPS"),
        ("https://cdn.one.example/a#fragment", "default-port HTTPS"),
        ("https://other.example/a", "differs from its group"),
    ],
)
def test_rejects_invalid_or_misgrouped_resource_url(url: str, message: str) -> None:
    raw = json.dumps(
        [{"crUX_domain": "one.example", "resources": [
            {"resource_domain": "cdn.one.example", "resource_urls": [url]}
        ]}]
    ).encode()
    with pytest.raises(ValueError, match=message):
        build_curated_source_receipt(raw)


def test_rebind_cannot_hide_receipt_identity_or_safety_tampering() -> None:
    receipt = build_curated_source_receipt(_source())
    payload = copy.deepcopy(receipt["payload"])
    payload["candidates"][0]["candidate_id"] = "curated-wrong"
    tampered = bind_receipt(payload, receipt_type=receipt["receipt_type"])
    with pytest.raises(ValueError, match="candidate identity"):
        validate_curated_source_receipt(tampered)

    payload = copy.deepcopy(receipt["payload"])
    payload["pre_browser_safety_matches"] = []
    tampered = bind_receipt(payload, receipt_type=receipt["receipt_type"])
    with pytest.raises(ValueError, match="safety matches"):
        validate_curated_source_receipt(tampered)


def test_rejects_oversized_input_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import qcsd_lab.class_curated_source as curated

    monkeypatch.setattr(curated, "MAX_SOURCE_BYTES", 10)
    with pytest.raises(ValueError, match="bounded raw bytes"):
        build_curated_source_receipt(_source())

    source = tmp_path / "oversized.json"
    source.write_bytes(_source())
    with pytest.raises(ValueError, match="parser limit"):
        import_curated_source(source, tmp_path / "receipt.json")
    assert not (tmp_path / "receipt.json").exists()


def test_rejects_excess_resource_urls_and_long_url(monkeypatch: pytest.MonkeyPatch) -> None:
    import qcsd_lab.class_curated_source as curated

    monkeypatch.setattr(curated, "MAX_RESOURCE_URLS_PER_DOMAIN", 1)
    with pytest.raises(ValueError, match="URL parser limit"):
        build_curated_source_receipt(_source())

    monkeypatch.setattr(curated, "MAX_RESOURCE_URLS_PER_DOMAIN", 50_000)
    monkeypatch.setattr(curated, "MAX_RESOURCE_URL_BYTES", 10)
    with pytest.raises(ValueError, match="parser length limit"):
        build_curated_source_receipt(_source())


def test_source_file_symlink_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(_source())
    link = tmp_path / "source-link.json"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="not a regular file"):
        import_curated_source(link, tmp_path / "receipt.json")
