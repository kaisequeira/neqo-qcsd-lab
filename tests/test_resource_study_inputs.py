"""Resource identity, strict source parsing and Native input-shape controls."""
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab.manifest import validate_manifest


def source_file(tmp_path, rows):
    path = tmp_path / "source.json"
    path.write_bytes(inputs.canonical_json(rows))
    return path


def group(host, urls):
    return {"resource_domain": host, "resource_urls": urls}


def row(source, *groups):
    return {"crUX_domain": source, "resources": list(groups)}


def test_query_is_resource_identity_and_fragments_are_not():
    assert inputs.normalize_url("HTTPS://CDN.Example.:443/th?id=A&v=1#part") == (
        "https://cdn.example/th?id=A&v=1")
    assert inputs.normalize_url("https://cdn.example") == "https://cdn.example/"
    assert inputs.normalize_url("https://cdn.example/x?") == "https://cdn.example/x?"
    assert inputs.normalize_url("https://cdn.example/x?a=1+2%2B&b=2&a=3#part") == (
        "https://cdn.example/x?a=1+2%2B&b=2&a=3")
    assert inputs.normalize_url("https://bücher.example/x") == (
        "https://xn--bcher-kva.example/x")


@pytest.mark.parametrize("url", [
    "http://cdn.example/a", "https://user@cdn.example/a",
    "https://user:secret@cdn.example/a", "https://cdn.example:444/a",
    "https://cdn.example:/a", "https:///a", "https://bad..example/a",
    "https://cdn.example/a b", "https://cdn.example/a\n",
    "https://cdn.example\\other.example/a", "https://%63dn.example/a", None, 1,
])
def test_unsafe_or_malformed_urls_are_refused(url):
    with pytest.raises(ValueError):
        inputs.normalize_url(url)


def test_global_dedup_preserves_first_seen_order_queries_and_all_occurrences(tmp_path):
    values = [row("one.example", group("cdn.example", [
        "https://CDN.example:443/th?id=A#first", "https://cdn.example/th?id=B"])),
        row("two.example", group("cdn.example", [
            "https://cdn.example/th?id=A#second", "https://cdn.example/th?id=C"])),
        row("three.example", group("other.example", ["https://other.example/x"]))]
    candidates = inputs.load_candidates(source_file(tmp_path, values))
    assert [candidate["hostname"] for candidate in candidates] == [
        "cdn.example", "other.example"]
    candidate = candidates[0]
    assert candidate["urls"] == ["https://cdn.example/th?id=" + key for key in "ABC"]
    assert candidate["sources"] == ["one.example", "two.example"]
    assert candidate["url_count"] == 3 and candidate["eligible"] is False
    assert [record["resource_urls"] for record in candidate["source_occurrences"]] == [
        values[0]["resources"][0]["resource_urls"], values[1]["resources"][0]["resource_urls"]]
    assert [record["source_index"] for record in candidate["source_occurrences"]] == [1, 2]


def test_hostname_label_mismatch_is_refused_even_with_same_parent(tmp_path):
    path = source_file(tmp_path, [row("site.example", group(
        "a.cdn.example", ["https://b.cdn.example/x"]))])
    with pytest.raises(ValueError, match="group label"):
        inputs.load_candidates(path)


def test_repeated_occurrences_cannot_inflate_the_twenty_resource_threshold(tmp_path):
    urls = [f"https://static.fmkorea.com/{index}" for index in range(14)]
    path = source_file(tmp_path, [row("first.example", group("static.fmkorea.com", urls)),
        row("second.example", group("static.fmkorea.com", urls[:11]))])
    candidate = inputs.load_candidates(path)[0]
    assert candidate["url_count"] == 14 and not candidate["eligible"]
    assert sum(len(record["resource_urls"]) for record in candidate["source_occurrences"]) == 25


@pytest.mark.parametrize("raw", [
    b'[{"crUX_domain":"a.example","crUX_domain":"b.example","resources":[]}]',
    b'[{"crUX_domain":"a.example","resources":[],"extra":true}]',
    b'[{"crUX_domain":"a.example","resources":{}}]',
    b'[{"crUX_domain":"a.example","resources":[{"resource_domain":"cdn.example","resource_urls":"https://cdn.example/a"}]}]',
    b'[{"crUX_domain":"a.example","resources":[{"resource_domain":"cdn.example","resource_urls":[],"extra":true}]}]',
    b'[{"crUX_domain":"a.example","resources":NaN}]',
    b'[]', b'{}', b'\xff',
])
def test_strict_json_and_shape_controls(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        inputs.load_candidates(path)


def test_catalogue_binds_the_same_read_bytes_as_its_candidates(tmp_path, monkeypatch):
    first = inputs.canonical_json([row("first.example", group("cdn.example", [
        f"https://cdn.example/{index}" for index in range(20)]))])
    replacement = inputs.canonical_json([row("replacement.example")])
    path = tmp_path / "source.json"
    path.write_bytes(first)
    original = inputs._candidates

    def replacing_parse(raw):
        path.write_bytes(replacement)
        return original(raw)

    monkeypatch.setattr(inputs, "_candidates", replacing_parse)
    catalogue = inputs.candidate_catalogue(path)
    assert catalogue["source_sha256"] == hashlib.sha256(first).hexdigest()
    assert catalogue["eligible_count"] == 1
    assert inputs.sha256_file(path) == hashlib.sha256(replacement).hexdigest()
    assert catalogue["modes"] == list(inputs.MODES)
    assert catalogue["target_classes"] == 50
    assert catalogue["resources_per_session"] == 20
    assert catalogue["sessions_per_mode"] == 400
    assert catalogue["total_sessions"] == 100_000


def test_native_manifest_has_native_serde_fields_and_actual_lengths():
    urls = [f"https://cdn.example/r?id={index}" for index in range(20)]
    lengths = {url: index + 1 for index, url in enumerate(urls)}
    manifest = inputs.native_manifest("CDN.EXAMPLE", urls, lengths)
    validate_manifest(manifest)
    assert len(manifest["resources"]) == 20
    assert [resource["id"] for resource in manifest["resources"]] == list(range(20))
    assert [resource["data_length"] for resource in manifest["resources"]] == list(range(1, 21))
    assert all(resource["content_length"] == resource["data_length"]
               and resource["type"] == "Other" and resource["known_valid"] is True
               and resource["chaff_priority"] is False and resource["depends_on"] == []
               and resource["headers"] == [] for resource in manifest["resources"])
    assert json.loads(inputs.canonical_json(manifest)) == manifest


def test_unknown_lengths_and_explicit_probe_do_not_fabricate_extent():
    manifest = inputs.native_manifest("cdn.example", ["https://cdn.example/a"],
                                      require_twenty=False)
    validate_manifest(manifest)
    assert manifest["resources"][0]["content_length"] is None
    assert manifest["resources"][0]["data_length"] == 0
    with pytest.raises(ValueError, match="exactly20"):
        inputs.native_manifest("cdn.example", ["https://cdn.example/a"])
    with pytest.raises(ValueError, match="nonempty"):
        inputs.native_manifest("cdn.example", [], require_twenty=False)


def test_native_manifest_refuses_normalized_duplicates_and_other_hosts():
    urls = [f"https://cdn.example/{index}" for index in range(20)]
    with pytest.raises(ValueError, match="distinct"):
        inputs.native_manifest("cdn.example", urls[:19] + [urls[0] + "#again"])
    with pytest.raises(ValueError, match="hostname"):
        inputs.native_manifest("cdn.example", urls[:19] + ["https://other.example/x"])
    with pytest.raises(ValueError):
        inputs.native_manifest("cdn.example", urls[:19])
    with pytest.raises(ValueError):
        inputs.native_manifest("cdn.example", urls + ["https://cdn.example/20"])


@pytest.mark.parametrize("length", [-1, True, 1.5, None, 1 << 64])
def test_native_manifest_refuses_invalid_lengths(length):
    with pytest.raises(ValueError, match="u64"):
        inputs.native_manifest("cdn.example", ["https://cdn.example/a"],
                              {"https://cdn.example/a": length}, require_twenty=False)


def test_lengths_cover_exact_selected_normalized_urls():
    urls = ["https://cdn.example/a"]
    manifest = inputs.native_manifest("cdn.example", urls,
        {"https://CDN.EXAMPLE:443/a#part": 12}, require_twenty=False)
    assert manifest["resources"][0]["data_length"] == 12
    for lengths in ({}, {"https://cdn.example/b": 12},
                    {urls[0]: 12, "https://cdn.example/a#part": 12}):
        with pytest.raises(ValueError):
            inputs.native_manifest("cdn.example", urls, lengths, require_twenty=False)


def test_canonical_json_has_one_terminal_newline_and_refuses_nonfinite():
    assert inputs.canonical_json({"z": 1, "a": "é"}) == b'{"a":"\xc3\xa9","z":1}\n'
    with pytest.raises(ValueError):
        inputs.canonical_json({"value": float("nan")})


def test_supplied_source_has_fifty_distinct_url_eligible_hosts():
    configured = os.environ.get("QCSD_RESOURCE_STUDY_SOURCE")
    path = (Path(configured) if configured else
            Path(__file__).resolve().parents[3] / "url-resource-urls 1.json")
    if not path.is_file():
        pytest.skip("supplied external source is absent; set QCSD_RESOURCE_STUDY_SOURCE")
    catalogue = inputs.candidate_catalogue(path)
    assert len(catalogue["candidates"]) == 92
    assert catalogue["eligible_count"] == 50
    assert sum(candidate["url_count"] for candidate in catalogue["candidates"]) == 5018
    assert sum(len(record["resource_urls"]) for candidate in catalogue["candidates"]
               for record in candidate["source_occurrences"]) == 5507
    by_host = {candidate["hostname"]: candidate for candidate in catalogue["candidates"]}
    assert by_host["static.fmkorea.com"]["url_count"] == 14
    assert not by_host["static.fmkorea.com"]["eligible"]
    bing = by_host["www.bing.com"]
    assert bing["url_count"] == 50 and bing["eligible"]
    assert len(set(bing["urls"])) == 50
