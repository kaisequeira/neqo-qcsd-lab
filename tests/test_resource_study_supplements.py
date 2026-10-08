"""Reserve inventory parsing/provenance controls, without network admission."""
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_supplements as supplements


def inventory(tmp_path, name, rows):
    path = tmp_path / name
    raw = inputs.canonical_json({"urls": rows, "historical_metadata": "preserved by full file SHA"})
    path.write_bytes(raw)
    path.chmod(0o444)
    return path


def rows(hostname, count, *, status=200):
    return [{"url": f"https://{hostname}/resource?id={index}", "status": status,
             "protocol": "historical-h3", "body_bytes": index + 1} for index in range(count)]


def test_reserve_pools_keep_exact_host_order_and_twenty_distinct_threshold(tmp_path):
    first = inventory(tmp_path, "first.json", rows("cdn.myanimelist.net", 19))
    second = inventory(tmp_path, "second.json", rows("ahrefs.com", 21))
    value = supplements.load_inventory_candidates([first, second])
    assert [candidate["hostname"] for candidate in value["candidates"]] == [
        "cdn.myanimelist.net", "ahrefs.com"]
    assert [candidate["url_count"] for candidate in value["candidates"]] == [19, 21]
    assert [candidate["eligible"] for candidate in value["candidates"]] == [False, True]
    assert value["eligible_count"] == 1
    assert value["scientific_credit"] is False and value["opt_in_required"] is True
    assert value["resources_per_session"] == 20
    assert not value["excluded_records"]


def test_across_file_dedup_preserves_queries_duplicates_and_original_records(tmp_path):
    first_rows = [{"url": "https://CDN.Example.:443/th?id=A#old", "status": 404},
                  {"url": "https://cdn.example/th?id=B", "status": 200}]
    second_rows = [{"url": "https://cdn.example/th?id=A#other", "status": 200},
                   {"url": "https://cdn.example/th?id=C&x=1+2%2B&a=2&a=1", "status": 500}]
    first = inventory(tmp_path, "first.json", first_rows)
    second = inventory(tmp_path, "second.json", second_rows)
    value = supplements.load_inventory_candidates([first, second])
    candidate, = value["candidates"]
    assert candidate["urls"] == ["https://cdn.example/th?id=A", "https://cdn.example/th?id=B",
        "https://cdn.example/th?id=C&x=1+2%2B&a=2&a=1"]
    assert candidate["sources"] == [str(first), str(second)]
    assert [row["record"] for row in candidate["source_occurrences"]] == first_rows + second_rows
    assert [(row["inventory_index"], row["record_index"]) for row in candidate["source_occurrences"]] == [
        (1, 1), (1, 2), (2, 1), (2, 2)]
    assert [row["record"]["status"] for row in candidate["source_occurrences"]] == [404, 200, 200, 500]
    assert candidate["url_count"] == 3 and candidate["eligible"] is False


def test_separate_origins_remain_separate_classes_and_invalid_urls_are_accounted(tmp_path):
    records = [{"url": "https://one.cdn.example/a"}, {"url": "https://two.cdn.example/a"},
               {"url": "http://one.cdn.example/b"}, {"url": "https://one.cdn.example:444/b"},
               {"url": "https://user@one.cdn.example/b"}, {"url": None}]
    source = inventory(tmp_path, "origins.json", records)
    value = supplements.load_inventory_candidates([source])
    assert [candidate["hostname"] for candidate in value["candidates"]] == [
        "one.cdn.example", "two.cdn.example"]
    assert [row["record"] for row in value["excluded_records"]] == records[2:]
    assert all(row["reason"] for row in value["excluded_records"])
    assert len(value["excluded_records"]) == 4


def test_repeated_occurrences_do_not_raise_structural_eligibility(tmp_path):
    source = inventory(tmp_path, "duplicate.json", rows("cdn.example", 10) * 3)
    value = supplements.load_inventory_candidates([source])
    candidate, = value["candidates"]
    assert candidate["url_count"] == 10 and not candidate["eligible"]
    assert len(candidate["source_occurrences"]) == 30


def test_historical_status_cannot_admit_or_select_resources(tmp_path):
    source = inventory(tmp_path, "historical.json", rows("cdn.example", 20, status=404))
    value = supplements.load_inventory_candidates([source])
    candidate, = value["candidates"]
    assert candidate["eligible"] is True
    assert len(candidate["urls"]) == 20
    assert all(row["record"]["status"] == 404 for row in candidate["source_occurrences"])
    assert value["scientific_credit"] is False
    assert "admitted" not in candidate and "verified" not in candidate


@pytest.mark.parametrize("mode", [0o444, 0o600, 0o644])
def test_full_original_file_sha_mode_and_size_bound_to_every_occurrence(tmp_path, mode):
    path = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    path.chmod(mode)
    raw = path.read_bytes()
    value = supplements.load_inventory_candidates([path])
    ref, = value["inventory_files"]
    assert ref == {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                   "mode": f"{mode:04o}", "size": len(raw), "record_count": 20}
    assert all(row["inventory"] == ref for row in value["candidates"][0]["source_occurrences"])
    assert path.read_bytes() == raw and (path.stat().st_mode & 0o7777) == mode


def test_metadata_changes_change_full_provenance_digest_without_changing_url_pool(tmp_path):
    path = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    first = supplements.load_inventory_candidates([path])
    path.chmod(0o644)
    payload = json.loads(path.read_bytes())
    payload["historical_metadata"] = "changed old receipt label"
    path.write_bytes(inputs.canonical_json(payload))
    second = supplements.load_inventory_candidates([path])
    assert first["candidates"][0]["urls"] == second["candidates"][0]["urls"]
    assert first["inventory_files"][0]["sha256"] != second["inventory_files"][0]["sha256"]


@pytest.mark.parametrize("raw", [
    b'[]', b'{}', b'{"urls":{}}', b'{"urls":["https://cdn.example/a"]}',
    b'{"urls":[{}]}', b'{"urls":[{"url":"https://cdn.example/a","url":"https://cdn.example/b"}]}',
    b'{"urls":[],"urls":[]}', b'{"urls":[],"elapsed":NaN}', b'\xff', b'bad',
])
def test_malformed_inventory_is_refused(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        supplements.load_inventory_candidates([path])


@pytest.mark.parametrize("paths", [[], None, "one.json", Path("one.json"), [None]])
def test_explicit_path_collection_required(paths):
    with pytest.raises(ValueError):
        supplements.load_inventory_candidates(paths)


def test_missing_inventory_refused(tmp_path):
    with pytest.raises(FileNotFoundError):
        supplements.load_inventory_candidates([tmp_path / "absent.json"])


def test_duplicate_file_cannot_repeat_inventory_authority(tmp_path):
    path = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    with pytest.raises(ValueError, match="supplied twice"):
        supplements.load_inventory_candidates([path, path])


@pytest.mark.parametrize("kind", ["symlink", "linked-parent", "hardlink", "directory", "parent-traversal"])
def test_linked_or_nonregular_paths_refused(tmp_path, kind):
    source = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    path = tmp_path / "alias"
    if kind == "symlink":
        path.symlink_to(source)
    elif kind == "linked-parent":
        path.symlink_to(tmp_path, target_is_directory=True)
        path = path / "raw.json"
    elif kind == "hardlink":
        os.link(source, path)
    elif kind == "directory":
        path.mkdir()
    else:
        child = tmp_path / "child"
        child.mkdir()
        path = child / ".." / "raw.json"
    with pytest.raises(ValueError):
        supplements.load_inventory_candidates([path])


def test_file_changed_during_read_is_refused(tmp_path, monkeypatch):
    source = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    original = supplements._stamp
    calls = 0
    def changed_after_read(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            source.chmod(0o600)
        return original(path)
    monkeypatch.setattr(supplements, "_stamp", changed_after_read)
    with pytest.raises(ValueError, match="changed while reading"):
        supplements.load_inventory_candidates([source])


def test_final_fence_refuses_inventory_change_during_normalization(tmp_path, monkeypatch):
    source = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    original = inputs.normalize_url
    changed = False
    def changing_normalizer(url):
        nonlocal changed
        if not changed:
            source.chmod(0o600)
            source.write_bytes(inputs.canonical_json({"urls": rows("other.example", 20)}))
            changed = True
        return original(url)
    monkeypatch.setattr(inputs, "normalize_url", changing_normalizer)
    with pytest.raises(ValueError, match="changed while building"):
        supplements.load_inventory_candidates([source])


def test_empty_native_inventory_is_a_zero_eligible_catalogue(tmp_path):
    path = inventory(tmp_path, "empty.json", [])
    value = supplements.load_inventory_candidates([path])
    assert value["candidates"] == [] and value["eligible_count"] == 0
    assert value["inventory_files"][0]["record_count"] == 0


def test_byte_limit_is_checked_before_json_parsing(tmp_path, monkeypatch):
    path = inventory(tmp_path, "raw.json", rows("cdn.example", 20))
    monkeypatch.setattr(supplements, "LIMIT", 8)
    with pytest.raises(ValueError, match="byte limit"):
        supplements.load_inventory_candidates([path])
