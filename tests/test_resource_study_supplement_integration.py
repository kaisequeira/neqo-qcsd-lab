"""Actual frozen reserve addition/candidate-pool integration; no live admission."""
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab.resource_study_store import StudyStore


def write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o644)
    path.write_bytes(inputs.canonical_json(payload))
    return path


@pytest.fixture
def case(tmp_path):
    primary = write(tmp_path / "primary.json", [{"crUX_domain": "referrer.example", "resources": [
        {"resource_domain": "primary.example", "resource_urls": [
            "https://primary.example/th?id=A", "https://primary.example/th?id=B"]}]}])
    root = tmp_path / "study"
    study.initialize(primary, root)
    reserve = write(tmp_path / "native.json", {"urls": [
        {"url": f"https://reserve.example/r?id={i}", "status": 200} for i in range(20)]})
    return root, primary, reserve


def destination(root):
    paths = list((root / "inputs/supplements").glob("*/catalogue.json"))
    assert len(paths) == 1
    return paths[0].parent


def test_primary_pool_is_bound_to_copied_source_and_grants_no_credit(case):
    root, primary, _ = case
    pool = study.candidate_pool(root)
    assert list(pool) == ["primary.example"]
    assert pool["primary.example"]["urls"] == ["https://primary.example/th?id=A", "https://primary.example/th?id=B"]
    assert pool["primary.example"]["eligible"] is False
    primary.unlink()
    assert study.candidate_pool(root) == pool
    assert StudyStore(root).status()["accepted_count"] == 0


def test_reserve_freezes_original_bytes_and_survives_external_file_removal(case):
    root, _, reserve = case
    original = reserve.read_bytes()
    study.add_inventories(root, [reserve])
    frozen = destination(root)
    assert (frozen / "inventory-001.json").read_bytes() == original
    assert (frozen / "inventory-001.json").stat().st_mode & 0o7777 == 0o444
    assert (frozen / "catalogue.json").stat().st_mode & 0o7777 == 0o444
    catalogue = json.loads((frozen / "catalogue.json").read_bytes())
    assert catalogue["inventory_files"][0]["sha256"] == hashlib.sha256(original).hexdigest()
    before = study.candidate_pool(root)
    reserve.unlink()
    assert study.candidate_pool(root) == before
    assert list(before) == ["primary.example", "reserve.example"]
    assert before["reserve.example"]["eligible"] is True
    assert StudyStore(root).status()["accepted_count"] == 0


def test_repeat_same_reserve_is_idempotent_and_does_not_rewrite_receipts(case):
    root, _, reserve = case
    study.add_inventories(root, [reserve])
    frozen = destination(root)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in frozen.iterdir()}
    study.add_inventories(root, [reserve])
    assert destination(root) == frozen
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in frozen.iterdir()} == before
    assert len(study.candidate_pool(root)["reserve.example"]["source_occurrences"]) == 20


def test_same_host_ordered_append_preserves_queries_primary_identity_and_duplicates(case):
    root, _, reserve = case
    write(reserve, {"urls": [{"url": "https://PRIMARY.example:443/th?id=B#duplicate"},
        {"url": "https://primary.example/th?id=C&x=1+2%2B&a=2&a=1"},
        {"url": "https://primary.example/th?id=D?"}]})
    primary_raw = (root / "inputs/candidates.json").read_bytes()
    study.add_inventories(root, [reserve])
    pool = study.candidate_pool(root)
    assert list(pool) == ["primary.example"]
    assert pool["primary.example"]["urls"] == ["https://primary.example/th?id=A", "https://primary.example/th?id=B",
        "https://primary.example/th?id=C&x=1+2%2B&a=2&a=1", "https://primary.example/th?id=D?"]
    assert pool["primary.example"]["url_count"] == 4
    assert len(pool["primary.example"]["source_occurrences"]) == 4
    assert (root / "inputs/candidates.json").read_bytes() == primary_raw
    assert study.candidate_pool(root) == pool  # No repeated in-memory append on reopen.


@pytest.mark.parametrize("kind", ["primary-source", "primary-catalogue", "reserve-raw", "reserve-catalogue", "missing-raw"])
def test_frozen_candidate_dependencies_refuse_tampering(case, kind):
    root, _, reserve = case
    study.add_inventories(root, [reserve])
    assert "reserve.example" in study.candidate_pool(root)
    frozen = destination(root)
    path = {"primary-source": root / "inputs/supplied-resources.json",
            "primary-catalogue": root / "inputs/candidates.json",
            "reserve-raw": frozen / "inventory-001.json",
            "reserve-catalogue": frozen / "catalogue.json", "missing-raw": frozen / "inventory-001.json"}[kind]
    if kind == "missing-raw":
        path.unlink()
    elif kind == "primary-catalogue":
        value = json.loads(path.read_bytes())
        value["candidates"][0]["urls"].append("https://primary.example/not-supplied")
        write(path, value)
    elif kind == "reserve-catalogue":
        value = json.loads(path.read_bytes())
        value["candidates"][0]["urls"].append("https://reserve.example/not-supplied")
        write(path, value)
    else:
        path.chmod(0o644)
        path.write_bytes(path.read_bytes().replace(b"id=0", b"id=X") if kind == "reserve-raw"
                         else path.read_bytes().replace(b"id=A", b"id=X"))
    with pytest.raises((ValueError, FileNotFoundError)):
        study.candidate_pool(root)
    assert StudyStore(root).status()["accepted_count"] == 0


def test_tampered_existing_reserve_refuses_idempotent_catalogue_reuse(case):
    root, _, reserve = case
    study.add_inventories(root, [reserve])
    path = destination(root) / "catalogue.json"
    value = json.loads(path.read_bytes())
    value["candidates"][0]["eligible"] = False
    write(path, value)
    with pytest.raises(ValueError, match="supplement catalogue changed"):
        study.add_inventories(root, [reserve])


def test_failed_or_short_old_inventory_is_structural_only_without_auto_selection(case):
    root, _, reserve = case
    write(reserve, {"urls": [{"url": "https://reserve.example/th?id=one", "status": 404}] * 30})
    study.add_inventories(root, [reserve])
    row = study.candidate_pool(root)["reserve.example"]
    assert row["urls"] == ["https://reserve.example/th?id=one"]
    assert row["eligible"] is False and row["url_count"] == 1
    assert len(row["source_occurrences"]) == 30
    assert StudyStore(root).enrolled() == []


def test_catalogue_mtime_changes_cannot_reorder_numbered_reserve_admissions(case):
    root, _, reserve = case
    write(reserve, {"urls": [{"url": "https://primary.example/th?id=C&v=1"}]})
    later = write(reserve.with_name("later.json"), {
        "urls": [{"url": "https://primary.example/th?id=D&v=2"}]})
    study.add_inventories(root, [reserve])
    study.add_inventories(root, [later])
    admissions = sorted((root / "inputs/supplement-admissions").glob("*.json"))
    assert [path.name for path in admissions] == ["000001.json", "000002.json"]
    saved = {path.name: path.read_bytes() for path in admissions}
    catalogues = [root / "inputs/supplements" / json.loads(path.read_bytes())["catalogue_sha256"] / "catalogue.json"
                  for path in admissions]
    # Reverse the filesystem timestamp ordering used by the previous route.
    os.utime(catalogues[0], ns=(4_000_000_000, 4_000_000_000))
    os.utime(catalogues[1], ns=(1_000_000_000, 1_000_000_000))
    assert sorted(catalogues, key=lambda path: path.stat().st_mtime_ns) == catalogues[::-1]
    assert study.candidate_pool(root)["primary.example"]["urls"] == [
        "https://primary.example/th?id=A", "https://primary.example/th?id=B",
        "https://primary.example/th?id=C&v=1", "https://primary.example/th?id=D&v=2"]
    assert {path.name: path.read_bytes() for path in admissions} == saved
