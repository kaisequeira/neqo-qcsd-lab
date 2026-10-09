"""Exact prospective selection provenance; synthetic inputs grant no H3 credit."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_selection as selection
from qcsd_lab.resource_study_supplements import load_inventory_candidates


HOST = "fonts.gstatic.com"


def put(path, value, *, raw=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists(): path.chmod(0o644)
    path.write_bytes(value if raw else inputs.canonical_json(value))
    path.chmod(0o444)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def import_inventory(root, path):
    catalogue = load_inventory_candidates([path])
    digest = hashlib.sha256(inputs.canonical_json(catalogue)).hexdigest()
    base = root / "inputs/supplements" / digest
    put(base / "inventory-001.json", path.read_bytes(), raw=True)
    put(base / "catalogue.json", catalogue)
    admissions = root / "inputs/supplement-admissions"
    index = len(list(admissions.glob("*.json"))) + 1
    put(admissions / f"{index:06d}.json", {"catalogue_sha256": digest,
        "scientific_credit": False, "reason": "explicit operator reserve inventory import"})
    return digest


@pytest.fixture
def pool(tmp_path):
    root = tmp_path / "study"
    original = [f"https://{HOST}/old/{n}.svg?id={n}&x=1+2%2B&a=2&a=1" for n in range(67)]
    source = [{"crUX_domain": "original.example", "resources": [
        {"resource_domain": HOST, "resource_urls": original}]}]
    source_path = root / "inputs/supplied-resources.json"
    digest = put(source_path, source)
    put(root / "study.json", {"source_sha256": digest})
    put(root / "inputs/candidates.json", inputs.candidate_catalogue(source_path))
    new = [f"https://{HOST}/fonts/{n}.woff2?version=1&x=1+2%2B" for n in range(24)]
    inventory = tmp_path / "official-inventory.json"
    put(inventory, {"urls": [{"url": url, "discovery_only": True} for url in new],
        "raw_source_sha256": "c" * 64, "body_downloads": 0, "scientific_credit": False})
    digest = import_inventory(root, inventory)
    return root, original, new, digest


def loaded(pool, tmp_path, *, urls=None, manifest=None, raw=None):
    root, old, new, _ = pool
    manifest = manifest or selection.make_manifest(root, HOST, urls or new[:20])
    path = tmp_path / ("selection-" + os.urandom(4).hex() + ".json")
    digest = put(path, raw if raw is not None else manifest, raw=raw is not None)
    return selection.load_selection(root, path, digest, HOST), path


def prepared(pool, tmp_path):
    root, _, new, _ = pool
    selected, _ = loaded(pool, tmp_path)
    binding = selection.freeze_selection(root, selected)
    attempt = root / "enrollment-attempts" / HOST / "prospective-001"
    base = attempt / "prepared"
    runtime = {"client_sha256": "a" * 64, "native_commit": "b" * 40}
    job = {"hostname": HOST, "urls": new[:20], "output": str(base), "runtime": runtime}
    put(attempt / "job.json", job)
    resources = [{"id": n, "url": url, "known_valid": True} for n, url in enumerate(new[:20])]
    input_path = base / "preparation-get/input.json"
    put(input_path, {"resources": resources})
    workload_path = base / "resources.json"
    workload_sha = put(workload_path, {"resources": resources})
    prepared_path = base / "prepared-workload.json"
    put(prepared_path, {"resources": resources, "preparation": {"runtime": runtime}})
    relative = lambda p: p.relative_to(root).as_posix()
    enrollment = {"hostname": HOST, "urls": list(new[:20]), "runtime": runtime,
        "preparation_dir": relative(base), "workload_path": relative(workload_path),
        "workload_sha256": workload_sha, "paths": {"prepared_workload": relative(prepared_path)},
        "files": {relative(p): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (input_path, workload_path, prepared_path)}}
    original = deepcopy(enrollment)
    enrollment = selection.bind_preparation(root, enrollment, binding, attempt / "job.json")
    assert "resource_selection" not in original
    paths = selection.selection_artifact_paths(enrollment)
    receipt = {"artifact_paths": paths, "files": {p: enrollment["files"][p] for p in paths.values()}}
    return root, enrollment, receipt


def test_explicit20_retains_queries_original67_and_source_order(pool, tmp_path):
    root, old, new, _ = pool
    before = (root / "inputs/supplied-resources.json").read_bytes()
    value, path = loaded(pool, tmp_path)
    assert value["manifest"]["urls"] == new[:20]
    assert value["manifest"]["scientific_credit"] is False
    assert value["raw"] == path.read_bytes()
    assert value["manifest"]["source_sha256"] == hashlib.sha256(before).hexdigest()
    binding = selection.freeze_selection(root, value)
    frozen = root / binding["manifest_path"]
    assert frozen.read_bytes() == value["raw"] and frozen.stat().st_mode & 0o777 == 0o444
    assert (root / "inputs/supplied-resources.json").read_bytes() == before
    assert selection.make_manifest(root, HOST, old[:20])["urls"] == old[:20]
    with pytest.raises(FileExistsError): selection.freeze_selection(root, value)


@pytest.mark.parametrize("case", ["nineteen", "twentyone", "duplicate", "reversed", "unknown",
    "foreign", "http", "fragment", "alias", "credentials", "port", "query-rewrite"])
def test_invalid_selected_resource_sets_refuse(pool, case):
    root, _, new, _ = pool
    urls = list(new[:20])
    if case == "nineteen": urls.pop()
    elif case == "twentyone": urls.append(new[20])
    elif case == "duplicate": urls[1] = urls[0]
    elif case == "reversed": urls.reverse()
    elif case == "unknown": urls[0] = f"https://{HOST}/unobserved.woff2"
    elif case == "foreign": urls[0] = "https://other.gstatic.com/fonts/0.woff2"
    elif case == "http": urls[0] = urls[0].replace("https:", "http:")
    elif case == "fragment": urls[0] += "#alias"
    elif case == "alias": urls[0] = urls[0].replace(HOST, HOST.upper())
    elif case == "credentials": urls[0] = urls[0].replace("https://", "https://user@")
    elif case == "port": urls[0] = urls[0].replace(HOST, HOST + ":444")
    elif case == "query-rewrite": urls[0] = urls[0].replace("1+2%2B", "1%202%2B")
    with pytest.raises(ValueError): selection.make_manifest(root, HOST, urls)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 1.5),
    ("scientific_credit", 0), ("scientific_credit", True), ("record_type", "historical"),
    ("hostname", "other.example"), ("source_sha256", "e" * 64), ("pool_sha256", "e" * 64),
    ("supplements", []), ("supplements", True), ("urls", "not-a-list")])
def test_manifest_schema_and_frozen_context_refuse(pool, tmp_path, field, value):
    root, _, new, _ = pool
    manifest = selection.make_manifest(root, HOST, new[:20]);manifest[field] = value
    with pytest.raises(ValueError): loaded(pool, tmp_path, manifest=manifest)


@pytest.mark.parametrize("mutation", ["unknown", "missing", "duplicate-key", "nonfinite"])
def test_strict_json_manifest_contract(pool, tmp_path, mutation):
    root, _, new, _ = pool
    manifest = selection.make_manifest(root, HOST, new[:20])
    if mutation == "unknown": manifest["unreviewed"] = True
    elif mutation == "missing": del manifest["scientific_credit"]
    raw = inputs.canonical_json(manifest)
    if mutation == "duplicate-key": raw = raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
    elif mutation == "nonfinite": raw = raw.replace(b'"schema_version":1', b'"schema_version":NaN')
    with pytest.raises(ValueError): loaded(pool, tmp_path, raw=raw)


@pytest.mark.parametrize("mutation", ["sha", "writable", "symlink", "hardlink", "traversal", "limit"])
def test_manifest_file_authority_refusals(pool, tmp_path, monkeypatch, mutation):
    root, _, new, _ = pool
    manifest = selection.make_manifest(root, HOST, new[:20]);path = tmp_path / "input.json";digest = put(path, manifest)
    if mutation == "sha": digest = "f" * 64
    elif mutation == "writable": path.chmod(0o644)
    elif mutation == "symlink": link = tmp_path / "link.json";link.symlink_to(path);path = link
    elif mutation == "hardlink": os.link(path, tmp_path / "second.json")
    elif mutation == "traversal": path = tmp_path / "unused/../input.json"
    elif mutation == "limit": monkeypatch.setattr(selection, "LIMIT", 16)
    with pytest.raises(ValueError): selection.load_selection(root, path, digest, HOST)


def test_frozen_context_survives_future_unrelated_import_and_ignores_claimed_status(pool, tmp_path):
    root, _, new, _ = pool
    value, path = loaded(pool, tmp_path)
    inventory = tmp_path / "later.json"
    put(inventory, {"urls": [{"url": f"https://other.example/{n}", "status": 200,
        "historical_h3": True} for n in range(20)]})
    import_inventory(root, inventory)
    again = selection.load_selection(root, path, value["sha256"], HOST)
    assert again == value
    assert len(selection.make_manifest(root, HOST, new[:20])["supplements"]) == 2


@pytest.mark.parametrize("target", ["source", "candidates", "admission", "catalogue", "inventory"])
def test_bound_pool_authority_mutation_refuses(pool, tmp_path, target):
    root, _, new, digest = pool
    value, path = loaded(pool, tmp_path)
    victim = {"source": root / "inputs/supplied-resources.json", "candidates": root / "inputs/candidates.json",
        "admission": root / "inputs/supplement-admissions/000001.json",
        "catalogue": root / f"inputs/supplements/{digest}/catalogue.json",
        "inventory": root / f"inputs/supplements/{digest}/inventory-001.json"}[target]
    victim.chmod(0o644);victim.write_bytes(victim.read_bytes() + b" ");victim.chmod(0o444)
    with pytest.raises(ValueError): selection.load_selection(root, path, value["sha256"], HOST)


def test_self_consistent_catalogue_lie_refuses_against_actual_inventory(pool, tmp_path):
    root, _, new, digest = pool
    old = root / f"inputs/supplements/{digest}/catalogue.json"
    catalogue = json.loads(old.read_bytes());catalogue["candidates"][0]["urls"][0] = f"https://{HOST}/invented.woff2"
    new_digest = hashlib.sha256(inputs.canonical_json(catalogue)).hexdigest()
    base = root / f"inputs/supplements/{new_digest}"
    put(base / "catalogue.json", catalogue)
    put(base / "inventory-001.json", (old.parent / "inventory-001.json").read_bytes(), raw=True)
    put(root / "inputs/supplement-admissions/000001.json", {"catalogue_sha256": new_digest,
        "scientific_credit": False, "reason": "explicit operator reserve inventory import"})
    with pytest.raises(ValueError, match="source inventories"): selection.make_manifest(root, HOST, new[:20])


def test_proof_joins_job_input_workload_and_receipt_and_does_not_mutate(pool, tmp_path):
    root, enrollment, receipt = prepared(pool, tmp_path)
    before = deepcopy(enrollment)
    facts = selection.validate_selection_proof(root, enrollment, receipt)
    assert facts["selected_urls"] == enrollment["urls"] and facts["scientific_credit"] is False
    assert enrollment == before
    assert set(receipt["files"]) == set(selection.selection_artifact_paths(enrollment).values())
    assert "inputs/supplied-resources.json" in enrollment["resource_selection"]["context_files"]


@pytest.mark.parametrize("target", ["job-urls", "job-runtime", "job-output", "job-extra", "input-order",
    "input-bool-id", "workload-order", "prepared-order", "prepared-runtime", "enrollment-urls",
    "context", "manifest-path", "job-path", "missing-context", "receipt-file", "receipt-path"])
def test_proof_semantic_and_inventory_mutations_refuse(pool, tmp_path, target):
    root, enrollment, receipt = prepared(pool, tmp_path)
    binding = enrollment["resource_selection"]
    if target.startswith("job-") and target != "job-path":
        relative = binding["job_path"];value = json.loads((root / relative).read_bytes())
        if target == "job-urls": value["urls"][0] = f"https://{HOST}/old/0.svg"
        elif target == "job-runtime": value["runtime"]["client_sha256"] = "f" * 64
        elif target == "job-output": value["output"] += "/foreign"
        elif target == "job-extra": value["unreviewed"] = True
        binding["job_sha256"] = enrollment["files"][relative] = put(root / relative, value)
    elif target in {"input-order", "input-bool-id", "workload-order", "prepared-order", "prepared-runtime"}:
        relative = {"input-order": enrollment["preparation_dir"] + "/preparation-get/input.json",
            "input-bool-id": enrollment["preparation_dir"] + "/preparation-get/input.json",
            "workload-order": enrollment["workload_path"], "prepared-order": enrollment["paths"]["prepared_workload"],
            "prepared-runtime": enrollment["paths"]["prepared_workload"]}[target]
        value = json.loads((root / relative).read_bytes())
        if target == "prepared-runtime": value["preparation"]["runtime"] = {"different": True}
        elif target == "input-bool-id": value["resources"][0]["id"] = False
        else: value["resources"][0]["url"], value["resources"][1]["url"] = value["resources"][1]["url"], value["resources"][0]["url"]
        enrollment["files"][relative] = put(root / relative, value)
        if target == "workload-order": enrollment["workload_sha256"] = enrollment["files"][relative]
    elif target == "enrollment-urls": enrollment["urls"].reverse()
    elif target == "context": binding["context_files"]["study.json"] = "f" * 64
    elif target == "manifest-path": binding["manifest_path"] = binding["job_path"]
    elif target == "job-path": binding["job_path"] = "../foreign.json"
    elif target == "missing-context": del enrollment["files"]["inputs/candidates.json"]
    elif target == "receipt-file": receipt["files"][binding["manifest_path"]] = "f" * 64
    elif target == "receipt-path": del receipt["artifact_paths"]["resource_selection_job"]
    with pytest.raises(ValueError): selection.validate_selection_proof(root, enrollment, receipt)


def test_historical_absence_and_partial_downgrade_refusal(pool, tmp_path):
    assert selection.validate_selection_proof(pool[0], {"urls": []}) is None
    assert selection.selection_artifact_paths({"urls": []}) == {}
    root, enrollment, receipt = prepared(pool, tmp_path)
    del enrollment["resource_selection"]
    with pytest.raises(ValueError, match="partial selection"): selection.validate_selection_proof(root, enrollment)
    with pytest.raises(ValueError, match="partial selection"): selection.validate_selection_proof(root, {"files": {}}, receipt)


def test_in_memory_raw_manifest_change_before_freeze_refuses(pool, tmp_path):
    selected, _ = loaded(pool, tmp_path)
    selected["manifest"]["urls"].reverse()
    with pytest.raises(ValueError, match="changed before freezing"): selection.freeze_selection(pool[0], selected)


def test_named_pipe_manifest_refuses_without_waiting_for_a_writer(pool, tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path, 0o444)
    with pytest.raises(ValueError, match="immutable unlinked"):
        selection.load_selection(pool[0], path, "f" * 64, HOST)


def test_manifest_changed_during_the_read_refuses(pool, tmp_path, monkeypatch):
    root, _, new, _ = pool
    path = tmp_path / "unstable.json"
    digest = put(path, selection.make_manifest(root, HOST, new[:20]))
    inode = path.stat().st_ino
    original = os.fstat
    calls = 0
    def changing(fd):
        nonlocal calls
        info = original(fd)
        if info.st_ino == inode:
            calls += 1
            if calls == 2:
                path.chmod(0o644);path.write_bytes(path.read_bytes() + b" ");path.chmod(0o444)
                info = original(fd)
        return info
    monkeypatch.setattr(selection.os, "fstat", changing)
    with pytest.raises(ValueError, match="changed or exceeds"):
        selection.load_selection(root, path, digest, HOST)


@pytest.mark.parametrize("target", ["manifest", "context", "binding-field", "orphan-field"])
def test_selection_proof_deletion_and_partial_fields_refuse(pool, tmp_path, target):
    root, enrollment, receipt = prepared(pool, tmp_path)
    if target == "manifest": (root / enrollment["resource_selection"]["manifest_path"]).unlink()
    elif target == "context": (root / "inputs/candidates.json").unlink()
    elif target == "binding-field": del enrollment["resource_selection"]["job_sha256"]
    elif target == "orphan-field": enrollment = {"resource_selection_manifest": "orphan"}
    with pytest.raises((ValueError, OSError)):
        selection.validate_selection_proof(root, enrollment, receipt)
