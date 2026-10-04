"""Exact input preservation, prospective role separation and public CLI checks."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from qcsd_lab.manifest import validate_manifest, validate_research_preparation
from qcsd_lab.supplied_static_graph import (
    canonical_bytes, digest, import_graph, verify_import,
)


def source():
    return [{"crUX_domain": "site.example", "resources": [
        {"resource_domain": "cdn.example", "resource_urls": [
            "https://cdn.example/a?v=1&v=2", "https://cdn.example/b%20c"]},
        {"resource_domain": "site.example", "resource_urls": [
            "https://site.example/app"]},
    ]}]


def imported(value=None):
    raw = canonical_bytes(source() if value is None else value)
    manifest, binding = import_graph(raw, digest(raw), "site.example")
    return raw, manifest, binding


def test_preserves_every_exact_address_and_declares_its_own_dag():
    raw, manifest, binding = imported()
    supplied = [url for group in source()[0]["resources"] for url in group["resource_urls"]]
    assert [row["url"] for row in manifest["resources"][1:]] == supplied
    assert [row["id"] for row in manifest["resources"]] == [0, 1, 2, 3]
    assert [row["depends_on"] for row in manifest["resources"]] == [[], [0], [0], [0]]
    assert binding["supplied_resource_ids"] == [1, 2, 3]
    assert binding["primary_added"] is True
    assert binding["origins"] == ["https://cdn.example", "https://site.example"]
    assert binding["browser_discovery_claim"] is False
    assert binding["scientific_credit"] is False
    assert "preparation" not in manifest
    assert all("known_valid" not in row for row in manifest["resources"])
    assert manifest["resources"][0]["headers"] == [
        ["accept", "*/*"], ["accept-encoding", "identity"],
        ["accept-language", "en-US,en;q=0.9"]]
    verify_import(raw, digest(raw), "site.example", manifest, binding)
    validate_manifest(manifest)
    with pytest.raises(ValueError, match="research-grade provenance"):
        validate_research_preparation(manifest, workload_id="unqualified-input")


def test_supplied_primary_is_retained_once_as_explicit_resource_zero():
    value = source()
    value[0]["resources"][1]["resource_urls"].insert(0, "https://site.example/")
    raw, manifest, binding = imported(value)
    assert [row["url"] for row in manifest["resources"]].count("https://site.example/") == 1
    assert binding["primary_added"] is False
    assert binding["supplied_resource_ids"] == [1, 2, 0, 3]
    assert binding["supplied_resource_count"] == 4
    verify_import(raw, digest(raw), "site.example", manifest, binding)


@pytest.mark.parametrize("mutation", ["drop", "add", "dependency", "headers", "claim-valid"])
def test_resealed_manifest_cannot_change_original_input(mutation):
    raw, manifest, binding = imported()
    if mutation == "drop":
        manifest["resources"].pop(1)
    elif mutation == "add":
        manifest["resources"].append({"id": 4, "url": "https://extra.example/x"})
    elif mutation == "dependency":
        manifest["resources"][2]["depends_on"] = [1]
    elif mutation == "headers":
        manifest["resources"][1]["headers"].append(["cookie", "made-up"])
    else:
        manifest["resources"][1]["known_valid"] = True
    binding["native_manifest_sha256"] = digest(canonical_bytes(manifest))
    with pytest.raises(ValueError, match="complete supplied list"):
        verify_import(raw, digest(raw), "site.example", manifest, binding)


@pytest.mark.parametrize("key,value", [("scientific_credit", True), ("site_credit", 1),
    ("formal_accepted_trace_count", 4), ("browser_discovery_claim", True),
    ("supplied_resource_ids", [1, 3]), ("origins", ["https://site.example"])])
def test_binding_cannot_relabel_or_prune_input(key, value):
    raw, manifest, binding = imported()
    binding[key] = value
    with pytest.raises(ValueError, match="complete supplied list"):
        verify_import(raw, digest(raw), "site.example", manifest, binding)


def test_source_byte_identity_is_explicit_and_not_self_resealed():
    raw, _, _ = imported()
    with pytest.raises(ValueError, match="explicit byte hash"):
        import_graph(raw + b"\n", digest(raw), "site.example")


@pytest.mark.parametrize("case", ["empty", "same-origin", "duplicate-url", "duplicate-domain",
    "duplicate-group", "credentials", "fragment", "wrong-group-host", "http", "unknown-field"])
def test_invalid_or_non_multiorigin_supplied_graph_fails_closed(case):
    value = source()
    group = value[0]["resources"][0]
    if case == "empty":
        value[0]["resources"] = []
    elif case == "same-origin":
        value[0]["resources"] = value[0]["resources"][1:]
    elif case == "duplicate-url":
        group["resource_urls"].append(group["resource_urls"][0])
    elif case == "duplicate-domain":
        value.append(copy.deepcopy(value[0]))
    elif case == "duplicate-group":
        value[0]["resources"].append(copy.deepcopy(group))
    elif case == "credentials":
        group["resource_urls"][0] = "https://user@cdn.example/a"
    elif case == "fragment":
        group["resource_urls"][0] += "#fragment"
    elif case == "wrong-group-host":
        group["resource_urls"][0] = "https://other.example/a"
    elif case == "http":
        group["resource_urls"][0] = "http://cdn.example/a"
    else:
        value[0]["approved"] = True
    raw = canonical_bytes(value)
    with pytest.raises(ValueError):
        import_graph(raw, digest(raw), "site.example")


def test_duplicate_json_keys_and_absent_selected_domain_reject():
    raw = b'[{"crUX_domain":"site.example","crUX_domain":"other.example","resources":[]}]'
    with pytest.raises(ValueError, match="duplicate key"):
        import_graph(raw, digest(raw), "site.example")
    raw = canonical_bytes(source())
    with pytest.raises(ValueError, match="absent"):
        import_graph(raw, digest(raw), "absent.example")


def test_actual_isolated_public_cli_writes_only_unqualified_create_only_inputs(tmp_path):
    raw = canonical_bytes(source())
    source_path = tmp_path / "source.json"
    source_path.write_bytes(raw)
    tool = Path(__file__).resolve().parents[1] / "tools/supplied_static_graph.py"
    out = tmp_path / "new-input"
    argv = [sys.executable, "-I", "-B", str(tool), "--source", str(source_path),
            "--source-sha256", digest(raw), "--domain", "site.example",
            "--output-root", str(out)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["scientific_credit"] is False
    assert {path.name for path in out.iterdir()} == {"native-input.json", "input-binding.json"}
    before = {path.name: path.read_bytes() for path in out.iterdir()}
    verify_import(raw, digest(raw), "site.example", json.loads(before["native-input.json"]),
                  json.loads(before["input-binding.json"]))
    repeated = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10)
    assert repeated.returncode != 0
    assert {path.name: path.read_bytes() for path in out.iterdir()} == before
