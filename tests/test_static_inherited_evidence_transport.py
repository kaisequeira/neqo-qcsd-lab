"""Sealed-prefix transport shared by preflight, collection, deep and recipes."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab import supplied_static_admission as admission
from qcsd_lab import supplied_static_preparation as preparation
from qcsd_lab import rapid_rolling_readiness as readiness


def reference(path):
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return reference(path)


def boundary(tmp_path, monkeypatch):
    old, current = tmp_path / "old-context", tmp_path / "new-context"
    complete, deferred, outer, later = (tmp_path / name for name in
        ("complete-get", "deferred-get", "closed-outer-records", "later-active-get"))
    for path in (old, current, complete, deferred, outer, later): path.mkdir()
    old_ref = write(old / "provenance.json", {"sealed": "old"})
    new_ref = write(current / "provenance.json", {"sealed": "new"})
    namespace = {key: write(outer / (key + ".json"), {"record": key})
                 for key in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr")}
    admitted = write(old / "attempts/one/terminal.json", {"payload": {
        "get_evidence_root": str(complete), "namespace": namespace}})
    failed = write(old / "attempts/two/terminal.json", {"payload": {
        "get_evidence_root": str(deferred), "namespace": None}})
    contexts = {old: SimpleNamespace(root=old, provenance={"parent_context": None, "inherited_terminals": []}),
                current: SimpleNamespace(root=current, provenance={"parent_context": old_ref,
                    "inherited_terminals": [admitted, failed]})}
    monkeypatch.setattr(preparation, "validate_static_preparation", lambda *args: {"context": new_ref})
    monkeypatch.setattr(preparation, "preparation_roots", lambda *args: [current])
    monkeypatch.setattr(admission, "load_context", lambda root: contexts[root])
    checked = []
    monkeypatch.setattr(admission, "verify_terminal", lambda path, context: checked.append(path))
    monkeypatch.setattr(admission.receipts, "_unpack", lambda raw, kind: json.loads(raw)["payload"])
    monkeypatch.setattr(admission, "acquisition_status", lambda *a, **k: pytest.fail("later active scan"))
    manifest = {"preparation": {"data_role": preparation.ROLE}, "resources": []}
    return manifest, checked, (old, current, complete, deferred, outer, later)


def recipe():
    path = ROOT / "tools/_rapid_class_mode_flight/flight/operator.py"
    spec = importlib.util.spec_from_file_location("prefix_transport_portable_recipe", path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_closed_prefix_raw_deferral_namespace_ancestor_and_minimal_public_recipe_agree(tmp_path, monkeypatch):
    manifest, checked, paths = boundary(tmp_path, monkeypatch)
    old, current, complete, deferred, outer, later = paths
    expected = {old, current, complete, deferred, outer}
    assert set(transport.manifest_roots(manifest)) == expected
    assert set(map(Path, recipe().static_roots(manifest))) == expected
    assert later not in expected and tmp_path not in expected
    assert checked and all(path.is_relative_to(old / "attempts") for path in checked)


@pytest.mark.parametrize("mutation", ["terminal", "namespace", "parent", "link", "transport-syntax"])
def test_changed_bound_prefix_or_unsafe_raw_path_rejects(tmp_path, monkeypatch, mutation):
    manifest, _, paths = boundary(tmp_path, monkeypatch)
    old, current, complete, deferred, outer, later = paths
    if mutation == "terminal": (old / "attempts/one/terminal.json").write_text("changed")
    elif mutation == "namespace": (outer / "outer_stderr.json").write_text("changed")
    elif mutation == "parent": (old / "provenance.json").write_text("changed")
    elif mutation == "link": complete.rmdir(); complete.symlink_to(later, target_is_directory=True)
    else:
        bad = tmp_path / "unsafe:raw"; bad.mkdir()
        path = old / "attempts/one/terminal.json"; value = json.loads(path.read_text())
        value["payload"]["get_evidence_root"] = str(bad); write(path, value)
        # Keep the reference current so the canonical transport check owns the rejection.
        admission.load_context(current).provenance["inherited_terminals"][0] = reference(path)
    with pytest.raises(ValueError): transport.manifest_roots(manifest)


def test_campaign_preflight_and_exact_public_deep_share_prefix_roots(tmp_path, monkeypatch):
    manifest, _, paths = boundary(tmp_path, monkeypatch)
    execution = tmp_path / "execution"; (execution / "config/campaigns").mkdir(parents=True)
    campaign = execution / "config/campaigns/group.yaml"
    campaign.write_text("workloads:\n  original_first: {}\n  inherited_second: {}\n")
    for name in ("original_first", "inherited_second"):
        write(execution / "config/workloads" / (name + ".json"), manifest)
    roots = transport.campaign_roots(execution, "run", campaign)
    assert set(roots) == set(paths[:-1])
    directory = tmp_path / "canary"; lineage = directory / "lineage/original-manifest.json"
    write(lineage, manifest)
    recipe_path = tmp_path / "recipe.py"; recipe_path.write_text("# exact recipe\n")
    helper = tmp_path / "helper.py"; helper.write_text("# exact helper\n")
    plan = {"recipe_sha256": sha256(recipe_path.read_bytes()).hexdigest(),
        "helper_sha256": sha256(helper.read_bytes()).hexdigest(),
        "original_workload_sha256": sha256(lineage.read_bytes()).hexdigest(),
        "canonical_runtime": {"collection_image_digest": "sha256:" + "a" * 64},
        "name": "sealed-prefix", "clean_runtime_root": str(execution), "execution_root": str(execution)}
    input_command = ["--user", "1000:1000", "--volume", f"{recipe_path}:/recipe.py:ro",
                     "--volume", f"{helper}:/helpers.py:ro"]
    actual = readiness._deep_command(plan, directory, "b" * 64, "tamaraw", "/lab/results/canary", input_command)
    mounts = {actual[i + 1] for i, item in enumerate(actual) if item == "--volume"}
    assert {f"{root}:{root}:ro" for root in roots}.issubset(mounts)
    assert actual[-4:] == ["--mode", "tamaraw", "--result", "/lab/results/canary"]
    assert not any(str(paths[-1]) in item for item in actual)


def test_browser_preparation_adds_no_static_mounts():
    assert transport.manifest_roots({"preparation": {"browser": True}, "resources": []}) == []


def test_actual_selected_inherited_manifest_covers_all_observed_retained_reads(monkeypatch):
    supplied = os.environ.get("QCSD_TRANSPORT_TEST_MANIFEST")
    if not supplied: pytest.skip("Provide a genuine inherited static manifest for HOST-only reopening")
    from qcsd_lab import supplied_static_get as get
    manifest = json.loads(Path(supplied).read_bytes())
    reads = set(); original = get._read
    def observe(path, *args, **kwargs):
        reads.add(Path(path).absolute())
        return original(path, *args, **kwargs)
    monkeypatch.setattr(get, "_read", observe)
    roots = transport.manifest_roots(manifest)
    retained = [path for path in reads if "diagnostic-rehearsals" in path.parts]
    assert retained and all(any(path.is_relative_to(root) for root in roots) for path in retained)
    inherited = [path for path in reads if path.name == "terminal.json"]
    assert len(inherited) >= 20
    assert not any("get-candidate-000053" in str(path) for path in roots)
    assert not any(root.name == "THESIS" for root in roots)
