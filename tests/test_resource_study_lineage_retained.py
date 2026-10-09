"""Retained49 public enrollment and pure proof controls; no live H3 credit.

The complete GET metadata and pilot boundary are explicitly synthetic. The
public coordinator, Native metadata inspector, SQLite enrollment, lineage,
selected-job proof and add-host publication execute on disposable HOST roots.
"""
from contextlib import nullcontext
from copy import deepcopy
import importlib.util
from pathlib import Path
import sqlite3

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_selection as selection
from qcsd_lab.resource_study_store import StudyStore

_spec = importlib.util.spec_from_file_location("retained_native_metadata_fixture",
    Path(__file__).with_name("test_resource_study_selection_integration.py"))
metadata = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(metadata)
RUNTIME = metadata.RUNTIME
HEALTHY = [m for m in inputs.MODES if m != "buflo"]
XXX = "xxxvideo.link"
SIBLINGS = ["angkanet26.com", "bflixcdn.xyz", "cdn.bookmark.xxx"]
HOSTS = [XXX, *SIBLINGS, lineage.EXCLUDED, *(f"class-{i:02d}.example" for i in range(45))]


@pytest.fixture
def current(tmp_path, monkeypatch):
    from qcsd_lab import resource_study_store as storage
    monkeypatch.setattr(storage.os, "fsync", lambda _: None)
    monkeypatch.setattr(storage, "_fsync", lambda _: None)
    monkeypatch.setattr(epochs, "docker_lock", nullcontext)
    # No synthetic pilot can qualify a live cell. This fixture only tests the
    # public membership/SQL transition after genuine-shaped Native20 metadata.
    monkeypatch.setattr(epochs, "_pilot", lambda *args: None)
    source = tmp_path / "source.json"
    metadata.write(source, [{"crUX_domain": "official.example", "resources": [
        {"resource_domain": h, "resource_urls": [f"https://{h}/r?i={i}&kept=1+2%2B" for i in range(30)]}
        for h in HOSTS]}])
    parent = StudyStore(tmp_path / "parent")
    study.initialize(source, parent.root)
    control = HOSTS[5]
    result = study.enroll(parent.root, RUNTIME, [*SIBLINGS, control], backend=metadata.Backend(parent.root))
    assert all(row["status"] == "enrolled" for row in result["enrollment"])
    epochs._bind(parent, parent)
    cells = {(h, m): epochs._cell(parent, h, m) for h in SIBLINGS for m in HEALTHY}
    cells.update({(control, mode): epochs._cell(parent, control, mode) for mode in inputs.MODES})
    epochs._publish(parent, [], cells, "initial", cells)
    inventory = tmp_path / "MAL.json"
    metadata.write(inventory, {"urls": [{"url": f"https://{lineage.INCLUDED}/r?i={i}"} for i in range(25)]})
    mal = StudyStore(tmp_path / "mal-healthy")
    lineage.initialize(parent.root, mal.root, inventory, storage_reserve_bytes=2*1024**3)
    assert study.enroll(mal.root, RUNTIME, [lineage.INCLUDED], backend=metadata.Backend(mal.root))["enrollment"][0]["status"] == "enrolled"
    epochs.create_epoch(parent.root, mal.root, change="replace-unused-class",
        affected_hostnames=[lineage.INCLUDED], affected_modes=HEALTHY)
    def child(name="child"):
        store = StudyStore(tmp_path / name)
        lineage.initialize(parent.root, store.root, inventory, storage_reserve_bytes=2*1024**3)
        return store
    return parent, child, mal


def enroll(store, host, *, selected=False, backend=None):
    kwargs = {}
    if selected:
        urls = study.candidate_pool(store.root)[host]["urls"][2:22]
        manifest = store.root.parent / (store.root.name + "-selection.json")
        digest = metadata.write(manifest, selection.make_manifest(store.root, host, urls))
        kwargs = {"resource_selection": manifest, "resource_selection_sha256": digest}
    result = study.enroll(store.root, RUNTIME, [host], backend=backend or metadata.Backend(store.root), **kwargs)
    return result, kwargs


@pytest.mark.parametrize("selected", [False, True])
def test_public_retained_xxx_default_and_selected20_enroll_with_full_proof(current, selected):
    parent, child, _ = current; store = child()
    before = (parent.root / "study.json").read_bytes()
    result, _ = enroll(store, XXX, selected=selected)
    assert result["enrollment"] == [{"hostname": XXX, "status": "enrolled", "resources": 20}]
    value = epochs._enrollments(store)[XXX][0]
    original = inputs.candidate_catalogue(store.root / lineage.SOURCE)["candidates"][0]
    assert value["urls"] == (original["urls"][2:22] if selected else original["urls"][:20])
    assert value["source_occurrences"] == original["source_occurrences"]
    assert ("resource_selection" in value) is selected
    epochs._verify_preparation(store, XXX)
    assert store.status()["accepted_count"] == 0
    assert (parent.root / "study.json").read_bytes() == before


def test_public_xxx_selected_add_host_keeps_all_old_cells_rows_and_fences(current):
    parent, child, _ = current; store = child()
    assert enroll(store, XXX, selected=True)[0]["enrollment"][0]["status"] == "enrolled"
    prior = deepcopy(epochs._records(parent)[-1])
    record = epochs.create_epoch(parent.root, store.root, change="add-host", affected_hostnames=[XXX], affected_modes=HEALTHY)
    new = {(c["hostname"], c["mode"]): c for c in record["cells"]}
    assert all(new[(c["hostname"], c["mode"])] == c for c in prior["cells"])
    assert record["class_transition"] == prior["class_transition"] and record["exclusions"] == prior["exclusions"]
    assert all(record["write_fences"][r] == v for r, v in prior["write_fences"].items())
    assert len(record["cells"]) == len(prior["cells"]) + 4
    assert epochs.status(parent.root)["accepted_count"] == 0


def test_original_buflo_siblings_matching_ordered20_admit_without_native_identity_change(current):
    parent, child, _ = current; store = child()
    before = deepcopy(epochs._records(parent)[-1])
    for host in SIBLINGS:
        assert enroll(store, host)[0]["enrollment"][0]["status"] == "enrolled"
        actual = epochs._enrollments(store)[host][0]; sibling = epochs._enrollments(parent)[host][0]
        assert actual["urls"] == sibling["urls"] and actual["workload_sha256"] == sibling["workload_sha256"]
    record = epochs.create_epoch(parent.root, store.root, change="add-host", affected_hostnames=SIBLINGS, affected_modes=["buflo"])
    assert record["affected"] == [[h, "buflo"] for h in sorted(SIBLINGS)]
    assert all(c in record["cells"] for c in before["cells"])
    assert epochs.status(parent.root)["accepted_count"] == 0


def test_default_retained_pool_can_skip_an_earlier_failed_url_without_reordering(current):
    _, child, _ = current; store = child()
    class SuccessfulSubsequence(metadata.Backend):
        def prepare(self, candidate, attempt):
            selected = deepcopy(candidate); selected["urls"] = selected["urls"][1:]
            value = metadata.prepare_metadata(self.root, selected, attempt)
            metadata.write(attempt / "job.json", {"hostname": candidate["hostname"], "urls": candidate["urls"],
                "output": str(attempt / "prepared"), "runtime": RUNTIME})
            return value
    assert enroll(store, XXX, backend=SuccessfulSubsequence(store.root))[0]["enrollment"][0]["status"] == "enrolled"
    actual = epochs._enrollments(store)[XXX][0]
    assert actual["urls"] == study.candidate_pool(store.root)[XXX]["urls"][1:21]
    assert "resource_selection" not in actual
    epochs._verify_preparation(store, XXX)


@pytest.mark.parametrize("failure", ["workload", "settings", "policy"])
def test_retained_added_mode_cannot_change_sibling_workload_or_mode_defaults(current, failure):
    parent, child, _ = current; store = child()
    class Changed(metadata.Backend):
        def prepare(self, candidate, attempt):
            selected = deepcopy(candidate)
            if failure == "workload": selected["urls"] = selected["urls"][1:]
            value = metadata.prepare_metadata(self.root, selected, attempt)
            if failure == "settings": value["mode_settings"]["buflo"] = {"changed": True}
            if failure == "policy": value["mode_policies"]["buflo"] = {"changed": True}
            return value
    assert enroll(store, SIBLINGS[0], backend=Changed(store.root))[0]["enrollment"][0]["status"] == "enrolled"
    head = epochs._records(parent)
    with pytest.raises(ValueError, match="resource/network epoch|mode/runtime defaults"):
        epochs.create_epoch(parent.root, store.root, change="add-host", affected_hostnames=[SIBLINGS[0]], affected_modes=["buflo"])
    assert epochs._records(parent) == head


def test_retained_runtime_mismatch_refuses_actual_native20_before_enrollment(current):
    _, child, _ = current; store = child()
    class Changed(metadata.Backend):
        def prepare(self, candidate, attempt):
            value = metadata.prepare_metadata(self.root, candidate, attempt)
            value["runtime"] = {**value["runtime"], "client_sha256": "d"*64}
            return value
    result, _ = enroll(store, XXX, backend=Changed(store.root))
    assert result["enrollment"][0]["status"] == "not-enrolled" and store.enrolled() == []


@pytest.mark.parametrize("selected", [False, True])
def test_retained_pure_receipt_validation_never_opens_store_or_sqlite(current, monkeypatch, selected):
    _, child, _ = current; store = child(); enroll(store, XXX, selected=selected)
    plan = store.plan(); value = epochs._enrollments(store)[XXX][0]
    def forbidden(*args, **kwargs): raise AssertionError("pure proof opened a ledger")
    monkeypatch.setattr(StudyStore, "__init__", forbidden)
    monkeypatch.setattr(StudyStore, "_transaction", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    lineage.validate_receipt_enrollment(store.root, plan, value)
    bad = deepcopy(value); bad["urls"][0] += "&invented=1"
    with pytest.raises(ValueError): lineage.validate_receipt_enrollment(store.root, plan, bad)


@pytest.mark.parametrize("failure", ["retired", "foreign", "MAL-url", "reordered", "nineteen", "duplicate",
    "pool", "provenance", "selection-context", "source-byte", "source-mode", "reserve-byte"])
def test_retained_enrollment_refuses_source_pool_order_occurrences_or_context_tampering(current, failure):
    _, child, _ = current; store = child(); enroll(store, XXX)
    value = deepcopy(epochs._enrollments(store)[XXX][0])
    if failure == "retired": value["hostname"] = lineage.EXCLUDED
    elif failure == "foreign": value["hostname"] = "foreign.example"
    elif failure == "MAL-url": value["urls"][0] = f"https://{lineage.INCLUDED}/r?i=0"
    elif failure == "reordered": value["urls"].reverse()
    elif failure == "nineteen": value["urls"].pop()
    elif failure == "duplicate": value["urls"][1] = value["urls"][0]
    elif failure == "pool": value["urls"][0] += "&unobserved=1"
    elif failure == "provenance": value["source_occurrences"] = []
    elif failure == "selection-context": value["class_selection"]["selection_sha256"] = "f"*64
    else:
        path = store.root / (lineage.INVENTORY if failure == "reserve-byte" else lineage.SOURCE)
        path.chmod(0o644)
        if failure != "source-mode": path.write_bytes(path.read_bytes()+b" ")
    with pytest.raises(ValueError): lineage.validate_enrollment(store, value)


@pytest.mark.parametrize("failure", ["partial", "manifest", "job", "input", "workload"])
def test_selected_retained_receipt_refuses_missing_or_changed_exact20_proof(current, failure):
    _, child, _ = current; store = child(); enroll(store, XXX, selected=True)
    value = deepcopy(epochs._enrollments(store)[XXX][0]); binding = value["resource_selection"]
    if failure == "partial": value.pop("resource_selection")
    else:
        relative = {"manifest":binding["manifest_path"], "job":binding["job_path"],
            "input":value["preparation_dir"]+"/preparation-get/input.json", "workload":value["workload_path"]}[failure]
        path = store.root / relative; path.chmod(0o644); path.write_bytes(path.read_bytes()+b" "); path.chmod(0o444)
    with pytest.raises(ValueError): lineage.validate_receipt_enrollment(store.root, store.plan(), value)


@pytest.mark.parametrize("selected", [False, True])
def test_incomplete_native20_refuses_before_retained_enrollment_or_epoch(current, selected):
    parent, child, _ = current; store = child(); prior = epochs._records(parent)
    result, _ = enroll(store, XXX, selected=selected, backend=metadata.Backend(store.root, failed_response=True))
    assert result["enrollment"][0]["status"] == "not-enrolled"
    assert store.enrolled() == [] and epochs._records(parent) == prior


def test_old_map_enrollment_and_mal_reserve_rules_are_unchanged(current):
    parent, child, _ = current
    assert "class_selection" not in parent.plan()
    assert enroll(parent, XXX)[0]["enrollment"][0]["status"] == "enrolled"
    store = child()
    assert enroll(store, lineage.INCLUDED)[0]["enrollment"][0]["status"] == "enrolled"
    value = deepcopy(epochs._enrollments(store)[lineage.INCLUDED][0]); value["urls"][0] = f"https://{XXX}/r?i=0&kept=1+2%2B"
    with pytest.raises(ValueError): lineage.validate_enrollment(store, value)


def test_selected_mal_keeps_exact_reserve_pool_and_full_native20(current):
    _, child, _ = current; store = child()
    result, _ = enroll(store, lineage.INCLUDED, selected=True)
    assert result["enrollment"][0]["status"] == "enrolled"
    value = epochs._enrollments(store)[lineage.INCLUDED][0]
    original = study.candidate_pool(store.root)[lineage.INCLUDED]
    assert value["urls"] == original["urls"][2:22]
    assert value["source_occurrences"] == original["source_occurrences"]
    epochs._verify_preparation(store, lineage.INCLUDED)
