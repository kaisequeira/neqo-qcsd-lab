"""Focused prospective supplemental-lineage controls, not live qualification.

The original public preparation, exact twenty-GET metadata reader, selection,
enrollment, parent admission and pure receipt reader run on disposable roots.
The Native GET producer and zero-credit pilot leaf are synthetic. Fsync is
omitted on disposable roots; these controls make no durability claim. The
external Docker lifecycle lock is omitted because this suite invokes no
Docker, VM, subprocess or capture backend; local authority/fence locks remain.
Historical enrollments and all original raw-verifier functions stay unchanged.
ROOT alone executes these HOST controls.
"""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import stat
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab import resource_study_selection as selection
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore
from tests.test_resource_study_selection_integration import Backend, RUNTIME, write


EURON = "static.euronews.com"
BING = "www.bing.com"
FLASH = "www.flashscore.com.mx"
HOSTS = (EURON, BING, FLASH)


def url(host, number):
    return f"https://{host}/r?i={number}&kept=1+2%2B"


def selected_enroll(store, host, urls):
    manifest = store.root.parent / (store.root.name + "-" + host + "-selection.json")
    digest = write(manifest, selection.make_manifest(store.root, host, urls))
    backend = Backend(store.root)
    result = study.enroll(store.root, RUNTIME, [host], backend=backend,
        resource_selection=manifest, resource_selection_sha256=digest)
    return result, backend


@contextmanager
def damaged_input(path, change):
    """Damage only a disposable fixture input and restore it before returning."""
    original, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
    try:
        if change == "missing":
            path.unlink()
        elif change == "mutable":
            path.chmod(0o644)
        elif change == "bytes":
            path.chmod(0o644)
            path.write_bytes(original + b"\n ")
            path.chmod(mode)
        else:
            raise AssertionError("unknown fixture damage")
        yield
    finally:
        if path.exists():
            path.chmod(0o644)
            path.write_bytes(original)
        else:
            path.write_bytes(original)
        path.chmod(mode)


@pytest.fixture(scope="module")
def prepared_context(tmp_path_factory):
    """One small actual public-API campaign shared by immutable reader cases."""
    base = tmp_path_factory.mktemp("cohort-input-authority")
    patch = pytest.MonkeyPatch()
    from qcsd_lab import resource_study_store as storage
    patch.setattr(storage.os, "fsync", lambda _: None)
    patch.setattr(storage, "_fsync", lambda _: None)
    patch.setattr(epochs, "docker_lock", nullcontext)
    patch.setattr(runtime, "docker_lock", nullcontext)
    patch.setattr(epochs, "_pilot", lambda *args: None)
    try:
        candidates = [*HOSTS, lineage.EXCLUDED,
            *(f"supplement-control-{number:02d}.example" for number in range(46))]
        source = base / "source.json"
        write(source, [{"crUX_domain": "official.example", "resources": [
            {"resource_domain": host, "resource_urls": [url(host, n) for n in range(30)]}
            for host in candidates]}])
        parent = StudyStore(base / "parent")
        study.initialize(source, parent.root, storage_reserve_bytes=2 * 1024**3)
        extra = base / "historical-supplement.json"
        write(extra, {"urls": [
            *[{"url": url(EURON, n % 28), "old_occurrence": n} for n in range(28)],
            *[{"url": url(host, n)} for host in (BING, FLASH) for n in range(30, 35)]]})
        study.add_inventories(parent.root, [extra])
        chosen = {EURON: [url(EURON, n) for n in range(2, 22)],
            **{host: [url(host, n) for n in range(5, 20)]
                + [url(host, n) for n in range(30, 35)] for host in (BING, FLASH)}}
        old_values, old_bytes = {}, {}
        for host in HOSTS:
            result, backend = selected_enroll(parent, host, chosen[host])
            assert result["enrollment"] == [{"hostname": host, "status": "enrolled", "resources": 20}]
            assert len(backend.calls) == 1
            path = parent.root / "classes" / host / "enrollment.json"
            old_bytes[host] = path.read_bytes()
            old_values[host] = json.loads(old_bytes[host])
        assert len(old_values[EURON]["source_occurrences"]) == 29
        epochs._bind(parent, parent)
        cells = {(host, "undefended"): epochs._cell(parent, host, "undefended") for host in HOSTS}
        epochs._publish(parent, [], cells, "initial", cells)
        reserve = base / "MAL.json"
        write(reserve, {"urls": [{"url": url(lineage.INCLUDED, n)} for n in range(25)]})
        mal = StudyStore(base / "mal")
        lineage.initialize(parent.root, mal.root, reserve, storage_reserve_bytes=2 * 1024**3)
        result = study.enroll(mal.root, RUNTIME, [lineage.INCLUDED], backend=Backend(mal.root))
        assert result["enrollment"][0]["status"] == "enrolled"
        epochs.create_epoch(parent.root, mal.root, change="replace-unused-class",
            affected_hostnames=[lineage.INCLUDED], affected_modes=["undefended"])
        sequence = {"value": 0}

        def fresh():
            sequence["value"] += 1
            store = StudyStore(base / ("fresh-%02d" % sequence["value"]))
            result = cohorts.initialize_cohort(parent.root, store.root)
            assert result["enrolled"] is result["admitted"] is result["scientific_credit"] is False
            return store

        new = fresh()
        new_values = {}
        for host in HOSTS:
            result, backend = selected_enroll(new, host, chosen[host])
            assert result["enrollment"] == [{"hostname": host, "status": "enrolled", "resources": 20}]
            assert len(backend.calls) == 1
            new_values[host] = epochs._enrollments(new)[host][0]
        yield SimpleNamespace(base=base, parent=parent, mal=mal, new=new, fresh=fresh,
            chosen=chosen, old_values=old_values, old_bytes=old_bytes, values=new_values)
    finally:
        patch.undo()


@pytest.mark.parametrize("host", HOSTS)
def test_public_prepare_preserves_frozen_twenty_and_original_supplement_bytes(prepared_context, host):
    c = prepared_context
    value = c.values[host]
    assert value["urls"] == c.chosen[host] == c.old_values[host]["urls"]
    assert value["workload_sha256"] == c.old_values[host]["workload_sha256"]
    assert value["source_occurrences"] == study.candidate_pool(c.new.root)[host]["source_occurrences"]
    binding = value[cohorts.INPUT_AUTHORITY_KEY]
    assert set(binding) == {"record_type", "context_path", "context_sha256"}
    assert binding["record_type"] == cohorts.INPUT_AUTHORITY_TYPE
    assert binding["context_path"] == cohorts.INPUT_CONTEXT
    context = c.new.root / cohorts.INPUT_CONTEXT
    assert value["files"][cohorts.INPUT_CONTEXT] == binding["context_sha256"] == sha256_file(context)
    assert stat.S_IMODE(context.stat().st_mode) == 0o444 and context.stat().st_nlink == 1
    proof = selection.validate_selection_proof(c.new.root, value)
    assert proof["scientific_credit"] is False
    epochs._verify_preparation(c.new, host)
    assert (c.parent.root / "classes" / host / "enrollment.json").read_bytes() == c.old_bytes[host]
    assert c.new.status()["accepted_count"] == c.new.status()["reserved"] == 0
    assert not (c.new.root / cohorts.MARKER).exists()
    primary = study.candidate_catalogue(c.new.root / lineage.SOURCE)["candidates"]
    primary = next(row for row in primary if row["hostname"] == host)
    if host == EURON:
        assert value["urls"] == primary["urls"][2:22]
        assert len(value["source_occurrences"]) == 29 > len(primary["source_occurrences"])
    else:
        assert len([u for u in value["urls"] if u not in primary["urls"]]) == 5


def test_new_receipt_binding_is_pure_file_validation_without_store_or_sql(prepared_context, monkeypatch):
    c = prepared_context
    plan = c.new.plan()

    def forbidden(*args, **kwargs):
        raise AssertionError("pure new-cohort receipt lineage opened a Store or ledger")

    monkeypatch.setattr(StudyStore, "__init__", forbidden)
    monkeypatch.setattr(StudyStore, "_transaction", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    for host in HOSTS:
        lineage.validate_receipt_enrollment(c.new.root, plan, c.values[host])


@pytest.mark.parametrize("failure", ["type", "context-path", "context-sha", "domain", "order", "url", "occurrences", "class-selection"])
def test_receipt_reader_rejects_changed_new_authority_or_frozen_treatment(prepared_context, failure):
    c = prepared_context
    value = deepcopy(c.values[BING])
    binding = value[cohorts.INPUT_AUTHORITY_KEY]
    if failure == "type": binding["record_type"] += "-unknown"
    elif failure == "context-path": binding["context_path"] = "inputs/other-context.json"
    elif failure == "context-sha": binding["context_sha256"] = "0" * 64
    elif failure == "domain": value["hostname"] = FLASH
    elif failure == "order": value["urls"].reverse()
    elif failure == "url": value["urls"][-1] = url(BING, 35)
    elif failure == "occurrences": value["source_occurrences"] = value["source_occurrences"][:-1]
    elif failure == "class-selection": value["class_selection"]["selection_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        lineage.validate_receipt_enrollment(c.new.root, c.new.plan(), value)


@pytest.mark.parametrize("host", [EURON, BING])
def test_new_context_cannot_silently_fall_back_to_original_retained49_authority(prepared_context, host):
    c = prepared_context
    value = deepcopy(c.values[host])
    value.pop(cohorts.INPUT_AUTHORITY_KEY)
    value["files"].pop(cohorts.INPUT_CONTEXT)
    with pytest.raises(ValueError):
        lineage.validate_receipt_enrollment(c.new.root, c.new.plan(), value)
    # The old production predicate still rejects both actual failure shapes;
    # a new typed authority, rather than editing historical provenance, is used.
    with pytest.raises(ValueError):
        lineage._legacy_validate_enrollment(c.new, value)


@pytest.mark.parametrize("failure", ["root", "parent", "predecessor"])
def test_self_consistent_local_hash_cannot_rebind_input_authority(prepared_context, failure):
    c = prepared_context
    path = c.new.root / cohorts.INPUT_CONTEXT
    original = path.read_bytes()
    context = json.loads(original)
    if failure == "root": context["root"] += "-other"
    elif failure == "parent": context["parent"]["root"] += "-other"
    elif failure == "predecessor": context["predecessor_sha256"] = "0" * 64
    value = deepcopy(c.values[BING])
    try:
        path.chmod(0o644)
        path.write_bytes(canonical_json(context))
        path.chmod(0o444)
        # Rebind both local hash declarations, so refusal comes from the
        # original root/parent/predecessor authority rather than a stale SHA.
        digest = sha256_file(path)
        value["files"][cohorts.INPUT_CONTEXT] = digest
        value[cohorts.INPUT_AUTHORITY_KEY]["context_sha256"] = digest
        with pytest.raises(ValueError):
            lineage.validate_receipt_enrollment(c.new.root, c.new.plan(), value)
    finally:
        path.chmod(0o644)
        path.write_bytes(original)
        path.chmod(0o444)
    lineage.validate_receipt_enrollment(c.new.root, c.new.plan(), c.values[BING])


def test_public_prepare_requires_exact_prior_selection_before_backend_or_attempt(prepared_context):
    c = prepared_context
    new = c.fresh()
    backend = Backend(new.root)
    with pytest.raises(ValueError):
        study.enroll(new.root, RUNTIME, [BING], backend=backend)
    different = [url(EURON, n) for n in range(3, 23)]
    manifest = c.base / "different-but-valid-primary-twenty.json"
    digest = write(manifest, selection.make_manifest(new.root, EURON, different))
    with pytest.raises(ValueError):
        study.enroll(new.root, RUNTIME, [EURON], backend=backend,
            resource_selection=manifest, resource_selection_sha256=digest)
    assert backend.calls == [] and new.enrolled() == []
    assert not (new.root / "enrollment-attempts").exists()
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


def test_public_prepare_joins_self_consistent_snapshot_to_actual_parent_head(prepared_context):
    c = prepared_context
    new = c.fresh()
    path = new.root / cohorts.INPUT_CONTEXT
    original = path.read_bytes()
    context = json.loads(original)
    context["predecessor"]["sequence"] += 1
    context["predecessor_sha256"] = lineage.digest(context["predecessor"])
    manifest = c.base / "correct-twenty-wrong-parent-snapshot.json"
    digest = write(manifest, selection.make_manifest(new.root, BING, c.chosen[BING]))
    backend = Backend(new.root)
    try:
        path.chmod(0o644)
        path.write_bytes(canonical_json(context))
        path.chmod(0o444)
        # All local snapshot hash declarations agree. Only the live preparation
        # reader, under the original parent lock, can join the actual head.
        with pytest.raises(ValueError):
            study.enroll(new.root, RUNTIME, [BING], backend=backend,
                resource_selection=manifest, resource_selection_sha256=digest)
    finally:
        path.chmod(0o644)
        path.write_bytes(original)
        path.chmod(0o444)
    assert backend.calls == [] and new.enrolled() == []
    assert not (new.root / "enrollment-attempts").exists()
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


def test_new_supplement_authority_cannot_promote_incomplete_native_twenty(prepared_context):
    c = prepared_context
    new = c.fresh()
    manifest = c.base / "correct-twenty-incomplete-native-response.json"
    digest = write(manifest, selection.make_manifest(new.root, BING, c.chosen[BING]))
    backend = Backend(new.root, failed_response=True)
    result = study.enroll(new.root, RUNTIME, [BING], backend=backend,
        resource_selection=manifest, resource_selection_sha256=digest)
    assert len(backend.calls) == 1
    assert result["enrollment"][0]["status"] == "not-enrolled" and new.enrolled() == []
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0
    assert not (new.root / cohorts.MARKER).exists()


@pytest.mark.parametrize("kind,change", [
    ("context", "mutable"), ("admission", "missing"),
    ("catalogue", "bytes"), ("inventory", "missing"), ("inventory", "mutable")])
def test_pure_receipt_reader_reauthenticates_active_supplement_inputs(prepared_context, kind, change):
    c = prepared_context
    catalogue = next(path for path in (c.new.root / "inputs/supplements").glob("*/catalogue.json")
        if EURON in {row["hostname"] for row in json.loads(path.read_bytes())["candidates"]})
    admission = next(path for path in (c.new.root / "inputs/supplement-admissions").glob("*.json")
        if json.loads(path.read_bytes())["catalogue_sha256"] == catalogue.parent.name)
    path = {"context": c.new.root / cohorts.INPUT_CONTEXT, "admission": admission,
        "catalogue": catalogue, "inventory": catalogue.parent / "inventory-001.json"}[kind]
    plan = c.new.plan()
    with damaged_input(path, change):
        with pytest.raises((ValueError, OSError)):
            lineage.validate_receipt_enrollment(c.new.root, plan, c.values[BING])
    lineage.validate_receipt_enrollment(c.new.root, plan, c.values[BING])
