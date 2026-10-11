"""Prospective map/ledger controls, with explicit synthetic raw-proof boundaries.

These are not live reserve qualification or scientific session evidence.
"""
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, _create


HOSTS = ["alpha.example", "beta.example", lineage.EXCLUDED,
         *(f"class-{i:02d}.example" for i in range(47))]


def enrollment(store, host, *, native="a", readiness=True):
    path = f"inputs/{host}/workload.json"
    _create(store.root / path, canonical_json({"host": host}))
    value = {"hostname": host, "urls": [f"https://{host}/r?i={i}" for i in range(20)],
            "workload_path": path, "workload_sha256": sha256_file(store.root / path),
            "runtime": {"client_sha256": native * 64, "platform": "linux/arm64",
                        "source": {"neqo_commit": "c" * 40}},
            "mode_settings": {m: {} for m in MODES}, "mode_policies": {m: {} for m in MODES},
            "mode_readiness": {m: readiness for m in MODES}, "files": {path: sha256_file(store.root / path)},
            "scientific_credit": False}
    if host == lineage.INCLUDED:
        value["source_occurrences"] = study.candidate_pool(store.root)[host]["source_occurrences"]
    return value


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    # Exercise real SQLite/index authority without repeatedly fsyncing test fixtures.
    from qcsd_lab import resource_study_store as storage
    monkeypatch.setattr(storage.os, "fsync", lambda _: None)
    monkeypatch.setattr(storage, "_fsync", lambda _: None)
    monkeypatch.setattr(epochs, "docker_lock", nullcontext)
    source = tmp_path / "source.json"
    source.write_bytes(canonical_json([{"crUX_domain": "official.example", "resources": [
        {"resource_domain": h, "resource_urls": [f"https://{h}/r?i={i}" for i in range(20)]}
        for h in HOSTS]}]))
    parent = StudyStore(tmp_path / "parent")
    study.initialize(source, parent.root, storage_reserve_bytes=2 * 1024 ** 3)
    for host in HOSTS[:2]:
        parent.enroll(enrollment(parent, host))
    cells = {(h, m): epochs._cell(parent, h, m) for h in HOSTS[:2] for m in MODES}
    epochs._bind(parent, parent)
    epochs._publish(parent, [], cells, "initial", cells)
    inventory = tmp_path / "MAL.json"
    inventory.write_bytes(canonical_json({"urls": [{"url": f"https://{lineage.INCLUDED}/r?i={i}"}
                                                   for i in range(25)]}))
    inventory.chmod(0o444)
    def child(name="child", *, native="a", readiness=True, prepare_boundary=True, enroll_class=True):
        root = tmp_path / name
        lineage.initialize(parent.root, root, inventory, storage_reserve_bytes=2 * 1024 ** 3)
        store = StudyStore(root)
        if not enroll_class:
            return store
        value = lineage.bind_enrollment(store, enrollment(store, lineage.INCLUDED,
                                                        native=native, readiness=readiness))
        store.enroll(value)
        if prepare_boundary:
            monkeypatch.setattr(epochs, "_verify_preparation", lambda *a, **kw: None)
        return store
    return parent, child, inventory


def admit(parent, child, modes=MODES, change="replace-unused-class"):
    return epochs.create_epoch(parent.root, child.root, change=change,
        affected_hostnames=[lineage.INCLUDED], affected_modes=list(modes))


def rewrite(path, value):
    path.chmod(0o600)
    path.write_bytes(canonical_json(value))
    path.chmod(0o444)


def controlled_credit(store, attempt, *, commit=True):
    """Actual immutable ledger transaction, synthetic raw-verifier boundary."""
    enrolled = epochs._enrollments(store)[attempt["hostname"]][0]
    raw = attempt["path"] + "/raw.bin"
    _create(store.root / raw, b"unit fixture; no real capture claim")
    plan = store.plan(); study_sha = sha256_file(store.root / "study.json")
    value = {"schema_version":1,"record_type":"qcsd-resource-domain-session-verification-v1",
        "verified":True,"purpose":"formal","scientific_credit":True,
        **{k:attempt[k] for k in ("hostname","mode","slot","attempt_id")},
        "acceptance":network.ACCEPTANCE,"study_sha256":study_sha,
        "tuple_uniqueness_scope":network.TUPLE_SCOPE,
        "class_network":network.receipt_binding(plan,study_sha,attempt["hostname"]),
        "five_tuple":[plan["class_network"]["assignments"][attempt["hostname"]]["client_ipv4"],31000,"8.8.8.8",443,17],
        "files":{raw:sha256_file(store.root/raw)},"runtime":enrolled["runtime"],
        "workload_sha256":enrolled["workload_sha256"],"mode_settings":enrolled["mode_settings"][attempt["mode"]]}
    path=store.root/attempt["path"]/"session.json";_create(path,canonical_json(value))
    if commit:
        store.commit_verified(path,validator=lambda _,v:{"verified":True,"five_tuple":v["five_tuple"]})
    return path


def test_stable_map_keeps49_addresses_and_original_physical_policy(campaign):
    parent, child, _ = campaign
    old_raw = (parent.root / "study.json").read_bytes()
    old = parent.plan()
    new = child().plan()
    assignments = network.validate_network_plan(new)
    assert len(assignments) == 50 and lineage.EXCLUDED not in assignments
    assert assignments[lineage.INCLUDED] == old["class_network"]["assignments"][lineage.EXCLUDED]
    assert all(assignments[h] == a for h, a in old["class_network"]["assignments"].items() if h != lineage.EXCLUDED)
    assert new["acceptance"] == old["acceptance"] == network.ACCEPTANCE
    assert new["source_sha256"] == old["source_sha256"]
    assert (parent.root / "study.json").read_bytes() == old_raw
    binding = network.receipt_binding(new, "f" * 64, lineage.INCLUDED)
    assert binding["record_type"] == lineage.MAP
    assert binding["mapping_sha256"] != network.mapping_sha256(old)


@pytest.mark.parametrize("change", ["retained-client", "retained-subnet", "reserve-slot", "extra-class",
    "wrong-predecessor", "chained-predecessor", "selection-hosts", "selection-source", "reserve-order",
    "parent-path", "inventory-ref", "missing-selection", "legacy-downgrade", "partial"])
def test_map_and_selection_mutations_fail_closed(campaign, change):
    parent, child, _ = campaign
    plan = deepcopy(child().plan())
    value, selection = plan["class_network"], plan["class_selection"]
    if change == "retained-client": value["assignments"]["alpha.example"]["client_ipv4"] = "10.232.0.99"
    elif change == "retained-subnet": value["assignments"]["alpha.example"]["subnet"] = "10.232.1.248/29"
    elif change == "reserve-slot": value["assignments"][lineage.INCLUDED] = deepcopy(value["assignments"]["alpha.example"])
    elif change == "extra-class": value["assignments"]["extra.example"] = deepcopy(value["assignments"][lineage.INCLUDED])
    elif change == "wrong-predecessor": value["predecessor"]["assignments"]["alpha.example"]["router_ipv4"] = "10.232.0.99"
    elif change == "chained-predecessor": value["predecessor"] = deepcopy(value)
    elif change == "selection-hosts": selection["selected_hostnames"][-1] = lineage.EXCLUDED
    elif change == "selection-source": selection["source_sha256"] = "e" * 64
    elif change == "reserve-order": selection["reserve_order"].reverse()
    elif change == "parent-path": selection["parent_root"] += "/../other"
    elif change == "inventory-ref": selection["reserve_inventory"]["path"] = "other.json"
    elif change == "missing-selection": plan.pop("class_selection")
    elif change == "legacy-downgrade": plan["class_network"] = deepcopy(parent.plan()["class_network"])
    elif change == "partial": plan.pop("class_network"); plan["acceptance"] = study.ACCEPTANCE
    if "class_network" in plan: selection["mapping_sha256"] = lineage.digest(plan["class_network"])
    with pytest.raises(ValueError): network.validate_network_plan(plan)


@pytest.mark.parametrize("which", [lineage.MANIFEST, lineage.INVENTORY, lineage.SOURCE])
@pytest.mark.parametrize("change", ["missing", "mutable", "bytes", "hardlink"])
def test_context_requires_actual_immutable_single_file_source_and_inventory(campaign, which, change):
    _, child, _ = campaign
    store = child()
    path = store.root / which
    if change == "missing": path.unlink()
    elif change == "mutable": path.chmod(0o644)
    elif change == "bytes": path.chmod(0o600); path.write_bytes(b"{}"); path.chmod(0o444)
    elif change == "hardlink": path.with_name("borrowed.json").hardlink_to(path)
    with pytest.raises((ValueError, OSError)): store.plan()


def test_fresh_candidate_cannot_allocate_credit_or_gain_membership_by_regular_add_host(campaign):
    parent, child, _ = campaign
    store = child()
    with pytest.raises(ValueError, match="committed parent"):
        store.allocate_attempt(lineage.INCLUDED, "front", purpose="pilot")
    with pytest.raises(ValueError, match="explicit replace-unused-class"):
        admit(parent, store, change="add-host")
    assert epochs.status(parent.root)["accepted_count"] == 0


def test_transition_retains_exact_old_cells_and_rows_then_allows_same_selection_mode_addition(campaign, monkeypatch):
    parent, child, _ = campaign
    monkeypatch.setattr(epochs, "_pilot", lambda *a: None)
    attempt = parent.allocate_attempt("alpha.example", "front")
    controlled_credit(parent, attempt)
    with parent._transaction() as connection:
        before = [tuple(r) for r in connection.execute("SELECT * FROM accepted ORDER BY hostname,mode,slot")]
    old = deepcopy(epochs._records(parent)[-1])
    store = child()
    modes = [m for m in MODES if m != "buflo"]
    value = admit(parent, store, modes)
    assert value["record_type"] == lineage.ADMISSION
    assert value["exclusions"] == old["exclusions"]
    current = {(c["hostname"], c["mode"]): c for c in value["cells"]}
    assert all(current[(c["hostname"], c["mode"])] == c for c in old["cells"])
    with parent._transaction() as connection:
        assert [tuple(r) for r in connection.execute("SELECT * FROM accepted ORDER BY hostname,mode,slot")] == before
    progress = epochs.status(parent.root)
    assert progress["record_type"] == lineage.COMPOSITION
    assert progress["accepted_count"] == 1 and len(progress["selected_hostnames"]) == 50
    second = child("buflo")
    assert second.plan()["class_selection"] == store.plan()["class_selection"]
    admit(parent, second, ["buflo"], change="add-host")
    assert epochs.status(parent.root)["accepted_count"] == 1
    assert len(epochs.status(parent.root)["cells"]) == 15


@pytest.mark.parametrize("change", ["enrolled-excluded", "historical-selected", "active-member", "unclosed-flight", "orphan-session"])
def test_replacement_refuses_nonunused_class_or_unclosed_participating_member(campaign, change):
    parent, child, _ = campaign
    if change == "enrolled-excluded": parent.enroll(enrollment(parent, lineage.EXCLUDED))
    elif change == "historical-selected":
        records = epochs._records(parent)
        cells = {(c["hostname"], c["mode"]): c for c in records[-1]["cells"]}
        foreign = deepcopy(next(iter(cells.values())))
        foreign["hostname"] = lineage.EXCLUDED
        cells[(lineage.EXCLUDED, foreign["mode"])] = foreign
        epochs._publish(parent, records, cells, "add-host", [(lineage.EXCLUDED, foreign["mode"])])
    elif change == "active-member": parent.allocate_attempt("alpha.example", "front", purpose="pilot")
    elif change == "unclosed-flight": _create(parent.root / "flights/unit/launched.json", canonical_json({}))
    elif change == "orphan-session": (parent.root / "attempts" / lineage.EXCLUDED).mkdir(parents=True)
    with pytest.raises(ValueError): child()


@pytest.mark.parametrize("change", ["wrong-native", "unqualified", "stale-head", "wrong-root", "pre-attempt"])
def test_admission_keeps_runtime_qualification_predecessor_and_freshness_fences(campaign, monkeypatch, change):
    parent, child, _ = campaign
    store = child(native="b" if change == "wrong-native" else "a", readiness=change != "unqualified")
    if change == "stale-head":
        records = epochs._records(parent)
        cells = {(c["hostname"], c["mode"]): c for c in records[-1]["cells"]}
        epochs._publish(parent, records, cells, "qualification", [])
    elif change == "wrong-root":
        old = epochs._records(parent)[-1]
        selection = deepcopy(store.plan()["class_selection"]); selection["parent_root"] = str(parent.root / "other")
        transition = {"record_type": lineage.TRANSITION, "class_selection": selection,
                      "class_network": store.plan()["class_network"], "member_proof": lineage.unused(parent, epochs._records(parent))}
        with pytest.raises(ValueError): lineage.validate_transition(parent, [old], transition)
        return
    elif change == "pre-attempt":
        with store._transaction() as connection:
            connection.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("f"*32,lineage.INCLUDED,"front",1,1,"attempts/unit","failed","x","x","unit","capture",None,None,None))
    with pytest.raises(ValueError): admit(parent, store)
    assert epochs.status(parent.root)["record_type"] != lineage.COMPOSITION


def test_retired_hostname_cannot_be_enrolled_or_readmitted_through_original_root(campaign):
    parent, child, _ = campaign
    admit(parent, child())
    with pytest.raises(ValueError, match="retired"):
        parent.enroll(enrollment(parent, lineage.EXCLUDED))
    with pytest.raises(ValueError, match="selected50"):
        epochs.create_epoch(parent.root, parent.root, change="add-host",
            affected_hostnames=[lineage.EXCLUDED], affected_modes=["front"])


def test_old_map_roots_use_new_lineage_code_only_after_transition(campaign):
    parent,child,_=campaign
    assert not epochs.stable_lineage_active(parent)
    old_plan=(parent.root/"study.json").read_bytes()
    admit(parent,child())
    assert epochs.stable_lineage_active(parent)
    assert "class_selection" not in parent.plan()
    assert (parent.root/"study.json").read_bytes()==old_plan
    assert "resource_study_lineage.py" in study.coordinator_provenance(class_selection=epochs.stable_lineage_active(parent))["files"]


def test_unrelated_map_or_wrong_cell_assignment_never_get_profile_normalization(campaign):
    parent, child, _ = campaign
    store = child()
    records = epochs._records(parent)
    transition = {"record_type": lineage.TRANSITION, "class_selection": store.plan()["class_selection"],
                  "class_network": store.plan()["class_network"], "member_proof": lineage.unused(parent, records)}
    candidate = deepcopy(epochs._cell(store, lineage.INCLUDED, "front"))
    candidate["definition"]["network"]["assignment"] = deepcopy(parent.plan()["class_network"]["assignments"]["alpha.example"])
    cells = {(c["hostname"],c["mode"]):c for c in records[-1]["cells"]}
    with pytest.raises(ValueError, match="lineage/address"):
        epochs._check_added_cell(cells, candidate, transition=transition)


def test_bad_native_preparation_is_replayed_before_parent_publication(campaign, monkeypatch):
    parent, child, _ = campaign
    store = child(prepare_boundary=False)
    before = deepcopy(epochs._records(parent)[-1])
    # Actual full verifier sees no Native GET artifacts in this metadata-only fixture.
    with pytest.raises((ValueError, KeyError, OSError)): admit(parent, store)
    assert epochs._records(parent)[-1] == before
    assert store.status()["accepted_count"] == 0


def test_new_receipt_joins_its_own_v3_plan_and_cannot_borrow_old_map(campaign):
    parent, child, _ = campaign
    store = child(); plan = store.plan(); host = lineage.INCLUDED
    digest = sha256_file(store.root / "study.json")
    receipt = {"hostname":host,"acceptance":network.ACCEPTANCE,"study_sha256":digest,
        "tuple_uniqueness_scope":network.TUPLE_SCOPE,"class_network":network.receipt_binding(plan,digest,host),
        "five_tuple":[plan["class_network"]["assignments"][host]["client_ipv4"],31000,"8.8.8.8",443,17]}
    assert network.validate_receipt_network(plan,digest,receipt)
    receipt["class_network"]["mapping_sha256"] = network.mapping_sha256(parent.plan())
    with pytest.raises(ValueError): network.validate_receipt_network(plan,digest,receipt)


def test_default_provenance_unchanged_new_context_explicitly_bound():
    original = study.coordinator_provenance()["files"]
    contextual = study.coordinator_provenance(class_selection=True)["files"]
    assert len(original) == 14 and len(contextual) == 15
    assert original["resource_study_integrity.py"] == sha256_file(
        Path(study.__file__).with_name("resource_study_integrity.py"))
    assert "resource_study_lineage.py" not in original
    assert set(contextual) - set(original) == {"resource_study_lineage.py"}
    assert {k: v for k, v in contextual.items() if k != "resource_study_lineage.py"} == original
    assert contextual["resource_study_lineage.py"] == sha256_file(Path(lineage.__file__))


def test_raw_receipt_selection_reader_never_opens_store_or_sqlite(campaign, monkeypatch):
    import sqlite3
    parent, child, _ = campaign
    store = child()
    plan, value = store.plan(), epochs._enrollments(store)[lineage.INCLUDED][0]
    def forbidden(*args, **kwargs):
        raise AssertionError("raw proof worker opened a ledger")
    monkeypatch.setattr(StudyStore, "__init__", forbidden)
    monkeypatch.setattr(StudyStore, "_transaction", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    lineage.validate_receipt_enrollment(store.root, plan, value)
    bad = deepcopy(value); bad["urls"][0] += "&invented=1"
    with pytest.raises(ValueError): lineage.validate_receipt_enrollment(store.root, plan, bad)


def test_fence_binds_exact_schema_rows_selection_and_head_and_defaults_to_deny(campaign, monkeypatch):
    import sqlite3
    parent, child, _ = campaign
    monkeypatch.setattr(epochs, "_pilot", lambda *a: None)
    old_attempt = parent.allocate_attempt("alpha.example", "front")
    controlled_credit(parent, old_attempt)
    with parent._transaction() as connection:
        before = lineage._rows(connection)
    oldhead = lineage.digest(epochs._records(parent)[-1])
    new = child(); record = admit(parent, new)
    assert set(record["write_fences"]) == {str(parent.root), str(new.root)}
    with parent._transaction() as connection:
        fence = lineage.check_fence_connection(parent, connection, expected_sha=record["write_fences"][str(parent.root)])
        after = lineage._rows(connection)
        assert {k:v for k,v in after.items() if k != "meta"} == {k:v for k,v in before.items() if k != "meta"}
        assert {k:v for k,v in after["meta"] if k != "epoch_head"} == {k:v for k,v in before["meta"] if k != "epoch_head"}
        assert dict(after["meta"])["epoch_head"] != dict(before["meta"])["epoch_head"]
        assert fence["historical_rows_sha256"] == lineage.digest(before)
        assert fence["predecessor_admission_sha256"] == oldhead
        assert fence["selection_sha256"] == lineage.digest(new.plan()["class_selection"])
        assert len(fence["ddl"]) == 15
        with pytest.raises(sqlite3.IntegrityError, match="write fence"):
            connection.execute("UPDATE accepted SET verified_at='invented'")
        with pytest.raises(sqlite3.IntegrityError, match="write fence"):
            connection.execute("DELETE FROM classes")
        for sql in ("UPDATE meta SET value='invented' WHERE key='study_sha256'",
                    "UPDATE meta SET value='invented' WHERE key='epoch_head'",
                    "INSERT INTO meta VALUES('invented','value')", "DELETE FROM meta"):
            with pytest.raises(sqlite3.IntegrityError, match="write fence"):
                connection.execute(sql)
    # The protected hook grants only this active cell's reservation and state writes.
    parent.enroll(enrollment(parent, "class-00.example"))
    assert any(row["hostname"] == "class-00.example" for row in parent.enrolled())
    with pytest.raises(ValueError, match="excluded"):
        parent.allocate_attempt("class-00.example", "front", purpose="pilot")
    attempt = parent.allocate_attempt("alpha.example", "front", purpose="pilot")
    parent.mark_captured(attempt["attempt_id"])
    parent.fail_attempt(attempt["attempt_id"], "zero-credit unit pilot", kind="pilot")
    assert parent.status()["accepted_count"] == 1
    with parent._transaction() as connection:
        assert connection.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()[0] == "failed"
    # A new formal transaction still runs its existing raw verifier and adds one row.
    fresh = parent.allocate_attempt("alpha.example", "tamaraw")
    controlled_credit(parent, fresh)
    assert epochs.status(parent.root)["accepted_count"] == 2


@pytest.mark.parametrize("change", ["drop-trigger", "alter-trigger", "new-schema", "fence-bytes", "fence-mutable", "head-ref"])
def test_fence_tampering_refuses_without_read_time_healing(campaign, change):
    import sqlite3
    parent, child, _ = campaign
    admit(parent, child())
    if change in {"drop-trigger", "alter-trigger", "new-schema"}:
        with sqlite3.connect(parent.database) as connection:
            if change == "new-schema": connection.execute("CREATE TABLE extraneous(value TEXT)")
            else:
                name = next(iter(lineage.fence_ddl()))
                connection.execute("DROP TRIGGER " + name)
                if change == "alter-trigger": connection.execute(f"CREATE TRIGGER {name} BEFORE INSERT ON classes BEGIN SELECT 1; END")
    elif change == "fence-bytes": rewrite(parent.root / lineage.FENCE, {})
    elif change == "fence-mutable": (parent.root / lineage.FENCE).chmod(0o644)
    else:
        records = epochs._records(parent); bad = deepcopy(records[-1]); bad["write_fences"][str(parent.root)] = "f" * 64
        rewrite(parent.root / "epoch-admissions/000001.json", bad)
        with parent._transaction() as connection:
            with pytest.raises(sqlite3.IntegrityError, match="write fence"):
                connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'", (canonical_json({"sequence":1,"sha256":lineage.digest(bad)}).decode(),))
    with pytest.raises((ValueError, OSError)): epochs.status(parent.root)


def test_head_publication_scope_is_exact_and_has_no_other_write_rights(campaign):
    import sqlite3
    parent, child, _ = campaign
    admit(parent, child())
    with epochs._lock(parent.root):
        records = epochs._records(parent)
        value = {**deepcopy(records[-1]), "sequence":len(records), "previous_sha256":lineage.digest(records[-1]),
                 "change":"qualification", "affected":[]}
        _create(parent.root / "epoch-admissions/000002.json", canonical_json(value))
        with lineage.publication_scope(parent, records, value):
            for sql in ("UPDATE meta SET value='wrong' WHERE key='epoch_head'",
                        "UPDATE meta SET value='wrong' WHERE key='study_sha256'",
                        "DELETE FROM meta", "DELETE FROM classes"):
                with parent._transaction() as connection, pytest.raises(sqlite3.IntegrityError, match="write fence"):
                    connection.execute(sql)
            with parent._transaction() as connection:
                connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                    (canonical_json({"sequence":2,"sha256":lineage.digest(value)}).decode(),))
            with parent._transaction() as connection, pytest.raises(sqlite3.IntegrityError, match="write fence"):
                connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                    (canonical_json({"sequence":1,"sha256":lineage.digest(records[-1])}).decode(),))
    assert epochs._records(parent)[-1] == value
    assert epochs.status(parent.root)["accepted_count"] == 0


@pytest.mark.parametrize("change", ["record-bytes", "fence-ref", "old-head", "wrong-parent"])
def test_head_publication_refuses_unbound_record_fences_predecessor_or_parent(campaign, change):
    parent, child, _ = campaign
    admit(parent, child())
    with epochs._lock(parent.root):
        records = epochs._records(parent)
        value = {**deepcopy(records[-1]), "sequence":len(records), "previous_sha256":lineage.digest(records[-1]),
                 "change":"qualification", "affected":[]}
        if change == "fence-ref": value["write_fences"][str(parent.root)]="f"*64
        elif change == "old-head": value["previous_sha256"]="f"*64
        elif change == "wrong-parent": value["parent_study_sha256"]="f"*64
        _create(parent.root / "epoch-admissions/000002.json", canonical_json(value))
        if change == "record-bytes": value["affected"]=[["alpha.example","front"]]
        with pytest.raises(ValueError):
            with lineage.publication_scope(parent, records, value):
                raise AssertionError("unbound meta publication authorized")
    assert epochs.status(parent.root)["accepted_count"] == 0


def test_fenced_recovery_has_only_existing_active_rows_and_no_credit(campaign):
    parent, child, _ = campaign
    new = child(); admit(parent, new)
    attempt = new.allocate_attempt(lineage.INCLUDED, "front", purpose="pilot")
    result = new.recover()
    assert result["interrupted"] == [attempt["attempt_id"]] and result["accepted_count"] == 0


def test_new_source_rejects_retired_enrollment_before_publication(campaign):
    parent, child, _ = campaign
    admit(parent, child())
    value = enrollment(parent, lineage.EXCLUDED)
    with pytest.raises(ValueError, match="retired"): parent.enroll(value)
    assert not (parent.root / "classes" / lineage.EXCLUDED).exists()
    class NoBackend:
        def prepare(self, *args, **kwargs):
            raise AssertionError("retired selection reached preparation")
    with pytest.raises(ValueError, match="retired"):
        study.enroll(parent.root, {}, [lineage.EXCLUDED], backend=NoBackend())
    assert not (parent.root / "enrollment-attempts" / lineage.EXCLUDED).exists()


def test_actual_old008_store_cannot_commit_enrollment_attempt_or_credit(campaign, monkeypatch, tmp_path):
    """Optional authenticated old-source control, run explicitly in migration review."""
    import os
    import subprocess
    import sys
    old_source = os.environ.get("QCSD_OLD008_SOURCE")
    if old_source is None:
        pytest.skip("requires separately authenticated exact old008 source checkout")
    identity = subprocess.run(["git", "-C", old_source, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    assert identity.stdout.strip() == "ca24db4354f018e455a7965061aa67d8303c0f0c"
    clean = subprocess.run(["git", "-C", old_source, "status", "--porcelain"], capture_output=True, text=True, check=True)
    assert clean.stdout == ""
    parent, child, _ = campaign
    monkeypatch.setattr(epochs, "_pilot", lambda *a: None)
    admit(parent, child())
    value = enrollment(parent, lineage.EXCLUDED)
    fixture = tmp_path / "old008-enrollment.json"; fixture.write_bytes(canonical_json(value))
    attempt = parent.allocate_attempt("alpha.example", "front")
    receipt = controlled_credit(parent, attempt, commit=False)
    with parent._transaction() as connection:
        before = lineage._rows(connection)
    code = '''import json,sys,sqlite3
sys.path.insert(0,sys.argv[1]+"/src")
from qcsd_lab.resource_study_store import StudyStore
s=StudyStore(sys.argv[2]); outcomes=[]
assert s.status()["accepted_count"] == 0  # Historical read APIs need no SQL function.
def meta(sql):
 with s._transaction() as connection:connection.execute(sql)
for name,call in [
 ("enroll",lambda:s.enroll(json.load(open(sys.argv[3])))),
 ("attempt",lambda:s._allocate_attempt("beta.example","front")),
 ("credit",lambda:s._commit_verified(sys.argv[4],validator=lambda root,v:{"verified":True,"five_tuple":v["five_tuple"]})),
 ("meta-insert",lambda:meta("INSERT INTO meta VALUES('invented','value')")),
 ("meta-update",lambda:meta("UPDATE meta SET value='invented' WHERE key='study_sha256'")),
 ("meta-delete",lambda:meta("DELETE FROM meta WHERE key='epoch_head'"))]:
 try: call()
 except sqlite3.OperationalError as e:
  assert "qcsd_class_v3_write_allowed" in str(e),str(e);outcomes.append(name)
 else: raise AssertionError(name+" bypassed stable fence")
print(json.dumps({"refused_before_commit":outcomes}))
'''
    run = subprocess.run([sys.executable, "-I", "-B", "-c", code, old_source, str(parent.root), str(fixture), str(receipt)],
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    assert '"refused_before_commit": ["enroll", "attempt", "credit", "meta-insert", "meta-update", "meta-delete"]' in run.stdout
    with parent._transaction() as connection:
        assert lineage._rows(connection) == before
    # Old _create precedes its INSERT: retain this failed nonadmission, never count it.
    assert (parent.root / "classes" / lineage.EXCLUDED / "enrollment.json").exists()
    assert parent.status()["accepted_count"] == 0
    with pytest.raises(ValueError, match="forbidden artifacts"): epochs.status(parent.root)


def test_bound_pretransition_flights_are_rechecked_and_bad_cleanup_refuses(campaign):
    parent, child, _ = campaign
    launch=parent.root/"flights/unit/launched.json";close=launch.with_name("closed.json")
    _create(launch,canonical_json({"scientific_credit":False}))
    _create(close,canonical_json({"cleanup_errors":[],"scientific_credit":False}))
    store=child();admit(parent,store)
    records=epochs._records(parent)
    assert records[-1]["class_transition"]["member_proof"][0]["closed_flights"]
    rewrite(close,{"cleanup_errors":["changed"],"scientific_credit":False})
    with pytest.raises(ValueError):epochs._records(parent)


def test_historical_admission_schema_cannot_resume_after_versioned_transition(campaign):
    import sqlite3
    parent,child,_=campaign
    value=admit(parent,child())
    assert value["record_type"]!=epochs.TYPE
    assert set(value)!={"record_type","sequence","previous_sha256","parent_study_sha256","change","affected","cells","exclusions"}
    records=epochs._records(parent)
    downgraded=deepcopy(value);downgraded.pop("class_transition");downgraded["record_type"]=epochs.TYPE
    path=parent.root/"epoch-admissions"/f'{value["sequence"]:06d}.json'
    rewrite(path,downgraded)
    with parent._transaction() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="write fence"):
            connection.execute("UPDATE meta SET value=? WHERE key='epoch_head'",
                (canonical_json({"sequence":value["sequence"],"sha256":lineage.digest(downgraded)}).decode(),))
    with pytest.raises(ValueError):epochs._records(parent)


@pytest.mark.parametrize("change", ["nested-root", "wrong-inventory", "existing-root"])
def test_candidate_initialization_refuses_wrong_scope_before_creating_child(campaign,tmp_path,change):
    parent,_,inventory=campaign
    root=tmp_path/"new-root"
    if change=="nested-root":root=parent.root/"new-root"
    elif change=="wrong-inventory":
        inventory=tmp_path/"other.json";inventory.write_bytes(canonical_json({"urls":[{"url":f"https://ahrefs.com/r?i={i}"} for i in range(20)]}))
    elif change=="existing-root":root.mkdir()
    with pytest.raises(ValueError):lineage.initialize(parent.root,root,inventory,storage_reserve_bytes=2*1024**3)
    if change!="existing-root":assert not root.exists()


def prepared_fixture(store, base, *, failure=None):
    """Synthetic complete GET rows for the untouched actual preparation reader."""
    from qcsd_lab import resource_study_native as native
    host = lineage.INCLUDED
    urls = [f"https://{host}/r?i={i}" for i in range(20)]
    manifest = native._manifest(host, urls, require_twenty=True)
    _create(base / "preparation-get/input.json", canonical_json(manifest))
    responses = [{"resource_id":r["id"],"url":r["url"],"request_headers":r["headers"],
        "response_headers":[[":status","200"],["content-length","2000"]],
        "status":200,"content_length":2000,"bytes":2000,"body_sha256":"b"*64,
        "request_stream_bytes":150,"complete":True,"outcome":"succeeded"} for r in manifest["resources"]]
    run = {"method":"GET","request_policy":"as-defined","seed":0,
        "workload_hash_sha256":sha256_file(base/"preparation-get/input.json"),
        "max_response_bytes":native.MAX_RESPONSE_BYTES,"completion_status":"complete",
        "error":None,"error_class":None,"terminal_evidence_render_errors":[],"migration_commit":"c"*40,
        "application_response_policy":"http-2xx-only-v1","application_workload_source_hash_sha256":None,
        "chaff_manifest_hash_sha256":None,"chaff_responses":[],"resolved_configuration":{"defense":{"kind":"none"}},
        "endpoints":[{"id":0,"origin":f"https://{host}/","negotiated_protocol":"h3"}],"responses":responses}
    completed = {"returncode":0,"timed_out":False,"client_unchanged":True,"client_sha256":"a"*64}
    if failure == "incomplete": run["responses"][0]["complete"] = False
    elif failure == "failed": run["responses"][0]["outcome"] = "failed"
    elif failure == "empty":
        run["responses"][0].update(bytes=0, content_length=0)
        run["responses"][0]["response_headers"][1][1] = "0"
    elif failure == "non2xx":
        run["responses"][0]["status"] = 404
        run["responses"][0]["response_headers"][0][1] = "404"
    elif failure == "missing": run["responses"].pop()
    elif failure == "native": run["migration_commit"] = "d"*40
    elif failure == "h2": run["endpoints"][0]["negotiated_protocol"] = "h2"
    elif failure == "terminal": completed["client_unchanged"] = False
    _create(base/"preparation-get/native/run.json",canonical_json(run))
    _create(base/"preparation-get/completed.json",canonical_json(completed))
    expected = [{k:r[k] for k in ("resource_id","status","bytes","body_sha256")} for r in responses]
    prepared = {**manifest,"preparation":{"role":native.ROLE,
        "actual_preparation_run":"preparation-get/native/run.json",
        "actual_preparation_run_sha256":sha256_file(base/"preparation-get/native/run.json"),
        "expected_responses":expected}}
    _create(base/"prepared-workload.json",canonical_json(prepared))
    _create(base/"resources.json",canonical_json(manifest))
    relative=base.relative_to(store.root).as_posix()
    value={"hostname":host,"urls":urls,"preparation_dir":relative,
        "paths":{"prepared_workload":relative+"/prepared-workload.json"},
        "workload_path":relative+"/resources.json","workload_sha256":sha256_file(base/"resources.json"),
        "runtime":{"client_sha256":"a"*64,"platform":"linux/arm64","source":{"neqo_commit":"c"*40}},
        "mode_settings":{m:{} for m in MODES},"mode_policies":{m:{} for m in MODES},
        "mode_readiness":dict.fromkeys(MODES,True),"scientific_credit":False,
        "source_occurrences":study.candidate_pool(store.root)[host]["source_occurrences"],
        "files":{p.relative_to(store.root).as_posix():sha256_file(p) for p in base.rglob("*") if p.is_file()}}
    if failure == "mutable": (base/"preparation-get/input.json").chmod(0o644)
    return value


@pytest.mark.parametrize("failure", [None,"incomplete","failed","empty","non2xx","missing","native","h2","terminal","mutable"])
def test_public_reserve_preparation_replays_full_raw20_before_enrollment(campaign, failure):
    parent, child, _ = campaign
    store=child(enroll_class=False,prepare_boundary=False)
    head=deepcopy(epochs._records(parent)[-1])
    class Backend:
        def prepare(self,candidate,output):
            return prepared_fixture(store,output/"prepared",failure=failure)
    runtime={"client_sha256":"a"*64,"platform":"linux/arm64","source":{"neqo_commit":"c"*40}}
    result=study.enroll(store.root,runtime,[lineage.INCLUDED],backend=Backend())
    assert result["enrollment"][0]["status"] == ("enrolled" if failure is None else "not-enrolled")
    assert len(store.enrolled()) == (1 if failure is None else 0)
    assert epochs._records(parent)[-1] == head
    if failure is None:
        admit(parent,store)
        assert epochs.status(parent.root)["accepted_count"] == 0


@pytest.mark.parametrize("failure", ["foreign-url","reorder","lost-occurrences","wrong-context"])
def test_actual_pool_and_occurrence_provenance_cannot_be_replaced(campaign,failure):
    _,child,_=campaign
    store=child(enroll_class=False)
    value=lineage.bind_enrollment(store,enrollment(store,lineage.INCLUDED))
    if failure=="foreign-url":value["urls"][-1]=f"https://{lineage.INCLUDED}/invented?i=999"
    elif failure=="reorder":value["urls"].reverse()
    elif failure=="lost-occurrences":value["source_occurrences"]=[]
    elif failure=="wrong-context":value["class_selection"]["selection_sha256"]="f"*64
    with pytest.raises(ValueError):store.enroll(value)
    assert store.enrolled()==[]
