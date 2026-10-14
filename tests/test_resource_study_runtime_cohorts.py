"""Prospective cohort ledger controls, not captures or runtime qualification.

The fixtures use actual immutable enrollment/receipt files and SQLite writes.
Only preparation and independent raw-proof leaves are controlled explicitly;
no write fence, admission reader, allocation or commit predicate is replaced.
The two synthetic Native tuples stand for distinct historical/new strata, not
the physical clients used by any study campaign. ROOT alone runs these tests.
"""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study as study
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import DuplicateSession, StudyStore, _create
from qcsd_lab.resource_study_supplements import load_inventory_candidates
from tests.test_resource_study_epochs import controlled_pilot as _controlled_pilot
from tests.test_resource_study_lineage import campaign, admit, enrollment as _enrollment, controlled_credit as _controlled_credit, rewrite


HOST = lineage.INCLUDED
MODE = "front"


def controlled_pilot(store, host, mode):
    _controlled_pilot(store, host, mode)
    path = store.root / "pilots" / host / mode / "controlled-boundary/session.json"
    value = json.loads(path.read_bytes())
    value["coordinator_provenance"] = study.coordinator_provenance(class_selection=True)
    rewrite(path, value)


def controlled_credit(store, attempt, *, commit=False):
    assert commit is False  # Every commit remains an explicit test action.
    path = _controlled_credit(store, attempt, commit=False)
    value = json.loads(path.read_bytes())
    value["coordinator_provenance"] = study.coordinator_provenance(class_selection=True)
    rewrite(path, value)
    return path


def first_mode_declaration(parent, new, path, *, hosts, modes, authorize=True):
    value = cohorts.first_mode_template(parent.root, new.root,
        affected_hostnames=hosts, affected_modes=modes)
    assert value["new_mode_authorized"] is False
    assert type(value["zero_prior_accepted"]) is int and value["zero_prior_accepted"] == 0
    assert value["runtime_is_analysis_stratum"] is True and "compatible_treatment" not in value
    if authorize:
        value["new_mode_authorized"] = True
        value["rationale"] = "Controlled first-mode unit declaration; no live qualification."
    _create(path, canonical_json(value))
    return path, sha256_file(path)


@contextmanager
def observed_transactions(monkeypatch, observe):
    """Control only an explicitly named read query, never writes or credit."""
    original = StudyStore._transaction

    class ReadObserver:
        def __init__(self, store, connection):
            self.store, self.connection = store, connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, sql, parameters=()):
            result = observe(self.store, " ".join(sql.split()), parameters)
            return self.connection.execute(sql, parameters) if result is None else result

    @contextmanager
    def transaction(store):
        with original(store) as connection:
            yield ReadObserver(store, connection)

    with monkeypatch.context() as patch:
        patch.setattr(StudyStore, "_transaction", transaction)
        yield


@pytest.fixture
def cohort_campaign(campaign, tmp_path, monkeypatch, request):
    parent, child, _ = campaign
    old = child("historical-native", native="a")
    admit(parent, old, modes=getattr(request, "param", study.MODES))
    raw_calls = []

    def raw_leaf(member, root, receipt):
        raw_calls.append((str(root), receipt["purpose"], receipt["runtime"]["client_sha256"]))
        return {"verified": True, "five_tuple": receipt.get("five_tuple")}

    # These are explicit synthetic raw-proof boundaries. The original pilot's
    # exact host/resource/enrollment/runtime checks and every ledger guard run.
    monkeypatch.setattr(epochs, "verify_receipt", lambda root, receipt: raw_leaf(None, root, receipt))
    monkeypatch.setattr(cohorts, "verify_receipt", lambda root, receipt: raw_leaf(None, root, receipt))
    controlled_pilot(old, HOST, MODE)
    sequence = {"root": 0, "declaration": 0}

    def credit(store, *, port=31000, path=None):
        if path is None:
            attempt = store.allocate_attempt(HOST, MODE)
            path = controlled_credit(store, attempt, commit=False)
            value = json.loads(path.read_bytes())
            value["five_tuple"][1] = port
            rewrite(path, value)
        store.commit_verified(path, validator=lambda root, value: {
            "verified": True, "five_tuple": value["five_tuple"]})
        return path

    old_receipt = credit(old)

    def fresh(*, change=None, native="b", change_mode=MODE):
        sequence["root"] += 1
        new = StudyStore(tmp_path / ("new-native-%02d" % sequence["root"]))
        initialized = cohorts.initialize_cohort(parent.root, new.root)
        assert initialized["enrolled"] is initialized["admitted"] is initialized["scientific_credit"] is False
        assert new.plan() == old.plan() and new.enrolled() == []
        value = deepcopy(epochs._enrollments(old)[HOST][0])
        workload = old._file(value["workload_path"])[0]
        if change == "workload":
            workload = canonical_json({"host": HOST, "changed-unit-workload": True})
        _create(new.root / value["workload_path"], workload)
        value["workload_sha256"] = sha256_file(new.root / value["workload_path"])
        value["files"][value["workload_path"]] = value["workload_sha256"]
        if change != "same-native":
            value["runtime"]["client_sha256"] = native * 64
            value["runtime"]["source"]["neqo_commit"] = "d" * 40
        candidate = load_inventory_candidates([new.root / lineage.INVENTORY])["candidates"][0]
        value["source_occurrences"] = candidate["source_occurrences"]
        if change == "urls":
            value["urls"] = candidate["urls"][1:21]
        elif change == "settings":
            value["mode_settings"][change_mode] = {"changed-unit-parameter": 1}
        elif change == "policies":
            value["mode_policies"][change_mode] = {"changed-unit-policy": True}
        elif change == "not-ready":
            value["mode_readiness"][change_mode] = False
        new.enroll(lineage.bind_enrollment(new, value))
        return new

    def declaration(new, *, approve=True, change=None):
        value = cohorts.compatibility_template(parent.root, new.root,
            affected_hostnames=[HOST], affected_modes=[MODE])
        if approve:
            value["compatible_treatment"] = True
            value["rationale"] = "Controlled unit declaration; no live admission or qualification."
        if change is not None:
            change(value)
        sequence["declaration"] += 1
        path = tmp_path / ("operator-declaration-%02d.json" % sequence["declaration"])
        _create(path, canonical_json(value))
        return path, sha256_file(path), value

    def append(new, *, approve=True, change=None):
        path, digest, _ = declaration(new, approve=approve, change=change)
        return cohorts.create_cohort(parent.root, new.root, path, digest)

    return SimpleNamespace(parent=parent, old=old, old_receipt=old_receipt,
        fresh=fresh, declaration=declaration, append=append, credit=credit,
        raw_calls=raw_calls, monkeypatch=monkeypatch)


def test_legacy_v3_has_no_cohort_allocation_or_count_override(cohort_campaign):
    c = cohort_campaign
    head = deepcopy(epochs._records(c.parent)[-1])
    assert head["record_type"] == lineage.ADMISSION
    assert cohorts.accepted_count(c.old, HOST, MODE) is None
    with c.old._transaction() as connection:
        assert cohorts.allocate_slots(c.old, HOST, MODE, connection) is None
    assert epochs._records(c.parent)[-1] == head
    assert epochs.status(c.parent.root)["accepted_count"] == 1
    assert not (c.old.root / cohorts.MARKER).exists()


def test_template_requires_explicit_operator_treatment_declaration(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    path, digest, value = c.declaration(new, approve=False)
    assert value["compatible_treatment"] is False
    assert value["runtime_is_analysis_stratum"] is True
    assert value["rationale"] == ""
    head = canonical_json(epochs._records(c.parent)[-1])
    with pytest.raises(ValueError):
        cohorts.create_cohort(c.parent.root, new.root, path, digest)
    assert canonical_json(epochs._records(c.parent)[-1]) == head
    assert c.old.status()["accepted_count"] == 1
    assert new.status()["accepted_count"] == 0
    assert not (new.root / cohorts.MARKER).exists()


@pytest.mark.parametrize("field,value", [
    ("schema_version", True),
    ("compatible_treatment", 1),
    ("runtime_is_analysis_stratum", False),
    ("rationale", ""),
    ("parent_study_sha256", "0" * 64),
    ("predecessor_admission_sha256", "0" * 64),
    ("retained_accepted_manifest_sha256", "0" * 64),
])
def test_failed_declaration_cannot_publish_or_add_credit(cohort_campaign, field, value):
    c = cohort_campaign
    new = c.fresh()
    head = canonical_json(epochs._records(c.parent)[-1])
    receipt = c.old_receipt.read_bytes()
    with pytest.raises(ValueError):
        c.append(new, change=lambda declaration: declaration.__setitem__(field, value))
    assert canonical_json(epochs._records(c.parent)[-1]) == head
    assert c.old_receipt.read_bytes() == receipt
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 0


@pytest.mark.parametrize("change", ["urls", "workload", "settings", "policies", "not-ready", "same-native"])
def test_native_stratum_cannot_change_the_original_twenty_resource_treatment(cohort_campaign, change):
    c = cohort_campaign
    head = canonical_json(epochs._records(c.parent)[-1])
    with pytest.raises(ValueError):
        c.append(c.fresh(change=change))
    assert canonical_json(epochs._records(c.parent)[-1]) == head
    assert c.old.status()["accepted_count"] == 1


def test_cohort_preserves_historical_receipt_and_uses_its_own_pilot(cohort_campaign, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    old_bytes = c.old_receipt.read_bytes()
    old_enrollment = deepcopy(epochs._enrollments(c.old)[HOST][0])
    original_file = StudyStore._file

    def no_historical_raw_replay(store, relative, digest=None):
        if store.root == c.old.root and str(relative).endswith("/raw.bin"):
            raise AssertionError("cohort declaration reopened historical capture bytes")
        return original_file(store, relative, digest)

    monkeypatch.setattr(StudyStore, "_file", no_historical_raw_replay)
    record = c.append(new)
    assert record["record_type"] == cohorts.ADMISSION
    entry = next(entry for entry in record["cohorts"] if (entry["hostname"], entry["mode"]) == (HOST, MODE))
    assert [member["cell"]["root"] for member in entry["members"]] == [str(c.old.root), str(new.root)]
    previous, current_member = entry["members"]
    assert previous["cell"]["definition"]["native"][0] == "a" * 64
    assert current_member["cell"]["definition"]["native"][0] == "b" * 64
    snapshot_ref = previous["frozen_accepted"]
    snapshot_path = c.parent.root / snapshot_ref["path"]
    assert sha256_file(snapshot_path) == snapshot_ref["sha256"]
    snapshot = json.loads(snapshot_path.read_bytes())
    assert snapshot["record_type"] == cohorts.SNAPSHOT
    assert snapshot["authority"] == "existing-accepted-SQL-rows; no new raw qualification"
    assert len(snapshot["rows"]) == 1
    assert snapshot["rows"][0]["receipt_sha256"] == sha256_file(c.old_receipt)
    assert snapshot["rows"][0]["root"] == str(c.old.root)
    assert current_member["frozen_accepted"] is None
    assert c.old_receipt.read_bytes() == old_bytes
    assert epochs._enrollments(c.old)[HOST][0] == old_enrollment
    assert len(old_enrollment["urls"]) == len(set(old_enrollment["urls"])) == 20
    current = epochs._enrollments(new)[HOST][0]
    assert current["urls"] == old_enrollment["urls"]
    assert current["workload_sha256"] == old_enrollment["workload_sha256"]
    assert current["mode_settings"] == old_enrollment["mode_settings"]
    assert current["mode_policies"] == old_enrollment["mode_policies"]
    assert old_enrollment["runtime"]["client_sha256"] == "a" * 64
    assert current["runtime"]["client_sha256"] == "b" * 64
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    assert new.status()["accepted_count"] == 0
    with pytest.raises(ValueError, match="pilot"):
        new.allocate_attempt(HOST, MODE)
    assert new.status()["reserved"] == 0
    controlled_pilot(new, HOST, MODE)
    path = c.credit(new, port=31001)
    assert json.loads(path.read_bytes())["runtime"]["client_sha256"] == "b" * 64
    assert c.old_receipt.read_bytes() == old_bytes
    assert c.old.status()["accepted_count"] == new.status()["accepted_count"] == 1
    status = cohorts.status(c.parent.root)
    assert status["accepted_count"] == 2
    assert status["raw_deep_verified"] is status["scientific_credit"] is False
    refs = {row["root"]: row for row in status["accepted"]}
    assert refs[str(c.old.root)]["native"][0] == "a" * 64
    assert refs[str(new.root)]["native"][0] == "b" * 64
    assert refs[str(c.old.root)]["cohort_id"] == previous["cohort_id"]
    assert refs[str(new.root)]["cohort_id"] == current_member["cohort_id"]


@pytest.mark.parametrize("change", ["hostname", "native", "enrollment", "workload", "settings", "policies"])
def test_new_cohort_pilot_cannot_borrow_another_binding(cohort_campaign, change):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    path = new.root / "pilots" / HOST / MODE / "controlled-boundary/session.json"
    value = json.loads(path.read_bytes())
    if change == "hostname": value["hostname"] = "alpha.example"
    elif change == "native": value["runtime"] = deepcopy(epochs._enrollments(c.old)[HOST][0]["runtime"])
    elif change == "enrollment": value["files"][value["artifact_paths"]["enrollment"]] = "0" * 64
    elif change == "workload": value["workload_sha256"] = "0" * 64
    elif change == "settings": value["mode_settings"] = {"changed": True}
    else: value["mode_policies"] = {"changed": True}
    rewrite(path, value)
    c.raw_calls.clear()
    with pytest.raises(ValueError, match="pilot"):
        new.allocate_attempt(HOST, MODE)
    assert c.raw_calls == [] and new.status()["reserved"] == 0
    assert cohorts.status(c.parent.root)["accepted_count"] == 1


def test_cross_root_tuple_collision_is_preserved_as_duplicate_without_credit(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    attempt = new.allocate_attempt(HOST, MODE)
    assert attempt["slot"] == 2
    path = controlled_credit(new, attempt, commit=False)
    with pytest.raises(DuplicateSession):
        new.commit_verified(path, validator=lambda root, value: {
            "verified": True, "five_tuple": value["five_tuple"]})
    assert path.exists() and new.status()["duplicate"] == 1
    assert new.status()["accepted_count"] == 0
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    with new._transaction() as connection:
        assert connection.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()[0] == "duplicate"
        assert connection.execute("SELECT count(*) FROM measurements WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
    replacement = new.allocate_attempt(HOST, MODE)
    assert replacement["slot"] == 2 and replacement["attempt"] > attempt["attempt"]


def test_pending_reservation_occupies_global_slot_and_recovers_without_credit(cohort_campaign, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    actual = cohorts.allocate_slots
    observed = []

    def observed_slots(*args):
        slots = actual(*args)
        observed.append(set(slots))
        return slots

    monkeypatch.setattr(cohorts, "allocate_slots", observed_slots)
    pending = new.allocate_attempt(HOST, MODE)
    assert pending["slot"] == 2 and observed[-1] == {1}
    with pytest.raises(ValueError):
        new.allocate_attempt(HOST, MODE)
    # The unchanged local pending gate precedes the global allocation hook.
    assert observed == [{1}] and new.status()["reserved"] == 1
    partial = new.root / pending["path"] / "partial.pcapng"
    partial.write_bytes(b"controlled interrupted bytes; never scientific credit")
    recovered = StudyStore(new.root).recover()
    assert recovered["interrupted"] == [pending["attempt_id"]]
    assert recovered["files_deleted"] == 0 and partial.exists()
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    replacement = new.allocate_attempt(HOST, MODE)
    assert replacement["slot"] == 2 and replacement["attempt_id"] != pending["attempt_id"]


def test_old_cohort_refuses_new_reservation_but_keeps_exact_idempotent_receipt(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    old_bytes = c.old_receipt.read_bytes()
    with pytest.raises(ValueError):
        c.old.allocate_attempt(HOST, MODE, purpose="pilot")
    assert c.old.commit_verified(c.old_receipt)["idempotent"] is True
    assert c.old_receipt.read_bytes() == old_bytes
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 0
    assert cohorts.status(c.parent.root)["accepted_count"] == 1


def test_preadmission_attempt_cannot_be_retained_as_credited_history(cohort_campaign):
    c = cohort_campaign
    pending = c.old.allocate_attempt(HOST, MODE)
    new = c.fresh()
    head = canonical_json(epochs._records(c.parent)[-1])
    with pytest.raises(ValueError):
        c.append(new)
    assert canonical_json(epochs._records(c.parent)[-1]) == head
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 0
    assert c.old.status()["reserved"] == 1 and pending["attempt_id"]


def test_global_four_hundred_limit_includes_old_credit_and_new_pending_slot(cohort_campaign):
    c = cohort_campaign
    # Real controlled commits, not invented accepted SQL rows or lowered quotas.
    # The fixture already contains its first historical accepted session.
    for number in range(1, 399):
        c.credit(c.old, port=31000 + number)
    assert c.old.status()["accepted_count"] == 399
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    last = new.allocate_attempt(HOST, MODE)
    assert last["slot"] == 400
    with pytest.raises(ValueError):
        new.allocate_attempt(HOST, MODE)
    assert new.status()["reserved"] == 1
    path = controlled_credit(new, last, commit=False)
    value = json.loads(path.read_bytes())
    value["five_tuple"][1] = 31399
    rewrite(path, value)
    c.credit(new, path=path)
    assert c.old.status()["accepted_count"] == 399 and new.status()["accepted_count"] == 1
    assert cohorts.status(c.parent.root)["accepted_count"] == 400
    with pytest.raises(ValueError, match="four hundred|400|quota"):
        new.allocate_attempt(HOST, MODE)
    assert new.status()["reserved"] == 0


def test_failed_receipt_verified_flag_is_not_a_credited_carry_reference(cohort_campaign):
    c = cohort_campaign
    attempt = c.old.allocate_attempt(HOST, MODE)
    failed = controlled_credit(c.old, attempt, commit=False)
    assert json.loads(failed.read_bytes())["verified"] is True
    c.old.fail_attempt(attempt["attempt_id"], "controlled request failure", kind="failed")
    raw = failed.read_bytes()
    new = c.fresh()
    c.append(new)
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    assert c.old.status()["failed"] == 1 and new.status()["accepted_count"] == 0
    assert failed.read_bytes() == raw


def test_unknown_verifier_contract_refuses_before_cohort_publication(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    head = canonical_json(epochs._records(c.parent)[-1])
    c.raw_calls.clear()
    with pytest.raises(ValueError):
        c.append(new, change=lambda declaration: declaration["verifier"].__setitem__("record_type", "unknown-unit-verifier-v99"))
    assert c.raw_calls == [] and canonical_json(epochs._records(c.parent)[-1]) == head
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 0


def test_old_idempotent_receipt_cannot_hide_changed_immutable_bytes(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    value = json.loads(c.old_receipt.read_bytes())
    value["runtime"]["client_sha256"] = "b" * 64
    rewrite(c.old_receipt, value)
    with pytest.raises(ValueError):
        c.old.commit_verified(c.old_receipt)
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 0


def test_healthy_undefended_keeps_original_root_runtime_and_credit_path(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    record = c.append(new)
    cells = {(cell["hostname"], cell["mode"]): cell for cell in record["cells"]}
    assert cells[(HOST, MODE)]["root"] == str(new.root)
    assert cells[(HOST, "undefended")]["root"] == str(c.old.root)
    assert cells[(HOST, "undefended")]["definition"]["native"][0] == "a" * 64
    controlled_pilot(c.old, HOST, "undefended")
    attempt = c.old.allocate_attempt(HOST, "undefended")
    path = controlled_credit(c.old, attempt, commit=False)
    c.old.commit_verified(path, validator=lambda root, value: {
        "verified": True, "five_tuple": value["five_tuple"]})
    assert json.loads(path.read_bytes())["runtime"]["client_sha256"] == "a" * 64
    assert cohorts.status(c.parent.root)["accepted_count"] == 2
    assert c.old.status()["accepted_count"] == 2 and new.status()["accepted_count"] == 0
    with pytest.raises(ValueError):
        new.allocate_attempt(HOST, "undefended", purpose="pilot")


def test_original_v3_reader_refuses_new_type_and_new_reader_keeps_explicit_dispatch(cohort_campaign):
    c = cohort_campaign
    legacy = epochs._legacy_records(c.parent)
    assert legacy == epochs._records(c.parent)
    new = c.fresh()
    record = c.append(new)
    with pytest.raises(ValueError):
        epochs._legacy_records(c.parent)
    assert epochs._records(c.parent)[-1] == record
    unsupported = deepcopy(record)
    unsupported["record_type"] = "qcsd-resource-domain-runtime-cohort-admission-v99"
    with pytest.raises(ValueError):
        cohorts._validate_record(c.parent, legacy, unsupported)
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 0


@pytest.mark.parametrize("change", ["member-contract", "reader-source", "reader-closure",
                                   "missing-producer", "producer-digest", "producer-name"])
def test_unknown_reader_or_malformed_producer_refuses_before_raw_leaf(cohort_campaign, change):
    c = cohort_campaign
    new = c.fresh()
    record = c.append(new)
    entry = next(entry for entry in record["cohorts"] if (entry["hostname"], entry["mode"]) == (HOST, MODE))
    member = deepcopy(entry["members"][0])
    receipt = json.loads(c.old_receipt.read_bytes())
    if change == "member-contract": member["verifier"]["implementation"] = "unsupported-unit-v99"
    elif change == "reader-source": member["verifier"]["files"]["resource_study_verify.py"] = "0" * 64
    elif change == "reader-closure": member["verifier"]["transitive_source_sha256"] = "0" * 64
    elif change == "missing-producer": receipt.pop("coordinator_provenance")
    elif change == "producer-digest": receipt["coordinator_provenance"]["files"]["resource_study_verify.py"] = "not-a-sha256"
    else: receipt["coordinator_provenance"]["files"]["../resource_study_verify.py"] = "0" * 64
    c.raw_calls.clear()
    with pytest.raises(ValueError, match="verifier|capture producer|SHA256"):
        cohorts.verify_by_contract(member, c.old.root, receipt)
    assert c.raw_calls == []


def test_historical_producer_differs_from_the_current_qualifying_reader_without_relabelling(cohort_campaign, monkeypatch):
    c = cohort_campaign
    attempt = c.old.allocate_attempt(HOST, MODE)
    path = controlled_credit(c.old, attempt, commit=False)
    receipt = json.loads(path.read_bytes())
    # ROOT supplied this actual historical producer digest. The fixture is
    # synthetic; it does not import an old reader or claim a live qualification.
    old_producer = "94c35857533eee942027155631cf3573856a9a477a86d55f6152fc086b8ed87a"
    receipt["coordinator_provenance"]["files"]["resource_study_verify.py"] = old_producer
    receipt["five_tuple"][1] = 31001
    rewrite(path, receipt)
    c.credit(c.old, path=path)
    bound_bytes, bound_sha = path.read_bytes(), sha256_file(path)
    new = c.fresh()
    record = c.append(new)
    entry = next(entry for entry in record["cohorts"] if (entry["hostname"], entry["mode"]) == (HOST, MODE))
    reader = entry["members"][0]["verifier"]
    assert reader == cohorts.verifier_contract()
    assert reader["files"]["resource_study_verify.py"] != old_producer
    original_leaf = cohorts.verify_receipt
    qualified = []

    def current_raw_leaf(root, value):
        qualified.append((value["attempt_id"], deepcopy(value["coordinator_provenance"])))
        return original_leaf(root, value)

    monkeypatch.setattr(cohorts, "verify_receipt", current_raw_leaf)
    value = cohorts.status(c.parent.root, deep=True)
    assert value["accepted_count"] == 2 and value["raw_deep_verified"] is True
    assert value["scientific_credit"] is False
    assert dict(qualified)[attempt["attempt_id"]] == receipt["coordinator_provenance"]
    ref = next(row for row in value["accepted"] if row["attempt_id"] == attempt["attempt_id"])
    assert ref["receipt_sha256"] == bound_sha
    assert value["qualifying_verifiers"][ref["verifier_sha256"]] == reader
    assert path.read_bytes() == bound_bytes and sha256_file(path) == bound_sha


def test_deep_dispatch_keeps_original_and_new_runtime_strata_distinct(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    c.credit(new, port=31001)
    c.raw_calls.clear()
    value = cohorts.status(c.parent.root, deep=True)
    assert value["accepted_count"] == 2 and value["raw_deep_verified"] is True
    assert value["complete"] is value["scientific_credit"] is False
    assert sorted(c.raw_calls) == sorted([
        (str(c.old.root), "formal", "a" * 64), (str(new.root), "formal", "b" * 64)])
    assert {row["native"][0] for row in value["accepted"]} == {"a" * 64, "b" * 64}


def test_allocation_filesystem_failure_keeps_failed_row_without_nested_parent_lock(cohort_campaign, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    original_lock = epochs._lock
    original_mkdir = Path.mkdir
    depth = {"value": 0}

    @contextmanager
    def no_recursive_parent_lock(root):
        assert depth["value"] == 0, "filesystem cleanup recursively reacquired the parent flock"
        with original_lock(root):
            depth["value"] += 1
            try:
                yield
            finally:
                depth["value"] -= 1

    def fail_attempt_directory(path, *args, **kwargs):
        if path.is_relative_to(new.root / "attempts"):
            raise OSError("controlled attempt directory failure")
        return original_mkdir(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(epochs, "_lock", no_recursive_parent_lock)
        patch.setattr(Path, "mkdir", fail_attempt_directory)
        with pytest.raises(OSError, match="controlled attempt directory"):
            new.allocate_attempt(HOST, MODE)
    assert depth["value"] == 0 and new.status()["failed"] == 1
    assert new.status()["reserved"] == new.status()["accepted_count"] == 0
    with pytest.raises(ValueError, match="authority|scope"):
        new._allocate_attempt(HOST, MODE)
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    replacement = new.allocate_attempt(HOST, MODE)
    assert replacement["slot"] == 2 and replacement["attempt"] == 2


def test_global_slot_guard_refuses_retained_slot_under_real_parent_authority(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    controlled_pilot(new, HOST, MODE)
    attempt = new.allocate_attempt(HOST, MODE)
    path = controlled_credit(new, attempt, commit=False)
    value = json.loads(path.read_bytes())
    value["five_tuple"][1] = 31001
    # The whole public commit also checks its original reservation. Here the
    # inner global guard independently sees a retained slot, under real scope,
    # without inventing an accepted row or an impossible concurrent admission.
    with epochs._lock(c.parent.root):
        records = epochs._records(c.parent)
        with cohorts._write_scope(new, c.parent, records, (HOST, MODE),
                [(HOST, MODE, attempt["attempt_id"])], {("attempts", "UPDATE")}):
            with new._transaction() as connection:
                assert cohorts.credit_conflict(new, connection, attempt, value, value["five_tuple"]) is None
                value["slot"] = 1
                refusal = cohorts.credit_conflict(new, connection, attempt, value, value["five_tuple"])
                assert type(refusal) is str and "global slot/tuple" in refusal
    assert new.status()["reserved"] == 1 and new.status()["accepted_count"] == 0
    assert cohorts.status(c.parent.root)["accepted_count"] == 1


def test_lost_committed_marker_cannot_fall_back_to_local_count(cohort_campaign):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    assert cohorts.accepted_count(new, HOST, MODE) == 1
    assert new.status()["accepted_count"] == 0
    (new.root / cohorts.MARKER).unlink()
    with pytest.raises((ValueError, OSError)):
        cohorts.accepted_count(new, HOST, MODE)
    with pytest.raises((ValueError, OSError)):
        new.allocate_attempt(HOST, MODE, purpose="pilot")
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


@pytest.mark.parametrize("cohort_campaign", [("front",)], indirect=True)
@pytest.mark.parametrize("mode", ["undefended", "tamaraw", "cs-buflo", "buflo"])
def test_first_mode_has_zero_carry_and_needs_its_own_exact_pilot(cohort_campaign, tmp_path, mode):
    c = cohort_campaign
    previous = deepcopy(epochs._records(c.parent)[-1])
    assert (HOST, mode) not in {(cell["hostname"], cell["mode"]) for cell in previous["cells"]}
    new = c.fresh()
    path, digest = first_mode_declaration(c.parent, new, tmp_path / "first-mode.json",
        hosts=[HOST], modes=[mode])
    record = cohorts.create_first_modes(c.parent.root, new.root, path, digest)
    assert record["record_type"] == cohorts.ADMISSION and record["change"] == "first-mode"
    entry = next(entry for entry in record["cohorts"] if (entry["hostname"], entry["mode"]) == (HOST, mode))
    assert len(entry["members"]) == 1 and entry["members"][0]["frozen_accepted"] is None
    member = entry["members"][0]
    template = epochs._cell(c.old, HOST, mode)
    actual = member["cell"]
    for field in ("urls", "workload_sha256", "settings", "policies", "network"):
        assert actual["definition"][field] == template["definition"][field]
    assert len(actual["definition"]["urls"]) == 20
    assert actual["definition"]["native"][0] == "b" * 64
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0
    assert cohorts.accepted_count(new, HOST, mode) == 0
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    with pytest.raises(ValueError, match="pilot"):
        new.allocate_attempt(HOST, mode)
    controlled_pilot(new, HOST, mode)
    attempt = new.allocate_attempt(HOST, mode)
    assert attempt["slot"] == 1
    receipt = controlled_credit(new, attempt, commit=False)
    new.commit_verified(receipt, validator=lambda root, value: {
        "verified": True, "five_tuple": value["five_tuple"]})
    assert cohorts.accepted_count(new, HOST, mode) == 1
    assert c.old.status()["accepted_count"] == 1 and new.status()["accepted_count"] == 1


@pytest.mark.parametrize("cohort_campaign", [("front",)], indirect=True)
@pytest.mark.parametrize("change", ["urls", "workload", "settings", "policies", "not-ready"])
def test_first_mode_cannot_change_frozen_resources_or_mode_template(cohort_campaign, tmp_path, change):
    c = cohort_campaign
    previous = canonical_json(epochs._records(c.parent)[-1])
    with pytest.raises(ValueError):
        new = c.fresh(change=change, change_mode="tamaraw")
        path, digest = first_mode_declaration(c.parent, new, tmp_path / "bad-first-mode.json",
            hosts=[HOST], modes=["tamaraw"])
        cohorts.create_first_modes(c.parent.root, new.root, path, digest)
    assert canonical_json(epochs._records(c.parent)[-1]) == previous
    assert c.old.status()["accepted_count"] == 1


@pytest.mark.parametrize("cohort_campaign", [("front",)], indirect=True)
def test_first_mode_requires_explicit_authority_and_refuses_an_existing_cell(cohort_campaign, tmp_path):
    c = cohort_campaign
    new = c.fresh()
    previous = canonical_json(epochs._records(c.parent)[-1])
    path, digest = first_mode_declaration(c.parent, new, tmp_path / "unauthorized-first-mode.json",
        hosts=[HOST], modes=["tamaraw"], authorize=False)
    with pytest.raises(ValueError):
        cohorts.create_first_modes(c.parent.root, new.root, path, digest)
    with pytest.raises(ValueError):
        cohorts.first_mode_template(c.parent.root, new.root,
            affected_hostnames=[HOST], affected_modes=["front"])
    assert canonical_json(epochs._records(c.parent)[-1]) == previous
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


def test_first_mode_public_admission_can_reach_all_two_hundred_fifty_cells(campaign, tmp_path):
    parent, child, _ = campaign
    old = child("all-selected-siblings", native="a")
    admit(parent, old, modes=["undefended"])
    selected = old.plan()["class_selection"]["selected_hostnames"]
    remaining = sorted(set(selected) - {"alpha.example", "beta.example", HOST})
    assert len(selected) == 50 and len(remaining) == 47

    def enroll_from_frozen_pool(store, hosts, native):
        pool = study.candidate_pool(store.root)
        for host in hosts:
            value = _enrollment(store, host, native=native)
            value["source_occurrences"] = pool[host]["source_occurrences"]
            store.enroll(lineage.bind_enrollment(store, value))

    enroll_from_frozen_pool(old, remaining, "a")
    epochs.create_epoch(parent.root, old.root, change="add-host",
        affected_hostnames=remaining, affected_modes=["undefended"])
    before = deepcopy(epochs._records(parent)[-1])
    assert len(before["cells"]) == 58
    hosts = sorted([HOST, *remaining])
    new = StudyStore(tmp_path / "all-first-modes")
    cohorts.initialize_cohort(parent.root, new.root)
    enroll_from_frozen_pool(new, hosts, "b")
    path, digest = first_mode_declaration(parent, new, tmp_path / "all-first-modes.json",
        hosts=hosts, modes=["front", "tamaraw", "cs-buflo", "buflo"])
    record = cohorts.create_first_modes(parent.root, new.root, path, digest)
    cells = {(cell["hostname"], cell["mode"]): cell for cell in record["cells"]}
    assert set(cells) == {(host, mode) for host in selected for mode in study.MODES}
    assert len(record["affected"]) == 192 and len(cells) == 250
    assert all(len(cell["definition"]["urls"]) == 20 for cell in cells.values())
    assert all(cells[(cell["hostname"], cell["mode"])] == cell for cell in before["cells"])
    status = cohorts.status(parent.root)
    assert status["accepted_count"] == 0 and status["total_sessions"] == 100000
    assert status["complete"] is status["scientific_credit"] is False
    assert all(cell["target"] == 400 and cell["accepted"] == 0 for cell in status["cells"])


def test_scheduler_count_snapshot_is_bounded_and_cannot_authorize_a_later_write(cohort_campaign, tmp_path, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    declaration = cohorts.compatibility_template(c.parent.root, new.root,
        affected_hostnames=[HOST], affected_modes=["front", "tamaraw"])
    declaration.update(compatible_treatment=True, rationale="Controlled two-cell snapshot only.")
    path = tmp_path / "two-cell-declaration.json"
    _create(path, canonical_json(declaration))
    cohorts.create_cohort(c.parent.root, new.root, path, sha256_file(path))
    original_records = epochs._records
    calls = []

    def observed_records(parent):
        calls.append(str(parent.root))
        return original_records(parent)

    with monkeypatch.context() as patch:
        patch.setattr(epochs, "_records", observed_records)
        snapshot = cohorts.counts_snapshot(new, [(HOST, "front"), (HOST, "tamaraw")])
    assert calls == [str(c.parent.root)]
    assert snapshot == {(HOST, "front"): 1, (HOST, "tamaraw"): 0}
    with pytest.raises(ValueError):
        cohorts.counts_snapshot(new, [(HOST, "undefended")])  # Another root owns this cell.
    (new.root / cohorts.MARKER).unlink()
    with pytest.raises((ValueError, OSError)):
        new.allocate_attempt(HOST, "front", purpose="pilot")
    assert snapshot == {(HOST, "front"): 1, (HOST, "tamaraw"): 0}
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


def test_operation_source_profile_hashes_at_boundaries_and_refuses_changed_or_closed_authority(cohort_campaign, tmp_path, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    c.append(new)
    source = Path(cohorts.__file__).parent
    private = tmp_path / "source-observation-fixture"
    private.mkdir()
    for name in cohorts.RAW_DEPENDENCIES:
        path = private / name
        path.write_bytes((source / name).read_bytes())
        path.chmod(stat.S_IMODE((source / name).stat().st_mode))
    original_hash = cohorts.sha256_file
    hashes = []

    def observed_hash(path):
        if Path(path).parent == private:
            hashes.append(Path(path).name)
        return original_hash(path)

    # Only temporary byte-identical source files are changed in this control.
    # No repository Source, reader implementation, ledger guard or raw gate is
    # replaced. Profile handoff is exercised on a genuine separate HOST thread.
    with monkeypatch.context() as patch:
        patch.setattr(cohorts, "__file__", str(private / "resource_study_cohorts.py"))
        patch.setattr(cohorts, "sha256_file", observed_hash)
        with cohorts.source_operation(new) as auth:
            assert auth is not None
            contract = cohorts.verifier_contract()
            unchanged_contract = deepcopy(contract)
            contract["files"]["resource_study_verify.py"] = "0" * 64
            assert cohorts.verifier_contract() == unchanged_contract
            contract = unchanged_contract
            assert cohorts.counts_snapshot(new, [(HOST, MODE)]) == {(HOST, MODE): 1}

            def bound_worker():
                with cohorts.bind_source(auth):
                    return cohorts.verifier_contract()

            with ThreadPoolExecutor(max_workers=1) as executor:
                assert executor.submit(bound_worker).result(timeout=10) == contract
        assert set(hashes) == set(cohorts.RAW_DEPENDENCIES)
        assert all(hashes.count(name) == 2 for name in cohorts.RAW_DEPENDENCIES)
        with pytest.raises(ValueError):
            with cohorts.bind_source(auth):
                cohorts.verifier_contract()
        target = private / "resource_study_verify.py"
        unchanged = target.read_bytes()
        with pytest.raises(ValueError):
            with cohorts.source_operation(new) as damaged:
                target.write_bytes(unchanged + b"\n# controlled temporary Source change\n")
                try:
                    with pytest.raises(ValueError):
                        new.allocate_attempt(HOST, MODE, purpose="pilot")
                    assert new.status()["reserved"] == 0
                finally:
                    target.write_bytes(unchanged)
        with pytest.raises(ValueError):
            with cohorts.bind_source(damaged):
                cohorts.verifier_contract()
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


@pytest.mark.parametrize("cohort_campaign", [("front",)], indirect=True)
def test_first_mode_admission_rechecks_hidden_prior_credit_after_clean_template(cohort_campaign, tmp_path, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    path, digest = first_mode_declaration(c.parent, new, tmp_path / "clean-first-mode-template.json",
        hosts=[HOST], modes=["tamaraw"])
    previous = canonical_json(epochs._records(c.parent)[-1])
    checked = []

    def hidden_read(store, sql, parameters):
        if (sql == "SELECT 1 FROM accepted WHERE hostname=? AND mode=?"
                and tuple(parameters) == (HOST, "tamaraw")):
            checked.append(str(store.root))
            if store.root == c.old.root:
                # Simulate only this negative read result. No accepted row,
                # receipt, write authority or scientific credit is fabricated.
                return SimpleNamespace(fetchone=lambda: (1,))

    with observed_transactions(monkeypatch, hidden_read):
        with pytest.raises(ValueError, match="prior unadmitted accepted credit"):
            cohorts.create_first_modes(c.parent.root, new.root, path, digest)
    assert str(c.old.root) in checked
    assert canonical_json(epochs._records(c.parent)[-1]) == previous
    assert not (new.root / cohorts.MARKER).exists()
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


@pytest.mark.parametrize("cohort_campaign", [("front",)], indirect=True)
def test_retained_first_mode_uses_bound_zero_carry_and_keeps_selected_rows_fresh(cohort_campaign, tmp_path, monkeypatch):
    c = cohort_campaign
    new = c.fresh()
    path, digest = first_mode_declaration(c.parent, new, tmp_path / "retained-first-mode.json",
        hosts=[HOST], modes=["tamaraw"])
    record = cohorts.create_first_modes(c.parent.root, new.root, path, digest)
    selected_reads = []

    def no_unrelated_prior_scan(store, sql, parameters):
        if sql == "SELECT 1 FROM accepted WHERE hostname=? AND mode=?":
            raise AssertionError("retained ancestry reran the historical zero-prior-credit admission census")
        if (sql.startswith("SELECT * FROM accepted WHERE hostname=? AND mode=? ORDER BY")
                and store.root == new.root and tuple(parameters) == (HOST, "tamaraw")):
            selected_reads.append(str(store.root))

    with observed_transactions(monkeypatch, no_unrelated_prior_scan):
        assert epochs._records(c.parent)[-1] == record
        assert cohorts.accepted_count(new, HOST, "tamaraw") == 0
    assert selected_reads == [str(new.root)]
    assert new.status()["accepted_count"] == new.status()["reserved"] == 0


def test_initializer_exposes_real_candidate_pool_with_immutable_empty_local_context(cohort_campaign, tmp_path):
    c = cohort_campaign
    root = tmp_path / "candidate-ready-empty-cohort"
    result = cohorts.initialize_cohort(c.parent.root, root)
    new = StudyStore(root)
    pool = study.candidate_pool(root)
    assert new.plan() == c.old.plan()
    selected = new.plan()["class_selection"]["selected_hostnames"]
    assert len(selected) == 50 and set(selected) <= pool.keys()
    local_mal = load_inventory_candidates([root / lineage.INVENTORY])["candidates"][0]
    assert pool[HOST] == local_mal
    for relative in (lineage.MANIFEST, lineage.INVENTORY, lineage.SOURCE, "inputs/candidates.json"):
        old, copied = c.old.root / relative, root / relative
        assert copied.read_bytes() == old.read_bytes()
        assert sha256_file(copied) == sha256_file(old)
        assert copied.stat().st_nlink == old.stat().st_nlink == 1
        assert stat.S_IMODE(copied.stat().st_mode) == 0o444
        assert copied.stat().st_ino != old.stat().st_ino
    assert result["enrolled"] is result["admitted"] is result["scientific_credit"] is False
    assert new.enrolled() == [] and new.status()["accepted_count"] == 0
    with new._transaction() as connection:
        assert all(connection.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0
                   for table in ("classes", "attempts", "accepted"))
    assert not (root / cohorts.MARKER).exists() and not (root / "epoch-membership.json").exists()


@pytest.mark.parametrize("context", ["primary-catalogue", "supplement-admission", "supplement-catalogue", "supplement-inventory"])
@pytest.mark.parametrize("change", ["missing", "mutable"])
def test_initializer_refuses_incomplete_or_mutable_current_candidate_context(cohort_campaign, tmp_path, context, change):
    c = cohort_campaign
    admission = sorted((c.old.root / "inputs/supplement-admissions").glob("*.json"))[0]
    catalogue_sha = json.loads(admission.read_bytes())["catalogue_sha256"]
    base = c.old.root / "inputs/supplements" / catalogue_sha
    victim = {"primary-catalogue": c.old.root / "inputs/candidates.json",
              "supplement-admission": admission, "supplement-catalogue": base / "catalogue.json",
              "supplement-inventory": base / "inventory-001.json"}[context]
    previous = canonical_json(epochs._records(c.parent)[-1])
    if change == "missing":
        victim.unlink()
    else:
        victim.chmod(0o644)
    root = tmp_path / "refused-candidate-context"
    with pytest.raises((ValueError, OSError)):
        cohorts.initialize_cohort(c.parent.root, root)
    assert canonical_json(epochs._records(c.parent)[-1]) == previous
    assert c.old.status()["accepted_count"] == 1
    assert not (root / cohorts.MARKER).exists() and not (root / "epoch-membership.json").exists()
    assert not (root / "attempts").exists() and not (root / "corpus").exists()


def test_initializer_keeps_selected_host_supplements_from_every_current_root(cohort_campaign, tmp_path):
    c = cohort_campaign
    other = c.fresh()
    extra = tmp_path / "selected-alpha-supplement.json"
    _create(extra, canonical_json({"urls": [
        {"url": "https://alpha.example/r?i=%d" % number} for number in range(20, 25)]}))
    study.add_inventories(other.root, [extra])
    before = study.candidate_pool(other.root)["alpha.example"]
    assert len(before["urls"]) == 25 and before["urls"][:20] == epochs._cell(c.parent, "alpha.example", MODE)["definition"]["urls"]
    c.append(other)
    extra.unlink()  # The original public pool already owns its frozen raw copy.
    root = tmp_path / "all-current-contexts"
    cohorts.initialize_cohort(c.parent.root, root)
    pool = study.candidate_pool(root)
    assert pool["alpha.example"] == before  # Complete original source IDs/order, not qualification.
    assert pool[HOST] == load_inventory_candidates([root / lineage.INVENTORY])["candidates"][0]
    catalogues = [path for path in (other.root / "inputs/supplements").glob("*/catalogue.json")
                  if "alpha.example" in {row["hostname"] for row in json.loads(path.read_bytes())["candidates"]}]
    assert len(catalogues) == 1
    for original in catalogues[0].parent.iterdir():
        copied = root / "inputs/supplements" / catalogues[0].parent.name / original.name
        assert copied.read_bytes() == original.read_bytes() and sha256_file(copied) == sha256_file(original)
        assert copied.stat().st_nlink == 1 and stat.S_IMODE(copied.stat().st_mode) == 0o444
    new = StudyStore(root)
    assert new.enrolled() == [] and new.status()["accepted_count"] == 0
    # Retained49 enrollment still has its separate original source-occurrence
    # guard. This pool/context test does not bypass it or claim live preparation.

