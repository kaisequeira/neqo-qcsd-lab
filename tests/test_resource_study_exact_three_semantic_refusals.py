"""SOURCE-only regression proposal; ROOT alone executes these tests.

The real Store, SQLite/index, cohort history, source profile, pilot/allocation,
frozen manifests, lineage fences and head CAS remain original. The campaign
uses one synthetic FRONT cell to exercise the slot mechanism economically;
only the exact scope/proof/standard-parent/preparation/raw leaves are disclosed
fixtures. A separate test authenticates every actual saved CS211 refusal byte.
These fixtures create no scientific receipt or public certification.
"""
from copy import deepcopy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from types import ModuleType

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as c
from qcsd_lab import resource_study_epochs as e
from qcsd_lab import resource_study_reader_compatibility as compatibility
from qcsd_lab import resource_study_semantic_refusals as semantic
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import DuplicateSession, StudyStore, _create
from tests.test_resource_study_lineage import campaign, rewrite
from tests.test_resource_study_runtime_cohorts import cohort_campaign, controlled_pilot, controlled_credit, HOST, MODE


HOST_SETUP = Path("/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/setup")
ACTUAL_PACK = Path("/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS096211-actual004-selected-two-phase-proof-DTOs-readonly-export-002")
ACTUAL_MANIFEST_SHA = "823280fb9814d8a3ceeaa0d12d731597095c74b4365205c81f24b8cbaf8f0c18"


def p587():
    path = HOST_SETUP / semantic.PARTITION[0]
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == semantic.PARTITION[1]
    module = ModuleType("test_exact_p587_original")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def pending_partition(rows, pending):
    original = p587()
    pending_keys = {semantic._key(row) for row in pending}
    qualified = [row for row in rows if semantic._key(row) not in pending_keys]
    return {"record_type": original.TYPE, "schema_version": 1,
        "full_local_accepted_count": len(rows), "qualified_accepted_count": len(qualified),
        "deferred_accepted_count": len(pending), "deferred_accepted": original.ordered(pending),
        "qualified_accepted_inventory_sha256": original.digest(qualified),
        "deferred_inventory_sha256": original.digest(pending),
        "failed_original_proof_preserved": True, "deferred_rows_whole_proved": False,
        "new_checkpoint_issued": False, "scientific_credit_added": 0}


@pytest.fixture
def retirement(cohort_campaign, tmp_path, monkeypatch):
    flight = cohort_campaign
    current = flight.fresh(native="b")
    initial = c.compatibility_template(flight.parent.root, current.root,
        affected_hostnames=[HOST], affected_modes=study.MODES)
    initial["compatible_treatment"] = True
    initial["rationale"] = "Synthetic all-mode same-root fixture, not a live qualification."
    initial_path = tmp_path / "initial-native-declaration.json"
    _create(initial_path, canonical_json(initial))
    c.create_cohort(flight.parent.root, current.root, initial_path, sha256_file(initial_path))
    controlled_pilot(current, HOST, MODE)
    for port in (32001, 32002, 32003):
        flight.credit(current, port=port)
    records = e._records(flight.parent)
    entry = c._entry(records[-1]["cohorts"], (HOST, MODE))
    member = c._writer(entry)
    fixed = [semantic._full_ref(member, str(current.root), row) for row in c._rows(current, (HOST, MODE))]
    assert len(fixed) == 3
    # Explicit synthetic scope and metadata-certificate leaves. Production
    # constants remain bound to two actual CS cells and all six saved refusals.
    monkeypatch.setattr(semantic, "CELLS", ((HOST, MODE),))
    monkeypatch.setattr(semantic, "FIXED_ROWS", fixed)
    monkeypatch.setattr(semantic, "evidence", lambda ref: [])
    before = {"records": deepcopy(records), "composition": c.status(flight.parent.root)}
    partition = pending_partition(before["composition"]["accepted"], fixed)
    def parent_leaf(ref, observed):
        assert observed == records
        return deepcopy(before), deepcopy(partition)
    monkeypatch.setattr(semantic, "_parent", parent_leaf)
    replacement = flight.fresh(native="b")
    evidence = tmp_path / "explicit-synthetic-proof-leaf.json"
    transfer = tmp_path / "explicit-synthetic-standard-parent-leaf.json"
    _create(evidence, canonical_json({"synthetic_leaf": "proof metadata only"}))
    _create(transfer, canonical_json({"synthetic_leaf": "standard certificate metadata only"}))
    declaration = semantic.template(flight.parent.root, replacement.root,
        evidence_path=evidence, evidence_sha256=sha256_file(evidence),
        parent_transfer_path=transfer, parent_transfer_sha256=sha256_file(transfer),
        rationale="Synthetic ledger regression; no actual retirement authority.")
    path = tmp_path / "semantic-declaration.json"
    _create(path, canonical_json(declaration))
    def publish():
        return semantic.create(flight.parent.root, replacement.root, path, sha256_file(path))
    return flight, current, replacement, before, partition, fixed, path, publish


def test_actual_saved_six_refusals_and_closed_pool_bytes(tmp_path):
    raw = (ACTUAL_PACK / "manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ACTUAL_MANIFEST_SHA
    manifest = json.loads(raw)
    actual = {row["guest_path"]: {"path": row["host_path"], "sha256": row["sha256"], "bytes": row["bytes"]}
              for row in manifest["files"]}
    path = tmp_path.resolve() / "actual-six-proof-binding.json"
    _create(path, canonical_json({"record_type": semantic.EVIDENCE, "schema_version": 1, "files": actual}))
    pairs = semantic.evidence({"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size})
    assert {(row["ordinal"], row["phase"]) for row in pairs} == {(n, p) for n in (407, 412, 583) for p in (1, 2)}
    assert semantic.CELLS == (("ph.747.live", "cs-buflo"), ("zerolifestyle.co", "cs-buflo"))
    assert len(semantic.FIXED_ROWS) == 3


@pytest.mark.parametrize("change", ["missing", "wrong-hash"])
def test_actual_proof_inventory_cannot_drop_or_substitute_a_negative(tmp_path, change):
    manifest = json.loads((ACTUAL_PACK / "manifest.json").read_bytes())
    actual = {row["guest_path"]: {"path": row["host_path"], "sha256": row["sha256"], "bytes": row["bytes"]}
              for row in manifest["files"]}
    selected = next(path for path in actual if path.endswith("receipt-000407.json"))
    if change == "missing":
        actual.pop(selected)
    else:
        actual[selected]["sha256"] = "0" * 64
    path = tmp_path.resolve() / "changed-proof-binding.json"
    _create(path, canonical_json({"record_type": semantic.EVIDENCE, "schema_version": 1, "files": actual}))
    with pytest.raises(ValueError):
        semantic.evidence({"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size})


def test_current_original_cohorts_contract_and_exact109_history():
    actual = c._fresh_verifier_contract()
    qualified = compatibility.qualify_execution(actual)
    assert actual == compatibility._profile(compatibility.execution_files())
    assert actual["transitive_source_files"] == 177
    assert "resource_study_semantic_refusals.py" in c.RAW_DEPENDENCIES
    assert len(compatibility.PRIOR_EXACT109_FILES) == 176
    compatibility.require_supported(compatibility.prior_exact109_execution_contract(), qualified)
    changed = deepcopy(actual); changed["transitive_source_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        compatibility.qualify_execution(changed)


def test_real_head_transition_preserves_all_SQL_attempts_and_releases_only_three_active_slots(retirement):
    flight, old, new, before, partition, fixed, path, publish = retirement
    with old._transaction() as connection:
        accepted = [tuple(row) for row in connection.execute("SELECT * FROM accepted ORDER BY slot")]
        attempts = [tuple(row) for row in connection.execute("SELECT * FROM attempts ORDER BY attempt_id")]
    admission = publish()
    assert admission["change"] == semantic.CHANGE
    assert set(admission["affected"][0]) == {HOST, MODE}
    assert all(a == b for a, b in zip(before["records"], e._records(flight.parent)[:-1]))
    after = c.status(flight.parent.root)
    assert after["record_type"] == semantic.COMPOSITION
    assert after["accepted_count"] == before["composition"]["accepted_count"] - 3
    assert after["historical_accepted_count"] == before["composition"]["accepted_count"]
    assert after["retired_historical_accepted_count"] == 3
    with old._transaction() as connection:
        assert accepted == [tuple(row) for row in connection.execute("SELECT * FROM accepted ORDER BY slot")]
        assert attempts == [tuple(row) for row in connection.execute("SELECT * FROM attempts ORDER BY attempt_id")]
    records = e._records(flight.parent)
    assert {row["five_tuple"] for row in fixed} <= e._excluded(flight.parent, records, (HOST, MODE))
    occupied = {row["slot"] for _, _, row in semantic.accepted(c._entry(records[-1]["cohorts"], (HOST, MODE)))}
    assert not {row["slot"] for row in fixed} & occupied
    old_entry = c._entry(before["records"][-1]["cohorts"], (HOST, MODE))
    entry = c._entry(records[-1]["cohorts"], (HOST, MODE))
    assert len(entry["members"]) == len(old_entry["members"]) + 1
    assert len(c._frozen_value(flight.parent, entry["members"][-2])["rows"]) == 3
    for key in {(row["hostname"], row["mode"]) for row in before["records"][-1]["cells"]} - {(HOST, MODE)}:
        assert c._entry(records[-1]["cohorts"], key) == c._entry(before["records"][-1]["cohorts"], key)


def test_replacement_still_needs_own_pilot_and_old_tuple_never_returns(retirement):
    flight, old, new, before, partition, fixed, path, publish = retirement
    publish()
    with pytest.raises(ValueError, match="own genuine matching mode pilot"):
        new.allocate_attempt(HOST, MODE)
    controlled_pilot(new, HOST, MODE)
    receipt = flight.credit(new, port=33001)
    assert json.loads(receipt.read_bytes())["slot"] in {row["slot"] for row in fixed}
    with pytest.raises((ValueError, DuplicateSession)):
        flight.credit(new, port=32001)
    assert old.status()["accepted_count"] == 3


def test_replacement_can_later_freeze_without_forgetting_retired_slot_overlap(retirement):
    flight, old, new, before, partition, fixed, path, publish = retirement
    publish(); controlled_pilot(new, HOST, MODE)
    receipt = flight.credit(new, port=33002)
    next_writer = flight.fresh(native="d")
    flight.append(next_writer)
    records = e._records(flight.parent)
    entry = c._entry(records[-1]["cohorts"], (HOST, MODE))
    c._check_frozen(flight.parent, [entry])
    assert len(semantic.accepted(entry)) == 2
    assert old.status()["accepted_count"] == 3 and new.status()["accepted_count"] == 1
    assert json.loads(receipt.read_bytes())["slot"] in {row["slot"] for row in fixed}


def test_unaffected_CS_member_on_same_old_root_remains_writable(retirement):
    flight, old, new, before, partition, fixed, path, publish = retirement
    with old._transaction() as connection:
        original_schema = [tuple(row) for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")]
        original_rows = [tuple(row) for row in connection.execute("SELECT * FROM accepted WHERE hostname=? AND mode=? ORDER BY slot", (HOST, MODE))]
    publish()
    mode = "cs-buflo"
    records = e._records(flight.parent)
    unaffected = c._entry(records[-1]["cohorts"], (HOST, mode))
    assert c._writer(unaffected)["cell"]["root"] == str(old.root)
    assert "semantic_refusals" not in unaffected
    controlled_pilot(old, HOST, mode)
    attempt = old.allocate_attempt(HOST, mode)
    receipt = controlled_credit(old, attempt, commit=False)
    value = json.loads(receipt.read_bytes()); value["five_tuple"][1] = 33999
    rewrite(receipt, value)
    old.commit_verified(receipt, validator=lambda root, observed: {"verified": True, "five_tuple": observed["five_tuple"]})
    with old._transaction() as connection:
        assert original_schema == [tuple(row) for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")]
        assert original_rows == [tuple(row) for row in connection.execute("SELECT * FROM accepted WHERE hostname=? AND mode=? ORDER BY slot", (HOST, MODE))]
    assert c.accepted_count(old, HOST, mode) == 1
    assert len(semantic.accepted(c._entry(e._records(flight.parent)[-1]["cohorts"], (HOST, MODE)))) == 1


def test_new_QDR_is_distinct_and_Q_is_conserved(retirement, monkeypatch):
    flight, old, new, before, partition, fixed, path, publish = retirement
    publish()
    after = {"records": e._records(flight.parent), "composition": c.status(flight.parent.root)}
    monkeypatch.setattr(semantic, "_source", lambda pair: p587())
    result = semantic.partition_for_retirement(partition, before, after)
    assert result["qualified_accepted_count"] == partition["qualified_accepted_count"]
    assert result["deferred_accepted_count"] == partition["deferred_accepted_count"] - 3
    assert result["retired_accepted_count"] == 3
    assert result["full_local_accepted_count"] == partition["full_local_accepted_count"]
    assert result["active_accepted_count"] == result["full_local_accepted_count"] - 3
    semantic.checked_active_partition(result, after)
    with pytest.raises(ValueError):
        p587().checked_partition(result, after)
    changed = deepcopy(result); changed["qualified_accepted"].append(changed["retired_accepted"][0])
    with pytest.raises(ValueError):
        semantic.checked_active_partition(changed, after)


def test_prehead_failure_issues_no_authority_and_orphan_marker_requires_explicit_recovery(retirement, monkeypatch):
    from qcsd_lab import resource_study_lineage as lineage
    flight, old, new, before, partition, fixed, path, publish = retirement
    head = e._meta(flight.parent, "epoch_head")
    @contextmanager
    def failed_head_publication(*args, **kwargs):
        raise RuntimeError("synthetic storage fault immediately before original head-publication scope")
        yield
    monkeypatch.setattr(lineage, "publication_scope", failed_head_publication)
    with pytest.raises(RuntimeError, match="synthetic storage fault"):
        publish()
    assert e._meta(flight.parent, "epoch_head") == head
    assert old.status()["accepted_count"] == 3 and new.status()["accepted_count"] == 0
    assert (new.root / c.MARKER).is_file()
    with pytest.raises(ValueError, match="unclaimed fresh writer"):
        publish()


@pytest.mark.parametrize("change", ["missing-retired", "unfrozen-retired", "old-tuple-reuse", "active-slot-overlap"])
def test_projection_keeps_original_history_identity_and_global_uniqueness(retirement, change):
    flight, old, new, before, partition, fixed, path, publish = retirement
    publish()
    entry = c._entry(e._records(flight.parent)[-1]["cohorts"], (HOST, MODE))
    history = [(deepcopy(member), StudyStore(member["cell"]["root"]), deepcopy(row))
        for member in entry["members"] for row in c._rows(StudyStore(member["cell"]["root"]), (HOST, MODE))]
    retired = {semantic._key(row): row for row in fixed}
    retired_index = next(i for i, (_, store, row) in enumerate(history) if (str(store.root), row["attempt_id"]) in retired)
    if change == "missing-retired":
        history.pop(retired_index)
    elif change == "unfrozen-retired":
        history[retired_index][0]["frozen_accepted"] = None
    else:
        source = history[retired_index] if change == "old-tuple-reuse" else next(
            item for item in history if (str(item[1].root), item[2]["attempt_id"]) not in retired)
        row = deepcopy(source[2]); row["attempt_id"] = "f" * 32
        if change == "active-slot-overlap":
            value = json.loads(row["five_tuple"]); value[1] = 34001
            row["five_tuple"] = c._json(value).decode()
        history.append((deepcopy(c._writer(entry)), new, row))
    with pytest.raises(ValueError):
        semantic._project(entry, history, retired)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("same_native_exception_only_exact_three", 1),
    ("scientific_credit_added", True), ("rationale", ""), ("fresh_root", "/foreign")])
def test_changed_semantic_declaration_refuses_before_head_switch(retirement, field, value):
    flight, old, new, before, partition, fixed, path, publish = retirement
    raw = json.loads(path.read_bytes()); raw[field] = value
    path.chmod(0o600); path.write_bytes(canonical_json(raw)); path.chmod(0o444)
    head = e._meta(flight.parent, "epoch_head")
    with pytest.raises((ValueError, KeyError)):
        publish()
    assert e._meta(flight.parent, "epoch_head") == head
    assert old.status()["accepted_count"] == 3 and new.status()["accepted_count"] == 0


@pytest.mark.parametrize("action", ["cohort-semantic-refusal-template", "cohort-semantic-refusal-admit"])
def test_original_public_parser_has_only_the_two_explicit_actions(action, tmp_path):
    common = [action, "--root", str(tmp_path / "parent"), "--cohort-root", str(tmp_path / "new")]
    with pytest.raises(SystemExit):
        study.parser().parse_args(common)
    args = (common + ["--evidence", str(tmp_path / "proof"), "--evidence-sha256", "a" * 64,
        "--parent-transfer", str(tmp_path / "standard"), "--parent-transfer-sha256", "b" * 64, "--rationale", "exact three"]
        if action.endswith("template") else common + ["--declaration", str(tmp_path / "declaration"), "--declaration-sha256", "c" * 64])
    assert study.parser().parse_args(args).action == action
    with pytest.raises(SystemExit):
        study.parser().parse_args(args + ["--force"])


@pytest.mark.parametrize("action", ["template", "admit"])
def test_actual_public_main_passes_exact_original_API_arguments(action, tmp_path, monkeypatch, capsys):
    calls = []
    def leaf(*args, **kwargs):
        calls.append((args, kwargs))
        return {"explicit_synthetic_dispatch_leaf": True, "no_authority_issued": True}
    monkeypatch.setattr(c, "semantic_refusal_template" if action == "template" else "create_semantic_refusal", leaf)
    parent, new = tmp_path / "parent", tmp_path / "fresh"
    common = ["cohort-semantic-refusal-" + action, "--root", str(parent), "--cohort-root", str(new)]
    if action == "template":
        proof, transfer = tmp_path / "proof", tmp_path / "transfer"
        args = common + ["--evidence", str(proof), "--evidence-sha256", "a" * 64,
            "--parent-transfer", str(transfer), "--parent-transfer-sha256", "b" * 64, "--rationale", "exact three"]
        expected = ((parent.absolute(), new.absolute()), {"evidence_path": proof.absolute(), "evidence_sha256": "a" * 64,
            "parent_transfer_path": transfer.absolute(), "parent_transfer_sha256": "b" * 64, "rationale": "exact three"})
    else:
        declaration = tmp_path / "declaration"
        args = common + ["--declaration", str(declaration), "--declaration-sha256", "c" * 64]
        expected = ((parent.absolute(), new.absolute(), declaration.absolute(), "c" * 64), {})
    assert study.main(args) == 0
    assert calls == [expected]
    assert json.loads(capsys.readouterr().out)["no_authority_issued"] is True
