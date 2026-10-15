"""Source017 admission / Source018 execution regression controls.

These HOST fixtures qualify source identities and the real metadata dispatch.
The one raw leaf is explicitly synthetic; no capture, Native qualification,
historical data replay, admission, ledger credit or durability is claimed.
ROOT alone executes these tests after the complete Source018 pins are sealed.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_reader_compatibility as compatibility
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import cohort_campaign


def qualified():
    return compatibility.qualify_execution(cohorts.verifier_contract())


def profile_from_files(files):
    """Independent original contract encoding, including its terminal LF."""
    return {"record_type": "qcsd-resource-domain-runtime-cohort-verifier-contract-v1",
        "schema_version": 1, "implementation": "resource-study-raw-v1",
        "files": {name: files[name] for name in compatibility.PRIMARY_FILES},
        "transitive_source_sha256": hashlib.sha256(canonical_json(files)).hexdigest(),
        "transitive_source_files": len(files),
        "transitive_source_scope": "complete declared package-import closure; conservative dormant branches included"}


def test_old_contract_is_the_complete_unchanged_source017_graph():
    old = compatibility.legacy_contract()
    assert len(compatibility.LEGACY_FILES) == 169
    assert old == profile_from_files(compatibility.LEGACY_FILES)
    assert old["transitive_source_sha256"] == "4d05b6d198ff06c0d5f9926ba29c63e01a1632df1d266c8b1a1785aeecea757d"
    assert hashlib.sha256(canonical_json(old)).hexdigest() == "ff2326d2594ee63eae6c815815e0c4330f86f793e7e4df4d6e69ab30f3852aa5"
    assert compatibility.LEGACY_FILES["resource_study_cohorts.py"] == "4fcd0fb3271697b6c8369a8d75090af23f2829215fdd4357de8a6b4b65c4b2e9"
    assert compatibility.LEGACY_FILES["resource_study_store.py"] == "22b55cc549c7c348d48dc9b24f9393ab88d09819424b97731a8f1cbc4b51c44a"
    old["files"].clear()
    assert len(compatibility.legacy_contract()["files"]) == 10


def test_old_admission_and_actual_execution_remain_distinct_and_unaliased():
    old = compatibility.legacy_contract()
    original = canonical_json(old)
    current = cohorts.verifier_contract()
    pair = compatibility.qualify_execution(current)
    assert current["transitive_source_files"] == 170
    assert current != old and current["files"] == old["files"]
    assert compatibility.require_supported(old, pair) is True
    assert compatibility.require_supported(current, pair) is True
    selected = compatibility.admission_contract(old, pair)
    assert canonical_json(selected) == original
    binding = compatibility.execution_binding(old, pair)
    assert binding["admission_reader"] == old
    assert binding["execution_reader"] == current
    assert binding["admission_reader_preserved"] is True
    assert binding["execution_reader_is_admission_reader"] is False
    assert binding["scientific_truth_conditions_changed"] is False
    assert binding["historical_receipts_requalified_by_compatibility"] is False
    assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0
    selected["files"].clear()
    binding["execution_reader"]["files"].clear()
    assert pair.contract() == current and canonical_json(old) == original


@pytest.mark.parametrize("change", ["implementation", "primary", "closure", "schema", "extra"])
def test_unknown_admission_reader_never_falls_through(change):
    value = compatibility.legacy_contract()
    if change == "implementation": value["implementation"] = "unknown-raw-v99"
    elif change == "primary": value["files"]["resource_study_verify.py"] = "0" * 64
    elif change == "closure": value["transitive_source_sha256"] = "0" * 64
    elif change == "schema": value["schema_version"] = True
    else: value["operator_says_compatible"] = True
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(value, qualified())


@pytest.mark.parametrize("name", ["fidelity.py", "capture_session.py", "resource_study_cohorts.py", "resource_study_store.py"])
def test_execution_source_change_outside_the_exact_approved_pair_refuses(name):
    files = compatibility.execution_files()
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(profile_from_files(files))


def test_legacy_profile_cannot_be_presented_as_the_current_execution():
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(compatibility.legacy_contract())
    with pytest.raises(ValueError, match="qualified Source020"):
        compatibility.require_supported(compatibility.legacy_contract(), object())


@pytest.mark.parametrize("unknown", [False, True])
def test_real_raw_dispatch_preserves_producer_and_calls_current_leaf_only_for_supported_reader(tmp_path, monkeypatch, unknown):
    root = tmp_path / "immutable-receipt-fixture"
    root.mkdir()
    enrollment_path = root / "enrollment.json"
    enrollment_path.write_bytes(canonical_json({"files": {}}))
    enrollment_path.chmod(0o444)
    member = {"verifier": compatibility.legacy_contract(), "cell": {
        "root": str(root), "enrollment_path": "enrollment.json",
        "enrollment_sha256": sha256_file(enrollment_path)}}
    if unknown: member["verifier"]["transitive_source_sha256"] = "0" * 64
    receipt = {"coordinator_provenance": {
        "record_type": "qcsd-resource-study-host-code-v1",
        "files": {"resource_study_verify.py": "94c35857533eee942027155631cf3573856a9a477a86d55f6152fc086b8ed87a"}},
        "five_tuple": ["192.0.2.1", 31001, "198.51.100.1", 443, 17]}
    receipt_path = root / "session.json"
    receipt_path.write_bytes(canonical_json(receipt)); receipt_path.chmod(0o444)
    original, original_sha = receipt_path.read_bytes(), sha256_file(receipt_path)
    calls = []

    def raw_leaf(actual_root, actual):
        calls.append((actual_root, deepcopy(actual)))
        return {"verified": True, "five_tuple": actual["five_tuple"]}

    monkeypatch.setattr(cohorts, "verify_receipt", raw_leaf)
    if unknown:
        with pytest.raises(ValueError, match="admission reader|verifier"):
            cohorts.verify_by_contract(member, root, receipt)
        assert calls == []
    else:
        value = cohorts.verify_by_contract(member, root, receipt)
        assert value == {"verified": True, "five_tuple": receipt["five_tuple"]}
        assert calls == [(root, receipt)]
    assert receipt_path.read_bytes() == original and sha256_file(receipt_path) == original_sha
    assert receipt == json.loads(original)


@pytest.mark.parametrize("unknown", [False, True])
def test_complete_retained_record_validation_uses_its_bound_admission_reader(cohort_campaign, tmp_path, unknown):
    """Synthetic historical metadata; every real cell/fence guard still runs.

    The altered record is never published and creates no head or credit. The
    existing fixture receipt/raw leaves remain explicitly controlled.
    """
    c = cohort_campaign
    current_record = c.append(c.fresh())
    actual_head = epochs._meta(c.parent, "epoch_head")
    original_receipt = c.old_receipt.read_bytes()
    prefix = epochs._records(c.parent)[:-1]
    old_reader = compatibility.legacy_contract()
    if unknown: old_reader["implementation"] = "unknown-prior-reader-v99"
    declaration = json.loads(Path(current_record["compatibility_declaration"]["path"]).read_bytes())
    declaration["verifier"] = deepcopy(old_reader)
    path = tmp_path / "synthetic-dated-reader-declaration.json"
    path.write_bytes(canonical_json(declaration)); path.chmod(0o444)
    historical = deepcopy(current_record)
    historical["compatibility_declaration"] = {"path": str(path), "sha256": sha256_file(path)}
    for entry in historical["cohorts"]:
        for member in entry["members"]:
            member["verifier"] = deepcopy(old_reader)
    bound = canonical_json(historical)
    with epochs._lock(c.parent.root):
        if unknown:
            with pytest.raises(ValueError, match="admission reader|verifier"):
                cohorts._validate_record(c.parent, prefix, historical, contract=old_reader)
        else:
            cohorts._validate_record(c.parent, prefix, historical, contract=old_reader)
    assert canonical_json(historical) == bound
    assert epochs._meta(c.parent, "epoch_head") == actual_head
    assert c.old_receipt.read_bytes() == original_receipt
