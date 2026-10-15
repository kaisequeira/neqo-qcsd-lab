"""Source017/018/019 admission and Source028 execution regression controls.

These HOST fixtures qualify source identities and the real metadata dispatch.
The one raw leaf is explicitly synthetic; no capture, Native qualification,
historical data replay, admission, ledger credit or durability is claimed.
ROOT alone executes these tests after the complete Source028 pins are sealed.
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
    assert current != old
    assert {name for name in current["files"] if current["files"][name] != old["files"][name]} == {"resource_study_network.py"}
    assert current["files"]["resource_study_network.py"] == compatibility.APPROVED_EXECUTION_FILES["resource_study_network.py"]
    assert compatibility.require_supported(old, pair) is True
    assert compatibility.require_supported(current, pair) is True
    selected = compatibility.admission_contract(old, pair)
    assert canonical_json(selected) == original
    binding = compatibility.execution_binding(old, pair)
    assert binding["admission_reader"] == old
    assert binding["execution_reader"] == current
    assert binding["admission_reader_preserved"] is True
    assert binding["execution_reader_is_admission_reader"] is False
    assert binding["coordinator_pool_thread_closure_changed"] is True
    assert binding["records_network_validation_cache_changed"] is True
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


@pytest.mark.parametrize("name", ["fidelity.py", "capture_session.py", "resource_study_cohorts.py", "resource_study_store.py",
    "resource_study.py", "resource_study_runtime.py", "resource_study_network.py"])
def test_execution_source_change_outside_the_exact_approved_pair_refuses(name):
    files = compatibility.execution_files()
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(profile_from_files(files))


def test_legacy_profile_cannot_be_presented_as_the_current_execution():
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(compatibility.legacy_contract())
    with pytest.raises(ValueError, match="qualified Source028"):
        compatibility.require_supported(compatibility.legacy_contract(), object())


@pytest.mark.parametrize("version", ["024", "027"])
def test_exact_prior_producer_profile_cannot_alias_source028_execution(version):
    # Immutable prior SOURCE metadata, independent of any live receipt.
    # Keeping this dated producer identity never grants a new admission.
    files = dict(compatibility.LEGACY_FILES)
    files.update({
        "resource_study_cohorts.py": "877384786ca6ae3e90f2d8ce4011fc2c018f48d00cf3ab726e0b7d1332114d9b",
        "resource_study_store.py": "76f49cb2f9e1a5788e4af073c7242125b3a689b414210e856fad0ed51a93ae53",
        "resource_study.py": "af071540149ebffb055baf0e043bb8dc5831cdd36d2b8569de6b8ee9cbdb0562",
        "resource_study_runtime.py": "82f1b92a3ff76a508a0d7e5304622a11391830c20c5e439189eeaf6acc22042d",
        compatibility.HELPER_NAME: "e554ebd4749ad6510d2c55f066a8859a80a1d0e8a18070fe694e6332bf25132c",
    })
    if version == "027":
        files.update({
            "resource_study.py": "3b8d2171b5b7a0d44a927e215fa6f553d6a2a3300c7311ec80ce3e2c8a3ea644",
            "resource_study_runtime.py": "90ea05084b7686e04da9f7a673dfa7d06ebc34c6cd0beee69e46fb8a4f1852e2",
            compatibility.HELPER_NAME: "d2f520fd2e3dbe6f3675f866a08d672541e5b9935de10d75f1c762cfe0f2423e",
        })
    dated = profile_from_files(files)
    assert dated["transitive_source_files"] == 170
    graph, contract = {
        "024": ("e6fc499a07e846675a15a7c8f0481a5d203ff446ec2b3ceb7dcb8017578fa2bb", "9487b3b2a8643e8f280185732b57d94f14d856d043aa085008e9405ef37595d3"),
        "027": ("889b366f5f328903bde4f927ebe802a2265ad1684e4c3d21be9d60762c599baa", "d6d658b708c358147939ac6e97d78e61d8123ee0b37bd1d7f001dcd434b706c1"),
    }[version]
    assert dated["transitive_source_sha256"] == graph
    assert hashlib.sha256(canonical_json(dated)).hexdigest() == contract
    original = canonical_json(dated)
    current = cohorts.verifier_contract()
    assert dated != current
    assert {name for name in current["files"] if current["files"][name] != dated["files"][name]} == {"resource_study_network.py"}
    with pytest.raises(ValueError, match="Source028 execution"):
        compatibility.qualify_execution(dated)
    pair = compatibility.qualify_execution(current)
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(dated, pair)
    assert pair.contract() == current and canonical_json(dated) == original
    assert compatibility.require_supported(compatibility.prior_capture_execution_contract(), pair) is True


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
