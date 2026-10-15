"""Source017/018/019 admission and Source040 execution regression controls.

These HOST fixtures qualify source identities and the real metadata dispatch.
The one raw leaf is explicitly synthetic; no capture, Native qualification,
historical data replay, admission, ledger credit or durability is claimed.
ROOT alone executes these tests after the complete Source040 pins are sealed.
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
    assert {name for name in current["files"] if current["files"][name] != old["files"][name]} == {
        "resource_study_network.py", "fidelity.py", "resource_study_verify.py", "resource_study_native.py"}
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
    assert binding["coordinator_kernel_thread_teardown_changed"] is True
    assert binding["buflo_capped_chaff_selection_changed"] is True
    assert binding["prospective_buflo_terminal_protocol_changed"] is True
    assert binding["scientific_truth_conditions_changed"] is True
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
    "resource_study.py", "resource_study_runtime.py", "resource_study_network.py",
    "resource_study_native.py", "resource_study_epochs.py", "resource_study_verify.py"])
def test_execution_source_change_outside_the_exact_approved_pair_refuses(name):
    files = compatibility.execution_files()
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(profile_from_files(files))


def test_legacy_profile_cannot_be_presented_as_the_current_execution():
    with pytest.raises(ValueError, match="execution reader"):
        compatibility.qualify_execution(compatibility.legacy_contract())
    with pytest.raises(ValueError, match="qualified Source040"):
        compatibility.require_supported(compatibility.legacy_contract(), object())


@pytest.mark.parametrize("version", ["024", "027", "028"])
def test_exact_prior_producer_profile_cannot_alias_source040_execution(version):
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
    if version in ("027", "028"):
        files.update({
            "resource_study.py": "3b8d2171b5b7a0d44a927e215fa6f553d6a2a3300c7311ec80ce3e2c8a3ea644",
            "resource_study_runtime.py": "90ea05084b7686e04da9f7a673dfa7d06ebc34c6cd0beee69e46fb8a4f1852e2",
            compatibility.HELPER_NAME: "d2f520fd2e3dbe6f3675f866a08d672541e5b9935de10d75f1c762cfe0f2423e",
        })
    if version == "028":
        files.update({
            "resource_study_cohorts.py": "07256a1008c8b4a1f7685aeebafaeb8717aad771ce27d47cc088352956ebcea8",
            "resource_study_network.py": "d1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20",
            compatibility.HELPER_NAME: "adba3411f23ce3d44c8714b3b24ba75196259c2edb5c5cfff1b580d0d8e30417",
        })
    dated = profile_from_files(files)
    assert dated["transitive_source_files"] == 170
    graph, contract = {
        "024": ("e6fc499a07e846675a15a7c8f0481a5d203ff446ec2b3ceb7dcb8017578fa2bb", "9487b3b2a8643e8f280185732b57d94f14d856d043aa085008e9405ef37595d3"),
        "027": ("889b366f5f328903bde4f927ebe802a2265ad1684e4c3d21be9d60762c599baa", "d6d658b708c358147939ac6e97d78e61d8123ee0b37bd1d7f001dcd434b706c1"),
        "028": ("886f314f3c4b67ebd3393fa62ce2ee27bad9a3996a6697bf7f5503c2ad8acf9f", "ac374a71eaa8edc9ce817092fe01085b314bd983d3ed9dfd35d9362a8f47e1b7"),
    }[version]
    assert dated["transitive_source_sha256"] == graph
    assert hashlib.sha256(canonical_json(dated)).hexdigest() == contract
    original = canonical_json(dated)
    current = cohorts.verifier_contract()
    assert dated != current
    expected_primary_changes = {"fidelity.py", "resource_study_verify.py", "resource_study_native.py"}
    if version != "028": expected_primary_changes.add("resource_study_network.py")
    assert {name for name in current["files"] if current["files"][name] != dated["files"][name]} == expected_primary_changes
    with pytest.raises(ValueError, match="Source040 execution"):
        compatibility.qualify_execution(dated)
    pair = compatibility.qualify_execution(current)
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(dated, pair)
    assert pair.contract() == current and canonical_json(dated) == original
    assert compatibility.require_supported(compatibility.prior_capture_execution_contract(), pair) is True


def test_source040_profile_binds_the_exact_five_changed_modules_and_old039_is_not_an_alias():
    current = cohorts.verifier_contract()
    expected = {
        "resource_study.py": "49058ed6a5ba1f7fc5fe73ece77ee8b2e2e99fdb2079de5fee9b06fa7d150d03",
        "resource_study_runtime.py": "d5c299a273c264c0b8e4c65cc86e43e22707ce23a3399a1f2a26d19623d8c923",
        "resource_study_native.py": "fbd8e9424720632e37b3f8ae6c8e022d5f451542ea49cc381abd10e7ca42cd41",
        "resource_study_epochs.py": "2a1b64cd23e45912b577f6fbb00bdcdc5587e824992b20696614b38d92e1f9e7",
        "resource_study_verify.py": "82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235",
    }
    files = compatibility.execution_files()
    assert {name: files[name] for name in expected} == expected
    assert current["transitive_source_files"] == 170
    assert current["transitive_source_sha256"] == "ed04b9ea7bbf02ac5f910b941d5a62697b8bbeff70454b01fe8950a3833b44d0"
    assert hashlib.sha256(canonical_json(current)).hexdigest() == "e4b7925f6ec718b939ee2d5d3de722d53b5f2a2b821d570a4a8523303c4f9771"
    files.update({
        "resource_study.py": "3b8d2171b5b7a0d44a927e215fa6f553d6a2a3300c7311ec80ce3e2c8a3ea644",
        "resource_study_runtime.py": "27946e752e90231dd6f73f982ef5d3758a9716685fba28c900e56f94f28eb27b",
        "resource_study_native.py": "073c07672f652f0d4a9a1ba53b8010684ace6bc8fa1b3ed67ea4ef4b64d75976",
        "resource_study_epochs.py": "8d10bd355563fa675d1245a86a91c33b9482859886476e0d3d09a289ac842c6c",
        "resource_study_verify.py": "80711b1ab52f11457ef5fe6269cef9a0f00531544782cd7cd60a4b488ad5dcac",
        compatibility.HELPER_NAME: "38a6ce24ab44f6ba6f9b0ec844c5e26f00418a5b463cd5359480bd676c9bae22",
    })
    dated = profile_from_files(files)
    assert dated["transitive_source_sha256"] == "a914ca56a8c0b3cb81f6e1d84d4c5d98cfe88114d818184ae133694fd5c420ee"
    assert hashlib.sha256(canonical_json(dated)).hexdigest() == "ae7b207f46fd05cd5770ed7ed949a06cd2ba1c462ead72a9175871d0ead11a02"
    assert {name for name in current["files"] if current["files"][name] != dated["files"][name]} == {
        "resource_study_native.py", "resource_study_verify.py"}
    with pytest.raises(ValueError, match="Source040 execution"):
        compatibility.qualify_execution(dated)
    pair = compatibility.qualify_execution(current)
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(dated, pair)
    for admission in (compatibility.legacy_contract(), compatibility.prior_execution_contract(),
                      compatibility.prior_capture_execution_contract()):
        assert compatibility.require_supported(admission, pair) is True


def test_original_source040_profile_is_distinct_from_four_field_job_cli_revision():
    files = compatibility.execution_files()
    files.update({
        "resource_study_runtime.py": "e829dd6cf5a51bc0b218a39224bee8ac6491c816ba242f371e4a11d3446a0fb9",
        "resource_study_native.py": "9b549288b7a6a50960c29f32bdd87443a462ead581cc1817ba48791544db4b3c",
        compatibility.HELPER_NAME: "2e3a601d0334bb98d59d8883351da43e6b936b57da5cbb45d29a4922b2d37fb0",
    })
    dated = profile_from_files(files)
    assert dated["transitive_source_files"] == 170
    assert dated["transitive_source_sha256"] == "85e253f934c13a9375700527a9b4bb324c4d09cfaa5dbf1a0317a885938088f5"
    assert hashlib.sha256(canonical_json(dated)).hexdigest() == "95aaf6ef0fc84c499b896859c3dcc61e00f98486bce120040aa7c39fc49659d9"
    current = cohorts.verifier_contract()
    assert {name for name in current["files"] if current["files"][name] != dated["files"][name]} == {"resource_study_native.py"}
    original = canonical_json(dated)
    with pytest.raises(ValueError, match="Source040 execution"):
        compatibility.qualify_execution(dated)
    pair = compatibility.qualify_execution(current)
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(dated, pair)
    assert canonical_json(dated) == original and pair.contract() == current


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
