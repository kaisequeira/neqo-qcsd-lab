"""Exact prospective127 Source-profile controls; no capture or Raw credit.

The frozen126 fixture was derived from all178 actual Source126 files. Its
ten primary hashes and full transitive digest preserve that historical
reader as data; these tests do not requalify any old receipt.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as reader


SOURCE127_COHORTS = "21356e98233ab22e783594e17b8b0568fb795e40dcd53514976944551c854760"
SOURCE126_BINDING = "qcsd-resource-domain-call-local-lineage-plan-projection-126-reader-execution-binding-v1"
SOURCE126_PROFILE = {
    "record_type": "qcsd-resource-domain-runtime-cohort-verifier-contract-v1",
    "schema_version": 1,
    "implementation": "resource-study-raw-v1",
    "files": {
        "resource_study_verify.py": "a9a609130d6d0ecb26e4e866abbaad0ba26367acf869a9ba1ec2a0817b18deee",
        "resource_study_inputs.py": "899b78d50063eea6c30140397b2342d900701d44aed8f1bfe9afb30abe9ffd2b",
        "fidelity.py": "460c7ee9540eb17d22eac54f73f5462c06a674110d72ede707555b11792847a8",
        "resource_study_native.py": "b9f2694f20d2582c57f62b70483b2242d188778fffee0560fd9d937704191cca",
        "resource_study_network.py": "d1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20",
        "resource_study_selection.py": "673a19748010c951f8e604d9b16c5ddc633a26b116499e07fdd63ec8617240e4",
        "resource_study_lineage.py": "b2e13cc9134c94e0882acbb615fc7b5ebb349cd459c3deeefeafa83b173c05aa",
        "kernel_tx.py": "5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125",
        "process_scheduler.py": "8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf",
        "capture.py": "c37a0444c62e77068891281fa72200bdc2c07192ee8e4e05a9832bfe1a681c99",
    },
    "transitive_source_sha256": "481948769f83a7e2f5a4eead30269f8970d608c33b25664df2fa05b37ca996cf",
    "transitive_source_files": 178,
    "transitive_source_scope": "complete declared package-import closure; conservative dormant branches included",
}


def test_current127_profile_matches_the_whole_actual178_source_graph():
    source = Path(cohorts.__file__).parent
    actual_files = {
        name: hashlib.sha256((source / name).read_bytes()).hexdigest()
        for name in cohorts.RAW_DEPENDENCIES
    }
    assert len(actual_files) == 178
    assert actual_files["resource_study_cohorts.py"] == SOURCE127_COHORTS
    assert reader.execution_files() == actual_files
    actual = cohorts.verifier_contract()
    qualified = reader.qualify_execution(actual)
    assert qualified.contract() == actual
    assert actual["transitive_source_files"] == 178
    assert actual != SOURCE126_PROFILE


def test_exact126_profile_is_preserved_but_cannot_claim_current_execution():
    actual = cohorts.verifier_contract()
    qualified = reader.qualify_execution(actual)
    historical = reader.prior_exact126_execution_contract()
    assert historical == SOURCE126_PROFILE
    assert reader.require_supported(historical, qualified) is True
    assert reader.admission_contract(historical, qualified) == SOURCE126_PROFILE
    with pytest.raises(ValueError):
        reader.qualify_execution(historical)


def test_binding_keeps_original126_admission_and_new127_execution_distinct():
    actual = cohorts.verifier_contract()
    qualified = reader.qualify_execution(actual)
    historical = reader.prior_exact126_execution_contract()
    value = reader.execution_binding(historical, qualified)
    assert value["record_type"] == reader.BINDING_TYPE != SOURCE126_BINDING
    assert value["admission_reader"] == historical == SOURCE126_PROFILE
    assert value["execution_reader"] == actual
    assert value["admission_reader_preserved"] is True
    assert value["execution_reader_is_admission_reader"] is False
    assert value["historical_receipts_requalified_by_compatibility"] is False
    assert value["authority_issued"] is False
    assert value["scientific_credit_added"] == 0
    value["admission_reader"]["files"]["resource_study_verify.py"] = "0" * 64
    assert historical == SOURCE126_PROFILE
    assert reader.prior_exact126_execution_contract() == SOURCE126_PROFILE


@pytest.mark.parametrize("changed", ["primary", "transitive", "file-count", "schema"])
def test_current_execution_refuses_any_changed_profile_field(changed):
    value = deepcopy(cohorts.verifier_contract())
    if changed == "primary":
        value["files"]["resource_study_verify.py"] = "0" * 64
    elif changed == "transitive":
        value["transitive_source_sha256"] = "0" * 64
    elif changed == "file-count":
        value["transitive_source_files"] = 177
    else:
        value["schema_version"] = True
    with pytest.raises(ValueError):
        reader.qualify_execution(value)


def test_a_changed126_profile_cannot_enter_the_supported_history():
    qualified = reader.qualify_execution(cohorts.verifier_contract())
    value = deepcopy(SOURCE126_PROFILE)
    value["files"]["resource_study_verify.py"] = "0" * 64
    with pytest.raises(ValueError):
        reader.require_supported(value, qualified)
    with pytest.raises(ValueError):
        reader.execution_binding(value, qualified)
