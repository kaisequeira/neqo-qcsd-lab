"""Source080 identity controls; ROOT alone runs these focused tests.

The original Source079 runtime and admissions keep their dated source graph.
No receipt, preparation, capture, SQL state or scientific credit is created.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility


CHANGED080 = {
    "resource_study.py": "2058cdc53cfba9c65b6554449f9caeae26459f3324ae8a8890e29b4d93d625d5",
    "resource_study_runtime.py": "db63162ef14f0c2c26e814411fac78505a6dc1352adb382c0564d402825458f2",
    "resource_study_cohorts.py": "84b59afc772db6794bd4319ec048f42fbb87924fa1bbec701bb8cf647212696c",
    "resource_study_epochs.py": "48dbc2afa5e3c8fea2debd8e36a70aaf9ed5034a0a423b9f6b80116d0efab3b6",
}
HISTORICAL = (
    "legacy_contract", "prior_execution_contract", "prior_capture_execution_contract",
    "prior_analysis_execution_contract", "prior_flight_execution_contract",
    "prior_monitor_execution_contract", "prior_authority_execution_contract",
    "prior_frozen_manifest_execution_contract", "prior_primary_partial_execution_contract",
    "prior_fin_permission_execution_contract", "prior_explicit_prepared_policy_execution_contract",
    "prior_complete_fin069_execution_contract", "prior_explicit_duration070_execution_contract",
    "prior_explicit_budget071_execution_contract", "prior_queued_http079_execution_contract",
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode()


def independent_profile(files):
    return {
        "record_type": "qcsd-resource-domain-runtime-cohort-verifier-contract-v1",
        "schema_version": 1, "implementation": "resource-study-raw-v1",
        "files": {name: files[name] for name in compatibility.PRIMARY_FILES},
        "transitive_source_sha256": hashlib.sha256(encoded(files)).hexdigest(),
        "transitive_source_files": len(files),
        "transitive_source_scope": "complete declared package-import closure; conservative dormant branches included",
    }


def qualified():
    return compatibility.qualify_execution(cohorts.verifier_contract())


def test_current080_graph_pins_four_changed_modules_and_actual_helper():
    assert compatibility.EXECUTION_KIND == "080"
    source = Path(compatibility.__file__).resolve(strict=True)
    expected = dict(compatibility.LEGACY_FILES)
    expected.update(compatibility.APPROVED_EXECUTION_FILES)
    expected[compatibility.HELPER_NAME] = hashlib.sha256(source.read_bytes()).hexdigest()
    assert {name: expected[name] for name in CHANGED080} == CHANGED080
    for name, sha in CHANGED080.items():
        assert hashlib.sha256((source.parent / name).read_bytes()).hexdigest() == sha
    actual = cohorts.verifier_contract()
    assert actual == independent_profile(expected)
    assert actual["transitive_source_files"] == 171
    assert qualified().contract() == actual


def test_dated079_is_exact_original_graph_and_is_never_current080():
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_QUEUED_HTTP079_EXECUTION_FILES)
    dated = compatibility.prior_queued_http079_execution_contract()
    assert dated == independent_profile(files)
    assert dated["transitive_source_sha256"] == "045c982ed0283defc5ebf10e724ee4f1e30b32d58b92df98e0e2c515cf9e95da"
    assert hashlib.sha256(encoded(dated)).hexdigest() == "4a9d2c4f344282e82a8ca5e694eda48e3c348493a796e71652f92efb9de78308"
    assert files["kernel_tx.py"] == "5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125"
    current = cohorts.verifier_contract()
    assert current != dated
    # The four coordinator changes are transitive dependencies; primary readers stay exact.
    assert current["files"] == dated["files"]
    assert current["transitive_source_files"] == dated["transitive_source_files"] == 171
    with pytest.raises(ValueError, match="Source080 execution reader"):
        compatibility.qualify_execution(dated)


@pytest.mark.parametrize("name", HISTORICAL)
def test_all_exact_historical_profiles_remain_supported_and_immutable(name):
    admission = getattr(compatibility, name)()
    original = encoded(admission)
    pair = qualified()
    assert compatibility.require_supported(admission, pair) is True
    selected = compatibility.admission_contract(admission, pair)
    binding = compatibility.execution_binding(admission, pair)
    selected["files"].clear()
    binding["admission_reader"]["files"].clear()
    binding["execution_reader"]["files"].clear()
    assert encoded(admission) == original
    assert compatibility.require_supported(admission, pair) is True
    assert pair.contract() == cohorts.verifier_contract()


@pytest.mark.parametrize("name", (*CHANGED080, compatibility.HELPER_NAME))
def test_any_changed_current_source_identity_refuses(name):
    files = compatibility.execution_files()
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="Source080 execution reader"):
        compatibility.qualify_execution(independent_profile(files))


@pytest.mark.parametrize("name", ("resource_study_cohorts.py", "resource_study_runtime.py",
                                  "kernel_tx.py", compatibility.HELPER_NAME))
def test_changed_dated079_source_never_inherits_compatibility(name):
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_QUEUED_HTTP079_EXECUTION_FILES)
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(independent_profile(files), qualified())


def test_binding_truthfully_keeps_dated079_and_new080_distinct_without_credit():
    dated = compatibility.prior_queued_http079_execution_contract()
    original = encoded(dated)
    binding = compatibility.execution_binding(dated, qualified())
    assert binding["record_type"] == compatibility.BINDING_TYPE
    assert "079-080-reader-execution-binding-v1" in binding["record_type"]
    assert binding["admission_reader"] == dated
    assert binding["admission_reader_preserved"] is True
    assert binding["execution_reader_is_admission_reader"] is False
    assert binding["source080_current_head_metadata_view_changed"] is True
    assert binding["source080_finite_native122_buflo_root_pool_changed"] is True
    assert binding["source080_native_runtime_or_scientific_truth_conditions_changed"] is False
    assert binding["historical_receipts_requalified_by_compatibility"] is False
    assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0
    assert encoded(dated) == original


@pytest.mark.parametrize("change", ("missing", "extra", "bad_hash"))
def test_unsealed_current_map_refuses_before_qualifying(monkeypatch, change):
    broken = deepcopy(compatibility.APPROVED_EXECUTION_FILES)
    if change == "missing":
        del broken["resource_study_cohorts.py"]
    elif change == "extra":
        broken["operator_override.py"] = "0" * 64
    else:
        broken["resource_study_cohorts.py"] = "not-a-source-hash"
    monkeypatch.setattr(compatibility, "APPROVED_EXECUTION_FILES", broken)
    with pytest.raises(ValueError, match="Source080.*not sealed"):
        compatibility.execution_files()


def test_qualified_object_cannot_be_replaced_with_an_operator_value():
    with pytest.raises(ValueError, match="qualified Source080 execution reader"):
        compatibility.require_supported(compatibility.prior_queued_http079_execution_contract(), object())
