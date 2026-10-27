"""Pure Source132 metadata controls; no runtime, SQL, Native or recording credit."""
import copy
import pytest
from qcsd_lab import capture_acceptance_policy as policy
from qcsd_lab import ft_supplemental_chaff as ft
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as reader

def test_source132_has_complete188_profile_and_preserves_exact131_reader179_package187():
    current = cohorts._fresh_verifier_contract()
    qualified = reader.qualify_execution(current)
    assert reader.EXECUTION_KIND == "132"
    assert current == qualified.contract() and current["transitive_source_files"] == 188
    files = reader.execution_files()
    assert set(files) == set(cohorts.RAW_DEPENDENCIES)
    assert len(files) == 188
    assert len(reader.PRIOR_EXACT131_FILES) == 179
    assert len(reader.PRIOR_SDK131_PACKAGE_FILES) == 187
    assert "ft_supplemental_chaff.py" not in reader.PRIOR_SDK131_PACKAGE_FILES
    old = reader.prior_exact131_execution_contract()
    assert old == reader.PRIOR_SDK131_PROFILE and old["transitive_source_files"] == 179
    assert reader.require_supported(old, qualified) is True
    binding = reader.execution_binding(old, qualified)
    assert binding["record_type"] == reader.BINDING_TYPE
    assert binding["source132_prior131_reader179_and_full_package187_preserved_without_relabelling"] is True
    assert binding["admission_reader"] == old and binding["execution_reader"] == current
    assert binding["historical_receipts_requalified_by_compatibility"] is False
    assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0

def test_current132_never_qualifies_a_dated_or_partial_or_changed_profile():
    current = cohorts._fresh_verifier_contract()
    qualified = reader.qualify_execution(current)
    dated = [reader.prior_exact131_execution_contract(),
             reader.prior_exact130_execution_contract(),
             reader.prior_explicit_duration070_execution_contract()]
    for old in dated:
        assert reader.require_supported(old, qualified) is True
        with pytest.raises(ValueError, match="unsupported or changed Source132"):
            reader.qualify_execution(old)
    actual = reader.execution_files()
    wrong = dict(actual);wrong["ft_supplemental_chaff.py"] = "0" * 64
    with pytest.raises(ValueError, match="unsupported or changed Source132"):
        reader.qualify_execution(reader._profile(wrong))
    partial = dict(actual);partial.pop("report.py")
    with pytest.raises(ValueError, match="unsupported or changed Source132"):
        reader.qualify_execution(reader._profile(partial))
    wrong = copy.deepcopy(current);wrong["transitive_source_files"] = 180
    with pytest.raises(ValueError, match="unsupported or changed Source132"):
        reader.qualify_execution(wrong)

def test_native158_schema7_guard_requires_exact_new_commit_and_matching_source():
    commit = ft.SOURCE132_NATIVE158_COMMIT
    assert commit == reader.SOURCE132_NATIVE158_COMMIT
    assert commit not in {"c9e09e7972eed46b44e5de59bf1433b10c8fa72c",
                          "d6a37bd7b6180b7a303923b7adafea9add968675"}
    actual = {"native_commit": commit, "source": {"neqo_commit": commit}}
    assert ft.require_native158_runtime(actual) is actual
    for value in [None, {}, {"native_commit": commit, "source": {}},
                  {"native_commit": "c9e09e7972eed46b44e5de59bf1433b10c8fa72c",
                   "source": {"neqo_commit": "c9e09e7972eed46b44e5de59bf1433b10c8fa72c"}}]:
        with pytest.raises(ValueError, match="exact new Native158"):
            ft.require_native158_runtime(value)

def test_additive_native158_conservative_contract_keeps154_and157_requirements():
    old = {"d6a37bd7b6180b7a303923b7adafea9add968675",
           "c9e09e7972eed46b44e5de59bf1433b10c8fa72c"}
    assert policy.CONSERVATIVE_ENQUEUE_REQUIRED_NATIVE_COMMITS == old | {ft.SOURCE132_NATIVE158_COMMIT}
    for commit in policy.CONSERVATIVE_ENQUEUE_REQUIRED_NATIVE_COMMITS:
        run = {"migration_commit": commit, "runner_wakeup_metrics": {"schema_version": 23}}
        policy._require_conservative_enqueue_source_contract(run, {"schema_version": 15})
        with pytest.raises(ValueError, match="exact kernel15/runner23"):
            policy._require_conservative_enqueue_source_contract(run, {"schema_version": 14})
        run["runner_wakeup_metrics"]["schema_version"] = 22
        with pytest.raises(ValueError, match="exact kernel15/runner23"):
            policy._require_conservative_enqueue_source_contract(run, {"schema_version": 15})
    # This exercises only the identity gate, not a fabricated physical receipt.
    policy._require_conservative_enqueue_source_contract({"migration_commit": "0" * 40}, None)

