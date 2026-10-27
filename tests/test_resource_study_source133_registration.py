"""Source metadata only; synthetic runtime dictionaries confer no readiness/credit."""
from copy import deepcopy
import re
import pytest
from qcsd_lab import capture_acceptance_policy as policy
from qcsd_lab import cs_supplemental_chaff as cs
from qcsd_lab import ft_supplemental_chaff as ft
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as reader


def test_exact_current189_supports_saved132188_and131179_without_requalification():
    actual = cohorts._fresh_verifier_contract()
    qualified = reader.qualify_execution(actual)
    assert reader.EXECUTION_KIND == "133" and actual == qualified.contract()
    assert actual["transitive_source_files"] == 189
    assert set(reader.execution_files()) == set(cohorts.RAW_DEPENDENCIES)
    assert len(reader.PRIOR_SDK132_PACKAGE_FILES) == len(reader.PRIOR_EXACT132_FILES) == 188
    assert len(reader.PRIOR_EXACT131_FILES) == 179 and len(reader.PRIOR_SDK131_PACKAGE_FILES) == 187
    for old in (reader.prior_exact132_execution_contract(), reader.prior_exact131_execution_contract()):
        assert reader.require_supported(old, qualified) is True
        with pytest.raises(ValueError, match="unsupported or changed Source133"):
            reader.qualify_execution(old)
        bound = reader.execution_binding(old, qualified)
        assert bound["admission_reader"] == old and bound["execution_reader"] == actual
        assert bound["historical_receipts_requalified_by_compatibility"] is False
        assert bound["authority_issued"] is False and bound["scientific_credit_added"] == 0


@pytest.mark.parametrize("mutation", ["CS-source", "FT-source", "drop-CS", "partial-count", "old132-renamed"])
def test_complete_source_authority_refuses_changed_or_partial_graph(mutation):
    files = reader.execution_files()
    if mutation == "old132-renamed":
        value = deepcopy(reader.PRIOR_SDK132_PROFILE)
        value["transitive_source_files"] = 189
    else:
        if mutation in ("CS-source", "FT-source"):
            files["cs_supplemental_chaff.py" if mutation == "CS-source" else "ft_supplemental_chaff.py"] = "0" * 64
        elif mutation == "drop-CS":
            files.pop("cs_supplemental_chaff.py")
        value = reader._profile(files)
        if mutation == "partial-count":
            value["transitive_source_files"] = 188
    with pytest.raises(ValueError, match="unsupported or changed Source133"):
        reader.qualify_execution(value)


def test_genuine_future159_FT_CS_axes_are_distinct_from_historical158():
    new = reader.SOURCE133_NATIVE159_COMMIT
    old = ft.SOURCE132_NATIVE158_COMMIT
    assert re.fullmatch(r"[0-9a-f]{40}", new) and new != old
    assert cs.SOURCE133_NATIVE159_COMMIT == ft.SOURCE133_NATIVE159_COMMIT == policy.SOURCE133_NATIVE159_COMMIT == new
    for commit in (old, new):
        runtime = {"native_commit": commit, "source": {"neqo_commit": commit}}
        assert ft.require_registered_ft_runtime(runtime) is runtime
        if commit == new:
            assert cs.require_native159_runtime(runtime) is runtime
        else:
            assert ft.require_native158_runtime(runtime) is runtime
            with pytest.raises(ValueError):
                cs.require_native159_runtime(runtime)
    for actual, source in ((new, old), (old, new), ("0" * 40, "0" * 40)):
        runtime = {"native_commit": actual, "source": {"neqo_commit": source}}
        with pytest.raises(ValueError):
            ft.require_registered_ft_runtime(runtime)
        with pytest.raises(ValueError):
            cs.require_native159_runtime(runtime)
    assert cs.MODES == ("cs-buflo",) and ft.MODES == ("front", "tamaraw")
    assert cs.POLICY != ft.POLICY and cs.SCOPE != ft.SCOPE


def test_current159_keeps_original_full_kernel15_runner23_identity_gate():
    commit = reader.SOURCE133_NATIVE159_COMMIT
    assert commit in policy.CONSERVATIVE_ENQUEUE_REQUIRED_NATIVE_COMMITS
    policy._require_conservative_enqueue_source_contract(
        {"migration_commit": commit, "runner_wakeup_metrics": {"schema_version": 23}},
        {"schema_version": 15})
    for kernel, runner in ((14, 23), (15, 22), (13, 21)):
        with pytest.raises(ValueError, match="exact kernel15/runner23"):
            policy._require_conservative_enqueue_source_contract(
                {"migration_commit": commit, "runner_wakeup_metrics": {"schema_version": runner}},
                {"schema_version": kernel})
