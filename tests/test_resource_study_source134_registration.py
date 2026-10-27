"""Source134 registration controls only; no synthetic runtime confers readiness or credit."""
from copy import deepcopy
import hashlib
from pathlib import Path
import re
import pytest
from qcsd_lab import capture_acceptance_policy as policy
from qcsd_lab import cs_supplemental_chaff as cs
from qcsd_lab import ft_supplemental_chaff as ft
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as reader


def test_current134_complete189_supports_literal133132131_readers():
    current = cohorts._fresh_verifier_contract()
    qualified = reader.qualify_execution(current)
    assert reader.EXECUTION_KIND == "134"
    assert current == qualified.contract() and current["transitive_source_files"] == 189
    assert set(reader.execution_files()) == set(cohorts.RAW_DEPENDENCIES)
    assert len(reader.PRIOR_EXACT133_FILES) == len(reader.PRIOR_SDK133_PACKAGE_FILES) == 189
    assert reader.prior_exact133_execution_contract() == reader.PRIOR_SDK133_PROFILE
    for old in (reader.prior_exact133_execution_contract(),
                reader.prior_exact132_execution_contract(), reader.prior_exact131_execution_contract()):
        assert reader.require_supported(old, qualified) is True
        with pytest.raises(ValueError, match="unsupported or changed Source134"):
            reader.qualify_execution(old)
        value = reader.execution_binding(old, qualified)
        assert value["admission_reader"] == old and value["execution_reader"] == current
        assert value["historical_receipts_requalified_by_compatibility"] is False
        assert value["authority_issued"] is False and value["scientific_credit_added"] == 0


@pytest.mark.parametrize("mutation", ["changed-policy", "omitted-helper", "borrowed133-helper", "partial-count", "old133-renamed"])
def test_current134_refuses_changed_partial_or_borrowed_source_graphs(mutation):
    if mutation == "old133-renamed":
        changed = deepcopy(reader.PRIOR_SDK133_PROFILE)
        changed["transitive_source_files"] = 189
    else:
        files = reader.execution_files()
        if mutation == "changed-policy":
            files["capture_acceptance_policy.py"] = "0" * 64
        elif mutation == "omitted-helper":
            files.pop(reader.HELPER_NAME)
        elif mutation == "borrowed133-helper":
            files[reader.HELPER_NAME] = reader.PRIOR_EXACT133_FILES[reader.HELPER_NAME]
        changed = reader._profile(files)
        if mutation == "partial-count":
            changed["transitive_source_files"] = 188
    with pytest.raises(ValueError, match="unsupported or changed Source134"):
        reader.qualify_execution(changed)


def test_only_two_python_sources_change_and_complete133_prefixes_remain_literal():
    current = reader.execution_files()
    old = reader.PRIOR_EXACT133_FILES
    assert set(current) == set(old)
    assert {name for name in current if current[name] != old[name]} == {
        "capture_acceptance_policy.py", "resource_study_reader_compatibility.py"}
    for filename, size, digest in [('capture_acceptance_policy.py', 86871, '4113220703e3b197a7857a13b25d5a04a2c3fce13dc857e0008094d3f76a4675'), ('resource_study_reader_compatibility.py', 687786, '9319663ae34d0f54689ce893c61f04721f170debc71c05ed56b12a3691d9ec7e')]:
        raw = (Path(reader.__file__).parent / filename).read_bytes()
        assert len(raw) > size and hashlib.sha256(raw[:size]).hexdigest() == digest
    for name, row in reader.PRIOR_SDK133_PACKAGE_FILES.items():
        assert row["sha256"] == old[name] and type(row["bytes"]) is int and row["bytes"] > 0


def test_actual160_adds_only_the_full_kernel15_runner23_source_fence():
    new = reader.SOURCE134_NATIVE160_COMMIT
    assert re.fullmatch(r"[0-9a-f]{40}", new)
    assert new not in {reader.SOURCE133_NATIVE159_COMMIT, reader.SOURCE132_NATIVE158_COMMIT}
    assert policy.SOURCE134_NATIVE160_COMMIT == new
    assert policy.CONSERVATIVE_ENQUEUE_REQUIRED_NATIVE_COMMITS == frozenset({
        "d6a37bd7b6180b7a303923b7adafea9add968675",
        "c9e09e7972eed46b44e5de59bf1433b10c8fa72c",
        policy.SOURCE132_NATIVE158_COMMIT, policy.SOURCE133_NATIVE159_COMMIT, new})
    # This exercises the source-downgrade fence only, not full kernel validity or credit.
    policy._require_conservative_enqueue_source_contract(
        {"migration_commit": new, "runner_wakeup_metrics": {"schema_version": 23}},
        {"schema_version": 15})
    for kernel, runner in ((14, 23), (15, 22), (13, 21), (True, 23), (15, True), (15, 23.0)):
        with pytest.raises(ValueError, match="exact kernel15/runner23"):
            policy._require_conservative_enqueue_source_contract(
                {"migration_commit": new, "runner_wakeup_metrics": {"schema_version": runner}},
                {"schema_version": kernel})


def test_160_cannot_borrow_retained158_or159_supplemental_authority():
    old158, old159 = ft.SOURCE132_NATIVE158_COMMIT, ft.SOURCE133_NATIVE159_COMMIT
    assert old159 == cs.SOURCE133_NATIVE159_COMMIT == reader.SOURCE133_NATIVE159_COMMIT
    for old in (old158, old159):
        value = {"native_commit": old, "source": {"neqo_commit": old}}
        assert ft.require_registered_ft_runtime(value) is value
        if old == old159:
            assert cs.require_native159_runtime(value) is value
    new = reader.SOURCE134_NATIVE160_COMMIT
    for actual, source in ((new, new), (new, old159), (old159, new)):
        value = {"native_commit": actual, "source": {"neqo_commit": source}}
        with pytest.raises(ValueError):
            ft.require_registered_ft_runtime(value)
        with pytest.raises(ValueError):
            cs.require_native159_runtime(value)
