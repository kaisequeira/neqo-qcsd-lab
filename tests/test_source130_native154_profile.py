"""Source130/Native154 metadata and synthetic proof-contract controls only.

These controls grant no runtime readiness, physical capture or formal credit.
"""
from copy import deepcopy
import hashlib

import pytest

from qcsd_lab import capture_acceptance_policy as policy
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as reader
from qcsd_lab.resource_study_inputs import canonical_json
from tests import test_buflo_cadence64_budget640 as cadence
from tests import test_kernel_tx_conservative_enqueue_witness as witness
from tests import test_kernel_tx_layered_feedback as layered

NATIVE154 = "d6a37bd7b6180b7a303923b7adafea9add968675"


def test_actual130_complete179_profile_matches_registered_current_reader():
    actual = cohorts._fresh_verifier_contract()
    assert actual == reader._profile(reader.execution_files())
    assert reader.EXECUTION_KIND == "130"
    assert actual["transitive_source_files"] == len(cohorts.RAW_DEPENDENCIES) == 179
    assert reader.qualify_execution(actual).contract() == actual


def test_exact129_history_remains_literal_and_compatible_without_relabelling():
    files = reader.PRIOR_EXACT129_FILES
    assert len(files) == 179
    assert files["resource_study_reader_compatibility.py"] == "55b6b8bf8244979bc88e085ce882656979de29dc0f0ed9ca8ca55c5ed1ca6568"
    assert hashlib.sha256(canonical_json(files)).hexdigest() == "38d32ec5144ae522589edea1c5b015c6539ad4c8061618ff36157ed1df21536d"
    old = reader.prior_exact129_execution_contract()
    original = canonical_json(old)
    qualified = reader.qualify_execution(cohorts._fresh_verifier_contract())
    assert reader.require_supported(old, qualified) is True
    assert reader.require_supported(reader.prior_exact128_execution_contract(), qualified) is True
    binding = reader.execution_binding(old, qualified)
    assert binding["admission_reader"] == old
    assert binding["execution_reader"] == qualified.contract()
    assert binding["execution_reader_is_admission_reader"] is False
    assert binding["source130_exact129_full179_profile_preserved_without_relabelling"] is True
    assert canonical_json(old) == original


def test_historical129_is_not_current_execution_authority():
    with pytest.raises(ValueError, match="execution reader"):
        reader.qualify_execution(reader.prior_exact129_execution_contract())


@pytest.mark.parametrize("name", ["kernel_tx.py", "fidelity.py", "capture_session.py",
    "buflo_handoff.py", "capture_acceptance_policy.py"])
def test_each_changed_physics_file_must_match_the_exact_current_profile(name):
    files = reader.execution_files()
    files[name] = "0" * 64
    with pytest.raises(ValueError, match="execution reader"):
        reader.qualify_execution(reader._profile(files))


@pytest.mark.parametrize("late", [False, True])
def test_actual154_requires_and_accepts_the_real15_fixture_in_both_public_entries(late):
    value = witness.run(witness.receipt(late_userspace=late))
    value["migration_commit"] = NATIVE154
    original = deepcopy(value)
    policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), value)
    assert policy.buflo_incoming_release_window(value) == 32_000
    assert value == original


@pytest.mark.parametrize("change", ["whole14", "whole13", "missing-kernel",
    "bool-kernel", "runner22", "bool-runner"])
def test_actual154_entire_legacy_or_malformed_downgrade_fails_both_public_entries(change):
    value = witness.run(witness.receipt())
    value["migration_commit"] = NATIVE154
    wakeups = value["runner_wakeup_metrics"]
    if change == "whole14":
        value = cadence.native_run(layered.layered_receipt())
        value["migration_commit"] = NATIVE154
    elif change == "whole13":
        value = cadence.native_run()
        value["migration_commit"] = NATIVE154
    elif change == "missing-kernel":
        del wakeups["buflo_kernel_tx"]
    elif change == "bool-kernel":
        wakeups["buflo_kernel_tx"]["schema_version"] = True
    elif change == "runner22":
        wakeups["schema_version"] = 22
    else:
        wakeups["schema_version"] = True
    for validate in (lambda: policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), value),
        lambda: policy.buflo_incoming_release_window(value)):
        with pytest.raises(ValueError, match="requires exact kernel15/runner23"):
            validate()


def test_historical_exact14_guard_remains_separate_from_exact154_identity():
    assert policy.CONSERVATIVE_ENQUEUE_REQUIRED_NATIVE_COMMITS == frozenset({NATIVE154})
    assert len(policy.LAYERED_TX_REQUIRED_NATIVE_COMMITS) == 7
    assert NATIVE154 not in policy.LAYERED_TX_REQUIRED_NATIVE_COMMITS
    old = cadence.native_run(layered.layered_receipt())
    old["migration_commit"] = "01e226fb43000691acbda57feb338855b26e66ca"
    policy.validate_buflo_kernel_preparation_source_binding(cadence.source(), old)
