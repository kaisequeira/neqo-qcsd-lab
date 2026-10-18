"""Focused Source081 source-identity controls; ROOT alone executes.

No receipt, qualification, runtime build, admission, SQL or capture is created.
Current081 two-module cap route and dated080 pool contracts remain distinct.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility

CHANGED081 = {
    'resource_study.py': '8b1bc5887aaa00db637d4a75aaa22073f1f3dc0b3723e1fc7f817a906a58331d',
    'resource_study_cohorts.py': '0b6e10ff93e72e633973b310fd123ecbe9c7160671f393ab6e087b494a105a68',
}
CURRENT_GRAPH = '0e4f6e54db1fc3ecab32ace8fe255672906def03b03eade6ee98bec0fd5bae11'
CURRENT_CONTRACT = '42c79c397e1f8dab619bdff6b942395be73abb87550391217fac72b3b9290f34'
DATED080_GRAPH = 'd0d52cf673de93f70a088ab4ca3b919dad7fe94ea449e1078dedcf8569a7bc95'
DATED080_CONTRACT = 'ef335d5ee0546ede40b96936162fc1a930d060f7c38f7e5396c371929e628579'
HISTORICAL = (
    'legacy_contract', 'prior_execution_contract', 'prior_capture_execution_contract',
    'prior_analysis_execution_contract', 'prior_flight_execution_contract',
    'prior_monitor_execution_contract', 'prior_authority_execution_contract',
    'prior_frozen_manifest_execution_contract', 'prior_primary_partial_execution_contract',
    'prior_fin_permission_execution_contract', 'prior_explicit_prepared_policy_execution_contract',
    'prior_complete_fin069_execution_contract', 'prior_explicit_duration070_execution_contract',
    'prior_explicit_budget071_execution_contract', 'prior_queued_http079_execution_contract',
    'prior_bf_pool080_execution_contract',
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False)+'\n').encode()


def independent_profile(files):
    return {'record_type': 'qcsd-resource-domain-runtime-cohort-verifier-contract-v1',
        'schema_version': 1, 'implementation': 'resource-study-raw-v1',
        'files': {name: files[name] for name in compatibility.PRIMARY_FILES},
        'transitive_source_sha256': hashlib.sha256(encoded(files)).hexdigest(),
        'transitive_source_files': len(files),
        'transitive_source_scope': 'complete declared package-import closure; conservative dormant branches included'}


def qualified():
    return compatibility.qualify_execution(cohorts.verifier_contract())


def test_current081_exact_two_new_modules_and_actual_complete171_graph():
    assert compatibility.EXECUTION_KIND == '081'
    source = Path(compatibility.__file__).resolve(strict=True)
    observed = {name: hashlib.sha256((source.parent/name).read_bytes()).hexdigest()
                for name in compatibility.execution_files()}
    assert len(observed) == 171
    assert {name: observed[name] for name in CHANGED081} == CHANGED081
    assert observed[compatibility.HELPER_NAME] == hashlib.sha256(source.read_bytes()).hexdigest()
    current = cohorts.verifier_contract()
    assert current == independent_profile(observed)
    assert current['transitive_source_sha256'] == CURRENT_GRAPH
    assert hashlib.sha256(encoded(current)).hexdigest() == CURRENT_CONTRACT
    assert qualified().contract() == current


def test_dated080_pool_and_current081_are_exact_separate_source_contracts():
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_BF_POOL080_EXECUTION_FILES)
    dated = compatibility.prior_bf_pool080_execution_contract()
    assert dated == independent_profile(files)
    assert dated['transitive_source_sha256'] == DATED080_GRAPH
    assert hashlib.sha256(encoded(dated)).hexdigest() == DATED080_CONTRACT
    assert files['resource_study.py'] == '2058cdc53cfba9c65b6554449f9caeae26459f3324ae8a8890e29b4d93d625d5'
    assert files['resource_study_cohorts.py'] == '84b59afc772db6794bd4319ec048f42fbb87924fa1bbec701bb8cf647212696c'
    assert files[compatibility.HELPER_NAME] == '8d325565cb44610a1473b8cc474ee3fbdf4684a6a79c9b01eac83f7bb3405648'
    current = cohorts.verifier_contract()
    assert current != dated and current['files'] == dated['files']
    assert compatibility.require_supported(dated, qualified()) is True
    with pytest.raises(ValueError, match='Source081 execution reader'):
        compatibility.qualify_execution(dated)


def test_dated079_runtime_producer_identity_is_unchanged():
    dated = compatibility.prior_queued_http079_execution_contract()
    assert dated['transitive_source_sha256'] == '045c982ed0283defc5ebf10e724ee4f1e30b32d58b92df98e0e2c515cf9e95da'
    assert hashlib.sha256(encoded(dated)).hexdigest() == '4a9d2c4f344282e82a8ca5e694eda48e3c348493a796e71652f92efb9de78308'
    assert compatibility.require_supported(dated, qualified()) is True
    with pytest.raises(ValueError, match='Source081 execution reader'):
        compatibility.qualify_execution(dated)


@pytest.mark.parametrize('name', HISTORICAL)
def test_each_exact_historical_contract_is_supported_without_mutable_alias(name):
    admission = getattr(compatibility, name)()
    original = encoded(admission)
    pair = qualified()
    assert compatibility.require_supported(admission, pair) is True
    selected = compatibility.admission_contract(admission, pair)
    binding = compatibility.execution_binding(admission, pair)
    selected['files'].clear()
    binding['admission_reader']['files'].clear()
    binding['execution_reader']['files'].clear()
    assert encoded(admission) == original
    assert pair.contract() == cohorts.verifier_contract()


@pytest.mark.parametrize('name', (*CHANGED081, compatibility.HELPER_NAME))
def test_mixed_current081_source_never_qualifies(name):
    files = compatibility.execution_files()
    files[name] = '0'*64
    with pytest.raises(ValueError, match='Source081 execution reader'):
        compatibility.qualify_execution(independent_profile(files))


@pytest.mark.parametrize('name', (*CHANGED081, 'resource_study_runtime.py', 'kernel_tx.py', compatibility.HELPER_NAME))
def test_changed_dated080_profile_never_inherits_compatibility(name):
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_BF_POOL080_EXECUTION_FILES)
    files[name] = '0'*64
    with pytest.raises(ValueError, match='admission reader'):
        compatibility.require_supported(independent_profile(files), qualified())


def test_binding_preserves_pool080_while_declaring_new081_cap_route_without_credit():
    dated = compatibility.prior_bf_pool080_execution_contract()
    original = encoded(dated)
    binding = compatibility.execution_binding(dated, qualified())
    assert binding['record_type'] == compatibility.BINDING_TYPE
    assert '079-080-081-reader-execution-binding-v1' in binding['record_type']
    assert binding['admission_reader'] == dated and binding['admission_reader_preserved'] is True
    assert binding['execution_reader_is_admission_reader'] is False
    assert binding['source081_same_runtime_capped_cover_admission_changed'] is True
    assert binding['source081_native_runtime_or_scientific_truth_conditions_changed'] is False
    assert binding['source080_current_head_metadata_view_changed'] is True
    assert binding['source080_finite_native122_buflo_root_pool_changed'] is True
    assert binding['historical_receipts_requalified_by_compatibility'] is False
    assert binding['authority_issued'] is False and binding['scientific_credit_added'] == 0
    assert encoded(dated) == original


@pytest.mark.parametrize('change', ('missing', 'extra', 'bad_hash'))
def test_unsealed_current081_map_refuses(monkeypatch, change):
    broken = deepcopy(compatibility.APPROVED_EXECUTION_FILES)
    if change == 'missing':
        del broken['resource_study_cohorts.py']
    elif change == 'extra':
        broken['operator_override.py'] = '0'*64
    else:
        broken['resource_study_cohorts.py'] = 'not-a-source-hash'
    monkeypatch.setattr(compatibility, 'APPROVED_EXECUTION_FILES', broken)
    with pytest.raises(ValueError, match='Source081.*not sealed'):
        compatibility.execution_files()


def test_operator_value_is_not_a_qualified081_execution_reader():
    with pytest.raises(ValueError, match='qualified Source081 execution reader'):
        compatibility.require_supported(compatibility.prior_bf_pool080_execution_contract(), object())
