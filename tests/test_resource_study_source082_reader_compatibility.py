"""Actual current082 source closure and exact dated081/080 interoperability."""
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility
from tests.test_resource_study_source081_reader_compatibility import encoded, independent_profile


def qualified():
    return compatibility.qualify_execution(cohorts.verifier_contract())


def test_actual082_complete_source_closure_has_truthful_fresh_retry_identity():
    assert compatibility.EXECUTION_KIND == '082'
    source = Path(compatibility.__file__).resolve(strict=True)
    observed = {name: hashlib.sha256((source.parent/name).read_bytes()).hexdigest()
                for name in compatibility.execution_files()}
    assert len(observed) == 171
    assert observed['resource_study.py'] == 'e5169ee3ce7613bf44482549c9399d9dc74c952f3be57e65c88f30192b4bbe0e'
    assert observed[compatibility.HELPER_NAME] == '4d29400859548d1d275622f649c1bb3b813bc1afbd542d0cbb28b267f6cf9f6e'
    current = cohorts.verifier_contract()
    assert current == independent_profile(observed)
    assert current['transitive_source_sha256'] == '3f81a0b08b7f96fe8014a41dfd27eb1a925673a5ee37c11f6e361d3f44a158b6'
    assert hashlib.sha256(encoded(current)).hexdigest() == '314883f65b3105cd3ef13480125fa03b5c7839f371da367c9029763746e09f45'
    assert qualified().contract() == current


@pytest.mark.parametrize('name,graph,contract', [
    ('prior_capped_cover081_execution_contract',
     '0e4f6e54db1fc3ecab32ace8fe255672906def03b03eade6ee98bec0fd5bae11',
     '42c79c397e1f8dab619bdff6b942395be73abb87550391217fac72b3b9290f34'),
    ('prior_bf_pool080_execution_contract',
     'd0d52cf673de93f70a088ab4ca3b919dad7fe94ea449e1078dedcf8569a7bc95',
     'ef335d5ee0546ede40b96936162fc1a930d060f7c38f7e5396c371929e628579'),
])
def test_exact_dated_reader_is_supported_and_cannot_impersonate_current(name, graph, contract):
    dated = getattr(compatibility, name)()
    original = deepcopy(dated)
    assert dated['transitive_source_sha256'] == graph
    assert hashlib.sha256(encoded(dated)).hexdigest() == contract
    pair = qualified()
    assert compatibility.require_supported(dated, pair) is True
    with pytest.raises(ValueError, match='Source082 execution reader'):
        compatibility.qualify_execution(dated)
    binding = compatibility.execution_binding(dated, pair)
    assert binding['admission_reader'] == original
    assert binding['execution_reader'] == pair.contract()
    assert binding['execution_reader_is_admission_reader'] is False
    assert binding['source082_bounded_fresh_buflo_collector_retries_changed'] is True
    assert binding['source082_buflo_max_consecutive_collector_failures'] == 3
    assert binding['source082_native_runtime_or_scientific_truth_conditions_changed'] is False
    binding['admission_reader']['files'].clear()
    assert dated == original


@pytest.mark.parametrize('name', ['resource_study.py', compatibility.HELPER_NAME])
def test_mixed_current082_source_refused(name):
    files = compatibility.execution_files()
    files[name] = '0'*64
    with pytest.raises(ValueError, match='Source082 execution reader'):
        compatibility.qualify_execution(independent_profile(files))
