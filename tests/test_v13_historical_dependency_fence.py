"""Historical fence representation and typed raw-observation controls.

These local zero-credit fixtures call no browser, network, capture, Git or
historical Source verifier. Copy this file into the prospective Source tests/.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import stat

import pytest


ROOT = Path(__file__).absolute().parents[1]
spec = importlib.util.spec_from_file_location('_v13_historical_fence_under_test',
    ROOT / 'tools/whole_graph_discovery_v13/graph_input.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


def fixture(tmp_path, mode=0o644):
    archive = tmp_path / 'original-archive'; archive.mkdir(mode=0o700)
    target = archive / 'original-raw.log'; target.write_bytes(b'original retained raw bytes\n')
    target.chmod(mode)
    legacy = {**producer.reference(target), 'mode': mode}
    closure = archive / 'original-closure.json'
    producer.create(closure, {'zero_credit_unit_fixture': True, 'references': [legacy]})
    batch_root = tmp_path / 'closed-batch'; batch_root.mkdir(mode=0o700)
    batch = batch_root / 'batch.json'; producer.create(batch, {'zero_credit_unit_fixture': True})
    plan = {'previous_batch': producer.reference(batch),
            'authenticated_historical_closure': producer.reference(closure)}
    return plan, closure, target, legacy


@pytest.mark.parametrize('mode', [0o600, 0o644, 0o2644])
def test_fence_normalizes_only_equivalent_historical_mode_and_preserves_original_bytes(tmp_path, mode):
    plan, closure, target, legacy = fixture(tmp_path, mode)
    before = closure.read_bytes(); fence = producer.dependency_fence(plan)
    retained = {row['path']: row for row in fence['files']}
    assert retained[str(target)] == producer.reference(target)
    assert retained[str(target)]['mode'] == f'{mode:04o}'
    assert stat.S_IMODE(target.stat().st_mode) == mode
    assert producer.load(closure)['references'][0] == legacy and closure.read_bytes() == before
    producer.verify_fence(fence)


@pytest.mark.parametrize('mutation', ['bytes', 'mode', 'symlink', 'extra-member'])
def test_closed_fence_refuses_raw_mode_link_or_batch_membership_change(tmp_path, mutation):
    plan, closure, target, legacy = fixture(tmp_path); fence = producer.dependency_fence(plan)
    if mutation == 'bytes': target.write_bytes(b'changed original raw bytes\n')
    elif mutation == 'mode': target.chmod(0o600)
    elif mutation == 'symlink':
        other = target.with_name('different-raw.log'); other.write_bytes(target.read_bytes()); other.chmod(0o644)
        target.unlink(); target.symlink_to(other)
    else: Path(plan['previous_batch']['path']).parent.joinpath('unbound-raw').write_bytes(b'extra')
    with pytest.raises(ValueError): producer.verify_fence(fence)


@pytest.mark.parametrize('mutation', [
    'wrong-integer-mode', 'wrong-sha', 'bool-mode', 'float-mode', 'noncanonical-text-mode',
    'permission-overflow', 'negative-mode', 'relative-path', 'parent-path', 'symlink',
])
def test_historical_compatibility_rejects_inequivalent_or_malformed_reference(tmp_path, mutation):
    plan, closure, target, legacy = fixture(tmp_path)
    if mutation == 'wrong-integer-mode': legacy['mode'] = 0o600
    elif mutation == 'wrong-sha': legacy['sha256'] = '0' * 64
    elif mutation == 'bool-mode': legacy['mode'] = True
    elif mutation == 'float-mode': legacy['mode'] = float(0o644)
    elif mutation == 'noncanonical-text-mode': legacy['mode'] = '644'
    elif mutation == 'permission-overflow': legacy['mode'] = 0o10000
    elif mutation == 'negative-mode': legacy['mode'] = -1
    elif mutation == 'relative-path': legacy['path'] = target.name
    elif mutation == 'parent-path': legacy['path'] = str(target.parent / 'unused' / '..' / target.name)
    else:
        other = target.with_name('different-raw.log'); other.write_bytes(target.read_bytes()); other.chmod(0o644)
        target.unlink(); target.symlink_to(other)
    changed = closure.with_name('changed-original-fixture.json')
    producer.create(changed, {'zero_credit_unit_fixture': True, 'references': [legacy]})
    plan['authenticated_historical_closure'] = producer.reference(changed)
    with pytest.raises(ValueError): producer.dependency_fence(plan)


def test_top_level_v13_reference_keeps_strict_octal_text_schema(tmp_path):
    plan, closure, target, legacy = fixture(tmp_path); plan['direct_v13_reference'] = legacy
    with pytest.raises(ValueError): producer.dependency_fence(plan)
    with pytest.raises(ValueError): producer.reopen(legacy)


def old_ref(path):
    ref = producer.reference(path)
    return {**ref, 'mode': int(ref['mode'], 8)}


def v8_fixture(tmp_path):
    plan, _, _, _ = fixture(tmp_path)
    source = tmp_path / 'past-producer'; source.mkdir(mode=0o700)
    names = {'README.md', 'graph_input.py', 'operator.py', 'discovery_control.py',
             'discovery_evidence_control.py', 'navigation_control.py', 'test_v8.py'}
    for name in names:
        (source / name).write_bytes(b'zero-credit current fixture Source\n'); (source / name).chmod(0o644)
    gate = tmp_path / 'past-gate'; gate.mkdir(mode=0o700)
    snapshot = gate / 'source-snapshot'; snapshot.mkdir(mode=0o700)
    archived = snapshot / 'test_v8.py'; archived.write_bytes(b'zero-credit old fixture test Source\n'); archived.chmod(0o644)
    observations = {name: old_ref(source / name) for name in names}
    observations['test_v8.py']['sha256'] = producer.reference(archived)['sha256']
    before, after = gate / 'source-before.json', gate / 'source-after.json'
    producer.create(before, observations); producer.create(after, observations)
    raws = []
    for name in ('unit-started.json', 'unit-completed.json', 'unit.stdout.log', 'unit.stderr.log'):
        path = gate / name
        path.write_bytes(b'{"zero_credit_unit_fixture":true}\n'); path.chmod(0o644)
        raws.append(old_ref(path))
    # Data fixtures are never sent to the historical verifier or claimed as
    # original passing operations. Only the finite fence schema is exercised.
    value = {
        'artifact_type': 'qcsd-external-v8-generic-supplement-catalogue-source-closure-v1',
        'schema_version': 1, 'contract': 'catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v8',
        'plan_type': 'qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v8',
        'input_type': 'qcsd-external-browser-whole-graph-input-v8',
        'scientific_credit': False, 'formal_accepted_trace_count': 0, 'effects_executed': False,
        'source_root': str(source), 'source_files': {name: old_ref(source / name) for name in names},
        'raw_operations': [{'gate': 1, 'name': 'unit', 'completion': {}, 'files': raws}],
        'read_only_refs': [old_ref(before), old_ref(after), old_ref(archived)],
        'actual_v7_plan': None, 'actual_v7_terminal_batch': 'zero-credit unit fixture',
        'controls': {}, 'production_pair': {}, 'distinct_passing_cases': 0, 'generic_count_bounds': [1, 5],
        'latest_cases': {}, 'original_browser_source_and_image_unchanged': True,
        'runtime_role': 'zero-credit unit fixture', 'scope': 'zero-credit unit fixture',
        'source_comparison': None, 'source_inventory': None,
    }
    closure = gate / 'source-closure-final.json'; producer.create(closure, value)
    plan['authenticated_historical_closure'] = producer.reference(closure)
    return plan, closure, value, before, after, source, archived


def rewrite_fixture(plan, closure, value):
    # Changed fixture inputs have fresh paths and hashes; no original evidence
    # or completed scientific artifact is rewritten by a control.
    path = closure.parent / 'changed' / 'source-closure-final.json'; path.parent.mkdir(mode=0o700)
    producer.create(path, value); plan['authenticated_historical_closure'] = producer.reference(path)


def test_v8_observation_leaf_preserves_old_labels_and_binds_actual_snapshot_and_current_source(tmp_path):
    plan, closure, value, before, after, source, archived = v8_fixture(tmp_path)
    original = (before.read_bytes(), after.read_bytes(), closure.read_bytes())
    fence = producer.dependency_fence(plan); files = {row['path']: row for row in fence['files']}
    for path in (before, after, archived, source / 'test_v8.py'):
        assert files[str(path)] == producer.reference(path)
    old = producer.load(before)['test_v8.py']
    assert old['path'] == str(source / 'test_v8.py')
    assert old['sha256'] == producer.reference(archived)['sha256'] != producer.reference(source / 'test_v8.py')['sha256']
    assert (before.read_bytes(), after.read_bytes(), closure.read_bytes()) == original
    producer.verify_fence(fence)


def test_unbound_lookalike_basename_is_not_a_raw_observation_leaf(tmp_path):
    plan, closure, value, before, after, source, archived = v8_fixture(tmp_path)
    plan['authenticated_historical_closure'] = producer.reference(before)
    with pytest.raises(ValueError): producer.dependency_fence(plan)


@pytest.mark.parametrize('mutation', ['raw-bytes', 'raw-mode', 'snapshot-bytes', 'snapshot-mode', 'current-source'])
def test_v8_observation_and_real_dependency_mutations_refuse(tmp_path, mutation):
    plan, closure, value, before, after, source, archived = v8_fixture(tmp_path)
    fence = producer.dependency_fence(plan)
    if mutation == 'raw-bytes': before.write_bytes(b'changed historical observation\n')
    elif mutation == 'raw-mode': before.chmod(0o644)
    elif mutation == 'snapshot-bytes': archived.write_bytes(b'changed retained original test\n')
    elif mutation == 'snapshot-mode': archived.chmod(0o600)
    else: (source / 'graph_input.py').write_bytes(b'changed actual current producer\n')
    with pytest.raises(ValueError): producer.verify_fence(fence)


@pytest.mark.parametrize('mutation', ['missing-role', 'duplicate-role', 'wrong-mode', 'wrong-schema',
                                     'unbound-root', 'ambiguous-authority', 'cyclic-source-role'])
def test_v8_observation_role_is_finite_and_cannot_mask_another_authority(tmp_path, mutation):
    plan, closure, value, before, after, source, archived = v8_fixture(tmp_path)
    value = deepcopy(value)
    if mutation == 'missing-role': value['read_only_refs'] = value['read_only_refs'][1:]
    elif mutation == 'duplicate-role': value['read_only_refs'].append(value['read_only_refs'][0])
    elif mutation == 'wrong-mode': value['read_only_refs'][0]['mode'] = 0o644
    elif mutation == 'wrong-schema': value['schema_version'] = True
    elif mutation == 'unbound-root': value['raw_operations'] = []
    elif mutation == 'ambiguous-authority': plan['also_current_authority'] = producer.reference(before)
    else: value['source_root'] = str(before.parent)
    rewrite_fixture(plan, closure, value)
    with pytest.raises(ValueError): producer.dependency_fence(plan)


def test_nested_v8_schema_lookalike_has_no_authenticated_closure_role(tmp_path):
    plan, closure, value, before, after, source, archived = v8_fixture(tmp_path)
    wrapper = closure.parent / 'wrapper.json'; producer.create(wrapper, {'not_a_closure': value})
    plan['authenticated_historical_closure'] = producer.reference(wrapper)
    with pytest.raises(ValueError): producer.dependency_fence(plan)
