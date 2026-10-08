"""Typed V2 ledger boundaries, with original deep/installed primitives controlled.

These tests award no scientific credit and make no network or capture. They
exercise actual files, artifact digests, fixed full graphs, source labels,
class/slot selection, chronology, create-only outputs and immutable closing.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_mixed_implementation_target as mixed
from qcsd_lab import front_fixed_configuration as front
from tests.test_rapid_fixed_condition_target import case, setting, duration_setting, proof, write, NATIVE, CLIENT
from tests.test_rapid_parallel_partial_lane import predecessor_bytes
from tests.test_capture_front_reserve_policy import marker as original_front_marker

NEW_NATIVE = 'b' * 40
NEW_CLIENT = hashlib.sha256(b'controlled prospective BF64 client').hexdigest()
OLD_IMAGE = 'sha256:' + '1' * 64
CURRENT_IMAGE = 'sha256:' + '2' * 64
NEW_IMAGE = 'sha256:' + '3' * 64
FRONT_NATIVE = 'd' * 40
FRONT_CLIENT = hashlib.sha256(b'controlled prospective FrontV5 client').hexdigest()
FRONT_IMAGE = 'sha256:' + '4' * 64


def front_setting(*, prospective=False):
    configuration, run = setting('front')
    configuration['application_body_identity_policy'] = 'complete-current-application-delivery-v1'
    run['resolved_configuration'] = front.resolved_configuration()
    marker = original_front_marker()
    if prospective:
        configuration[front.FIELD] = front.POLICY
        configuration['front_configuration_sha256'] = front.CONFIGURATION_SHA256
        marker.update(schema_version=5, policy=front.POLICY,
            n_client_packets=450, n_server_packets=600, peak_minimum_seconds=1.0,
            peak_maximum_seconds=4.0, control_interval_us=10000,
            incoming_release_window_us=10000, configuration_sha256=front.CONFIGURATION_SHA256)
    else:
        run['resolved_configuration']['control_interval_us'] = 5000
        run['resolved_configuration']['defense'].update(n_client_packets=900,
            n_server_packets=1200, peak_minimum_seconds=0.1, peak_maximum_seconds=2.5)
    run[fixed.FRONT_FIELD] = marker
    return configuration, run


def bf_setting():
    configuration, run = setting('buflo')
    configuration['application_body_identity_policy'] = 'complete-current-application-delivery-v1'
    configuration['defenses'][0].update(parameters_sha256=mixed.PARAMETER_SHA256,
        provenance_sha256=mixed.PROVENANCE_SHA256)
    run['defense_parameters'] = {'kind': 'buflo', 'sha256': mixed.PARAMETER_SHA256,
        'implementation_scope': 'client_only_quic', 'paper_equivalent': False,
        'buflo_duration_budget': dict(mixed.RECEIPT)}
    run['resolved_configuration']['defense'] = {'kind': 'buflo',
        'parameters': '/controlled/prospective-parameters.json'}
    run[fixed.BUFLO_FIELD] = {'schema_version': 1, 'source': 'bound-preparation-v1',
        'policy': mixed.INCOMING_POLICY, 'period_us': 64000, 'cell_bytes': 1200,
        'incoming_release_window_us': 32000, 'scientific_credit': False}
    run[fixed.BUFLO_KERNEL_PREPARATION_FIELD] = {'schema_version': 1, 'source': 'bound-preparation-v1',
        'policy': mixed.PREPARATION_POLICY, 'period_us': 64000, 'cell_bytes': 1200,
        'nominal_selection_lead_us': 5000, 'rolling_preparation_after_release_us': 4000,
        'outgoing_physical_window_us': 5000, 'preparation_reserve_us': 1000,
        'tick_zero_before_release': True, 'allow_omissions': False,
        'paper_equivalent': False, 'scientific_credit': False}
    return configuration, run


@pytest.fixture
def epoch_case(case, monkeypatch):
    front_config, front_run = front_setting()
    case.conditions['front'] = fixed.describe_condition(write(case.root / 'original-front4-config.json', front_config),
        write(case.root / 'original-front4-run.json', front_run), 'front', case.root / 'original-front4-condition.json')
    old_config, old_run = duration_setting()
    old_config['application_body_identity_policy'] = 'complete-current-application-delivery-v1'
    case.conditions['buflo'] = fixed.describe_condition(write(case.root / 'original-bf200-config.json', old_config),
        write(case.root / 'original-bf200-run.json', old_run), 'buflo', case.root / 'original-bf200-condition.json')
    case.target = fixed.publish_target(namespace='original-fixed-bf200-example', enrollment=case.enrollment,
        conditions=case.conditions, native_head=NATIVE, client_sha256=CLIENT, history=[case.history],
        output=case.root / 'original-bf200-target.json')
    def historical(row):
        row['measurement_source']['image_digest'] = OLD_IMAGE
    old_proof = proof(case, monkeypatch, 'undefended', [0], row_change=historical)
    old_progress = fixed.initialize_progress(target=case.target, proofs=[old_proof],
        output=case.root / 'old-progress.json')
    binding_refs = {}
    for mode in fixed.MODES:
        native, client, image = (NEW_NATIVE, NEW_CLIENT, NEW_IMAGE) if mode == 'buflo' else (NATIVE, CLIENT, CURRENT_IMAGE)
        manifest = {'lab_commit': 'a' * 40, 'lab_dirty': False,
            'neqo_commit': native, 'neqo_pinned_commit': native, 'neqo_dirty': False}
        binding_refs[mode] = write(case.root / (mode + '-binding.json'),
            {'files': {}, 'binding': {'read_dependencies': [], 'runtime_identity': {'source': manifest,
                'client_sha256': client, 'collection_image_digest': image}}})
    # Original installed/runtime Source acceptance is explicitly controlled.
    # Its original raw binding files remain authentic byte/mode observations.
    monkeypatch.setattr(fixed, '_measurement_source', lambda ref:
        json.loads(fixed._open(ref).read_bytes()))
    cfg, run = bf_setting()
    condition = fixed.describe_condition(write(case.root / 'bf64-configuration.json', cfg),
        write(case.root / 'bf64-run.json', run), 'buflo', case.root / 'bf64-condition.json')
    target = mixed.publish_target(namespace='prospective-mixed-bf64-example',
        retained_progress=old_progress, buflo_condition=condition,
        implementations=binding_refs, output=case.root / 'mixed-target.json')
    progress = fixed.initialize_progress(target=target, proofs=[old_proof],
        output=case.root / 'mixed-progress.json')
    return SimpleNamespace(case=case, old_progress=old_progress, target=target, progress=progress,
        condition=condition, binding_refs=binding_refs)


@pytest.fixture
def front_epoch(epoch_case):
    epoch = epoch_case
    cfg, run = front_setting(prospective=True)
    condition = fixed.describe_condition(write(epoch.case.root / 'front5-config.json', cfg),
        write(epoch.case.root / 'front5-run.json', run), 'front', epoch.case.root / 'front5-condition.json')
    refs = deepcopy(epoch.binding_refs)
    value = json.loads(Path(refs['front']['path']).read_bytes())
    runtime = value['binding']['runtime_identity']
    runtime['source'].update(neqo_commit=FRONT_NATIVE, neqo_pinned_commit=FRONT_NATIVE)
    runtime.update(client_sha256=FRONT_CLIENT, collection_image_digest=FRONT_IMAGE)
    refs['front'] = write(epoch.case.root / 'front5-binding.json', value)
    declared = mixed.publish_target(namespace='prospective-front5-bf64-example',
        retained_progress=epoch.old_progress, buflo_condition=epoch.condition,
        front_condition=condition, implementations=refs, output=epoch.case.root / 'front5-mixed-target.json')
    proofs = fixed.validate_progress(epoch.old_progress)['proofs']
    progress = fixed.initialize_progress(target=declared, proofs=proofs,
        output=epoch.case.root / 'front5-mixed-progress.json')
    return SimpleNamespace(case=epoch.case, old_progress=epoch.old_progress,
        target=declared, progress=progress, condition=epoch.condition,
        front_condition=condition, binding_refs=refs)


def new_proof(epoch, monkeypatch, mode='buflo', slot=0, change=None):
    declaration = fixed.validate_target(epoch.target)
    def update(row):
        implementation = declaration['implementations'][mode]
        row['measurement_source'] = deepcopy(implementation['measurement_source'])
        row['client_sha256'] = implementation['identity']['client_sha256']
        row['condition'] = deepcopy(declaration['conditions'][mode]['identity'])
        row['capture_limits'] = fixed._capture_limits(mode, row['capture_limits'], row['condition'])
        row['source_binding'] = epoch.binding_refs[mode]
        if change: change(row)
    return proof(epoch.case, monkeypatch, mode, [slot], row_change=update)


def test_v1_import_keeps_original_rows_proofs_images_and_bf_empty(epoch_case):
    old = fixed.validate_progress(epoch_case.old_progress)
    new = fixed.validate_progress(epoch_case.progress)
    declaration = fixed.validate_target(epoch_case.target)
    assert new['accepted_rows'] == old['accepted_rows']
    assert new['proofs'] == old['proofs']
    assert new['imported_accepted_count'] == new['target_accepted_count'] == 1
    assert new['accepted_rows'][0]['measurement_source']['image_digest'] == OLD_IMAGE
    assert declaration['implementations']['undefended']['identity']['image_digest'] == CURRENT_IMAGE
    assert all(row['remaining_slots'] == list(range(64)) for row in new['remaining_vectors'] if row['mode'] == 'buflo')
    original = fixed.validate_target(old['target'])
    for mode in mixed.UNCHANGED:
        assert declaration['conditions'][mode] == original['conditions'][mode]
        assert fixed.mode_implementation(declaration, mode)['native_head'] == NATIVE
    assert declaration['classes'] == original['classes']
    assert fixed.mode_implementation(declaration, 'buflo')['native_head'] == NEW_NATIVE


def test_new_bf64_and_unchanged_front_append_with_separate_implementations(epoch_case, monkeypatch):
    bf = new_proof(epoch_case, monkeypatch)
    first = fixed.append_progress(progress=epoch_case.progress, proofs=[bf], output=epoch_case.case.root / 'bf-next.json')
    front = new_proof(epoch_case, monkeypatch, mode='front', slot=5)
    second = fixed.append_progress(progress=first, proofs=[front], output=epoch_case.case.root / 'front-next.json')
    value = fixed.validate_progress(second)
    assert value['target_accepted_count'] == 3
    assert value['accepted_rows'][0] == fixed.validate_progress(epoch_case.old_progress)['accepted_rows'][0]
    assert value['accepted_rows'][1]['client_sha256'] == NEW_CLIENT
    assert value['accepted_rows'][2]['client_sha256'] == CLIENT
    assert value['accepted_rows'][1]['capture_limits']['timeout_seconds'] == 680
    assert value['accepted_rows'][1]['capture_limits']['capture_seconds'] == 740
    inputs = fixed.chunk_inputs(second, [1], 'buflo')
    assert 0 not in inputs['remaining_slots'] and inputs['capture_limits']['capture_seconds'] == 740
    assert inputs['classes'][0]['capture_limits']['capture_seconds'] == 180
    assert fixed.chunk_inputs(second, [1], 'front')['capture_limits']['capture_seconds'] == 180


@pytest.mark.parametrize('change', ['native', 'pinned-native', 'client', 'image', 'source', 'old-condition',
    'cap', 'pre-declaration', 'graph', 'slot-bool', 'scope'])
def test_new_bf_rows_refuse_changed_implementation_or_science_before_publication(change, epoch_case, monkeypatch):
    def mutate(row):
        if change == 'native': row['measurement_source']['neqo_commit'] = NATIVE
        elif change == 'pinned-native': row['measurement_source']['neqo_pinned_commit'] = NATIVE
        elif change == 'client': row['client_sha256'] = CLIENT
        elif change == 'image': row['measurement_source']['image_digest'] = CURRENT_IMAGE
        elif change == 'source': row['measurement_source']['lab_commit'] = '9' * 40
        elif change == 'old-condition': row['condition'] = fixed.validate_target(epoch_case.case.target)['conditions']['buflo']['identity']
        elif change == 'cap': row['capture_limits']['timeout_seconds'] -= 1
        elif change == 'pre-declaration': row['intent_started_at'] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        elif change == 'graph': row['original_graph_sha256'] = '0' * 64
        elif change == 'slot-bool': row['logical_visit'] = False
        else: row['condition']['defense_parameters']['implementation_scope'] = 'bilateral'
    p = new_proof(epoch_case, monkeypatch, change=mutate)
    output = epoch_case.case.root / ('refused-' + change + '.json')
    with pytest.raises(ValueError): fixed.append_progress(progress=epoch_case.progress, proofs=[p], output=output)
    assert not output.exists()


def test_old_image_is_retained_only_by_original_import_not_new_captures(epoch_case, monkeypatch):
    p = new_proof(epoch_case, monkeypatch, mode='undefended', slot=1,
        change=lambda row: row['measurement_source'].update(image_digest=OLD_IMAGE))
    with pytest.raises(ValueError, match='image'):
        fixed.append_progress(progress=epoch_case.progress, proofs=[p], output=epoch_case.case.root / 'old-image-refused.json')


@pytest.mark.parametrize('field', ['native_head', 'client_sha256'])
def test_unchanged_mode_implementation_cannot_switch_to_new_bf(field, epoch_case):
    ref = epoch_case.binding_refs['front']; raw = json.loads(Path(ref['path']).read_bytes())
    runtime = raw['binding']['runtime_identity']
    if field == 'native_head': runtime['source'].update(neqo_commit=NEW_NATIVE, neqo_pinned_commit=NEW_NATIVE)
    else: runtime['client_sha256'] = NEW_CLIENT
    revised = write(epoch_case.case.root / ('wrong-front-' + field + '.json'), raw)
    refs = {**epoch_case.binding_refs, 'front': revised}
    output = epoch_case.case.root / ('wrong-implementation-' + field + '.json')
    with pytest.raises(ValueError, match='unchanged-mode'):
        mixed.publish_target(namespace='wrong-mixed-front-example', retained_progress=epoch_case.old_progress,
            buflo_condition=epoch_case.condition, implementations=refs, output=output)
    assert not output.exists()


def test_accepted_old_buflo_rows_cannot_be_relabelled_as_new_epoch(epoch_case, monkeypatch):
    condition = fixed.validate_target(epoch_case.case.target)['conditions']['buflo']['identity']
    def old_bf(row):
        row['condition'] = deepcopy(condition)
        row['capture_limits'] = fixed._capture_limits('buflo', row['capture_limits'], condition)
    p = proof(epoch_case.case, monkeypatch, 'buflo', [3], row_change=old_bf)
    old_bf = fixed.append_progress(progress=epoch_case.old_progress, proofs=[p], output=epoch_case.case.root / 'old-bf.json')
    with pytest.raises(ValueError, match='old BuFLO'):
        mixed.publish_target(namespace='cannot-promote-old-bf-example', retained_progress=old_bf,
            buflo_condition=epoch_case.condition, implementations=epoch_case.binding_refs,
            output=epoch_case.case.root / 'old-bf-refused.json')


def test_class_extension_keeps_identity_and_original_class_graphs(epoch_case):
    enrollment = write(epoch_case.case.root / 'all-three-enrollment.json', {'classes': epoch_case.case.rows})
    next_target = mixed.publish_target(namespace='prospective-mixed-bf64-example',
        retained_progress=epoch_case.old_progress, buflo_condition=epoch_case.condition,
        implementations=epoch_case.binding_refs, enrollment=enrollment, parent=epoch_case.target,
        output=epoch_case.case.root / 'mixed-extended-target.json')
    next_progress = fixed.append_progress(progress=epoch_case.progress, proofs=[], target=next_target,
        output=epoch_case.case.root / 'mixed-extended-progress.json')
    value = fixed.validate_progress(next_progress)
    assert len(value['classes']) == 3 and value['target_accepted_count'] == 1
    assert value['target_id'] == fixed.validate_progress(epoch_case.progress)['target_id']
    bad = deepcopy(epoch_case.case.rows); bad[0]['capture_limits']['capture_megabytes'] += 1
    altered = write(epoch_case.case.root / 'bad-caps-enrollment.json', {'classes': bad})
    with pytest.raises(ValueError, match='class'):
        mixed.publish_target(namespace='prospective-mixed-bf64-example', retained_progress=epoch_case.old_progress,
            buflo_condition=epoch_case.condition, implementations=epoch_case.binding_refs, enrollment=altered,
            parent=epoch_case.target, output=epoch_case.case.root / 'class-change-refused.json')


@pytest.mark.parametrize('field', ['max_events', 'interval_us', 'duration_budget_us', 'schema_version'])
def test_new_duration_receipt_has_no_bool_float_or_value_alias(field):
    value = fixed.condition_identity(*bf_setting(), 'buflo')
    for invalid in [True, float(mixed.RECEIPT[field]), mixed.RECEIPT[field] + 1]:
        changed = deepcopy(value); changed['defense_parameters']['buflo_duration_budget'][field] = invalid
        with pytest.raises(ValueError): mixed.buflo64_condition(changed)


def test_target_and_progress_source_mode_mutation_are_refused(epoch_case):
    original = Path(epoch_case.target['path']); original.chmod(0o644)
    with pytest.raises(ValueError, match='mode'):
        fixed.validate_progress(epoch_case.progress)


def test_migration_requires_exact_original_proof_list_and_create_only_output(epoch_case):
    with pytest.raises(ValueError, match='original proofs'):
        fixed.initialize_progress(target=epoch_case.target, proofs=[], output=epoch_case.case.root / 'missing-proof-refused.json')
    with pytest.raises(ValueError, match='create-only'):
        fixed.initialize_progress(target=epoch_case.target, proofs=fixed.validate_progress(epoch_case.old_progress)['proofs'],
            output=Path(epoch_case.progress['path']))


def test_v1_source_projection_keeps_every_old_scientific_unit(tmp_path):
    old = predecessor_bytes(); current = Path(fixed.__file__).read_bytes()
    assert fixed._reader_code_projection(old, 'target') == fixed._reader_code_projection(
        fixed._parallel_partial_source_projection(current), 'target')
    path = tmp_path / 'old-published-target.py'; path.write_bytes(old); path.chmod(0o644)
    assert fixed._compatible_code_ref('target', fixed.reference(path), fixed.reference(Path(fixed.__file__)))
    changed = current.replace(b"row['client_sha256']!=target['target_identity']['client_sha256']", b'False', 1)
    assert changed != current
    assert fixed._reader_code_projection(old, 'target') != fixed._reader_code_projection(
        fixed._parallel_partial_source_projection(changed), 'target')


def test_mixed_dispatch_mutation_cannot_project_as_v1():
    current = Path(fixed.__file__).read_bytes()
    dispatch = b"        return _mixed_epoch().capture_limits(original, condition)\n"
    assert current.count(dispatch) == 1
    changed = current.replace(dispatch, b"        return dict(original)\n", 1)
    assert changed != current
    with pytest.raises(ValueError, match='projection is incomplete'):
        fixed._mixed_implementation_source_projection(changed)


@pytest.mark.parametrize('role', ['acceptance', 'duration', 'traffic', 'front_preparation', 'capture_plan', 'chunks', 'dynamic'])
def test_finite_legacy_inverse_restores_full_scientific_source_and_rejects_mutation(role, tmp_path):
    names = {'acceptance': 'capture_acceptance_policy', 'duration': 'buflo_duration_budget',
        'traffic': 'rapid_capture_traffic', 'front_preparation': 'front_preparation_evidence',
        'capture_plan': 'rapid_capture_plan', 'chunks': 'rapid_slot_chunks', 'dynamic': 'rapid_chunk_partial_lane'}
    source = fixed.reference(Path(fixed.__file__).with_name(names[role] + '.py'))
    raw = Path(source['path']).read_bytes()
    old, current, _edits = mixed._LEGACY_MODULE_INVERSES[role]
    assert source['sha256'] == current
    restored = mixed.legacy_source_projection(role, raw, historical_sha256=old)
    assert hashlib.sha256(restored).hexdigest() == old
    before = tmp_path / 'historical.py'; before.write_bytes(restored); before.chmod(0o644)
    after = tmp_path / 'prospective.py'; after.write_bytes(raw); after.chmod(0o644)
    assert mixed.compatible_legacy_reader(role, fixed.reference(before), fixed.reference(after))
    with pytest.raises(ValueError):
        mixed.legacy_source_projection(role, raw + b'\n# protected bytes mutation\n', historical_sha256=old)
    with pytest.raises(ValueError):
        mixed.legacy_source_projection(role, raw, historical_sha256='0' * 64)
    after.chmod(0o600)
    with pytest.raises(ValueError):
        mixed.compatible_legacy_reader(role, fixed.reference(before), fixed.reference(after))


def test_finite_traffic_inverse_preserves_original_quick_dispatch_pin():
    source = fixed._sources()['traffic']
    raw = Path(source['path']).read_bytes()
    original = '4eb2d2ce5a35005f342befe9fb86dd6dad27980b2635e5372fda227902764542'
    restored = mixed.legacy_source_projection('traffic', raw, historical_sha256=original)
    assert hashlib.sha256(restored).hexdigest() == original


def test_front_and_bf_amendments_preserve_all_retained_ordinary_rows_and_other_modes(front_epoch):
    original = fixed.validate_progress(front_epoch.old_progress)
    value = fixed.validate_progress(front_epoch.progress)
    declaration = fixed.validate_target(front_epoch.target)
    predecessor = fixed.validate_target(original['target'])
    assert value['accepted_rows'] == original['accepted_rows']
    assert value['proofs'] == original['proofs']
    assert declaration['classes'] == predecessor['classes']
    for mode in ('undefended', 'tamaraw', 'cs-buflo'):
        assert declaration['conditions'][mode] == predecessor['conditions'][mode]
        assert fixed.mode_implementation(declaration, mode)['native_head'] == NATIVE
    assert fixed.mode_implementation(declaration, 'front')['native_head'] == FRONT_NATIVE
    assert fixed.mode_implementation(declaration, 'buflo')['native_head'] == NEW_NATIVE
    assert all(row['remaining_slots'] == list(range(64)) for row in value['remaining_vectors']
        if row['mode'] in ('front', 'buflo'))


def test_new_front5_rows_use_own_source_client_image_and_unchanged_caps(front_epoch, monkeypatch):
    p = new_proof(front_epoch, monkeypatch, mode='front', slot=9)
    output = fixed.append_progress(progress=front_epoch.progress, proofs=[p],
        output=front_epoch.case.root / 'front5-accepted.json')
    value = fixed.validate_progress(output)
    assert value['target_accepted_count'] == 2
    row = value['accepted_rows'][-1]
    assert row['measurement_source']['image_digest'] == FRONT_IMAGE
    assert row['client_sha256'] == FRONT_CLIENT
    assert row['capture_limits']['timeout_seconds'] == 120
    assert row['capture_limits']['capture_seconds'] == 180
    assert fixed.chunk_inputs(output, [1], 'front')['remaining_slots'] == [slot for slot in range(64) if slot != 9]


@pytest.mark.parametrize('change', ['native', 'client', 'image', 'condition', 'earlier-intent', 'graph', 'cap'])
def test_new_front5_rows_cannot_borrow_old_runtime_or_predeclaration_authority(change, front_epoch, monkeypatch):
    def mutate(row):
        if change == 'native': row['measurement_source']['neqo_commit'] = NATIVE
        elif change == 'client': row['client_sha256'] = CLIENT
        elif change == 'image': row['measurement_source']['image_digest'] = CURRENT_IMAGE
        elif change == 'condition': row['condition'] = fixed.validate_target(front_epoch.case.target)['conditions']['front']['identity']
        elif change == 'earlier-intent': row['intent_started_at'] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        elif change == 'graph': row['original_graph_sha256'] = '0' * 64
        else: row['capture_limits']['capture_seconds'] += 1
    p = new_proof(front_epoch, monkeypatch, mode='front', slot=8, change=mutate)
    output = front_epoch.case.root / ('front5-refused-' + change + '.json')
    with pytest.raises(ValueError):
        fixed.append_progress(progress=front_epoch.progress, proofs=[p], output=output)
    assert not output.exists()


def test_original_front_credit_prevents_prospective_front_amendment(front_epoch, monkeypatch):
    old_condition = fixed.validate_target(front_epoch.case.target)['conditions']['front']['identity']
    def change(row): row.update(condition=deepcopy(old_condition))
    p = proof(front_epoch.case, monkeypatch, 'front', [3], row_change=change)
    retained = fixed.append_progress(progress=front_epoch.old_progress, proofs=[p],
        output=front_epoch.case.root / 'old-front-accepted.json')
    output = front_epoch.case.root / 'old-front-promotion-refused.json'
    with pytest.raises(ValueError, match='Front empty'):
        mixed.publish_target(namespace='refused-old-front-promotion', retained_progress=retained,
            buflo_condition=front_epoch.condition, front_condition=front_epoch.front_condition,
            implementations=front_epoch.binding_refs, output=output)
    assert not output.exists()


@pytest.mark.parametrize('change', ['counts', 'peaks', 'control', 'configuration-sha', 'incoming',
    'outgoing', 'omission-cap', 'bool-schema', 'extra-policy', 'body'])
def test_front5_condition_is_exact_typed_complete_tuple(change):
    value = fixed.condition_identity(*front_setting(prospective=True), 'front')
    marker = value['capture_policies'][fixed.FRONT_FIELD]
    if change == 'counts': value['resolved_configuration']['defense']['n_client_packets'] = 900
    elif change == 'peaks': value['resolved_configuration']['defense']['peak_minimum_seconds'] = 0.1
    elif change == 'control': value['resolved_configuration']['control_interval_us'] = 5000
    elif change == 'configuration-sha': marker['configuration_sha256'] = '0' * 64
    elif change == 'incoming': marker['incoming_release_window_us'] = 5000
    elif change == 'outgoing': marker['outgoing_release_window_us'] = 20000
    elif change == 'omission-cap': marker['outgoing_omission_ratio_numerator'] = 2
    elif change == 'bool-schema': marker['schema_version'] = True
    elif change == 'extra-policy': value['capture_policies'][fixed.BUFLO_FIELD] = {}
    else: value['application_body_identity_policy'] = 'application-first-buffer-v1'
    with pytest.raises(ValueError): mixed.front5_condition(value)


@pytest.mark.parametrize('field', ['tail_wait_us', 'automatic_receive_window', 'max_chaff_streams', 'max_udp_payload_size'])
def test_front_amendment_cannot_change_a_predecessor_common_native_field(field, front_epoch):
    retained = fixed.validate_progress(front_epoch.old_progress)
    original = deepcopy(fixed.validate_target(retained['target']))
    declarations = fixed._conditions({mode: ref['reference'] for mode, ref in
        fixed.validate_target(front_epoch.target)['conditions'].items()})
    implementations = mixed._implementations(front_epoch.binding_refs)
    original['conditions']['front']['identity']['resolved_configuration'][field] += 1
    with pytest.raises(ValueError, match='outside'):
        mixed._unchanged(retained, original, declarations, implementations, original['classes'])


def test_saved_portable_dynamic_reader_inverse_preserves_entire_v1_and_v2_bodies(tmp_path):
    raw = Path(fixed.dynamic.__file__).read_bytes()
    old_sha = mixed._LEGACY_MODULE_INVERSES['dynamic'][0]
    original = mixed.legacy_source_projection('dynamic', raw, historical_sha256=old_sha)
    assert fixed._portable_dynamic_source_projection(raw) == fixed._portable_dynamic_source_projection(original)
    before = tmp_path / 'original-dynamic.py'; before.write_bytes(original); before.chmod(0o644)
    after = tmp_path / 'current-dynamic.py'; after.write_bytes(raw); after.chmod(0o644)
    assert fixed._compatible_code_ref('dynamic', fixed.reference(before), fixed.reference(after))
    changed = raw.replace(b'def _runtime_operation(', b'def _changed_runtime_operation(', 1)
    assert changed != raw
    with pytest.raises(ValueError): fixed._portable_dynamic_source_projection(changed)
    after.chmod(0o600)
    with pytest.raises(ValueError, match='mode'):
        fixed._compatible_code_ref('dynamic', fixed.reference(before), fixed.reference(after))


@pytest.mark.parametrize('mutation', [None, 'plan-bytes', 'chunk-mode', 'plan-symlink'])
def test_portable_binding_old_capture_plan_and_chunks_use_exact_registered_inverse(tmp_path, mutation):
    package = tmp_path / 'original-source' / 'src' / 'qcsd_lab'
    package.mkdir(parents=True)
    refs = {}
    roles = {'qcsd_lab.rapid_chunk_partial_lane': 'dynamic',
        'qcsd_lab.rapid_slot_chunks': 'chunks', 'qcsd_lab.rapid_capture_plan': 'capture_plan'}
    for name, current in fixed.dynamic._reader_sources().items():
        raw = Path(current['path']).read_bytes()
        if name in roles:
            old = mixed._LEGACY_MODULE_INVERSES[roles[name]][0]
            raw = mixed.legacy_source_projection(roles[name], raw, historical_sha256=old)
        path = package / (name.rsplit('.', 1)[-1] + '.py')
        path.write_bytes(raw); path.chmod(0o644)
        refs[name] = fixed.reference(path)
    plan_path = Path(refs['qcsd_lab.rapid_capture_plan']['path'])
    chunk_path = Path(refs['qcsd_lab.rapid_slot_chunks']['path'])
    if mutation == 'plan-bytes':
        plan_path.write_bytes(plan_path.read_bytes() + b'\n# changed historical body\n')
        refs['qcsd_lab.rapid_capture_plan'] = fixed.reference(plan_path)
    elif mutation == 'chunk-mode':
        chunk_path.chmod(0o600)
        refs['qcsd_lab.rapid_slot_chunks'] = fixed.reference(chunk_path)
    elif mutation == 'plan-symlink':
        saved = tmp_path / 'moved-original-plan.py'; saved.write_bytes(plan_path.read_bytes())
        plan_path.unlink(); plan_path.symlink_to(saved)
    if mutation is None:
        assert fixed.dynamic._compatible_reader_sources(refs) == str(package.parent.parent)
    else:
        with pytest.raises(ValueError): fixed.dynamic._compatible_reader_sources(refs)
