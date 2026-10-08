"""Selected BF64 chunks through the stock plan and two-worker readers.

The inherited fixture explicitly controls admission, original target progress,
canonical installation and packet/deep canary eligibility. It grants no actual
runtime authority or credit. Source files, references, rendering, policy/plan
validation, per-mode identity checks, worker selection and recovery are real.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest
import yaml

from qcsd_lab import application_response_policy as app
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_mixed_implementation_target as mixed
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_target_parallel_schedule as workers
from qcsd_lab import rapid_slot_chunks as geometry
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as runtime
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import front_fixed_configuration as front
from tests.test_rapid_ordinary_parallel import current
from tests.test_rapid_target_chunks import case as serial_case
from tests.test_rapid_target_chunks import duration_case as serial_duration_case
from tests.test_rapid_target_chunks import policy, planned
from tests.test_rapid_mixed_implementation_target import bf_setting, front_setting


@pytest.fixture
def case(serial_case):
    return serial_case


@pytest.fixture
def duration_case(serial_duration_case):
    return serial_duration_case


@pytest.fixture
def cadence64_case(duration_case, monkeypatch):
    case = duration_case
    current, base = case.current, case.current.payload
    old_source = json.loads(current.spec.source_manifest.read_bytes())
    old_client = lanes._sha(current.spec.client_binary.read_bytes())
    old_image = current.spec.collection_image_digest
    new_source = {**old_source, 'neqo_commit': 'e' * 40, 'neqo_pinned_commit': 'e' * 40}
    new_image = 'sha256:' + '3' * 64
    current.spec.source_manifest.write_bytes(target._json(new_source))
    current.spec.client_binary.write_bytes(b'explicit controlled BF64 successor binary')
    new_client = lanes._sha(current.spec.client_binary.read_bytes())
    current.spec = replace(current.spec, collection_image_digest=new_image)
    current.runtime = {key: current.spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    current.canonical.update(source=new_source, collection_image_digest=new_image,
        installed_client_sha256=new_client)
    canonical_path = Path(case.canonical_ref['path'])
    canonical_path.write_bytes(target._json(current.canonical))
    case.canonical_ref = target.reference(canonical_path)
    current.canonical_ref = rolling._ref(canonical_path)
    base.pop(ordinary.FIELD, None)
    base['runtime'] = deepcopy(current.runtime)
    base['runtime_artifacts'] = {key: rolling._ref(Path(current.runtime[key]))
        for key in ('source_manifest', 'client_binary', 'base_launcher', 'host_launcher')}
    base['sites'] = [asdict(site) for site in current.sites]
    base['readiness'] = {'buflo': current.canary}
    base[target.traffic.FIELD] = target.duration.CADENCE64_POLICY
    base['application_body_identity_policy'] = app.COMPLETE_APPLICATION_DELIVERY_POLICY
    configuration, run = bf_setting()
    run['application_response_policy'] = case.inputs['inputs']['condition']['identity']['application_response_policy']
    run['primary_document_identity_policy'] = case.inputs['inputs']['condition']['identity']['primary_document_identity_policy']
    configuration['limits'] = {**target.duration.capture_limits('buflo', base['capture_limits'],
        policy=target.duration.CADENCE64_POLICY), 'max_attempts': 1}
    (case.result / 'accepted/sample/neqo/run.json').write_bytes(target._json(run))
    (case.result / 'experiment.json').write_bytes(target._json({'configuration': configuration,
        'samples': [{'path': 'accepted/sample', 'state': 'accepted', 'defense': 'buflo'}]}))
    condition = target.condition_identity(configuration, run, 'buflo')
    mixed.buflo64_condition(condition)
    case.inputs['inputs']['condition'] = {'identity': condition, 'identity_sha256': target._digest(condition)}
    case.inputs['inputs']['capture_limits'] = mixed.capture_limits(base['capture_limits'], condition)
    # BF starts empty; all64 slots remain. Old ordinary offsets are not imported.
    case.inputs['inputs']['remaining_slots'] = list(range(64))
    case.inputs['inputs']['ranges'] = [{'slot_start': start, 'slot_count': 16} for start in (0, 16, 32, 48)]
    current.facts.update(source={**new_source, 'image_digest': new_image},
        authority_source={**new_source, 'image_digest': new_image}, client_sha256=new_client,
        traffic_hashes=target.traffic.expected(target.duration.CADENCE64_POLICY),
        application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)
    implementations = {}
    for mode in target.MODES:
        source, client, image = ((new_source, new_client, new_image) if mode == 'buflo'
            else (old_source, old_client, old_image))
        implementations[mode] = {'identity': {'native_head': source['neqo_commit'],
            'client_sha256': client, 'image_digest': image},
            'measurement_source': {**source, 'image_digest': image}}
    declaration = {'contract': mixed.CONTRACT, 'implementations': implementations,
        'target_identity': {'namespace': 'controlled-selected-bf64-chunks',
            'conditions': {mode: target._digest(condition) for mode in target.MODES},
            'implementations': {mode: value['identity'] for mode, value in implementations.items()},
            'classes': 50, 'slots': 64, 'total': 16000}}
    # The retained progress and installed runtime are labeled synthetic authority
    # boundaries; their actual selected-mode check is deliberately not replaced.
    monkeypatch.setattr(target, 'validate_target', lambda ref: (target._open(ref), deepcopy(declaration))[1])
    case.declaration = declaration
    repository = Path(chunks.__file__).resolve().parents[2]
    for relative in workers.CONTROL_FILES:
        path = case.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        original = repository / relative
        path.write_bytes(original.read_bytes())
        path.chmod(original.stat().st_mode & 0o7777)
    monkeypatch.setattr(runtime, 'reopen_runtime', lambda ref, actual, **kw: (
        current.canonical, {relative: (case.source / relative).read_bytes()
            for relative in workers.CONTROL_FILES}))
    current.spec.plan_receipt.write_bytes(rolling.admission._json(
        rolling.admission._bind(lanes.PLAN_TYPE, base)))
    return case


@pytest.fixture
def front5_case(cadence64_case):
    """Construct a new complete FRONT fixture; no old graph is relabelled."""
    case = cadence64_case
    current, base = case.current, case.current.payload
    base.pop(target.traffic.FIELD)
    base[front.FIELD] = front.POLICY
    base['readiness'] = {'front': current.canary}
    source = json.loads(current.spec.source_manifest.read_bytes())
    source.update(neqo_commit='f' * 40, neqo_pinned_commit='f' * 40)
    current.spec.source_manifest.write_bytes(target._json(source))
    current.spec.client_binary.write_bytes(b'explicit controlled FrontV5 successor binary')
    client = lanes._sha(current.spec.client_binary.read_bytes())
    image = 'sha256:' + '4' * 64
    current.spec = replace(current.spec, collection_image_digest=image)
    current.runtime = {key: current.spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    current.canonical.update(source=source, collection_image_digest=image, installed_client_sha256=client)
    canonical_path = Path(case.canonical_ref['path'])
    canonical_path.write_bytes(target._json(current.canonical))
    case.canonical_ref = target.reference(canonical_path)
    current.canonical_ref = rolling._ref(canonical_path)
    base['runtime'] = deepcopy(current.runtime)
    base['runtime_artifacts'] = {key: rolling._ref(Path(current.runtime[key]))
        for key in ('source_manifest', 'client_binary', 'base_launcher', 'host_launcher')}
    sites = []
    for index, old in enumerate(current.sites):
        path = current.spec.workload_root / (old.workload_id + '.json')
        manifest = json.loads(path.read_bytes())
        manifest['preparation'].update(application_response_policy=app.COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
            primary_document_identity_policy=app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
        path.write_bytes(target._json(manifest))
        site = replace(old, workload_sha256=lanes._sha(path.read_bytes()),
            qualification_set='controlled-front-v5-named120')
        sites.append(site)
        case.inputs['inputs']['classes'][index]['original_graph_sha256'] = target.membership.graph_identity(path)
    current.sites = tuple(sites)
    base['sites'] = [asdict(site) for site in current.sites]
    for row in base['lanes']: row.update(mode='front', qualification_set='controlled-front-v5-named120')
    repository = Path(chunks.__file__).resolve().parents[2]
    for root_name in ('execution_root', 'runtime_source_root', 'module_root'):
        root = Path(current.runtime[root_name])
        for relative in (front.CONFIGURATION_PATH, front.PROVENANCE_PATH,
            'src/qcsd_lab/front_fixed_configuration.py'):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((repository / relative).read_bytes())
            path.chmod(0o644)
    configuration, run = front_setting(prospective=True)
    configuration['limits'] = {**base['capture_limits'], 'max_attempts': 1}
    (case.result / 'accepted/sample/neqo/run.json').write_bytes(target._json(run))
    (case.result / 'experiment.json').write_bytes(target._json({'configuration': configuration,
        'samples': [{'path': 'accepted/sample', 'state': 'accepted', 'defense': 'front'}]}))
    condition = target.condition_identity(configuration, run, 'front')
    mixed.front5_condition(condition)
    case.inputs['mode'] = 'front'
    case.inputs['inputs']['condition'] = {'identity': condition, 'identity_sha256': target._digest(condition)}
    case.inputs['inputs']['capture_limits'] = deepcopy(base['capture_limits'])
    current.facts.update(mode='front', source={**source, 'image_digest': image},
        authority_source={**source, 'image_digest': image}, client_sha256=client,
        traffic_hashes={key: digest for key, (_, digest) in target.traffic.plan_files(base).items()},
        front_configuration_policy=front.POLICY, front_configuration_sha256=front.CONFIGURATION_SHA256)
    selected = {'identity': {'native_head': source['neqo_commit'], 'client_sha256': client, 'image_digest': image},
        'measurement_source': {**source, 'image_digest': image}}
    case.declaration['implementations']['front'] = selected
    case.declaration['target_identity']['implementations']['front'] = selected['identity']
    case.declaration['target_identity']['conditions']['front'] = target._digest(condition)
    current.spec.plan_receipt.write_bytes(rolling.admission._json(rolling.admission._bind(lanes.PLAN_TYPE, base)))
    return case


def scheduled(case, *, suffix='workers'):
    spec, policy_path = planned(case)
    reference = workers.publish_schedule(spec, case.current.runtime, spec.qualification_spec,
        case.current.canonical_ref, case.current.canonical_ref, case.current.root / (suffix + '-capsule.json'),
        reason='controlled prospective BF64 selected-mode contract')
    output = workers.publish_plan(spec, reference, case.current.root / (suffix + '-plan.json'))
    return replace(spec, plan_receipt=output), target.reference(policy_path), reference


def test_selected_bf64_derives_physical_caps_and_preserves_all_original_limits(cadence64_case):
    case = cadence64_case
    original = deepcopy(case.current.payload['capture_limits'])
    spec, policy_ref, scheduling = scheduled(case)
    sites, payload = rolling.verify_capture_plan(spec, require_current=True)
    policy_value, _, base = chunks.validate_policy(policy_ref)
    assert policy_value['native_head'] == case.declaration['implementations']['buflo']['identity']['native_head']
    assert policy_value['client_sha256'] == case.declaration['implementations']['buflo']['identity']['client_sha256']
    assert policy_value['capture_limits'] == {**original, 'timeout_seconds': 680, 'capture_seconds': 740}
    assert base['capture_limits'] == original
    assert case.inputs['inputs']['classes'][0]['capture_limits'] == original
    assert payload['capture_limits'] == original
    assert payload['planned_trace_count'] == 64 * len(sites)
    assert payload['scientific_credit'] is False and payload['formal_accepted_trace_count'] == 0
    assert [(row['slot_start'], row['visits_per_workload']) for row in payload['lanes']] == [
        (0, 16), (16, 16), (32, 16), (48, 16)]
    lanes_selected = [lanes._lane({'plan_payload': payload}, row['campaign_name']) for row in payload['lanes']]
    for lane in lanes_selected:
        document = yaml.safe_load(lanes._render_lane_campaign(spec, lane, sites))
        assert document['limits'] == policy_value['capture_limits']
        assert document['workloads'] == {site.workload_id: 16 for site in sites}
        assert document['application_body_identity_policy'] == app.COMPLETE_APPLICATION_DELIVERY_POLICY
        assert document['defenses'][0]['parameters'].endswith('buflo-cadence64-budget640.json')
    assert workers.validate_schedule(scheduling)['capture_limits'] == policy_value['capture_limits']
    assert workers.require_worker(payload, lanes_selected[0], sites, spec) == {
        (site.workload_id, 'buflo', slot) for site in sites for slot in range(16)}
    workers.require_disjoint([(spec, payload, lane, sites) for lane in lanes_selected[:2]])
    with pytest.raises(ValueError, match='repeat'):
        workers.require_disjoint([(spec, payload, lanes_selected[0], sites)] * 2)


@pytest.mark.parametrize('change', ['native', 'pinned-native', 'client', 'image', 'source'])
def test_selected_mode_runtime_cannot_use_an_unchanged_mode_identity(change, cadence64_case):
    case = cadence64_case
    ordinary_identity = case.declaration['implementations']['undefended']
    if change == 'native':
        case.current.canonical['source']['neqo_commit'] = ordinary_identity['identity']['native_head']
    elif change == 'pinned-native':
        case.current.canonical['source']['neqo_pinned_commit'] = ordinary_identity['identity']['native_head']
    elif change == 'client':
        case.current.canonical['installed_client_sha256'] = ordinary_identity['identity']['client_sha256']
    elif change == 'image':
        case.current.canonical['collection_image_digest'] = ordinary_identity['identity']['image_digest']
    else:
        case.current.canonical['source']['lab_commit'] = '9' * 40
    output = case.current.root / ('refused-selected-' + change + '.json')
    with pytest.raises(ValueError):
        chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    assert not output.exists()


@pytest.mark.parametrize('change', ['incoming-period', 'outgoing-window', 'graph', 'formal-cap', 'practice-cap'])
def test_selected_bf64_refuses_changed_scientific_condition_graph_and_caps(change, cadence64_case):
    case = cadence64_case
    if change == 'incoming-period':
        case.inputs['inputs']['condition']['identity']['capture_policies'][target.BUFLO_FIELD]['period_us'] = 20000
    elif change == 'outgoing-window':
        case.inputs['inputs']['condition']['identity']['capture_policies'][target.BUFLO_KERNEL_PREPARATION_FIELD]['outgoing_physical_window_us'] = 32000
    elif change == 'graph':
        case.inputs['inputs']['classes'][0]['original_graph_sha256'] = '0' * 64
    elif change == 'formal-cap':
        case.inputs['inputs']['capture_limits']['capture_seconds'] -= 1
    else:
        path = case.result / 'experiment.json'
        payload = json.loads(path.read_bytes())
        payload['configuration']['limits']['max_response_bytes'] += 1
        path.write_bytes(target._json(payload))
    output = case.current.root / ('refused-scientific-' + change + '.json')
    with pytest.raises(ValueError):
        chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    assert not output.exists()


def test_bf64_parallel_recovery_keeps_slot_identity_and_accepted_peer_immutable(cadence64_case):
    case = cadence64_case
    spec, policy_ref, _ = scheduled(case)
    sites, before = rolling.verify_capture_plan(spec, require_current=True)
    first, peer = before['lanes'][:2]
    path = workers.publish_successor(spec, first['campaign_name'], 2, case.current.root / 'g02-workers.json')
    recovered_spec = replace(spec, plan_receipt=path)
    recovered_sites, after = rolling.verify_capture_plan(recovered_spec, require_current=True)
    assert recovered_sites == sites and len(after['lanes']) == 1
    recovered = after['lanes'][0]
    assert recovered['slot_start'] == first['slot_start'] == 0
    assert recovered['visits_per_workload'] == first['visits_per_workload'] == 16
    assert recovered['workload_ids'] == first['workload_ids']
    assert recovered['slot_policy_sha256'] == first['slot_policy_sha256'] == policy_ref['sha256']
    assert recovered['generation'] == 2
    assert before['lanes'][1] == peer and peer['slot_start'] == 16
    old_lane = lanes._lane({'plan_payload': before}, peer['campaign_name'])
    new_lane = lanes._lane({'plan_payload': after}, recovered['campaign_name'])
    workers.require_disjoint([(spec, before, old_lane, sites), (recovered_spec, after, new_lane, sites)])
    assert yaml.safe_load(lanes._render_lane_campaign(recovered_spec, new_lane, sites))['limits'] == {
        **case.current.payload['capture_limits'], 'timeout_seconds': 680, 'capture_seconds': 740}
    with pytest.raises(ValueError):
        workers.publish_successor(spec, first['campaign_name'], 3, case.current.root / 'skipped-workers.json')


def test_front5_selected_mode_reaches_stock_parallel_render_with_unchanged_caps(front5_case):
    case = front5_case
    spec, policy_ref, scheduling = scheduled(case)
    sites, value = rolling.verify_capture_plan(spec, require_current=True)
    policy_value, _, base = chunks.validate_policy(policy_ref)
    assert policy_value['capture_limits'] == base['capture_limits'] == case.inputs['inputs']['capture_limits']
    assert policy_value['native_head'] == 'f' * 40
    assert policy_value['native_head'] != case.declaration['implementations']['buflo']['identity']['native_head']
    assert policy_value['client_sha256'] == case.declaration['implementations']['front']['identity']['client_sha256']
    assert value['planned_trace_count'] == 64 * len(sites)
    for row in value['lanes']:
        lane = lanes._lane({'plan_payload': value}, row['campaign_name'])
        campaign = yaml.safe_load(lanes._render_lane_campaign(spec, lane, sites))
        assert campaign[front.FIELD] == front.POLICY
        assert campaign['limits']['timeout_seconds'] == 120
        assert campaign['limits']['capture_seconds'] == 180
        assert campaign['workloads'] == {site.workload_id: 16 for site in sites}
        assert campaign['defenses'] == ['front']
    assert workers.validate_schedule(scheduling)['capture_limits'] == base['capture_limits']


@pytest.mark.parametrize('change', ['native', 'client', 'image', 'marker', 'selection', 'raw-config', 'config-mode'])
def test_front5_plan_refuses_old_mode_identity_or_mutated_fixed_authority(change, front5_case):
    case = front5_case
    old = case.declaration['implementations']['undefended']['identity']
    if change == 'native': case.current.canonical['source']['neqo_commit'] = old['native_head']
    elif change == 'client': case.current.canonical['installed_client_sha256'] = old['client_sha256']
    elif change == 'image': case.current.canonical['collection_image_digest'] = old['image_digest']
    elif change == 'marker':
        case.inputs['inputs']['condition']['identity']['capture_policies'][target.FRONT_FIELD]['incoming_release_window_us'] = 5000
    elif change == 'selection': case.current.payload.pop(front.FIELD)
    else:
        path = Path(case.current.runtime['execution_root']) / front.CONFIGURATION_PATH
        if change == 'raw-config': path.write_bytes(path.read_bytes() + b'\n# changed fixed bytes\n')
        else: path.chmod(0o600)
    output = case.current.root / ('front5-refused-plan-' + change + '.json')
    with pytest.raises(ValueError):
        chunks.publish_policy(case.current.spec, case.inputs_ref, case.canonical_ref, output)
    assert not output.exists()


def test_front5_recovery_restarts_only_failed_worker_with_same_front_configuration(front5_case):
    case = front5_case
    spec, policy_ref, _ = scheduled(case)
    sites, original = rolling.verify_capture_plan(spec, require_current=True)
    first, peer = original['lanes'][:2]
    output = workers.publish_successor(spec, first['campaign_name'], 2, case.current.root / 'front5-g02.json')
    recovered_spec = replace(spec, plan_receipt=output)
    _, recovered = rolling.verify_capture_plan(recovered_spec, require_current=True)
    assert original['lanes'][1] == peer
    assert len(recovered['lanes']) == 1
    lane = lanes._lane({'plan_payload': recovered}, recovered['lanes'][0]['campaign_name'])
    assert lane.slot_start == first['slot_start'] == 0 and lane.visits_per_workload == 16
    assert lane.slot_policy_sha256 == policy_ref['sha256']
    document = yaml.safe_load(lanes._render_lane_campaign(recovered_spec, lane, sites))
    assert document[front.FIELD] == front.POLICY and document['limits'] == case.current.payload['capture_limits']


def test_selected_parallel_keeps_the_rolling_reference_schema_strict(cadence64_case):
    case = cadence64_case
    spec, policy_path = planned(case)
    assert set(case.current.canonical_ref) == {'path', 'sha256'}
    assert set(case.canonical_ref) == {'path', 'sha256', 'mode'}
    policy_payload = json.loads(policy_path.read_bytes())['payload']
    assert policy_payload['current_canonical'] == case.canonical_ref
    output = case.current.root / 'unsupported-three-field-worker-capsule.json'
    with pytest.raises(ValueError, match='rolling reference fields differ'):
        workers.publish_schedule(spec, case.current.runtime, spec.qualification_spec,
            case.canonical_ref, case.canonical_ref, output,
            reason='controlled unsupported reference shape must remain refused')
    assert not output.exists()


def test_selected_parallel_keeps_the_canonical_full_mode_bound(cadence64_case):
    case = cadence64_case
    spec, policy_path = planned(case)
    policy_payload = json.loads(policy_path.read_bytes())['payload']
    assert policy_payload['current_canonical'] == case.canonical_ref
    path = Path(case.current.canonical_ref['path'])
    original_mode = path.stat().st_mode & 0o7777
    assert original_mode == case.canonical_ref['mode']
    path.chmod(original_mode ^ 0o100)
    output = case.current.root / 'mutated-full-mode-worker-capsule.json'
    try:
        with pytest.raises(ValueError, match='reference bytes or mode changed'):
            workers.publish_schedule(spec, case.current.runtime, spec.qualification_spec,
                case.current.canonical_ref, case.current.canonical_ref, output,
                reason='controlled canonical permission mutation must remain refused')
        assert not output.exists()
    finally:
        path.chmod(original_mode)
