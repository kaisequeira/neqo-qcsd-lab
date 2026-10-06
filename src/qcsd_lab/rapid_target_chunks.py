"""Current qualified chunks selected from a declared fixed-condition target.

The geometry is the unchanged bounded ChunkLane. Its authority is this distinct
policy and plan, never the historical SCI progress or old ChunkPolicy. A target
declaration and its readers retain their owned immutable Source epoch.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
from typing import Mapping

from . import rapid_fixed_condition_target as target
from . import rapid_slot_chunks as geometry
from . import rapid_capture_plan as legacy
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_readiness as readiness
from . import rapid_rolling_schedule as runtime_reader
from . import rapid_site_admission as receipts
from .rapid_operation_facts import current_context

POLICY_TYPE = 'qcsd-current-fixed-condition-target-slot-chunk-policy-v1'
PLAN_TYPE = 'qcsd-current-fixed-condition-target-slot-chunk-plan-v1'
CONTRACT = 'declared-fixed-condition-progress-current-qualified-full-graph-chunks-v1'
FIELD = 'target_chunk_policy'
CONTROL_MODULES = ('rapid_target_chunks', 'rapid_slot_chunks', 'rapid_fixed_condition_target',
    'rapid_lane_evidence', 'rapid_rolling_capture', 'rapid_rolling_readiness', 'rapid_operation_facts',
    'buflo_duration_budget', 'rapid_capture_traffic')
CONTROL_FILENAMES = tuple('src/qcsd_lab/' + name + '.py' for name in CONTROL_MODULES) + (
    'tools/rapid_target_chunks.py',)
POLICY_KEYS = {'contract', 'lane_layout', 'base_spec', 'base_four_visit_plan', 'target_chunk_inputs',
    'current_canonical', 'target_id', 'condition_sha256', 'classes', 'capture_limits', 'mode',
    'remaining_slots', 'ranges', 'maximum_visits', 'current_canary', 'runtime', 'native_head', 'client_sha256',
    'control_sources', 'original_deep_program_sha256', 'published_at', 'scientific_credit',
    'formal_accepted_trace_count', 'historical_progress_authority_inferred'}


def _read(path):
    context = current_context()
    return lanes._read(Path(path)) if context is None else context.watch_file(Path(path))


def _executing_source_path(relative, runtime):
    """Python executes from its package; CLI files use the declared Source mount."""
    path = Path(relative)
    if path.parts[:2] == ('src', 'qcsd_lab') and len(path.parts) == 3 and path.suffix == '.py':
        from . import (rapid_target_chunks, rapid_slot_chunks, rapid_fixed_condition_target,
            rapid_lane_evidence, rapid_rolling_capture, rapid_rolling_readiness,
            rapid_operation_facts, buflo_duration_budget, rapid_capture_traffic,
            rapid_target_parallel_schedule, rapid_ordinary_parallel_schedule,
            rapid_undefended_capture, rapid_capture_plan, rapid_rolling_schedule,
            rapid_formal_parallel, rapid_runtime_epochs, rapid_ordinary_group_canary,
            rapid_ordinary_transport_control)
        modules = {module.__name__.rsplit('.', 1)[-1]: module for module in (
            rapid_target_chunks, rapid_slot_chunks, rapid_fixed_condition_target,
            rapid_lane_evidence, rapid_rolling_capture, rapid_rolling_readiness,
            rapid_operation_facts, buflo_duration_budget, rapid_capture_traffic,
            rapid_target_parallel_schedule, rapid_ordinary_parallel_schedule,
            rapid_undefended_capture, rapid_capture_plan, rapid_rolling_schedule,
            rapid_formal_parallel, rapid_runtime_epochs, rapid_ordinary_group_canary,
            rapid_ordinary_transport_control)}
        if path.stem not in modules:
            raise ValueError('target control Source module is outside the closed installed set')
        return Path(modules[path.stem].__file__)
    return lanes._regular_directory(Path(runtime['module_root'])) / relative


def sources(runtime=None):
    """Keep authority refs at mounted Source paths in HOST and installed readers."""
    if runtime is None:
        package = Path(__file__).absolute().parent
        if package.name != 'qcsd_lab' or package.parent.name != 'src':
            raise ValueError('installed target controls require their explicitly bound runtime')
        runtime = {'module_root': str(package.parent.parent)}
    root = lanes._regular_directory(Path(runtime['module_root']))
    return {relative: target.reference(root / relative) for relative in CONTROL_FILENAMES}


def _checked_sources(runtime, source_files, filenames):
    """Authenticate executing bytes and both explicit clean Source mounts."""
    module_root = lanes._regular_directory(Path(runtime['module_root']))
    runtime_root = lanes._regular_directory(Path(runtime['runtime_source_root']))
    controls = {}
    for relative in filenames:
        path = module_root / relative
        ref = target.reference(path)
        executing = target.reference(_executing_source_path(relative, runtime))
        installed = target.reference(runtime_root / relative)
        if (source_files.get(relative) != _read(path)
                or any(observed[name] != ref[name] for observed in (executing, installed)
                       for name in ('sha256', 'mode'))):
            raise ValueError('target executing/installed/frozen relevant control Source differs')
        controls[relative] = ref
    return controls


def is_plan(path):
    value = lanes._load(_read(path))
    return isinstance(value, dict) and value.get('receipt_type') == PLAN_TYPE


def _base(spec):
    lanes._check_spec(spec)
    value = receipts._unpack(_read(spec.plan_receipt), lanes.PLAN_TYPE)
    if (value.get('study_version') != 6 or 'scheduling' in value or 'lane_layout' in value
            or FIELD in value or 'slot_chunk_policy' in value):
        raise ValueError('target chunks require their current unscheduled four-visit serial base')
    return rolling.verify_capture_plan(spec, require_current=True, _context=current_context())


def _condition(spec, sites, base, mode):
    """Use actual validated canary values, never a purported resolved config."""
    matching = [row for row in base['lanes'] if row['mode'] == mode]
    if not matching:
        raise ValueError('target chunk mode lacks its own current qualified serial lane')
    lane = lanes._lane({'plan_payload': base}, matching[0]['campaign_name'])
    reference = rolling.require_mode_readiness(spec, lane, _context=current_context())
    from . import rapid_ordinary_canary_carry as carry
    from . import rapid_ordinary_group_canary as group
    carried = reference.get('schema_version') == 6 and reference.get('artifact_type') == carry.TYPE and mode == 'undefended'
    current_group = (reference.get('schema_version') == 5
        and reference.get('artifact_type') == group.TYPE and mode == 'undefended')
    if (reference.get('schema_version') not in (1, 5) and not carried
            or mode != 'undefended' and reference.get('schema_version') != 1):
        raise ValueError('target chunks cannot inherit a historical canary or control bridge')
    runtime = {key: spec.serializable()[key] for key in lanes.RUNTIME_KEYS}
    context = current_context()
    facts = (readiness.validate_canary(reference, runtime=runtime, mode=mode) if context is None
             else context.validate_canary(reference, runtime, mode, readiness.validate_canary))
    expected_source = {**lanes._load(_read(spec.source_manifest)), 'image_digest': spec.collection_image_digest}
    from .rapid_capture_traffic import plan_files
    from .application_response_policy import (application_body_identity_policy, application_response_policy,
        primary_document_identity_policy, validate_prepared_response_graph,
        COMPLETE_APPLICATION_DELIVERY_POLICY, COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY, VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
    if ((not carried and facts.get('source') != expected_source) or facts.get('authority_source') != expected_source
            or facts.get('client_sha256') != lanes._sha(_read(spec.client_binary))
            or facts.get('traffic_hashes') != {key: digest for key, (_, digest) in plan_files(base).items()}
            or application_body_identity_policy(facts) != application_body_identity_policy(base)
            or base.get('qualification_delivery_compatibility') is not None):
        raise ValueError('target chunks need their current Source/client/traffic canary without inherited qualification')
    root = lanes._regular_directory(Path(facts['result_root']))
    experiment = lanes._load(_read(root / 'experiment.json'))
    samples = experiment['samples']
    if len(samples) != 1 or samples[0].get('state') != 'accepted' or samples[0].get('defense') != mode:
        raise ValueError('target condition needs the original complete single-visit canary')
    run_path = readiness._child(root, samples[0]['path'] + '/neqo/run.json')
    run = lanes._load(_read(run_path))
    configuration = experiment['configuration']
    identity = target.condition_identity(configuration, run, mode)
    limits = target._capture_limits(mode, base['capture_limits'], identity)
    if limits != base['capture_limits']:
        if (target.traffic.declared(base) != target.duration.POLICY
                or not target._typed_equal(configuration.get('limits'), {**limits, 'max_attempts': 1})):
            raise ValueError('target BuFLO200 canary requires its declared duration and exact practice caps')
    if application_body_identity_policy(configuration) != application_body_identity_policy(base):
        raise ValueError('target canary and planned body policy differ')
    individual = facts.get('ordinary_individual_primary_authority') if carried else None
    if individual is not None:
        if (individual.get('artifact_type') != carry.INDIVIDUAL_POLICY_TYPE
                or individual.get('measured_native_primary_policy') != identity['primary_document_identity_policy']
                or individual.get('scientific_credit') is not False
                or individual.get('original_verified_sample_count') != 20
                or len(individual.get('individual_manifests', [])) != len(sites)):
            raise ValueError('target ordinary Native label lacks its distinct authenticated individual Lab authority')
    for index, site in enumerate(sites):
        path = spec.workload_root / (site.workload_id + '.json')
        manifest_raw = _read(path)
        manifest = lanes._load(manifest_raw)
        primary = identity['primary_document_identity_policy']
        if individual is not None:
            authority = individual['individual_manifests'][index]
            if (authority['candidate_id'] != site.candidate_id or authority['workload_id'] != site.workload_id
                    or carry.reference(path) != authority['authority_manifest']):
                raise ValueError('target ordinary individual authority changes full ordered current manifest identity')
            primary = authority['lab_primary_policy']
        elif current_group and primary_document_identity_policy(manifest) == VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY:
            # A fresh current ordinary group proves complete delivery. Its
            # Native label remains exact; the individual Lab policy is explicit.
            if (facts.get('ordinary_successful_group_canary') != group.TYPE
                    or primary != EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
                    or identity['application_response_policy'] != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
                    or application_body_identity_policy(base) != COMPLETE_APPLICATION_DELIVERY_POLICY
                    or lanes._sha(manifest_raw) != site.workload_sha256):
                raise ValueError('target ordinary current group lacks its exact Native/body/full manifest authority')
            validate_prepared_response_graph(manifest)
            primary = VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
        if (application_response_policy(manifest) != identity['application_response_policy']
                or primary_document_identity_policy(manifest) != primary):
            raise ValueError('target cohort changes its full response/status or primary acceptance condition')
    return reference, identity


def _derive(spec, inputs_ref, canonical_ref):
    sites, base = _base(spec)
    value = target.read_chunk_inputs(inputs_ref)
    inputs, mode = value['inputs'], value['mode']
    if (not inputs['ranges'] or not 1 <= len(inputs['classes']) <= 5
            or not target._typed_equal(inputs['capture_limits'], target._capture_limits(
                mode, base.get('capture_limits'), inputs['condition']['identity']))):
        raise ValueError('target chunks require remaining slots and exact homogeneous full-graph caps')
    expected = [(row['candidate_id'], row['workload_id']) for row in inputs['classes']]
    if expected != [(site.candidate_id, site.workload_id) for site in sites]:
        raise ValueError('target chunks changed the exact existing qualified cohort membership or order')
    from .rapid_partial_progress import graph_identity
    for site, row in zip(sites, inputs['classes']):
        if graph_identity(spec.workload_root / (site.workload_id + '.json')) != row['original_graph_sha256']:
            raise ValueError('target chunk changed an original full graph, request or origin')
    runtime = {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    canonical, source_files = runtime_reader.reopen_runtime(
        {key: canonical_ref[key] for key in ('path', 'sha256')}, runtime, _inspector=True)
    target._open(canonical_ref)
    controls = _checked_sources(runtime, source_files, CONTROL_FILENAMES)
    declaration = target.validate_target(inputs['target'])
    identity = declaration['target_identity']
    if (canonical['source']['neqo_commit'] != identity['native_head']
            or canonical['source']['neqo_pinned_commit'] != identity['native_head']
            or canonical['installed_client_sha256'] != identity['client_sha256']
            or lanes._sha(_read(spec.client_binary)) != identity['client_sha256']):
        raise ValueError('target chunk changed its fixed Native or verified client')
    canary, condition = _condition(spec, sites, base, mode)
    if (not target._typed_equal(condition, inputs['condition']['identity'])
            or target._digest(condition) != inputs['condition']['identity_sha256']):
        raise ValueError('target chunk current canary differs from the exact declared fixed condition')
    return {'contract': CONTRACT, 'lane_layout': geometry.LAYOUT, 'base_spec': spec.serializable(),
        'base_four_visit_plan': target.reference(spec.plan_receipt), 'target_chunk_inputs': inputs_ref,
        'current_canonical': canonical_ref, 'target_id': inputs['target_id'],
        'condition_sha256': inputs['condition']['identity_sha256'], 'classes': inputs['classes'],
        'capture_limits': inputs['capture_limits'], 'mode': mode, 'remaining_slots': inputs['remaining_slots'],
        'ranges': inputs['ranges'], 'maximum_visits': value['maximum'], 'current_canary': canary, 'runtime': runtime,
        'native_head': identity['native_head'], 'client_sha256': identity['client_sha256'],
        'control_sources': controls, 'original_deep_program_sha256': lanes._sha(target.epoch._PROGRAM.encode()),
        'scientific_credit': False, 'formal_accepted_trace_count': 0,
        'historical_progress_authority_inferred': False}, sites, base


@target._owned
def publish_policy(base_spec, inputs_ref, canonical_ref, output):
    derived, _, base = _derive(base_spec, inputs_ref, canonical_ref)
    # The base enrollment policy is the stable study publication boundary.
    batch, _, _ = rolling._verify_enrollment(base_spec.cohort)
    output = geometry._publication_path(Path(output), rolling._open_ref(batch['policy']).parent)
    target._check_action()
    return rolling._write(output, POLICY_TYPE, {**derived, 'published_at': receipts._now()})


@target._owned
def validate_policy(reference):
    value = receipts._unpack(_read(target._open(reference)), POLICY_TYPE)
    key = ('validated-target-chunk-policy', target._digest(reference))
    if current_context().has(key): return current_context().get(key)
    target._keys(value, POLICY_KEYS, 'fixed target chunk policy')
    spec = runtime_reader._spec(value['base_spec'])
    expected, sites, base = _derive(spec, value['target_chunk_inputs'], value['current_canonical'])
    if (not target._typed_equal({k: v for k, v in value.items() if k != 'published_at'}, expected)
            or not receipts._utc(base['declared_at']) <= receipts._utc(value['published_at']) <= receipts._utc(receipts._now())):
        raise ValueError('target chunk policy changed its target slots, fixed condition, inputs, Source or runtime')
    return current_context().remember(key, (value, sites, base))


def planned_lanes(policy, reference, sites, *, shard):
    rows = policy['classes']
    if [(r['candidate_id'], r['workload_id']) for r in rows] != [(s.candidate_id, s.workload_id) for s in sites]:
        raise ValueError('target chunk geometry changed its exact immutable class cohort')
    accepted = set(range(64)) - set(policy['remaining_slots'])
    if policy['ranges'] != [{'slot_start': start, 'slot_count': count} for start, count in geometry.ranges(
            accepted, maximum=policy['maximum_visits'])]:
        raise ValueError('target chunk ranges do not retain exact ordered remaining slots')
    answer = []
    mode = policy['mode']
    for ordinal, row in enumerate(policy['ranges'], 1):
        lane = geometry.ChunkLane('formal', ordinal, shard, mode, '', tuple(s.workload_id for s in sites),
            row['slot_count'], None if mode == 'undefended' else sites[0].qualification_set,
            row['slot_start'], reference['sha256'])
        lane = replace(lane, campaign_name=geometry.name(lane, 1))
        answer.append(geometry.checked_lane(asdict(lane)))
    observed = {(workload, lane.slot_start + local) for lane in answer for workload in lane.workload_ids
                for local in range(lane.visits_per_workload)}
    expected = {(s.workload_id, slot) for s in sites for slot in policy['remaining_slots']}
    if observed != expected or sum(l.sample_count for l in answer) != len(observed):
        raise ValueError('target chunk plan repeats, loses or invents a logical target slot')
    return tuple(answer)


@target._owned
def publish_plan(base_spec, policy_ref, output, *, _context=None):
    policy, sites, base = validate_policy(policy_ref)
    if policy['base_spec'] != base_spec.serializable():
        raise ValueError('target chunk plan changed its current qualified serial base')
    batch, _, _ = rolling._verify_enrollment(base_spec.cohort)
    output = geometry._publication_path(Path(output), rolling._open_ref(batch['policy']).parent)
    planned = planned_lanes(policy, policy_ref, sites, shard=batch['ordinal'])
    target._check_action(); rows = []
    for lane in planned:
        raw = geometry.render(lane, sites, **geometry._render_options(base))
        campaign = base_spec.campaign_dir / (lane.campaign_name + '.yml')
        receipts.durable_create(campaign, raw); current_context().watch_file(campaign)
        rows.append(geometry._row(lane, raw))
    target._check_action()
    return rolling._write(output, PLAN_TYPE, {**base, 'lanes': rows,
        'readiness': {policy['mode']: base['readiness'][policy['mode']]},
        'planned_trace_count': sum(l.sample_count for l in planned), 'declared_at': receipts._now(),
        'lane_layout': geometry.LAYOUT, FIELD: policy_ref, 'previous_target_chunk_plan': None})


@target._owned
def verify_plan(spec, *, require_current=False, _context=None):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    for path in input_files(value): current_context().watch_file(path)
    policy, sites, base = validate_policy(value.get(FIELD))
    base_spec = runtime_reader._spec(policy['base_spec'])
    if spec != replace(base_spec, plan_receipt=spec.plan_receipt):
        raise ValueError('target chunk spec changed its current runtime, full graphs or input roles')
    target._keys(value, set(base) | {'lane_layout', FIELD, 'previous_target_chunk_plan'}, 'target chunk plan')
    changing = {'lanes', 'readiness', 'planned_trace_count', 'declared_at'}
    if (any(not target._typed_equal(value[k], v) for k, v in base.items() if k not in changing)
            or value['lane_layout'] != geometry.LAYOUT
            or value['readiness'] != {policy['mode']: base['readiness'][policy['mode']]}
            or not receipts._utc(policy['published_at']) <= receipts._utc(value['declared_at']) <= receipts._utc(receipts._now())):
        raise ValueError('target chunk plan changed its fixed condition, caps, Source or readiness')
    batch, _, _ = rolling._verify_enrollment(spec.cohort)
    expected = planned_lanes(policy, value[FIELD], sites, shard=batch['ordinal'])
    if value['previous_target_chunk_plan'] is not None:
        predecessor = target._open(value['previous_target_chunk_plan'])
        if predecessor == spec.plan_receipt:
            raise ValueError('target chunk recovery ancestry is cyclic')
        _, previous = rolling.verify_capture_plan(replace(spec, plan_receipt=predecessor), _context=current_context())
        if (len(value['lanes']) != 1 or any(value[k] != previous[k] for k in value if k not in
                {'lanes', 'planned_trace_count', 'declared_at', 'previous_target_chunk_plan'})
                or receipts._utc(value['declared_at']) < receipts._utc(previous['declared_at'])):
            raise ValueError('target chunk recovery changes its original target or condition')
        lane = geometry.checked_lane({k: v for k, v in value['lanes'][0].items() if k != 'campaign_sha256'})
        predecessors = [geometry.checked_lane({k: v for k, v in row.items() if k != 'campaign_sha256'})
            for row in previous['lanes'] if row['campaign_name'] == geometry.name(lane, lane.generation - 1)]
        if len(predecessors) != 1 or geometry.successor(predecessors[0], lane.generation) != lane:
            raise ValueError('target chunk recovery skips a generation or changes logical slots')
        expected = (lane,)
    actual = []
    for lane in expected:
        raw = geometry.render(lane, sites, **geometry._render_options(base))
        if _read(spec.campaign_dir / (lane.campaign_name + '.yml')) != raw:
            raise ValueError('target chunk campaign changes its full graph, fixed traffic or logical slots')
        actual.append(geometry._row(lane, raw))
    if (value['lanes'] != actual or type(value['planned_trace_count']) is not int
            or value['planned_trace_count'] != sum(l.sample_count for l in expected)):
        raise ValueError('target chunk plan lost, repeated or invented remaining target slots')
    return sites, value


@target._owned
def publish_successor(spec, lane_name, generation, output):
    sites, value = rolling.verify_capture_plan(spec, _context=current_context())
    matching = [row for row in value['lanes'] if row['campaign_name'] == lane_name]
    if len(matching) != 1: raise ValueError('target chunk recovery requires one immediate failed lane')
    lane = geometry.successor(geometry.checked_lane({k: v for k, v in matching[0].items()
        if k != 'campaign_sha256'}), generation)
    batch, _, _ = rolling._verify_enrollment(spec.cohort)
    output = geometry._publication_path(Path(output), rolling._open_ref(batch['policy']).parent)
    raw = geometry.render(lane, sites, **geometry._render_options(value))
    target._check_action(); campaign = spec.campaign_dir / (lane.campaign_name + '.yml')
    receipts.durable_create(campaign, raw); current_context().watch_file(campaign)
    target._check_action()
    return rolling._write(output, PLAN_TYPE, {**value, 'lanes': [geometry._row(lane, raw)],
        'planned_trace_count': lane.sample_count, 'declared_at': receipts._now(),
        'previous_target_chunk_plan': target.reference(spec.plan_receipt)})


def input_files(value):
    policy_path = target._open(value[FIELD]); policy = receipts._unpack(_read(policy_path), POLICY_TYPE)
    inputs_path = target._open(policy['target_chunk_inputs'])
    inputs = target.read_chunk_inputs(policy['target_chunk_inputs'])['inputs']
    files = {policy_path, inputs_path, target._open(policy['current_canonical']),
        target._open(policy['base_four_visit_plan']), *[target._open(r) for r in policy['control_sources'].values()]}
    files.update(target._open(r) for r in target.input_files(inputs['progress']))
    previous = value.get('previous_target_chunk_plan'); seen = set()
    while previous is not None:
        path = target._open(previous)
        if path in seen or len(seen) >= legacy.MAX_LANE_GENERATION:
            raise ValueError('target chunk plan ancestry is cyclic or exceeds the recovery bound')
        files.add(path); seen.add(path)
        previous = receipts._unpack(_read(path), PLAN_TYPE).get('previous_target_chunk_plan')
    return files


def roots(spec):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    policy = receipts._unpack(_read(target._open(value[FIELD])), POLICY_TYPE)
    inputs = target.read_chunk_inputs(policy['target_chunk_inputs'])['inputs']
    result = {path.parent for path in input_files(value)}
    result.update(target.roots(inputs['progress']))
    result.update(rolling.enrollment_roots(runtime_reader._spec(policy['base_spec'])))
    return result


def require_partial_binding(report):
    """Recorded original proof must observe this exact target policy and plan."""
    lane = geometry.checked_lane(report['lane'])
    spec = runtime_reader._spec(report['spec'])
    _, value = verify_plan(spec)
    if value != report['lineage']['image_check']['proof']['plan_payload']:
        raise ValueError('partial target chunk plan differs from the original executed authority')
    policy = target.reference(target._open(value[FIELD])); plan = target.reference(spec.plan_receipt)
    if (policy['sha256'] != lane.slot_policy_sha256
            or any(ref not in report['read_dependencies'] for ref in (policy, plan))):
        raise ValueError('partial target chunk original proof did not bind its exact policy and plan')
    return {**report, 'chunk_bindings': {'plan': plan, 'policy': policy}}
