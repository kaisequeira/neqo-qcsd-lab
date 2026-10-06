"""Serial chunks from the combined, original-proof per-mode Native-epoch gaps."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
from typing import Mapping

from . import rapid_fixed_condition_target as target
from . import rapid_per_mode_native_target as epoch_target
from . import rapid_target_chunks as original_chunks
from . import rapid_slot_chunks as geometry
from . import rapid_capture_plan as legacy
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_readiness as readiness
from . import rapid_rolling_schedule as runtime_reader
from . import rapid_site_admission as receipts
from .rapid_operation_facts import current_context
from . import rapid_action_local_source_facts as source_facts

POLICY_TYPE = 'qcsd-per-mode-native-epoch-target-slot-chunk-policy-v1'
PLAN_TYPE = 'qcsd-per-mode-native-epoch-target-slot-chunk-plan-v1'
CONTRACT = 'declared-epoch-progress-current-qualified-full-graph-chunks-v1'
FIELD = 'epoch_target_chunk_policy'
CONTROL_FILENAMES = original_chunks.CONTROL_FILENAMES + (
    'src/qcsd_lab/rapid_epoch_target_chunks.py',
    'src/qcsd_lab/rapid_per_mode_native_target.py',
    'tools/rapid_epoch_target_chunks.py',)
POLICY_KEYS = {'contract', 'lane_layout', 'base_spec', 'base_four_visit_plan', 'target_chunk_inputs',
    'current_canonical', 'target_id', 'condition_sha256', 'classes', 'capture_limits', 'mode',
    'remaining_slots', 'ranges', 'maximum_visits', 'current_canary', 'runtime', 'native_head', 'client_sha256',
    'epoch_index', 'epoch_target', 'epoch_progress', 'epoch_declared_at', 'source_binding',
    'control_sources', 'original_deep_program_sha256', 'published_at', 'scientific_credit',
    'formal_accepted_trace_count', 'historical_progress_authority_inferred'}


def _read(path):
    context = current_context()
    return lanes._read(Path(path)) if context is None else context.watch_file(Path(path))


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
    controls = original_chunks._checked_sources(runtime, source_files, original_chunks.CONTROL_FILENAMES)
    module_root = lanes._regular_directory(Path(runtime['module_root']))
    runtime_root = lanes._regular_directory(Path(runtime['runtime_source_root']))
    executing = {
        'src/qcsd_lab/rapid_epoch_target_chunks.py': Path(__file__),
        'src/qcsd_lab/rapid_per_mode_native_target.py': Path(epoch_target.__file__),
    }
    for relative in filenames[len(original_chunks.CONTROL_FILENAMES):]:
        path = module_root / relative
        ref = target.reference(path)
        live = target.reference(executing.get(relative, path))
        installed = target.reference(runtime_root / relative)
        if (source_files.get(relative) != _read(path)
                or any(observed[name] != ref[name] for observed in (live, installed)
                       for name in ('sha256', 'mode'))):
            raise ValueError('epoch target executing/installed/frozen control Source differs')
        controls[relative] = ref
    return controls


def is_plan(path):
    value = lanes._load(_read(path))
    return isinstance(value, dict) and value.get('receipt_type') == PLAN_TYPE


def _base(spec):
    return original_chunks._base(spec)


def _condition(spec, sites, base, mode):
    return original_chunks._condition(spec, sites, base, mode)


def _derive(spec, inputs_ref, canonical_ref):
    sites, base = _base(spec)
    value = epoch_target.read_chunk_inputs(inputs_ref)
    inputs, mode = value['inputs'], value['mode']
    slots = inputs['remaining_slots']
    if (type(value['maximum']) is not int or not 1 <= value['maximum'] <= 16
            or not isinstance(slots, list) or any(type(slot) is not int or not 0 <= slot < 64 for slot in slots)
            or slots != sorted(set(slots))):
        raise ValueError('epoch chunk remaining slots or maximum have another geometry')
    expected_ranges = [{'slot_start': start, 'slot_count': count} for start, count in
                       geometry.ranges(set(range(64)) - set(slots), maximum=value['maximum'])]
    if (not inputs['ranges'] or not 1 <= len(inputs['classes']) <= 5
            or inputs['ranges'] != expected_ranges
            or not target._typed_equal(inputs['capture_limits'], target._capture_limits(
                mode, base.get('capture_limits'), inputs['condition']['identity']))):
        raise ValueError('epoch chunks require combined remaining slots and exact homogeneous full-graph caps')
    expected = [(row['candidate_id'], row['workload_id']) for row in inputs['classes']]
    if expected != [(site.candidate_id, site.workload_id) for site in sites]:
        raise ValueError('epoch chunks changed the exact existing qualified cohort membership or order')
    from .rapid_partial_progress import graph_identity
    for site, row in zip(sites, inputs['classes']):
        if graph_identity(spec.workload_root / (site.workload_id + '.json')) != row['original_graph_sha256']:
            raise ValueError('epoch chunk changed an original full graph, request or origin')
    runtime = {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    canonical, source_files = runtime_reader.reopen_runtime(
        {key: canonical_ref[key] for key in ('path', 'sha256')}, runtime, _inspector=True)
    target._open(canonical_ref)
    controls = _checked_sources(runtime, source_files, CONTROL_FILENAMES)
    declaration = epoch_target.validate_target(inputs['target'])
    progress = epoch_target.validate_progress(inputs['progress'])
    identity = inputs['epoch']
    try:
        selected_record = declaration['mode_targets'][mode][inputs['epoch_index']]
        selected_identity = declaration['identity']['epochs'][mode][inputs['epoch_index']]
        selected_stamp = declaration['epoch_declared_at'][mode][inputs['epoch_index']]
    except (KeyError, IndexError, TypeError) as error:
        raise ValueError('epoch chunk selected an undeclared mode or Native epoch') from error
    if (not target._typed_equal(selected_identity, identity)
            or selected_record['source_binding'] != inputs['source_binding']
            or selected_stamp != inputs['epoch_declared_at']):
        raise ValueError('epoch chunk changed its declared selected Native epoch')
    if (progress['target'] != inputs['target'] or progress['target_id'] != inputs['target_id']
            or declaration['target_id'] != inputs['target_id']
            or canonical['source']['neqo_commit'] != identity['native_head']
            or canonical['source']['neqo_pinned_commit'] != identity['native_head']
            or canonical['installed_client_sha256'] != identity['client_sha256']
            or lanes._sha(_read(spec.client_binary)) != identity['client_sha256']):
        raise ValueError('epoch chunk changed combined progress, Native or verified client')
    binding_ref = inputs['source_binding']
    if (binding_ref is None) != (inputs['epoch_declared_at'] is None):
        raise ValueError('epoch chunk cannot omit or invent its prospective installed Source binding')
    if binding_ref is not None:
        source = epoch_target._binding(binding_ref, identity)
        installed = source['binding']
        if (source['native_head'] != identity['native_head']
                or any(installed['runtime_identity']['source'][key] != identity['native_head']
                       for key in ('neqo_commit', 'neqo_pinned_commit'))
                or installed['runtime_identity']['client_sha256'] != identity['client_sha256']):
            raise ValueError('epoch chunk differs from its declared installed Native/client pair')
    canary, condition = _condition(spec, sites, base, mode)
    if (not target._typed_equal(condition, inputs['condition']['identity'])
            or target._digest(condition) != inputs['condition']['identity_sha256']):
        raise ValueError('epoch chunk current canary differs from the exact declared fixed condition')
    return {'contract': CONTRACT, 'lane_layout': geometry.LAYOUT, 'base_spec': spec.serializable(),
        'base_four_visit_plan': target.reference(spec.plan_receipt), 'target_chunk_inputs': inputs_ref,
        'current_canonical': canonical_ref, 'target_id': inputs['target_id'],
        'condition_sha256': inputs['condition']['identity_sha256'], 'classes': inputs['classes'],
        'capture_limits': inputs['capture_limits'], 'mode': mode, 'remaining_slots': inputs['remaining_slots'],
        'ranges': inputs['ranges'], 'maximum_visits': value['maximum'], 'current_canary': canary, 'runtime': runtime,
        'native_head': identity['native_head'], 'client_sha256': identity['client_sha256'],
        'epoch_index': inputs['epoch_index'], 'epoch_target': inputs['target'],
        'epoch_progress': inputs['progress'], 'epoch_declared_at': inputs['epoch_declared_at'],
        'source_binding': binding_ref,
        'control_sources': controls, 'original_deep_program_sha256': lanes._sha(target.epoch._PROGRAM.encode()),
        'scientific_credit': False, 'formal_accepted_trace_count': 0,
        'historical_progress_authority_inferred': False}, sites, base


@epoch_target._owned
def publish_policy(base_spec, inputs_ref, canonical_ref, output):
    derived, _, base = _derive(base_spec, inputs_ref, canonical_ref)
    # The base enrollment policy is the stable study publication boundary.
    batch, _, _ = rolling._verify_enrollment(base_spec.cohort)
    output = geometry._publication_path(Path(output), rolling._open_ref(batch['policy']).parent)
    published = receipts._now()
    if any(stamp is not None and receipts._utc(stamp) > receipts._utc(published) for stamp in (
            derived['epoch_declared_at'],
            epoch_target.validate_target(derived['epoch_target'])['published_at'],
            epoch_target.validate_progress(derived['epoch_progress'])['published_at'])):
        raise ValueError('epoch chunk policy predates its declared epoch or combined progress')
    target._check_action()
    return rolling._write(output, POLICY_TYPE, {**derived, 'published_at': published})


@epoch_target._owned
def validate_policy(reference):
    value = receipts._unpack(_read(target._open(reference)), POLICY_TYPE)
    key = ('validated-epoch-target-chunk-policy', target._digest(reference))
    if current_context().has(key): return current_context().get(key)
    target._keys(value, POLICY_KEYS, 'per-mode epoch target chunk policy')
    spec = runtime_reader._spec(value['base_spec'])
    expected, sites, base = _derive(spec, value['target_chunk_inputs'], value['current_canonical'])
    if (not target._typed_equal({k: v for k, v in value.items() if k != 'published_at'}, expected)
            or any(stamp is not None and receipts._utc(stamp) > receipts._utc(value['published_at']) for stamp in (
                base['declared_at'], value['epoch_declared_at'],
                epoch_target.validate_target(value['epoch_target'])['published_at'],
                epoch_target.validate_progress(value['epoch_progress'])['published_at']))
            or receipts._utc(value['published_at']) > receipts._utc(receipts._now())):
        raise ValueError('epoch chunk policy changed its joined slots, fixed condition, inputs, Source or runtime')
    return current_context().remember(key, (value, sites, base))


def require_intent(policy_ref, started_at):
    """Reject an actuation preceding its selected, prospective epoch."""
    policy, _, _ = validate_policy(policy_ref)
    if (receipts._utc(started_at) < receipts._utc(policy['published_at'])
            or policy['epoch_declared_at'] is not None
            and receipts._utc(started_at) < receipts._utc(policy['epoch_declared_at'])):
        raise ValueError('epoch chunk intent predates its selected epoch and policy')
    return policy


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


@epoch_target._owned
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
        'lane_layout': geometry.LAYOUT, FIELD: policy_ref, 'previous_epoch_target_chunk_plan': None})


@epoch_target._owned
def verify_plan(spec, *, require_current=False, _context=None):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    for path in input_files(value): current_context().watch_file(path)
    policy, sites, base = validate_policy(value.get(FIELD))
    base_spec = runtime_reader._spec(policy['base_spec'])
    if spec != replace(base_spec, plan_receipt=spec.plan_receipt):
        raise ValueError('target chunk spec changed its current runtime, full graphs or input roles')
    target._keys(value, set(base) | {'lane_layout', FIELD, 'previous_epoch_target_chunk_plan'}, 'epoch target chunk plan')
    changing = {'lanes', 'readiness', 'planned_trace_count', 'declared_at'}
    if (any(not target._typed_equal(value[k], v) for k, v in base.items() if k not in changing)
            or value['lane_layout'] != geometry.LAYOUT
            or value['readiness'] != {policy['mode']: base['readiness'][policy['mode']]}
            or not receipts._utc(policy['published_at']) <= receipts._utc(value['declared_at']) <= receipts._utc(receipts._now())):
        raise ValueError('target chunk plan changed its fixed condition, caps, Source or readiness')
    batch, _, _ = rolling._verify_enrollment(spec.cohort)
    expected = planned_lanes(policy, value[FIELD], sites, shard=batch['ordinal'])
    if value['previous_epoch_target_chunk_plan'] is not None:
        predecessor = target._open(value['previous_epoch_target_chunk_plan'])
        if predecessor == spec.plan_receipt:
            raise ValueError('target chunk recovery ancestry is cyclic')
        _, previous = rolling.verify_capture_plan(replace(spec, plan_receipt=predecessor), _context=current_context())
        if (len(value['lanes']) != 1 or any(value[k] != previous[k] for k in value if k not in
                {'lanes', 'planned_trace_count', 'declared_at', 'previous_epoch_target_chunk_plan'})
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


@epoch_target._owned
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
        'previous_epoch_target_chunk_plan': target.reference(spec.plan_receipt)})


@source_facts.selection
def input_files(value):
    policy_path = target._open(value[FIELD]); policy = receipts._unpack(_read(policy_path), POLICY_TYPE)
    inputs_path = target._open(policy['target_chunk_inputs'])
    inputs = epoch_target.read_chunk_inputs(policy['target_chunk_inputs'])['inputs']
    files = {policy_path, inputs_path, target._open(policy['current_canonical']),
        target._open(policy['base_four_visit_plan']), *[target._open(r) for r in policy['control_sources'].values()]}
    files.update(target._open(r) for r in epoch_target.input_files(inputs['progress']))
    previous = value.get('previous_epoch_target_chunk_plan'); seen = set()
    while previous is not None:
        path = target._open(previous)
        if path in seen or len(seen) >= legacy.MAX_LANE_GENERATION:
            raise ValueError('target chunk plan ancestry is cyclic or exceeds the recovery bound')
        files.add(path); seen.add(path)
        previous = receipts._unpack(_read(path), PLAN_TYPE).get('previous_epoch_target_chunk_plan')
    return files


def roots(spec):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    policy = receipts._unpack(_read(target._open(value[FIELD])), POLICY_TYPE)
    inputs = epoch_target.read_chunk_inputs(policy['target_chunk_inputs'])['inputs']
    result = {path.parent for path in input_files(value)}
    result.update(Path(ref['path']).parent for ref in epoch_target.input_files(inputs['progress']))
    result.update(Path(row['path']) for row in epoch_target.directory_dependencies(inputs['progress']))
    def original_mounts(ref):
        for path in target.roots(ref):
            if path.is_file() and not path.is_symlink(): result.add(path.parent)
            elif path.is_dir() and not path.is_symlink(): result.add(path)
            else: raise ValueError('original fixed-target dependency is not a regular mount input')
    def original_roots(ref, seen):
        if ref['path'] in seen: return
        seen.add(ref['path'])
        progress = epoch_target.validate_progress(ref)
        for mode_refs in progress['mode_progress'].values():
            for original in mode_refs: original_mounts(original)
        declaration = epoch_target.validate_target(progress['target'])
        original_mounts(declaration['carry_progress'])
        for previous in (progress['parent'], progress['previous_progress']):
            if previous is not None: original_roots(previous, seen)
    original_roots(inputs['progress'], set())
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
    require_intent(value[FIELD], report['intent']['started_at'])
    if (policy['sha256'] != lane.slot_policy_sha256
            or any(ref not in report['read_dependencies'] for ref in (policy, plan))):
        raise ValueError('partial target chunk original proof did not bind its exact policy and plan')
    return {**report, 'chunk_bindings': {'plan': plan, 'policy': policy}}
