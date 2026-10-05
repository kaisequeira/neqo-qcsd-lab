"""Current fixed-target chunk workers; no historical qualification waiver."""
from dataclasses import asdict, replace
from pathlib import Path

from . import rapid_target_chunks as chunks
from . import rapid_fixed_condition_target as target
from . import rapid_slot_chunks as geometry
from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_rolling_schedule as schedule
from . import rapid_ordinary_parallel_schedule as old_workers
from . import rapid_undefended_capture as ordinary
from . import rapid_site_admission as receipts
from .rapid_operation_facts import current_context

CAPSULE_TYPE = 'qcsd-current-fixed-condition-target-parallel-scheduling-v1'
PLAN_TYPE = 'qcsd-current-fixed-condition-target-parallel-plan-v1'
CONTRACT = 'current-target-same-mode-disjoint-one-through-sixteen-slot-workers-v1'
FIELD = 'target_parallel_contract'
BASE_FIELD = 'target_parallel_base_spec'
CONTROL_FILES = tuple(sorted(set(old_workers.CONTROL_FILES) | set(chunks.sources()) | {
    'src/qcsd_lab/rapid_target_parallel_schedule.py', 'tools/rapid_target_parallel.py'}))
CAPSULE_KEYS = {'schema_version', 'artifact_type', 'contract', 'base_spec', 'runtime',
    'qualification_spec', 'original_canonical', 'current_canonical', 'target_policy',
    'target_id', 'condition_sha256', 'mode', 'capture_limits', 'canary', 'control_sources',
    'published_at', 'reason', 'formal_accepted_trace_count', 'scientific_credit'}
EXTRA_KEYS = {'scheduling', FIELD, BASE_FIELD}
_scope = target._owned
_read = chunks._read
_spec = schedule._spec


def is_plan(path):
    return lanes._load(_read(path)).get('receipt_type') == PLAN_TYPE


def is_payload(value):
    return value.get(FIELD) == CONTRACT


def is_schedule(reference):
    return lanes._load(_read(rolling._open_ref(reference))).get('artifact_type') == CAPSULE_TYPE


def _base(spec):
    if not chunks.is_plan(spec.plan_receipt):
        raise ValueError('target scheduling needs its exact unscheduled target chunk plan')
    return chunks.verify_plan(spec, require_current=True, _context=current_context())


def input_dependencies(base, sites, *, _context=None):
    files, trees = old_workers.input_dependencies(base, sites, _context=_context)
    _, payload = _base(base)
    files.update(chunks.input_files(payload))
    qualifier = lanes._load(_read(base.qualification_spec))
    for row in qualifier.get('qualification_sets', []):
        for name in ('manifest', 'sidecar_root'):
            path = Path(row[name]); path = path if path.is_absolute() else base.qualification_spec.parent / path
            files.add(path) if name == 'manifest' else trees.add(path)
    context = _context or current_context()
    if context is not None:
        for path in files: context.watch_file(path)
        for path in trees: context.watch_tree(path)
    return files, trees


def bind_dependencies(value, context):
    base = _spec(value['base_spec']); context.bind_capture(base)
    sites, _ = _base(base)
    input_dependencies(base, sites, _context=context)
    pending, seen = [value['current_canonical']], set()
    while pending:
        item = pending.pop(); path = rolling._open_ref(item)
        if path in seen: raise ValueError('target runtime dependency contains an ancestor cycle')
        seen.add(path); context.watch_tree(path.parent)
        canonical = lanes._load(context.watch_file(path)); context._references(canonical, path.parent)
        for name in ('client_reuse_recipe', 'client_reuse_proof', 'original_native_build_record', 'closure_recipe'):
            if name in canonical: context.watch_file(rolling._open_ref(canonical[name]))
        if canonical.get('original_canonical') is not None: pending.append(canonical['original_canonical'])


def _derive(base, runtime, canonical_ref):
    runtime = rolling._runtime(runtime)
    if runtime != {key: base.serializable()[key] for key in rolling.RUNTIME_FIELDS}:
        raise ValueError('target scheduling changed its exact current serial runtime')
    sites, payload = _base(base)
    policy, _, _ = chunks.validate_policy(payload[chunks.FIELD])
    if (not payload['lanes'] or any(row['mode'] != policy['mode'] for row in payload['lanes'])
            or target.reference(rolling._open_ref(canonical_ref)) != policy['current_canonical']):
        raise ValueError('target scheduling changed mode or actual current canonical')
    canonical, blobs = schedule.reopen_runtime(canonical_ref, runtime, _inspector=True)
    controls = {}
    for relative in CONTROL_FILES:
        own = Path(__file__).resolve().parents[2] / relative
        ref = target.reference(own)
        runtime_path, module_path = Path(runtime['runtime_source_root']) / relative, Path(runtime['module_root']) / relative
        if (blobs.get(relative) != _read(own) or target.reference(runtime_path)['sha256'] != ref['sha256']
                or target.reference(module_path)['sha256'] != ref['sha256']
                or any(target.reference(path)['mode'] != ref['mode'] for path in (runtime_path, module_path))):
            raise ValueError('target scheduling executing/installed/current control Source differs')
        controls[relative] = {'sha256': ref['sha256'], 'mode': ref['mode']}
    input_dependencies(base, sites, _context=current_context())
    return {'target_policy': payload[chunks.FIELD], 'target_id': policy['target_id'],
        'condition_sha256': policy['condition_sha256'], 'mode': policy['mode'],
        'capture_limits': policy['capture_limits'], 'canary': policy['current_canary'], 'control_sources': controls}


@_scope
def publish_schedule(base_spec, runtime, qualification_spec, original_canonical, current_canonical,
                     output, *, reason):
    if (original_canonical != current_canonical or rolling._ref(qualification_spec) != rolling._ref(base_spec.qualification_spec)
            or not isinstance(reason, str) or not reason.strip()):
        raise ValueError('target workers need one current canonical/input and a prospective reason')
    seed = {'base_spec': base_spec.serializable(), 'current_canonical': dict(current_canonical)}
    bind_dependencies(seed, current_context())
    derived = _derive(base_spec, runtime, current_canonical)
    output = geometry._publication_path(Path(output), rolling._open_ref(rolling._verify_enrollment(base_spec.cohort)[0]['policy']).parent)
    value = {'schema_version': 1, 'artifact_type': CAPSULE_TYPE, 'contract': CONTRACT,
        'base_spec': base_spec.serializable(), 'runtime': dict(runtime), 'qualification_spec': rolling._ref(qualification_spec),
        'original_canonical': dict(original_canonical), 'current_canonical': dict(current_canonical), **derived,
        'published_at': receipts._now(), 'reason': reason.strip(), 'scientific_credit': False, 'formal_accepted_trace_count': 0}
    target._check_action(); receipts.durable_create(output, lanes._json(value))
    return rolling._ref(output)


@_scope
def validate_schedule(reference, *, runtime=None, before=None, _context=None):
    path = rolling._open_ref(reference); raw = _read(path); value = lanes._load(raw)
    rolling._keys(value, CAPSULE_KEYS, 'target worker scheduling')
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['artifact_type'] != CAPSULE_TYPE or value['contract'] != CONTRACT
            or value['original_canonical'] != value['current_canonical']
            or value['scientific_credit'] is not False or type(value['formal_accepted_trace_count']) is not int
            or value['formal_accepted_trace_count'] != 0 or not isinstance(value['reason'], str) or not value['reason'].strip()
            or runtime is not None and dict(runtime) != value['runtime']
            or not receipts._utc(value['published_at']) <= receipts._utc(before or receipts._now())):
        raise ValueError('target scheduling exact header/runtime/chronology differs')
    context = current_context(); bind_dependencies(value, context)
    key = (CAPSULE_TYPE, lanes._sha(raw))
    if context.has(key): derived = context.get(key)
    else:
        derived = _derive(_spec(value['base_spec']), value['runtime'], value['current_canonical'])
        context.remember(key, derived)
    if any(value[name] != item for name, item in derived.items()):
        raise ValueError('target scheduling changed graph/caps/condition/current qualification/Source')
    canonical = lanes._load(_read(rolling._open_ref(value['current_canonical'])))
    if (not receipts._utc(canonical['verified_at']) <= receipts._utc(value['published_at'])
            or rolling._ref(_spec(value['base_spec']).qualification_spec) != value['qualification_spec']):
        raise ValueError('target scheduling predates its actual current runtime or changed its input')
    return value


@_scope
def publish_plan(base_spec, scheduling, output, *, _context=None):
    capsule = validate_schedule(scheduling)
    if capsule['base_spec'] != base_spec.serializable(): raise ValueError('target worker plan changed its serial base')
    _, base = _base(base_spec)
    output = geometry._publication_path(Path(output), rolling._open_ref(rolling._verify_enrollment(base_spec.cohort)[0]['policy']).parent)
    value = {**base, 'scheduling': dict(scheduling), FIELD: CONTRACT, BASE_FIELD: base_spec.serializable(), 'declared_at': receipts._now()}
    target._check_action(); return rolling._write(output, PLAN_TYPE, value)


@_scope
def verify_plan(spec, *, require_current=False, _context=None):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE); base = _spec(value[BASE_FIELD])
    if spec != replace(base, plan_receipt=spec.plan_receipt): raise ValueError('target worker wrapper changed its full serial spec')
    sites, old = _base(base); require_plan(value)
    if not receipts._utc(old['declared_at']) <= receipts._utc(value['declared_at']) <= receipts._utc(receipts._now()):
        raise ValueError('target worker plan predates its serial authority')
    return sites, value


def require_plan(value, *, _context=None):
    if not is_payload(value): raise ValueError('target worker typed policy missing')
    capsule = validate_schedule(value['scheduling'], runtime=value['runtime'], before=value['declared_at'], _context=_context)
    base = _spec(value[BASE_FIELD]); _, old = _base(base)
    rolling._keys(value, set(old) | EXTRA_KEYS, 'target parallel payload')
    if capsule['base_spec'] != base.serializable() or any(value[key] != item for key, item in old.items() if key != 'declared_at'):
        raise ValueError('target worker payload changed its full serial authority')
    return capsule


def check_layout(spec, inputs):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE); base = _spec(value[BASE_FIELD])
    if spec != replace(base, plan_receipt=spec.plan_receipt): raise ValueError('target wrapper layout changed its serial input')
    ordinary.check_layout(base, inputs)
    require_plan(value)


def prepared_lane(value): return geometry.checked_lane(value)


def prepared_sites(payload, rows):
    return tuple((ordinary.OrdinarySite if ordinary.FIELD in payload else lanes.plan.Site)(**row) for row in rows)


def require_worker(payload, lane, sites, spec):
    capsule = require_plan(payload)
    if (lane.role != 'formal' or lane.mode != capsule['mode'] or not isinstance(lane, geometry.ChunkLane)
            or not 1 <= lane.visits_per_workload <= 16 or lane.sample_count != lane.visits_per_workload * len(lane.workload_ids)
            or not set(lane.workload_ids) <= {site.workload_id for site in sites}
            or spec != replace(_spec(capsule['base_spec']), plan_receipt=spec.plan_receipt)
            or asdict(lanes._lane({'plan_payload': payload}, lane.campaign_name)) != asdict(lane)):
        raise ValueError('target worker changed its exact registered mode/slots/full input')
    return {(workload, lane.mode, geometry.logical_slot(lane, local))
        for workload in lane.workload_ids for local in range(lane.visits_per_workload)}


def require_disjoint(facts):
    if not any(is_payload(payload) for _, payload, _, _ in facts): return
    if len(facts) != 2 or not all(is_payload(payload) for _, payload, _, _ in facts):
        raise ValueError('target workers cannot mix another scheduling contract')
    occupied, identities = set(), set()
    for spec, payload, lane, sites in facts:
        capsule = require_plan(payload)
        identities.add((capsule['target_id'], capsule['condition_sha256'], capsule['mode']))
        own = require_worker(payload, lane, sites, spec)
        if occupied & own: raise ValueError('target workers repeat a logical class/mode/slot')
        occupied.update(own)
    if len(identities) != 1: raise ValueError('target workers need the exact same fixed mode/condition')


@_scope
def mount_roots(reference, *, _context=None):
    capsule = validate_schedule(reference); base = _spec(capsule['base_spec']); sites, payload = _base(base)
    files, trees = input_dependencies(base, sites)
    roots = set(chunks.roots(base)) | trees | {path.parent for path in files} | {Path(reference['path']).parent}
    roots.update(Path(capsule['runtime'][key]) for key in ('runtime_source_root', 'module_root', 'execution_root'))
    roots.update(Path(capsule['runtime'][key]).parent for key in ('source_manifest', 'client_binary', 'base_launcher', 'host_launcher'))
    roots.update(rolling.readiness_roots(base, payload['lanes'][0]['campaign_name']))
    pending, seen = [capsule['current_canonical']], set()
    while pending:
        path = rolling._open_ref(pending.pop())
        if path in seen: raise ValueError('target runtime transport has an ancestor cycle')
        seen.add(path); roots.add(path.parent); canonical = lanes._load(_read(path))
        for key in ('client_reuse_recipe', 'client_reuse_proof', 'original_native_build_record', 'closure_recipe'):
            if key in canonical: roots.add(rolling._open_ref(canonical[key]).parent)
        if canonical.get('original_canonical') is not None: pending.append(canonical['original_canonical'])
    return sorted(root for root in roots if not any(root != other and root.is_relative_to(other) for other in roots))


def roots(spec):
    value = receipts._unpack(_read(spec.plan_receipt), PLAN_TYPE)
    return set(mount_roots(value['scheduling'])) | {spec.plan_receipt.parent}


def validate_current_implementation(old, current, reference, *, actual_image, before=None, _context=None):
    value = validate_schedule(reference, before=before, _context=_context)
    if old != current or actual_image != value['runtime']['collection_image_digest']:
        raise ValueError('target scheduling cannot exempt changed implementation or image')
    from . import chaff_qualification as qualification
    qualification._validate_implementation_receipt(current, require_current=False)
    canonical = lanes._load(_read(rolling._open_ref(value['current_canonical'])))
    if (current['sha256'] != canonical['checks']['collection']['qualification_implementation_sha256']
            or current['source'] != canonical['source']
            or current['neqo_qcsd_client']['sha256'] != canonical['installed_client_sha256']):
        raise ValueError('target current qualification differs from its actual canonical implementation/client')


@_scope
def publish_successor(spec, lane_name, generation, output):
    _, value = verify_plan(spec); base = _spec(value[BASE_FIELD]); output = Path(output)
    serial, capsule_path = output.with_name(output.stem + '-serial.json'), output.with_name(output.stem + '-scheduling.json')
    if any(path.exists() or path.is_symlink() for path in (output, serial, capsule_path)):
        raise FileExistsError('target recovery is create-only including its serial/capsule authority')
    path = chunks.publish_successor(base, lane_name, generation, serial); successor = replace(base, plan_receipt=path)
    capsule = validate_schedule(value['scheduling'])
    reference = publish_schedule(successor, value['runtime'], base.qualification_spec,
        capsule['current_canonical'], capsule['current_canonical'], capsule_path,
        reason='immediate failed worker successor; accepted peer stays immutable')
    return publish_plan(successor, reference, output)
