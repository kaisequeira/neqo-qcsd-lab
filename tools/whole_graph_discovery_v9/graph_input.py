"""Prospective V9: retain an interrupted V8 batch and assess its same reservations.

Original producer files and installed Source are never edited. Historical
function bodies execute in separate, command-local namespaces; V9 identities,
effect fences and exception projection are explicitly new reviewed code.
"""
from __future__ import annotations
import ast
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import time
from types import FunctionType, SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import action_facts

ORIGINAL = HERE.parent / 'whole-graph-navigation-generic-catalogue-producer-20261006-013'
ORIGINAL_PAIR = {'graph_input.py': 'ca61994bff27939e04cd4f17a00800afe43e73757a8dd206b2e2f09336cb30d9',
                 'operator.py': 'bf37b0ba64eff7844b04730c9307615c5d91530fb16348aa9345153ed315678a'}
ORIGINAL_CONTROLLER = 'aa18c6cb226d2984cca17c28b3294ed1e52619228a6e87a72488debb5363cf8b'
# The same-daemon attestation applies to this recorded interruption and this
# later observation. It grants no recovery authority to another old batch.
ORIGINAL_INTERRUPTION_PLAN = 'da3374dc5210b22a61b0f684e5c105d5abae5b8f962a969e6d313a1748166909'
ORIGINAL_INTERRUPTION_INPUTS = 'b647159d3957b2067d1e8f794dd6db8def785a857006eb27912557b4d97bc9a4'
ORIGINAL_TERMINAL_OBSERVATION = '76db27a648cf34bde0bece5d5f83f684a55e6dc36e4c4aed5ced0da31aa25d02'
ORIGINAL_PROTOCOL_REVIEW = HERE.parent / 'supplemental-born-v8-interruption-protocol-readonly-review-20261007-001/review.json'
ORIGINAL_PROTOCOL_REVIEW_SHA = 'e42c3cdd0cd7a07a06c2e7fe3dfc01c03e6061de44bad82975c19a2c3c1309a3'
ORIGINAL_FAILURE_TREE_REVIEW = ORIGINAL_PROTOCOL_REVIEW.with_name('candidate31-full-retained-tree-addendum.json')
ORIGINAL_FAILURE_TREE_REVIEW_SHA = '5800b9cdc99d542ae8181d81b11e6566232f8e06a710fd52d35794eba761c571'
ORIGINAL_INTERRUPTED_DIRECTORY_MODE = 0o700
PLAN_TYPE = 'qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v9'
CONTINUATION_PLAN_TYPE = 'qcsd-external-navigation-seeded-born-interruption-continuation-plan-v9'
INPUT_TYPE = 'qcsd-external-browser-whole-graph-input-v9'
CONTRACT = 'catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v9'
INTERRUPTION_TYPE = 'qcsd-retained-born-v8-interruption-and-pending-reservations-v1'
ZERO = {'scientific_credit': False, 'site_credit': 0, 'formal_accepted_trace_count': 0}
DAEMON = 'unix:///var/run/docker.sock'
OUTER = {'policy': 'declared-setup240-discovery180-cleanup30-outer450-kill15-v1',
         'setup_seconds': 240, 'discovery_seconds': 180, 'cleanup_seconds': 30,
         'term_seconds': 450, 'kill_after_seconds': 15, 'maximum_recorded_seconds': 470,
         'docker_host': DAEMON}


def read(path):
    return action_facts.current().read(path)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def reader():
    return action_facts.current().reader(ORIGINAL / 'graph_input.py', ORIGINAL_PAIR['graph_input.py'])


def reference(path):
    path = Path(path).absolute()
    raw = read(path)
    return {'path': str(path), 'sha256': sha(raw), 'mode': f'{stat.S_IMODE(path.stat().st_mode):04o}'}


def reopen(ref):
    if not isinstance(ref, dict) or set(ref) != {'path', 'sha256', 'mode'}:
        raise ValueError('exact source reference required')
    path = Path(ref['path']).absolute()
    raw = read(path)
    if reference(path) != ref:
        raise ValueError('source reference changed')
    return path, raw


def utc(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None or result.utcoffset() != timezone.utc.utcoffset(result):
        raise ValueError('UTC chronology required')
    return result


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def sources():
    return {name: reference(HERE / name) for name in ('graph_input.py', 'operator.py')}


def dependencies():
    return {name: reference(HERE / name) for name in ('action_facts.py', 'controller.py')}


def operation(prefix, expected_code, *, expected_command=None):
    prefix = Path(prefix)
    refs = {k: reference(Path(str(prefix) + suffix)) for k, suffix in (
        ('started', '-started.json'), ('completed', '-completed.json'),
        ('stdout', '.stdout.log'), ('stderr', '.stderr.log'))}
    start, end = (load(reopen(refs[k])[1]) for k in ('started', 'completed'))
    if (type(end.get('returncode')) is not int or end['returncode'] != expected_code
            or end['stdout_sha256'] != refs['stdout']['sha256']
            or end['stderr_sha256'] != refs['stderr']['sha256']
            or not utc(start['started_at']) <= utc(end['completed_at'])
            or expected_command is not None and start['command'] != expected_command):
        raise ValueError('actual terminal operation/raw/command differs')
    return refs, start, end


def tree(root):
    root = Path(root).absolute()
    action_facts.current().watch_tree(root)
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_file():
            result[str(path.relative_to(root))] = reference(path)
        if len(result) > 64:
            raise ValueError('retained interruption exceeds bounded file count')
    return {'root': str(root), 'membership_modes': action_facts.tree_state(root), 'files': result}


def partial(original_plan, original_root, actors_prefix):
    """Authenticate the actual born interruption; never generate failed.json."""
    old = reader()
    plan_path = Path(original_plan).absolute()
    if reference(plan_path)['sha256'] != ORIGINAL_INTERRUPTION_PLAN:
        raise ValueError('another original batch lacks this interruption authority')
    raw_plan = load(read(plan_path))
    action_facts.current().watch_tree(Path(raw_plan['source']['root']))
    plan = old.check_plan(plan_path)
    if plan['schema_version'] != 8 or len(plan['candidates']) != 5 or plan['producer_sources'] != {
            name: reference(ORIGINAL / name) for name in ORIGINAL_PAIR}:
        raise ValueError('the exact original five-reservation V8 plan is required')
    root = Path(original_root).absolute()
    action_facts.current().watch_tree(root)
    if reference(root / 'inputs.json')['sha256'] != ORIGINAL_INTERRUPTION_INPUTS:
        raise ValueError('another original controller action lacks this daemon attestation')
    inputs = load(read(root / 'inputs.json'))
    if (inputs['plan'] != reference(plan_path) or inputs['producer'] != reference(ORIGINAL / 'graph_input.py')
            or inputs['driver']['sha256'] != ORIGINAL_CONTROLLER
            or inputs['candidate_ids'] != [r['candidate_id'] for r in plan['candidates']]):
        raise ValueError('original Root controller, plan or reservations differ')
    if reference(inputs['driver']['path']) != inputs['driver']:
        raise ValueError('original controller bytes/full mode changed')
    controller = action_facts.current().reader(inputs['driver']['path'], ORIGINAL_CONTROLLER)
    authority = controller.authorities()
    if (inputs.get('producer_closure') != authority['closure']
            or inputs.get('producer_review') != authority['review']):
        raise ValueError('original reviewed producer authority differs')
    closed31_path = root / 'candidate-000001-closed.json'
    closed31 = load(read(closed31_path))
    first = root / 'attempts/candidate-000001'
    first_failure = load(read(first / 'failed.json'))
    first_start = load(read(first / 'started.json'))
    op31, begin31, end31 = operation(root / 'operations/candidate-000001-discover', 1)
    failed31 = controller.failed(old, plan, plan_path, first, plan['candidates'][0],
                                root / 'operations/candidate-000001-discover')
    if (closed31 != controller.closed_row(old, plan['candidates'][0], first, 1, failed31)
            or any(type(closed31.get(key)) is not int for key in
                   ('discovery_returncode', 'formal_credit', 'site_credit'))):
        raise ValueError('original31 typed failure was changed or promoted')
    second = root / 'attempts/candidate-000002'
    files32 = tree(second)
    required32 = {'started.json', 'image-source-metadata.json', 'navigation-started.json',
        'navigation-result.json', 'navigation-control.json', 'navigation-completed.json',
        'pass-01-started.json', 'pass-01-result.json', 'pass-01-completed.json', 'pass-02-started.json'}
    if set(files32['files']) != required32:
        raise ValueError('exact interrupted32 prefix membership is required')
    op32, begin32, end32 = operation(root / 'operations/candidate-000002-discover', -9)
    old_prefix = ['timeout', '--signal=TERM', '--kill-after=15s', '210s', 'docker', 'run']
    for start in (begin31, begin32):
        if start['command'][:6] != old_prefix or start['command'].count(plan['browser_image']) != 1:
            raise ValueError('original210/15 command was changed')
    if not 0 < end32['elapsed_seconds'] <= 230:
        raise ValueError('original210/15 actual bound differs')
    command32 = begin32['command']
    principal = command32[command32.index('--user') + 1]
    if not re.fullmatch('[1-9][0-9]*:[1-9][0-9]*', principal):
        raise ValueError('original unprivileged executor identity differs')
    uid, gid = map(int, principal.split(':'))
    render = FunctionType(controller.command.__code__, {**controller.command.__globals__,
        'os': SimpleNamespace(getuid=lambda: uid, getgid=lambda: gid)})
    prefix = command32[command32.index('--name') + 1].removesuffix('-002')
    if (begin31['command'] != render(old, plan, plan_path, root, 1, prefix)
            or command32 != render(old, plan, plan_path, root, 2, prefix)):
        raise ValueError('exact original physical argv differs')
    started32 = load(read(second / 'started.json'))
    metadata32 = read(second / 'image-source-metadata.json')
    runtime32 = old._retained_runtime(plan, metadata32)
    if (started32['plan'] != reference(plan_path) or started32['candidate'] != plan['candidates'][1]
            or started32['runtime'] != runtime32 or not old.zero_credit(started32)
            or load(metadata32) != load(old.reopen(plan['source_metadata'])[1])
            or not utc(end31['completed_at']) <= utc(begin32['started_at']) <= utc(started32['started_at'])
                < utc(end32['completed_at'])):
        raise ValueError('born32 identity/runtime/chronology differs')
    nav = {k: reference(second / ('navigation-' + k + '.json'))
           for k in ('started', 'result', 'control', 'completed')}
    old.verify_navigation(nav, second, plan['candidates'][1], runtime32,
        old._modules(Path(plan['source']['root'])), reference(plan_path), utc(started32['started_at']))
    pass1 = load(read(second / 'pass-01-completed.json'))
    if (pass1['started'] != reference(second / 'pass-01-started.json')
            or pass1['result'] != reference(second / 'pass-01-result.json')
            or pass1['successful_graph_input_pass'] is not True):
        raise ValueError('retained first pass closure differs')
    old.validate_discovery(load(read(second / 'pass-01-result.json')),
                           old._modules(Path(plan['source']['root'])))
    pass2 = load(read(second / 'pass-02-started.json'))
    if (pass2['ordinal'] != 2 or pass2['runtime'] != runtime32
            or pass2['source_url'] != plan['candidates'][1]['source_url']
            or not utc(pass1['completed_at']) <= utc(pass2['started_at']) <= utc(end32['completed_at'])):
        raise ValueError('interrupted second-pass birth differs')
    for local in (3, 4, 5):
        if ((root / 'attempts' / f'candidate-{local:06d}').exists()
                or (root / f'candidate-{local:06d}-closed.json').exists()
                or (root / 'operations' / f'candidate-{local:06d}-discover-started.json').exists()):
            raise ValueError('original33–35 must remain genuinely unassessed')
    if (root / 'batch-closed.json').exists():
        raise ValueError('a complete original batch conflicts with interruption recovery')
    actors, abegin, aend = operation(actors_prefix, 0, expected_command=[
        'docker', '--host', DAEMON, 'ps', '--format', '{{.ID}} {{.Names}}'])
    if (actors['started']['sha256'] != ORIGINAL_TERMINAL_OBSERVATION
            or read(actors['stdout']['path']).strip() or read(actors['stderr']['path']).strip()
            or not utc(end32['completed_at']) <= utc(abegin['started_at']) <= utc(aend['completed_at'])):
        raise ValueError('genuine post-interruption terminal actor absence required')
    report_ref = reference(ORIGINAL_PROTOCOL_REVIEW)
    if report_ref['sha256'] != ORIGINAL_PROTOCOL_REVIEW_SHA:
        raise ValueError('original immutable interruption observation changed')
    report = load(read(ORIGINAL_PROTOCOL_REVIEW))
    def reported(ref):
        if not isinstance(ref, dict) or set(ref) != {'path', 'sha256', 'mode', 'size'}:
            raise ValueError('original interruption observation has another reference shape')
        return {key: ref[key] for key in ('path', 'sha256', 'mode')}
    if (reference(closed31_path) != reported(report['candidate31_closure'])
            or files32['files'] != {name: reported(ref) for name, ref in
                report['candidate32']['retained_partial_files'].items()}
            or op31 != {name: reported(ref) for name, ref in report['actual_discover_operations']['1']['refs'].items()}
            or op32 != {name: reported(ref) for name, ref in report['actual_discover_operations']['2']['refs'].items()}):
        raise ValueError('previously observed failure, interrupted raw prefix or outer operation was resealed')
    first_tree_ref = reference(ORIGINAL_FAILURE_TREE_REVIEW)
    if first_tree_ref['sha256'] != ORIGINAL_FAILURE_TREE_REVIEW_SHA:
        raise ValueError('original failed-attempt tree observation changed')
    first_tree_report = load(read(ORIGINAL_FAILURE_TREE_REVIEW))
    files31 = tree(first)
    if (files31['root'] != first_tree_report['root']
            or files31['files'] != {name: reported(ref) for name, ref in first_tree_report['files'].items()}
            or files31['membership_modes'] != {name: [row['kind'], int(row['mode'], 8)]
                for name, row in first_tree_report['membership_full_modes'].items()}
            or files32['membership_modes'] != {'.': ['directory', ORIGINAL_INTERRUPTED_DIRECTORY_MODE],
                **{name: ['file', int(ref['mode'], 8)] for name, ref in files32['files'].items()}}):
        raise ValueError('original failed or interrupted tree bytes/membership/full modes changed')
    return {'schema_version': 1, 'artifact_type': INTERRUPTION_TYPE,
        'original_protocol_observation': report_ref,
        'original_failed_tree_observation': first_tree_ref,
        'original_plan': reference(plan_path), 'original_root_inputs': reference(root / 'inputs.json'),
        'original_candidates': deepcopy(plan['candidates']), 'original_root': str(root),
        'candidate31_closure': reference(closed31_path), 'candidate31_attempt': files31,
        'candidate31_operation': op31, 'candidate32_attempt': files32, 'candidate32_operation': op32,
        'candidate32_status': 'born-interrupted-no-typed-terminal-no-site-classification',
        'candidate33_35_status': 'reserved-unassessed-no-attempt', 'post_interruption_actor_observation': actors,
        'original_browser_daemon': DAEMON, 'same_browser_daemon_binding':
            'Root-attested-original-DOCKER_HOST-and-recorded-explicit-observation',
        'executor_uid_gid': principal,
        'original_batch_complete_claimed': False, 'prior_outcomes_reclassified': False,
        'new_catalogue_reservations': False, **ZERO}


def plan_value(original, retained, *, previous=None, batch=None, count=None, declared_at):
    old = reader()
    base = old.check_plan(reopen(original)[0])
    retained_value = load(reopen(retained)[1])
    if retained_value != partial(reopen(original)[0], retained_value['original_root'],
            Path(retained_value['post_interruption_actor_observation']['started']['path']).with_name(
                Path(retained_value['post_interruption_actor_observation']['started']['path']).name.removesuffix('-started.json'))):
        raise ValueError('retained interruption proof differs')
    prior = check_plan(reopen(previous)[0]) if previous else None
    if prior:
        verify_batch(reopen(batch)[0], prior)
        if prior['original_plan'] != original or prior['retained_interruption'] != retained:
            raise ValueError('new lineage changed its retained original reservations')
        receipt, catalogue = old._modules(Path(base['source']['root']))['class_catalogue'].load_candidate_catalogue_receipt(
            old.reopen(base['catalogue'])[0])
        candidates = old.select_candidates(catalogue, base['original_prefix']['domains'], [prior], count)
        reserved = old.reserved_candidates([prior])
        indices = list(range(1, len(candidates) + 1))
    else:
        candidates = deepcopy(base['candidates'][1:])
        reserved = old.reserved_candidates([base])
        indices = [2, 3, 4, 5]
    return {'schema_version': 9, 'artifact_type': PLAN_TYPE if prior else CONTINUATION_PLAN_TYPE,
        'contract': CONTRACT, 'declared_at': declared_at, 'original_plan': original,
        'retained_interruption': retained, 'previous_plan': previous, 'previous_batch': batch,
        'original_candidate_indices': indices, 'local_candidate_indices': list(range(1, len(candidates) + 1)),
        'candidates': candidates, 'reserved_candidates': reserved, 'producer_sources': sources(),
        'action_local_sources': dependencies(), 'outer_budget': deepcopy(OUTER),
        'executor_uid_gid': retained_value['executor_uid_gid'],
        **{k: deepcopy(base[k]) for k in ('source', 'source_metadata', 'browser_image', 'original_prefix',
            'catalogue', 'discovery_control', 'candidate_deadline_seconds', 'backend_navigation_timeout_ms',
            'max_origin_passes', 'max_approved_origins', 'passive_render_contract')}, **ZERO}


def check_plan(path):
    path = Path(path).absolute()
    raw = read(path)
    key = ('v9-plan', str(path), sha(raw), reference(path)['mode'], tuple(sorted((n, r['sha256']) for n,r in sources().items())))
    def build():
        value = load(raw)
        if (value.get('schema_version') != 9 or value.get('producer_sources') != sources()
                or value.get('action_local_sources') != dependencies() or value.get('outer_budget') != OUTER
                or value.get('candidate_deadline_seconds') != 180):
            raise ValueError('V9 reader/dependency/setup-aware budget differs')
        expected = plan_value(value['original_plan'], value['retained_interruption'],
            previous=value['previous_plan'], batch=value['previous_batch'],
            count=len(value['candidates']), declared_at=value['declared_at'])
        if value != expected:
            raise ValueError('V9 declaration changed history/reservations/mapping/provenance')
        action_facts.current().watch_tree(Path(value['source']['root']))
        action_facts.current().check()
        return value
    return action_facts.current().fact(key, build)


def declare(original_plan, original_root, actors_prefix, output):
    original = reference(original_plan)
    retained = partial(original_plan, original_root, actors_prefix)
    old = reader()
    action_facts.current().check()
    root = old.fresh_directory(Path(output), [Path(original_root), Path(original_plan).parent,
        HERE, Path(retained['original_plan']['path']).parent, Path(old.check_plan(Path(original_plan))['source']['root'])])
    ref = old.create_json(root / 'retained-interruption.json', retained)
    value = plan_value(original, ref, declared_at=now())
    old.create_json(root / 'plan.json', value)
    check_plan(root / 'plan.json')
    return root / 'plan.json'


def declare_next(previous_plan, previous_batch, count, output):
    previous = reference(previous_plan)
    prior = check_plan(reopen(previous)[0])
    batch = reference(previous_batch)
    verify_batch(reopen(batch)[0], prior)
    value = plan_value(prior['original_plan'], prior['retained_interruption'],
        previous=previous, batch=batch, count=count, declared_at=now())
    action_facts.current().check()
    root = reader().fresh_directory(Path(output), [HERE, Path(previous_plan).parent,
        Path(previous_batch).parent, *transport_roots(prior)])
    reader().create_json(root / 'plan.json', value)
    check_plan(root / 'plan.json')
    return root / 'plan.json'


def terminal_locals(error):
    """Observation only: fixed methods and exact opaque-ID digests, no payloads."""
    rows = []
    tb = error.__traceback__
    for _ in range(64):
        if tb is None:
            break
        frame = tb.tb_frame
        if frame.f_code.co_name == '_handle_forwarded':
            values = frame.f_locals
            method, event, source = values.get('method'), values.get('event'), values.get('source')
            if method in ('Network.loadingFinished', 'Network.loadingFailed') and isinstance(event, dict):
                def digest(value):
                    return sha(value.encode()) if isinstance(value, str) and 0 < len(value) <= 256 else None
                request = event.get('requestId')
                session = getattr(source, 'session_path', None)
                rows.append({'method': method, 'request_id_sha256': digest(request),
                    'session_path_sha256': sha(json.dumps(session).encode())
                        if isinstance(session, tuple) and len(session) <= 8 and all(isinstance(s,str) and len(s)<=256 for s in session) else None,
                    'active_occurrence_absent': values.get('active', object()) is None})
                if len(rows) == 4:
                    break
        tb = tb.tb_next
    return {'schema_version': 1, 'policy': 'failure-only-bounded-terminal-traceback-locals-v1', 'terminal_events': rows}


def protocol_function(name):
    """Change only the literal version and explicit new identity/fence bindings."""
    old = reader()
    module = ast.parse(read(ORIGINAL / 'graph_input.py'))
    function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name)
    constants = [n for n in ast.walk(function) if isinstance(n, ast.Constant) and type(n.value) is int and n.value == 8]
    if len(constants) != 1:
        raise ValueError('original discover/verify protocol literal projection changed')
    constants[0].value = 9
    namespace = dict(old.__dict__)
    namespace.update(INPUT_TYPE=INPUT_TYPE, CONTRACT=CONTRACT, check_plan=check_plan,
        transport_roots=transport_roots,
        __name__=__name__, __file__=str(HERE / 'graph_input.py'))
    namespace['_modules'] = old._modules
    namespace['actual_runtime'] = lambda p,m: {**old.actual_runtime(p,m),
        'execution_role': 'actual-browser-image-navigation-seeded-graph-input-only-v9'}
    original_create, original_fresh = old.create_json, old.fresh_directory
    def create(path, value):
        if Path(path).name in ('whole-graph-input.json', 'failed.json'):
            action_facts.current().check()
        return original_create(path, value)
    def fresh(path, protected):
        action_facts.current().check()
        return original_fresh(path, protected)
    namespace.update(create_json=create, fresh_directory=fresh)
    def evidence(error):
        original = old.exception_evidence(error)['exception_evidence']
        combined = {'original_exception_evidence': original, 'terminal_traceback_locals': terminal_locals(error)}
        return {'exception_evidence': combined, 'exception_evidence_sha256': sha(old.canonical(combined))}
    namespace['exception_evidence'] = evidence
    if name == 'discover':
        # Close all transitive immutable inputs immediately before original
        # backend construction/browser effects, retaining its exact180s timer.
        trial = next(n for n in function.body if isinstance(n, ast.Try))
        trial.body.insert(0, ast.Expr(ast.Call(ast.Attribute(ast.Call(ast.Name('current_facts',ast.Load()),[],[]),'check',ast.Load()),[],[])))
        namespace['current_facts'] = action_facts.current
    tree_ast = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(tree_ast, str(HERE / 'graph_input.py') + ':' + name, 'exec'), namespace)
    return namespace[name]


def discover(plan_path, index, output):
    setup = time.monotonic()
    check_plan(plan_path)
    if time.monotonic() - setup > OUTER['setup_seconds']:
        raise ValueError('declared setup bound expired before attempt birth')
    return protocol_function('discover')(Path(plan_path), index, Path(output))


def verify_input(path):
    return protocol_function('verify_input')(Path(path))


def transport_roots(plan):
    base = reader().check_plan(reopen(plan['original_plan'])[0])
    roots = set(reader().transport_roots(base)) | {HERE, ORIGINAL_PROTOCOL_REVIEW.parent,
        ORIGINAL.parent / 'supplemental-generic-v8-root-controller-authoring-20261006-001'}
    for ref in (plan['original_plan'], plan['retained_interruption'], plan['previous_plan'], plan['previous_batch']):
        if ref is not None:
            roots.add(reopen(ref)[0].parent)
    retained = load(reopen(plan['retained_interruption'])[1])
    roots |= {Path(retained['original_root']),
              Path(retained['post_interruption_actor_observation']['started']['path']).parent}
    return sorted(p for p in roots if not any(p != q and p.is_relative_to(q) for q in roots))


def verify_batch(path, plan):
    # Implemented by the independently bound controller, with exact prospective
    # timeout argv, every terminal attempt/raw proof and before/after observations.
    import controller
    return controller.verify_batch(Path(path), plan)
