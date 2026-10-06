"""Prospective fixed conditions, independent of the retained-history numerator.

Declarations never grant trace credit. Only original installed/deep-verified
formal rows may enter this target, with their Source labels and raw dependencies
retained. The old epoch reader's SCI anchor and old chunk policy remain exact.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextvars import ContextVar
from functools import wraps
import hashlib
import json
from pathlib import Path
import re
import sys

from . import rapid_epoch_corpus as epoch
from . import rapid_chunk_partial_lane as dynamic
from . import rapid_partial_progress as membership
from . import rapid_slot_chunks as chunks
from . import tamaraw_fixed_configuration as tam
from . import rapid_per_class_selected_enrollment as budgets
from . import buflo_duration_budget as duration
from . import rapid_capture_traffic as traffic
from .rapid_operation_facts import OperationFacts, current_context

TARGET_TYPE = 'qcsd-prospective-fifty-site-five-fixed-condition-target-v1'
PROGRESS_TYPE = 'qcsd-original-verified-fixed-condition-slot-progress-v1'
AUDIT_TYPE = 'qcsd-fixed-condition-original-lane-trace-audit-v1'
CONDITION_TYPE = 'qcsd-declared-full-fixed-condition-identity-v1'
CHUNK_INPUT_TYPE = 'qcsd-fixed-condition-remaining-slot-planning-input-v1'
CORPUS_TYPE = 'qcsd-exact-fifty-site-five-fixed-condition-sixty-four-slot-corpus-v1'
CONTRACT = 'exact-fixed-conditions-original-graphs-and-16000-independent-slots-v1'
MODES = ('undefended', 'front', 'tamaraw', 'buflo', 'cs-buflo')
CLASSES, SLOTS, TOTAL = 50, 64, 16000
SHA = re.compile(r'[0-9a-f]{64}\Z')
HEAD = re.compile(r'[0-9a-f]{40}\Z')
from .capture_acceptance_policy import (FIELD as BUFLO_FIELD, BUFLO_KERNEL_PREPARATION_FIELD,
    TAMARAW_FIELD, TERMINAL_PRIMARY_FIELD, FRONT_FIELD)
POLICY_FIELDS = (TAMARAW_FIELD, TERMINAL_PRIMARY_FIELD, FRONT_FIELD,
                 BUFLO_FIELD, BUFLO_KERNEL_PREPARATION_FIELD)
_OBSERVATIONS = ContextVar('qcsd_fixed_condition_target_observations',default=None)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(label + ' has missing or unknown fields')


def _owned(function):
    @wraps(function)
    def run(*args, **kwargs):
        context = current_context()
        if context is None:
            context = OperationFacts(); context.begin_action()
        state=_OBSERVATIONS.get();token=None
        if state is None or state['context'] is not context:
            token=_OBSERVATIONS.set({'context':context,'directories':{}})
        try:
            with context.scope():
                answer = function(*args, **kwargs)
                _check_action()
                return answer
        finally:
            if token is not None:_OBSERVATIONS.reset(token)
    return run


def _check_action():
    state=_OBSERVATIONS.get()
    if state is not None:
        for path,declared in state['directories'].items():
            if epoch._directory(Path(path))!=declared:
                raise ValueError('fixed target raw directory membership or mode changed during action')
    if current_context() is not None:current_context().check()


def reference(path):
    path = epoch._path(path)
    context = current_context(); key = ('fixed-target-file', str(path))
    if context is not None and context.has(key): return context.get(key)
    raw = context.watch_file(path) if context is not None else path.read_bytes()
    value = {'path':str(path), 'sha256':hashlib.sha256(raw).hexdigest(), 'mode':path.stat().st_mode & 0o7777}
    if context is not None: context.remember(key, value)
    return value


def _open(value):
    _keys(value, {'path','sha256','mode'}, 'fixed target reference')
    if (type(value['mode']) is not int or not 0 <= value['mode'] <= 0o7777
            or not isinstance(value['sha256'], str) or SHA.fullmatch(value['sha256']) is None):
        raise ValueError('fixed target reference bytes or mode schema differs')
    if reference(value['path']) != value:
        raise ValueError('fixed target reference bytes or mode changed')
    return Path(value['path'])


def _document(value, role):
    _open(value)
    context = current_context(); key = ('fixed-target-document', value['path'], value['sha256'], value['mode'], role)
    if context is not None and context.has(key): return context.get(key)
    result = epoch._document(value, role)
    if context is not None: context.remember(key, result)
    return result


def _time(value):
    if not isinstance(value,str): raise ValueError('fixed target timestamp has another type')
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
        raise ValueError('fixed target timestamp must be explicit UTC')
    return stamp


def _identity(value):
    _keys(value, {'namespace','conditions','native_head','client_sha256','classes','slots','total'}, 'fixed target identity')
    _keys(value['conditions'], MODES, 'fixed condition identity hashes')
    if (not isinstance(value['namespace'],str) or re.fullmatch(r'[a-z0-9][a-z0-9-]{1,95}',value['namespace']) is None
            or not isinstance(value['native_head'],str) or HEAD.fullmatch(value['native_head']) is None
            or not isinstance(value['client_sha256'],str) or SHA.fullmatch(value['client_sha256']) is None
            or any(not isinstance(v,str) or SHA.fullmatch(v) is None for v in value['conditions'].values())
            or any(type(value[k]) is not int or value[k]!=n for k,n in (('classes',CLASSES),('slots',SLOTS),('total',TOTAL)))):
        raise ValueError('fixed target identity is not the declared50×5×64 Native/client condition')
    return value


def _sources():
    from . import rapid_operation_facts as facts, capture_acceptance_policy as acceptance
    from . import application_response_policy as application
    from . import rapid_target_overlay_source as overlay
    return {name:reference(path) for name,path in {
        'target':Path(__file__), 'epoch':Path(epoch.__file__), 'dynamic':Path(dynamic.__file__),
        'membership':Path(membership.__file__), 'chunks':Path(chunks.__file__), 'tamaraw':Path(tam.__file__),
        'facts':Path(facts.__file__), 'acceptance':Path(acceptance.__file__), 'application':Path(application.__file__),
        'budgets':Path(budgets.__file__),
        'duration':Path(duration.__file__), 'traffic':Path(traffic.__file__),
        'overlay':Path(overlay.__file__),
    }.items()}


def _compatible_sources(producer):
    """Authenticate retained authority and identical relevant executing code.

    A path relocation or unrelated release metadata is not a traffic change.
    The retained epoch module also binds the unchanged original deep program.
    This never imports a producer to decide its own trust.
    """
    current = _sources()
    _keys(producer, set(current), 'fixed target producer/reader Source units')
    for name, expected in current.items():
        _open(producer[name]); _open(expected)
        if any(producer[name][key] != expected[key] for key in ('sha256', 'mode')):
            raise ValueError('fixed target relevant producer/reader code bytes or modes differ')
    return True


def _compatible_membership(producer, current, producer_sources):
    """Only equivalent code locations can differ in the membership read set."""
    _compatible_sources(producer_sources)
    _membership_close(producer)
    old_root = Path(producer_sources['target']['path']).parents[2]
    new_root = Path(__file__).resolve().parents[2]
    def normalized(value, root):
        result = json.loads(_json(value))
        for row in result['files']:
            path = Path(row['path'])
            if path.is_relative_to(root):
                relative = path.relative_to(root)
                if (relative.suffix == '.py' and (relative.is_relative_to('src/qcsd_lab')
                        or relative.is_relative_to('tools'))):
                    row['path'] = 'identical-bound-code/' + relative.as_posix()
        result['files'].sort(key=lambda row: row['path'])
        result['trees'].sort(key=lambda row: (row['path'], row['ignore_git']))
        return result
    return _typed_equal(normalized(producer, old_root), normalized(current, new_root))


def _close(files, directories=()):
    for value in files: _open(value)
    for value in directories:
        _keys(value, {'path','mode','members'}, 'fixed target directory observation')
        state=_OBSERVATIONS.get()
        if state is not None:
            previous=state['directories'].get(value['path'])
            if previous is not None and previous!=value:
                raise ValueError('fixed target directory was redefined within one action')
            state['directories'][value['path']]=value
        if epoch._directory(Path(value['path'])) != value:
            raise ValueError('fixed target raw dependency membership or mode changed')
    if current_context() is not None: current_context().check()


def _write(output, kind, payload, files=(), directories=()):
    output = Path(output).absolute()
    _close(files, directories)
    source_roots={Path(__file__).absolute().parents[2]}
    for row in files:
        path=Path(row['path'])
        if path.as_posix().endswith('/src/qcsd_lab/rapid_rolling_capture.py'):source_roots.add(path.parents[2])
    if any(output.is_relative_to(root) for root in source_roots):
        raise ValueError('target publication cannot enter executing or measured Source')
    if any(output == Path(r['path']) or output.is_relative_to(Path(r['path']).parent)
           for r in files if r['path'].endswith(('/run.json','/experiment.json','/evidence.sha256'))):
        raise ValueError('target publication cannot enter original measurement evidence')
    _check_action()
    return epoch._write(output, kind, payload)


def _typed_equal(left, right):
    if type(left) is not type(right): return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(_typed_equal(left[k],right[k]) for k in left)
    if isinstance(left, list):
        return len(left)==len(right) and all(_typed_equal(a,b) for a,b in zip(left,right))
    return left == right


def _capture_limits(mode, original, condition):
    """Retain admission caps; derive only the declared exact BuFLO200 setting."""
    limits = budgets.valid_limits(original)
    if mode not in MODES or condition.get('mode') != mode:
        raise ValueError('fixed target caps require their own declared mode')
    defense = condition['defense']; parameter = condition['defense_parameters']
    selected = None
    if mode == 'buflo' and (defense.get('parameters_sha256') == duration.PARAMETER_SHA256
            or isinstance(parameter, dict) and duration.RUN_FIELD in parameter):
        resolved = condition['resolved_configuration']
        if (defense.get('kind') != 'buflo'
                or defense.get('parameters_sha256') != duration.PARAMETER_SHA256
                or defense.get('provenance_sha256') != traffic.PROVENANCE_SHA256
                or not isinstance(parameter, dict) or parameter.get('kind') != 'buflo'
                or parameter.get('sha256') != duration.PARAMETER_SHA256
                or parameter.get('implementation_scope') != 'client_only_quic'
                or parameter.get('paper_equivalent') is not False
                or not isinstance(resolved, dict) or resolved.get('defense', {}).get('kind') != 'buflo'
                or not _typed_equal(resolved['defense'].get('parameters'), {'sha256': duration.PARAMETER_SHA256})):
            raise ValueError('fixed target duration caps lack the exact BuFLO200 parameter/provenance identity')
        duration.validate_receipt(parameter.get(duration.RUN_FIELD))
        selected = duration.POLICY
    return duration.capture_limits(mode, limits, policy=selected)


def _membership(enrollment):
    """Collect the existing typed membership selector's own exact raw read set."""
    outer=current_context();key=('fixed-target-membership',enrollment['path'],enrollment['sha256'],enrollment['mode'])
    if outer is not None and outer.has(key): return outer.get(key)
    collector=OperationFacts();collector.begin_action()
    with collector.scope():
        collector.watch_file(Path(__file__))
        collector.watch_file(Path(membership.__file__))
        collector._enrollment(_open(enrollment))
        rows=membership._class_rows(enrollment)
        collector.check()
    dependencies={'files':[{'path':str(path),**observation} for path,observation in sorted(collector._files.items())],
        'trees':[{'path':str(path),'ignore_git':ignore_git,'members':members}
                 for (path,ignore_git),members in sorted(collector._trees.items())]}
    if outer is not None:
        for path,observation in collector._files.items():
            if path in outer._files and outer._files[path]!=observation:
                raise ValueError('fixed target membership alias changed')
            outer._files[path]=observation
        for tree,observation in collector._trees.items():
            if tree in outer._trees and outer._trees[tree]!=observation:
                raise ValueError('fixed target membership tree alias changed')
            outer._trees[tree]=observation
        outer.remember(key,(rows,dependencies))
    return rows,dependencies


def _membership_close(dependencies):
    _keys(dependencies, {'files','trees'}, 'fixed target membership dependencies')
    _close(dependencies['files'])
    from .rapid_operation_facts import _tree
    for row in dependencies['trees']:
        _keys(row, {'path','ignore_git','members'}, 'fixed target membership tree')
        if type(row['ignore_git']) is not bool: raise ValueError('membership tree selector type differs')
        path=epoch._path(row['path'],directory=True);context=current_context()
        observed=context.watch_tree(path,ignore_git=row['ignore_git']) if context is not None else _tree(path,ignore_git=row['ignore_git'])
        if observed!=row['members']: raise ValueError('fixed target membership raw tree changed')


def condition_identity(configuration, run, mode):
    """Bind values, not output locations or per-visit random/sample identities."""
    if (mode not in MODES or configuration.get('profile') != 'research-1200'
            or configuration.get('request_policies') != ['as-defined']
            or not isinstance(configuration.get('defenses'), list) or len(configuration['defenses']) != 1):
        raise ValueError('fixed condition requires its exact singleton research setting')
    defense = dict(configuration['defenses'][0])
    if (defense.get('name') != mode or type(defense.get('baseline')) is not bool
            or defense['baseline'] != (mode == 'undefended') or 'schedule' in defense):
        raise ValueError('fixed condition changed its mode, baseline or external schedule')
    # Original full parameter and provenance hashes remain. Relocated frozen
    # paths are not a traffic value; removing them requires their exact digests.
    for path_key, hash_key in (('parameters','parameters_sha256'), ('provenance','provenance_sha256')):
        if path_key in defense:
            if not isinstance(defense.get(hash_key),str) or SHA.fullmatch(defense[hash_key]) is None:
                raise ValueError('fixed condition lost its exact parameter provenance digest')
            defense.pop(path_key)
    resolved = run.get('resolved_configuration')
    if mode != 'undefended':
        if not isinstance(resolved,dict) or set(resolved) != set(tam.resolved_configuration()):
            raise ValueError('fixed condition lacks the full resolved Native configuration')
        if not isinstance(resolved.get('defense'),dict) or not resolved['defense']:
            raise ValueError('fixed condition lacks its complete Native defense')
        if any(type(resolved[key]) is not type(default) or
               type(default) is int and resolved[key]<0
               for key,default in tam.resolved_configuration().items() if key!='defense'):
            raise ValueError('fixed condition Native configuration has a malformed integer/Boolean field')
        resolved = json.loads(_json(resolved))
        if 'parameters' in resolved['defense']:
            digest = defense.get('parameters_sha256')
            if not isinstance(digest,str) or SHA.fullmatch(digest) is None:
                raise ValueError('fixed condition parameter path lacks its frozen digest')
            resolved['defense']['parameters'] = {'sha256':digest}
    elif resolved is not None:
        if (not isinstance(resolved, dict) or set(resolved) != set(tam.resolved_configuration())
                or resolved.get('schema_version') != 2
                or resolved.get('defense') != {'kind': 'none'}
                or any(type(resolved[key]) is not type(default) or
                       type(default) is int and resolved[key] < 0
                       for key, default in tam.resolved_configuration().items() if key != 'defense')):
            raise ValueError('ordinary fixed condition has a defended or malformed Native configuration')
        resolved = json.loads(_json(resolved))
    from .application_response_policy import (application_body_identity_policy,
        HTTP_2XX_ONLY_POLICY, COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY, VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
    body_policy=application_body_identity_policy(configuration)
    if (run.get('application_response_policy') not in (HTTP_2XX_ONLY_POLICY,COMPLETED_TERMINAL_HTTP_ERRORS_POLICY)
            or run.get('primary_document_identity_policy') not in
                (EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY,VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)):
        raise ValueError('fixed condition lacks its closed original full-graph/primary acceptance policies')
    selected = tam.policy(configuration)
    if mode == 'tamaraw':
        if selected != tam.POLICY: raise ValueError('this target requires the prospective8192 Tamaraw condition')
        tam.validate_run(run, selected_policy=selected)
        from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
        if configuration.get('application_body_identity_policy') != COMPLETE_APPLICATION_DELIVERY_POLICY:
            raise ValueError('fixed8192 target requires complete current application delivery')
        if ('qualification_delivery_compatibility' in configuration
                or configuration.get('tamaraw_configuration_sha256')!=tam.configuration_sha256()):
            raise ValueError('fixed8192 target cannot inherit an old qualification witness or another frozen configuration')
    elif selected is not None:
        raise ValueError('another setting cannot carry the fixed Tamaraw marker')
    provenance=run.get('defense_parameters')
    if provenance is not None:
        if (not isinstance(provenance,dict) or not isinstance(provenance.get('sha256'),str)
                or SHA.fullmatch(provenance['sha256']) is None or provenance['sha256']!=defense.get('parameters_sha256')):
            raise ValueError('fixed condition Native parameters differ from the exact frozen parameter bytes')
        provenance=dict(provenance)
        if 'path' in provenance: provenance.pop('path')
    value = {'mode':mode, 'profile':configuration['profile'], 'request_policy':'as-defined',
        'defense':defense, 'resolved_configuration':resolved,
        'defense_parameters':provenance,
        'application_body_identity_policy':body_policy,
        'application_response_policy':run.get('application_response_policy'),
        'primary_document_identity_policy':run.get('primary_document_identity_policy'),
        'capture_policies':{k:run[k] for k in POLICY_FIELDS if k in run},
        'tamaraw_configuration_policy':selected}
    # Force a total finite JSON representation; no wildcard, missing mode or
    # ignored field is used when comparing original measurements.
    _json(value)
    return value


@_owned
def describe_condition(configuration_ref, run_ref, mode, output):
    configuration = json.loads(_open(configuration_ref).read_bytes())
    if 'configuration' in configuration: configuration = configuration['configuration']
    run = json.loads(_open(run_ref).read_bytes())
    value = condition_identity(configuration, run, mode)
    return _write(output, CONDITION_TYPE, {'identity':value, 'identity_sha256':_digest(value),
        'configuration':configuration_ref, 'run':run_ref, 'scientific_credit':False}, [configuration_ref,run_ref])


def _conditions(refs):
    _keys(refs, MODES, 'five fixed conditions')
    result = {}
    for mode in MODES:
        value = _document(refs[mode], CONDITION_TYPE)
        _keys(value, {'identity','identity_sha256','configuration','run','scientific_credit'}, 'declared condition')
        configuration = json.loads(_open(value['configuration']).read_bytes())
        if 'configuration' in configuration: configuration = configuration['configuration']
        run = json.loads(_open(value['run']).read_bytes())
        actual = condition_identity(configuration,run,mode)
        if (value['scientific_credit'] is not False or not _typed_equal(value['identity'],actual)
                or value['identity_sha256'] != _digest(actual)):
            raise ValueError('fixed condition descriptor differs from its complete original values')
        result[mode] = {'reference':refs[mode], 'identity':actual, 'identity_sha256':_digest(actual)}
    return result


def _classes(enrollment_ref):
    rows,dependencies = _membership(enrollment_ref)
    if (not 1 <= len(rows) <= CLASSES or [r['class_index'] for r in rows] != list(range(1,len(rows)+1))
            or any(type(r['class_index']) is not int for r in rows)
            or len({r['candidate_id'] for r in rows}) != len(rows)
            or len({r['workload_id'] for r in rows}) != len(rows)):
        raise ValueError('fixed target changed its append-only admitted class indices')
    for row in rows:
        budgets.valid_limits(row['capture_limits'])
        _open(row['original_manifest'])
        if membership.graph_identity(Path(row['original_manifest']['path'])) != row['original_graph_sha256']:
            raise ValueError('fixed target changed an original full resource graph')
    epoch._classes(rows,final=False)
    return rows,dependencies


@_owned
def publish_target(*, namespace, enrollment, conditions, native_head, client_sha256,
                   history, output, parent=None):
    if (not isinstance(namespace,str) or re.fullmatch(r'[a-z0-9][a-z0-9-]{1,95}',namespace) is None
            or not isinstance(native_head,str) or HEAD.fullmatch(native_head) is None
            or not isinstance(client_sha256,str) or SHA.fullmatch(client_sha256) is None):
        raise ValueError('fixed target needs explicit namespace/Native/client identities')
    declarations = _conditions(conditions); rows,dependencies = _classes(enrollment)
    if not isinstance(history,list): raise ValueError('retained history must be an explicit audit-only list')
    for ref in history: _open(ref)
    identity = {'namespace':namespace,'conditions':{k:v['identity_sha256'] for k,v in declarations.items()},
                'native_head':native_head,'client_sha256':client_sha256,'classes':CLASSES,'slots':SLOTS,'total':TOTAL}
    _identity(identity)
    declared = datetime.now(timezone.utc).isoformat()
    if parent is not None:
        old = validate_target(parent)
        if (identity != old['target_identity'] or rows[:len(old['classes'])] != old['classes']
                or len(rows) <= len(old['classes']) or history[:len(old['retained_history'])] != old['retained_history']):
            raise ValueError('target extension relabels a condition, class, graph, caps or history')
        declared = old['declared_at']
    value = {'contract':CONTRACT,'target_identity':identity,'target_id':_digest(identity),
        'enrollment':enrollment,'classes':rows,'membership_dependencies':dependencies,'conditions':declarations,'retained_history':history,
        'history_counts_as_target_credit':False,'parent':parent,'declared_at':declared,
        'published_at':datetime.now(timezone.utc).isoformat(),'sources':_sources(),'scientific_credit':False}
    _membership_close(dependencies)
    return _write(output,TARGET_TYPE,value,list(value['sources'].values())+[enrollment,*history])


@_owned
def validate_target(ref, _seen=None):
    context=current_context();key=('fixed-target-validated',_digest(ref))
    if context.has(key):return context.get(key)
    seen=set() if _seen is None else _seen
    if ref['path'] in seen: raise ValueError('fixed target ancestry is cyclic')
    seen.add(ref['path']);value=_document(ref,TARGET_TYPE)
    _keys(value,{'contract','target_identity','target_id','enrollment','classes','membership_dependencies','conditions','retained_history',
        'history_counts_as_target_credit','parent','declared_at','published_at','sources','scientific_credit'},'fixed target')
    rows,dependencies=_classes(value['enrollment']);declarations=_conditions({k:r['reference'] for k,r in value['conditions'].items()})
    identity=_identity(value['target_identity'])
    if (value['contract']!=CONTRACT or value['scientific_credit'] is not False
            or value['history_counts_as_target_credit'] is not False or not _compatible_sources(value['sources'])
            or value['classes']!=rows or not _compatible_membership(value['membership_dependencies'],dependencies,value['sources']) or not _typed_equal(value['conditions'],declarations)
            or value['target_id']!=_digest(identity) or identity['classes']!=CLASSES or identity['slots']!=SLOTS
            or identity['total']!=TOTAL or identity['conditions']!={k:r['identity_sha256'] for k,r in declarations.items()}
            or not _time(value['declared_at'])<=_time(value['published_at'])<=datetime.now(timezone.utc)):
        raise ValueError('fixed target authority, conditions or admitted full graphs changed')
    _membership_close(dependencies)
    if not isinstance(value['retained_history'],list): raise ValueError('fixed target history has another schema')
    for history in value['retained_history']: _open(history)
    if value['parent'] is not None:
        old=validate_target(value['parent'],seen)
        if (identity!=old['target_identity'] or value['declared_at']!=old['declared_at']
                or rows[:len(old['classes'])]!=old['classes'] or len(rows)<=len(old['classes'])
                or value['retained_history'][:len(old['retained_history'])]!=old['retained_history']
                or _time(value['published_at'])<_time(old['published_at'])):
            raise ValueError('target extension replaced an original class or fixed condition')
    context.remember(key,value)
    return value


def _measurement_source(source_binding):
    from . import rapid_target_overlay_source as overlay
    raw=json.loads(_open(source_binding).read_bytes())
    if raw.get('artifact_type')==overlay.SOURCE_TYPE:
        return overlay._source(source_binding)
    # The existing installed-equality reader retains its closed default schema.
    return dynamic._source(source_binding)


def _complete_dependencies(source, source_binding, report, operation):
    if 'overlay_registration' in source:
        from . import rapid_target_overlay_source as overlay
        return overlay.input_closure(source,source_binding,report,operation)
    return dynamic._input_closure(source,source_binding,report,operation)


def _complete_operation(source_binding, operation):
    _keys(operation, {'started','completed','interpreter'}, 'target complete proof operation')
    _keys(operation['interpreter'], {'command','binary'}, 'target original interpreter')
    _open(operation['interpreter']['binary'])
    interpreter=operation['interpreter']['command']
    if not isinstance(interpreter,str) or not Path(interpreter).is_absolute():
        raise ValueError('target proof interpreter is not an original absolute command')
    if reference(Path(interpreter).resolve(strict=True))!=operation['interpreter']['binary']:
        raise ValueError('target original interpreter command differs from its bound binary bytes or mode')
    source=_measurement_source(source_binding)
    start=json.loads(_open(operation['started']).read_bytes());end=json.loads(_open(operation['completed']).read_bytes())
    _keys(start,{'command','request','started_at'},'target original proof start')
    if (set(end)!=set(start)|{'completed_at','returncode','stdout','stderr'}
            or any(end[k]!=v for k,v in start.items()) or type(end['returncode']) is not int or end['returncode']!=0
            or start['command']!=[interpreter,'-I','-B','-c',epoch._PROGRAM]
            or set(start['request'])!={'source_root','enrollment','closures'}
            or start['request']['source_root']!=source['root'] or start['request']['enrollment'] is not None
            or not isinstance(start['request']['closures'],list) or not start['request']['closures']
            or not _time(start['started_at'])<=_time(end['completed_at'])<=datetime.now(timezone.utc)):
        raise ValueError('target original complete-lane proof operation changed')
    report=json.loads(_open(end['stdout']).read_bytes());_open(end['stderr'])
    if report.get('read_only') is not True or report.get('membership') is not None:
        raise ValueError('target original complete proof changed its read-only role')
    if [r['closure'] for r in report['lanes']]!=start['request']['closures']:
        raise ValueError('target complete proof substituted an original lane')
    _close(report['read_dependencies'],report['directory_dependencies'])
    return source,report,end['completed_at']


def _dependency_union(*groups):
    files={};directories={}
    for group in groups:
        for row in group['read_dependencies']:
            if row['path'] in files and files[row['path']]!=row:
                raise ValueError('target original raw reference aliases disagree')
            files[row['path']]=row
        for row in group['directory_dependencies']:
            if row['path'] in directories and directories[row['path']]!=row:
                raise ValueError('target original directory aliases disagree')
            directories[row['path']]=row
    result={'read_dependencies':[files[k] for k in sorted(files)],
            'directory_dependencies':[directories[k] for k in sorted(directories)]}
    _close(result['read_dependencies'],result['directory_dependencies'])
    return result


def _run_rows(source, report):
    identity=source['binding']['runtime_identity'];rows=[]
    observed={r['path']:r for r in report['read_dependencies']}
    for lane in report['lanes']:
        if 'overlay_registration' in source:
            from . import rapid_target_overlay_source as overlay
            overlay.validate_lane(source,lane)
        if (lane['measurement_source']!={**identity['source'],'image_digest':identity['collection_image_digest']}
                or lane['spec']['collection_image_digest']!=identity['collection_image_digest']
                or lane['spec']['module_root']!=source['root']
                or reference(lane['spec']['client_binary'])['sha256']!=identity['client_sha256']):
            raise ValueError('target lane differs from its trusted actual installed measurement release')
        root=epoch._path(lane['facts']['result_root'],directory=True)
        experiment_ref=reference(root/'experiment.json')
        if observed.get(experiment_ref['path'])!=experiment_ref:
            raise ValueError('target lane lost its original deep-observed experiment')
        experiment=json.loads(_open(experiment_ref).read_bytes())
        samples={r['sample_id']:r for r in experiment['samples']}
        intent_ref=reference(Path(lane['receipt']['path']).parent/'intent.json')
        if observed.get(intent_ref['path'])!=intent_ref: raise ValueError('target lane lost its original owned intent')
        intent=json.loads(_open(intent_ref).read_bytes())['payload']
        for slot in lane['samples']:
            sample=samples.get(slot['sample_id'])
            if sample is None or sample['state']!='accepted' or sample['eligible'] is not True:
                raise ValueError('target lane promoted a nonaccepted original sample')
            from .verification import resolved_sample_directory
            run_ref=reference(resolved_sample_directory(root,sample)/'neqo/run.json')
            if observed.get(run_ref['path'])!=run_ref:
                raise ValueError('target lane lacks its full original deep-observed Native run')
            run=json.loads(_open(run_ref).read_bytes())
            rows.append({**slot,'logical_visit':slot['visit'],'result_root':str(root),'run':run_ref,
                'condition':condition_identity(lane['configuration'],run,lane['mode']),
                'capture_limits':lane['configuration']['limits'],'intent_started_at':intent['started_at'],
                'measurement_source':lane['measurement_source'],'client_sha256':identity['client_sha256'],
                'source_binding':source['binding_reference'],'lane_closure':lane['closure']})
    return rows


@_owned
def audit_complete(*, source_binding, closures, audit_root, output):
    source=_measurement_source(source_binding);source['binding_reference']=source_binding
    if not isinstance(closures,list) or not closures or len({_digest(r) for r in closures})!=len(closures):
        raise ValueError('target complete audit requires distinct actual lane closures')
    for ref in closures: _open(ref)
    protected=[Path(source['root'])]
    for ref in closures:
        payload=json.loads(_open(ref).read_bytes())['payload']
        protected.extend([Path(ref['path']).parent,Path(payload['facts']['result_root'])])
    audit=Path(audit_root).absolute()
    if any(audit.is_relative_to(p) or p.is_relative_to(audit) for p in protected):
        raise ValueError('target original complete proof requires a disjoint fresh audit namespace')
    interpreter={'command':sys.executable,'binary':reference(Path(sys.executable).resolve())}
    operation=epoch._run_epoch(source,None,closures,audit)
    refs={'started':operation['started'],'completed':operation['completed'],'interpreter':interpreter}
    reopened,report,completed=_complete_operation(source_binding,refs)
    reopened['binding_reference']=source_binding
    rows=_run_rows(reopened,report)
    dependencies=_complete_dependencies(reopened,source_binding,report,
        {'started':refs['started'],'completed':refs['completed'],'interpreter':interpreter['binary']})
    dependencies=_dependency_union(dependencies)
    return _write(output,AUDIT_TYPE,{'kind':'complete','source_binding':source_binding,'operation':refs,
        'rows':rows,**dependencies,
        'completed_at':completed,'sources':_sources(),'scientific_credit':False},
        dependencies['read_dependencies'],dependencies['directory_dependencies'])


def _partial_operation(operation):
    _keys(operation, {'receipt','verification'}, 'target incomplete-lane proof')
    receipt=operation['receipt'];raw=json.loads(_open(receipt).read_bytes())
    if raw.get('artifact_type') not in (dynamic.TYPE,dynamic.FOUR_TYPE):
        raise ValueError('target partial proof has another reader role')
    value=dynamic._document(receipt,raw['artifact_type'])
    kind,contract=dynamic._kind(value['registered_layout'])
    if raw['artifact_type']!=kind or value['contract']!=contract:
        raise ValueError('target partial receipt changed its exact serial layout contract')
    source_binding=value['inputs']['source_binding'];source=dynamic._source(source_binding)
    first,first_end=dynamic._recorded_operation(source,value['inputs'],value['deep_operation'])
    first_facts=dynamic.partial_subset(first)
    if (value['reader_sources']!=dynamic._reader_sources()
            or value['lane_pass_claim'] is not False or type(value['aggregate_formal_credit']) is not int
            or value['aggregate_formal_credit']!=0
            or any(not _typed_equal(value.get(k),v) for k,v in first_facts.items())):
        raise ValueError('target partial receipt changes original accepted or incomplete labels')
    verified=operation['verification']
    _keys(verified, {'accepted_count','registered_layout','slot_start','slot_count','aggregate_status',
        'lane_pass_claim','aggregate_formal_credit','fresh_deep_operation','read_dependencies','directory_dependencies'},
        'target independent partial verification')
    second,second_end=dynamic._recorded_operation(source,value['inputs'],verified['fresh_deep_operation'])
    second_facts=dynamic.partial_subset(second)
    first_inputs=dynamic._input_closure(source,source_binding,first,value['deep_operation'])
    second_inputs=dynamic._input_closure(source,source_binding,second,verified['fresh_deep_operation'])
    second_start=json.loads(_open(verified['fresh_deep_operation']['started.json']).read_bytes())
    if (not _typed_equal(first_facts,second_facts) or value['deep_operation']==verified['fresh_deep_operation']
            or not _time(first_end['completed_at'])<=_time(value['published_at'])<=_time(second_start['started_at'])
                <=_time(second_end['completed_at'])<=datetime.now(timezone.utc)
            or any(not _typed_equal(verified[k],second_facts[k]) for k in
                ('accepted_count','registered_layout','slot_start','slot_count','aggregate_status','lane_pass_claim','aggregate_formal_credit'))
            or value['read_dependencies']!=first_inputs['read_dependencies']
            or value['directory_dependencies']!=first_inputs['directory_dependencies']
            or verified['read_dependencies']!=second_inputs['read_dependencies']
            or verified['directory_dependencies']!=second_inputs['directory_dependencies']):
        raise ValueError('target partial proof lacks separate unchanged original deep verification')
    dependencies=_dependency_union(first_inputs,second_inputs,
        {'read_dependencies':[receipt], 'directory_dependencies':[]})
    source['binding_reference']=source_binding
    return source,second,second_facts,dependencies,second_end['completed_at']


def _partial_rows(source,report,facts):
    observed={r['path']:r for r in report['read_dependencies']};root=epoch._path(report['result_root'],directory=True)
    from .verification import resolved_sample_directory
    samples={s['sample_id']:s for s in report['experiment']['samples']}
    workloads={w['id']:w for w in report['experiment']['configuration']['workloads']};rows=[]
    for slot in facts['accepted_samples']:
        sample=samples[slot['sample_id']]
        run_ref=reference(resolved_sample_directory(root,sample)/'neqo/run.json')
        manifest_ref=reference(root/workloads[slot['workload_id']]['path'])
        if observed.get(run_ref['path'])!=run_ref or observed.get(manifest_ref['path'])!=manifest_ref:
            raise ValueError('target partial trace lost its original deep-observed run or complete graph')
        if manifest_ref['sha256']!=slot['workload_sha256']:
            raise ValueError('target partial graph differs from its original frozen workload')
        run=json.loads(_open(run_ref).read_bytes())
        rows.append({**slot,'visit':slot['logical_visit'],
            'original_graph_sha256':membership.graph_identity(Path(manifest_ref['path'])),
            'result_root':str(root),'run':run_ref,'condition':condition_identity(facts['configuration'],run,slot['mode']),
            'capture_limits':facts['configuration']['limits'],'intent_started_at':facts['intent']['started_at'],
            'measurement_source':facts['measurement_source'],'client_sha256':source['binding']['runtime_identity']['client_sha256'],
            'source_binding':source['binding_reference'],'partial_layout':facts['registered_layout'],
            'aggregate_status':'incomplete','lane_pass_claim':False,'aggregate_formal_credit':0})
    return rows


@_owned
def audit_partial(*, receipt, audit_root, output):
    # The public reader runs a genuinely separate original deep proof here.
    # Reopening this new audit later authenticates both exact original operations.
    verification=dynamic.verify(receipt,audit_root=Path(audit_root))
    operation={'receipt':receipt,'verification':verification}
    source,report,facts,dependencies,completed=_partial_operation(operation)
    rows=_partial_rows(source,report,facts)
    return _write(output,AUDIT_TYPE,{'kind':'partial','source_binding':source['binding_reference'],'operation':operation,
        'rows':rows,**dependencies,'completed_at':completed,'sources':_sources(),'scientific_credit':False},
        dependencies['read_dependencies'],dependencies['directory_dependencies'])


@_owned
def validate_audit(ref):
    context=current_context();key=('fixed-target-audit-validated',_digest(ref))
    if context.has(key):return context.get(key)
    value=_document(ref,AUDIT_TYPE)
    _keys(value,{'kind','source_binding','operation','rows','read_dependencies','directory_dependencies',
                'completed_at','sources','scientific_credit'},'target trace audit')
    if value['kind'] not in ('complete','partial') or not _compatible_sources(value['sources']) or value['scientific_credit'] is not False:
        raise ValueError('target trace audit has another role or executing Source')
    if value['kind']=='complete':
        source,report,completed=_complete_operation(value['source_binding'],value['operation'])
        source['binding_reference']=value['source_binding'];rows=_run_rows(source,report)
        operation=value['operation'];dependencies=_complete_dependencies(source,value['source_binding'],report,
            {'started':operation['started'],'completed':operation['completed'],'interpreter':operation['interpreter']['binary']})
        dependencies=_dependency_union(dependencies)
    else:
        source,report,facts,dependencies,completed=_partial_operation(value['operation'])
        rows=_partial_rows(source,report,facts)
        if source['binding_reference']!=value['source_binding']:
            raise ValueError('target partial proof substituted its installed Source registration')
    if (not _typed_equal(value['rows'],rows) or value['completed_at']!=completed
            or value['read_dependencies']!=dependencies['read_dependencies']
            or value['directory_dependencies']!=dependencies['directory_dependencies']):
        raise ValueError('target trace rows differ from original complete-deep authority')
    context.remember(key,value)
    return value


def _select(target, proofs, *, initial):
    if not isinstance(proofs,list): raise ValueError('target proofs must be an explicit original-audit list')
    context=current_context();memo_key=('fixed-target-selected',_digest(target),_digest(proofs),initial)
    if context is not None and context.has(memo_key):return context.get(memo_key)
    by_candidate={r['candidate_id']:r for r in target['classes']};rows=[];slots=set();physical=set()
    for proof in proofs:
        audit=validate_audit(proof)
        for row in audit['rows']:
            mode=row['mode'];member=by_candidate.get(row['candidate_id'])
            if mode not in MODES: raise ValueError('target trace has an unregistered condition')
            if initial and mode not in ('undefended','front'):
                raise ValueError('initial target may carry only exactly matched ordinary/FRONT; Tamaraw starts empty')
            if (member is None or row['workload_id']!=member['workload_id']
                    or row['original_graph_sha256']!=member['original_graph_sha256']
                    or not _typed_equal(row['capture_limits'], _capture_limits(
                        mode, member['capture_limits'], target['conditions'][mode]['identity']))
                    or row['client_sha256']!=target['target_identity']['client_sha256']
                    or row['measurement_source']['neqo_commit']!=target['target_identity']['native_head']
                    or row['measurement_source']['neqo_pinned_commit']!=target['target_identity']['native_head']
                    or not _typed_equal(row['condition'],target['conditions'][mode]['identity'])
                    or type(row['logical_visit']) is not int or not 0<=row['logical_visit']<SLOTS):
                raise ValueError('target trace changed condition, full graph, caps, client or logical slot')
            if (mode=='tamaraw' and _time(row['intent_started_at'])<_time(target['declared_at'])):
                raise ValueError('fixed8192 target cannot retrocredit an earlier Tamaraw intent')
            key=(member['class_index'],mode,row['logical_visit']);actual=(row['result_root'],row['sample_id'])
            if key in slots or actual in physical: raise ValueError('target repeats a logical slot or original physical sample')
            slots.add(key);physical.add(actual)
            rows.append({**row,'class_index':member['class_index'],'proof':proof,'condition_sha256':_digest(row['condition'])})
    if context is not None:context.remember(memo_key,rows)
    return rows


def _vectors(classes, rows):
    accepted={(r['class_index'],r['mode'],r['logical_visit']) for r in rows}
    return [{'class_index':c['class_index'],'candidate_id':c['candidate_id'],'mode':mode,
             'remaining_slots':[v for v in range(SLOTS) if (c['class_index'],mode,v) not in accepted]}
            for c in classes for mode in MODES]


def _aggregate(classes, rows):
    return 'complete' if len(classes)==CLASSES and len(rows)==TOTAL and not any(
        row['remaining_slots'] for row in _vectors(classes,rows)) else 'incomplete'


@_owned
def initialize_progress(*, target, proofs, output):
    declaration=validate_target(target);rows=_select(declaration,proofs,initial=True)
    value={'contract':CONTRACT,'target':target,'target_id':declaration['target_id'],'parent':None,
        'proofs':proofs,'classes':declaration['classes'],'accepted_rows':rows,'remaining_vectors':_vectors(declaration['classes'],rows),
        'target_accepted_count':len(rows),'retained_history':declaration['retained_history'],
        'history_counts_as_target_credit':False,'final_target':TOTAL,'sources':_sources(),
        'published_at':datetime.now(timezone.utc).isoformat(),'aggregate_status':_aggregate(declaration['classes'],rows)}
    return _write(output,PROGRESS_TYPE,value,[target,*proofs,*value['sources'].values()])


@_owned
def validate_progress(ref, _seen=None):
    context=current_context();key=('fixed-target-progress-validated',_digest(ref))
    if context.has(key):return context.get(key)
    seen=set() if _seen is None else _seen
    if ref['path'] in seen: raise ValueError('fixed target progress ancestry is cyclic')
    seen.add(ref['path']);value=_document(ref,PROGRESS_TYPE);target=validate_target(value['target'])
    _keys(value,{'contract','target','target_id','parent','proofs','classes','accepted_rows','remaining_vectors',
        'target_accepted_count','retained_history','history_counts_as_target_credit','final_target','sources',
        'published_at','aggregate_status'},'fixed target progress')
    rows=_select(target,value['proofs'],initial=value['parent'] is None)
    if (value['contract']!=CONTRACT or not _compatible_sources(value['sources']) or value['target_id']!=target['target_id']
            or value['classes']!=target['classes'] or value['accepted_rows']!=rows
            or value['remaining_vectors']!=_vectors(target['classes'],rows) or value['target_accepted_count']!=len(rows)
            or type(value['target_accepted_count']) is not int or type(value['final_target']) is not int or value['final_target']!=TOTAL
            or value['retained_history']!=target['retained_history'] or value['history_counts_as_target_credit'] is not False
            or value['aggregate_status']!=_aggregate(target['classes'],rows)
            or not _time(target['published_at'])<=_time(value['published_at'])<=datetime.now(timezone.utc)
            or any(_time(validate_audit(proof)['completed_at'])>_time(value['published_at']) for proof in value['proofs'])):
        raise ValueError('fixed target progress moved accepted conditions or remaining slots')
    if value['parent'] is not None:
        old=validate_progress(value['parent'],seen)
        if (old['target_id']!=value['target_id'] or value['proofs'][:len(old['proofs'])]!=old['proofs']
                or rows[:len(old['accepted_rows'])]!=old['accepted_rows']
                or value['classes'][:len(old['classes'])]!=old['classes']
                or _time(value['published_at'])<_time(old['published_at'])):
            raise ValueError('target progress rewrote a retained original proof or accepted slot')
    context.remember(key,value)
    return value


@_owned
def append_progress(*, progress, proofs, output, target=None):
    old=validate_progress(progress);target_ref=old['target'] if target is None else target
    declaration=validate_target(target_ref)
    if declaration['target_id']!=old['target_id'] or declaration['classes'][:len(old['classes'])]!=old['classes']:
        raise ValueError('target progress cannot change its fixed condition namespace or class mapping')
    all_proofs=old['proofs']+proofs;rows=_select(declaration,all_proofs,initial=False)
    if rows[:len(old['accepted_rows'])]!=old['accepted_rows']:
        raise ValueError('target append renumbered or relabelled an earlier accepted slot')
    value={**old,'target':target_ref,'parent':progress,'proofs':all_proofs,'classes':declaration['classes'],
        'accepted_rows':rows,'target_accepted_count':len(rows),'remaining_vectors':_vectors(declaration['classes'],rows),
        'retained_history':declaration['retained_history'],'published_at':datetime.now(timezone.utc).isoformat(),
        'aggregate_status':_aggregate(declaration['classes'],rows)}
    return _write(output,PROGRESS_TYPE,value,[progress,target_ref,*all_proofs,*value['sources'].values()])


@_owned
def remaining_vectors(progress):
    return validate_progress(progress)['remaining_vectors']


@_owned
def chunk_inputs(progress, classes, mode, *, maximum=16):
    value=validate_progress(progress)
    if (mode not in MODES or not isinstance(classes,list) or not classes or len(set(classes))!=len(classes)
            or any(type(c) is not int for c in classes) or type(maximum) is not int or not 1<=maximum<=16):
        raise ValueError('fixed target chunk selection requires distinct classes/known mode/maximum1..16')
    selected=[r for r in value['classes'] if r['class_index'] in classes]
    if [r['class_index'] for r in selected]!=classes: raise ValueError('target chunk changed admitted class ordering')
    vectors=[r['remaining_slots'] for r in value['remaining_vectors'] if r['class_index'] in classes and r['mode']==mode]
    if any(v!=vectors[0] for v in vectors):
        raise ValueError('one exact chunk cohort requires identical remaining vectors; select a separate recoverable group')
    if any(r['capture_limits']!=selected[0]['capture_limits'] for r in selected):
        raise ValueError('one fixed target flight requires homogeneous per-class caps')
    accepted=set(range(SLOTS))-set(vectors[0]);target=validate_target(value['target'])
    return {'target':value['target'],'progress':progress,'target_id':value['target_id'],'condition':target['conditions'][mode],
        'classes':selected,'capture_limits':_capture_limits(mode, selected[0]['capture_limits'],
            target['conditions'][mode]['identity']),'remaining_slots':vectors[0],
        'ranges':[{'slot_start':start,'slot_count':count} for start,count in chunks.ranges(accepted,maximum=maximum)],
        'old_capsule_or_chunk_authority_inferred':False}


@_owned
def publish_chunk_inputs(progress, classes, mode, *, maximum=16, output):
    value=chunk_inputs(progress,classes,mode,maximum=maximum)
    return _write(output,CHUNK_INPUT_TYPE,{'mode':mode,'maximum':maximum,'inputs':value,
        'planning_only':True,'scientific_credit':False,'sources':_sources()},[progress,*_sources().values()])


@_owned
def read_chunk_inputs(ref):
    value=_document(ref,CHUNK_INPUT_TYPE)
    _keys(value, {'mode','maximum','inputs','planning_only','scientific_credit','sources'}, 'fixed condition chunk input')
    expected=chunk_inputs(value['inputs']['progress'],[r['class_index'] for r in value['inputs']['classes']],
        value['mode'],maximum=value['maximum'])
    if (not _typed_equal(value['inputs'],expected) or value['planning_only'] is not True
            or value['scientific_credit'] is not False or not _compatible_sources(value['sources'])):
        raise ValueError('fixed condition chunk input changed an authenticated remaining-slot vector')
    return value


@_owned
def final_coverage(progress):
    value=validate_progress(progress)
    if len(value['classes'])!=CLASSES or value['target_accepted_count']!=TOTAL or any(r['remaining_slots'] for r in value['remaining_vectors']):
        raise ValueError('fixed target final corpus requires exactly50×5×64 original independent accepted slots')
    return {'target':value['target'],'progress':progress,'target_id':value['target_id'],
            'accepted':TOTAL,'classes':CLASSES,'conditions':5,'slots_per_class_condition':SLOTS,
            'history_counts_as_target_credit':False,'original_source_labels_retained':True}


@_owned
def publish_final(progress, output):
    facts=final_coverage(progress);value=validate_progress(progress)
    files=input_files(progress);directories=directory_dependencies(progress)
    _check_action()
    return _write(output,CORPUS_TYPE,{'contract':CONTRACT,**facts,'accepted_rows':value['accepted_rows'],
        'read_dependencies':files,'directory_dependencies':directories,'sources':_sources(),
        'published_at':datetime.now(timezone.utc).isoformat(),'scientific_credit':True},files)


@_owned
def input_files(progress):
    value=validate_progress(progress);files={reference(Path(__file__))['path']:reference(Path(__file__))}
    def add(ref): files[ref['path']]=ref;_open(ref)
    add(progress);add(value['target'])
    def target_inputs(target_ref):
        add(target_ref);target=validate_target(target_ref)
        for ref in [target['enrollment'],*target['sources'].values(),*target['retained_history'],
                    *target['membership_dependencies']['files']]:add(ref)
        for tree in target['membership_dependencies']['trees']:
            for name,member in tree['members'].items():
                if member['kind']=='file':add({'path':str(Path(tree['path'])/name),
                    'sha256':member['sha256'],'mode':member['mode']})
        for condition in target['conditions'].values():
            add(condition['reference']);descriptor=_document(condition['reference'],CONDITION_TYPE)
            add(descriptor['configuration']);add(descriptor['run'])
        for row in target['classes']:add(row['original_manifest'])
        if target['parent'] is not None:target_inputs(target['parent'])
    target_inputs(value['target'])
    for proof in value['proofs']:
        add(proof);audit=validate_audit(proof)
        for ref in [audit['source_binding'],*audit['read_dependencies']]:add(ref)
        source=_measurement_source(audit['source_binding'])
        for ref in source['files'].values():add(ref)
        for ref in source['binding']['read_dependencies']:add(ref)
    if value['parent'] is not None:
        for ref in input_files(value['parent']):add(ref)
    return [files[k] for k in sorted(files)]


@_owned
def roots(progress):
    # Exact authenticated files can be mounted as files. Preserve immutable
    # directory membership roots separately; never broaden to a workspace.
    value=validate_progress(progress);paths={Path(ref['path']) for ref in input_files(progress)}
    for row in directory_dependencies(progress):paths.add(Path(row['path']))
    return tuple(sorted(paths,key=str))


@_owned
def directory_dependencies(progress):
    value=validate_progress(progress);directories={}
    def target_trees(target_ref):
        target=validate_target(target_ref)
        for tree in target['membership_dependencies']['trees']:
            directories[(tree['path'],'complete-membership-tree')]={'path':tree['path'],'kind':'complete-membership-tree',
                'ignore_git':tree['ignore_git'],'members':tree['members']}
        if target['parent'] is not None:target_trees(target['parent'])
    target_trees(value['target'])
    for proof in value['proofs']:
        for row in validate_audit(proof)['directory_dependencies']:
            key=(row['path'],'shallow-directory');declared={'kind':'shallow-directory',**row};old=directories.get(key)
            if old is not None and old!=declared:
                raise ValueError('target raw directory observations have conflicting selectors')
            directories[key]=declared
    if value['parent'] is not None:
        for row in directory_dependencies(value['parent']):
            key=(row['path'],row['kind']);old=directories.get(key)
            if old is not None and old!=row:raise ValueError('target ancestry directory observations disagree')
            directories[key]=row
    return [directories[k] for k in sorted(directories)]
