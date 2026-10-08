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
import math
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
from . import rapid_action_local_source_facts as source_facts

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
                # Nested readers share the same action. Its owner closes every
                # observation once; _write still closes before publication.
                if token is not None: _check_action()
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



_LEGACY_READER_UNITS = {
    "overlay": {"_derive":"e7031bf8ea172089a7cccc7470c2a00748bc01722addf57287481ecf1cf1028f","_source":"61fc23613473c2e8f53e6cb0a98aa11eee7424ed186d1e5a465908cbcfb3d4b4"},
    "dynamic": {
        "_runtime_operation": "ec75e4ed975b8a8dd57843dccac57796f08edd482c113dea45b03693b80c6a3a",
        "_source": "0900a7ee99e9c5ef2518875531caaa5bedfcd89ba51d27c2260261a606413da4"
    },
    "target": {
        "_owned": "c417f8b78f43a6641e00213a5e8a1904c39bfa34348ee7135144949b9b9fed86",
        "_compatible_membership": "79b50dbbd6a04dfc54d11ed9b9f5b3577770e6f1fca078c6132c1f0b53920806",
        "_compatible_sources": "57bbe929e751a1219414f3021a4a830974d9ddf8cc0cbad08f7019da7b46b1de",
        "roots": "ded0e25f7074be581b7258c910661b510dbd0f063f8509253d85b32a4751377c"
    }
}
_READER_COMPATIBILITY_HELPERS = {
    'overlay': ('_compatible_overlay_sources',),
    'target': ('_reader_code_projection', '_compatible_code_ref',
               '_planning_source_projection', '_membership_code_path',
               '_compatible_selected_membership_code', '_epoch_dispatch_source_projection',
               '_epoch_dynamic_source_projection', '_parallel_facts_source_projection',
               '_portable_dynamic_source_projection',
               '_parallel_schedule_source_projection', '_acquisition_reader_sources',
               '_v13_input_reader_source_projection', '_v13_supplement_reader_source_projection',
               '_v13_cohort_reader_source_projection', '_required_parent_get_source_projection',
               '_source65_selected_input_source_projection',
               '_v12_input_reader_source_projection',
               '_v11_input_reader_source_projection',
               '_compatible_acquisition_code', '_cohort_acquisition_source_projection',
               '_membership_additive_reader_roles', '_parallel_partial_source_projection',
               '_mixed_epoch', 'mode_implementation', '_mixed_implementation_source_projection'),
    'dynamic': ('_compatible_reader_sources',),
}
_ACTION_LOCAL_SOURCE_FACTS_SHA256 = '55460a08b99461c5d29d30579605f5f79ce187e69db6657fbdd87399794ed744'


def _reader_code_projection(raw, role, *, legacy=False):
    """Keep every scientific unit; only closed compatibility guards may differ."""
    import ast
    if role not in _LEGACY_READER_UNITS:
        raise ValueError('reader compatibility role is outside the closed set')
    context = current_context()
    key = ('fixed-target-reader-fingerprint', role, legacy, hashlib.sha256(raw).hexdigest())
    if context is not None and context.has(key):
        return context.get(key)
    tree = ast.parse(raw)
    retained = []; seen = set()
    for node in tree.body:
        if (role == 'target' and isinstance(node, ast.ImportFrom) and node.level == 1
                and node.module is None and len(node.names) == 1
                and node.names[0].name == 'rapid_action_local_source_facts'
                and node.names[0].asname == 'source_facts'):
            if legacy: raise ValueError('retained reader added an action-local memo')
            continue
        if (role == 'target' and isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == '_ACTION_LOCAL_SOURCE_FACTS_SHA256'):
            if (legacy or not isinstance(node.value, ast.Constant)
                    or node.value.value not in ('34586599ad4eeeb1f765eb5ff7ca0d36559be2ef0a7d7521eff0fc7a681e4c0c',
                        '55460a08b99461c5d29d30579605f5f79ce187e69db6657fbdd87399794ed744')):
                raise ValueError('action-local memo helper is outside the reviewed Source')
            continue
        if role == 'target' and isinstance(node, ast.FunctionDef):
            memo_units = {
                '_measurement_source': ('source', '82934e22e357e815313f2869f78611a8f28fd4468693a6301803308d6cdae127'),
                'input_files': ('selection', 'b3a511bde750b11f4a50164c246a87465c9132ac30c106bb4cb523dee043f464'),
                'roots': ('selection', 'e778874d2029fb77845ec30ed0053251ae448a0bc7aecfe1ae6b134d6160ae2c'),
                'directory_dependencies': ('selection', '6358e66ae5b125a12655fec6b9d3df02455974dcd286076dd6cf1827f448d481'),
            }
            memo = [d for d in node.decorator_list if isinstance(d, ast.Attribute)
                    and isinstance(d.value, ast.Name) and d.value.id == 'source_facts']
            if memo:
                if (legacy or node.name not in memo_units or len(memo) != 1
                        or memo[0].attr != memo_units[node.name][0]):
                    raise ValueError('reader memo decorates an unreviewed authority unit')
                node.decorator_list.remove(memo[0])
                shape = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                if shape != memo_units[node.name][1]:
                    raise ValueError('reader memo changes original validation or dependency selection')
        if isinstance(node, ast.FunctionDef) and node.name in _LEGACY_READER_UNITS[role]:
            if node.name in seen:
                raise ValueError('reader compatibility guard is duplicated')
            seen.add(node.name)
            shape = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            if legacy and shape != _LEGACY_READER_UNITS[role][node.name]:
                raise ValueError('retained reader compatibility guard is not the original shape')
            if role == 'target' and node.name == '_owned' and shape not in (
                    _LEGACY_READER_UNITS['target']['_owned'],
                    '4e2825b98c6221ea6c4f66da8e7503ec6eb12d3da7319764334144c41ac5b45b'):
                raise ValueError('fixed target action boundary is outside the exact old/new shapes')
            continue
        if isinstance(node, ast.FunctionDef) and node.name in _READER_COMPATIBILITY_HELPERS[role]:
            if legacy:
                raise ValueError('retained reader added a compatibility helper')
            continue
        if (role == 'target' and isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id in
                        ('_LEGACY_READER_UNITS', '_READER_COMPATIBILITY_HELPERS') for t in node.targets)):
            if legacy:
                raise ValueError('retained reader added a compatibility declaration')
            continue
        retained.append(node)
    if seen != set(_LEGACY_READER_UNITS[role]):
        raise ValueError('reader compatibility guard set is incomplete')
    tree.body = retained
    value = ast.dump(tree, include_attributes=False).encode()
    if context is not None: context.remember(key, value)
    return value


def _compatible_code_ref(role, producer, current):
    _open(producer); _open(current)
    if producer['mode'] != current['mode']:
        raise ValueError('reader compatibility changes a full file mode')
    if producer['sha256'] == current['sha256']:
        return True
    if (role == 'dynamic'
            and producer['sha256'] == 'dce570b9ba7d1ac1ce35431e8a83ba0a93a0daaa4acbe8c0ee61e99e2e27c567'
            and current['sha256'] == '12ba6b327f278ddef1faaade56b22d5a5b80a388fbf636f9e3cb648607108225'):
        return _mixed_epoch().compatible_legacy_reader('dynamic', producer, current)
    # Source34 is itself an authenticated compatibility reader. Its complete
    # published file hash selects that known shape; older producers still
    # require the original guard AST fingerprints above.
    enhanced_target = (role == 'target' and producer['sha256'] in {
                       '3d75eee530f282fe81373b3fa584603360e1f216dbe559fc368ed1aadd5e6cad',
                       '9ec1c86f9d6e310f0f510e821a586d6a23d96222813d495fc3ef22d14e638571',
                       '2644a9156562a2b8b377f9ee019325ce2cda04a4dfc0770bdbb89013fcede14c',
                       '8a263b9d3f2bfac765170edaf05eee6bff77e3523ea8cd635f1f831b37ab1676',
                       '5efeb8f9bdce65d4eb43e781e6388ac84a83453378812d456dc40862bd955b36',
                       '26b41cd9cff02e7dde8b9dbda902fa69d370fe5b242dd075f41c5db39c356b26',
                       '784ceb0f5e5a8cbde41eafdee4bb209781ba2df352cd72a0fbab8f24eacc46cf',
                       '38b58853b7788608ad7601f927a4a924d7257641f1e373d3c288dd228b93b705',
                       '49ed0ab36f1b9cb1c01375814c57a35a9f186f19020dcf86d5553d5404369b03',
                       '76eb0532100db6bfbd247aa9bbac0006902d25502de37ee42d1bb3148659444c',
                       'd485db59ab1e976382e0e544522ea0f15aa638bbe7ca16b62373b5089528de00',
                       '1537b2bc43ca527ed8b1c33fcca14e82b3fb468881cc193bad81a012a5815005',
                       'aef299755e14c577e366fffa8df0f281f5f10bdef0937abb6fea52e51dd4ae90',
                       '80783154a4c0097fa8729b69c3ea5dd6ca8f617dd655ce286c7e929874ba8f45',
                       'e57126d7a6e179a82f6f997dd8935a543fbf3378718466ad0eb5033b4811890a',
                       '13b8610c344176087bc8c85a29d8912c8aed14320999130e2f0a28e394c6bb86'})
    epoch_dynamic = (role == 'dynamic' and producer['sha256'] in {
        '17d9b19159a521e7c18cea732ba8ed44dff6044a18442807a716e793586cb3a3',
        'e5c49b345c0e5acb1af442dbaae7d2caabfcdcf09892239d5ebb78f5d03a318a',
        '1e917253a51a0468cea929526d5c73e65e5a0220868f48447b0bd7b8648edbdd'}
        and current['sha256'] in {
            '1e917253a51a0468cea929526d5c73e65e5a0220868f48447b0bd7b8648edbdd',
            '9339d219b5b0e97b23ec9f1ea78cd7378ec9b81d5018f64a14eace5928d6cbcd'})
    portable_dynamic = (role == 'dynamic' and producer['sha256'] in {
        '17d9b19159a521e7c18cea732ba8ed44dff6044a18442807a716e793586cb3a3',
        'e5c49b345c0e5acb1af442dbaae7d2caabfcdcf09892239d5ebb78f5d03a318a',
        '1e917253a51a0468cea929526d5c73e65e5a0220868f48447b0bd7b8648edbdd',
        '9339d219b5b0e97b23ec9f1ea78cd7378ec9b81d5018f64a14eace5928d6cbcd'}
        and current['sha256'] in {'dce570b9ba7d1ac1ce35431e8a83ba0a93a0daaa4acbe8c0ee61e99e2e27c567',
            '12ba6b327f278ddef1faaade56b22d5a5b80a388fbf636f9e3cb648607108225'})
    try:
        if portable_dynamic:
            old = _epoch_dynamic_source_projection(Path(producer['path']).read_bytes())
            new = _portable_dynamic_source_projection(Path(current['path']).read_bytes())
        elif epoch_dynamic:
            old = _epoch_dynamic_source_projection(Path(producer['path']).read_bytes())
            new = _epoch_dynamic_source_projection(Path(current['path']).read_bytes())
        else:
            old_raw = Path(producer['path']).read_bytes()
            new_raw = Path(current['path']).read_bytes()
            if role == 'target':
                old_raw = _mixed_implementation_source_projection(old_raw)
                new_raw = _mixed_implementation_source_projection(new_raw)
                old_raw = _parallel_partial_source_projection(old_raw)
                new_raw = _parallel_partial_source_projection(new_raw)
            old = _reader_code_projection(old_raw, role,
                                          legacy=not enhanced_target)
            new = _reader_code_projection(new_raw, role)
    except (ValueError, SyntaxError) as error:
        raise ValueError('fixed target relevant producer/reader code changed') from error
    if old != new:
        raise ValueError('fixed target relevant producer/reader code changes protected scientific code')
    return True


def _mixed_epoch():
    from . import rapid_mixed_implementation_target as mixed
    declared = reference(Path(mixed.__file__))
    if (declared['sha256'] != '28c28ab5148e1dc68e5d6db8edfad8532d68821a723ebb586d0546806b3bbc1f'
            or declared['mode'] != 0o644):
        raise ValueError('mixed target reader differs from its exact reviewed module')
    return mixed


def mode_implementation(declaration, mode):
    mixed = _mixed_epoch()
    if mixed.is_declaration(declaration):
        return mixed.mode_implementation(declaration, mode)
    if mode not in MODES:
        raise ValueError('fixed target mode is not registered')
    return declaration['target_identity']


def _mixed_implementation_source_projection(raw):
    """Remove only the exact distinct V2 dispatch; retain every V1 validator."""
    import ast
    seams = {
        'validate_target': "if _mixed_epoch().is_target(ref):\n    return _mixed_epoch().validate_target(ref, _seen=_seen)\n",
        'validate_progress': "if _mixed_epoch().is_progress(ref):\n    return _mixed_epoch().validate_progress(ref, _seen=_seen)\n",
        'initialize_progress': "if _mixed_epoch().is_target(target):\n    return _mixed_epoch().initialize_progress(target=target, proofs=proofs, output=output)\n",
        'append_progress': "if _mixed_epoch().is_progress(progress):\n    return _mixed_epoch().append_progress(progress=progress, proofs=proofs, output=output, target=target)\n",
        'publish_final': "if _mixed_epoch().is_progress(progress):\n    return _mixed_epoch().publish_final(progress, output)\n",
        'input_files': "if _mixed_epoch().is_progress(progress):\n    return _mixed_epoch().input_files(progress)\n",
        'directory_dependencies': "if _mixed_epoch().is_progress(progress):\n    return _mixed_epoch().directory_dependencies(progress)\n",
        '_capture_limits': "if mode == 'buflo' and condition.get('defense', {}).get('parameters_sha256') == '5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e':\n    return _mixed_epoch().capture_limits(original, condition)\n",
    }
    tree = ast.parse(raw); found = set()
    shape = lambda node: ast.dump(node, include_attributes=False)
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name not in seams:
            continue
        expected = ast.parse(seams[node.name]).body[0]
        matches = [item for item in node.body if shape(item) == shape(expected)]
        if matches:
            offset = 1 if node.name == '_capture_limits' else 0
            if len(matches) != 1 or node.body[offset] is not matches[0]:
                raise ValueError('mixed target dispatch duplicated or moved its V1 boundary')
            node.body.remove(matches[0]); found.add(node.name)
    if found and found != set(seams):
        raise ValueError('mixed target V1 dispatch projection is incomplete')
    return ast.unparse(tree).encode() if found else raw


def _parallel_partial_source_projection(raw):
    """Remove only exact new parallel-role dispatch seams before old comparison.

    Every old scientific body, including partial joins and target selection,
    remains in the compared AST. The new reader owns a separate bound Source.
    """
    raw = _mixed_implementation_source_projection(raw)
    import ast
    tree = ast.parse(raw)
    seam = ast.parse(
        "if json.loads(_open(operation['receipt']).read_bytes()).get('artifact_type') == "
        "'qcsd-original-deep-verified-individual-traces-from-incomplete-parallel-chunk-v1':\n"
        "    from . import rapid_parallel_partial_lane as parallel_partial\n"
        "    return parallel_partial.target_operation(operation)\n").body[0]
    audit = ast.parse(
        "if json.loads(_open(receipt).read_bytes()).get('artifact_type') == "
        "'qcsd-original-deep-verified-individual-traces-from-incomplete-parallel-chunk-v1':\n"
        "    from . import rapid_parallel_partial_lane as parallel_partial\n"
        "    verification=parallel_partial.verify(receipt,audit_root=Path(audit_root))\n"
        "else:\n"
        "    verification=dynamic.verify(receipt,audit_root=Path(audit_root))\n").body[0]
    rows = ast.parse(
        "if facts.get('actuator') == 'parallel-formal-worker':\n"
        "    from . import rapid_parallel_partial_lane as parallel_partial\n"
        "    return parallel_partial.target_rows(source,report,facts)\n").body[0]
    shape = lambda value: ast.dump(value, include_attributes=False)
    removed = set()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name == '_partial_operation':
            matches = [i for i, statement in enumerate(node.body) if shape(statement) == shape(seam)]
            if matches:
                if matches != [1]:
                    raise ValueError('parallel partial dispatch moved or duplicated')
                node.body.pop(1); removed.add(node.name)
        elif node.name == 'audit_partial':
            matches = [i for i, statement in enumerate(node.body) if shape(statement) == shape(audit)]
            if matches:
                if matches != [0]:
                    raise ValueError('parallel partial public dispatch moved or duplicated')
                node.body[0:1] = audit.orelse; removed.add(node.name)
        elif node.name == '_partial_rows':
            matches = [i for i, statement in enumerate(node.body) if shape(statement) == shape(rows)]
            if matches:
                if matches != [0]:
                    raise ValueError('parallel partial row dispatch moved or duplicated')
                node.body.pop(0); removed.add(node.name)
    if removed and removed not in ({'_partial_operation', 'audit_partial'},
            {'_partial_operation', 'audit_partial', '_partial_rows'}):
        raise ValueError('parallel partial compatibility lacks its paired original dispatch seams')
    return ast.unparse(tree).encode()


def _epoch_dynamic_source_projection(raw):
    """Retain every other dynamic reader unit for one exact partial-binding pair."""
    import ast
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in {
            '17d9b19159a521e7c18cea732ba8ed44dff6044a18442807a716e793586cb3a3',
            'e5c49b345c0e5acb1af442dbaae7d2caabfcdcf09892239d5ebb78f5d03a318a',
            '1e917253a51a0468cea929526d5c73e65e5a0220868f48447b0bd7b8648edbdd',
            '9339d219b5b0e97b23ec9f1ea78cd7378ec9b81d5018f64a14eace5928d6cbcd'}:
        raise ValueError('dynamic epoch binding is outside the exact Source pair')
    tree = ast.parse(raw)
    found = 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_measurement_binding':
            found += 1; node.body = [ast.Pass()]
    if found != 1: raise ValueError('dynamic epoch binding definition is absent or duplicated')
    return _reader_code_projection(ast.unparse(tree).encode(), 'dynamic')


def _portable_dynamic_source_projection(raw):
    """Remove only the exact reviewed v2 transport layer from a pinned reader."""
    import ast
    if hashlib.sha256(raw).hexdigest() == '12ba6b327f278ddef1faaade56b22d5a5b80a388fbf636f9e3cb648607108225':
        raw = _mixed_epoch().legacy_source_projection('dynamic', raw,
            historical_sha256='dce570b9ba7d1ac1ce35431e8a83ba0a93a0daaa4acbe8c0ee61e99e2e27c567')
    if hashlib.sha256(raw).hexdigest() != 'dce570b9ba7d1ac1ce35431e8a83ba0a93a0daaa4acbe8c0ee61e99e2e27c567':
        raise ValueError('portable dynamic reader is outside its exact reviewed Source')
    new_units = {'portable_release_snapshot', '_portable_installed_release', '_portable_runtime_roles',
                 '_run_portable_runtime', 'bind_portable_source', '_portable_source'}
    retained = []; found = set(); source_count = 0; binding_count = 0
    expected_dispatch = ast.parse("if json.loads(reopen(ref).read_bytes()).get('artifact_type') == SOURCE_V2_TYPE:\n    return _portable_source(ref)").body[0]
    for node in ast.parse(raw).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and
                isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'SOURCE_V2_TYPE'):
            if ('SOURCE_V2_TYPE' in found or not isinstance(node.value, ast.Constant) or
                    node.value.value != 'qcsd-chunk-partial-lane-portable-installed-release-source-v2'):
                raise ValueError('portable dynamic Source type changed')
            found.add('SOURCE_V2_TYPE'); continue
        if isinstance(node, ast.FunctionDef) and node.name in new_units:
            if node.name in found: raise ValueError('portable dynamic binding helper duplicated')
            found.add(node.name); continue
        if isinstance(node, ast.FunctionDef) and node.name == '_source':
            source_count += 1
            if (not node.body or ast.dump(node.body[0], include_attributes=False) !=
                    ast.dump(expected_dispatch, include_attributes=False)):
                raise ValueError('portable dynamic dispatch changes its v1 reader')
            node.body = node.body[1:]
            if hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest() != 'ed88e86c6bb197d1822cc215a55c433aa0058e39173aed0b766d13920bd8f475':
                raise ValueError('portable dynamic v1 Source reader changed')
        if isinstance(node, ast.FunctionDef) and node.name == '_measurement_binding':
            binding_count += 1; node.body = [ast.Pass()]
        retained.append(node)
    if found != new_units | {'SOURCE_V2_TYPE'} or source_count != 1 or binding_count != 1:
        raise ValueError('portable dynamic binding units are incomplete')
    tree = ast.Module(body=retained, type_ignores=[])
    return _reader_code_projection(ast.unparse(tree).encode(), 'dynamic')


def _planning_source_projection(raw):
    """Planning bodies are not enrollment/admission validators."""
    import ast
    context = current_context()
    key = ('fixed-target-membership-planning-fingerprint', hashlib.sha256(raw).hexdigest())
    if context is not None and context.has(key):
        return context.get(key)
    tree = ast.parse(raw); seen = set()
    optional = {'_sites_from_enrollment': 'enrolled_subgroup', 'publish_plan': 'class_indices',
                'verify_capture_plan': None}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name not in optional:
            continue
        if node.name in seen:
            raise ValueError('membership planner definition is duplicated')
        seen.add(node.name)
        name = optional[node.name]
        if name is not None:
            pairs = list(zip(node.args.kwonlyargs, node.args.kw_defaults))
            for argument, default in pairs:
                if argument.arg == name:
                    if (argument.annotation is not None or not isinstance(default, ast.Constant)
                            or default.value is not None):
                        raise ValueError('membership planner adds an executing default or annotation')
            pairs = [(arg, default) for arg, default in pairs if arg.arg != name]
            node.args.kwonlyargs = [arg for arg, _ in pairs]
            node.args.kw_defaults = [default for _, default in pairs]
        node.body = [ast.Pass()]
    if seen != set(optional):
        raise ValueError('membership planner definition set is incomplete')
    value = ast.dump(tree, include_attributes=False).encode()
    if context is not None: context.remember(key, value)
    return value


def _epoch_dispatch_source_projection(raw):
    """Normalize only exact published/held epoch dispatch bytes for membership."""
    import ast
    digest = hashlib.sha256(raw).hexdigest()
    source52 = 'c133974ffb1895d77b3fc88fd5888c9de28ed9e9b280ec2b9d576aa07b6c9702'
    source53 = '2101877af8bfdaea5a3a4ad38317adc5a2289d013dab5f5c8c77a8fc2c46c739'
    owned_check = 'b6f8db16953987f60a3c7ea0003fdad187dd41343b875233e3abacb5f2e4fe14'
    quick_profile = 'b9f316d212cf024e3d09ab4fa1a61035233f68f50f8a7c03c7450495cf81d2b0'
    front_profile = '6f5fc34f6d8ee14390378200d2ebba55d4de9fc205d6788453c960739f138881'
    if digest == front_profile:
        # Restore this exact future FRONT planner before historical membership
        # comparison. Its old enrollment, graph, Native and client units remain
        # byte-for-byte the Source64 reader; a current code mutation cannot alias it.
        edits = (
            (b"                     capture_limits: Mapping[str, int] | None = None,\n                     application_body_identity_policy: str | None = None,\n                     qualification_delivery_compatibility: Mapping[str, str] | None = None,\n                     tamaraw_configuration_policy: str | None = None) -> bytes:\n    from .rapid_additive_static_enrollment import CONTRACT as ADDITIVE_CONTRACT\n    from .rapid_per_class_selected_enrollment import CONTRACT as PER_CLASS_CONTRACT\n    return plan.render_lane_campaign(lane, sites, static_capture_limits=(\n",
             b"                     capture_limits: Mapping[str, int] | None = None,\n                     application_body_identity_policy: str | None = None,\n                     qualification_delivery_compatibility: Mapping[str, str] | None = None,\n                     tamaraw_configuration_policy: str | None = None,\n                     front_configuration_policy: str | None = None) -> bytes:\n    from .rapid_additive_static_enrollment import CONTRACT as ADDITIVE_CONTRACT\n    from .rapid_per_class_selected_enrollment import CONTRACT as PER_CLASS_CONTRACT\n    return plan.render_lane_campaign(lane, sites, static_capture_limits=(\n"),
            (b"        buflo_duration_policy=buflo_duration_policy,\n        application_body_identity_policy=application_body_identity_policy,\n        qualification_delivery_compatibility=qualification_delivery_compatibility,\n        tamaraw_configuration_policy=tamaraw_configuration_policy if lane.mode == \"tamaraw\" else None)\n\n\ndef _static_canary_facts(facts: Mapping[str, Any], amendment: Mapping[str, Any]) -> dict[str, Any]:\n",
             b"        buflo_duration_policy=buflo_duration_policy,\n        application_body_identity_policy=application_body_identity_policy,\n        qualification_delivery_compatibility=qualification_delivery_compatibility,\n        tamaraw_configuration_policy=tamaraw_configuration_policy if lane.mode == \"tamaraw\" else None,\n        front_configuration_policy=front_configuration_policy if lane.mode == \"front\" else None)\n\n\ndef _static_canary_facts(facts: Mapping[str, Any], amendment: Mapping[str, Any]) -> dict[str, Any]:\n"),
            (b"                 application_body_identity_policy: str | None = None,\n                 qualification_delivery_compatibility: Mapping[str, str] | None = None,\n                 tamaraw_configuration_policy: str | None = None,\n                 selected_input_renewal: Path | None = None, class_indices=None, _context=None) -> Path:\n    from .application_response_policy import validate_application_body_identity_policy, application_body_identity_policy as declared_body_policy, COMPLETE_APPLICATION_DELIVERY_POLICY\n    body_policy = validate_application_body_identity_policy(application_body_identity_policy)\n    from .tamaraw_fixed_configuration import validate_policy as validate_fixed_tamaraw_policy\n    fixed_tamaraw = validate_fixed_tamaraw_policy(tamaraw_configuration_policy)\n    if fixed_tamaraw is not None and (set(readiness) != {\"tamaraw\"} or scheduling is not None\n            or front_capture_amendment is not None or static_capture_amendment is not None\n            or qualification_delivery_compatibility is not None or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):\n",
             b"                 application_body_identity_policy: str | None = None,\n                 qualification_delivery_compatibility: Mapping[str, str] | None = None,\n                 tamaraw_configuration_policy: str | None = None,\n                 front_configuration_policy: str | None = None,\n                 selected_input_renewal: Path | None = None, class_indices=None, _context=None) -> Path:\n    from .application_response_policy import validate_application_body_identity_policy, application_body_identity_policy as declared_body_policy, COMPLETE_APPLICATION_DELIVERY_POLICY\n    body_policy = validate_application_body_identity_policy(application_body_identity_policy)\n    from .tamaraw_fixed_configuration import validate_policy as validate_fixed_tamaraw_policy\n    fixed_tamaraw = validate_fixed_tamaraw_policy(tamaraw_configuration_policy)\n    from .front_fixed_configuration import validate_policy as validate_fixed_front_policy\n    fixed_front = validate_fixed_front_policy(front_configuration_policy)\n    if fixed_front is not None and (set(readiness) != {\"front\"} or scheduling is not None\n            or fixed_tamaraw is not None or front_capture_amendment is not None\n            or static_capture_amendment is None or selected_input_renewal is not None\n            or qualification_delivery_compatibility is not None or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):\n        raise ValueError(\"fixed FRONT plan requires its own current serial full-graph amended canary\")\n    if fixed_tamaraw is not None and (set(readiness) != {\"tamaraw\"} or scheduling is not None\n            or front_capture_amendment is not None or static_capture_amendment is not None\n            or qualification_delivery_compatibility is not None or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):\n"),
            (b"                application_body_identity_policy=application_body_identity_policy,\n                qualification_delivery_compatibility=qualification_delivery_compatibility,\n                tamaraw_configuration_policy=tamaraw_configuration_policy,\n                selected_input_renewal=selected_input_renewal, class_indices=class_indices, _context=_context)\n    if _context is not None:\n        _context._enrollment(enrollment)\n",
             b"                application_body_identity_policy=application_body_identity_policy,\n                qualification_delivery_compatibility=qualification_delivery_compatibility,\n                tamaraw_configuration_policy=tamaraw_configuration_policy,\n                front_configuration_policy=front_configuration_policy,\n                selected_input_renewal=selected_input_renewal, class_indices=class_indices, _context=_context)\n    if _context is not None:\n        _context._enrollment(enrollment)\n"),
            (b"        if (fixed_tamaraw_policy(facts) != fixed_tamaraw\n            or fixed_tamaraw is not None and facts.get(\"tamaraw_configuration_sha256\") != configuration_sha256()):\n            raise ValueError(\"rolling plan differs from its canary's fixed Tamaraw condition\")\n        if facts.get(\"control_authority_witness\", facts.get(\"qualification_delivery_compatibility\")) != qualification_delivery_compatibility:\n            raise ValueError(\"rolling plan differs from its canary's qualification delivery witness\")\n        if static_amendment is not None:\n",
             b"        if (fixed_tamaraw_policy(facts) != fixed_tamaraw\n            or fixed_tamaraw is not None and facts.get(\"tamaraw_configuration_sha256\") != configuration_sha256()):\n            raise ValueError(\"rolling plan differs from its canary's fixed Tamaraw condition\")\n        from . import front_fixed_configuration as front\n        if (front.policy(facts) != fixed_front\n            or fixed_front is not None and facts.get(\"front_configuration_sha256\") != front.CONFIGURATION_SHA256):\n            raise ValueError(\"rolling plan differs from its canary's fixed FRONT condition\")\n        if facts.get(\"control_authority_witness\", facts.get(\"qualification_delivery_compatibility\")) != qualification_delivery_compatibility:\n            raise ValueError(\"rolling plan differs from its canary's qualification delivery witness\")\n        if static_amendment is not None:\n"),
            (b"        raw = _render_campaign(lane, sites, policy, buflo_duration_policy=duration_policy, capture_limits=effective_limits,\n                               application_body_identity_policy=application_body_identity_policy,\n                               qualification_delivery_compatibility=qualification_delivery_compatibility,\n                               tamaraw_configuration_policy=fixed_tamaraw)\n        if path.exists():\n            if lanes._read(path) != raw:\n                raise ValueError(\"rolling plan cannot replace an earlier campaign\")\n",
             b"        raw = _render_campaign(lane, sites, policy, buflo_duration_policy=duration_policy, capture_limits=effective_limits,\n                               application_body_identity_policy=application_body_identity_policy,\n                               qualification_delivery_compatibility=qualification_delivery_compatibility,\n                               tamaraw_configuration_policy=fixed_tamaraw,\n                               front_configuration_policy=fixed_front)\n        if path.exists():\n            if lanes._read(path) != raw:\n                raise ValueError(\"rolling plan cannot replace an earlier campaign\")\n"),
            (b"            declared_at=payload[\"declared_at\"], _context=_context)\n    if application_body_identity_policy is not None:\n        payload[\"application_body_identity_policy\"] = body_policy\n    if fixed_tamaraw is not None:\n        payload[\"tamaraw_configuration_policy\"] = fixed_tamaraw\n    if selected_reference is not None:\n",
             b"            declared_at=payload[\"declared_at\"], _context=_context)\n    if application_body_identity_policy is not None:\n        payload[\"application_body_identity_policy\"] = body_policy\n    if fixed_front is not None:\n        payload[\"front_configuration_policy\"] = fixed_front\n    if fixed_tamaraw is not None:\n        payload[\"tamaraw_configuration_policy\"] = fixed_tamaraw\n    if selected_reference is not None:\n"),
            (b"            subgroup.require_canary(reference, subgroup_value)\n    from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy\n    fixed_tamaraw = fixed_tamaraw_policy(value)\n    selected_reference = value.get(\"selected_input_renewal\")\n    if selected_reference is not None:\n        from . import rapid_selected_input_renewal as renewed\n",
             b"            subgroup.require_canary(reference, subgroup_value)\n    from .tamaraw_fixed_configuration import policy as fixed_tamaraw_policy\n    fixed_tamaraw = fixed_tamaraw_policy(value)\n    from . import front_fixed_configuration as front\n    fixed_front = front.policy(value)\n    if fixed_front is not None:\n        fields.add(front.FIELD)\n        if (set(value[\"readiness\"]) != {\"front\"} or \"scheduling\" in value\n            or \"static_capture_amendment\" not in value or fixed_tamaraw is not None\n            or any(key in value for key in (\"front_capture_amendment\", \"qualification_delivery_compatibility\", \"selected_input_renewal\"))\n            or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY):\n            raise ValueError(\"fixed FRONT plan changed its separate serial condition authority\")\n    selected_reference = value.get(\"selected_input_renewal\")\n    if selected_reference is not None:\n        from . import rapid_selected_input_renewal as renewed\n"),
            (b"                               capture_limits=value.get(\"capture_limits\"),\n                               application_body_identity_policy=value.get(\"application_body_identity_policy\"),\n                               qualification_delivery_compatibility=value.get(\"qualification_delivery_compatibility\"),\n                               tamaraw_configuration_policy=fixed_tamaraw)\n        if lanes._read(spec.campaign_dir / f\"{lane.campaign_name}.yml\") != raw:\n            raise ValueError(\"rolling campaign changed sites, graph, visits or fixed settings\")\n        actual.append({**asdict(lane), \"workload_ids\": list(lane.workload_ids), \"campaign_sha256\": lanes._sha(raw)})\n",
             b"                               capture_limits=value.get(\"capture_limits\"),\n                               application_body_identity_policy=value.get(\"application_body_identity_policy\"),\n                               qualification_delivery_compatibility=value.get(\"qualification_delivery_compatibility\"),\n                               tamaraw_configuration_policy=fixed_tamaraw,\n                               front_configuration_policy=fixed_front)\n        if lanes._read(spec.campaign_dir / f\"{lane.campaign_name}.yml\") != raw:\n            raise ValueError(\"rolling campaign changed sites, graph, visits or fixed settings\")\n        actual.append({**asdict(lane), \"workload_ids\": list(lane.workload_ids), \"campaign_sha256\": lanes._sha(raw)})\n"),
            (b"    if (fixed_tamaraw_policy(facts) != fixed_tamaraw_policy(payload)\n        or fixed_tamaraw_policy(payload) is not None and facts.get(\"tamaraw_configuration_sha256\") != configuration_sha256()):\n        raise ValueError(\"formal readiness changed its fixed Tamaraw condition\")\n    if facts.get(\"control_authority_witness\", facts.get(\"qualification_delivery_compatibility\")) != payload.get(\"qualification_delivery_compatibility\"):\n        raise ValueError(\"formal readiness changed its declared qualification delivery witness\")\n    if publication is not None and (admission._utc(publication) > admission._utc(payload[\"declared_at\"])\n",
             b"    if (fixed_tamaraw_policy(facts) != fixed_tamaraw_policy(payload)\n        or fixed_tamaraw_policy(payload) is not None and facts.get(\"tamaraw_configuration_sha256\") != configuration_sha256()):\n        raise ValueError(\"formal readiness changed its fixed Tamaraw condition\")\n    from . import front_fixed_configuration as front\n    if (front.policy(facts) != front.policy(payload)\n        or front.policy(payload) is not None and facts.get(\"front_configuration_sha256\") != front.CONFIGURATION_SHA256):\n        raise ValueError(\"formal readiness changed its fixed FRONT condition\")\n    if facts.get(\"control_authority_witness\", facts.get(\"qualification_delivery_compatibility\")) != payload.get(\"qualification_delivery_compatibility\"):\n        raise ValueError(\"formal readiness changed its declared qualification delivery witness\")\n    if publication is not None and (admission._utc(publication) > admission._utc(payload[\"declared_at\"])\n"),
            (b"                                    buflo_duration_policy=value.get(\"buflo_duration_policy\"),\n                                    application_body_identity_policy=value.get(\"application_body_identity_policy\"),\n                                    qualification_delivery_compatibility=value.get(\"qualification_delivery_compatibility\"),\n                                    tamaraw_configuration_policy=value.get(\"tamaraw_configuration_policy\") if lane.mode == \"tamaraw\" else None)\n    admission.durable_create(spec.campaign_dir / f\"{lane.campaign_name}.yml\", raw)\n    value = {**value, \"lanes\": [{**asdict(lane), \"workload_ids\": list(lane.workload_ids), \"campaign_sha256\": lanes._sha(raw)}],\n             \"planned_trace_count\": lane.sample_count, \"declared_at\": admission._now()}\n",
             b"                                    buflo_duration_policy=value.get(\"buflo_duration_policy\"),\n                                    application_body_identity_policy=value.get(\"application_body_identity_policy\"),\n                                    qualification_delivery_compatibility=value.get(\"qualification_delivery_compatibility\"),\n                                    tamaraw_configuration_policy=value.get(\"tamaraw_configuration_policy\") if lane.mode == \"tamaraw\" else None,\n                                    front_configuration_policy=value.get(\"front_configuration_policy\") if lane.mode == \"front\" else None)\n    admission.durable_create(spec.campaign_dir / f\"{lane.campaign_name}.yml\", raw)\n    value = {**value, \"lanes\": [{**asdict(lane), \"workload_ids\": list(lane.workload_ids), \"campaign_sha256\": lanes._sha(raw)}],\n             \"planned_trace_count\": lane.sample_count, \"declared_at\": admission._now()}\n"),
        )
        for before, after in reversed(edits):
            if raw.count(after) != 1:
                raise ValueError('rolling FRONT inverse is absent or ambiguous')
            raw = raw.replace(after, before, 1)
        if hashlib.sha256(raw).hexdigest() != quick_profile:
            raise ValueError('rolling FRONT inverse changes protected Source bytes')
        digest = quick_profile
    if digest not in {
            'b2d6be3fbc3ab2060bdfa683d372def0122669daa251b31c2000a759c4e4f610',
            '23e64994de9127aad06e952dae996d7e7b24fd5d44e5c5877eb658d845d64e9b',
            'a7a2302f4e835dcfe37b15278d624890065794673f7ee2182b18a9fd61e196e4',
            source52, source53, owned_check, quick_profile}:
        raise ValueError('rolling epoch dispatch is outside the exact published Source pair')
    if digest == quick_profile:
        # The new path is selected only by a quick-profile receipt. Restore
        # the complete Source57 reader before applying the older projection.
        additions = (
            b'    from . import rapid_quick_profile as quick\n'
            b'    if quick.is_plan(spec.plan_receipt):\n'
            b'        return quick.verify_plan(spec, _context=_context)\n',
            b'    from . import rapid_quick_profile as quick\n'
            b'    if quick.is_payload(payload):\n'
            b'        quick.require_worker(payload, lane, sites, spec)\n'
            b'        return payload["scheduling"]\n',
            b'    from . import rapid_quick_profile as quick\n'
            b'    if quick.is_plan(spec.plan_receipt):\n'
            b'        return quick.mount_roots(lanes.plan_payload(lanes._read(spec.plan_receipt))["scheduling"])\n',
            b'    from . import rapid_quick_profile as quick\n'
            b'    if quick.is_payload(payload):\n'
            b'        return quick.mount_roots(payload["scheduling"], _context=_context)\n',
        )
        for addition in additions:
            if raw.count(addition) != 1:
                raise ValueError('rolling quick dispatch is absent or duplicated')
            raw = raw.replace(addition, b'', 1)
        if hashlib.sha256(raw).hexdigest() != owned_check:
            raise ValueError('rolling quick dispatch changes protected Source bytes')
        digest = owned_check
    if digest == owned_check:
        def restore_once(changed, predecessor):
            nonlocal raw
            if raw.count(changed) != 1:
                raise ValueError('rolling owned check change is outside the reviewed bytes')
            raw = raw.replace(changed, predecessor, 1)
        def restore_span(first, following, expected_sha, predecessor):
            nonlocal raw
            if raw.count(first) != 1:
                raise ValueError('rolling owned check changed-unit start is absent or duplicated')
            begin = raw.index(first)
            end = raw.find(following, begin)
            if end < 0 or hashlib.sha256(raw[begin:end]).hexdigest() != expected_sha:
                raise ValueError('rolling owned check changed-unit bytes differ')
            raw = raw[:begin] + predecessor + raw[end:]
        restore_once(b'import json\nimport secrets\nimport subprocess\n', b'import json\nimport subprocess\n')
        restore_once(
            b'def lane_check_command(spec: lanes.CaptureSpec, root: Path, target: Path, *, complete: bool,\n'
            b'                       operation_token: str | None = None, _context=None) -> list[str]:\n',
            b'def lane_check_command(spec: lanes.CaptureSpec, root: Path, target: Path, *, complete: bool, _context=None) -> list[str]:\n')
        restore_span(
            b'    if operation_token is not None:\n', b'    command[-2:] = [LANE_CHECK_SCRIPT',
            'a26cda839884f649d51024d33c11893ca6efebd7a65543c4dada4e79f65eef0e', b'')
        restore_once(
            b'    """Run the unchanged ordinary deep verifier in the actual bound image."""\n'
            b'    _, plan_payload = verify_capture_plan(spec, _context=_context)\n',
            b'    """Run the unchanged ordinary deep verifier in the actual bound image."""\n'
            b'    verify_capture_plan(spec, _context=_context)\n')
        restore_span(
            b'    lane = lanes._lane({"plan_payload": plan_payload}, target.parent.name)\n'
            b'    # One installed plan/source allowance plus one frozen capture timeout per trace.\n',
            b'    if _context is not None:\n',
            '83a113e6e392ba6fb2d3d6a5a276b1476d912fdecee4e1d0bc11764da06e1a07',
            b'    command = lane_check_command(spec, root, target, complete=complete, _context=_context)\n')
        restore_span(
            b'    parent = root / "lane-checks"\n', b'    start_path = directory / "actual-started.json"\n',
            '67b4667c7cc77b7e85cc78ca754e315cea47af7556004339368304b5c1011372',
            b'    start = {"command": command, "started_at": admission._now()}\n'
            b'    directory = root / "lane-checks" / lanes._sha(admission._json(start))\n'
            b'    directory.mkdir(parents=True)\n')
        restore_once(b'                                check=False, timeout=timeout_seconds)\n',
                     b'                                check=False, timeout=600)\n')
        restore_span(
            b'    except subprocess.TimeoutExpired as failure:\n',
            b'    except (OSError, subprocess.SubprocessError) as failure:\n',
            '06e27c63afdae1235d355aa12a2c0117f8dd35ac119da5a9b6d080bb657c9000', b'')
        restore_once(b'           "operation_token": operation_token, "timeout_seconds": timeout_seconds,\n', b'')
        restore_span(
            b'    _, plan_payload = verify_capture_plan(spec)\n'
            b'    started_path, completed_path = _open_ref(value["started"]), _open_ref(value["completed"])\n',
            b'        or type(end["returncode"]) is not int or end["returncode"] != 0 or end["invocation_error"] is not None\n',
            '1e7459fd1317ad2847ddd3c9d55337af572c632d8ead6bf648ec91f7de3e352f',
            b'    verify_capture_plan(spec)\n'
            b'    start = lanes._load(lanes._read(_open_ref(value["started"])))\n'
            b'    end = lanes._load(lanes._read(_open_ref(value["completed"])))\n'
            b'    command = lane_check_command(spec, root, target, complete=value["complete"])\n'
            b'    if (set(start) != {"command", "started_at"} or set(end) != {"command", "started_at", "completed_at", "returncode", "invocation_error", "stdout", "stderr"}\n'
            b'        or start["command"] != command or end["command"] != command or end["started_at"] != start["started_at"]\n')
        if hashlib.sha256(raw).hexdigest() != source53:
            raise ValueError('rolling owned check changes bytes outside reviewed operational units')
        digest = source53
    if digest == source53:
        reviewed = (
            b'# Completion just deep-verified this result; the host reopens its sealed bytes.\n'
            b"print(json.dumps({'receipt':str(receipt),'facts':e.verify_launch_receipt(\n"
            b"    receipt,spec=spec,evidence_root=root,_manifest_already_deep_verified=value['complete'])},\n"
            b'    sort_keys=True,allow_nan=False))'
        )
        predecessor = (
            b"print(json.dumps({'receipt':str(receipt),'facts':e.verify_launch_receipt("
            b'receipt,spec=spec,evidence_root=root)},sort_keys=True,allow_nan=False))'
        )
        if raw.count(reviewed) != 1:
            raise ValueError('rolling installed deep change is outside the exact reviewed script')
        raw = raw.replace(reviewed, predecessor, 1)
        if hashlib.sha256(raw).hexdigest() != source52:
            raise ValueError('rolling installed deep change alters other Source bytes')
    tree = ast.parse(raw)
    names = {'image_plan_check', 'validate_host_launch', 'publish_successor', 'enrollment_roots',
             'require_mode_readiness'}
    found = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            if node.name in found: raise ValueError('rolling epoch dispatch definition is duplicated')
            found.add(node.name); node.body = [ast.Pass()]
    if found != names: raise ValueError('rolling epoch dispatch definition set is incomplete')
    return _planning_source_projection(ast.unparse(tree).encode())


def _parallel_facts_source_projection(raw):
    """Retain every Facts unit except exact reviewed action-local dispatches."""
    import ast
    digest = hashlib.sha256(raw).hexdigest()
    quick_profile = 'b71aeb8ea29056d13c1153ea16cd3d1445d8ca355c7e4e1928df5dfa560449f8'
    if digest == '0e6889b169b647048718107230e7a2c1f6c3c2171c16dfb2f327895b964c3938':
        before = b'        if isinstance(item, dict) and item.get("artifact_type") == quick.CAPSULE_TYPE:\n'
        after = b'        if quick.is_profile(item):\n'
        if raw.count(after) != 1:
            raise ValueError('Facts explicit-mode dispatch is absent or duplicated')
        raw = raw.replace(after, before, 1)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != quick_profile:
            raise ValueError('Facts explicit-mode dispatch changes protected Source bytes')
    if digest == quick_profile:
        additions = (
            b'        from . import rapid_quick_profile as quick\n'
            b'        if isinstance(item, dict) and item.get("artifact_type") == quick.CAPSULE_TYPE:\n'
            b'            for reference in item["material_files"]:\n'
            b'                self._reference(reference)\n'
            b'            return\n'
            b'        if isinstance(item, dict) and item.get("receipt_type") == quick.PLAN_TYPE:\n'
            b'            quick.validate_profile(item["payload"]["scheduling"], _context=self)\n'
            b'            return\n',
            b'        from . import rapid_quick_profile as quick\n'
            b'        if quick.is_plan(spec.plan_receipt):\n'
            b'            quick.bind(spec, self)\n'
            b'            return\n',
        )
        for addition in additions:
            if raw.count(addition) != 1:
                raise ValueError('Facts quick dispatch is absent or duplicated')
            raw = raw.replace(addition, b'', 1)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != '304a383d7c7cb17cc6dfb4c366e7cb195f9369bd262fdb57dc99a9c64fdce3d6':
            raise ValueError('Facts quick dispatch changes protected Source bytes')
    if digest not in {
            'ffd0ce58b57a2a94cd974573e79064fc4c69d62f99b586d5449b1424bc86973d',
            'e667bfab9ef36467211c3d4a9227da0db55264bc262295751b281e0a2f156fe4',
            '304a383d7c7cb17cc6dfb4c366e7cb195f9369bd262fdb57dc99a9c64fdce3d6'}:
        raise ValueError('operation Facts dispatch is outside the exact old/new Source pair')
    tree = ast.parse(raw); found = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == 'OperationFacts':
            for method in node.body:
                if isinstance(method, ast.FunctionDef) and method.name in {'bind_schedule', '_enrollment'}:
                    if method.name in found:
                        raise ValueError('operation Facts reviewed dispatch is duplicated')
                    found.add(method.name); method.body = [ast.Pass()]
                    if method.name == '_enrollment':
                        # The reused per-class proof is returned at runtime;
                        # this annotation alone carries no scientific guard.
                        method.returns = None
    if found != {'bind_schedule', '_enrollment'}:
        raise ValueError('operation Facts reviewed dispatch is absent or duplicated')
    return ast.dump(tree, include_attributes=False).encode()


def _parallel_schedule_source_projection(raw):
    """Retain every scheduling unit except the exact typed adapter dispatches."""
    import ast
    digest = hashlib.sha256(raw).hexdigest()
    if digest == '925cc2c7d76e4c76f63b0c298ae10126f79eee70a74a708e631af0932f0fe2c6':
        replacements = (
            (b'    if quick.is_profile(value):\n', b'    if isinstance(value, dict) and value.get("artifact_type") == quick.CAPSULE_TYPE:\n', 1),
            (b'    if quick.is_profile(capsule):\n', b'    if capsule["artifact_type"] == quick.CAPSULE_TYPE:\n', 2),
        )
        for after, before, count in replacements:
            if raw.count(after) != count:
                raise ValueError('scheduling explicit-mode dispatch is absent or duplicated')
            raw = raw.replace(after, before)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != '3563882347e3ddb2df93846538bc8f95c833b158b62435964f35586046d03f5b':
            raise ValueError('scheduling explicit-mode dispatch changes protected Source bytes')
    if digest == '3563882347e3ddb2df93846538bc8f95c833b158b62435964f35586046d03f5b':
        additions = (
            b'    from . import rapid_quick_profile as quick\n'
            b'    if isinstance(value, dict) and value.get("artifact_type") == quick.CAPSULE_TYPE:\n'
            b'        return quick.validate_profile(reference, runtime=runtime, before=before, _context=_context)\n',
            b'    from . import rapid_quick_profile as quick\n'
            b'    if capsule["artifact_type"] == quick.CAPSULE_TYPE:\n'
            b'        qualification._validate_implementation_receipt(current_impl, require_current=False)\n'
            b'        if (actual_image != capsule["runtime"]["collection_image_digest"]\n'
            b'            or current_impl["source"] != capsule["source"]\n'
            b'            or old_impl["neqo_qcsd_client"]["sha256"] != capsule["client_sha256"]\n'
            b'            or current_impl["neqo_qcsd_client"]["sha256"] != capsule["client_sha256"]):\n'
            b'            raise ValueError("quick setting changed its qualified Native818 client or current installed source")\n'
            b'        return\n',
            b'    from . import rapid_quick_profile as quick\n'
            b'    if capsule["artifact_type"] == quick.CAPSULE_TYPE:\n'
            b'        return quick.mount_roots(reference, _context=_context)\n',
        )
        for addition in additions:
            if raw.count(addition) != 1:
                raise ValueError('quick scheduling dispatch is absent or duplicated')
            raw = raw.replace(addition, b'', 1)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != '15b423aa04fe942fc08b3b61e26973b1cd3473363184e5660c1f02c27b4b5ddb':
            raise ValueError('quick scheduling dispatch changes protected Source bytes')
    if digest not in {
            '2137c31db996a12e7269dae82b008982281d118304fe984feb44c5eefdf01d77',
            '15b423aa04fe942fc08b3b61e26973b1cd3473363184e5660c1f02c27b4b5ddb'}:
        raise ValueError('scheduling reader dispatch is outside the exact old/new Source pair')
    tree = ast.parse(raw); found = set()
    names = {'validate_schedule', 'validate_qualification_reuse', 'validate_ready_canary', 'mount_roots'}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            if node.name in found:
                raise ValueError('scheduling adapter dispatch definition is duplicated')
            found.add(node.name); node.body = [ast.Pass()]
    if found != names:
        raise ValueError('scheduling adapter dispatch definition set is incomplete')
    return ast.dump(tree, include_attributes=False).encode()


def _membership_code_path(path, target_source):
    package = Path(target_source['path']).parent
    if path.parent == package and path.suffix == '.py':
        return 'src/qcsd_lab/' + path.name
    if package.parent.name == 'src':
        root = package.parent.parent
        if path.is_relative_to(root / 'tools') and path.suffix == '.py':
            return path.relative_to(root).as_posix()
    return None


def _acquisition_reader_sources():
    """Authenticate this one prospective reader set before historical reuse."""
    sources = {
        'rapid_selected_capture_input.py': '72933db93fef22fd599dce35b2ae27dd2f525b112bc6140134540d1f1cad1fb1',
        'rapid_selected_budget_input.py': '3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb',
        'rapid_per_class_selected_enrollment.py': '4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0',
        'whole_graph_input.py': '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',
        'whole_graph_supplement.py': 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98',
        'rapid_supplemental_cohort.py': '2391723d90e339680c9d6b7d0ce31ab84b437f1a963ed1b166eb1237a49ed091',
    }
    _open(reference(Path(__file__)))
    result = {}
    for name, sha in sources.items():
        item = reference(Path(__file__).parent / name)
        _open(item)
        if item['sha256'] != sha or item['mode'] != 0o644:
            raise ValueError('historical acquisition reader is outside the exact prospective Source set')
        result['src/qcsd_lab/' + name] = item
    return result


def _v13_input_reader_source_projection(raw):
    """Restore every Source62 byte after finite prospective V13 registration."""
    if hashlib.sha256(raw).hexdigest() == '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8':
        current = b"    value = get._load(get._read(path))\n    plan_path = reopen(value[\"plan\"])\n    plan = get._load(get._read(plan_path))\n    if isinstance(plan, dict) and plan.get(\"artifact_type\") == V13_PLAN_TYPE:\n        operator = _producer(plan)\n        if (not zero(plan) or path.name != \"failed.json\" or not zero(value)\n                or value.get(\"candidate\") not in plan[\"candidates\"]\n                or value.get(\"outcome\") != \"operational-discovery-failure-no-admission\"):\n            raise ValueError(\"V13 discovery failure changes its declared zero-credit role\")\n        _verify_external(operator, \"verify-failure\", \"--failure\", path.absolute(), timeout=None)\n        return value\n    plan = load_plan(plan_path)\n    if plan[\"schema_version\"] >= 4:\n"
        original = b"    value = get._load(get._read(path))\n    plan = load_plan(reopen(value[\"plan\"]))\n    if plan[\"schema_version\"] == 13:\n        if (path.name != \"failed.json\" or not zero(value)\n                or value.get(\"candidate\") not in plan[\"candidates\"]\n                or value.get(\"outcome\") != \"operational-discovery-failure-no-admission\"):\n            raise ValueError(\"V13 discovery failure changes its declared zero-credit role\")\n        _verify_external(_producer(plan), \"verify-failure\", \"--failure\", path.absolute(), timeout=None)\n        return value\n    if plan[\"schema_version\"] >= 4:\n"
        if raw.count(current) != 1:
            raise ValueError('closed HOST V13 failure reader hunk is not unique')
        raw = raw.replace(current, original, 1)
        if hashlib.sha256(raw).hexdigest() != '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c':
            raise ValueError('closed HOST failure reader changes protected V13 bytes')
    if hashlib.sha256(raw).hexdigest() not in ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',
            '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c'):
        raise ValueError('V13 discovery reader is outside its exact reviewed Source')
    start, end = b'V13_PLAN_TYPE = ', b'ZERO = '
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError('V13 registration block is not unique')
    projected = raw[:raw.index(start)] + raw[raw.index(end):]
    additions = (
        b"    if version[0] == 13:\n        if any(paths[name].parent != paths[\"operator.py\"].parent or paths[name].name != name\n                for name in producers):\n            raise ValueError(\"V13 discovery producer files have another name or location\")\n        return paths[\"operator.py\"]\n",
        b"    if plan[\"schema_version\"] == 13:\n        if (path.name != \"failed.json\" or not zero(value)\n                or value.get(\"candidate\") not in plan[\"candidates\"]\n                or value.get(\"outcome\") != \"operational-discovery-failure-no-admission\"):\n            raise ValueError(\"V13 discovery failure changes its declared zero-credit role\")\n        _verify_external(_producer(plan), \"verify-failure\", \"--failure\", path.absolute(), timeout=None)\n        return value\n",
        b"        if declaration[\"schema_version\"] == 13:\n            if declaration[\"previous_plan\"] is not None:\n                plan(declaration[\"previous_plan\"])\n                batch = ref(declaration[\"previous_batch\"])\n                sources.add(batch.parent)\n                for item in sorted(batch.parent.rglob(\"*\")):\n                    if item.is_symlink():\n                        raise ValueError(\"V13 preceding batch has a linked raw member\")\n                    if item.is_file():\n                        files.add(item)\n            return\n",
        b"def _v13_dependencies(value: Any, ref) -> None:\n    \"\"\"Retain every explicit resolution and recorded HOST validation reference.\"\"\"\n    if isinstance(value, dict):\n        if set(value) == {\"path\", \"sha256\", \"mode\"}:\n            ref(value)\n        else:\n            for item in value.values():\n                _v13_dependencies(item, ref)\n    elif isinstance(value, list):\n        for item in value:\n            _v13_dependencies(item, ref)\n\n\n",
        b"    if value[\"schema_version\"] == 13:\n        canonical = ref(value[\"canonical_homepage\"])\n        _v13_dependencies(get._load(get._read(canonical)), ref)\n        validation = ref(value[\"host_validation\"])\n        validated = get._load(get._read(validation))\n        _v13_dependencies(validated, ref)\n        sources = sorted({*sources, *(Path(root) for root in validated[\"dependency_fence\"][\"trees\"])})\n        _v13_dependencies(value[\"attempt_inventory\"], ref)\n",
    )
    for addition in additions:
        if projected.count(addition) != 1:
            raise ValueError('V13 registration changed another original reader unit')
        projected = projected.replace(addition, b'', 1)
    replacements = (
        (b"timeout: int | None = 60", b"timeout: int = 60"),
        (b"**({\"timeout\": None} if value[\"schema_version\"] == 13 else\n           {\"timeout\": 240} if value[\"schema_version\"] in (8, 9, 10, 11, 12) else {}))", b"**({\"timeout\": 240} if value[\"schema_version\"] in (8, 9, 10, 11, 12) else {}))"),
        (b"**({\"timeout\": None} if version[0] == 13 else\n           {\"timeout\": 240} if version[0] in (8, 9, 10, 11, 12) else {}))", b"**({\"timeout\": 240} if version[0] in (8, 9, 10, 11, 12) else {}))"),
        (b"if declaration[\"schema_version\"] >= 5 and declaration[\"schema_version\"] != 13:", b"if declaration[\"schema_version\"] >= 5:"),
        (b"elif value[\"schema_version\"] >= 2:", b"if value[\"schema_version\"] >= 2:"),
    )
    for current, original in replacements:
        if projected.count(current) != 1:
            raise ValueError('V13 dispatch changed another original reader unit')
        projected = projected.replace(current, original, 1)
    if hashlib.sha256(projected).hexdigest() != '5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5':
        raise ValueError('V13 reader changes protected Source62 graph or proof bytes')
    return projected


def _source65_selected_input_source_projection(raw):
    """Restore every Source65 byte after exact selected GET reader registration."""
    digest = hashlib.sha256(raw).hexdigest()
    if digest == 'ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442':
        return raw
    if digest != '72933db93fef22fd599dce35b2ae27dd2f525b112bc6140134540d1f1cad1fb1':
        raise ValueError('selected GET reader is outside its exact Source65/66 pair')
    replacements = (
        (b"    historical.append(source44)\n    source65 = {\n        'qcsd_lab.application_response_policy': '817e48d727bcb5b056f37582c8c469af7070deabbd367571c2ea05b9f36ac49a',\n        'qcsd_lab.rapid_additive_static_enrollment': '5404821bf1bf087493d60076d33c5769748052f6301c352dccc6dae61e630670',\n        plain_name: 'ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442',\n        'qcsd_lab.supplied_static_bootstrap_get': '4a53baeb9f66220b6108ea304f54dd834fc447a4cc43f58a358de018b421f692',\n        'qcsd_lab.supplied_static_get': 'ce20fe5b5d60f7b268b7eb659ab56e98048d5934bc9cb3b456e2ef99c330d322',\n        'qcsd_lab.supplied_static_graph': '87370d25d526a22cac7519a721aed0db19b72fa5957a353301782779409d4efa',\n        'qcsd_lab.supplied_static_preparation': '087ebcea7cf8c793a82cbf40bcb0e77fb1555ba50b648c02af85e52c76641f44',\n        whole_name: '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0',\n    }\n    if budget_name in expected:\n        source65[budget_name] = '3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb'\n        source65['qcsd_lab.supplied_static_budget_successor'] = 'a297fd337517ddffc30fc6e08b5961e2556f9311cbe5f7837baa0209bcf298d1'\n    if (recorded == source65 and expected == {**source65,\n            plain_name: expected[plain_name],\n            whole_name: 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98'}):\n        historical.append(source65)\n", b"    historical.append(source44)\n"),
        (b"def _selected_get_manifests(value: Mapping[str, Any], declaration: Mapping[str, Any],\n                            neutral: dict) -> tuple[dict, dict]:\n    \"\"\"Reconstruct the exact recorded full-GET policy, without promoting V1.\"\"\"\n    if value[\"original_role\"] == whole.ROLE:\n        policy = whole._declaration_manifest_policy(declaration)\n        if (declaration[\"schema_version\"] == 2\n                and declaration[\"producer_sources\"] != whole.producer_sources()):\n            raise ValueError(\"selected required-parent GET changes its exact prospective producer\")\n        return whole._manifests(neutral, policy=policy)\n    primary = {\"resources\": [deepcopy(neutral[\"resources\"][0])]}\n    full = deepcopy(neutral)\n    full[\"resources\"][0][\"known_valid\"] = True\n    return primary, full\n\n\ndef _raw_selected_proof(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict:\n", b"def _raw_selected_proof(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict:\n"),
        (b"    primary, full = _selected_get_manifests(value, declaration, neutral)\n    if (declaration[\"neutral_input_sha256\"] != graph.digest(graph.canonical_bytes(neutral))\n", b"    primary = {\"resources\": [deepcopy(neutral[\"resources\"][0])]}\n    full = deepcopy(neutral)\n    full[\"resources\"][0][\"known_valid\"] = True\n    if (declaration[\"neutral_input_sha256\"] != graph.digest(graph.canonical_bytes(neutral))\n"),
    )
    for current, original in replacements:
        if raw.count(current) != 1:
            raise ValueError('selected GET registration changes another original reader unit')
        raw = raw.replace(current, original, 1)
    if hashlib.sha256(raw).hexdigest() != 'ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442':
        raise ValueError('selected GET reader changes protected Source65 proof or graph bytes')
    return raw


def _required_parent_get_source_projection(raw):
    """Restore every Source64 byte after the exact versioned probe registration."""
    digest = hashlib.sha256(raw).hexdigest()
    if digest == '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0':
        return raw
    if digest != 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98':
        raise ValueError('required-parent GET reader is outside its exact Source pair')
    replacements = (
        (b"RECEIPT_TYPE = \"qcsd-whole-occurrence-independent-get-preparation-v1\"\nNAMESPACE_TYPE = \"qcsd-whole-occurrence-recorded-get-execution-v1\"\n\nLEGACY_MANIFEST_POLICY = \"primary-only-known-valid-full-get-input-v1\"\nREQUIRED_PARENT_MANIFEST_POLICY = \"required-2xx-roots-and-dependency-parents-terminal-auxiliary-leaves-v1\"\n\nclass PreparationIneligible(ValueError):\n    \"\"\"A closed complete GET fails a specified whole-graph admission property.\"\"\"\n", b"RECEIPT_TYPE = \"qcsd-whole-occurrence-independent-get-preparation-v1\"\nNAMESPACE_TYPE = \"qcsd-whole-occurrence-recorded-get-execution-v1\"\n\n\nclass PreparationIneligible(ValueError):\n    \"\"\"A closed complete GET fails a specified whole-graph admission property.\"\"\"\n"),
        (b"        'qcsd_lab.whole_graph_input': input_sha,\n        'qcsd_lab.whole_graph_supplement': supplement_sha}\n        for input_sha, supplement_sha in (\n            ('7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c',\n             '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0'),\n            ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n             '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'),\n            ('5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5',\n", b"        'qcsd_lab.whole_graph_input': input_sha,\n        'qcsd_lab.whole_graph_supplement': supplement_sha}\n        for input_sha, supplement_sha in (\n            ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n             '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'),\n            ('5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5',\n"),
        (b"    return row, ref, value, neutral\n\n\ndef _manifests(neutral: dict, *, policy: str = LEGACY_MANIFEST_POLICY) -> tuple[dict, dict]:\n    if policy not in {LEGACY_MANIFEST_POLICY, REQUIRED_PARENT_MANIFEST_POLICY}:\n        raise ValueError(\"whole graph GET manifest policy is unsupported\")\n    primary = {\"resources\": [deepcopy(neutral[\"resources\"][0])]}\n    full = deepcopy(neutral)\n    if policy == LEGACY_MANIFEST_POLICY:\n        full[\"resources\"][0][\"known_valid\"] = True\n    else:\n        from .application_response_policy import terminal_http_error_resource_allowed\n        resources = neutral[\"resources\"]\n        if any(row.get(\"known_valid\") is not False or row.get(\"chaff_priority\") is not False\n               for row in resources):\n            raise ValueError(\"whole graph GET requires an unchanged neutral input\")\n        # These flags require 2xx completion; they do not claim qualification.\n        # Only dependent auxiliary leaves may complete with terminal 4xx/5xx.\n        for row in full[\"resources\"]:\n            row[\"known_valid\"] = not terminal_http_error_resource_allowed(row, resources)\n    return primary, full\n\n\ndef _declaration_manifest_policy(declaration: Any) -> str:\n    if not isinstance(declaration, dict) or type(declaration.get(\"schema_version\")) is not int:\n        raise ValueError(\"whole graph GET declaration version is invalid\")\n    if declaration[\"schema_version\"] == 1 and \"manifest_policy\" not in declaration:\n        return LEGACY_MANIFEST_POLICY\n    if (declaration[\"schema_version\"] == 2\n            and declaration.get(\"manifest_policy\") == REQUIRED_PARENT_MANIFEST_POLICY):\n        return REQUIRED_PARENT_MANIFEST_POLICY\n    raise ValueError(\"whole graph GET declaration manifest policy is invalid\")\n\n\ndef _execution_root(root: Path, namespace: Any, expected: dict, *, failed_phase=None):\n    if namespace is None:\n        return root\n", b"    return row, ref, value, neutral\n\n\ndef _manifests(neutral: dict) -> tuple[dict, dict]:\n    primary = {\"resources\": [deepcopy(neutral[\"resources\"][0])]}\n    full = deepcopy(neutral)\n    full[\"resources\"][0][\"known_valid\"] = True\n    return primary, full\n\n\ndef _execution_root(root: Path, namespace: Any, expected: dict, *, failed_phase=None):\n    if namespace is None:\n        return root\n"),
        (b"\ndef _declaration(root: Path, context: Context, position: int) -> tuple[dict, dict, dict, dict, dict]:\n    row, ref, input_value, neutral = _candidate_input(context, position)\n    raw = get._read(root / \"declaration.json\")\n    declaration = get._load(raw)\n    policy = _declaration_manifest_policy(declaration)\n    primary, full = _manifests(neutral, policy=policy)\n    get._exact(declaration, {\"schema_version\", \"record_type\", \"declared_at\", \"context\", \"position\", \"candidate_id\", \"domain\",\n        \"graph_input\", \"discovery_runtime\", \"runtime_binding\", \"producer_sources\", \"neutral_input_sha256\",\n        \"bootstrap_input_sha256\", \"full_input_sha256\", \"max_response_bytes\", \"timeout_seconds\", \"primary_claim\",\n        \"public_origin_policy\", *inputs.ZERO,\n        *({\"manifest_policy\"} if declaration[\"schema_version\"] == 2 else set())}, \"whole graph GET declaration\")\n    expected = context.provenance[\"runtime_binding\"]\n    if (declaration[\"record_type\"] != PROOF_TYPE or not inputs.zero(declaration)\n            or declaration[\"schema_version\"] == 2 and declaration[\"producer_sources\"] != producer_sources()\n            or declaration[\"context\"] != original.reference(context.root / \"provenance.json\")\n            or type(declaration[\"position\"]) is not int or declaration[\"position\"] != position\n            or declaration[\"candidate_id\"] != row[\"candidate_id\"] or declaration[\"domain\"] != row[\"domain\"]\n", b"\ndef _declaration(root: Path, context: Context, position: int) -> tuple[dict, dict, dict, dict, dict]:\n    row, ref, input_value, neutral = _candidate_input(context, position)\n    primary, full = _manifests(neutral)\n    raw = get._read(root / \"declaration.json\")\n    declaration = get._load(raw)\n    get._exact(declaration, {\"schema_version\", \"record_type\", \"declared_at\", \"context\", \"position\", \"candidate_id\", \"domain\",\n        \"graph_input\", \"discovery_runtime\", \"runtime_binding\", \"producer_sources\", \"neutral_input_sha256\",\n        \"bootstrap_input_sha256\", \"full_input_sha256\", \"max_response_bytes\", \"timeout_seconds\", \"primary_claim\",\n        \"public_origin_policy\", *inputs.ZERO}, \"whole graph GET declaration\")\n    expected = context.provenance[\"runtime_binding\"]\n    if (type(declaration[\"schema_version\"]) is not int or declaration[\"schema_version\"] != 1\n            or declaration[\"record_type\"] != PROOF_TYPE or not inputs.zero(declaration)\n            or declaration[\"context\"] != original.reference(context.root / \"provenance.json\")\n            or type(declaration[\"position\"]) is not int or declaration[\"position\"] != position\n            or declaration[\"candidate_id\"] != row[\"candidate_id\"] or declaration[\"domain\"] != row[\"domain\"]\n"),
        (b"        get.util.require_disjoint_path(root, [protected], label=\"whole graph GET output\")\n    root.mkdir(mode=0o700, parents=False, exist_ok=False)\n    (root / \"bootstrap\").mkdir(mode=0o700)\n    primary, full = _manifests(neutral, policy=REQUIRED_PARENT_MANIFEST_POLICY)\n    get._json(root / \"neutral-input.json\", neutral)\n    get._json(root / \"runtime.json\", runtime)\n    declaration = {\"schema_version\": 2, \"record_type\": PROOF_TYPE,\n        \"manifest_policy\": REQUIRED_PARENT_MANIFEST_POLICY, \"declared_at\": datetime.now(UTC).isoformat(),\n        \"context\": original.reference(context.root / \"provenance.json\"), \"position\": position, \"candidate_id\": row[\"candidate_id\"],\n        \"domain\": row[\"domain\"], \"graph_input\": ref, \"discovery_runtime\": value[\"runtime\"], \"runtime_binding\": expected,\n        \"producer_sources\": producer_sources(), \"neutral_input_sha256\": graph.digest(graph.canonical_bytes(neutral)),\n", b"        get.util.require_disjoint_path(root, [protected], label=\"whole graph GET output\")\n    root.mkdir(mode=0o700, parents=False, exist_ok=False)\n    (root / \"bootstrap\").mkdir(mode=0o700)\n    primary, full = _manifests(neutral)\n    get._json(root / \"neutral-input.json\", neutral)\n    get._json(root / \"runtime.json\", runtime)\n    declaration = {\"schema_version\": 1, \"record_type\": PROOF_TYPE, \"declared_at\": datetime.now(UTC).isoformat(),\n        \"context\": original.reference(context.root / \"provenance.json\"), \"position\": position, \"candidate_id\": row[\"candidate_id\"],\n        \"domain\": row[\"domain\"], \"graph_input\": ref, \"discovery_runtime\": value[\"runtime\"], \"runtime_binding\": expected,\n        \"producer_sources\": producer_sources(), \"neutral_input_sha256\": graph.digest(graph.canonical_bytes(neutral)),\n"),
    )
    for current, original in replacements:
        if raw.count(current) != 1:
            raise ValueError('required-parent GET inverse is absent or duplicated')
        raw = raw.replace(current, original, 1)
    if hashlib.sha256(raw).hexdigest() != '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0':
        raise ValueError('required-parent GET changes protected Source64 bytes')
    return raw


def _v13_cohort_reader_source_projection(raw):
    if hashlib.sha256(raw).hexdigest() == '2391723d90e339680c9d6b7d0ce31ab84b437f1a963ed1b166eb1237a49ed091':
        addition = b"    }, {\n        \"qcsd_lab.whole_graph_input\": \"7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c\",\n        \"qcsd_lab.whole_graph_supplement\": \"dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98\",\n        \"qcsd_lab.rapid_per_class_selected_enrollment\": \"4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0\",\n        \"qcsd_lab.rapid_supplemental_cohort\": \"e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad\",\n"
        if raw.count(addition) != 1:
            raise ValueError('retained SDK973 cohort reader family is not unique')
        raw = raw.replace(addition, b'', 1)
        if hashlib.sha256(raw).hexdigest() != 'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad':
            raise ValueError('SDK973 cohort registration changes protected bytes')
    """Restore exact Source62 bytes after its finite cohort reader recognition."""
    if hashlib.sha256(raw).hexdigest() == 'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad':
        addition = b"    }, {\n        \"qcsd_lab.whole_graph_input\": \"7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c\",\n        \"qcsd_lab.whole_graph_supplement\": \"4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0\",\n        \"qcsd_lab.rapid_per_class_selected_enrollment\": \"4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0\",\n        \"qcsd_lab.rapid_supplemental_cohort\": \"c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d\",\n"
        if raw.count(addition) != 1:
            raise ValueError('retained Source64 cohort reader family is not unique')
        raw = raw.replace(addition, b'', 1)
        if hashlib.sha256(raw).hexdigest() != 'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d':
            raise ValueError('Source64 cohort registration changes protected bytes')
    if hashlib.sha256(raw).hexdigest() not in ('39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',
            'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d'):
        raise ValueError('V13 cohort reader is outside its exact reviewed Source')
    start, end = b'def _recognized_reader_sources(', b'def is_context('
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError('Source62 cohort reader recognition is not unique')
    projected = raw[:raw.index(start)] + raw[raw.index(end):]
    current = b'or not _recognized_reader_sources(value["reader_sources"])'
    original = b'or value["reader_sources"] != reader_sources()'
    if projected.count(current) != 1:
        raise ValueError('Source62 cohort reader recognition changed another context guard')
    projected = projected.replace(current, original, 1)
    if hashlib.sha256(projected).hexdigest() != '12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be':
        raise ValueError('V13 cohort reader changes protected admission or graph bytes')
    return projected


def _v13_supplement_reader_source_projection(raw):
    """Recover exact Source62 bytes after adding its retained GET context pair."""
    if hashlib.sha256(raw).hexdigest() == 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98':
        raw = _required_parent_get_source_projection(raw)
    if hashlib.sha256(raw).hexdigest() not in ('293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b',
            '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0'):
        raise ValueError('V13 supplement reader is outside its exact reviewed Source')
    additions = (
        b"            ('5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5',\n"
        b"             '164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7'),\n",
        b"            ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n"
        b"             '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'),\n",
    )
    projected = raw
    for addition in additions:
        if projected.count(addition) > 1:
            raise ValueError('retained whole-GET reader pair is not unique')
        projected = projected.replace(addition, b'', 1)
    if hashlib.sha256(projected).hexdigest() != '164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7':
        raise ValueError('V13 supplement reader changes protected GET or graph bytes')
    return projected


def _v12_input_reader_source_projection(raw):
    """Recover every exact V11 reader byte after finite V12 registration."""
    if hashlib.sha256(raw).hexdigest() in ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',
            '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',
            '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c'):
        raw = _v13_input_reader_source_projection(raw)
    if hashlib.sha256(raw).hexdigest() != '5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5':
        raise ValueError('V12 discovery reader is outside its exact reviewed Source')
    start, end = b'V12_PLAN_TYPE = ', b'ZERO = '
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError('V12 registration block is not unique')
    projected = raw[:raw.index(start)] + raw[raw.index(end):]
    replacements = (
        (b'(9, 10, 11, 12)', b'(9, 10, 11)', 2),
        (b'(8, 9, 10, 11, 12)', b'(8, 9, 10, 11)', 2),
        (b'action_sources = (V9_ACTION_SOURCES if version[0] == 9 else\n                              V10_ACTION_SOURCES if version[0] == 10 else\n                              V11_ACTION_SOURCES if version[0] == 11 else V12_ACTION_SOURCES)', b'action_sources = (V9_ACTION_SOURCES if version[0] == 9 else\n                              V10_ACTION_SOURCES if version[0] == 10 else V11_ACTION_SOURCES)', 1),
        (b'if declaration["schema_version"] in (10, 11, 12):', b'if declaration["schema_version"] in (10, 11):', 1),
    )
    for current, original, count in replacements:
        if projected.count(current) != count:
            raise ValueError('V12 dispatch changed another original reader unit')
        projected = projected.replace(current, original)
    if hashlib.sha256(projected).hexdigest() != '7477a9735dd949cc894bf3a457c69638851615c64ca0f4c5723bf439f98b33bf':
        raise ValueError('V12 reader changes protected historical graph or proof bytes')
    return projected

def _v11_input_reader_source_projection(raw):
    """Restore exact Source53 bytes after reviewed V11/V12 registration."""
    if hashlib.sha256(raw).hexdigest() in (
            '5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',
            '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',
            '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c',
            '5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5'):
        raw = _v12_input_reader_source_projection(raw)
    if hashlib.sha256(raw).hexdigest() != '7477a9735dd949cc894bf3a457c69638851615c64ca0f4c5723bf439f98b33bf':
        raise ValueError('V11 discovery reader is outside its exact reviewed Source')
    start, end = b'V11_PLAN_TYPE = ', b'ZERO = '
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError('V11 registration block is not unique')
    projected = raw[:raw.index(start)] + raw[raw.index(end):]
    replacements = (
        (b'(9, 10, 11)', b'(9, 10)', 2),
        (b'(8, 9, 10, 11)', b'(8, 9, 10)', 2),
        (b'action_sources = (V9_ACTION_SOURCES if version[0] == 9 else\n'
         b'                              V10_ACTION_SOURCES if version[0] == 10 else V11_ACTION_SOURCES)',
         b'action_sources = V9_ACTION_SOURCES if version[0] == 9 else V10_ACTION_SOURCES', 1),
        (b'if declaration["schema_version"] in (10, 11):',
         b'if declaration["schema_version"] == 10:', 1),
    )
    for current, original, count in replacements:
        if projected.count(current) != count:
            raise ValueError('V11 dispatch changed another original reader unit')
        projected = projected.replace(current, original)
    if hashlib.sha256(projected).hexdigest() != '455aa51a397f025d4a6b0145c5a963d6455c0af51159b03535c69b506150d47b':
        raise ValueError('V11 reader changes protected historical graph or proof bytes')
    return projected


def _cohort_acquisition_source_projection(raw, relative):
    """Remove only the exact prospective dispatch statements, retaining old bodies."""
    import ast
    if (relative == 'src/qcsd_lab/rapid_selected_capture_input.py'
            and hashlib.sha256(raw).hexdigest() == '72933db93fef22fd599dce35b2ae27dd2f525b112bc6140134540d1f1cad1fb1'):
        raw = _source65_selected_input_source_projection(raw)
    if (relative == 'src/qcsd_lab/whole_graph_supplement.py'
            and hashlib.sha256(raw).hexdigest() == 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98'):
        raw = _required_parent_get_source_projection(raw)
    if (relative == 'src/qcsd_lab/whole_graph_supplement.py'
            and hashlib.sha256(raw).hexdigest() ==
                '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0'):
        addition = (
            b"            ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n"
            b"             '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'),\n"
        )
        if raw.count(addition) != 1:
            raise ValueError('retained Source63 GET reader pair is not unique')
        raw = raw.replace(addition, b'', 1)
    import_sha = 'f2a706dd23b2283470da2476cf29e830c18e1433543e5b72f09e1106c356aaaa'
    order_sha = '2051f49616452fcfdc2829e49f13928271d068877a5dc1e9bc4867cd07fd17a0'
    if relative == 'src/qcsd_lab/whole_graph_supplement.py':
        expected_sha = '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'
        hooks = {
            'load_context': ((0, import_sha), (1, '06b7c22232f3786dd56d2e1e93c034061ac244cabc0ed10147deacffa5ec6a77')),
            'is_context': ((0, import_sha), (1, '0a81ca9efc243020b02578740d82f06c7d8317af09a4f42f63a752cd939219a6')),
            'identity': ((0, '814cefc603c9a3e346826d2959668ff59c548fa5dd527ef1beea4d7c1b58efa3'),),
            'execute_get': ((1, '04fed5e8421f404c2355d33212b785890a862b10d15aef26bfaa89d42d08c490'),),
            'admit': ((0, order_sha),), 'record_deferral': ((0, order_sha),),
            'record_input_rejection': ((0, order_sha),), 'verify_terminal': ((3, order_sha),),
            'sealed_context_roots': ((1, '981972b92997f13eaa841369a07358001b12e5fd5477178e5811e5573a58d994'),),
        }
        helper_sha = '20d5a338047f73eca19a71c2214b81b9e990db0b32d6e8e55ae60cc242209bb4'
    elif relative == 'src/qcsd_lab/rapid_per_class_selected_enrollment.py':
        expected_sha = '4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0'
        hooks = {'_context_metadata': ((0, import_sha),
            (1, 'f940f1b783f9f1e09d0487902cb6719a17ac97b7369435fe16a4f6343ff9c3f0'))}
        helper_sha = None
    else:
        return raw
    digest = hashlib.sha256(raw).hexdigest()
    if (digest != expected_sha and not (relative == 'src/qcsd_lab/whole_graph_supplement.py'
            and digest == '72a3e7030356955033fefab3703abe895c4fdb264910ea9c4d40ca398f175052')
            and not (relative == 'src/qcsd_lab/rapid_per_class_selected_enrollment.py'
            and digest == '410616cb3f2847a9cfa48b62229bd4f65f72b2e2f4857f8c50c981fb7dcb46a5')):
        raise ValueError('cohort dispatch is outside the exact prospective Source')
    tree = ast.parse(raw); seen = set(); retained = []; helpers = 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_cohort':
            helpers += 1
            if (helper_sha is None or helpers != 1 or
                    hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest() != helper_sha):
                raise ValueError('cohort dispatch helper changed its exact type guard')
            continue
        if isinstance(node, ast.FunctionDef) and node.name in hooks:
            if node.name in seen:
                raise ValueError('cohort dispatch repeats a protected definition')
            seen.add(node.name)
            for index, sha in hooks[node.name]:
                if (index >= len(node.body) or
                        hashlib.sha256(ast.dump(node.body[index], include_attributes=False).encode()).hexdigest() != sha):
                    raise ValueError('cohort dispatch changes the exact prospective branch')
            indices = {index for index, _ in hooks[node.name]}
            node.body = [item for index, item in enumerate(node.body) if index not in indices]
        retained.append(node)
    if seen != set(hooks) or helpers != (1 if helper_sha is not None else 0):
        raise ValueError('cohort dispatch definition set is incomplete')
    tree.body = retained
    return ast.unparse(tree).encode()


def _compatible_acquisition_code(relative, before, after):
    """Compare finite reader identities and retain every unmodified AST unit."""
    import ast
    current = _acquisition_reader_sources()
    if relative not in current:
        raise ValueError('acquisition reader role is outside the closed set')
    _open(before); _open(after)
    if (after['sha256'] != current[relative]['sha256'] or
            before['mode'] != 0o644 or after['mode'] != 0o644):
        raise ValueError('acquisition compatibility changes the reviewed reader or full mode')
    if before['sha256'] == after['sha256']:
        return True
    if (relative == 'src/qcsd_lab/rapid_selected_capture_input.py'
            and before['sha256'] == 'ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442'):
        if _source65_selected_input_source_projection(Path(after['path']).read_bytes()) != Path(before['path']).read_bytes():
            raise ValueError('selected GET reader changes protected Source65 bytes')
        return True
    if (relative == 'src/qcsd_lab/rapid_supplemental_cohort.py'
            and before['sha256'] in ('12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be',
                '39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',
                'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d',
                'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad')):
        old_raw = Path(before['path']).read_bytes()
        if before['sha256'] in ('39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',
                'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d',
                'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad'):
            old_raw = _v13_cohort_reader_source_projection(old_raw)
        if _v13_cohort_reader_source_projection(Path(after['path']).read_bytes()) != old_raw:
            raise ValueError('V13 cohort reader changes protected Source62 admission or graph bytes')
        return True
    if (relative == 'src/qcsd_lab/whole_graph_supplement.py'
            and before['sha256'] == '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0'):
        if _required_parent_get_source_projection(Path(after['path']).read_bytes()) != Path(before['path']).read_bytes():
            raise ValueError('required-parent GET reader changes protected Source64 bytes')
        return True
    if (relative == 'src/qcsd_lab/whole_graph_supplement.py'
            and before['sha256'] in ('164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7',
                '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b')):
        old_raw = Path(before['path']).read_bytes()
        if before['sha256'] == '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b':
            old_raw = _v13_supplement_reader_source_projection(old_raw)
        if _v13_supplement_reader_source_projection(Path(after['path']).read_bytes()) != old_raw:
            raise ValueError('V13 supplement reader changes protected Source62 GET or graph bytes')
        return True
    if relative == 'src/qcsd_lab/whole_graph_input.py':
        old_raw, new_raw = Path(before['path']).read_bytes(), Path(after['path']).read_bytes()
        if before['sha256'] in ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',
                '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c'):
            old_raw = _v13_input_reader_source_projection(old_raw)
            projected = _v13_input_reader_source_projection(new_raw)
        elif before['sha256'] == '5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5':
            projected = _v13_input_reader_source_projection(new_raw)
        elif before['sha256'] == '7477a9735dd949cc894bf3a457c69638851615c64ca0f4c5723bf439f98b33bf':
            projected = _v12_input_reader_source_projection(new_raw)
        elif before['sha256'] == '455aa51a397f025d4a6b0145c5a963d6455c0af51159b03535c69b506150d47b':
            projected = _v11_input_reader_source_projection(new_raw)
        else:
            raise ValueError('whole graph reader is outside exact historical/V13 registration pairs')
        if projected != old_raw:
            raise ValueError('V13 reader changes protected historical graph or proof bytes')
        return True
    roles = {
        'src/qcsd_lab/rapid_selected_capture_input.py': (
            {'ef14e839e0c1ab1b1540a9b8c024f0e8545c1a3cf5478deec30a500134aff337',
             'f12460f830c4f4ba7a2d5c5600be59c7fd9800ee0d974692b24bba84ed356308'},
            {'validate_input'}, {'_compatible_direct_validator_sources'}, set()),
        'src/qcsd_lab/rapid_selected_budget_input.py': (
            {'d4bbea3459cccf36217fa9897fbef4a51f73b3690151ef8aec883344e84145ca',
             '9e13ebe6eb79f066b2d96e9fc1cb90056584d4ba02f203ec8d8b42da95c57cf7',
             '6283ef9cafac972d9df8696c1c4d0249c920db855f7a83fc8fcd8fce434d079d'},
            {'_v3_inventory', 'audit_budget', 'read_audit', '_validate_input_uncached', '_input_dependencies'}, set(),
            {'LEGACY_SELECTED_SOURCE_SHA256', 'V3_HOST_INVENTORY_SHA256', 'V3_HOST_AUTHORITY_SHA256',
             'V3_ADMISSION_SOURCE_SHA256', 'V3_DEFERRAL_SOURCE_SHA256', '_AUDIT_PROGRAM_V3',
             'V3_SELECTED_SOURCE_SHA256', '_AUDIT_PROGRAM_V3_SCOPED'}),
        'src/qcsd_lab/rapid_per_class_selected_enrollment.py': (
            {'512e140944a953707b2ac9326fdb2dd6928ac8a763b519174a46534de4f3b07f',
             '048c0766e3a68d198547f26f4516d4337665c58163c1b6fc1ee1870b9808dc52',
             'd1860179aa08a911400eadc82cef3acb99b591f20656919cbe95268eeef64056',
             '3436b935a6f0e2124bd64195bffadfeec7870f3824c76726d7f5e3c7bc8a5fad',
             '410616cb3f2847a9cfa48b62229bd4f65f72b2e2f4857f8c50c981fb7dcb46a5'},
            {'_policy_sources', 'verify_policy', 'membership_inputs', 'verify_enrollment'}, set(), set()),
        'src/qcsd_lab/whole_graph_supplement.py': (
            {'726c0d6215830730f3938b69545f3b4acc8c727dda3b4528a34732701f8d9f07',
             'a12ba1de531fd37a4e6ab8abbc8497911ea51d4d45e54d452e3afc927058db66',
             '80bd66d3d710f5f14cf4827b43245d96af75e8ec0994418bed480e3c2a348357',
             '72a3e7030356955033fefab3703abe895c4fdb264910ea9c4d40ca398f175052'},
            {'_plan_rows', '_declaration'},
            {'_recognized_producer_sources', '_input_rejection', 'record_input_rejection'}, set()),
    }
    if relative not in roles or before['sha256'] not in roles[relative][0]:
        raise ValueError('acquisition reader is outside the exact historical/current Source pairs')
    _, changing, additions, declarations = roles[relative]
    source44 = before['sha256'] in {
        'f12460f830c4f4ba7a2d5c5600be59c7fd9800ee0d974692b24bba84ed356308',
        '3436b935a6f0e2124bd64195bffadfeec7870f3824c76726d7f5e3c7bc8a5fad',
        '80bd66d3d710f5f14cf4827b43245d96af75e8ec0994418bed480e3c2a348357',
        '72a3e7030356955033fefab3703abe895c4fdb264910ea9c4d40ca398f175052'}
    def projection(raw, *, successor):
        strip_cohort = successor or (relative == 'src/qcsd_lab/whole_graph_supplement.py'
            and before['sha256'] == '72a3e7030356955033fefab3703abe895c4fdb264910ea9c4d40ca398f175052') or (
            relative == 'src/qcsd_lab/rapid_per_class_selected_enrollment.py'
            and before['sha256'] == '410616cb3f2847a9cfa48b62229bd4f65f72b2e2f4857f8c50c981fb7dcb46a5')
        tree = ast.parse(_cohort_acquisition_source_projection(raw, relative) if strip_cohort else raw)
        retained = []; removed = set(); added = set()
        for node in tree.body:
            if (successor and not source44 and relative.endswith('whole_graph_supplement.py')
                    and isinstance(node, ast.FunctionDef) and node.name == 'verify_terminal'):
                branches = [item for item in node.body if isinstance(item, ast.If)
                    and ast.dump(item.test, include_attributes=False) == ast.dump(
                        ast.parse("value['outcome'] == 'input-ineligible'", mode='eval').body,
                        include_attributes=False)]
                if (len(branches) != 1 or hashlib.sha256(ast.dump(branches[0],
                        include_attributes=False).encode()).hexdigest() !=
                        'c3838a3202bac8848404ce49e6c0bd4ea6b7cef8b8e5f2505d48dac842c56e84'):
                    raise ValueError('whole terminal rejection is outside the exact new branch')
                node.body.remove(branches[0])
                outcomes = [item for item in ast.walk(node) if isinstance(item, ast.Compare)
                    and len(item.ops) == 1 and isinstance(item.ops[0], ast.NotIn)
                    and ast.dump(item.left, include_attributes=False) == ast.dump(
                        ast.parse("value['outcome']", mode='eval').body, include_attributes=False)]
                if (len(outcomes) != 1 or len(outcomes[0].comparators) != 1
                        or ast.dump(outcomes[0].comparators[0], include_attributes=False) != ast.dump(
                            ast.parse("{'admitted', 'operational-deferred', 'input-ineligible'}", mode='eval').body,
                            include_attributes=False)):
                    raise ValueError('whole terminal rejection changes original outcome guards')
                outcomes[0].comparators[0].elts.pop()
            if isinstance(node, ast.FunctionDef) and node.name in changing | additions:
                if node.name in removed:
                    raise ValueError('acquisition reader duplicates a reviewed changed unit')
                removed.add(node.name)
                if node.name in additions: added.add(node.name)
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id in declarations for target in targets):
                    continue
            retained.append(node)
        required = set(changing)
        if before['sha256'] == 'd4bbea3459cccf36217fa9897fbef4a51f73b3690151ef8aec883344e84145ca' and not successor:
            required.remove('_v3_inventory')
        if before['sha256'] == '512e140944a953707b2ac9326fdb2dd6928ac8a763b519174a46534de4f3b07f' and not successor:
            required.remove('_policy_sources')
        expected_additions = additions if successor or source44 else set()
        if removed != required | expected_additions or added != expected_additions:
            raise ValueError('acquisition reader changed-unit projection is incomplete')
        tree.body = retained
        return ast.dump(tree, include_attributes=False)
    if projection(Path(before['path']).read_bytes(), successor=False) != projection(
            Path(after['path']).read_bytes(), successor=True):
        raise ValueError('acquisition reader changes protected graph, proof or admission code')
    return True


def _compatible_selected_membership_code(relative, before, after):
    """Bind the finite reviewed selected readers, retaining all other AST units."""
    import ast
    if (relative in ('src/qcsd_lab/rapid_selected_capture_input.py',
                     'src/qcsd_lab/whole_graph_supplement.py') or
            after['sha256'] == _acquisition_reader_sources().get(relative, {}).get('sha256')):
        return _compatible_acquisition_code(relative, before, after)
    roles = {
        'src/qcsd_lab/rapid_selected_budget_input.py': (
            'd4bbea3459cccf36217fa9897fbef4a51f73b3690151ef8aec883344e84145ca',
            '9e13ebe6eb79f066b2d96e9fc1cb90056584d4ba02f203ec8d8b42da95c57cf7',
            '6283ef9cafac972d9df8696c1c4d0249c920db855f7a83fc8fcd8fce434d079d',
            {'_v3_inventory', 'audit_budget', 'read_audit', '_validate_input_uncached', '_input_dependencies'},
            {'LEGACY_SELECTED_SOURCE_SHA256', 'V3_HOST_INVENTORY_SHA256', 'V3_HOST_AUTHORITY_SHA256',
             'V3_ADMISSION_SOURCE_SHA256', 'V3_DEFERRAL_SOURCE_SHA256', '_AUDIT_PROGRAM_V3'},
            {'V3_SELECTED_SOURCE_SHA256', '_AUDIT_PROGRAM_V3_SCOPED'}),
        'src/qcsd_lab/rapid_per_class_selected_enrollment.py': (
            '512e140944a953707b2ac9326fdb2dd6928ac8a763b519174a46534de4f3b07f',
            '048c0766e3a68d198547f26f4516d4337665c58163c1b6fc1ee1870b9808dc52',
            'd1860179aa08a911400eadc82cef3acb99b591f20656919cbe95268eeef64056',
            {'_policy_sources', 'verify_policy', 'membership_inputs'}, set(), set()),
    }
    old_sha, v3_sha, scoped_sha, changing, v3_additions, scoped_additions = roles[relative]
    additions = v3_additions | scoped_additions
    _open(before); _open(after)
    if before['sha256'] == after['sha256'] and before['mode'] == after['mode']:
        return True
    if (before['mode'] != after['mode'] or (before['sha256'], after['sha256']) not in
            {(old_sha, v3_sha), (old_sha, scoped_sha), (v3_sha, scoped_sha)}):
        raise ValueError('selected budget reader is outside the exact reviewed old/new Source pair')
    def projection(raw, *, stage):
        old = stage == old_sha
        expected_additions = set() if old else v3_additions | (scoped_additions if stage == scoped_sha else set())
        tree = ast.parse(raw); retained = []; removed = set(); extra = set()
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in changing:
                if node.name in removed:
                    raise ValueError('selected budget reader duplicates a changed unit')
                removed.add(node.name)
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                found = {target.id for target in targets if isinstance(target, ast.Name) and target.id in additions}
                if found:
                    if old or found & extra or len(found) != 1:
                        raise ValueError('historical selected reader contains a v3-only declaration')
                    extra.update(found); continue
            retained.append(node)
        required = changing - ({'_v3_inventory'} if old and relative.endswith('rapid_selected_budget_input.py') else
                               {'_policy_sources'} if old and relative.endswith('rapid_per_class_selected_enrollment.py') else set())
        if removed != required or extra != expected_additions:
            raise ValueError('selected reader changed-unit projection is incomplete')
        tree.body = retained
        return ast.dump(tree, include_attributes=False)
    if projection(Path(before['path']).read_bytes(), stage=before['sha256']) != projection(
            Path(after['path']).read_bytes(), stage=after['sha256']):
        raise ValueError('selected budget reader changes protected admission or graph code')


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
        if name in _LEGACY_READER_UNITS:
            _compatible_code_ref(name, producer[name], expected)
        elif name == 'facts':
            if (producer[name]['mode'] != expected['mode'] or
                    producer[name]['sha256'] != expected['sha256'] and
                    _parallel_facts_source_projection(Path(producer[name]['path']).read_bytes()) !=
                    _parallel_facts_source_projection(Path(expected['path']).read_bytes())):
                raise ValueError('fixed target operation Facts changed protected code or full modes')
        elif name == 'budgets':
            _compatible_selected_membership_code(
                'src/qcsd_lab/rapid_per_class_selected_enrollment.py',
                producer[name], expected)
        elif (name in ('acceptance', 'duration', 'traffic', 'chunks')
                and _mixed_epoch().compatible_legacy_reader(name, producer[name], expected)):
            pass
        elif name == 'traffic':
            if producer[name]['mode'] != expected['mode']:
                raise ValueError('fixed target traffic reader full modes differ')
            if producer[name]['sha256'] != expected['sha256']:
                if (producer[name]['sha256'] != '4eb2d2ce5a35005f342befe9fb86dd6dad27980b2635e5372fda227902764542'
                        or expected['sha256'] != '7210b7da27e5d1129e0a2c754fe903e5f151057b5ff0393f814e0ae311e47082'):
                    raise ValueError('fixed target traffic reader changed outside the exact quick dispatch pair')
                raw = Path(expected['path']).read_bytes()
                addition = (
                    b'        from . import rapid_quick_profile as quick\n'
                    b'        if quick.is_payload(payload):\n'
                    b'            quick.validate_profile(payload["scheduling"])\n'
                    b'            return value\n'
                )
                if raw.count(addition) != 1 or hashlib.sha256(raw.replace(addition, b'', 1)).hexdigest() != producer[name]['sha256']:
                    raise ValueError('fixed target traffic reader changes protected traffic or deep code')
                # Facts imports this dispatcher while reading an old enrollment.
                # Pin its complete Source so a new receipt type cannot alias an
                # old one while the historical projection is in use.
                from . import rapid_quick_profile as quick
                quick_ref = reference(Path(quick.__file__))
                _open(quick_ref)
                if (quick_ref['sha256'] != '35808d483b82a4da1cd9c22e4a9ef967986dd7ab4ede448f8cd98db9d0c3b25c'
                        or quick_ref['mode'] != 0o644):
                    raise ValueError('fixed target quick dispatcher Source or full mode changed')
        elif any(producer[name][key] != expected[key] for key in ('sha256', 'mode')):
            raise ValueError('fixed target relevant producer/reader code bytes or modes differ')
    return True


def _membership_additive_reader_roles(old_code, new_code):
    """Authenticate the two added readers before comparing an older read set."""
    additions = set(new_code) - set(old_code)
    allowed = {'src/qcsd_lab/whole_graph_input.py',
               'src/qcsd_lab/rapid_supplemental_cohort.py',
               'src/qcsd_lab/rapid_parallel_partial_lane.py'}
    if not additions <= allowed:
        return None
    readers = _acquisition_reader_sources()
    if 'src/qcsd_lab/rapid_parallel_partial_lane.py' in additions:
        readers['src/qcsd_lab/rapid_parallel_partial_lane.py'] = reference(
            Path(__file__).with_name('rapid_parallel_partial_lane.py'))
    for relative in additions:
        _open(new_code[relative])
        if not _typed_equal(new_code[relative], readers[relative]):
            raise ValueError('membership added reader differs from its exact current Source')
    return additions


def _compatible_membership(producer, current, producer_sources):
    """Reopen all original data; compare only membership-relevant code roles."""
    _compatible_sources(producer_sources)
    _membership_close(producer)
    executing = _sources()
    def code_refs(value, source):
        return {_membership_code_path(Path(row['path']), source): row for row in value['files']
                if _membership_code_path(Path(row['path']), source) is not None}
    old_code = code_refs(producer, producer_sources['target'])
    new_code = code_refs(current, executing['target'])
    added_readers = _membership_additive_reader_roles(old_code, new_code)
    if added_readers is None:
        return False
    for relative in added_readers:
        if sum(_membership_code_path(Path(row['path']), executing['target']) == relative
               for row in current['files']) != 1:
            raise ValueError('membership repeats an added current reader')
    selected_roles = ('src/qcsd_lab/rapid_selected_budget_input.py',
                      'src/qcsd_lab/rapid_per_class_selected_enrollment.py',
                      'src/qcsd_lab/rapid_selected_capture_input.py',
                      'src/qcsd_lab/whole_graph_supplement.py')
    input_reader = 'src/qcsd_lab/whole_graph_input.py'
    if input_reader in old_code and input_reader in new_code:
        _compatible_acquisition_code(input_reader, old_code[input_reader], new_code[input_reader])
    for relative in selected_roles:
        if relative not in old_code and relative not in new_code:
            continue
        if relative not in old_code or relative not in new_code:
            return False
        _compatible_selected_membership_code(relative, old_code[relative], new_code[relative])
    rolling = 'src/qcsd_lab/rapid_rolling_capture.py'
    if rolling in old_code and rolling in new_code:
        before, after = old_code[rolling], new_code[rolling]
        _open(before); _open(after)
        pair = (before['sha256'], after['sha256'])
        epoch_predecessors = {
            'b2d6be3fbc3ab2060bdfa683d372def0122669daa251b31c2000a759c4e4f610',
            '23e64994de9127aad06e952dae996d7e7b24fd5d44e5c5877eb658d845d64e9b',
            'a7a2302f4e835dcfe37b15278d624890065794673f7ee2182b18a9fd61e196e4'}
        epoch_successors = {
            'a7a2302f4e835dcfe37b15278d624890065794673f7ee2182b18a9fd61e196e4',
            'c133974ffb1895d77b3fc88fd5888c9de28ed9e9b280ec2b9d576aa07b6c9702',
            '2101877af8bfdaea5a3a4ad38317adc5a2289d013dab5f5c8c77a8fc2c46c739',
            'b6f8db16953987f60a3c7ea0003fdad187dd41343b875233e3abacb5f2e4fe14',
            'b9f316d212cf024e3d09ab4fa1a61035233f68f50f8a7c03c7450495cf81d2b0',
            '6f5fc34f6d8ee14390378200d2ebba55d4de9fc205d6788453c960739f138881'}
        exact_deep_successor = (
            pair[0] in {'c133974ffb1895d77b3fc88fd5888c9de28ed9e9b280ec2b9d576aa07b6c9702',
                        '2101877af8bfdaea5a3a4ad38317adc5a2289d013dab5f5c8c77a8fc2c46c739'}
            and pair[1] in {'2101877af8bfdaea5a3a4ad38317adc5a2289d013dab5f5c8c77a8fc2c46c739',
                            'b6f8db16953987f60a3c7ea0003fdad187dd41343b875233e3abacb5f2e4fe14'})
        project = (_epoch_dispatch_source_projection if
                   (pair[0] in epoch_predecessors and pair[1] in epoch_successors) or exact_deep_successor
                   else _planning_source_projection)
        if (before['mode'] != after['mode']
                or project(Path(before['path']).read_bytes())
                != project(Path(after['path']).read_bytes())):
            return False
    facts = 'src/qcsd_lab/rapid_operation_facts.py'
    if facts in old_code or facts in new_code:
        if facts not in old_code or facts not in new_code:
            return False
        before, after = old_code[facts], new_code[facts]
        _open(before); _open(after)
        if (before['mode'] != after['mode'] or
                before['sha256'] != after['sha256'] and
                _parallel_facts_source_projection(Path(before['path']).read_bytes()) !=
                _parallel_facts_source_projection(Path(after['path']).read_bytes())):
            return False
    def normalized(value, source, *, successor=False):
        result = json.loads(_json(value))
        if successor:
            result['files'] = [row for row in result['files']
                if _membership_code_path(Path(row['path']), source) not in added_readers]
        for row in result['files']:
            relative = _membership_code_path(Path(row['path']), source)
            if relative is not None:
                row['path'] = 'identical-bound-code/' + relative
                if relative == rolling and rolling in old_code and rolling in new_code:
                    row['sha256'] = old_code[rolling]['sha256']
                elif relative == facts and facts in old_code and facts in new_code:
                    row['sha256'] = old_code[facts]['sha256']
                elif relative == 'src/qcsd_lab/rapid_fixed_condition_target.py':
                    row['sha256'] = producer_sources['target']['sha256']
                elif relative in selected_roles:
                    row['sha256'] = old_code[relative]['sha256']
                elif relative == input_reader and input_reader in old_code and input_reader in new_code:
                    row['sha256'] = old_code[input_reader]['sha256']
        result['files'].sort(key=lambda row: row['path'])
        result['trees'].sort(key=lambda row: (row['path'], row['ignore_git']))
        return result
    return _typed_equal(normalized(producer, producer_sources['target']),
                        normalized(current, executing['target'], successor=True))


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


def _capture_limits_equal(actual, expected):
    """Compare finite seconds by value and keep byte/count caps exact integers."""
    seconds = {'capture_seconds', 'timeout_seconds', 'settle_seconds',
               'per_origin_cooldown_seconds'}
    counts = {'capture_megabytes', 'max_response_bytes', 'max_attempts'}
    if (type(actual) is not dict or type(expected) is not dict
            or set(actual) != seconds | counts or set(expected) != seconds | counts):
        return False
    for field in seconds:
        if (type(actual[field]) not in (int, float) or type(expected[field]) not in (int, float)
                or not math.isfinite(actual[field]) or not math.isfinite(expected[field])
                or actual[field] != expected[field]):
            return False
    return all(type(actual[field]) is int and type(expected[field]) is int
               and actual[field] == expected[field] for field in counts)


def _capture_limits(mode, original, condition):
    """Retain admission caps; derive only the declared exact BuFLO200 setting."""
    if mode == 'buflo' and condition.get('defense', {}).get('parameters_sha256') == '5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e':
        return _mixed_epoch().capture_limits(original, condition)
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
    if _mixed_epoch().is_target(ref):
        return _mixed_epoch().validate_target(ref, _seen=_seen)
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


@source_facts.source
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
    if json.loads(_open(operation['receipt']).read_bytes()).get('artifact_type') == 'qcsd-original-deep-verified-individual-traces-from-incomplete-parallel-chunk-v1':
        from . import rapid_parallel_partial_lane as parallel_partial
        return parallel_partial.target_operation(operation)
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
    if facts.get('actuator') == 'parallel-formal-worker':
        from . import rapid_parallel_partial_lane as parallel_partial
        return parallel_partial.target_rows(source,report,facts)
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
    if json.loads(_open(receipt).read_bytes()).get('artifact_type') == 'qcsd-original-deep-verified-individual-traces-from-incomplete-parallel-chunk-v1':
        from . import rapid_parallel_partial_lane as parallel_partial
        verification=parallel_partial.verify(receipt,audit_root=Path(audit_root))
    else:
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
                    or not _capture_limits_equal(row['capture_limits'], _capture_limits(
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
    if _mixed_epoch().is_target(target):
        return _mixed_epoch().initialize_progress(target=target, proofs=proofs, output=output)
    declaration=validate_target(target);rows=_select(declaration,proofs,initial=True)
    value={'contract':CONTRACT,'target':target,'target_id':declaration['target_id'],'parent':None,
        'proofs':proofs,'classes':declaration['classes'],'accepted_rows':rows,'remaining_vectors':_vectors(declaration['classes'],rows),
        'target_accepted_count':len(rows),'retained_history':declaration['retained_history'],
        'history_counts_as_target_credit':False,'final_target':TOTAL,'sources':_sources(),
        'published_at':datetime.now(timezone.utc).isoformat(),'aggregate_status':_aggregate(declaration['classes'],rows)}
    return _write(output,PROGRESS_TYPE,value,[target,*proofs,*value['sources'].values()])


@_owned
def validate_progress(ref, _seen=None):
    if _mixed_epoch().is_progress(ref):
        return _mixed_epoch().validate_progress(ref, _seen=_seen)
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
    if _mixed_epoch().is_progress(progress):
        return _mixed_epoch().append_progress(progress=progress, proofs=proofs, output=output, target=target)
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
    if _mixed_epoch().is_progress(progress):
        return _mixed_epoch().publish_final(progress, output)
    facts=final_coverage(progress);value=validate_progress(progress)
    files=input_files(progress);directories=directory_dependencies(progress)
    _check_action()
    return _write(output,CORPUS_TYPE,{'contract':CONTRACT,**facts,'accepted_rows':value['accepted_rows'],
        'read_dependencies':files,'directory_dependencies':directories,'sources':_sources(),
        'published_at':datetime.now(timezone.utc).isoformat(),'scientific_credit':True},files)


@_owned
@source_facts.selection
def input_files(progress):
    if _mixed_epoch().is_progress(progress):
        return _mixed_epoch().input_files(progress)
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
@source_facts.selection
def roots(progress):
    # Exact authenticated files can be mounted as files. Preserve immutable
    # directory membership roots separately; never broaden to a workspace.
    value=validate_progress(progress);paths={Path(ref['path']) for ref in input_files(progress)}
    for row in directory_dependencies(progress):paths.add(Path(row['path']))
    # Original HOST interpreter aliases remain original in installed readers.
    from .rapid_ordinary_canary_carry import _interpreter_dependency_roots
    aliases=set()
    for proof in value['proofs']:
        audit=validate_audit(proof)
        if audit['kind']=='complete':
            interpreter=audit['operation']['interpreter']
            aliases.update(_interpreter_dependency_roots(interpreter['command'],interpreter['binary']))
        source=_measurement_source(audit['source_binding'])
        start=json.loads(_open(source['binding']['runtime_operation']['started.json']).read_bytes())
        aliases.update(_interpreter_dependency_roots(start['command'][0],start['interpreter']))
    retained=[p for p in aliases if not any(p!=other and p.is_relative_to(other) for other in aliases)]
    for path in retained:
        epoch._path(path,directory=True)
    paths.update(retained)
    return tuple(sorted(paths,key=str))


@_owned
@source_facts.selection
def directory_dependencies(progress):
    if _mixed_epoch().is_progress(progress):
        return _mixed_epoch().directory_dependencies(progress)
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
