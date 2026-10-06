"""Closed AST dependency resolution; no qualification requests or image effects."""
from __future__ import annotations

import ast

import pytest

from qcsd_lab import rapid_runtime_compatibility as compatibility
from tests.test_rapid_runtime_compatibility import original_sources, bridge, changed_sources


def inventory_source(*, constants='_MODULE_NAMES = {"qcsd_lab.util"}',
                     expression='_MODULE_NAMES | ({OPTIONAL} if enabled else set())',
                     before='', iterator='sorted(names)', call='importlib.import_module(name)',
                     function='implementation_sources', argument='enabled=False', suffix=''):
    return ast.parse(f'''import importlib
{constants}
OPTIONAL = "qcsd_lab.manifest"
def {function}({argument}):
    names = {expression}
{before}    return {{name: {call}.__file__ for name in ({iterator})}}
{suffix}
''')


def resolve(tree, *, module='rapid_attempt_failure_evidence', function='implementation_sources'):
    target = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == function)
    call = next(item for item in ast.walk(target) if isinstance(item, ast.Call)
                and isinstance(item.func, ast.Attribute) and item.func.attr == 'import_module')
    return compatibility._dynamic_import_dependencies(module, function, tree, target, call)


def test_original_dynamic_source_bytes_are_preserved_and_fully_protected(original_sources):
    before = dict(original_sources)
    surface = compatibility.qualification_dependencies(original_sources)
    assert original_sources == before
    for module, expression in (
        ('rapid_selected_budget_input', b'__import__(__name__'),
        ('rapid_selected_capture_input', b'__import__(__name__'),
        ('whole_graph_supplement', b'__import__(__name__'),
        ('rapid_per_class_selected_enrollment', b'__import__(__name__'),
        ('rapid_attempt_failure_evidence', b'importlib.import_module(name)'),
        ('rapid_site_admission', b'importlib.import_module(name)'),
    ):
        path = f'src/qcsd_lab/{module}.py'
        assert expression in original_sources[path]
        assert surface['source_hashes'][path] == compatibility._sha(original_sources[path])
    # Every opt-in branch is loaded, even when the default argument is false.
    for module in ('application_response_policy', 'chaff_qualification', 'capture_acceptance_policy'):
        assert f'src/qcsd_lab/{module}.py' in surface['source_hashes']
    assert 'src/qcsd_lab/capture_session.py' not in surface['source_hashes']
    assert 'src/qcsd_lab/orchestrator.py' not in surface['source_hashes']
    assert 'prepare._run_neqo' in surface['reachable_symbols']


def test_original_inventory_still_uses_exact_collector_comparison(original_sources):
    old, new, functions = changed_sources(original_sources)
    result = bridge(old, new, functions)
    assert result['old_source_hashes'] == compatibility._source_inventory(old)
    assert result['new_source_hashes'] == compatibility._source_inventory(new)
    assert result['scientific_credit'] is False
    changed = dict(new)
    path = 'src/qcsd_lab/rapid_selected_budget_input.py'
    changed[path] += b'\nUNREVIEWED_METADATA_CHANGE = True\n'
    with pytest.raises(ValueError, match='qualification dependency surface'):
        bridge(old, changed, functions)


@pytest.mark.parametrize(('module', 'function', 'expression', 'iterator'), [
    ('rapid_attempt_failure_evidence', 'implementation_sources',
     '_MODULE_NAMES | ({OPTIONAL} if enabled else set())', 'sorted(names)'),
    ('rapid_site_admission', 'preparation_implementation_sources',
     '(*_MODULE_NAMES, *((OPTIONAL,) if enabled else ()))', 'names'),
])
def test_closed_union_and_starred_inventory_load_every_branch(module, function, expression, iterator):
    tree = inventory_source(expression=expression, iterator=iterator, function=function)
    assert resolve(tree, module=module, function=function) == {'util', 'manifest'}


@pytest.mark.parametrize('options', [
    {'constants': '_MODULE_NAMES = unknown'},
    {'constants': '_MODULE_NAMES = read_runtime_names()'},
    {'constants': '_MODULE_NAMES = OTHER\nOTHER = _MODULE_NAMES'},
    {'constants': '_MODULE_NAMES = {"outside.package"}'},
    {'constants': '_MODULE_NAMES = "qcsd_lab.util"'},
    {'constants': '_MODULE_NAMES = {{"qcsd_lab.util"}}'},
    {'constants': '_MODULE_NAMES = {"qcsd_lab.util"}\n_MODULE_NAMES = unknown'},
    {'constants': '_MODULE_NAMES = {"qcsd_lab.util"}\n_MODULE_NAMES.add(unknown)'},
    {'constants': '_MODULE_NAMES = {"qcsd_lab.util"}\nmutate(_MODULE_NAMES)'},
    {'before': '    names = unknown\n'},
    {'before': '    names.add(unknown)\n'},
    {'before': '    alias = names\n'},
    {'before': '    mutate(names)\n'},
    {'iterator': 'runtime_names()'},
    {'iterator': 'sorted(names)', 'argument': 'enabled=False, sorted=None'},
    {'iterator': 'sorted(names) if runtime else unknown'},
    {'call': 'importlib.import_module(name, package="qcsd_lab")'},
    {'suffix': 'importlib = unknown'},
    {'before': '    importlib = unknown\n'},
])
def test_unknown_cyclic_rebound_mutable_or_nonfinite_imports_are_refused(options):
    with pytest.raises(ValueError, match='unresolved dynamic dependency'):
        resolve(inventory_source(**options))


def test_finite_inventory_resolution_does_not_grant_other_functions_authority():
    tree = inventory_source(function='other_inventory')
    with pytest.raises(ValueError, match='unresolved dynamic dependency'):
        resolve(tree, function='other_inventory')


@pytest.mark.parametrize('expression', [
    'exec("pass")', 'eval("1")', '__import__(requested, fromlist=["_"])',
    '__import__(__name__, fromlist=unknown)', '__import__(__name__, fromlist=["* "])',
    '__import__(__name__, fromlist=["_"], level=1)',
    'unknown.import_module("qcsd_lab.util")',
])
def test_all_other_dynamic_calls_remain_refused(expression):
    tree = ast.parse(f'def _modules():\n    return {expression}\n')
    target = tree.body[0]
    call = target.body[0].value
    with pytest.raises(ValueError, match='unresolved dynamic dependency'):
        compatibility._dynamic_import_dependencies('rapid_selected_budget_input', '_modules', tree, target, call)


def test_static_self_import_only_resolves_its_original_module():
    tree = ast.parse('def _modules():\n    return __import__(__name__, fromlist=["_"])\n')
    function = tree.body[0]
    call = function.body[0].value
    assert compatibility._dynamic_import_dependencies('rapid_selected_budget_input', '_modules',
                                                       tree, function, call) == {'rapid_selected_budget_input'}
    tree.body.append(ast.parse('__name__ = requested').body[0])
    with pytest.raises(ValueError, match='unresolved dynamic dependency'):
        compatibility._dynamic_import_dependencies('rapid_selected_budget_input', '_modules', tree, function, call)


def test_missing_finite_package_dependency_is_not_omitted(original_sources):
    sources = dict(original_sources)
    del sources['src/qcsd_lab/class_catalogue.py']
    with pytest.raises(ValueError, match='dependency source is missing: class_catalogue'):
        compatibility.qualification_dependencies(sources)
