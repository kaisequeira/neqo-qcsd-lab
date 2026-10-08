"""SDK selection controls; mocked installed closures grant no runtime authority.

Metadata cases substitute only checked_runtime's expensive installed closure.
They exercise the real metadata joins and package binding. Root's optional
portable HOST integration remains the genuine stage/amend/finalize gate.
"""
from importlib import util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

from qcsd_lab import buflo_duration_budget as duration
from qcsd_lab import front_fixed_configuration as front
from qcsd_lab import rapid_operation_facts as facts

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'tools/_rapid_class_mode_flight'
RECIPE = BUNDLE / 'flight/operator.py'


@pytest.fixture
def recipe():
    spec = util.spec_from_file_location('sdk_binding_flight_recipe', RECIPE)
    value = util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_declared_cli_policies_match_the_qualified_sdk(recipe):
    assert recipe.CLI_BUFLO_POLICIES == (duration.POLICY, duration.CADENCE64_POLICY)
    assert recipe.CLI_FRONT_POLICY == front.POLICY


@pytest.mark.parametrize('arguments', [('--help',), ('stage', '--help')])
def test_help_requires_no_qcsd_package_at_all(tmp_path, arguments):
    clone = tmp_path / 'recipe-only clone'
    (clone / 'tools').mkdir(parents=True)
    entry = clone / 'tools/rapid_class_mode_flight.py'
    shutil.copy2(ROOT / 'tools/rapid_class_mode_flight.py', entry)
    shutil.copytree(BUNDLE, clone / 'tools/_rapid_class_mode_flight')
    assert not (clone / 'src').exists()
    result = subprocess.run([sys.executable, '-I', '-B', str(entry), *arguments],
        cwd=tmp_path, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert 'stage' in result.stdout


def test_same_authenticated_sdk_keeps_original_package_identity(recipe, monkeypatch):
    import qcsd_lab
    package = qcsd_lab
    search_path = tuple(package.__path__)
    monkeypatch.setattr(sys, 'path', list(sys.path))
    recipe.host_imports(ROOT)
    assert sys.modules['qcsd_lab'] is package
    assert tuple(package.__path__) == search_path
    assert sys.path[:2] == [str(ROOT / 'src'), str(ROOT)]


@pytest.mark.parametrize('mismatch', ['package-source', 'package-search-path', 'module-source'])
def test_wrong_already_imported_sdk_is_refused_without_relabelling(recipe, tmp_path, monkeypatch, mismatch):
    import qcsd_lab
    original = qcsd_lab
    wrong = tmp_path / 'another-src/qcsd_lab'
    wrong.mkdir(parents=True)
    (wrong / '__init__.py').write_bytes(b'')
    if mismatch == 'module-source':
        (wrong / 'already_loaded.py').write_bytes(b'')
        name = 'qcsd_lab.already_loaded'
        loaded = ModuleType(name)
        loaded.__file__ = str(wrong / 'already_loaded.py')
    else:
        name = 'qcsd_lab'
        loaded = ModuleType(name)
        loaded.__file__ = str(wrong / '__init__.py' if mismatch == 'package-source'
                              else ROOT / 'src/qcsd_lab/__init__.py')
        loaded.__path__ = [str(wrong)]
    monkeypatch.setitem(sys.modules, name, loaded)
    before = list(sys.path)
    with pytest.raises(ValueError, match='another source root|another package search path'):
        recipe.host_imports(ROOT)
    assert sys.modules[name] is loaded
    assert sys.path == before
    if name != 'qcsd_lab':
        assert sys.modules['qcsd_lab'] is original


@pytest.fixture
def metadata(recipe, tmp_path, monkeypatch):
    """Controlled closure boundary; actual installed validation is not claimed."""
    build, output = tmp_path / 'bound-build', tmp_path / 'fresh-flight'
    build.mkdir()
    output.mkdir()
    canonical = {'source': {'lab_commit': '1' * 40, 'neqo_commit': '2' * 40},
        'source_manifest': str(build / 'runtime-export/source.json'),
        'client_binary': str(build / 'runtime-export/neqo-qcsd-client')}
    raw = recipe.encode(canonical)
    canonical_path = build / 'canonical-runtime.json'
    canonical_path.write_bytes(raw)
    (output / 'canonical-runtime.json').write_bytes(raw)
    calls = []

    def checked_runtime(args):
        assert args.runtime_build_root == build
        assert args.clean_runtime_root == ROOT
        assert args.canonical_sha256 == recipe.digest(raw)
        assert args.expected_lab_commit == canonical['source']['lab_commit']
        assert args.expected_native_commit == canonical['source']['neqo_commit']
        calls.append(args)
        return recipe.ref(canonical_path), canonical, ROOT

    monkeypatch.setattr(recipe, 'checked_runtime', checked_runtime)
    monkeypatch.setattr(sys, 'path', list(sys.path))
    setup = {'recipe': recipe.ref(RECIPE), 'mode': 'front', 'output': str(output),
        'runtime_build_root': str(build), 'clean_runtime_root': str(ROOT),
        'expected_lab_commit': canonical['source']['lab_commit'],
        'expected_native_commit': canonical['source']['neqo_commit'],
        'canonical_runtime_sha256': recipe.digest(raw), 'canonical_runtime': canonical,
        'canonical_runtime_reference': recipe.ref(canonical_path)}
    plan = {'recipe_sha256': recipe.digest(recipe.read(RECIPE)),
        'helper_sha256': recipe.FIRST_HELPER_SHA, 'clean_runtime_root': str(ROOT),
        'expected_lab_commit': canonical['source']['lab_commit'],
        'expected_native_commit': canonical['source']['neqo_commit'],
        'canonical_runtime_sha256': recipe.digest(raw), 'canonical_runtime': canonical}
    setup_path, plan_path = output / 'setup.json', output / 'plan.json'
    setup_path.write_bytes(recipe.encode(setup))
    plan_path.write_bytes(recipe.encode(plan))
    return SimpleNamespace(build=build, output=output, setup=setup_path, plan=plan_path,
        setup_sha256=recipe.digest(recipe.read(setup_path)),
        plan_sha256=recipe.digest(recipe.read(plan_path)), calls=calls)


@pytest.mark.parametrize('command', ['amend', 'finalize', 'run', 'readiness'])
def test_host_metadata_authenticates_original_runtime_before_binding(recipe, metadata, command):
    args = SimpleNamespace(command=command, setup=metadata.setup, setup_sha256=metadata.setup_sha256,
        plan=metadata.plan, plan_sha256=metadata.plan_sha256)
    assert recipe._bind_host_sdk(args) == ROOT
    assert len(metadata.calls) == 1
    assert metadata.calls[0].runtime_build_root == metadata.build


@pytest.mark.parametrize('command', ['amend', 'run'])
def test_hash_changed_host_metadata_refuses_before_runtime_selection(recipe, metadata, command):
    args = SimpleNamespace(command=command, setup=metadata.setup, setup_sha256=metadata.setup_sha256,
        plan=metadata.plan, plan_sha256=metadata.plan_sha256)
    path = metadata.setup if command == 'amend' else metadata.plan
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(ValueError, match='setup changed|plan changed'):
        recipe._bind_host_sdk(args)
    assert metadata.calls == []


def stage_arguments(recipe, tmp_path):
    return [str(RECIPE), 'stage', '--runtime-build-root', str(tmp_path / 'build'),
        '--clean-runtime-root', str(ROOT), '--study-root', str(tmp_path / 'study'),
        '--enrollment', str(tmp_path / 'enrollment.json'), '--output', str(tmp_path / 'fresh'),
        '--python', sys.executable, '--canonical-sha256', 'a' * 64,
        '--expected-lab-commit', '1' * 40, '--expected-native-commit', '2' * 40,
        '--name', 'controlled-sdk-order', '--campaign-seed', '43', '--mode', 'front',
        '--front-configuration-policy', recipe.CLI_FRONT_POLICY]


def test_stage_runtime_binding_precedes_owned_facts_and_dispatch(recipe, tmp_path, monkeypatch, capsys):
    observed = []
    monkeypatch.setattr(sys, 'argv', stage_arguments(recipe, tmp_path))
    monkeypatch.setattr(sys, 'path', list(sys.path))

    def runtime(args):
        assert facts.current_context() is None
        observed.append('authenticated-runtime')
        return None, None, ROOT

    def stage(args):
        assert isinstance(facts.current_context(), facts.OperationFacts)
        assert sys.path[:2] == [str(ROOT / 'src'), str(ROOT)]
        observed.append('owned-dispatch')
        return {'physical_actions_performed': False}

    monkeypatch.setattr(recipe, 'checked_runtime', runtime)
    monkeypatch.setattr(recipe, 'stage', stage)
    recipe.main()
    assert observed == ['authenticated-runtime', 'owned-dispatch']
    assert facts.current_context() is None
    assert json.loads(capsys.readouterr().out) == {'physical_actions_performed': False}


def test_failed_runtime_authentication_never_dispatches_or_prints_success(recipe, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', stage_arguments(recipe, tmp_path))

    def refused(args):
        raise ValueError('actual runtime closure refused')

    def forbidden(args):
        raise AssertionError('failed authentication cannot dispatch')

    monkeypatch.setattr(recipe, 'checked_runtime', refused)
    monkeypatch.setattr(recipe, 'stage', forbidden)
    with pytest.raises(ValueError, match='actual runtime closure refused'):
        recipe.main()
    assert facts.current_context() is None
    assert capsys.readouterr().out == ''


def test_image_dispatch_keeps_installed_sdk_without_host_rebinding(recipe, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', [str(RECIPE), 'preamble-image', '--plan',
        str(tmp_path / 'controlled-plan.json'), '--plan-sha256', 'a' * 64])

    def forbidden(args):
        raise AssertionError('image command cannot select a HOST SDK')

    def image_action(args):
        assert isinstance(facts.current_context(), facts.OperationFacts)
        return {'installed_sdk_dispatch': True}

    monkeypatch.setattr(recipe, '_bind_host_sdk', forbidden)
    monkeypatch.setattr(recipe, 'image_action', image_action)
    recipe.main()
    assert facts.current_context() is None
    assert json.loads(capsys.readouterr().out) == {'installed_sdk_dispatch': True}
