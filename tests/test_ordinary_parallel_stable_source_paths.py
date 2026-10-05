"""Stable Source paths with genuine validator bytes and controlled GET proof."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_ordinary_parallel_schedule as parallel
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_selected_budget_input as budget_input
from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_per_class_selected_enrollment as per_class
from qcsd_lab.rapid_operation_facts import OperationFacts


def fixture(tmp_path, monkeypatch, *, clone, budget, overlap=False):
    declared = tmp_path / 'declared'
    imported_root = tmp_path / 'execution' if clone else declared
    bound_root = imported_root if overlap else tmp_path / 'original-source'
    input_module = budget_input if budget else selected
    actual_modules = budget_input._modules() if budget else selected._direct_modules()
    assert len(actual_modules) == (10 if budget else 8)
    modules, originals, bound_files, references, sources = [], set(), set(), {}, {}
    for actual in actual_modules:
        relative = Path('src') / Path(*actual.__name__.split('.')).with_suffix('.py')
        original = declared / relative
        original.parent.mkdir(parents=True, exist_ok=True)
        original.write_bytes(Path(actual.__file__).read_bytes())
        imported = imported_root / relative
        imported.parent.mkdir(parents=True, exist_ok=True)
        if imported != original:
            imported.write_bytes(original.read_bytes())
        bound_validator = bound_root / relative
        bound_validator.parent.mkdir(parents=True, exist_ok=True)
        if bound_validator != imported:
            bound_validator.write_bytes(original.read_bytes())
        references[actual.__name__] = selected.reference(bound_validator)
        sources[actual.__name__] = references[actual.__name__]['sha256']
        modules.append(SimpleNamespace(__name__=actual.__name__, __file__=str(imported)))
        originals.add(original)
        bound_files.add(bound_validator)
    receipt = tmp_path / 'selected-input.json'
    receipt.write_bytes(parallel.receipts._json(parallel.receipts._bind(input_module.RECEIPT_TYPE,
        {'direct_validator_files': references, 'direct_validator_sources': sources})))
    cohort, qspec, plan = [tmp_path / name for name in ('cohort.json', 'input.json', 'plan.json')]
    for path in (cohort, qspec, plan):
        path.write_text('{}')
    workload = tmp_path / 'workloads' / 'fixture.json'
    workload.parent.mkdir()
    field = budget_input.FIELD if budget else 'selected_input_evidence'
    workload.write_text(json.dumps({'preparation': {'data_role': input_module.ROLE,
        field: {'receipt': selected.reference(receipt)}}, 'resources': []}))
    bound = tmp_path / 'original-admission.json'; bound.write_bytes(b'controlled original GET proof')
    raw = tmp_path / 'original-raw'; raw.mkdir(); (raw / 'raw.bin').write_bytes(b'controlled GET bytes')
    base = SimpleNamespace(cohort=cohort, qualification_spec=qspec, plan_receipt=plan,
                           workload_root=workload.parent, module_root=declared)
    monkeypatch.setattr(per_class, 'enrollment_kind', lambda path: False)
    monkeypatch.setattr(additive, 'enrollment_kind', lambda path: True)
    monkeypatch.setattr(additive, 'membership_inputs', lambda path: {cohort})
    monkeypatch.setattr(parallel.lanes, 'plan_payload', lambda raw: {})
    monkeypatch.setattr(OperationFacts, 'bind_capture', lambda self, spec: None)
    monkeypatch.setattr(selected, '_direct_modules', lambda: tuple(modules[:8]))
    monkeypatch.setattr(budget_input, '_modules', lambda: tuple(modules))
    monkeypatch.setattr(input_module, 'preparation_inputs', lambda *args:
        ({bound, receipt, *bound_files, *(Path(module.__file__) for module in modules)}, {raw}))
    return base, (SimpleNamespace(workload_id='fixture'),), modules, originals, bound_files, bound, raw


@pytest.mark.parametrize('clone', [False, True])
@pytest.mark.parametrize('budget', [False, True], ids=['plain-eight', 'budget-ten'])
def test_stable_refs_and_real_byte_fences(tmp_path, monkeypatch, clone, budget):
    base, sites, modules, originals, bound_files, bound, raw = fixture(
        tmp_path, monkeypatch, clone=clone, budget=budget)
    with OperationFacts().scope() as context:
        files, trees = parallel.input_dependencies(base, sites, _context=context)
        assert originals <= files and bound_files <= files and bound in files and trees == {raw}
        assert not ({Path(module.__file__) for module in modules} - originals) & files
        context.check()


@pytest.mark.parametrize('budget', [False, True], ids=['plain-eight', 'budget-ten'])
def test_original_receipt_bound_imports_are_preserved(tmp_path, monkeypatch, budget):
    base, sites, modules, originals, bound_files, bound, raw = fixture(
        tmp_path, monkeypatch, clone=True, budget=budget, overlap=True)
    assert bound_files == {Path(module.__file__) for module in modules}
    with OperationFacts().scope() as context:
        files, trees = parallel.input_dependencies(base, sites, _context=context)
        assert originals <= files and bound_files <= files and bound in files and trees == {raw}
        context.check()


@pytest.mark.parametrize('budget', [False, True], ids=['plain-eight', 'budget-ten'])
@pytest.mark.parametrize('validator', [0, -1])
def test_changed_execution_validator_refuses(tmp_path, monkeypatch, budget, validator):
    base, sites, modules, *_ = fixture(tmp_path, monkeypatch, clone=True, budget=budget)
    Path(modules[validator].__file__).write_bytes(b'different implementation')
    with OperationFacts().scope() as context:
        with pytest.raises(ValueError, match='differs from its declared runtime'):
            parallel.input_dependencies(base, sites, _context=context)


@pytest.mark.parametrize('drift', ['bytes', 'mode'])
@pytest.mark.parametrize('budget', [False, True], ids=['plain-eight', 'budget-ten'])
@pytest.mark.parametrize('validator', [0, -1])
def test_imported_validator_remains_in_closing_fence(tmp_path, monkeypatch, drift, budget, validator):
    base, sites, modules, *_ = fixture(tmp_path, monkeypatch, clone=True, budget=budget)
    imported = Path(modules[validator].__file__)
    with OperationFacts().scope() as context:
        parallel.input_dependencies(base, sites, _context=context)
        if drift == 'bytes':
            imported.write_bytes(imported.read_bytes() + b'\n')
        else:
            imported.chmod(imported.stat().st_mode & 0o7777 ^ 0o100)
        with pytest.raises(ValueError):
            context.check()
