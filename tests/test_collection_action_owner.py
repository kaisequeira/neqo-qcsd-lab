"""HOST collection ownership and exact Source projection controls.

Campaign parsing, materialization, sample planning, experiment initialization,
typed authority memo and byte/mode/membership fences are real. The original
qualification producer, installed runtime, study lock and collector are explicit
controlled boundaries. These checks grant no installed speed or capture credit.
"""
import ast
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

import pytest

from qcsd_lab import cli, orchestrator
from qcsd_lab import qualification_control_authority as control
from qcsd_lab import qualification_delivery_compatibility as delivery
from qcsd_lab import rapid_canary_control_bridge as bridge
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_rolling_readiness as ready
from tests.test_campaign import _configuration, _resource
from tests.test_rapid_canary_control_bridge import authority_case


def campaign(tmp_path):
    return _configuration(tmp_path, workloads={
        f"site-{number}": (4, [_resource(0, f"https://fixture-{number}.invalid/")])
        for number in range(1, 6)
    })


def count(monkeypatch, module, name, calls):
    original = getattr(module, name)

    def counted(*args, **kwargs):
        calls[name] = calls.get(name, 0) + 1
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, counted)


@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_public_collection_owner_spans_real_campaign_load_copy_plan_and_execute(
    tmp_path, monkeypatch, capsys, authority_case, entrypoint
):
    path = campaign(tmp_path / "campaign")
    reference = control.declare(authority_case.output,
        original_witness=authority_case.original_ref, consumer=authority_case.roles[1],
        body_policy=delivery.POLICY)
    calls, scopes = {}, []
    for module, name in ((delivery, "validate"), (delivery, "_bind"), (control, "_derive")):
        count(monkeypatch, module, name, calls)
    original_load, original_copy = orchestrator.load_campaign, orchestrator._materialize_inputs

    def qualified_readers(number):
        owner = operations.current_context()
        assert owner is not None
        scopes.append(owner)
        for _ in range(number):
            with control.qualification_context(reference, body_policy=delivery.POLICY):
                assert operations.current_context() is owner

    def load(*args, **kwargs):
        # One campaign authority + group + five site-reader scopes. Historical
        # scientific producer/runtime proof is the authority_case boundary.
        control.validate(reference, body_policy=delivery.POLICY)
        qualified_readers(6)
        return original_load(*args, **kwargs)

    def materialize(*args, **kwargs):
        # Five copied site-reader scopes + the copied named group scope.
        qualified_readers(6)
        return original_copy(*args, **kwargs)

    @contextmanager
    def lock(_root):
        scopes.append(operations.current_context())
        yield

    def execute(root, loaded, experiment):
        owner = operations.current_context()
        assert owner is not None and len(loaded.workloads) == 5
        assert len(experiment["samples"]) == 20
        assert any(key[0] == root / "inputs" for key in owner._trees)
        owner.check()
        scopes.append(owner)
        # The mutable result parent is deliberately not a watched input tree.
        (root / "collector-output.json").write_bytes(b"controlled collector boundary")
        return root

    monkeypatch.setattr(orchestrator, "load_campaign", load)
    monkeypatch.setattr(orchestrator, "_materialize_inputs", materialize)
    monkeypatch.setattr(orchestrator, "_has_durable_attempt_budget", lambda _campaign: True)
    monkeypatch.setattr(orchestrator, "_study_capture_lock", lock)
    monkeypatch.setattr(orchestrator, "_execute", execute)
    results = tmp_path / "results"
    if entrypoint == "cli":
        monkeypatch.setenv("QCSD_RESULTS_ROOT", str(results))
        cli.main(["run", str(path)])
        assert len(capsys.readouterr().out.splitlines()) == 1
    else:
        assert orchestrator.run_campaign(path, results).is_dir()
    assert calls == {"validate": 1, "_bind": 1, "_derive": 1}
    assert len(scopes) == 4 and all(owner is scopes[0] for owner in scopes)
    assert operations.current_context() is None


def test_borrowed_collection_owner_is_preserved_and_new_owned_action_reproves(
    tmp_path, monkeypatch, authority_case
):
    path = campaign(tmp_path / "campaign")
    reference = control.declare(authority_case.output,
        original_witness=authority_case.original_ref, consumer=authority_case.roles[1],
        body_policy=delivery.POLICY)
    calls = {}
    count(monkeypatch, control, "_derive", calls)
    original = orchestrator.load_campaign

    def load(*args, **kwargs):
        control.validate(reference, body_policy=delivery.POLICY)
        control.validate(reference, body_policy=delivery.POLICY)
        return original(*args, **kwargs)

    monkeypatch.setattr(orchestrator, "load_campaign", load)
    monkeypatch.setattr(orchestrator, "_execute", lambda root, *_args: root)
    owner = operations.OperationFacts()
    with owner.scope():
        orchestrator.run_campaign(path, tmp_path / "borrowed")
        assert operations.current_context() is owner
        owner.check()
    orchestrator.run_campaign(path, tmp_path / "fresh")
    assert calls["_derive"] == 2 and operations.current_context() is None


def test_campaign_mutation_during_lock_wait_refuses_before_materialization(tmp_path, monkeypatch):
    path = campaign(tmp_path)
    reached = []

    @contextmanager
    def lock(_root):
        path.write_bytes(path.read_bytes() + b"\n# changed while waiting\n")
        yield

    monkeypatch.setattr(orchestrator, "_has_durable_attempt_budget", lambda _campaign: True)
    monkeypatch.setattr(orchestrator, "_study_capture_lock", lock)
    monkeypatch.setattr(orchestrator, "_run_loaded_campaign", lambda *_args: reached.append("effect"))
    with pytest.raises(ValueError, match="operation dependency"):
        orchestrator.run_campaign(path, tmp_path / "results")
    assert reached == [] and operations.current_context() is None


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_frozen_input_mutation_refuses_immediately_before_collector(tmp_path, monkeypatch, mutation):
    from qcsd_lab import experiment

    path = campaign(tmp_path)
    reached = []
    original = experiment.initialize_experiment

    def initialize(root, **kwargs):
        value = original(root, **kwargs)
        frozen = root / "inputs" / "campaign.yml"
        if mutation == "bytes":
            frozen.write_bytes(frozen.read_bytes() + b"\n# changed after planning\n")
        elif mutation == "mode":
            frozen.chmod((frozen.stat().st_mode & 0o777) ^ 0o040)
        else:
            (frozen.parent / "unreported-member").write_bytes(b"unexpected input")
        return value

    monkeypatch.setattr(experiment, "initialize_experiment", initialize)
    monkeypatch.setattr(orchestrator, "_execute", lambda *_args: reached.append("effect"))
    with pytest.raises(ValueError, match="operation dependency"):
        orchestrator.run_campaign(path, tmp_path / "results")
    assert reached == [] and operations.current_context() is None


@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_success_fence_refuses_changed_campaign_before_success_output(tmp_path, monkeypatch, capsys, entrypoint):
    path = campaign(tmp_path)

    def execute(root, *_args):
        path.chmod((path.stat().st_mode & 0o777) ^ 0o040)
        return root

    monkeypatch.setattr(orchestrator, "_execute", execute)
    if entrypoint == "api":
        with pytest.raises(ValueError, match="operation dependency"):
            orchestrator.run_campaign(path, tmp_path / "results")
    else:
        monkeypatch.setenv("QCSD_RESULTS_ROOT", str(tmp_path / "results"))
        with pytest.raises(SystemExit) as failure:
            cli.main(["run", str(path)])
        assert failure.value.code == 1 and capsys.readouterr().out == ""
    assert operations.current_context() is None


def test_incomplete_collection_keeps_original_cli_status_and_retained_root(tmp_path, monkeypatch, capsys):
    path = campaign(tmp_path)
    roots = []

    def execute(root, *_args):
        roots.append(root)
        raise orchestrator.CampaignIncomplete(root)

    monkeypatch.setattr(orchestrator, "_execute", execute)
    monkeypatch.setenv("QCSD_RESULTS_ROOT", str(tmp_path / "results"))
    with pytest.raises(SystemExit) as failure:
        cli.main(["run", str(path)])
    captured = capsys.readouterr()
    assert failure.value.code == 1 and captured.out == str(roots[0]) + "\n"
    assert captured.err == f"campaign incomplete; evidence retained at {roots[0]}\n"
    assert (roots[0] / "experiment.json").is_file()
    assert operations.current_context() is None


def altered(raw, relative, *, control_unit=True):
    tree = ast.parse(raw)
    if relative.endswith("/cli.py"):
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        target = "run" if control_unit else "resume"
        branch = next(node for node in main.body if isinstance(node, ast.If)
            and ast.dump(node.test) == ast.dump(ast.parse(f'args.command == "{target}"', mode="eval").body))
        branch.body.insert(0, ast.Expr(value=ast.Constant(value="controlled changed branch")))
    else:
        target = "run_campaign" if control_unit else "_execute"
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == target)
        function.body.insert(0, ast.Expr(value=ast.Constant(value="controlled changed function")))
    return ast.unparse(tree).encode()


@pytest.mark.parametrize("relative", ["src/qcsd_lab/cli.py", "src/qcsd_lab/orchestrator.py"])
def test_exact_collection_projection_records_only_named_controls(authority_case, relative):
    before, after = deepcopy(authority_case.after), deepcopy(authority_case.after)
    after[relative] = altered(after[relative], relative)
    comparison = control._source_comparison(before, after)
    names = set(comparison["changed_consumer_units"][relative]["new_units"])
    assert "main.run" in names if relative.endswith("/cli.py") else {"run_campaign", "_run_loaded_campaign"} <= names
    old, old_units = control._collection_control_project(relative, before[relative])
    new, new_units = control._collection_control_project(relative, after[relative])
    assert old == new and old_units != new_units


@pytest.mark.parametrize("relative", ["src/qcsd_lab/cli.py", "src/qcsd_lab/orchestrator.py"])
def test_qualification_projection_refuses_other_cli_branch_or_capture_acceptance(authority_case, relative):
    before, after = deepcopy(authority_case.after), deepcopy(authority_case.after)
    after[relative] = altered(after[relative], relative, control_unit=False)
    with pytest.raises(ValueError, match="unnamed qualification implementation"):
        control._source_comparison(before, after)


def test_projector_refuses_duplicate_or_moved_run_branch():
    relative = "src/qcsd_lab/cli.py"
    for raw in (b'def main():\n if args.command == "run":\n  pass\n if args.command == "run":\n  pass\n',
                b'def main():\n if True:\n  if args.command == "run":\n   pass\n'):
        with pytest.raises(ValueError, match="exact direct CLI RUN branch"):
            control._collection_control_project(relative, raw)


@pytest.mark.parametrize("relative", ["src/qcsd_lab/cli.py", "src/qcsd_lab/orchestrator.py"])
def test_bridge_protects_all_residual_bytes_and_records_collection_units(tmp_path, monkeypatch, relative):
    repository = Path(__file__).parents[1]
    for name in ("qcsd-lab", "src/qcsd_lab/cli.py", "src/qcsd_lab/orchestrator.py"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((repository / name).read_bytes())

    def groups(root, _inventory):
        return {"measurement": {"qcsd-lab:protected-measurement": {"sha256": "shell", "executable": True},
            "src/qcsd_lab/orchestrator.py": {"sha256": ready._sha((root / "src/qcsd_lab/orchestrator.py").read_bytes()), "executable": False}},
            "chaff": {"src/qcsd_lab/cli.py": {"sha256": ready._sha((root / "src/qcsd_lab/cli.py").read_bytes()), "executable": False}}}, {}

    monkeypatch.setattr(ready, "_groups", groups)
    before, units = bridge._groups(tmp_path, {})
    path = tmp_path / relative
    raw = path.read_bytes()
    path.write_bytes(altered(raw, relative))
    after, changed = bridge._groups(tmp_path, {})
    assert before == after and units["collection_control_units"] != changed["collection_control_units"]
    path.write_bytes(altered(raw, relative, control_unit=False))
    residual, _ = bridge._groups(tmp_path, {})
    assert residual != before
