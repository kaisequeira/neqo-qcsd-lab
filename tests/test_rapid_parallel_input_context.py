"""Real parameter and campaign loading keeps Source separate from inputs."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from qcsd_lab import orchestrator, parameters, rapid_parallel_capture as parallel, util

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = ("buflo-live.json", "buflo-live.json.provenance.json",
            "cs-buflo-ctsp-live.json", "cs-buflo-ctsp-live.json.provenance.json")


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    source, execution = (tmp_path / name for name in ("immutable-source", "execution with spaces"))
    for root in (source, execution):
        (root / "config/defense-params").mkdir(parents=True)
        for name in FIXTURES:
            (root / "config/defense-params" / name).write_bytes((PROJECT / "config/defense-params" / name).read_bytes())
    (execution / "config/campaigns").mkdir()
    (execution / "config/workloads").mkdir()
    workload = "hyper-basic-client-r1"
    (execution / "config/workloads" / (workload + ".json")).write_bytes(
        (PROJECT / "config/workloads" / (workload + ".json")).read_bytes())
    campaigns = []
    for mode, kind, filename in (("buflo", "buflo", FIXTURES[0]),
                                 ("cs-buflo", "cs_buflo", FIXTURES[2])):
        path = execution / "config/campaigns" / (mode + ".yml")
        value = {"schema": 1, "name": "rapid-curated-tranco50-v2-diagnostic-" + mode,
            "purpose": "smoke", "seed": 1, "profile": "research-1200",
            "workloads": {workload: 1}, "request_policies": ["as-defined"],
            "defenses": [{"name": mode, "kind": kind, "parameters": "../defense-params/" + filename}]}
        path.write_text(yaml.safe_dump(value))
        campaigns.append({"path": str(path), "sha256": parallel.sha(path.read_bytes())})
    monkeypatch.setattr(parameters, "LAB_ROOT", source)
    monkeypatch.setenv("QCSD_LAB_ROOT", str(source))
    authority = {"runtime": {"runtime_source_root": str(source), "execution_root": str(execution)},
                 "campaigns": campaigns}
    return source, execution, authority, workload


def test_real_campaign_loader_reproduces_the_source_fixture_mismatch(inputs):
    source, _, authority, _ = inputs
    for row in authority["campaigns"]:
        with pytest.raises(ValueError, match="reviewed parameter fixtures must be checked in under"):
            orchestrator.load_campaign(Path(row["path"]))
    assert parameters.LAB_ROOT == source


@pytest.mark.parametrize("index", [0, 1])
def test_real_defense_loader_accepts_only_identical_canonical_execution_fixtures(inputs, index):
    source, execution, authority, _ = inputs
    row = authority["campaigns"][index]
    raw = yaml.safe_load(Path(row["path"]).read_bytes())
    source_context = util.LAB_ROOT
    with parallel._execution_parameter_context(authority):
        # This is the unmodified production loader and provenance/shape/fixture
        # verifier. Qualification image execution is a separate offline gate.
        defense, = orchestrator._load_defenses(Path(row["path"]).parent,
            raw["defenses"], "smoke", "research-1200", {})
        assert defense.parameters_path == execution / "config/defense-params" / FIXTURES[index * 2]
        assert defense.parameters_provenance_path == defense.parameters_path.with_suffix(".json.provenance.json")
        assert parameters.LAB_ROOT == execution
        assert util.LAB_ROOT == source_context
    assert parameters.LAB_ROOT == source


def test_real_campaign_reaches_qualification_after_parameter_guard_and_restores_on_error(inputs, monkeypatch):
    source, _, authority, _ = inputs
    class QualificationImageRequired(RuntimeError):
        pass
    def image_gate(*args, **kwargs):
        raise QualificationImageRequired("parameter guard passed; actual image qualification remains required")
    # Stop only at the later image gate. Campaign parsing, workloads, and every
    # actual parameter/provenance guard above it execute without substitution.
    monkeypatch.setattr(orchestrator, "_load_qualified_chaff_inputs", image_gate)
    for row in authority["campaigns"]:
        with pytest.raises(QualificationImageRequired), parallel._execution_parameter_context(authority):
            orchestrator.load_campaign(Path(row["path"]))
        assert parameters.LAB_ROOT == source


@pytest.mark.parametrize("filename", FIXTURES)
def test_any_execution_parameter_or_provenance_change_is_rejected_before_rebinding(inputs, filename):
    source, execution, authority, _ = inputs
    path = execution / "config/defense-params" / filename
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="differs from the clean runtime source"):
        with parallel._execution_parameter_context(authority):
            pytest.fail("changed fixture entered the input context")
    assert parameters.LAB_ROOT == source


@pytest.mark.parametrize("where", ["source-file", "execution-file", "execution-parent"])
def test_symlinked_fixture_file_or_parent_cannot_gain_input_authority(inputs, tmp_path, where):
    source, execution, authority, _ = inputs
    if where == "execution-parent":
        path = execution / "config/defense-params"
        moved = tmp_path / "external-fixtures"
        path.rename(moved)
        path.symlink_to(moved, target_is_directory=True)
    else:
        root = source if where == "source-file" else execution
        path = root / "config/defense-params" / FIXTURES[0]
        moved = tmp_path / "external-file"
        path.rename(moved)
        path.symlink_to(moved)
    with pytest.raises(ValueError, match="without symlinks"):
        with parallel._execution_parameter_context(authority):
            pytest.fail("symlinked fixture entered the input context")
    assert parameters.LAB_ROOT == source


@pytest.mark.parametrize("selection", ["alias", "source-absolute", "execution-absolute", "alias-symlink", "parent-symlink", "other-kind"])
def test_identical_but_noncanonical_campaign_parameter_selection_is_rejected(inputs, selection):
    source, execution, authority, _ = inputs
    path = Path(authority["campaigns"][0]["path"])
    raw = yaml.safe_load(path.read_bytes())
    defense = raw["defenses"][0]
    if selection == "alias":
        alternate = execution / "config/defense-params/alternate.json"
        alternate.write_bytes((execution / "config/defense-params" / FIXTURES[0]).read_bytes())
        defense["parameters"] = "../defense-params/alternate.json"
    elif selection == "source-absolute":
        defense["parameters"] = str(source / "config/defense-params" / FIXTURES[0])
    elif selection == "execution-absolute":
        defense["parameters"] = str(execution / "config/defense-params" / FIXTURES[0])
    elif selection == "alias-symlink":
        alternate = execution / "config/defense-params/alternate.json"
        alternate.symlink_to(execution / "config/defense-params" / FIXTURES[0])
        defense["parameters"] = "../defense-params/alternate.json"
    elif selection == "parent-symlink":
        (execution / "config/alias-params").symlink_to(execution / "config/defense-params", target_is_directory=True)
        defense["parameters"] = "../alias-params/" + FIXTURES[0]
    else:
        defense["kind"] = "front"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match="canonical execution parameter fixture|without symlinks"):
        with parallel._execution_parameter_context(authority):
            pytest.fail("alternate parameter selection entered the input context")
    assert parameters.LAB_ROOT == source


def test_changed_execution_root_and_original_guard_are_not_silently_accepted(inputs, tmp_path):
    source, _, authority, _ = inputs
    changed = copy.deepcopy(authority)
    changed["runtime"]["execution_root"] = str(tmp_path / "missing-execution")
    with pytest.raises(ValueError, match="directory must exist"):
        with parallel._execution_parameter_context(changed):
            pytest.fail("unknown execution root entered the input context")
    assert parameters.LAB_ROOT == source
    # Leaving the context has not widened the ordinary guard's accepted root.
    with pytest.raises(ValueError, match="reviewed parameter fixtures must be checked in under"):
        orchestrator.load_campaign(Path(authority["campaigns"][0]["path"]))
