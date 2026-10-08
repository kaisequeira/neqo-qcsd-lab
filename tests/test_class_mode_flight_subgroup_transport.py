"""HOST-only subgroup transport controls; no traffic or readiness proof.

Original admission/raw verification and metadata selection are explicit
controlled boundaries. The real typed subgroup, canonical path, file/full-mode
and tree fences, operator argv and readiness expected argv run here.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_enrolled_subgroup as subgroup
from qcsd_lab import rapid_operation_facts as facts
from qcsd_lab import rapid_per_class_selected_enrollment as per_class
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import selected_capture_amendment as additive_metadata
from qcsd_lab import per_class_selected_capture_amendment as per_class_metadata
from qcsd_lab import static_evidence_transport as transport

from tests.test_class_mode_flight_control import recipe, image_plan, volumes, common_volumes


def put(path, body=b"{}\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path


@pytest.fixture
def closure(tmp_path, monkeypatch):
    enrollment = put(tmp_path / "study/batches/b0004/enrollment.json")
    policy_file = put(tmp_path / "study/policy.json")
    admission = put(tmp_path / "admissions/original/terminal.json")
    source = tmp_path / "original-source"
    source_file = put(source / "src/qcsd_lab/original.py", b"# original Source\n")
    source_receipt = put(tmp_path / "original-export/source.json")
    graphs = [put(tmp_path / "original-inputs" / (name + ".json"),
                  json.dumps({"resources": [{"id": i} for i in range(count)]}).encode())
              for name, count in (("clarin", 201), ("dictionary", 38))]
    batch = {"ordinal": 4, "selected_candidate_ids": ["candidate-000037", "candidate-000039"]}
    classes = [{"class_index": index, "candidate_id": candidate, "workload_id": name,
                "prepared_workload": rolling._ref(graph)}
               for index, candidate, name, graph in zip(
                   (12, 13), batch["selected_candidate_ids"], ("clarin", "dictionary"), graphs)]
    value = subgroup.declare(enrollment, batch, classes, [12, 13])
    policy = {"contract": additive.CONTRACT}
    files = {enrollment, policy_file, admission, source_file, source_receipt, *graphs}
    trees = {source, source / "src/qcsd_lab"}
    calls = []

    def metadata(path, current_batch, current_classes, current_policy):
        assert path == enrollment
        assert current_batch == batch and current_classes == classes and current_policy is policy
        calls.append(current_policy["contract"])
        return files, trees

    monkeypatch.setattr(rolling, "_verify_enrollment", lambda path: (batch, classes, policy))
    monkeypatch.setattr(additive_metadata, "metadata_inputs", metadata)
    monkeypatch.setattr(per_class_metadata, "metadata_inputs", metadata)
    return {"enrollment": enrollment, "reference": rolling._ref(enrollment), "value": value,
            "batch": batch, "classes": classes, "policy": policy, "files": files, "trees": trees,
            "source": source, "policy_file": policy_file, "graphs": graphs, "calls": calls}


def flight(tmp_path, recipe, closure):
    plan, output = image_plan(tmp_path, recipe)
    for field in ("static_preparation_roots", "group_preparation_roots"):
        for directory in plan[field]:
            Path(directory).mkdir()
    plan.update({"enrollment": closure["reference"], subgroup.FIELD: closure["value"],
                 "helper_path": str(recipe.FIRST_HELPER),
                 "helper_sha256": recipe.FIRST_HELPER_SHA,
                 "recipe_sha256": recipe.digest(recipe.read(recipe.__file__))})
    selected = []
    for row, graph in zip(closure["classes"], closure["graphs"]):
        path = put(Path(plan["execution_root"]) / "config/workloads" / (row["workload_id"] + ".json"), graph.read_bytes())
        path.chmod(0o600)
        selected.append({**{key: row[key] for key in ("class_index", "candidate_id", "workload_id")},
                         "capture_manifest": recipe.ref(path)})
    plan["selected_classes"] = selected
    original = b'{"resources":[]}\n'
    put(output / "lineage/original-manifest.json", original)
    plan["original_workload_sha256"] = hashlib.sha256(original).hexdigest()
    return plan, output


@pytest.mark.parametrize("contract", [additive.CONTRACT, per_class.CONTRACT])
def test_typed_metadata_is_minimal_and_closed_in_owning_operation(contract, closure):
    closure["policy"]["contract"] = contract
    with facts.OperationFacts().scope() as context:
        roots = subgroup.input_roots(closure["reference"], closure["value"])
        expected = closure["trees"] | {path.parent for path in closure["files"]}
        expected = sorted(root for root in expected
                          if not any(root != parent and root.is_relative_to(parent) for parent in expected))
        assert roots == expected
        assert set(context._files) == closure["files"]
        assert set(context._trees) == {(path, True) for path in closure["trees"]}
        assert not any(root == closure["enrollment"].parents[3] for root in roots)
        # Unrelated later study outputs are not immutable Source membership.
        put(closure["policy_file"].parent / "future-output.json")
        context.check()
    assert closure["calls"] == [contract, contract]
    assert [len(json.loads(path.read_bytes())["resources"]) for path in closure["graphs"]] == [201, 38]


@pytest.mark.parametrize("action", ["preamble-image", "qualify-image", "preflight-image", "verify-image"])
def test_each_installed_action_transports_original_enrollment_readonly(action, tmp_path, recipe, closure):
    plan, output = flight(tmp_path, recipe, closure)
    roots = subgroup.input_roots(closure["reference"], closure["value"])
    argv = recipe.image_argv(plan, output, action)
    raw_roots = plan["group_preparation_roots"]
    if action == "verify-image":
        raw_roots = sorted(set(raw_roots) | set(plan["static_preparation_roots"]))
    expected = sorted(set(raw_roots) | set(map(str, roots)))
    assert volumes(argv) == common_volumes(plan, output, action) + [root + ":" + root + ":ro" for root in expected]
    for path in closure["files"]:
        assert any(path.is_relative_to(Path(root)) for root in roots)
    assert all(volume.endswith(":ro") for volume in volumes(argv)[5:])
    assert argv[argv.index("--network") + 1] == ("bridge" if action == "qualify-image" else "none")


def test_generated_deep_argv_equals_readiness_expected_argv(tmp_path, recipe, closure, monkeypatch):
    plan, output = flight(tmp_path, recipe, closure)
    # Current selected manifests are independently reopened for group transport.
    monkeypatch.setattr(transport, "manifest_roots",
                        lambda original: list(map(Path, plan["group_preparation_roots"]
                            if original["resources"] else plan["static_preparation_roots"])))
    result = "/lab/results/controlled-first-site/run"
    argv = recipe.image_argv(plan, output, "verify-image", "--mode", "undefended", "--result", result)
    assert readiness._deep_command(plan, output, recipe.digest(recipe.read(output / "plan.json")),
                                   "undefended", result, argv) == argv


@pytest.mark.parametrize("action", ["preamble-image", "qualify-image", "preflight-image", "verify-image"])
def test_non_subgroup_layout_preserves_exact_existing_argv(action, tmp_path, recipe, closure, monkeypatch):
    plan, output = flight(tmp_path, recipe, closure)
    del plan[subgroup.FIELD]
    monkeypatch.setattr(subgroup, "input_roots",
                        lambda *args: pytest.fail("non-subgroup command accessed subgroup inputs"))
    argv = recipe.image_argv(plan, output, action)
    roots = plan["static_preparation_roots"] if action == "verify-image" else plan["group_preparation_roots"]
    assert volumes(argv) == common_volumes(plan, output, action) + [root + ":" + root + ":ro" for root in roots]
    if action == "verify-image":
        monkeypatch.setattr(transport, "manifest_roots", lambda original: list(map(Path, roots)))
        result = "/lab/results/controlled-first-site/run"
        argv = recipe.image_argv(plan, output, action, "--mode", "undefended", "--result", result)
        assert readiness._deep_command(plan, output, recipe.digest(recipe.read(output / "plan.json")),
                                       "undefended", result, argv) == argv


@pytest.mark.parametrize("mutation", ["enrollment-bytes", "class-record", "class-order", "unknown-contract"])
def test_changed_subgroup_or_unregistered_policy_refused(mutation, closure):
    value = deepcopy(closure["value"])
    if mutation == "enrollment-bytes":
        closure["enrollment"].write_bytes(b'{"changed":true}\n')
    elif mutation == "class-record":
        closure["classes"][0]["workload_id"] = "different-full-graph"
    elif mutation == "class-order":
        value["class_indices"].reverse()
        value["classes"].reverse()
    else:
        closure["policy"]["contract"] = "unknown-selected-policy"
    with pytest.raises(ValueError):
        subgroup.input_roots(closure["reference"], value)


@pytest.mark.parametrize("mutation", ["symlink-file", "symlink-tree", "colon-parent", "missing-file"])
def test_unsafe_metadata_transport_refused(mutation, tmp_path, closure):
    if mutation == "symlink-file":
        target = put(tmp_path / "unlinked.json")
        closure["policy_file"].unlink()
        closure["policy_file"].symlink_to(target)
    elif mutation == "symlink-tree":
        alias = tmp_path / "source-alias"
        alias.symlink_to(closure["source"], target_is_directory=True)
        closure["trees"].add(alias)
    elif mutation == "colon-parent":
        closure["files"].add(put(tmp_path / "unsafe:mount/receipt.json"))
    else:
        closure["policy_file"].unlink()
    with pytest.raises(ValueError):
        subgroup.input_roots(closure["reference"], closure["value"])


@pytest.mark.parametrize("mutation", ["file-bytes", "file-full-mode", "source-membership"])
def test_metadata_dependencies_survive_until_outer_final_fence(mutation, closure):
    with facts.OperationFacts().scope() as context:
        subgroup.input_roots(closure["reference"], closure["value"])
        if mutation == "file-bytes":
            closure["policy_file"].write_bytes(b'{"changed":true}\n')
        elif mutation == "file-full-mode":
            closure["policy_file"].chmod(closure["policy_file"].stat().st_mode ^ 0o1000)
        else:
            put(closure["source"] / "added-source.py")
        with pytest.raises(ValueError):
            context.check()


def test_metadata_changed_during_reopen_refused_before_return(closure, monkeypatch):
    calls = []

    def metadata(*args):
        calls.append(1)
        if len(calls) == 2:
            closure["policy_file"].write_bytes(b'{"changed-during-validation":true}\n')
        return closure["files"], closure["trees"]

    monkeypatch.setattr(additive_metadata, "metadata_inputs", metadata)
    with pytest.raises(ValueError):
        subgroup.input_roots(closure["reference"], closure["value"])
    assert len(calls) == 2


@pytest.mark.parametrize("mutation", ["files", "trees"])
def test_metadata_selection_changed_during_reopen_refused(mutation, tmp_path, closure, monkeypatch):
    calls = []

    def metadata(*args):
        calls.append(1)
        files, trees = set(closure["files"]), set(closure["trees"])
        if len(calls) == 2:
            if mutation == "files":
                files.add(put(tmp_path / "new-authority.json"))
            else:
                directory = tmp_path / "new-source"
                directory.mkdir()
                trees.add(directory)
        return files, trees

    monkeypatch.setattr(additive_metadata, "metadata_inputs", metadata)
    with pytest.raises(ValueError):
        subgroup.input_roots(closure["reference"], closure["value"])
    assert len(calls) == 2


def test_optional_saved_preamble_failure_preserves_healthy_full_graph_metadata(tmp_path, recipe, monkeypatch):
    """Saved metadata is an oracle for transport shape, never a raw/deep proof."""
    root_text = os.environ.get("QCSD_SUBGROUP_TRANSPORT_HOST_ROOT")
    if root_text is None:
        pytest.skip("authentic saved HOST metadata oracle is optional")
    root = Path(root_text).absolute()
    from tests.test_rapid_target_chunks_ordinary_subgroup import ENROLLMENT, TARGET, GRAPHS, GRAPH_ROOT, pinned
    practice = root / ("diagnostic-rehearsals/"
        "ordinary-b0004-native818-source66-sdk-healthy012-013-practice-root-actual-20261008-002")
    saved_plan = pinned(practice, ("plan.json",
        "af685c764447e94ec971dca04ec858e0c6dfbc84606e0f88bd32e64649b5abc5", 0o600))
    saved_setup = pinned(practice, ("setup.json",
        "81932177bd7a7e79cf92f61ff75f1a45b45cdf51d3ec661b23ef151aac718f9d", 0o600))
    plan, setup = json.loads(saved_plan.read_bytes()), json.loads(saved_setup.read_bytes())
    enrollment = pinned(root, ENROLLMENT)
    assert plan["enrollment"] == rolling._ref(enrollment)
    target = json.loads(pinned(root, TARGET).read_bytes())["payload"]
    fields = ("candidate_id", "terminal", "admission_root", "class_index", "primary_origin",
              "workload_id", "canonical_sites", "capture_input", "prepared_workload")
    classes = [{key: deepcopy(row[key]) for key in fields} for row in target["classes"]
               if 12 <= row["class_index"] <= 16]
    batch = json.loads(enrollment.read_bytes())["payload"]
    subgroup.validate(plan[subgroup.FIELD], enrollment, batch, classes)
    assert plan[subgroup.FIELD]["class_indices"] == [12, 13]
    files = {enrollment}
    for identifier, digest, count in GRAPHS:
        path = pinned(root, (GRAPH_ROOT + "/" + identifier + ".json", digest, 0o600))
        assert len(json.loads(path.read_bytes())["resources"]) == count
        files.add(path)
    # The full original admission traversal is the same explicit boundary as
    # the portable unit controls; the actual saved graph bytes stay immutable.
    policy = {"contract": additive.CONTRACT}
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda path: (batch, classes, policy))
    monkeypatch.setattr(additive_metadata, "metadata_inputs", lambda *args: (files, set()))
    output = tmp_path / "oracle-output"
    output.mkdir()
    put(output / "plan.json", saved_plan.read_bytes())
    assert all(not enrollment.is_relative_to(Path(path)) for path in plan["static_preparation_roots"])
    assert any(enrollment.is_relative_to(Path(path)) for path in setup["original_roots"])
    for action in ("preamble-image", "verify-image"):
        argv = recipe.image_argv(plan, output, action)
        assert str(enrollment.parent) + ":" + str(enrollment.parent) + ":ro" in volumes(argv)
    assert plan["scientific_credit"] is False and plan["formal_accepted_trace_count"] == 0
