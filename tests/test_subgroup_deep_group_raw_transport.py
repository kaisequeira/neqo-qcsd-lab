"""HOST transport controls: two complete selected manifests, one captured site.

Enrollment verification and the original Native GET proof are explicit synthetic
boundaries. Stock manifest transport dispatch, canonical references, operator
argv, readiness equality, and OperationFacts byte/full-mode/raw-tree fences run
unchanged. These fixtures grant no admission, canary or capture credit.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_enrolled_subgroup as subgroup
from qcsd_lab import rapid_operation_facts as facts
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import static_evidence_transport as transport
from tests.test_class_mode_flight_control import recipe, image_plan, volumes, common_volumes


def put(path, raw=b"{}\n", mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


@pytest.fixture
def group(tmp_path, recipe, monkeypatch):
    plan, output = image_plan(tmp_path, recipe)
    metadata = tmp_path / "metadata"
    metadata_file = put(metadata / "enrollment.json")
    rows, manifests, raw_roots, semantic_files = [], [], [], []
    for index, candidate, name, count in ((12, "candidate-000037", "clarin", 201),
                                         (13, "candidate-000039", "dictionary", 38)):
        root = tmp_path / "original-GET" / candidate
        proof = put(root / "full-get-proof.json", b'{"controlled_original_proof":true}\n')
        original_receipt = put(metadata / (name + "-selected-input.json"))
        manifest = {"preparation": {"data_role": selected.ROLE,
                    "controlled_raw_root": str(root), "controlled_receipt": str(original_receipt)},
                    "resources": [{"id": ordinal} for ordinal in range(count)]}
        path = put(Path(plan["execution_root"]) / "config/workloads" / (name + ".json"),
                   json.dumps(manifest, sort_keys=True).encode() + b"\n")
        rows.append({"class_index": index, "candidate_id": candidate, "workload_id": name,
                     "capture_manifest": recipe.ref(path)})
        manifests.append(manifest); raw_roots.append(root)
        semantic_files.append({original_receipt, proof})
    identity = ("class_index", "candidate_id", "workload_id")
    authority = {"classes": [{key: row[key] for key in identity} for row in rows]}
    plan.update({"selected_classes": rows, subgroup.FIELD: authority,
        "enrollment": recipe.ref(metadata_file),
        "helper_path": str(recipe.FIRST_HELPER), "helper_sha256": recipe.FIRST_HELPER_SHA,
        "recipe_sha256": recipe.digest(recipe.read(recipe.__file__)),
        "static_preparation_roots": sorted(map(str, [metadata, raw_roots[0]])),
        "group_preparation_roots": sorted(map(str, [metadata, *raw_roots]))})
    original_raw = json.dumps(manifests[0], sort_keys=True).encode() + b"\n"
    put(output / "lineage/original-manifest.json", original_raw)
    plan["original_workload_sha256"] = hashlib.sha256(original_raw).hexdigest()

    # The separately tested enrollment and original GET validators are the
    # controlled boundary. Paths/resources and the actual final fences remain.
    def metadata_roots(reference, value):
        assert reference == recipe.ref(metadata_file) and value == authority
        context = facts.current_context()
        if context is not None:
            context.watch_file(metadata_file)
        return [metadata]

    def dependencies(preparation, resources):
        index = next(i for i, value in enumerate(manifests) if value["preparation"] == preparation)
        assert resources == manifests[index]["resources"]
        return set(semantic_files[index]), {raw_roots[index]}

    def preparation_roots(preparation, resources):
        files, trees = dependencies(preparation, resources)
        return sorted(trees | {path.parent for path in files})

    monkeypatch.setattr(subgroup, "input_roots", metadata_roots)
    monkeypatch.setattr(selected, "preparation_inputs", dependencies)
    monkeypatch.setattr(selected, "preparation_roots", preparation_roots)
    return {"plan": plan, "output": output, "rows": rows, "manifests": manifests,
            "raw_roots": raw_roots, "metadata": metadata, "semantic_files": semantic_files}


def deep(group, recipe):
    plan, output = group["plan"], group["output"]
    result = "/lab/results/controlled-first-site/run"
    argv = recipe.image_argv(plan, output, "verify-image", "--mode", "undefended", "--result", result)
    expected = readiness._deep_command(plan, output, recipe.digest(recipe.read(output / "plan.json")),
                                       "undefended", result, argv)
    return argv, expected


def test_subgroup_deep_transports_both_original_GET_trees_with_exact_operator_readiness_parity(group, recipe):
    assert str(group["raw_roots"][1]) not in group["plan"]["static_preparation_roots"]
    assert [len(value["resources"]) for value in group["manifests"]] == [201, 38]
    with facts.OperationFacts().scope() as context:
        argv, expected = deep(group, recipe)
        assert argv == expected
        roots = group["plan"]["group_preparation_roots"]
        assert volumes(argv) == common_volumes(group["plan"], group["output"], "verify-image") + [
            root + ":" + root + ":ro" for root in roots]
        assert set(context._trees) == {(root, False) for root in group["raw_roots"]}
        assert group["metadata"] not in {root for root, _ in context._trees}
        assert {Path(row["capture_manifest"]["path"]) for row in group["rows"]} <= set(context._files)
        context.check()
    assert argv[argv.index("--network") + 1] == "none"


@pytest.mark.parametrize("mutation", ["missing-second", "extra", "duplicate", "reordered", "rw-suffix"])
def test_hostile_declared_group_roots_refused_after_an_intact_baseline(mutation, tmp_path, group, recipe):
    assert deep(group, recipe)[0] == deep(group, recipe)[1]
    roots = group["plan"]["group_preparation_roots"]
    if mutation == "missing-second":
        roots.remove(str(group["raw_roots"][1]))
    elif mutation == "extra":
        extra = tmp_path / "unrelated"; extra.mkdir()
        roots.append(str(extra)); roots.sort()
    elif mutation == "duplicate":
        roots.append(roots[-1])
    elif mutation == "reordered":
        roots.reverse()
    else:
        roots[-1] += ":rw"
    with pytest.raises(ValueError):
        deep(group, recipe)


@pytest.mark.parametrize("mutation", ["sha", "bytes", "mode", "special-mode", "missing", "symlink",
                                      "wrong-name", "wrong-root", "relative", "extra-ref-field"])
def test_second_selected_manifest_cannot_escape_its_exact_hash_path_or_full_mode(mutation, tmp_path, group, recipe):
    assert deep(group, recipe)[0] == deep(group, recipe)[1]
    reference = group["rows"][1]["capture_manifest"]
    path = Path(reference["path"])
    if mutation == "sha":
        reference["sha256"] = "0" * 64
    elif mutation == "bytes":
        path.write_bytes(path.read_bytes() + b" \n")
    elif mutation == "mode":
        path.chmod(0o644)
    elif mutation == "special-mode":
        path.chmod(0o1600)
    elif mutation == "missing":
        path.unlink()
    elif mutation == "symlink":
        other = put(tmp_path / "same-bytes.json", path.read_bytes())
        path.unlink(); path.symlink_to(other)
    elif mutation in ("wrong-name", "wrong-root"):
        other = put(path.with_name("other.json") if mutation == "wrong-name" else tmp_path / path.name,
                    path.read_bytes())
        reference.update(recipe.ref(other))
    elif mutation == "relative":
        reference["path"] = path.name
    else:
        reference["mode"] = "0600"
    with pytest.raises(ValueError):
        deep(group, recipe)


def test_transport_parent_can_acquire_unrelated_output_without_changing_selected_inputs(group, recipe):
    with facts.OperationFacts().scope() as context:
        assert deep(group, recipe)[0] == deep(group, recipe)[1]
        put(group["metadata"] / "future-unrelated-output.json")
        context.check()


@pytest.mark.parametrize("mutation", ["manifest-bytes", "manifest-full-mode", "raw-bytes", "raw-full-mode",
                                      "raw-membership", "raw-directory-mode", "semantic-file"])
def test_actual_semantic_dependencies_remain_closed_until_the_owning_final_fence(mutation, group, recipe):
    with facts.OperationFacts().scope() as context:
        argv, expected = deep(group, recipe)
        assert argv == expected
        manifest = Path(group["rows"][1]["capture_manifest"]["path"])
        raw = group["raw_roots"][1]
        if mutation == "manifest-bytes":
            manifest.write_bytes(manifest.read_bytes() + b"\n")
        elif mutation == "manifest-full-mode":
            manifest.chmod(0o1600)
        elif mutation == "raw-bytes":
            (raw / "full-get-proof.json").write_bytes(b'{"changed":true}\n')
        elif mutation == "raw-full-mode":
            (raw / "full-get-proof.json").chmod(0o1600)
        elif mutation == "raw-membership":
            put(raw / "added.json")
        elif mutation == "raw-directory-mode":
            raw.chmod(raw.stat().st_mode ^ 0o1000)
        else:
            next(path for path in group["semantic_files"][1] if path.parent == group["metadata"]).write_bytes(b"changed\n")
        with pytest.raises(ValueError):
            context.check()


@pytest.mark.parametrize("action", ["preamble-image", "qualify-image", "preflight-image", "verify-image"])
def test_non_subgroup_commands_keep_the_exact_original_first_site_and_group_rules(action, group, recipe):
    del group["plan"][subgroup.FIELD]
    plan, output = group["plan"], group["output"]
    argv = recipe.image_argv(plan, output, action)
    roots = plan["static_preparation_roots"] if action == "verify-image" else plan["group_preparation_roots"]
    assert volumes(argv) == common_volumes(plan, output, action) + [root + ":" + root + ":ro" for root in roots]
    if action == "verify-image":
        assert str(group["raw_roots"][1]) + ":" + str(group["raw_roots"][1]) + ":ro" not in volumes(argv)
        assert deep(group, recipe)[0] == deep(group, recipe)[1]


def test_optional_authentic_failed_source68_deep_is_preserved_as_a_transport_failure():
    supplied = os.environ.get("QCSD_SOURCE68_SUBGROUP_PRACTICE_ROOT")
    if supplied is None:
        pytest.skip("authentic Source68 failed deep records are not bound")
    root = transport._path(Path(supplied).absolute(), directory=True)
    pins = {"plan.json": ("38291238b7dc242af4809c09fcc6afeeb90266d81de137d1268c0ee8dc47c0c4", 0o600),
        "logs/undefended-deep-started.json": ("acefa29590bf9013a795d129655c04fad4b9231778e879134bdfde72c301d8b0", 0o644),
        "logs/undefended-deep-completed.json": ("c75a139b0f1669d9905ed564128a3e25b623db0163b46004d5b7f26f5c3e2a54", 0o644),
        "logs/undefended-deep.stderr.log": ("909e8a68724950925aad7b1f46bf1b6eca6906661ea9a8f9ad79e70b66c552a0", 0o644)}
    raw = {}
    for relative, (sha, mode) in pins.items():
        path = transport._path(root / relative)
        raw[relative] = path.read_bytes()
        assert hashlib.sha256(raw[relative]).hexdigest() == sha
        assert path.stat().st_mode & 0o7777 == mode
    plan = json.loads(raw["plan.json"])
    started = json.loads(raw["logs/undefended-deep-started.json"])
    completed = json.loads(raw["logs/undefended-deep-completed.json"])
    missing = "/home/kaisequeira/University/THESIS/diagnostic-rehearsals/supplied-static-native5f-next-candidates-20261005-010/get-candidate-000039"
    assert missing in plan["group_preparation_roots"] and missing not in plan["static_preparation_roots"]
    assert missing + ":" + missing + ":ro" not in volumes(started["command"])
    assert [row["full_graph"]["resource_count"] for row in plan["selected_classes"]] == [201, 38]
    assert completed["returncode"] == 1 and completed["stderr_sha256"] == pins["logs/undefended-deep.stderr.log"][0]
    assert missing.encode() in raw["logs/undefended-deep.stderr.log"]
    assert plan["scientific_credit"] is False and plan["formal_accepted_trace_count"] == 0
