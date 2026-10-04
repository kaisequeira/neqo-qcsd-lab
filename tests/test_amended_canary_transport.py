"""HOST transport fixtures; no Native, image, qualification or capture credit."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab import supplied_static_preparation as preparation
from tests.test_supplied_static_capture_amendment import original, publish
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture


@pytest.fixture
def amended(original):
    publish(original, front=True, buflo=False)
    directory = original.study / "canary"
    (directory / "lineage").mkdir(parents=True)
    (directory / "lineage/original-manifest.json").write_bytes(original.original.read_bytes())
    recipe, helper = directory / "recipe.py", directory / "helper.py"
    recipe.write_bytes(b"# HOST opaque recorded recipe fixture\n")
    helper.write_bytes(b"# HOST opaque recorded helper fixture\n")
    plan = {"name": "host-amended-fixture", "recipe_sha256": readiness._sha(recipe.read_bytes()),
        "helper_sha256": readiness._sha(helper.read_bytes()),
        "helper_path": str(helper), "recipe_path": str(recipe),
        "original_workload_sha256": readiness._sha(original.original.read_bytes()),
        "workload_sha256": readiness._sha(original.target.read_bytes()),
        "workload_relative": original.target.relative_to(Path(original.runtime["execution_root"])).as_posix(),
        "clean_runtime_root": original.runtime["runtime_source_root"],
        "execution_root": original.runtime["execution_root"], "static_capture_amendment": preparation.reference(original.output),
        "data_role": json.loads(original.target.read_bytes())["preparation"]["data_role"],
        "canonical_runtime": {"collection_image_digest": original.runtime["collection_image_digest"]}}
    return original, directory, plan


def command(a, directory, plan):
    plan["static_preparation_roots"] = [str(root) for root in transport.amended_canary_roots(plan, directory)]
    (directory / "plan.json").write_bytes(readiness._encoded(plan))
    image = plan["canonical_runtime"]["collection_image_digest"]
    argv = ["docker", "run", "--rm", "--name", "qcsd-v12-host-amended-fixture-verify-image",
            "--network", "none", "--user", "1000:1000", "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL", "--env", "QCSD_LAB_IMAGE_DIGEST=" + image,
            "--env", "QCSD_LAB_ROOT=/lab", "--env", "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json",
            "--env", "QCSD_PUBLIC_ORIGIN_ONLY=1", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--volume", plan["clean_runtime_root"] + ":/runtime-src:ro",
            "--volume", plan["execution_root"] + ":/lab:ro", "--volume", str(directory) + ":/diagnostic:rw",
            "--volume", plan["recipe_path"] + ":/recipe.py:ro", "--volume", plan["helper_path"] + ":/helpers.py:ro"]
    for root in plan["static_preparation_roots"]:
        argv += ["--volume", root + ":" + root + ":ro"]
    return argv + ["--workdir", "/lab", "--entrypoint", "/opt/qcsd-venv/bin/python3", image,
                   "-I", "-B", "/recipe.py", "verify-image", "--plan", "/diagnostic/plan.json",
                   "--plan-sha256", readiness._sha((directory / "plan.json").read_bytes()),
                   "--mode", "front", "--result", "/lab/results/fixture/001"]


def test_amended_exact_public_deep_argv_and_all_absolute_readonly_roots(amended):
    a, directory, plan = amended
    argv = command(a, directory, plan)
    expected = readiness._deep_command(plan, directory, readiness._sha((directory / "plan.json").read_bytes()),
                                      "front", "/lab/results/fixture/001", argv)
    assert argv == expected
    roots = transport.amended_canary_roots(plan, directory)
    required = [Path(a.runtime["runtime_source_root"]), Path(a.runtime["execution_root"]),
                Path(a.runtime["client_binary"]).parent, a.output.parent, a.context.root, a.get_root]
    for path in required:
        assert any(path == root or path.is_relative_to(root) for root in roots)
    for root in roots:
        assert argv.count(f"{root}:{root}:ro") == 1
        assert f"{root}:{root}:rw" not in argv


@pytest.mark.parametrize("mutation", ["declaration", "source", "client", "lineage", "derived", "receipt"])
def test_changed_or_absent_bound_amendment_inputs_reject_transport(amended, mutation):
    a, directory, plan = amended
    if mutation == "declaration":
        json.loads(a.target.read_bytes())  # fixture target is independently retained
        declaration = preparation.open_reference(json.loads(a.output.read_bytes())["payload"]["declaration"])
        declaration.unlink()
    elif mutation == "source":
        (Path(a.runtime["runtime_source_root"]) / "src/qcsd_lab/kernel_tx.py").unlink()
    elif mutation == "client":
        Path(a.runtime["client_binary"]).unlink()
    elif mutation == "lineage":
        (directory / "lineage/original-manifest.json").write_bytes(b"{}\n")
    elif mutation == "derived":
        value = json.loads(a.target.read_bytes())
        value["resources"].pop()
        a.target.write_bytes(readiness._encoded(value))
    else:
        a.output.write_bytes(b"{}\n")
    with pytest.raises((ValueError, FileNotFoundError, KeyError)):
        transport.amended_canary_roots(plan, directory)


def test_readiness_roots_include_authenticated_amendment_declaration(amended, monkeypatch):
    a, directory, plan = amended
    argv = command(a, directory, plan)
    started = directory / "deep-started.json"
    started.write_bytes(readiness._encoded({"command": argv}))
    reference = {"schema_version": 1, "plan": preparation.reference(directory / "plan.json"),
                 "deep": {"started": preparation.reference(started)}}
    # This fixture tests transport after the canary validator boundary only.
    # Real public readiness must still validate actual capture/deep operations.
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: {})
    roots = readiness.readiness_mount_roots(reference, runtime=a.runtime, mode="front")
    assert set(transport.amended_canary_roots(plan, directory)) <= set(roots)
    assert a.study in roots


def test_caller_roots_cannot_inject_a_volume(amended):
    a, directory, plan = amended
    plan["static_preparation_roots"] = ["/caller/arbitrary"]
    recipe, helper = Path(plan["recipe_path"]), Path(plan["helper_path"])
    argv = ["docker", "run", "--user", "1000:1000",
            "--volume", str(recipe) + ":/recipe.py:ro", "--volume", str(helper) + ":/helpers.py:ro"]
    expected = readiness._deep_command(plan, directory, "b" * 64, "front", "/lab/results/fixture/001", argv)
    assert all("/caller/arbitrary" not in arg for arg in expected)


def test_missing_bound_source_client_or_declaration_mount_changes_exact_expected_command(amended):
    a, directory, plan = amended
    argv = command(a, directory, plan)
    expected = readiness._deep_command(plan, directory, readiness._sha((directory / "plan.json").read_bytes()),
                                      "front", "/lab/results/fixture/001", argv)
    for required in (a.output.parent, Path(a.runtime["client_binary"]).parent,
                     Path(a.runtime["runtime_source_root"])):
        roots = transport.amended_canary_roots(plan, directory)
        root, = [root for root in roots if required == root or required.is_relative_to(root)]
        missing = list(argv)
        index = missing.index(f"{root}:{root}:ro")
        del missing[index - 1:index + 1]
        assert missing != expected


def test_workload_escape_and_receipt_substitution_cannot_add_roots(amended):
    a, directory, plan = amended
    changed = deepcopy(plan)
    changed["workload_relative"] = "../escape.json"
    with pytest.raises(ValueError, match="outside"):
        transport.amended_canary_roots(changed, directory)
    changed = deepcopy(plan)
    changed["static_capture_amendment"] = preparation.reference(a.enrollment)
    with pytest.raises(ValueError):
        transport.amended_canary_roots(changed, directory)
