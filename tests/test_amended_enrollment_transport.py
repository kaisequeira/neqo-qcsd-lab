"""HOST-only split-runtime transport; real validators, synthetic measurement data."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab import supplied_static_capture_amendment as amendment
from qcsd_lab import supplied_static_preparation as preparation
from tests.test_amended_canary_transport import command
from tests.test_supplied_static_capture_amendment import original, publish
from tests.test_supplied_static_preparation import actual_contract_fixture, fixed_graph, runtime


@pytest.fixture
def split_runtime(original):
    a = original
    old_runtime = dict(a.runtime)
    base = Path(old_runtime["data_root"]) / "prospective-runtime"
    _, current = runtime(base)
    current["data_root"] = old_runtime["data_root"]
    for relative in amendment.SOURCE_FILES.values():
        path = Path(current["runtime_source_root"]) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((Path(__file__).resolve().parents[1] / relative).read_bytes())
    a.runtime = current
    a.target = Path(current["workload_root"]) / a.original.name
    publish(a, front=True, buflo=False)
    directory = base / "canary"
    (directory / "lineage").mkdir(parents=True)
    (directory / "lineage/original-manifest.json").write_bytes(a.original.read_bytes())
    recipe, helper = directory / "recipe.py", directory / "helper.py"
    recipe.write_bytes(b"# HOST transport recipe fixture\n")
    helper.write_bytes(b"# HOST transport helper fixture\n")
    plan = {"name": "host-amended-fixture", "recipe_sha256": readiness._sha(recipe.read_bytes()),
        "helper_sha256": readiness._sha(helper.read_bytes()), "helper_path": str(helper), "recipe_path": str(recipe),
        "original_workload_sha256": readiness._sha(a.original.read_bytes()),
        "workload_sha256": readiness._sha(a.target.read_bytes()),
        "workload_relative": a.target.relative_to(Path(current["execution_root"])).as_posix(),
        "clean_runtime_root": current["runtime_source_root"], "execution_root": current["execution_root"],
        "static_capture_amendment": preparation.reference(a.output),
        "data_role": json.loads(a.target.read_bytes())["preparation"]["data_role"],
        "canonical_runtime": {"collection_image_digest": current["collection_image_digest"]}}
    return a, old_runtime, directory, plan


def test_distinct_original_policy_runtime_is_transported_without_data_root(split_runtime):
    a, old, directory, plan = split_runtime
    closed = amendment._closed(a.output)
    assert closed["runtime"] == a.runtime and a.runtime != old
    roots = transport.manifest_roots(json.loads(a.target.read_bytes()))
    required = {a.study, Path(old["runtime_source_root"]), Path(old["module_root"]),
                Path(old["execution_root"]), Path(old["source_manifest"]).parent,
                Path(old["client_binary"]).parent, Path(old["base_launcher"]).parent,
                Path(old["host_launcher"]).parent}
    assert all(any(path == root or path.is_relative_to(root) for root in roots) for path in required)
    assert Path(old["data_root"]) not in roots
    assert not any(Path(old["data_root"]).is_relative_to(root) for root in roots)
    # Original GET/admission and the declaration's current runtime remain bound.
    assert a.get_root in roots and a.context.root in roots
    assert Path(a.runtime["runtime_source_root"]) in roots
    assert Path(a.runtime["execution_root"]) in roots


def test_public_campaign_and_deep_share_exact_transitive_roots(split_runtime):
    a, old, directory, plan = split_runtime
    roots = transport.amended_canary_roots(plan, directory)
    campaign = Path(a.runtime["campaign_dir"]) / "host-transport.yml"
    campaign.write_text("workloads:\n  " + a.target.stem + ": {}\n")
    assert transport.campaign_roots(Path(a.runtime["execution_root"]), "run", campaign) == roots
    argv = command(a, directory, plan)
    assert argv == readiness._deep_command(plan, directory,
        readiness._sha((directory / "plan.json").read_bytes()), "front", "/lab/results/fixture/001", argv)
    for required in (Path(old["runtime_source_root"]), Path(old["execution_root"]), a.study):
        root, = [root for root in roots if required == root or required.is_relative_to(root)]
        assert argv.count(f"{root}:{root}:ro") == 1
        assert f"{root}:{root}:rw" not in argv
        missing = list(argv)
        index = missing.index(f"{root}:{root}:ro")
        del missing[index - 1:index + 1]
        assert missing != argv


@pytest.mark.parametrize("key", ["source_manifest", "client_binary", "base_launcher", "host_launcher"])
def test_missing_original_policy_artifact_rejects_before_mount_derivation(split_runtime, key):
    a, old, directory, plan = split_runtime
    Path(old[key]).unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        transport.amended_canary_roots(plan, directory)


def test_replaced_original_policy_and_arbitrary_caller_roots_are_not_authority(split_runtime):
    a, old, directory, plan = split_runtime
    changed = deepcopy(plan)
    changed["static_preparation_roots"] = ["/caller/injected"]
    assert "/caller/injected" not in {str(path) for path in transport.amended_canary_roots(changed, directory)}
    (a.study / "policy.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError):
        transport.amended_canary_roots(plan, directory)


def test_original_static_preparation_adds_no_enrollment_or_capture_runtime_mount(split_runtime):
    a, old, directory, plan = split_runtime
    roots = transport.manifest_roots(json.loads(a.original.read_bytes()))
    assert a.study not in roots
    assert Path(old["runtime_source_root"]) not in roots
    assert Path(old["execution_root"]) not in roots

def test_sealed_parent_and_inherited_deferral_roots_exclude_later_decisions(split_runtime, monkeypatch, tmp_path):
    """Selection-only fixture after the declaration's real validator boundary."""
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import rapid_site_admission as receipts
    from qcsd_lab import supplied_static_admission as admission
    a, old, directory, plan = split_runtime
    declaration_path = preparation.open_reference(json.loads(a.output.read_bytes())["payload"]["declaration"])
    verified = amendment._declaration(declaration_path)
    # First prove this fixture's ordinary declaration with the real validators.
    # The following sealed metadata models transport selection only, not a
    # fabricated passing enrollment, GET, source, qualification or capture.
    get_root, outer = tmp_path / "retained-failed-get", tmp_path / "outer-closure"
    get_root.mkdir()
    outer.mkdir()
    namespace = {}
    for key in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"):
        path = outer / (key + ".json")
        path.write_bytes(b"HOST sealed transport prefix fixture\n")
        namespace[key] = preparation.reference(path)
    terminal = tmp_path / "sealed-deferral.json"
    value = json.loads(a.terminal.read_bytes())["payload"]
    value.update(outcome="operational-deferred", prepared_workload=None,
                 get_evidence_root=str(get_root), namespace=namespace)
    terminal.write_bytes(receipts._json(receipts._bind(admission.TERMINAL_TYPE, value)))
    child_context = tmp_path / "sealed-parent-context"
    child_context.mkdir()
    context = json.loads((a.context.root / "provenance.json").read_bytes())["payload"]
    context.update(parent_context=preparation.reference(a.context.root / "provenance.json"),
                   inherited_terminals=[preparation.reference(terminal)])
    context_path = child_context / "provenance.json"
    context_path.write_bytes(receipts._json(receipts._bind(admission.PROVENANCE_TYPE, context)))
    batch = json.loads(a.enrollment.read_bytes())["payload"]
    batch.update(parent=preparation.reference(a.enrollment), admission_root=str(child_context),
                 admission_provenance=preparation.reference(context_path))
    extension = a.study / "batches/b0002/enrollment.json"
    extension.parent.mkdir()
    extension.write_bytes(receipts._json(receipts._bind(rolling.ENROLLMENT_TYPE, batch)))
    selected = dict(verified, enrollment=preparation.reference(extension))
    monkeypatch.setattr(amendment, "_declaration", lambda *args, **kwargs: selected)
    later_root = tmp_path / "later-unbound-get"
    later_root.mkdir()
    # An unbound later terminal has no bearing on an already sealed enrollment.
    (child_context / "later-terminal.json").write_bytes(
        json.dumps({"get_evidence_root": str(later_root)}).encode())
    roots = amendment.preparation_roots(json.loads(a.target.read_bytes())["preparation"])
    assert get_root in roots and outer in roots and child_context in roots
    assert a.context.root in roots and later_root not in roots
    (outer / "outer_stderr.json").write_bytes(b"changed bound prefix log\n")
    with pytest.raises(ValueError, match="referenced bytes"):
        amendment.preparation_roots(json.loads(a.target.read_bytes())["preparation"])
