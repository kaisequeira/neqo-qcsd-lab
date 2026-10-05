"""Raw selector/fence fixtures for explicit external runtime producer refs.

These fixtures test transport membership; no installed/runtime/witness
acceptance or scientific credit is manufactured.
"""
from pathlib import Path
import json

import pytest

from qcsd_lab import qualification_delivery_compatibility as compatibility
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_rolling_readiness as evidence


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return compatibility._ref(path)


@pytest.fixture
def declared(tmp_path):
    external = tmp_path / "immutable-reuse-producer"
    external.mkdir()
    recipe = external / "reuse_client.py"
    recipe.write_bytes(b"# retained external reuse producer\n")
    closer = external / "close_runtime.py"
    closer.write_bytes(b"# retained external closure producer\n")
    base_ref = write(tmp_path / "original-runtime/canonical-runtime.json", {
        "native_artifact_action": "new-cached-native-release-build",
        "closure_recipe": compatibility._ref(closer)})
    proof = write(tmp_path / "current-runtime/client-reuse.json", {"synthetic_metadata": True})
    native = write(tmp_path / "original-runtime/client-build.json", {"synthetic_metadata": True})
    current_ref = write(tmp_path / "current-runtime/canonical-runtime.json", {
        "native_artifact_action": "verified-exact-existing-client-reuse",
        "client_reuse_proof": proof, "client_reuse_recipe": compatibility._ref(recipe),
        "original_native_build_record": native, "original_canonical": base_ref,
        "closure_recipe": compatibility._ref(closer)})
    source = tmp_path / "source"
    source.mkdir()
    artifacts = {}
    for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        path = source / name
        path.write_bytes(b"retained artifact\n")
        artifacts[name] = str(path)
    runtime = {"runtime_source_root": str(source), "module_root": str(source), **artifacts}
    role = {"canonical": current_ref, "runtime": runtime}
    group = write(tmp_path / "complete-group/_qualification-set.json", {"synthetic_metadata": True})
    value = {"producer": role, "consumer": role, "qualification_group": group, "qualified_inputs": []}
    ref = write(tmp_path / "witness.json", value)
    return ref, value, recipe, closer, external


def test_authenticated_runtime_external_refs_are_selected_before_reuse(declared):
    ref, value, recipe, closer, external = declared
    files, trees = compatibility._raw_dependencies(ref, value)
    assert recipe in files and closer in files
    assert external not in trees
    assert len(files) == len(set(files))
    assert not any(recipe.is_relative_to(tree) for tree in trees)
    roots = {path.parent for path in files} | set(trees)
    assert external in roots


@pytest.mark.parametrize("field", ["client_reuse_proof", "client_reuse_recipe", "original_native_build_record", "closure_recipe"])
def test_present_invalid_runtime_ref_cannot_be_ignored(declared, field):
    ref, value, _recipe, _closer, _external = declared
    path = Path(value["consumer"]["canonical"]["path"])
    current = json.loads(path.read_bytes())
    current[field] = None
    replacement = write(path, current)
    for role in (value["producer"], value["consumer"]):
        role["canonical"] = replacement
    with pytest.raises((ValueError, TypeError)):
        compatibility._raw_dependencies(ref, value)


@pytest.mark.parametrize("mutation", ["bytes", "mode"])
def test_external_runtime_producer_mutation_invalidates_owned_fence(declared, mutation):
    ref, value, recipe, _closer, _external = declared
    context = operations.OperationFacts()
    with context.scope():
        compatibility._bind(context, ref, value)
        context.check()
        if mutation == "bytes":
            recipe.write_bytes(b"changed external producer\n")
        else:
            recipe.chmod(0o600 if recipe.stat().st_mode & 0o777 != 0o600 else 0o644)
        with pytest.raises(ValueError, match="bytes or mode"):
            context.check()


def test_changed_external_ref_digest_is_rejected_before_memo(declared):
    ref, value, recipe, _closer, _external = declared
    recipe.write_bytes(b"changed producer before validation\n")
    with pytest.raises(ValueError, match="SHA-256 differs"):
        compatibility._raw_dependencies(ref, value)
