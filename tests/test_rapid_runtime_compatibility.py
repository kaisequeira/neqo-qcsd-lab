"""Role comparison uses real source surfaces; only image actuation is absent."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_runtime_compatibility as compatibility


@pytest.fixture(scope="module")
def original_sources():
    root = Path(__file__).parents[1]
    paths = {*(root / "src/qcsd_lab").glob("*.py"),
             *(root / path for path in qualification.IMPLEMENTATION_STATIC_FILES)}
    sources = {path.relative_to(root).as_posix(): path.read_bytes() for path in paths}
    # An unchanged fixed fixture and Native source snapshot are covered by the
    # source inventory, independently of their runtime identity labels.
    sources["config/defense-params/buflo-live.json"] = b'{"fixed": true}\n'
    sources["neqo-qcsd/neqo-bin/src/qcsd/mod.rs"] = b"// fixed Native source\n"
    return sources


def runtime(sources, *, successor=False):
    hashes = compatibility._source_inventory(sources)
    source = {
        "image_digest": None, "lab_commit": ("d" if successor else "b") * 40,
        "lab_dirty": False, "lab_patch_sha256": qualification.EMPTY_SHA256,
        "neqo_commit": "c" * 40, "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": qualification.EMPTY_SHA256,
    }
    implementation = {
        "schema_version": 2, "artifact_type": "qcsd-chaff-qualification-implementation",
        "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN, "source": source,
        "source_files": {path: hashes[path] for path in qualification.IMPLEMENTATION_FILES},
        "installed_modules": {
            path: {"path": f"/installed/{path}", "sha256": hashes[path]}
            for path in qualification.IMPLEMENTATION_PYTHON_FILES
        },
        "installed_entrypoint": {"path": "/installed/qcsd-lab", "sha256": hashes["qcsd-lab"]},
        "neqo_qcsd_client": {"path": "/usr/local/bin/neqo-qcsd-client", "sha256": "e" * 64},
    }
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    image = "sha256:" + ("f" if successor else "a") * 64
    return {
        "schema_version": 1, "artifact_type": "qcsd-rapid-v5-installed-runtime-preflight",
        "collection_image_digest": image, "runtime_source": {**source, "image_digest": image},
        "source_manifest_sha256": compatibility._sha(compatibility._json(source)),
        "client_sha256": "e" * 64, "base_launcher_sha256": hashes["qcsd-lab"],
        "host_launcher_sha256": "9" * 64, "qualification_implementation": implementation,
        "traffic_hashes": {"buflo": compatibility._sha(sources["config/defense-params/buflo-live.json"])},
        "formal_accepted_trace_count": 0, "scientific_credit": False,
    }


def review(old, new, functions):
    return {
        "schema_version": 1, "artifact_type": compatibility.REVIEW_TYPE,
        "repair_scope": "collector-lifecycle-only",
        "reason": "Fix observer startup/copy lifecycle while preserving every qualification and traffic role.",
        "changes": {
            path: {"before_sha256": compatibility._sha(old[path]),
                   "after_sha256": compatibility._sha(new[path]), "functions": names}
            for path, names in functions.items()
        },
    }


def changed_sources(original_sources):
    old = dict(original_sources)
    new = dict(old)
    path = "src/qcsd_lab/capture_session.py"
    needle = b'raise RuntimeError("dumpcap exited before capture start")'
    assert needle in new[path]
    new[path] = new[path].replace(needle, b'raise RuntimeError("dumpcap exited while awaiting observer readiness")', 1)
    return old, new, {path: ["_wait_for_capture_start"]}


def bridge(old, new, functions):
    return compatibility.validate_compatibility(
        runtime(old), runtime(new, successor=True), old, new, review(old, new, functions))


def test_actual_source_dependency_surface_separates_v2_from_collector(original_sources):
    surface = compatibility.qualification_dependencies(original_sources)
    assert surface["root_functions"] == list(compatibility.ROOT_FUNCTIONS)
    assert "src/qcsd_lab/chaff_qualification.py" in surface["source_hashes"]
    assert "src/qcsd_lab/process_scheduler.py" in surface["source_hashes"]
    assert "src/qcsd_lab/capture.py" in surface["source_hashes"]
    assert "src/qcsd_lab/capture_session.py" not in surface["source_hashes"]
    assert "src/qcsd_lab/orchestrator.py" not in surface["source_hashes"]
    assert "chaff_qualification._run_response_qualifications_v2" in surface["reachable_symbols"]
    assert "prepare._run_neqo" in surface["reachable_symbols"]
    assert surface["authority_boundaries"] == ["chaff_qualification._validate_implementation_receipt"]


def test_reviewed_observer_repair_reuses_all_installed_qualification_roles(original_sources):
    old, new, functions = changed_sources(original_sources)
    result = bridge(old, new, functions)
    assert result["changed_sources"] == review(old, new, functions)["changes"]
    assert result["client_sha256"] == "e" * 64
    assert result["formal_accepted_trace_count"] == 0
    assert result["scientific_credit"] is False
    assert result["old_source_hashes"] != result["new_source_hashes"]
    compatibility.validate_current_implementation(
        runtime(old)["qualification_implementation"],
        runtime(new, successor=True)["qualification_implementation"], result)


def test_provenance_commit_and_image_labels_can_change_without_executable_changes(original_sources):
    result = bridge(original_sources, original_sources, {})
    assert result["changed_sources"] == {}
    assert result["old_implementation_sha256"] != result["new_implementation_sha256"]
    assert result["old_source_hashes"] == result["new_source_hashes"]


def test_cumulative_base_to_successor_review_preserves_both_repairs(original_sources):
    old, new, functions = changed_sources(original_sources)
    path = "src/qcsd_lab/capture_session.py"
    needle = b"shutil.copyfileobj(reader, writer, length=1024 * 1024)"
    assert needle in new[path]
    new[path] = new[path].replace(needle, b"shutil.copyfileobj(reader, writer, length=512 * 1024)", 1)
    functions[path] = ["_copy_create_once", "_wait_for_capture_start"]
    result = bridge(old, new, functions)
    assert result["changed_sources"][path]["functions"] == functions[path]


def test_checkpoint_persistence_repair_protects_summary_authority(original_sources):
    old = dict(original_sources)
    new = dict(old)
    path = "src/qcsd_lab/orchestrator.py"
    needle = b"    checkpoint_experiment(root, experiment)\n"
    assert needle in new[path]
    new[path] = new[path].replace(needle, b"    # Keep persistence scoped to this exact frozen experiment.\n" + needle, 1)
    result = bridge(old, new, {path: ["_checkpoint"]})
    assert result["changed_sources"][path]["functions"] == ["_checkpoint"]
    bad = dict(new)
    bad[path] = bad[path].replace(b'passed=experiment.get("status") == "complete"', b"passed=True", 1)
    with pytest.raises(ValueError, match="summary or checkpoint authority"):
        bridge(old, bad, {path: ["_checkpoint"]})


def test_reviewed_packet_reconciliation_repair_preserves_qualification_projection(original_sources):
    old = dict(original_sources)
    new = dict(old)
    path = "src/qcsd_lab/fidelity.py"
    needle = b'raise ValueError("direct trace is empty")'
    assert needle in new[path]
    new[path] = new[path].replace(needle, b'raise ValueError("direct packet observation is empty")', 1)
    result = bridge(old, new, {path: ["_read_direct_packets"]})
    assert result["changed_sources"][path]["functions"] == ["_read_direct_packets"]
    assert result["qualification_dependencies"]["source_projections"][path][
        "excluded_collector_functions"] == ["_read_direct_packets", "_reconcile_runner_packets"]
    bad = dict(new)
    needle = b"DEFAULT_TIMESTAMP_TOLERANCE_NS = 10_000_000"
    assert needle in bad[path]
    bad[path] = bad[path].replace(needle, b"DEFAULT_TIMESTAMP_TOLERANCE_NS = 20_000_000", 1)
    with pytest.raises(ValueError, match="dependency surface|protected"):
        bridge(old, bad, {path: ["_read_direct_packets"]})


def test_qualification_reachable_packet_function_cannot_be_excluded(original_sources):
    sources = dict(original_sources)
    path = "src/qcsd_lab/chaff_qualification.py"
    needle = b'    """Create one v2 sidecar from a sustained deterministic candidate prefix."""\n'
    assert needle in sources[path]
    sources[path] = sources[path].replace(needle, needle + (
        b"    from .fidelity import _reconcile_runner_packets\n"
        b"    _reconcile_runner_packets([], [], timestamp_tolerance_ns=0, end_anchor_adjustment_ns=None)\n"
    ), 1)
    result = compatibility.qualification_dependencies(sources)
    assert "fidelity._reconcile_runner_packets" in result["reachable_symbols"]
    assert result["source_projections"]["src/qcsd_lab/fidelity.py"][
        "excluded_collector_functions"] == ["_read_direct_packets"]


@pytest.mark.parametrize("path", [
    "src/qcsd_lab/chaff_qualification.py", "src/qcsd_lab/util.py",
    "src/qcsd_lab/prepare.py", "src/qcsd_lab/process_scheduler.py",
    "src/qcsd_lab/application_response_policy.py", "src/qcsd_lab/parameters.py",
    "src/qcsd_lab/verification.py", "src/qcsd_lab/rapid_capture_plan.py",
    "src/qcsd_lab/rapid_runtime_compatibility.py", "qcsd-lab", "Dockerfile",
    "pyproject.toml", "uv.lock", "config/defense-params/buflo-live.json",
    "neqo-qcsd/neqo-bin/src/qcsd/mod.rs",
])
def test_repair_rejects_protected_qualification_validation_method_and_native_sources(original_sources, path):
    old, new, functions = changed_sources(original_sources)
    new[path] += b"\n# unrelated executable/input change\n"
    with pytest.raises(ValueError):
        bridge(old, new, functions)


@pytest.mark.parametrize("replacement", [
    (b"timeout_seconds: float = 5", b"timeout_seconds: float = 50"),
    (b"import ctypes", b"import ctypes\nimport importlib"),
    (b"STATIC_MODES = {", b"STATIC_MODES = set(); OLD_STATIC_MODES = {"),
    (b"def _validate_run_binding(", b"def _changed_validate_run_binding("),
])
def test_collector_file_rejects_changed_defaults_imports_constants_and_validators(original_sources, replacement):
    old, new, functions = changed_sources(original_sources)
    path = "src/qcsd_lab/capture_session.py"
    before, after = replacement
    assert before in new[path]
    new[path] = new[path].replace(before, after, 1)
    with pytest.raises(ValueError, match="protected"):
        bridge(old, new, functions)


@pytest.mark.parametrize("field", ["client", "native", "traffic", "host_launcher"])
def test_repair_rejects_changed_runtime_execution_roles(original_sources, field):
    old, new, functions = changed_sources(original_sources)
    current = runtime(new, successor=True)
    implementation = current["qualification_implementation"]
    if field == "client":
        current["client_sha256"] = "0" * 64
        implementation["neqo_qcsd_client"]["sha256"] = "0" * 64
    elif field == "native":
        for receipt in (current["runtime_source"], implementation["source"]):
            receipt["neqo_commit"] = receipt["neqo_pinned_commit"] = "0" * 40
    elif field == "traffic":
        current["traffic_hashes"]["buflo"] = "0" * 64
    else:
        current["host_launcher_sha256"] = "0" * 64
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    with pytest.raises(ValueError, match="Native, client, launcher or fixed traffic"):
        compatibility.validate_compatibility(runtime(old), current, old, new, review(old, new, functions))


def test_installed_path_change_is_not_a_reviewed_source_repair(original_sources):
    old, new, functions = changed_sources(original_sources)
    current = runtime(new, successor=True)
    impl = current["qualification_implementation"]
    impl["installed_modules"]["src/qcsd_lab/capture_session.py"]["path"] = "/another/module.py"
    impl["sha256"] = qualification._implementation_aggregate(impl)
    with pytest.raises(ValueError, match="installed module path"):
        compatibility.validate_compatibility(runtime(old), current, old, new, review(old, new, functions))


def test_incomplete_generic_implementation_inventory_rejected(original_sources):
    old, new, functions = changed_sources(original_sources)
    current = runtime(new, successor=True)
    impl = current["qualification_implementation"]
    del impl["source_files"]["src/qcsd_lab/capture_session.py"]
    impl["sha256"] = qualification._implementation_aggregate(impl)
    with pytest.raises(ValueError, match="file receipt"):
        compatibility.validate_compatibility(runtime(old), current, old, new, review(old, new, functions))


def test_retained_bytes_must_match_actual_installed_receipt(original_sources):
    old, new, functions = changed_sources(original_sources)
    with pytest.raises(ValueError, match="retained source"):
        compatibility.validate_compatibility(
            runtime(old), runtime(old, successor=True), old, new, review(old, new, functions))


@pytest.mark.parametrize("mutation", ["wrong_hash", "wrong_function", "missing_change", "broad_scope"])
def test_review_must_cover_exact_changed_bytes_and_functions(original_sources, mutation):
    old, new, functions = changed_sources(original_sources)
    value = review(old, new, functions)
    path = next(iter(functions))
    if mutation == "wrong_hash":
        value["changes"][path]["after_sha256"] = "0" * 64
    elif mutation == "wrong_function":
        value["changes"][path]["functions"] = ["_collect_attempt"]
    elif mutation == "missing_change":
        value["changes"] = {}
    else:
        value["repair_scope"] = "anything-needed"
    with pytest.raises(ValueError, match="review does not name"):
        compatibility.validate_compatibility(runtime(old), runtime(new, successor=True), old, new, value)


def test_bridge_cannot_authorize_another_installed_runtime(original_sources):
    old, new, functions = changed_sources(original_sources)
    result = bridge(old, new, functions)
    other = runtime(new, successor=True)["qualification_implementation"]
    other["source"]["lab_commit"] = "8" * 40
    other["sha256"] = qualification._implementation_aggregate(other)
    with pytest.raises(ValueError, match="another installed receipt"):
        compatibility.validate_current_implementation(runtime(old)["qualification_implementation"], other, result)


def test_changed_bridge_and_historical_receipt_rejected(original_sources):
    old, new, functions = changed_sources(original_sources)
    result = bridge(old, new, functions)
    changed = copy.deepcopy(result)
    changed["scientific_credit"] = True
    with pytest.raises(ValueError, match="malformed or changed"):
        compatibility.validate_current_implementation(
            runtime(old)["qualification_implementation"], runtime(new, successor=True)["qualification_implementation"], changed)
    old_impl = runtime(old)["qualification_implementation"]
    old_impl["schema_version"] = 1
    old_impl["domain"] = "qcsd-chaff-qualification-implementation-v1"
    path = "src/qcsd_lab/application_response_policy.py"
    del old_impl["source_files"][path]
    del old_impl["installed_modules"][path]
    old_impl["sha256"] = qualification._implementation_aggregate(old_impl)
    with pytest.raises(ValueError, match="historical implementation"):
        compatibility.validate_current_implementation(
            old_impl, runtime(new, successor=True)["qualification_implementation"], result)


@pytest.mark.parametrize("operation", ["add", "remove", "missing_dependency"])
def test_source_inventory_must_remain_complete_and_closed(original_sources, operation):
    old, new, functions = changed_sources(original_sources)
    original_proof = runtime(old)
    successor_proof = runtime(new, successor=True)
    exact_review = review(old, new, functions)
    if operation == "add":
        new["src/qcsd_lab/new_collector.py"] = b"pass\n"
    elif operation == "remove":
        del new["src/qcsd_lab/capture_session.py"]
    else:
        del old["src/qcsd_lab/discovery_evidence.py"]
        del new["src/qcsd_lab/discovery_evidence.py"]
    with pytest.raises(ValueError, match="add or remove|dependency source is missing"):
        compatibility.validate_compatibility(original_proof, successor_proof, old, new, exact_review)
