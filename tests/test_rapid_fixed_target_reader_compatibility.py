"""HOST fixtures for retained reader authority; no installed/deep primitives run."""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from qcsd_lab import rapid_chunk_partial_lane as dynamic
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_target_overlay_source as overlay

BASE = "16e61c556bd3b90c62532e7c321679639dc2563f"
REPO = Path(__file__).parents[1]


def baseline(name):
    return subprocess.check_output(
        ["git", "-C", str(REPO), "show", BASE + ":src/qcsd_lab/" + name + ".py"])


def put(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return target.reference(path)


def old_sources(tmp_path):
    refs = target._sources()
    for role, name in (("target", "rapid_fixed_condition_target"),
                       ("dynamic", "rapid_chunk_partial_lane"),
                       ("overlay", "rapid_target_overlay_source")):
        refs[role] = put(tmp_path / "producer/src/qcsd_lab" / (name + ".py"), baseline(name))
    return refs


def change_function(raw, name):
    tree = ast.parse(raw)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    lines = raw.decode().splitlines(keepends=True)
    lines.insert(node.body[0].lineno - 1, "    pass  # controlled changed body\n")
    return "".join(lines).encode()


def test_original_target_and_dynamic_guards_have_closed_compatible_shapes(tmp_path):
    assert target._compatible_sources(old_sources(tmp_path))


@pytest.mark.parametrize("name", ["condition_identity", "_select", "validate_target", "_complete_operation"])
def test_target_scientific_body_change_refused(tmp_path, name):
    refs = old_sources(tmp_path)
    refs["target"] = put(Path(refs["target"]["path"]), change_function(baseline("rapid_fixed_condition_target"), name))
    with pytest.raises(ValueError, match="protected scientific code"):
        target._compatible_sources(refs)


def test_arbitrary_old_compatibility_guard_refused(tmp_path):
    refs = old_sources(tmp_path)
    refs["target"] = put(Path(refs["target"]["path"]),
        change_function(baseline("rapid_fixed_condition_target"), "_compatible_sources"))
    with pytest.raises(ValueError, match="original shape"):
        target._compatible_sources(refs)


def test_source_full_mode_change_refused(tmp_path):
    refs = old_sources(tmp_path)
    refs["target"] = put(Path(refs["target"]["path"]), baseline("rapid_fixed_condition_target"), 0o600)
    with pytest.raises(ValueError, match="full file mode"):
        target._compatible_sources(refs)


@pytest.mark.parametrize("name", ["_verify_enrollment", "_prepared_workload", "verify_policy"])
def test_membership_validator_body_changes_remain_protected(name):
    raw = baseline("rapid_rolling_capture")
    assert target._planning_source_projection(raw) != target._planning_source_projection(change_function(raw, name))


def test_planning_only_body_change_is_not_membership_change():
    raw = baseline("rapid_rolling_capture")
    assert target._planning_source_projection(raw) == target._planning_source_projection(change_function(raw, "publish_plan"))


def test_eager_planning_default_is_protected():
    raw = baseline("rapid_rolling_capture").replace(b"class_indices=None", b"class_indices=print('eager')")
    # Historical Source has no class_indices; inject the explicit keyword at its known keyword-only boundary.
    raw = raw.replace(b"selected_input_renewal: Path | None = None, _context=None) -> Path:",
                      b"selected_input_renewal: Path | None = None, class_indices=print('eager'), _context=None) -> Path:")
    with pytest.raises(ValueError, match="executing default"):
        target._planning_source_projection(raw)


def test_installed_package_geometry_uses_same_logical_module_name(tmp_path):
    module = tmp_path / "venv/lib/python3.11/site-packages/qcsd_lab/rapid_fixed_condition_target.py"
    assert target._membership_code_path(module.parent / "rapid_rolling_capture.py",
        {"path": str(module)}) == "src/qcsd_lab/rapid_rolling_capture.py"


def membership_pair(tmp_path):
    sources = old_sources(tmp_path)
    old_roll = put(tmp_path / "producer/src/qcsd_lab/rapid_rolling_capture.py", baseline("rapid_rolling_capture"))
    raw = put(tmp_path / "evidence/full-original-graph.json", b'{"full_graph":"controlled"}')
    producer = {"files": [sources["target"], old_roll, raw], "trees": []}
    current = {"files": [target._sources()["target"], target.reference(Path(rolling.__file__)), raw], "trees": []}
    return sources, producer, current


def test_retained_full_data_and_planning_role_match(tmp_path):
    sources, producer, current = membership_pair(tmp_path)
    assert target._compatible_membership(producer, current, sources)


def test_changed_full_graph_dependency_refused(tmp_path):
    sources, producer, current = membership_pair(tmp_path)
    current["files"][-1] = put(tmp_path / "changed/full-original-graph.json", b'{"full_graph":"changed"}')
    assert not target._compatible_membership(producer, current, sources)


def test_changed_rolling_full_mode_refused(tmp_path):
    sources, producer, current = membership_pair(tmp_path)
    current["files"][1] = put(tmp_path / "installed/qcsd_lab/rapid_rolling_capture.py",
        Path(rolling.__file__).read_bytes(), 0o600)
    # Keep the executing target package coherent while exercising the same canonical role.
    current["files"][0] = put(tmp_path / "installed/qcsd_lab/rapid_fixed_condition_target.py",
        Path(target.__file__).read_bytes())
    monkey_sources = target._sources()
    original = target._sources
    target._sources = lambda: {**monkey_sources, "target": current["files"][0]}
    try:
        assert not target._compatible_membership(producer, current, sources)
    finally:
        target._sources = original


def relocated_readers(tmp_path):
    readers = dynamic._reader_sources()
    for name, ref in readers.items():
        raw = (baseline("rapid_chunk_partial_lane") if name == dynamic.__name__
               else Path(ref["path"]).read_bytes())
        readers[name] = put(tmp_path / "old-reader/src/qcsd_lab" /
                            (name.rsplit(".", 1)[-1] + ".py"), raw, ref["mode"])
    return readers


def test_all_six_original_reader_refs_reopened_with_identity_preserved(tmp_path):
    readers = relocated_readers(tmp_path)
    assert len(readers) == 6
    assert dynamic._compatible_reader_sources(readers) == str(tmp_path / "old-reader")


@pytest.mark.parametrize("mutation", ["bytes", "mode", "path", "unit"])
def test_relocated_reader_drift_refused(tmp_path, mutation):
    readers = relocated_readers(tmp_path)
    name = next(n for n in readers if n != dynamic.__name__)
    ref = readers[name]
    if mutation == "bytes":
        readers[name] = put(Path(ref["path"]), b"# changed scientific reader\n")
    elif mutation == "mode":
        readers[name] = put(Path(ref["path"]), Path(ref["path"]).read_bytes(), 0o600)
    elif mutation == "path":
        readers[name] = put(tmp_path / "other-package" / Path(ref["path"]).name,
                            Path(ref["path"]).read_bytes())
    else:
        readers.pop(name)
    with pytest.raises(ValueError):
        dynamic._compatible_reader_sources(readers)


def runtime_fixture(tmp_path):
    readers = relocated_readers(tmp_path)
    root = tmp_path / "measurement"; root.mkdir()
    launcher = put(root / "qcsd-lab", b"# synthetic installed launcher")
    client = put(root / "client", b"synthetic c24 client", 0o755)
    manifest = put(root / "source.json", b"{}")
    canonical = put(tmp_path / "canonical.json", b"{}")
    runtime = {"runtime_source_root": str(root), "module_root": str(root),
               "base_launcher": launcher["path"], "host_launcher": launcher["path"],
               "source_manifest": manifest["path"], "client_binary": client["path"],
               "collection_image_digest": "sha256:" + "1" * 64}
    release = {"files": {"qcsd-lab": launcher}, "lab_head": "2" * 40, "native_head": "3" * 40}
    audit = tmp_path / "operation"; audit.mkdir()
    request = dynamic._runtime_request(release, canonical, runtime, audit)
    request["source_root"] = str(tmp_path / "old-reader")
    alias = tmp_path / "original-host-python"
    alias.symlink_to(Path(sys.executable).resolve())
    binary = target.reference(Path(sys.executable).resolve())
    start = {"command": [str(alias), "-I", "-B", "-c", dynamic._RUNTIME_PROGRAM],
             "request": request, "reader_sources": readers, "interpreter": binary,
             "started_at": "2026-10-01T00:00:00+00:00"}
    empty = hashlib.sha256(b"").hexdigest()
    report = {"source": {"lab_commit": release["lab_head"], "neqo_commit": release["native_head"],
              "neqo_pinned_commit": release["native_head"], "lab_dirty": False, "neqo_dirty": False,
              "lab_patch_sha256": empty, "neqo_patch_sha256": empty},
              "collection_image_digest": runtime["collection_image_digest"], "client_sha256": client["sha256"],
              "source_files": {"qcsd-lab": {k: launcher[k] for k in ("sha256", "mode")}},
              "base_launcher": launcher["path"], "host_launcher": launcher["path"],
              "read_dependencies": [], "directory_dependencies": []}
    refs = {"stdout.log": put(audit / "stdout.log", target._json(report)),
            "stderr.log": put(audit / "stderr.log", b""),
            "started.json": put(audit / "started.json", target._json(start))}
    refs["completed.json"] = put(audit / "completed.json", target._json({
        "returncode": 0, "completed_at": "2026-10-01T00:00:01+00:00",
        "stdout_sha256": refs["stdout.log"]["sha256"], "stderr_sha256": refs["stderr.log"]["sha256"]}))
    return release, canonical, runtime, refs, readers, start


def test_original_runtime_request_and_interpreter_are_preserved(tmp_path):
    release, canonical, runtime, refs, readers, start = runtime_fixture(tmp_path)
    report, _ = dynamic._runtime_operation(release, canonical, runtime, refs, reader_sources=readers)
    assert report["source"]["lab_commit"] == release["lab_head"]
    assert start["request"]["source_root"] == str(tmp_path / "old-reader")


@pytest.mark.parametrize("field", ["source_root", "interpreter", "program"])
def test_original_runtime_identity_transplant_refused(tmp_path, field):
    release, canonical, runtime, refs, readers, start = runtime_fixture(tmp_path)
    if field == "source_root":
        start["request"]["source_root"] = str(tmp_path / "current-reader")
    elif field == "interpreter":
        start["interpreter"]["sha256"] = "0" * 64
    else:
        start["command"][-1] += "\n# changed proof program"
    refs["started.json"] = put(Path(refs["started.json"]["path"]), target._json(start))
    with pytest.raises(ValueError):
        dynamic._runtime_operation(release, canonical, runtime, refs, reader_sources=readers)


def test_public_chunk_input_reader_recomputes_remaining_vector(monkeypatch, tmp_path):
    limits = {"max_response_bytes": 16 * 1024 * 1024, "capture_megabytes": 64,
              "capture_seconds": 180, "timeout_seconds": 120, "max_attempts": 3,
              "settle_seconds": 2, "per_origin_cooldown_seconds": 0}
    progress = put(tmp_path / "progress.json", b"controlled original deep boundary")
    target_ref = put(tmp_path / "target.json", b"controlled admitted membership boundary")
    classes = [{"class_index": 17, "candidate_id": "controlled", "workload_id": "controlled",
                "capture_limits": limits}]
    declaration = {"target_id": "4" * 64, "conditions": {"tamaraw": {"identity": {
        "mode": "tamaraw", "defense": {"kind": "tamaraw"}, "defense_parameters": None}}}}
    state = {"target": target_ref, "target_id": declaration["target_id"], "classes": classes,
             "remaining_vectors": [{"class_index": 17, "mode": "tamaraw",
                                    "remaining_slots": list(range(4, 64))}]}
    monkeypatch.setattr(target, "validate_progress", lambda ref: state)
    monkeypatch.setattr(target, "validate_target", lambda ref: declaration)
    inputs = target.chunk_inputs(progress, [17], "tamaraw", maximum=16)
    payload = {"mode": "tamaraw", "maximum": 16, "inputs": inputs, "planning_only": True,
               "scientific_credit": False, "sources": target._sources()}
    ref = put(tmp_path / "chunk-inputs.json", target._json({"schema_version": 1,
        "artifact_type": target.CHUNK_INPUT_TYPE, "payload": payload,
        "payload_sha256": hashlib.sha256(target.epoch._json(payload)).hexdigest()}))
    assert target.read_chunk_inputs(ref)["inputs"]["ranges"][0] == {"slot_start": 4, "slot_count": 16}
    payload["inputs"]["remaining_slots"][0] = 3
    ref = put(tmp_path / "bad-chunk-inputs.json", target._json({"schema_version": 1,
        "artifact_type": target.CHUNK_INPUT_TYPE, "payload": payload,
        "payload_sha256": hashlib.sha256(target.epoch._json(payload)).hexdigest()}))
    with pytest.raises(ValueError, match="remaining-slot"):
        target.read_chunk_inputs(ref)


@pytest.mark.parametrize("role", ["acceptance", "application", "traffic"])
def test_unrelated_acceptance_body_request_code_refused(tmp_path, role):
    refs = old_sources(tmp_path)
    refs[role] = put(tmp_path / (role + ".py"), b"# changed protected acceptance/request/body code")
    with pytest.raises(ValueError, match="code bytes or modes"):
        target._compatible_sources(refs)


def test_original_tree_membership_stays_closed(tmp_path):
    sources, producer, current = membership_pair(tmp_path)
    tree = tmp_path / "raw-attempts"; tree.mkdir()
    from qcsd_lab.rapid_operation_facts import _tree
    observation = {"path": str(tree), "ignore_git": True, "members": _tree(tree, ignore_git=True)}
    producer["trees"] = [observation]
    current["trees"] = [deepcopy(observation)]
    assert target._compatible_membership(producer, current, sources)
    put(tree / "unreported-attempt.json", b"original evidence cannot gain a member")
    with pytest.raises(ValueError, match="raw tree changed"):
        target._compatible_membership(producer, current, sources)


@pytest.mark.parametrize("drift", ["client", "source"])
def test_runtime_native_client_and_source_flags_remain_exact(tmp_path, drift):
    release, canonical, runtime, refs, readers, start = runtime_fixture(tmp_path)
    report = json.loads(Path(refs["stdout.log"]["path"]).read_bytes())
    if drift == "client":
        report["client_sha256"] = "0" * 64
    else:
        report["source"]["lab_dirty"] = True
    refs["stdout.log"] = put(Path(refs["stdout.log"]["path"]), target._json(report))
    end = json.loads(Path(refs["completed.json"]["path"]).read_bytes())
    end["stdout_sha256"] = refs["stdout.log"]["sha256"]
    refs["completed.json"] = put(Path(refs["completed.json"]["path"]), target._json(end))
    with pytest.raises(ValueError, match="installed Source, client or launcher"):
        dynamic._runtime_operation(release, canonical, runtime, refs, reader_sources=readers)


def old_overlay_sources(tmp_path):
    names = {"overlay": "rapid_target_overlay_source", "target": "rapid_fixed_condition_target",
             "dynamic_runtime_reader": "rapid_chunk_partial_lane", "original_epoch_reader": "rapid_epoch_corpus"}
    return {key: put(tmp_path / "retained/src/qcsd_lab" / (name + ".py"), baseline(name))
            for key, name in names.items()}


def test_original_overlay_four_reader_refs_remain_original(tmp_path):
    refs = old_overlay_sources(tmp_path)
    assert overlay._compatible_overlay_sources(refs) == refs


def test_overlay_original_scientific_epoch_reader_change_refused(tmp_path):
    refs = old_overlay_sources(tmp_path)
    refs["original_epoch_reader"] = put(Path(refs["original_epoch_reader"]["path"]),
                                        b"# altered original scientific reader")
    with pytest.raises(ValueError, match="scientific reader code"):
        overlay._compatible_overlay_sources(refs)


def test_retained_overlay_derivation_preserves_original_reader_dependencies(monkeypatch, tmp_path):
    refs = old_overlay_sources(tmp_path)
    module = tmp_path / "measurement-module"
    (module / "src").mkdir(parents=True); (module / "tools").mkdir()
    native = put(module / "neqo-qcsd/native.txt", b"controlled unchanged c24")
    python = put(module / "src/qcsd_lab/proof.py", b"controlled measured module")
    source_binding = put(tmp_path / "runtime-binding.json", b"controlled original runtime proof")
    canonical = put(tmp_path / "canonical.json", b"controlled original canonical")
    release = {"root": str(module), "lab_head": "a" * 40, "native_head": "b" * 40,
               "files": {"neqo-qcsd/native.txt": native, "src/qcsd_lab/proof.py": python}}
    runtime = {"root": str(module), "native_head": release["native_head"],
               "files": {"neqo-qcsd/native.txt": native},
               "binding": {"read_dependencies": [], "directory_dependencies": [], "reader_sources": {},
                           "runtime_operation": {}, "canonical": canonical,
                           "runtime_identity": {"controlled": True}}}
    # Installed runtime, Git release and publication are explicit controlled primitives.
    monkeypatch.setattr(dynamic, "_source", lambda ref: runtime)
    monkeypatch.setattr(dynamic, "release_snapshot", lambda *args: release)
    monkeypatch.setattr(overlay, "_publication", lambda *args: [])
    _, derived = overlay._derive(release, {"controlled": "publication"}, source_binding,
                                  producer_sources=refs)
    assert derived["sources"] == refs
    assert all(ref in derived["read_dependencies"] for ref in refs.values())
    assert derived["module_installed_claim"] is False
    assert derived["scientific_credit"] is False


@pytest.mark.parametrize("mutation", ["bytes", "mode"])
def test_reader_fingerprint_memo_keeps_source_fence_and_ends_with_action(monkeypatch, tmp_path, mutation):
    from qcsd_lab.rapid_operation_facts import OperationFacts
    producer = put(tmp_path / "old-target.py", baseline("rapid_fixed_condition_target"))
    current = target._sources()["target"]
    original_parse = ast.parse; calls = []
    def counted(*args, **kwargs):
        calls.append(1); return original_parse(*args, **kwargs)
    monkeypatch.setattr(ast, "parse", counted)
    context = OperationFacts(); context.begin_action()
    with context.scope():
        assert target._compatible_code_ref("target", producer, current)
        assert target._compatible_code_ref("target", producer, current)
        assert len(calls) == 2  # One original and one current full residual AST.
        path = Path(producer["path"])
        if mutation == "bytes": path.write_bytes(path.read_bytes() + b"\n")
        else: path.chmod(0o600)
        with pytest.raises(ValueError, match="bytes or mode changed"):
            context.check()
    path.write_bytes(baseline("rapid_fixed_condition_target")); path.chmod(producer["mode"])
    fresh = OperationFacts(); fresh.begin_action()
    with fresh.scope():
        assert target._compatible_code_ref("target", producer, current)
        fresh.check()
    assert len(calls) == 4  # No fingerprint authority persists between actions.


@pytest.mark.parametrize("mutation", ["bytes", "mode"])
def test_planning_fingerprint_memo_keeps_original_file_fence(monkeypatch, tmp_path, mutation):
    from qcsd_lab.rapid_operation_facts import OperationFacts
    producer = put(tmp_path / "old-rolling.py", baseline("rapid_rolling_capture"))
    raw = Path(producer["path"]).read_bytes()
    original_parse = ast.parse; calls = []
    def counted(*args, **kwargs):
        calls.append(1); return original_parse(*args, **kwargs)
    monkeypatch.setattr(ast, "parse", counted)
    context = OperationFacts(); context.begin_action()
    with context.scope():
        target._open(producer)
        assert target._planning_source_projection(raw) == target._planning_source_projection(raw)
        assert len(calls) == 1
        path = Path(producer["path"])
        if mutation == "bytes": path.write_bytes(path.read_bytes() + b"\n")
        else: path.chmod(0o600)
        with pytest.raises(ValueError, match="bytes or mode changed"):
            context.check()
