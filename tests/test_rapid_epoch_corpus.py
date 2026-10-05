"""Engineering fixtures for release authority, isolation and exact slot mapping.

Synthetic Source and mapping fixtures grant no scientific corpus credit. No
Docker, Native process, original capture validator or network runs here.
"""
from pathlib import Path
import copy
import hashlib
import json
import subprocess

import pytest

from qcsd_lab import rapid_epoch_corpus as corpus


def classes(count=50):
    return [{"candidate_id": f"candidate-{i:06d}", "class_index": i, "workload_id": f"complete-{i}",
             "canonical_sites": [f"class{i}.invalid"], "original_graph_sha256": f"{i:064x}",
             "capture_limits": {"max_response_bytes": 16 * 1024 * 1024, "capture_megabytes": 64}}
            for i in range(1, count + 1)]


def lane(row, mode, start, count=16, *, epoch="current", legacy=False):
    logical = f"class{row['class_index']}-{mode}-{start}"
    return {"spec": {"data_root": f"/retained-{epoch}"}, "logical_lane": logical, "mode": mode,
            "workload_ids": [row["workload_id"]], "layout": "original-four-visit-block-v6" if legacy else "explicit-logical-offset-bounded-sixteen-visit-chunks-v1",
            "logical_slots": list(range(start, start + count)), "configuration": {"limits": dict(row["capture_limits"])},
            "facts": {"scientific_credit": True, "host_returncode": 0, "accepted": count,
                      "result_root": f"/retained-{epoch}/{logical}"},
            "samples": [{"candidate_id": row["candidate_id"], "class_index": row["class_index"],
                         "workload_id": row["workload_id"], "original_graph_sha256": row["original_graph_sha256"],
                         "mode": mode, "visit": start + local, "actual_local_visit": local, "sample_id": f"sample-{local}"}
                        for local in range(count)]}


def test_complete_synthetic_fifty_site_mapping_requires_exact_16000():
    values = classes()
    rows = [lane(row, mode, start) for row in values for mode in corpus.MODES for start in range(0, 64, 16)]
    facts = corpus.coverage(values, rows)
    assert facts == {"accepted": 16000, "complete": True, "missing_slots": 0, "class_count": 50, "lane_count": 1000, "scientific_credit": True}
    with pytest.raises(ValueError, match="holes"):
        corpus.coverage(values, rows[:-1])
    # No corpus file is published by this synthetic mapping fixture.


def test_original_and_chunk_epochs_preserve_old_offsets_without_recollection():
    row = classes(1)[0]
    old = [lane(row, "tamaraw", start, 4, epoch="original", legacy=True) for start in range(8, 32, 4)]
    new = [lane(row, "tamaraw", start, count) for start, count in [(0, 8), (32, 16), (48, 16)]]
    facts = corpus.coverage([row], old + new, require_complete=False)
    assert facts["accepted"] == 64 and facts["scientific_credit"] is False
    repeated = lane(row, "tamaraw", 8, 4, epoch="changed-source", legacy=True)
    with pytest.raises(ValueError, match="duplicates"):
        corpus.coverage([row], old + new + [repeated], require_complete=False)


@pytest.mark.parametrize("key,value", [("visit", 7), ("actual_local_visit", True), ("class_index", 2),
                                     ("candidate_id", "substituted"), ("workload_id", "another"),
                                     ("original_graph_sha256", "f" * 64)])
def test_moved_slots_and_class_graph_substitutions_refuse(key, value):
    row = classes(1)[0]
    report = lane(row, "tamaraw", 8, 4, legacy=True)
    report["samples"][0][key] = value
    with pytest.raises(ValueError):
        corpus.coverage([row], [report], require_complete=False)


def test_failed_lane_duplicate_samples_and_changed_caps_refuse():
    row = classes(1)[0]
    for update in [{"host_returncode": 1}, {"host_returncode": False}, {"scientific_credit": False}, {"accepted": True}]:
        report = lane(row, "tamaraw", 0)
        report["facts"].update(update)
        with pytest.raises(ValueError):
            corpus.coverage([row], [report], require_complete=False)
    report = lane(row, "tamaraw", 0)
    report["samples"][1]["sample_id"] = report["samples"][0]["sample_id"]
    with pytest.raises(ValueError, match="duplicates"):
        corpus.coverage([row], [report], require_complete=False)
    report = lane(row, "tamaraw", 0)
    report["configuration"]["limits"]["max_response_bytes"] = 64 * 1024 * 1024
    with pytest.raises(ValueError, match="budgets"):
        corpus.coverage([row], [report], require_complete=False)


def test_fifty_candidates_must_be_distinct_sites_and_workload_groups():
    for key in ["candidate_id", "canonical_sites", "workload_id"]:
        values = classes()
        values[1][key] = values[0][key]
        with pytest.raises(ValueError, match="duplicates"):
            corpus.coverage(values, [])
    with pytest.raises(ValueError, match="fifty"):
        corpus.coverage(classes(49), [])
    report = lane(classes(1)[0], "tamaraw", 0)
    report["samples"].pop()
    with pytest.raises(ValueError, match="group"):
        corpus.coverage(classes(1), [report], require_complete=False)


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          env={"PATH": "/usr/bin:/bin", "GIT_AUTHOR_NAME": "HOST fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                               "GIT_COMMITTER_NAME": "HOST fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}).stdout


@pytest.fixture
def released_source(tmp_path):
    root = tmp_path / "original-source"
    root.mkdir()
    native = root / "neqo-qcsd"
    native.mkdir()
    git(native, "init", "-q")
    (native / "Cargo.toml").write_text('[package]\nname="source-only-fixture"\nversion="0.1.0"\n')
    git(native, "add", "."); git(native, "commit", "-qm", "Native Source fixture only")
    native_head = git(native, "rev-parse", "HEAD").decode().strip()
    package = root / "src/qcsd_lab"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "rapid_lane_evidence.py").write_text("# Synthetic read-only interpreter boundary.\n")
    (package / "rapid_rolling_capture.py").write_text('''import hashlib,json\nfrom pathlib import Path\ndef _open_ref(ref):\n    path=Path(ref["path"])\n    if set(ref)!={"path","sha256"} or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=ref["sha256"]:\n        raise ValueError("original reference changed")\n    return path\ndef _verify_enrollment(path):\n    value=json.loads(path.read_bytes())\n    if value.get("inspect_directory"):\n        list(Path(value["inspect_directory"]).iterdir())\n    if value.get("attempt_write"):\n        Path(value["attempt_write"]).write_text("forbidden")\n    return {},value["classes"],value.get("policy",{"capture_limits":value["capture_limits"]})\n''')
    git(root, "init", "-q"); git(root, "add", "src")
    git(root, "update-index", "--add", "--cacheinfo", "160000," + native_head + ",neqo-qcsd")
    git(root, "commit", "-qm", "Synthetic historical reader Source")
    return root, git(root, "rev-parse", "HEAD").decode().strip(), native_head


def test_original_full_release_inventory_rejects_subset_byte_mode_and_extra_imports(released_source):
    root, head, native = released_source
    expected = corpus.source_snapshot(root, head, native)
    assert len(expected["files"]) == 4 and "neqo-qcsd/Cargo.toml" in expected["files"]
    path = root / "src/qcsd_lab/rapid_lane_evidence.py"
    raw = path.read_bytes()
    path.write_bytes(raw + b"# changed\n")
    with pytest.raises(ValueError, match="bytes"):
        corpus.source_snapshot(root, head, native)
    path.write_bytes(raw); path.chmod(0o755)
    with pytest.raises(ValueError, match="mode"):
        corpus.source_snapshot(root, head, native)
    path.chmod(0o644)
    extra = root / "src/qcsd_lab/ambient.py"
    extra.write_text("# unbound import\n")
    with pytest.raises(ValueError, match="importable"):
        corpus.source_snapshot(root, head, native)
    extra.unlink()
    git(root, "update-index", "--force-remove", "src/qcsd_lab/rapid_lane_evidence.py")
    with pytest.raises(ValueError, match="omitted"):
        corpus.source_snapshot(root, head, native)


def test_source_binding_and_reference_substitution_refuse(released_source, tmp_path):
    root, head, native = released_source
    ref = corpus.bind_source(root, head, native, tmp_path / "bound.json")
    value = corpus._source(ref)
    assert value["scientific_credit"] is False
    changed = dict(ref, sha256="f" * 64)
    with pytest.raises(ValueError, match="reference"):
        corpus._source(changed)
    target = tmp_path / "raw.txt"; target.write_text("original complete raw bytes")
    bound = corpus.reference(target)
    target.chmod(0o600)
    with pytest.raises(ValueError, match="mode"):
        corpus.reopen(bound)
    link = tmp_path / "linked"; link.symlink_to(root)
    with pytest.raises(ValueError, match="nonlinked"):
        corpus.source_snapshot(link, head, native)


def enrollment_fixture(tmp_path):
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    manifest = raw_root / "complete.json"
    # Repeated URL occurrences and a non-star graph are retained byte-for-byte.
    value = {"preparation": {"final_url": "https://primary.invalid/", "approved_origins": ["https://primary.invalid", "https://asset.invalid"]},
             "resources": [{"id": 0, "url": "https://primary.invalid/", "dependencies": [], "request_headers": []},
                           {"id": 1, "url": "https://asset.invalid/repeat", "dependencies": [0], "request_headers": [["x-fixture", "one"]]},
                           {"id": 2, "url": "https://asset.invalid/repeat", "dependencies": [1], "request_headers": [["x-fixture", "two"]]}]}
    manifest.write_text(json.dumps(value))
    row = classes(1)[0]
    row["prepared_workload"] = {"path": str(manifest), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}
    path = raw_root / "enrollment.json"
    path.write_text(json.dumps({"classes": [row], "capture_limits": row["capture_limits"], "inspect_directory": str(raw_root)}))
    return path, manifest


def test_isolated_read_observer_records_transitive_raw_graph_without_effects(released_source, tmp_path):
    root, head, native = released_source
    path, manifest = enrollment_fixture(tmp_path)
    result = corpus._run_epoch({"root": str(root)}, path, [], tmp_path / "readonly")
    report = result["report"]
    assert report["read_only"] is True and report["lanes"] == []
    assert corpus.reference(path) in report["read_dependencies"] and corpus.reference(manifest) in report["read_dependencies"]
    assert report["membership"][0]["original_graph_sha256"] != classes(1)[0]["original_graph_sha256"]
    directory = next(ref for ref in report["directory_dependencies"] if ref["path"] == str(path.parent))
    assert directory == corpus._directory(path.parent)
    bound = next(ref for ref in report["read_dependencies"] if ref["path"] == str(manifest))
    manifest.write_bytes(manifest.read_bytes() + b" ")
    with pytest.raises(ValueError, match="reference"):
        corpus.reopen(bound)
    (path.parent / "new-raw-record.json").write_text("{}")
    assert corpus._directory(path.parent) != directory


def test_isolated_reader_forbids_writes_and_retains_failure(released_source, tmp_path):
    root, head, native = released_source
    path, manifest = enrollment_fixture(tmp_path)
    value = json.loads(path.read_bytes()); target = tmp_path / "forbidden.txt"
    value["attempt_write"] = str(target); path.write_text(json.dumps(value))
    operation = tmp_path / "failed-readonly"
    with pytest.raises(ValueError, match="raw operation"):
        corpus._run_epoch({"root": str(root)}, path, [], operation)
    assert not target.exists() and json.loads((operation / "completed.json").read_bytes())["returncode"] != 0
    assert (operation / "stderr.log").is_file()


@pytest.mark.parametrize("chained", [False, True])
def test_isolated_additive_seed_without_prepared_field_keeps_original_graph(released_source, tmp_path, chained):
    root, _, _ = released_source
    path, manifest = enrollment_fixture(tmp_path)
    value = json.loads(path.read_bytes())
    row = value["classes"][0]
    original_ref = corpus.reference(manifest)
    row.pop("prepared_workload")
    package = root / "src/qcsd_lab"
    # These synthetic historical modules preserve the actual public API/ref
    # shapes; they stand only for the already verified enrollment boundary.
    (package / "rapid_selected_capture_input.py").write_text('''import hashlib,stat\nfrom pathlib import Path\ndef reopen(ref):\n    path=Path(ref["path"])\n    if set(ref)!={"path","sha256","mode"} or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=ref["sha256"] or stat.S_IMODE(path.stat().st_mode)!=ref["mode"]:\n        raise ValueError("selected original reference changed")\n    return path\n''')
    (package / "rapid_additive_static_enrollment.py").write_text('''import json\nfrom .rapid_selected_capture_input import reopen\ndef input_metadata(ref):\n    return json.loads(reopen(ref).read_bytes()),{}\n''')
    (package / "rapid_site_admission.py").write_text('''import hashlib,json\ndef _unpack(raw,kind):\n    value=json.loads(raw)\n    digest=hashlib.sha256((json.dumps(value["payload"],sort_keys=True,indent=2,allow_nan=False)+"\\n").encode()).hexdigest()\n    if set(value)!={"schema_version","receipt_type","payload","payload_sha256"} or value["receipt_type"]!=kind or value["payload_sha256"]!=digest: raise ValueError("seed policy binding changed")\n    return value["payload"]\n''')
    with (package / "rapid_rolling_capture.py").open("a") as file:
        file.write("\nfrom . import rapid_site_admission as admission\n")
    data = {key: row[key] for key in ["candidate_id", "workload_id", "canonical_sites"]}
    data["original_manifest"] = original_ref
    direct = path.parent / "selected-input.json"; direct.write_text(json.dumps(data))
    policy = {"capture_limits": row["capture_limits"], "seed_inputs": {row["candidate_id"]: corpus.reference(direct)}}
    if chained:
        seed = path.parent / "seed-policy.json"
        seed.write_bytes(corpus._json({"schema_version": 1, "receipt_type": "synthetic-authenticated-seed-policy",
                                      "payload": policy, "payload_sha256": hashlib.sha256(corpus._json(policy)).hexdigest()}))
        policy = {"capture_limits": row["capture_limits"], "seed_policy": {key: corpus.reference(seed)[key] for key in ("path", "sha256")}}
    value["policy"] = policy; path.write_text(json.dumps(value))
    git(root, "add", "src"); git(root, "commit", "-qm", "Synthetic additive seed read API")
    result = corpus._run_epoch({"root": str(root)}, path, [], tmp_path / "seed-readonly")
    report = result["report"]
    assert report["membership"][0]["candidate_id"] == row["candidate_id"]
    assert report["membership"][0]["original_graph_sha256"] != classes(1)[0]["original_graph_sha256"]
    assert corpus.reference(manifest) in report["read_dependencies"]
    assert corpus.reference(direct) in report["read_dependencies"]
    # The exact selected original ref is checked, not its path alone.
    manifest.write_bytes(manifest.read_bytes() + b" ")
    with pytest.raises(ValueError, match="raw operation"):
        corpus._run_epoch({"root": str(root)}, path, [], tmp_path / "substituted-seed")


def test_isolated_prepared_manifest_reference_digest_is_required(released_source, tmp_path):
    root, _, _ = released_source
    path, manifest = enrollment_fixture(tmp_path)
    value = json.loads(path.read_bytes())
    value["classes"][0]["prepared_workload"]["sha256"] = "f" * 64
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="raw operation"):
        corpus._run_epoch({"root": str(root)}, path, [], tmp_path / "substituted-prepared")


def test_public_audit_retains_zero_credit_and_final_publish_refuses_incomplete_fixture(released_source, tmp_path):
    root, head, native = released_source
    path, manifest = enrollment_fixture(tmp_path)
    source = corpus.bind_source(root, head, native, tmp_path / "source.json")
    with pytest.raises(ValueError, match="SCI36"):
        corpus.audit(corpus.reference(path), source, [], [], [], tmp_path / "unclaimed-audit")
    assert not (tmp_path / "unclaimed-audit").exists()
    payload = {"contract": corpus.CONTRACT, "scientific_credit": False, "measurement_equivalence_claimed": False,
               "reader_source": corpus.reference(Path(corpus.__file__)), "membership_source": source,
               "epoch_sources": [], "read_dependencies": [corpus.reference(manifest)], "classes": classes(1), "lanes": [], "operations": []}
    payload["directory_dependencies"] = []
    payload.update(final_enrollment=corpus.reference(path), closures=[], prior_progress=[], facts={}, closed_at="2026-01-01T00:00:00+00:00")
    ref = corpus._write(tmp_path / "incomplete-audit.json", corpus.AUDIT_TYPE, payload)
    with pytest.raises(ValueError, match="SCI36"):
        corpus.publish(ref, tmp_path / "final.json")
    assert not (tmp_path / "final.json").exists()


def prior_fixture(tmp_path):
    row = classes(1)[0]
    report = lane(row, "tamaraw", 8, 4, legacy=True)
    report["facts"]["completed_at"] = "2026-01-01T00:00:00+00:00"
    report["campaign_name"] = "original-four-visit-b03"
    closure = tmp_path / "closure.json"; closure.write_text("original closed lane")
    complete = tmp_path / "complete.json"; complete.write_text("original complete receipt")
    report["closure"] = corpus.reference(closure); report["receipt"] = corpus.reference(complete)
    value = {"artifact_type": "root-reopened-rolling-static-scientific-progress", "actual_installed_deep_reopened": True,
             "measurement_epochs_preserve_original_source_and_runtime_labels": True, "final_target": 16000,
             "formal_accepted_trace_count": 4, "closed_at": "2026-01-02T00:00:00+00:00",
             "lanes": [{"accepted": 4, "complete_reference": report["receipt"], "lane_closure_reference": report["closure"]}],
             "accepted_formal_slots": [{key: sample[key] for key in ["candidate_id", "class_index", "mode", "visit"]}
                                       for sample in report["samples"]]}
    path = tmp_path / "prior.json"; path.write_text(json.dumps(value))
    return row, report, path, value


def test_genuine_prior_anchor_cannot_be_omitted_or_replaced_by_recollection(tmp_path):
    row, report, path, value = prior_fixture(tmp_path)
    assert len(corpus._prior([corpus.reference(path)], [report], [row])) == 3
    with pytest.raises(ValueError, match="retain"):
        corpus._prior([], [report], [row])
    with pytest.raises(ValueError, match="omitted or replaced"):
        corpus._prior([corpus.reference(path)], [], [row])
    replacement = copy.deepcopy(report)
    replacement["closure"] = {**replacement["closure"], "sha256": "f" * 64}
    with pytest.raises(ValueError, match="omitted or replaced"):
        corpus._prior([corpus.reference(path)], [replacement], [row])
    value["accepted_formal_slots"][0]["visit"] = 7
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="counter"):
        corpus._prior([corpus.reference(path)], [report], [row])


def test_prior_counter_cannot_relabel_blocks_or_add_unknown_slot_fields(tmp_path):
    row, report, path, value = prior_fixture(tmp_path)
    value["accepted_formal_slots"][0].update(actual_local_visit=0, registered_block=2, campaign_name=report["campaign_name"])
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="registered"):
        corpus._prior([corpus.reference(path)], [report], [row])
    value["accepted_formal_slots"][0] = {key: report["samples"][0][key] for key in ["candidate_id", "class_index", "mode", "visit"]}
    value["accepted_formal_slots"][0]["extra"] = "unbound"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="moved or duplicated"):
        corpus._prior([corpus.reference(path)], [report], [row])


def test_original_raw_output_dependency_omission_and_membership_mutation_refuse(tmp_path):
    raw = tmp_path / "raw"; raw.mkdir()
    primary = raw / "primary.json"; primary.write_text("complete primary bytes")
    full = raw / "full.json"; full.write_text("complete full graph bytes")
    original = [corpus.reference(primary), corpus.reference(full)]
    directories = {str(raw): corpus._directory(raw)}
    corpus._close_original_dependencies(original, directories, original, list(directories.values()))
    with pytest.raises(ValueError, match="omitted"):
        corpus._close_original_dependencies(original, directories, original[:1], list(directories.values()))
    with pytest.raises(ValueError, match="omitted"):
        corpus._close_original_dependencies(original, directories, original, [])
    (raw / "new-unsealed-member.json").write_text("{}")
    with pytest.raises(ValueError, match="membership"):
        corpus._close_original_dependencies(original, directories, original, list(directories.values()))


def test_original_operation_source_and_membership_requests_cannot_be_relabelled():
    source = {"path": "/bound/source.json", "sha256": "a" * 64, "mode": 0o644}
    final = {"path": "/retained/final-enrollment.json", "sha256": "b" * 64}
    sources = {(source["path"], source["sha256"]): {"root": "/original/module-source"}}
    request = {"source_root": "/original/module-source", "enrollment": final["path"], "closures": []}
    started = {"command": ["python", "-I", "-B"], "request": request, "started_at": "2026-01-01T00:00:00+00:00"}
    assert corpus._operation_request(started, source, sources, source, final) == request
    for replacement in [{"source_root": "/another/module-source"}, {"enrollment": "/substituted/enrollment.json"},
                        {"extra": "unbound"}, {"closures": None}]:
        changed = copy.deepcopy(started); changed["request"].update(replacement)
        with pytest.raises(ValueError, match="Source"):
            corpus._operation_request(changed, source, sources, source, final)
    with pytest.raises(ValueError, match="Source"):
        corpus._operation_request(started, dict(source, sha256="c" * 64), sources, source, final)


def test_isolated_lane_reader_keeps_original_two_key_reference_abi(released_source, tmp_path):
    root, _, _ = released_source
    with (root / "src/qcsd_lab/rapid_rolling_capture.py").open("a") as file:
        file.write('''\ndef _reopen_lane_check(ref):\n    if set(ref)!={"path","sha256"}: raise ValueError("unsupported original reference shape")\n    _open_ref(ref)\n    raise ValueError("original two-key reference authenticated; synthetic lane boundary ends")\n''')
    git(root, "add", "src"); git(root, "commit", "-qm", "Synthetic original closure ABI")
    closure = tmp_path / "closure.json"; closure.write_text("synthetic raw closure")
    operation = tmp_path / "original-api"
    with pytest.raises(ValueError, match="raw operation"):
        corpus._run_epoch({"root": str(root)}, None, [corpus.reference(closure)], operation)
    assert "original two-key reference authenticated" in (operation / "stderr.log").read_text()
    # The fixture ends before any lane/admission/capture claim is possible.
