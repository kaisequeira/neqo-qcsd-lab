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


@pytest.mark.parametrize("case", ["authenticated-600", "mode-drift", "digest-drift", "unknown-key"])
def test_isolated_mode_reference_authenticates_before_legacy_projection(released_source, tmp_path, case):
    """Original verifier is strict two-key; the owned reader binds all three.

    This fixture exercises the real isolated program and read observer, while
    its enrollment validator represents the authenticated historical boundary.
    The separate retained-input operation uses the actual eleven-class source.
    """
    root, _, _ = released_source
    path, manifest = enrollment_fixture(tmp_path)
    manifest.chmod(0o600)
    value = json.loads(path.read_bytes())
    bound = corpus.reference(manifest)
    if case == "mode-drift":
        bound["mode"] = 0o644
    elif case == "digest-drift":
        bound["sha256"] = "f" * 64
    elif case == "unknown-key":
        bound["unregistered"] = True
    value["classes"][0]["prepared_workload"] = bound
    path.write_text(json.dumps(value))
    operation = tmp_path / "mode-bearing-original-reference"
    if case != "authenticated-600":
        with pytest.raises(ValueError, match="raw operation"):
            corpus._run_epoch({"root": str(root)}, path, [], operation)
        assert json.loads((operation / "completed.json").read_bytes())["returncode"] != 0
        return
    result = corpus._run_epoch({"root": str(root)}, path, [], operation)
    assert result["report"]["read_only"] is True
    assert bound in result["report"]["read_dependencies"]
    assert result["report"]["membership"][0]["prepared_workload"] == bound
    assert result["report"]["lanes"] == []


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


def partial_fixture(row, local, *, result="/synthetic-original-incomplete-b02"):
    """Mapping fixture only: original deep/host proof is not supplied here."""
    return {"candidate_id": row["candidate_id"], "class_index": row["class_index"],
        "workload_id": row["workload_id"], "original_graph_sha256": row["original_graph_sha256"],
        "mode": "tamaraw", "logical_visit": 4 + local, "actual_local_visit": local, "registered_block": 2,
        "sample_id": f"original-class{row['class_index']}-local{local}", "result_root": result,
        "original_state": "accepted", "individual_trace_authority": "original-collector-accepted-and-original-deep-verified-v1",
        "aggregate_status": "incomplete", "lane_pass_claim": False, "aggregate_formal_credit": 0,
        "host_returncode": 1, "capture_limits": dict(row["capture_limits"]),
        "artifacts": {"original-raw": "a" * 64},
        "partial_receipt": {"path": "/synthetic-partial.json", "sha256": "b" * 64},
        "measurement_source": {"lab_commit": "86cd8c78cf16447e6add3d10ffa02f6167505276",
            "neqo_commit": "c24da2afeec2944a67c48b38eba957dcd543728d", "image_digest": "sha256:" + "c" * 64}}


def test_partial_individual_slots_complete_exact_16000_without_lane_promotion():
    values = classes()
    complete = [lane(row, mode, start, 4, legacy=True) for row in values for mode in corpus.MODES
                for start in range(0, 64, 4) if not (row["class_index"] in {2, 5} and mode == "tamaraw" and start == 4)]
    partial_rows = [partial_fixture(values[index - 1], local) for index in (2, 5) for local in range(4)]
    facts = corpus.partial_coverage(values, complete, partial_rows)
    assert facts["accepted"] == 16000 and facts["scientific_credit"] is True
    assert facts["accepted_individual_partial_traces"] == 8 and facts["incomplete_lane_count"] == 1
    assert all(row["aggregate_status"] == "incomplete" and row["lane_pass_claim"] is False
               and row["host_returncode"] == 1 for row in partial_rows)
    # Synthetic arithmetic is not a published corpus or an actual deep proof.
    with pytest.raises(ValueError, match="holes"):
        corpus.partial_coverage(values, complete, partial_rows[:-1])
    with pytest.raises(ValueError, match="duplicates"):
        corpus.partial_coverage(values, complete, partial_rows + [copy.deepcopy(partial_rows[0])])


@pytest.mark.parametrize("key,value", [
    ("aggregate_status", "complete"), ("lane_pass_claim", True), ("aggregate_formal_credit", 8),
    ("host_returncode", 0), ("host_returncode", True), ("original_state", "failed"),
    ("individual_trace_authority", "collector-only"), ("logical_visit", 0), ("actual_local_visit", True),
    ("registered_block", 3), ("candidate_id", "another"), ("class_index", True),
    ("original_graph_sha256", "d" * 64),
])
def test_partial_corpus_refuses_promoted_failed_or_moved_epoch_slots(key, value):
    values = classes(2)
    row = partial_fixture(values[1], 0)
    row[key] = value
    with pytest.raises(ValueError):
        corpus.partial_coverage(values, [], [row], require_complete=False)


def test_partial_corpus_rejects_recollected_slot_and_changed_caps_or_raw_identity():
    values = classes(2)
    good = partial_fixture(values[1], 0)
    full = lane(values[1], "tamaraw", 4, 4, legacy=True)
    with pytest.raises(ValueError, match="duplicates"):
        corpus.partial_coverage(values, [full], [good], require_complete=False)
    for update in ({"capture_limits": {"max_response_bytes": 67108864, "capture_megabytes": 256}},
                   {"artifacts": {}}, {"sample_id": ""}, {"partial_receipt": {"path": "/missing", "sha256": "wrong"}}):
        changed = copy.deepcopy(good); changed.update(update)
        with pytest.raises(ValueError):
            corpus.partial_coverage(values, [], [changed], require_complete=False)
    changed = copy.deepcopy(good); changed["result_root"] = full["facts"]["result_root"]
    with pytest.raises(ValueError, match="mixes incomplete"):
        corpus.partial_coverage(values, [full], [changed], require_complete=False)


def partial_publication_fixture(tmp_path, monkeypatch):
    """Control only the original proof boundaries; exercise publication itself.

    The fixture supplies no original deep evidence and confers no actual corpus
    credit. Its complete-lane reports and typed progress proof are synthetic.
    Raw dependency closure, typed envelopes and final slot arithmetic are real.
    """
    values = classes()
    complete = [lane(row, mode, start, 4, legacy=True) for row in values for mode in corpus.MODES
                for start in range(0, 64, 4) if not (row["class_index"] in {2, 5} and mode == "tamaraw" and start == 4)]
    rows = [partial_fixture(values[index - 1], local) for index in (2, 5) for local in range(4)]
    raw = tmp_path / "original-raw"; raw.mkdir()
    dependency = raw / "retained-deep-output.json"
    dependency.write_text("synthetic original read dependency\n")
    files, directories = [corpus.reference(dependency)], [corpus._directory(raw)]
    base_ref = corpus._write(tmp_path / "complete-audit.json", corpus.AUDIT_TYPE, {"controlled_original_proof": True})
    progress_ref = corpus._write(tmp_path / "partial-progress.json", "controlled-typed-progress-boundary", {})
    base = {"classes": values, "lanes": complete, "read_dependencies": files,
            "directory_dependencies": directories}
    progress_value = {"individual_slots": rows, "aggregate_status": "incomplete", "lane_pass_claim": False}

    def original_proof(ref, *, require_complete=True):
        assert ref == base_ref and require_complete is False
        corpus.reopen(ref)
        return copy.deepcopy(base), corpus.coverage(values, complete, require_complete=False)

    def partial_proof(refs):
        assert refs == [progress_ref]
        corpus.reopen(progress_ref)
        return copy.deepcopy(rows), [copy.deepcopy(progress_value)], list(files), list(directories)

    monkeypatch.setattr(corpus, "_reopen_audit", original_proof)
    monkeypatch.setattr(corpus, "_partial_inputs", partial_proof)
    expected_files, expected_directories = corpus._combined_dependencies(base, base_ref, files, directories)
    payload = {"contract": corpus.PARTIAL_CONTRACT, "complete_audit": base_ref,
        "partial_progress": [progress_ref], "partial_progress_values": [progress_value],
        "accepted_partial_rows": rows, "read_dependencies": expected_files,
        "directory_dependencies": expected_directories,
        "facts": corpus.partial_coverage(values, complete, rows, require_complete=False),
        "reader_source": corpus.reference(Path(corpus.__file__)), "scientific_credit": False,
        "measurement_equivalence_claimed": False, "closed_at": "2026-01-01T00:00:00+00:00"}
    audit_ref = corpus._write(tmp_path / "partial-audit.json", corpus.PARTIAL_AUDIT_TYPE, payload)
    return audit_ref, payload, base, rows, dependency


def test_partial_publication_keeps_complete_and_incomplete_lane_authorities_separate(tmp_path, monkeypatch):
    ref, _, base, rows, _ = partial_publication_fixture(tmp_path, monkeypatch)
    output = tmp_path / "final-synthetic-corpus.json"
    result = corpus.publish_with_partials(ref, output)
    value = corpus._document(result, corpus.PARTIAL_CORPUS_TYPE)
    assert value["accepted"] == 16000 and value["missing_slots"] == 0
    assert value["complete_lanes"] == base["lanes"] and value["accepted_partial_rows"] == rows
    assert "lanes" not in value and value["incomplete_aggregate_labels_preserved"] is True
    assert all(row["aggregate_status"] == "incomplete" and row["host_returncode"] == 1
               and row["lane_pass_claim"] is False for row in value["accepted_partial_rows"])
    # This is a synthetic control artifact, not actual scientific evidence.


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_partial_publication_final_raw_fence_refuses_mutation_before_write(tmp_path, monkeypatch, mutation):
    ref, _, _, _, raw = partial_publication_fixture(tmp_path, monkeypatch)
    original = corpus._combined_dependencies

    def changed_after_observation(*args):
        value = original(*args)
        if mutation == "bytes":
            raw.write_text("changed original raw bytes\n")
        elif mutation == "mode":
            raw.chmod(0o600)
        else:
            (raw.parent / "new-unsealed-member.json").write_text("{}")
        return value

    monkeypatch.setattr(corpus, "_combined_dependencies", changed_after_observation)
    output = tmp_path / "must-remain-absent.json"
    with pytest.raises(ValueError, match="changed"):
        corpus.publish_with_partials(ref, output)
    assert not output.exists()


def test_partial_publication_refuses_holes_substituted_output_and_default_type(tmp_path, monkeypatch):
    ref, payload, base, rows, _ = partial_publication_fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="schema"):
        corpus._document(ref, corpus.AUDIT_TYPE)
    changed = copy.deepcopy(payload)
    changed["accepted_partial_rows"][0]["host_returncode"] = 0
    altered = corpus._write(tmp_path / "substituted-audit.json", corpus.PARTIAL_AUDIT_TYPE, changed)
    with pytest.raises(ValueError, match="substituted"):
        corpus.publish_with_partials(altered, tmp_path / "no-promotion.json")
    # A genuine typed join can still have holes; it must not produce a final
    # 16K manifest merely because its individual eight traces were verified.
    missing_rows = rows[:-1]
    missing_value = copy.deepcopy(payload["partial_progress_values"])
    missing_value[0]["individual_slots"] = missing_rows
    monkeypatch.setattr(corpus, "_partial_inputs", lambda _: (missing_rows, missing_value,
        base["read_dependencies"], base["directory_dependencies"]))
    changed = copy.deepcopy(payload)
    changed.update(accepted_partial_rows=missing_rows, partial_progress_values=missing_value,
                   facts=corpus.partial_coverage(base["classes"], base["lanes"], missing_rows, require_complete=False))
    altered = corpus._write(tmp_path / "holes-audit.json", corpus.PARTIAL_AUDIT_TYPE, changed)
    with pytest.raises(ValueError, match="holes"):
        corpus.publish_with_partials(altered, tmp_path / "no-holes.json")
    assert not (tmp_path / "no-promotion.json").exists() and not (tmp_path / "no-holes.json").exists()


def test_old_public_publish_rejects_the_new_partial_audit_type(tmp_path):
    # Type refusal happens before any original Source or evidence proof. A
    # partial audit cannot accidentally enter the historical all-lanes route.
    ref = corpus._write(tmp_path / "new-type.json", corpus.PARTIAL_AUDIT_TYPE, {})
    with pytest.raises(ValueError, match="schema"):
        corpus.publish(ref, tmp_path / "must-remain-absent.json")
    assert not (tmp_path / "must-remain-absent.json").exists()


def test_public_partial_cli_requires_explicit_join_and_preserves_old_dispatch(tmp_path, monkeypatch, capsys):
    from tools import rapid_epoch_corpus as cli
    paths = {name: tmp_path / (name + ".json") for name in ("enrollment", "source", "lane", "prior", "join", "audit")}
    for path in paths.values(): path.write_text("synthetic CLI boundary only\n")
    calls = []
    monkeypatch.setattr(corpus, "audit_with_partials", lambda *args: calls.append(("partial", args)) or {"control": True})
    monkeypatch.setattr(corpus, "audit", lambda *args: calls.append(("old", args)) or {"control": True})
    shared = ["--final-enrollment", str(paths["enrollment"]), "--membership-source", str(paths["source"]),
              "--lane-closure", str(paths["lane"]), "--prior-progress", str(paths["prior"]),
              "--output-root", str(tmp_path / "unclaimed-output")]
    with pytest.raises(SystemExit) as error:
        cli.main(["audit-partial", *shared])
    assert error.value.code == 2 and not calls
    assert cli.main(["audit-partial", *shared, "--partial-progress", str(paths["join"])]) == 0
    assert calls[-1][0] == "partial" and calls[-1][1][-2] == [corpus.reference(paths["join"])]
    assert cli.main(["audit", *shared]) == 0 and calls[-1][0] == "old"
    with pytest.raises(SystemExit) as error:
        cli.main(["audit", *shared, "--partial-progress", str(paths["join"])])
    assert error.value.code == 2 and len(calls) == 2
    assert not (tmp_path / "unclaimed-output").exists()
    capsys.readouterr()


# This fixture executes the separately bound progress reader over controlled
# original Source/runtime/deep reports. It creates no genuine trace credit.
from tests.test_rapid_partial_progress import fixture as retained_partial_join


def partial_api_coupling(tmp_path, monkeypatch, retained_partial_join):
    from qcsd_lab import rapid_partial_progress as progress
    from qcsd_lab import rapid_partial_lane as original
    from qcsd_lab.rapid_operation_facts import OperationFacts
    ref = progress.publish(prior_progress=retained_partial_join["prior"],
        enrollment=retained_partial_join["enrollment"], partials=[retained_partial_join["portion"]],
        output=retained_partial_join["output"])
    membership = []
    for member in retained_partial_join["classes"]:
        membership.append({**member, "canonical_sites": [f"class{member['class_index']}.invalid"],
            "original_graph_sha256": member.get("original_graph_sha256", "1" * 64),
            "capture_limits": member.get("capture_limits", {"max_response_bytes": 16777216, "capture_megabytes": 64})})
    base = {"classes": membership, "lanes": [], "read_dependencies": [], "directory_dependencies": []}

    def base_audit(enrollment, source, epochs, closures, prior, root):
        root.mkdir()
        return corpus._write(root / "audit.json", corpus.AUDIT_TYPE, {"controlled_original_complete_audit": True})

    def base_proof(ref, *, require_complete=True):
        corpus.reopen(ref)
        assert require_complete is False
        return copy.deepcopy(base), corpus.coverage(membership, [], require_complete=False)

    monkeypatch.setattr(corpus, "audit", base_audit)
    monkeypatch.setattr(corpus, "_reopen_audit", base_proof)
    monkeypatch.setattr(original, "_run_original", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("consuming partial evidence must not rerun the original deep validator")))
    derive, observed, watch = progress._derive, progress.observed_inputs, OperationFacts.watch_file
    counts = {"derive": 0, "watched_after_snapshot": None, "watched": 0}
    dependency = Path(retained_partial_join["fresh"]["stdout.log"]["path"])

    def counted_derive(*args, **kwargs):
        counts["derive"] += 1
        return derive(*args, **kwargs)

    def counted_watch(self, path):
        if Path(path).absolute() == dependency: counts["watched"] += 1
        return watch(self, path)

    def counted_observed(*args, **kwargs):
        value = observed(*args, **kwargs)
        counts["watched_after_snapshot"] = counts["watched"]
        return value

    monkeypatch.setattr(progress, "_derive", counted_derive)
    monkeypatch.setattr(progress, "observed_inputs", counted_observed)
    monkeypatch.setattr(OperationFacts, "watch_file", counted_watch)
    arguments = (retained_partial_join["enrollment"], retained_partial_join["portion"]["receipt"], [], [],
        [{"path": retained_partial_join["prior"]["path"], "sha256": corpus.RETAINED_PROGRESS_SHA256}], [ref])
    return arguments, ref, counts, dependency


def test_public_partial_audit_uses_one_original_proof_and_authenticated_snapshots(
        tmp_path, monkeypatch, retained_partial_join):
    from qcsd_lab import rapid_partial_progress as progress
    arguments, joined, counts, _ = partial_api_coupling(tmp_path, monkeypatch, retained_partial_join)
    root = tmp_path / "corpus-audit"
    ref = corpus.audit_with_partials(*arguments, root)
    value = corpus._document(ref, corpus.PARTIAL_AUDIT_TYPE)
    assert counts["derive"] == 1
    assert counts["watched"] == counts["watched_after_snapshot"]
    assert value["facts"]["accepted_individual_partial_traces"] == 4
    assert value["scientific_credit"] is False and value["measurement_equivalence_claimed"] is False
    assert value["partial_progress"] == [joined]
    rows = value["accepted_partial_rows"]
    assert [row["logical_visit"] for row in rows] == [4, 5, 6, 7]
    assert all(row["host_returncode"] == 1 and row["aggregate_status"] == "incomplete"
        and row["capture_limits"]["max_attempts"] == 3 for row in rows)
    dependencies = {ref["path"] for ref in value["read_dependencies"]}
    assert Path(retained_partial_join["fresh"]["stdout.log"]["path"]).as_posix() in dependencies
    assert Path(retained_partial_join["portion"]["verify"]["completed"]["path"]).as_posix() in dependencies
    # The fixture's enrollment/release/original proof is controlled, not a real
    # SCI36 join. The genuine public deep operations are not repeated here.


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_partial_api_final_fence_rejects_changes_after_authenticated_snapshot(
        tmp_path, monkeypatch, retained_partial_join, mutation):
    arguments, _, _, dependency = partial_api_coupling(tmp_path, monkeypatch, retained_partial_join)
    combine = corpus._combined_dependencies

    def changed(*args):
        value = combine(*args)
        if mutation == "bytes": dependency.write_text("substituted sealed deep output\n")
        elif mutation == "mode": dependency.chmod(0o644 if dependency.stat().st_mode & 0o777 == 0o600 else 0o600)
        else:
            directory = Path(retained_partial_join["report"]["directory_dependencies"][0]["path"])
            (directory / "unsealed-new-entry").write_text("must refuse")
        return value

    monkeypatch.setattr(corpus, "_combined_dependencies", changed)
    root = tmp_path / "refused-corpus-audit"
    with pytest.raises(ValueError, match="changed|membership"):
        corpus.audit_with_partials(*arguments, root)
    assert not (root / "audit.json").exists()


def test_partial_api_missing_independent_verification_refuses_before_publication(
        tmp_path, monkeypatch, retained_partial_join):
    from qcsd_lab import rapid_partial_progress as progress
    retained_partial_join["portion"]["verify"].pop("completed")
    with pytest.raises(ValueError):
        progress.publish(prior_progress=retained_partial_join["prior"],
            enrollment=retained_partial_join["enrollment"], partials=[retained_partial_join["portion"]],
            output=retained_partial_join["output"])
    assert not retained_partial_join["output"].exists()
