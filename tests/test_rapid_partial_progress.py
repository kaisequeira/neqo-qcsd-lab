"""HOST controls with explicitly synthetic original proof/enrollment boundaries.

No fixture supplies actual scientific credit. The original isolated program is
executed over the controlled original API from test_rapid_partial_lane.
"""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import sys
import shutil

import pytest

from qcsd_lab import rapid_partial_progress as join
from qcsd_lab import rapid_partial_lane as original
from qcsd_lab import rapid_slot_chunks as chunks
from qcsd_lab.rapid_operation_facts import OperationFacts
from tests.test_rapid_partial_lane import formal_report, original_fixture

REAL_CLASS_ROWS = join._class_rows


def now(): return datetime.now(timezone.utc).isoformat()


def outer(root, name, command, started_at, result):
    root.mkdir(exist_ok=True)
    values = {
        "started": {"command": command, "started_at": started_at, "cwd": str(root)},
        "stdout": {"operation": name, "status": "closed", "result": result},
    }
    paths = {"started": root / (name + "-started.json"), "completed": root / (name + "-completed.json"),
             "stdout": root / (name + ".stdout.log"), "stderr": root / (name + ".stderr.log")}
    for key in ("started", "stdout"): paths[key].write_bytes(original.encoded(values[key]))
    paths["stderr"].write_bytes(b"")
    paths["completed"].write_bytes(original.encoded({"returncode": 0, "completed_at": now(),
        "elapsed_seconds": 1.0, "stdout_sha256": original.reference(paths["stdout"])["sha256"],
        "stderr_sha256": original.reference(paths["stderr"])["sha256"]}))
    return {k: original.reference(p) for k, p in paths.items()}


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    report = formal_report()
    report["lane"]["mode"] = "tamaraw"
    report["experiment"]["configuration"]["defenses"][0]["name"] = "tamaraw"
    report["experiment"]["source"]["lab_commit"] = "86cd8c78cf16447e6add3d10ffa02f6167505276"
    report["lineage"]["lab_commit"] = report["experiment"]["source"]["lab_commit"]
    report["experiment"]["configuration"].pop("capture_limits")
    report["experiment"]["configuration"]["limits"] = {
        "capture_megabytes": 64, "capture_seconds": 180, "max_attempts": 3,
        "max_response_bytes": 16777216, "per_origin_cooldown_seconds": 0.0,
        "settle_seconds": 2.0, "timeout_seconds": 120}
    manifests = tmp_path / "manifests"; manifests.mkdir()
    classes = [{"candidate_id": "retained-first", "class_index": 1, "workload_id": "retained-first-site"}]
    for site in report["sites"]:
        p = manifests / (site["workload_id"] + ".json")
        # Repeated URL occurrences, nonstar dependency and exact safe headers.
        p.write_bytes(original.encoded({"resources": [
            {"id": 0, "url": "https://primary.test/", "headers": {}, "dependencies": []},
            {"id": 1, "url": "https://second.test/shared?q=%2F", "headers": {"accept": "*/*"}, "dependencies": [0]},
            {"id": 2, "url": "https://second.test/shared?q=%2F", "headers": {"accept": "*/*"}, "dependencies": [1]}],
            "preparation": {"primary_resource_id": 0, "final_url": "https://primary.test/",
                            "approved_origins": ["https://primary.test", "https://second.test"]}}))
        site["workload_sha256"] = original.reference(p)["sha256"]
        classes.append({"candidate_id": site["candidate_id"], "class_index": int(site["workload_id"][-1]),
            "workload_id": site["workload_id"], "original_manifest": original.reference(p),
            "capture_limits": {**report["experiment"]["configuration"]["limits"], "max_attempts": 1},
            "original_graph_sha256": join.graph_identity(p)})
    for row in report["experiment"]["configuration"]["workloads"]:
        row["sha256"] = next(s["workload_sha256"] for s in report["sites"] if s["workload_id"] == row["id"])
    for sample in report["experiment"]["samples"]: sample["defense"] = "tamaraw"
    source, inputs = original_fixture(tmp_path, report)
    (Path(source["root"]) / "tools").mkdir()
    source.update({"lab_head": report["lineage"]["lab_commit"],
        "native_head": "c24da2afeec2944a67c48b38eba957dcd543728d",
        "files": {p.relative_to(source["root"]).as_posix(): original.reference(p)
                  for p in Path(source["root"]).rglob("*") if p.is_file()}})
    binding = original._write(tmp_path / "source.json", original.SOURCE_TYPE, source)
    # Only the original complete paired Git release boundary is controlled.
    # Actual production always invokes the unchanged original full validator.
    monkeypatch.setattr(join, "_release_source", lambda ref: deepcopy(source))
    inputs["source_binding"] = binding
    tool = original.reference(Path(join.__file__).parents[2] / "tools/rapid_partial_lane.py")
    ds = now(); first, deep = original._run_original(source, inputs, tmp_path / "declare-deep")
    facts = original.accepted_subset(first)
    receipt = original._write(tmp_path / "partial.json", original.TYPE, {
        "contract": original.CONTRACT, "inputs": inputs, "reader": original.reference(Path(original.__file__)),
        "deep_operation": deep, "read_dependencies": first["read_dependencies"],
        "directory_dependencies": first["directory_dependencies"], **facts, "published_at": now()})
    args = {"--source-binding": binding["path"], "--spec": inputs["spec"]["path"],
        "--evidence-root": inputs["evidence_root"], "--intent": inputs["intent"]["path"],
        "--result": inputs["result"]["path"], "--audit-root": str(tmp_path / "declare-deep"),
        "--output": receipt["path"]}
    command = [sys.executable, "-I", "-B", tool["path"], "declare"] + [x for pair in args.items() for x in pair]
    declared = outer(tmp_path / "public", "declare", command, ds, receipt)
    vs = now(); second, fresh = original._run_original(source, inputs, tmp_path / "verify-deep")
    verified = outer(tmp_path / "public", "verify", [sys.executable, "-I", "-B", tool["path"], "verify",
        "--receipt", receipt["path"], "--audit-root", str(tmp_path / "verify-deep")], vs,
        {"accepted_count": facts["accepted_count"], "aggregate_status": "incomplete", "lane_pass_claim": False,
         "aggregate_formal_credit": 0, "fresh_deep_operation": fresh})
    portion = {"receipt": receipt, "tool": tool, "declare": declared, "verify": verified}
    enrollment = tmp_path / "enrollment.json"; enrollment.write_bytes(original.encoded(classes))
    def controlled_classes(ref):
        rows = join._json(ref)
        for row in rows[1:]:
            join._open(row["original_manifest"])
            assert row["original_graph_sha256"] == join.graph_identity(Path(row["original_manifest"]["path"]))
        return rows
    monkeypatch.setattr(join, "_class_rows", controlled_classes)
    prior_slots = [(1, "undefended", i) for i in range(8)] + [(1, "front", i) for i in range(4)]
    prior_slots += [(1, "tamaraw", i) for i in [*range(4), *range(12, 32)]]
    prior_value = {"artifact_type": "controlled-original-proof-boundary", "closed_at": "2026-01-01T00:00:00+00:00",
        "historical_browser_traces_excluded": 0, "formal_accepted_trace_count": 36,
        "actual_installed_deep_reopened": True, "measurement_epochs_preserve_original_source_and_runtime_labels": True,
        "accepted_formal_slots": [{"candidate_id": "retained-first", "class_index": c, "mode": m, "visit": v}
                                  for c, m, v in prior_slots]}
    prior = tmp_path / "prior.json"; prior.write_bytes(original.encoded(prior_value))
    real_prior = chunks.prior_progress
    def controlled_prior(ref, rows):
        if Path(ref["path"]) == prior:
            join._open(ref)
            return deepcopy(prior_value), set(prior_slots), {prior}
        return real_prior(ref, rows)
    monkeypatch.setattr(chunks, "prior_progress", controlled_prior)
    return {"portion": portion, "prior": original.reference(prior), "enrollment": original.reference(enrollment),
            "classes": classes, "facts": facts, "fresh": fresh, "report": first, "output": tmp_path / "join.json"}


def publish(f):
    return join.publish(prior_progress=f["prior"], enrollment=f["enrollment"], partials=[f["portion"]], output=f["output"])


def change(ref, update):
    p = Path(ref["path"]); value = json.loads(p.read_bytes()); update(value)
    p.write_bytes(original.encoded(value)); return original.reference(p)


def test_public_join_keeps_real_logical_gaps_failed_aggregate_and_graph(fixture):
    ref = publish(fixture); value, files = join.read_inputs(ref)
    assert value["retained_prior_trace_count"] == 36 and value["formal_accepted_trace_count"] == 40
    assert value["aggregate_status"] == "incomplete" and value["aggregate_formal_credit"] == 0
    assert value["partial_lanes"][0]["remaining_samples"] == fixture["facts"]["remaining_samples"]
    assert [r["logical_visit"] for r in value["individual_slots"]] == [4, 5, 6, 7]
    assert all(r["host_returncode"] == 1 and r["lane_pass_claim"] is False for r in value["individual_slots"])
    assert all(r["capture_limits"]["max_attempts"] == 3 and r["capture_limits"]["timeout_seconds"] == 120
               and r["capture_limits"]["capture_seconds"] == 180 for r in value["individual_slots"])
    assert value["classes"][1]["capture_limits"]["max_attempts"] == 1
    assert all(r["original_graph_sha256"] == fixture["classes"][1]["original_graph_sha256"] for r in value["individual_slots"])
    assert chunks.ranges({*range(4), *range(12, 32)}) == ((4, 8), (32, 16), (48, 16))
    assert Path(fixture["portion"]["receipt"]["path"]) in files
    assert Path(fixture["fresh"]["stdout.log"]["path"]) in files
    assert all(Path(ref["path"]) in files for ref in fixture["portion"]["declare"].values())
    payload = original._document(fixture["portion"]["receipt"], original.TYPE)
    assert all(Path(ref["path"]) in files for ref in payload["deep_operation"].values())
    assert Path(payload["reader"]["path"]) in files
    inner_start = join._json(payload["deep_operation"]["started.json"])
    assert Path(inner_start["interpreter"]["path"]) in files


def test_chunk_public_dispatch_preserves_every_original_slot_and_skips_good_partial_only(fixture):
    ref = publish(fixture)
    value, slots, files = chunks.prior_progress({k: ref[k] for k in ("path", "sha256")}, fixture["classes"])
    assert len(slots) == 40 and (2, "tamaraw", 4) in slots and (3, "tamaraw", 4) not in slots
    assert (1, "tamaraw", 0) in slots and (1, "tamaraw", 8) not in slots
    assert chunks.ranges({v for c, m, v in slots if c == 2 and m == "tamaraw"}) == ((0, 4), (8, 16), (24, 16), (40, 16), (56, 8))
    assert Path(ref["path"]) in files and value["individual_trace_count"] == 4


@pytest.mark.parametrize("case", ["missing-verify", "same-deep", "public-failed", "public-command", "deep-command",
    "changed-original-source", "receipt-accepted", "receipt-aggregate", "wrong-order", "class-moved", "class-caps", "source-subset"])
def test_join_refuses_missing_failed_relabelled_or_substituted_authority(fixture, case):
    f = fixture; p = f["portion"]
    if case == "missing-verify": p.pop("verify")
    elif case == "same-deep":
        p["verify"]["stdout"] = change(p["verify"]["stdout"], lambda v: v["result"].update(
            fresh_deep_operation=original._document(p["receipt"], original.TYPE)["deep_operation"]))
    elif case == "public-failed": p["verify"]["completed"] = change(p["verify"]["completed"], lambda v: v.update(returncode=1))
    elif case == "public-command": p["verify"]["started"] = change(p["verify"]["started"], lambda v: v["command"].append("--skip"))
    elif case == "deep-command":
        Path(f["fresh"]["started.json"]["path"]).write_text("{}")
    elif case == "changed-original-source":
        binding = original._document(p["receipt"], original.TYPE)["inputs"]["source_binding"]
        Path(binding["path"]).write_text("{}")
    elif case.startswith("receipt-"):
        def mutate(v):
            if case == "receipt-accepted": v["payload"]["accepted_samples"][0]["logical_visit"] = 0
            else: v["payload"]["lane_pass_claim"] = True
            v["payload_sha256"] = hashlib.sha256(original.encoded(v["payload"])).hexdigest()
        p["receipt"] = change(p["receipt"], mutate)
    elif case == "wrong-order": p["verify"]["started"] = change(p["verify"]["started"], lambda v: v.update(started_at="2000-01-01T00:00:00+00:00"))
    elif case in {"class-moved", "class-caps"}:
        def mutate(v):
            if case == "class-moved": v[1]["class_index"] = 3
            else: v[1]["capture_limits"]["max_response_bytes"] *= 4
        f["enrollment"] = change(f["enrollment"], mutate)
    else:
        binding = original._document(p["receipt"], original.TYPE)["inputs"]["source_binding"]
        change(binding, lambda v: v["payload"].update(files={}))
    with pytest.raises((ValueError, KeyError)): publish(f)
    assert not f["output"].exists()


@pytest.mark.parametrize("case", ["bytes", "mode", "membership"])
def test_owned_action_closing_fence_rejects_post_validation_mutation(fixture, case):
    ref = publish(fixture); facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        join.validate(ref)
        p = Path(fixture["report"]["read_dependencies"][0]["path"])
        if case == "bytes": p.write_text("changed")
        elif case == "mode": p.chmod(0o600 if p.stat().st_mode & 0o777 != 0o600 else 0o644)
        else:
            directory = Path(fixture["report"]["directory_dependencies"][0]["path"])
            (directory / "unexpected-after-proof").write_text("new")
        with pytest.raises(ValueError): join.close_operation(facts)


def test_duplicate_partial_or_prior_slot_never_receives_twice_the_credit(fixture):
    with pytest.raises(ValueError, match="repeats"):
        join.publish(prior_progress=fixture["prior"], enrollment=fixture["enrollment"],
                     partials=[fixture["portion"], fixture["portion"]], output=fixture["output"])
    assert not fixture["output"].exists()


def test_read_inputs_authenticates_one_derivation_and_old_reader_never_runs_on_consume(fixture, monkeypatch):
    ref = publish(fixture); count = []
    real = join._derive
    monkeypatch.setattr(join, "_derive", lambda *a, **kw: (count.append(1), real(*a, **kw))[1])
    monkeypatch.setattr(original, "_run_original", lambda *a, **kw: pytest.fail("new consumption ran historical deep"))
    value, files = join.read_inputs(ref)
    assert len(count) == 1 and len(value["individual_slots"]) == 4 and files


def test_progress_consumer_source_change_is_refused(fixture, monkeypatch):
    ref = publish(fixture); sources = join._sources(); sources["rapid_slot_chunks"] = "f" * 64
    monkeypatch.setattr(join, "_sources", lambda: sources)
    with pytest.raises(ValueError, match="Source"): join.validate(ref)


@pytest.mark.parametrize("case", ["program", "reader", "interpreter", "request"])
def test_rehashed_inner_command_source_and_request_substitution_refuses(fixture, case):
    source = original._document(original._document(fixture["portion"]["receipt"], original.TYPE)["inputs"]["source_binding"], original.SOURCE_TYPE)
    inputs = original._document(fixture["portion"]["receipt"], original.TYPE)["inputs"]
    operation = deepcopy(fixture["fresh"])
    def mutate(v):
        if case == "program": v["command"][-1] += "\n# substituted"
        elif case == "request": v["request"]["result"] = inputs["evidence_root"]
        else: v[case]["sha256"] = "f" * 64
    operation["started.json"] = change(operation["started.json"], mutate)
    public = fixture["portion"]["verify"]; args = {"--receipt": fixture["portion"]["receipt"]["path"],
        "--audit-root": str(Path(operation["started.json"]["path"]).parent)}
    _, interpreter, _, _ = join._outer(public, "verify", args, fixture["portion"]["tool"])
    reader = original._document(fixture["portion"]["receipt"], original.TYPE)["reader"]
    with pytest.raises(ValueError): join._deep(source, inputs, operation, reader, interpreter)


@pytest.mark.parametrize("case", ["current-input", "sealed-membership"])
def test_publication_closes_all_dependencies_before_creating_output(fixture, monkeypatch, case):
    real_close = join._close
    def mutate_after_last_raw_close(value):
        real_close(value)
        if value.get("contract") == join.CONTRACT:
            if case == "current-input": Path(fixture["enrollment"]["path"]).write_text("changed after first proof")
            else:
                p = Path(value["directory_dependencies"][0]["path"])
                (p / "late-member-before-publication").write_text("new")
    monkeypatch.setattr(join, "_close", mutate_after_last_raw_close)
    with pytest.raises(ValueError): publish(fixture)
    assert not fixture["output"].exists()


def test_semantic_json_uses_the_same_authenticated_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "snapshot.json"; path.write_bytes(original.encoded({"accepted": 1}))
    ref = original.reference(path)
    # A second unbound semantic read could differ from the observed raw bytes.
    # The new reader consumes the authenticated snapshot itself.
    real_read = join._observe
    def observed_then_replaced(value, **kwargs):
        p, raw = real_read(value, **kwargs)
        p.write_bytes(original.encoded({"accepted": 999}))
        return p, raw
    monkeypatch.setattr(join, "_observe", observed_then_replaced)
    facts = OperationFacts(); facts.begin_action()
    with facts.scope():
        assert join._json(ref) == {"accepted": 1}
        with pytest.raises(ValueError): facts.check()


def offline_portion(f, tmp_path, monkeypatch):
    """Controlled immutable-image boundary; no Docker/image execution or credit."""
    old = original._document(f["portion"]["receipt"], original.TYPE)
    source = original._document(old["inputs"]["source_binding"], original.SOURCE_TYPE)
    root = tmp_path / "offline-proof"; root.mkdir()
    producer = tmp_path / "original-reader"
    for relative, path in (("tools/rapid_partial_lane.py", f["portion"]["tool"]["path"]),
                           ("src/qcsd_lab/rapid_partial_lane.py", original.__file__)):
        target = producer / relative; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    tool = original.reference(producer / "tools/rapid_partial_lane.py")
    reader = original.reference(producer / "src/qcsd_lab/rapid_partial_lane.py")
    image = deepcopy(join.REGISTERED_IMAGES[source["lab_head"]])
    export = {"lab_commit": source["lab_head"], "neqo_commit": source["native_head"],
              "lab_dirty": False, "neqo_dirty": False}
    export_path = root / "source-export.json"; export_path.write_bytes(original.encoded(export))
    image["source_export"] = original.reference(export_path)["sha256"]
    monkeypatch.setattr(join, "REGISTERED_IMAGES", {source["lab_head"]: image})
    runtime_path = root / "runtime.json"
    runtime_path.write_bytes(original.encoded({"collection_image_digest": image["image"],
        "installed_client_sha256": image["client"], "source_manifest": str(export_path),
        "exported_source_manifest_sha256": image["source_export"], "source": export,
        "installed_byte_verification_completed": True, "scientific_credit": False}))
    driver = root / "controlled-driver.py"; driver.write_text("# Controlled HOST image boundary only\n")
    plan = root / "inputs.json"; plan.write_bytes(original.encoded({
        "original_source": source["root"], "original_lab": source["lab_head"],
        "original_native": source["native_head"], "original_image": image["image"],
        "formal_credit_added": 0, "aggregate_lane_pass_claim": False,
        "intended_lane": f["facts"]["lane"]["campaign_name"],
        "driver": original.reference(driver), "reader_closure": original.reference(driver),
        "reader_review": original.reference(driver)}))
    authority = {"artifact_type": join.OFFLINE_TYPE, "runtime": original.reference(runtime_path),
                 "root_inputs": original.reference(plan)}
    old_verified = json.loads(Path(f["portion"]["verify"]["stdout"]["path"]).read_bytes())["result"]
    timestamp = datetime.now(timezone.utc)
    at = lambda seconds: (timestamp - timedelta(seconds=seconds)).isoformat()
    operations = []
    for name, old_operation in (("declare", old["deep_operation"]), ("verify", old_verified["fresh_deep_operation"])):
        destination = root / (name + "-deep")
        shutil.copytree(Path(old_operation["started.json"]["path"]).parent, destination)
        start_path = destination / "started.json"; start = json.loads(start_path.read_bytes())
        start.update(reader=reader, interpreter=image["interpreter"])
        start["started_at"] = at(6 if name == "declare" else 2)
        start["command"][0] = image["entrypoint"]
        start["request"]["scratch_root"] = str(destination / "scratch")
        start_path.write_bytes(original.encoded(start))
        end_path = destination / "completed.json"; end = json.loads(end_path.read_bytes())
        end["completed_at"] = at(5 if name == "declare" else 1)
        end_path.write_bytes(original.encoded(end))
        operations.append({name: original.reference(destination / name)
                           for name in ("started.json", "completed.json", "stdout.log", "stderr.log")})
    old.update(reader=reader, deep_operation=operations[0], published_at=at(4))
    receipt = original._write(root / "partial.json", original.TYPE, old)
    workspace = Path(source["root"]).parent
    prefix = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "1000:1000", "--volume",
        f"{workspace}:{workspace}:ro", "--volume", f"{root}:{root}:rw", "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=268435456", "--workdir", str(workspace), "--entrypoint",
        image["entrypoint"], image["image"], "-I", "-B", tool["path"]]
    args = {"--source-binding": old["inputs"]["source_binding"]["path"], "--spec": old["inputs"]["spec"]["path"],
        "--evidence-root": old["inputs"]["evidence_root"], "--intent": old["inputs"]["intent"]["path"],
        "--result": old["inputs"]["result"]["path"], "--audit-root": str(root / "declare-deep"),
        "--output": receipt["path"]}
    declared = outer(root / "operations", "declare", prefix + ["declare", *[x for pair in args.items() for x in pair]],
                     at(7), receipt)
    declared["completed"] = change(declared["completed"], lambda value: value.update(completed_at=at(3)))
    verified = outer(root / "operations", "verify", prefix + ["verify", "--receipt", receipt["path"],
        "--audit-root", str(root / "verify-deep")], at(2.5),
        {**old_verified, "fresh_deep_operation": operations[1]})
    f["portion"] = {"receipt": receipt, "tool": tool, "declare": declared, "verify": verified,
                    "offline_image": authority}
    return f


def test_offline_public_proof_preserves_image_interpreter_label_and_portable_workspace(fixture, tmp_path, monkeypatch):
    f = offline_portion(fixture, tmp_path, monkeypatch)
    ref = publish(f)
    value, files = join.read_inputs(ref)
    assert len(value["individual_slots"]) == 4
    assert Path("/usr/bin/python3.11") not in files
    assert Path(f["portion"]["offline_image"]["runtime"]["path"]) in files
    assert Path(f["portion"]["offline_image"]["root_inputs"]["path"]) in files


@pytest.mark.parametrize("case", ["network", "workspace-rw", "extra-mount", "image", "root-user", "entrypoint",
                                 "wrong-lane", "binary"])
def test_offline_public_proof_refuses_unbound_sandbox_and_image(fixture, tmp_path, monkeypatch, case):
    f = offline_portion(fixture, tmp_path, monkeypatch)
    row = f["portion"]
    if case in {"wrong-lane", "binary"}:
        key = "root_inputs" if case == "wrong-lane" else "runtime"
        row["offline_image"][key] = change(row["offline_image"][key], lambda v:
            v.update({"intended_lane": "another-lane"} if case == "wrong-lane" else {"installed_client_sha256": "f" * 64}))
    else:
        def mutate(v):
            argv = v["command"]
            if case == "network": argv[4] = "bridge"
            elif case == "workspace-rw": argv[13] = argv[13].removesuffix(":ro") + ":rw"
            elif case == "extra-mount": argv[22:22] = ["--volume", "/other:/other:ro"]
            elif case == "image": argv[22] = "sha256:" + "f" * 64
            elif case == "root-user": argv[11] = "0:0"
            else: argv[21] = "/other/python"
        row["declare"]["started"] = change(row["declare"]["started"], mutate)
    with pytest.raises(ValueError): publish(f)
    assert not f["output"].exists()


def test_action_raw_reference_and_original_release_validate_once_with_fresh_close(fixture, monkeypatch):
    ref = fixture["report"]["read_dependencies"][0]
    binding = original._document(fixture["portion"]["receipt"], original.TYPE)["inputs"]["source_binding"]
    context = OperationFacts(); context.begin_action(); calls = []
    real_watch, real_source = context.watch_file, join._release_source
    def watch(path):
        if str(path) == ref["path"]: calls.append("file")
        return real_watch(path)
    monkeypatch.setattr(context, "watch_file", watch)
    monkeypatch.setattr(join, "_release_source", lambda value: (calls.append("source"), real_source(value))[1])
    with context.scope():
        for _ in range(20): join._open(ref); join._source(binding)
        assert calls.count("file") == 1 and calls.count("source") == 1
        observed = join.observed_inputs({Path(ref["path"])}, context)
        assert observed == [ref]
        Path(ref["path"]).write_text("changed after memo")
        with pytest.raises(ValueError): join.close_operation(context)


def test_directory_fence_is_shallow_and_rejects_late_membership(fixture, monkeypatch):
    context = OperationFacts(); context.begin_action()
    monkeypatch.setattr(context, "watch_tree", lambda *_a, **_k: pytest.fail("raw directories were recursively watched"))
    with context.scope():
        for _ in range(20): join._close(fixture["report"])
        parent = Path(fixture["report"]["directory_dependencies"][0]["path"])
        (parent / "late-shallow-member").write_text("changed")
        with pytest.raises(ValueError): join.close_operation(context)


def test_input_snapshot_export_needs_authentication_and_current_owner(tmp_path):
    p = tmp_path / "unobserved"; p.write_text("not authority")
    with pytest.raises(ValueError): join.observed_inputs({p})
    context = OperationFacts(); context.begin_action()
    with context.scope():
        with pytest.raises(ValueError): join.observed_inputs({p})


@pytest.mark.parametrize("case", ["complete", "changed-mode", "changed-bytes"])
def test_real_class_rows_authenticate_prepared_three_field_reference(fixture, monkeypatch, case):
    classes = [{**row, "prepared_workload": row["original_manifest"]} for row in fixture["classes"][1:]]
    monkeypatch.setattr(join.rolling, "_verify_enrollment", lambda path: ({}, classes, {
        "capture_limits": classes[0]["capture_limits"]}))
    if case == "changed-mode":
        classes[0]["prepared_workload"] = {**classes[0]["prepared_workload"], "mode": 0o700}
    elif case == "changed-bytes":
        Path(classes[0]["prepared_workload"]["path"]).write_text("changed")
    if case == "complete":
        actual = REAL_CLASS_ROWS(fixture["enrollment"])
        assert len(actual) == 5 and all(row["original_manifest"]["mode"] == 0o644 for row in actual)
        assert actual[0]["original_graph_sha256"] == fixture["classes"][1]["original_graph_sha256"]
    else:
        with pytest.raises(ValueError): REAL_CLASS_ROWS(fixture["enrollment"])


def test_three_field_prior_is_authenticated_before_unchanged_legacy_helper(tmp_path, monkeypatch):
    p = tmp_path / "prior.json"; p.write_text('{}')
    ref = original.reference(p); seen = []
    real = chunks.rolling._open_ref
    def strict_legacy(value):
        seen.append(value)
        assert set(value) == {"path", "sha256"}
        return real(value)
    monkeypatch.setattr(chunks.rolling, "_open_ref", strict_legacy)
    monkeypatch.setattr(chunks.enrollment, "_progress", lambda *_: (_ for _ in ()).throw(ValueError("controlled stop after legacy boundary")))
    with pytest.raises(ValueError, match="controlled stop"): chunks.prior_progress(ref, [])
    assert seen == [{k: ref[k] for k in ("path", "sha256")}]
    seen.clear()
    with pytest.raises(ValueError): chunks.prior_progress({**ref, "mode": 0o700}, [])
    assert not seen
