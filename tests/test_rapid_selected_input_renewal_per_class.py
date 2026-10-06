"""Portable HOST defended renewal of a complete larger-budget GET fixture.

The physical responses, original audit inventory and installed runtime are
synthetic boundaries. Complete GET proof, two-class seed, per-class enrollment,
renewal, portable stage/finalize/readers and planned deep-verifier transport
use their actual APIs.
No Native, image, qualification, canary, network or formal capture is executed.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import shutil
import sys

import pytest

from qcsd_lab import application_response_policy as responses
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_selected_budget_input as budget_input
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_selected_input_renewal as renewed
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
from qcsd_lab import supplied_static_budget_successor as budget
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as preparation
from qcsd_lab import tamaraw_fixed_configuration as tamaraw
from tests.test_rapid_selected_input_renewal import snapshots, separated_stage_case
from tests.test_selected_capture_amendment import flight
from tests.test_selected_capture_input import REPOSITORY, load, write
from tests.test_supplied_static_get import reseal_outputs
from tests.test_supplied_static_preparation import POLICIES


@pytest.fixture
def complete_per_class_case(separated_stage_case, tmp_path, monkeypatch):
    # Prospective outputs are siblings of the retained input namespace. Keep
    # the real operator's immutable-input disjointness checks intact.
    inner = tmp_path / "immutable-per-class-inputs"
    inner.mkdir()
    seed = separated_stage_case
    limited = inner / "retained-budget-limited-get"
    shutil.copytree(seed["second"]["raw"], limited)
    for path in limited.rglob("*.json"):
        path.write_bytes(path.read_bytes().replace(b"second.example", b"third.example"))
    source_rows = [load(seed["raw"] / "source-list.json")[0], load(limited / "source-list.json")[-1]]
    write(limited / "source-list.json", source_rows)
    source_bytes = (limited / "source-list.json").read_bytes()
    source_sha = graph.digest(source_bytes)
    neutral, binding, primary, full = bootstrap._inputs(source_bytes, source_sha, "third.example")
    for relative, value in (("neutral-input.json", neutral), ("input-binding.json", binding),
            ("bootstrap/native-input.json", primary), ("native-input.json", full)):
        write(limited / relative, value)
    prefix = inner / "original-static-context"
    prefix.mkdir()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:09:30Z")
    static.initialize_context(prefix, limited / "source-list.json", source_sha256=source_sha,
        expected_runtime=seed["context"].provenance["runtime_binding"], parent_context=seed["context"].root)
    declaration = load(limited / "declaration.json")
    declaration.update(context=preparation.reference(prefix / "provenance.json"), source_sha256=source_sha,
        domain="third.example", candidate_queue_position=2, candidate_source_position=2,
        input_binding_sha256=graph.digest((limited / "input-binding.json").read_bytes()),
        neutral_input_sha256=graph.digest((limited / "neutral-input.json").read_bytes()),
        bootstrap_input_sha256=graph.digest((limited / "bootstrap/native-input.json").read_bytes()),
        full_input_sha256=graph.digest((limited / "native-input.json").read_bytes()))
    write(limited / "declaration.json", declaration)
    for child, field in ((limited / "bootstrap", "bootstrap_input_sha256"), (limited, "full_input_sha256")):
        started = load(child / "native-started.json")
        started.update(declaration_sha256=graph.digest((limited / "declaration.json").read_bytes()),
            command=bootstrap._command(child, 16 * 1024 * 1024, 120,
                bootstrap.STRICT_POLICY if child != limited else bootstrap.get.RESPONSE_POLICY))
        write(child / "native-started.json", started)
        run = load(child / "native/run.json")
        run["workload_hash_sha256"] = declaration[field]
        if child == limited:
            run["completion_status"] = "partial"
            run["responses"][1].update(bytes=16_778_994, content_length=46_150_619,
                complete=False, outcome="response_limit")
        write(child / "native/run.json", run)
        reseal_outputs(child)
    (limited / "full-get-proof.json").unlink()
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:11:00Z")
    budget_root = inner / "budget-successor"
    budget.initialize_context(budget_root, original_context=prefix, retained_attempt=limited)
    context = budget.load_context(budget_root)
    raw = inner / "fresh-complete-large-budget-get"
    shutil.copytree(limited, raw)
    def later(value, key=""):
        if isinstance(value, dict): return {name: later(item, name) for name, item in value.items()}
        if isinstance(value, list): return [later(item, key) for item in value]
        if type(value) is int and key.endswith("unix_ns"): return value + 120_000_000_000
        if isinstance(value, str): return value.replace("2026-10-04T00:10:", "2026-10-04T00:12:")
        return value
    for path in raw.rglob("*.json"):
        write(path, later(load(path)))
    declaration = load(raw / "declaration.json")
    declaration.update(context=preparation.reference(context.active.root / "provenance.json"),
        max_response_bytes=budget.RESPONSE_BYTES)
    write(raw / "declaration.json", declaration)
    for child, policy in ((raw / "bootstrap", bootstrap.STRICT_POLICY), (raw, bootstrap.get.RESPONSE_POLICY)):
        started = load(child / "native-started.json")
        started.update(declaration_sha256=graph.digest((raw / "declaration.json").read_bytes()),
            command=bootstrap._command(child, budget.RESPONSE_BYTES, 120, policy))
        write(child / "native-started.json", started)
        run = load(child / "native/run.json")
        run["max_response_bytes"] = budget.RESPONSE_BYTES
        if child == raw:
            count = 16_778_994
            run["completion_status"] = "complete"
            run["responses"][1].update(bytes=count, content_length=count, complete=True,
                outcome="succeeded", body_sha256=graph.digest(b"a" * count))
            run["responses"][1]["response_headers"][1][1] = str(count)
        write(child / "native/run.json", run)
        reseal_outputs(child)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:13:00Z")
    arguments = static._get_arguments(context.active, 2)
    write(raw / "full-get-proof.json", bootstrap.build_proof(raw, **arguments))
    static.admit(context.active, 2, raw, policies=POLICIES)
    budget.terminal_path(context, 2).parent.mkdir(parents=True)
    terminal = budget.account_terminal(context, 2)
    original, _ = budget.prepared_workload(context, terminal)
    candidate = context.candidates[1]
    audit_row = {"candidate": candidate, "manifest": preparation.reference(original),
        "terminal": preparation.reference(terminal), "context": preparation.reference(budget_root / "provenance.json"),
        "capture_limits": context.provenance["capture_limits"],
        "facts": budget.verify_terminal(terminal, context), "scientific_credit": False}
    # Original historical audit/inventory execution is outside this portable
    # HOST fixture. All downstream selected raw and Source validators stay real.
    inventory_path = inner / "synthetic-original-audit-inventory.json"
    write(inventory_path, {"author_root": str(REPOSITORY), "synthetic_audit_boundary": True})
    def inventory_boundary(source_root, inventory, *, full):
        assert source_root == REPOSITORY and inventory == selected.reference(inventory_path)
        return load(selected.reopen(inventory))
    monkeypatch.setattr(budget_input, "_inventory", inventory_boundary)
    started = {"schema_version": 1, "command": [sys.executable, "-I", "-B", "-c", budget_input._AUDIT_PROGRAM,
        str(REPOSITORY), str(budget_root), str(terminal)], "started_at": "2026-10-04T00:13:01Z",
        "source_inventory": selected.reference(inventory_path), "context": selected.reference(budget_root / "provenance.json"),
        "terminal": selected.reference(terminal)}
    start, stdout, stderr, end = (inner / name for name in
        ("audit-started.json", "audit.stdout.log", "audit.stderr.log", "audit-completed.json"))
    write(start, started)
    write(stdout, audit_row)
    stderr.write_bytes(b"")
    write(end, {"schema_version": 1, "returncode": 0, "elapsed_seconds": 1.0,
        "completed_at": "2026-10-04T00:13:02Z", "started": selected.reference(start),
        "stdout": selected.reference(stdout), "stderr": selected.reference(stderr)})
    audit = inner / "selection-audit.json"
    write(audit, receipts._bind(budget_input.AUDIT_TYPE, {"contract": budget_input.CONTRACT,
        "source_root": str(REPOSITORY), "source_inventory": selected.reference(inventory_path),
        "program_sha256": graph.digest(budget_input._AUDIT_PROGRAM.encode()), "result": audit_row,
        "started": selected.reference(start), "completed": selected.reference(end),
        "stdout": selected.reference(stdout), "stderr": selected.reference(stderr),
        "published_at": "2026-10-04T00:13:03Z", "scientific_credit": False}))
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:14:00Z")
    capture_input = budget_input.publish_input(inner / "input.json", audit=audit, candidate_id=candidate["candidate_id"])
    current_runtime = seed["runtime"]
    study = inner / "per-class-study"
    study.mkdir()
    ledger.initialize(study, seed_enrollment=seed["new_enrollment"],
        seed_progress=selected.reference(seed["progress"]), runtime=current_runtime)
    value, _, proof = budget_input.validate_input(capture_input)
    prepared = budget_input.prepare_input(capture_input, inner / (value["workload_id"] + ".json"))
    enrollment = ledger.enroll(study, acquisition_root=budget_root,
        inputs={value["candidate_id"]: selected.reference(capture_input)},
        prepared_workloads={value["candidate_id"]: selected.reference(prepared)})
    batch, classes, policy = ledger.verify_enrollment(enrollment)
    seed_classes = ledger._seed(seed["new_enrollment"])[1]
    assert len(classes) == 3 and classes[:2] == seed_classes
    assert batch["seed"] == rolling._ref(seed["new_enrollment"])
    assert classes[-1]["class_index"] == 3
    assert classes[-1]["candidate_id"] == audit_row["candidate"]["candidate_id"]
    assert ledger.select_classes(batch, classes, policy)[1] == value["capture_limits"]
    assert value["capture_limits"]["max_response_bytes"] == 64 * 1024 * 1024
    assert value["capture_limits"]["capture_megabytes"] == 256
    assert proof["full_list_coverage"] is True
    return {"runtime": current_runtime, "new_enrollment": enrollment, "new_study": study,
        "second": {"prepared": prepared, "input": capture_input, "raw": Path(value["raw_root"])},
        "original": original, "proof": proof, "seed_classes": seed_classes,
        "seed_enrollment": seed["new_enrollment"], "seed_progress": seed["progress"]}


def installed_runtime_boundary(case, api, monkeypatch):
    current_runtime = snapshots(case)
    source = Path(current_runtime["runtime_source_root"])
    shutil.copytree(REPOSITORY / "src/qcsd_lab", source / "src/qcsd_lab", dirs_exist_ok=True)
    for relative in ("config", "neqo-qcsd"):
        shutil.copytree(Path(current_runtime["execution_root"]) / relative,
            source / relative, dirs_exist_ok=True)
    build = case["new_study"] / "controlled-runtime-build"
    (build / "image-context").mkdir(parents=True)
    shutil.copytree(source, build / "image-context/source")
    (build / "runtime-export").mkdir()
    (build / "runtime-export/source.json").write_bytes(Path(current_runtime["source_manifest"]).read_bytes())
    (build / "runtime-export/neqo-qcsd-client").write_bytes(Path(current_runtime["client_binary"]).read_bytes())
    inventory = {p.relative_to(source).as_posix(): {"sha256": graph.digest(p.read_bytes()),
        "executable": bool(p.stat().st_mode & 0o111)} for p in source.rglob("*") if p.is_file()}
    write(build / "source-inventory.json", inventory)
    canonical = {"source": load(Path(current_runtime["source_manifest"])),
        "collection_image_digest": current_runtime["collection_image_digest"],
        "source_inventory_sha256": graph.digest((build / "source-inventory.json").read_bytes())}
    write(build / "canonical-runtime.json", canonical)
    monkeypatch.setattr(api, "checked_runtime", lambda args:
        (api.ref(build / "canonical-runtime.json"), canonical, source))
    monkeypatch.setattr(api, "host_imports", lambda clean: None)
    return current_runtime, source, build, canonical


@pytest.mark.parametrize("mode", ["tamaraw", "cs-buflo"])
def test_actual_complete_per_class_budget_stage_finalize_and_changed_cap_or_graph_rejects(
        complete_per_class_case, monkeypatch, mode):
    case, api = complete_per_class_case, flight()
    current_runtime, source, build, canonical = installed_runtime_boundary(case, api, monkeypatch)
    fixed = tamaraw.POLICY if mode == "tamaraw" else None
    output = Path(current_runtime["data_root"]) / (mode + "-per-class-current-flight")
    retained_paths = (case["new_enrollment"], case["second"]["prepared"], case["second"]["input"],
        case["original"], case["second"]["raw"] / "native/run.json", case["seed_enrollment"], case["seed_progress"])
    before = {path: path.read_bytes() for path in retained_paths}
    args = SimpleNamespace(name=output.name, campaign_seed=71, mode=mode,
        python=Path(sys.executable), enrollment=case["new_enrollment"], study_root=case["new_study"],
        output=output, runtime_build_root=build, clean_runtime_root=source,
        canonical_sha256=api.digest(api.read(build / "canonical-runtime.json")),
        expected_lab_commit=canonical["source"]["lab_commit"],
        expected_native_commit=canonical["source"]["neqo_commit"],
        application_body_identity_policy=responses.COMPLETE_APPLICATION_DELIVERY_POLICY,
        tamaraw_configuration_policy=fixed, renew_selected_inputs=True)
    api.stage(args)
    setup_args = SimpleNamespace(setup=output / "setup.json",
        setup_sha256=api.ref(output / "setup.json")["sha256"])
    setup, _, _, flight_runtime, bindings, manifests = api.checked_setup(setup_args)
    assert renewed.FIELD in setup and "ordinary_renewal" not in setup
    assert setup["original_limits"]["max_response_bytes"] == 64 * 1024 * 1024
    assert setup["original_limits"]["capture_megabytes"] == 256
    assert bindings[0]["class_index"] == 3
    assert manifests[0]["resources"] == load(case["original"])["resources"]
    assert len(manifests[0]["resources"]) == case["proof"]["resource_count"]
    assert manifests[0]["resources"][1]["data_length"] > 16 * 1024 * 1024
    admission_copy = output / "lineage/admission-originals" / case["second"]["prepared"].name
    assert admission_copy.read_bytes() == before[case["second"]["prepared"]]
    api.finalize(setup_args)
    plan_args = SimpleNamespace(plan=output / "plan.json",
        plan_sha256=api.ref(output / "plan.json")["sha256"], command="preamble-image")
    plan, _, _ = api.checked_plan(plan_args)
    assert plan[renewed.FIELD] == setup[renewed.FIELD] and plan["reuse"] is None
    assert plan["capture_limits"]["max_response_bytes"] == 64 * 1024 * 1024
    assert plan["capture_limits"]["capture_megabytes"] == 256
    assert plan["capture_limits"]["max_attempts"] == 1
    assert plan["selected_classes"][0]["class_index"] == 3
    assert plan["selected_classes"][0]["full_graph"] == api.graph(load(case["original"]))
    assert plan.get("tamaraw_configuration_policy") == fixed
    assert plan["formal_accepted_trace_count"] == 0 and not plan["scientific_credit"]
    commands = load(output / "commands.json")
    assert "qualify" in commands and "--selected-input-renewal" in commands["plan"]
    deep = api.image_argv(plan, output, "verify-image", "--mode", mode, "--result", "fixture-result")
    assert readiness._deep_command(plan, output, plan_args.plan_sha256,
        mode, "fixture-result", deep) == deep

    # Rehash the changed metadata so rejection is attributable to the exact
    # per-class condition, rather than the outer flight's sealed reference.
    renewal_path = rolling._open_ref(setup[renewed.FIELD])
    value, _, classes, _ = renewed.validate(renewal_path, enrollment=case["new_enrollment"],
        runtime=flight_runtime, mode=mode, tamaraw_configuration_policy=fixed)
    assert classes[:2] == case["seed_classes"]
    original_renewal = renewal_path.read_bytes()
    changed = deepcopy(value)
    changed["capture_limits"]["max_response_bytes"] = 16 * 1024 * 1024
    write(renewal_path, changed)
    with pytest.raises(ValueError, match="exact graph, mode, runtime, Source or zero-credit role"):
        renewed.validate(renewal_path, enrollment=case["new_enrollment"], runtime=flight_runtime,
            mode=mode, tamaraw_configuration_policy=fixed)
    renewal_path.write_bytes(original_renewal)

    # Rebind the manifest and execution-copy hashes after removing one real
    # resource. The selected full-GET validator must still reject the prune.
    [row] = value["rows"]
    manifest_path = selected.reopen(row["current_manifest"])
    target = Path(flight_runtime["workload_root"]) / manifest_path.name
    manifest_bytes, target_bytes = manifest_path.read_bytes(), target.read_bytes()
    changed_manifest = load(manifest_path)
    changed_manifest["resources"].pop()
    write(manifest_path, changed_manifest)
    target.write_bytes(manifest_path.read_bytes())
    changed = deepcopy(value)
    changed["rows"][0]["current_manifest"] = selected.reference(manifest_path)
    changed["renewals"][row["candidate_id"]]["manifest"] = selected.reference(manifest_path)
    write(renewal_path, changed)
    with pytest.raises(ValueError):
        renewed.validate(renewal_path, enrollment=case["new_enrollment"], runtime=flight_runtime,
            mode=mode, tamaraw_configuration_policy=fixed)
    manifest_path.write_bytes(manifest_bytes)
    target.write_bytes(target_bytes)
    renewal_path.write_bytes(original_renewal)
    renewed.validate(renewal_path, enrollment=case["new_enrollment"], runtime=flight_runtime,
        mode=mode, tamaraw_configuration_policy=fixed)
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert list((output / "logs").iterdir()) == []
