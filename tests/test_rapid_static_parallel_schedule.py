"""Current static scheduling seams; synthetic external runtime/120/canary facts.

Static declarations, complete GET/raw validation, derived manifests, public
plans, scheduling dispatch, exact byte/mode dependencies and fences are real
HOST code. No actual runtime, capture, qualification or scientific credit.
The legacy runtime tests separately exercise the full twelve-operation parser.
"""
from datetime import UTC, datetime
import copy
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from qcsd_lab import buflo_duration_budget as budget
from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as legacy
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_runtime_epochs as epochs
from qcsd_lab import rapid_static_parallel_schedule as schedule
from qcsd_lab import supplied_static_capture_amendment as amendment
from qcsd_lab import supplied_static_graph as graph
from tests.test_supplied_static_capture_amendment import original, qualifier_and_canary, publish, REPOSITORY
from tests.test_supplied_static_get import actual_contract_fixture, load, write
from tests.test_supplied_static_preparation import fixed_graph, append_context
from tests.test_rapid_buflo_duration_amendment import planned
from tools import rapid_rolling_capture as cli

REAL_NAMED_VALIDATOR = schedule.qualification.validate_named_qualification_set_manifest


@pytest.fixture(autouse=True)
def common_data_root(monkeypatch):
    from tests import test_supplied_static_capture_amendment as fixtures
    original_runtime = fixtures.runtime
    def runtime(tmp_path):
        study, value = original_runtime(tmp_path)
        # Real CaptureSpec requires acquisition and capture inputs under its
        # declared data root. Publish that common root in the original policy.
        value["data_root"] = str(tmp_path)
        return study, value
    monkeypatch.setattr(fixtures, "runtime", runtime)


@pytest.fixture(params=["front", "buflo200"])
def current(original, request, monkeypatch):
    a = original
    original_policy_root = Path(a.runtime["runtime_source_root"])
    current_source = original_policy_root.with_name("current-source")
    shutil.copytree(original_policy_root, current_source)
    a.runtime["runtime_source_root"] = str(current_source)
    for name, filename in (("source_manifest", "source.json"), ("client_binary", "client"),
                           ("base_launcher", "qcsd-lab")):
        a.runtime[name] = str(current_source / filename)
    if request.param == "buflo200":
        base, canary, facts = planned(a)
        mode = "buflo"
    else:
        publish(a, buflo=False)
        qualifier, _, canary, facts = qualifier_and_canary(a)
        output = a.study / "serial-plan.json"
        rolling.publish_plan(a.study, a.enrollment, qualifier, output, readiness={"front": canary},
                             runtime_inputs=a.runtime, static_capture_amendment=a.output)
        base = rolling.capture_spec(a.study, a.enrollment, qualifier, output)
        mode = "front"
    selected = budget.POLICY if mode == "buflo" else None
    for relative in {*amendment.authority_files(budget.POLICY).values(), *schedule.CONTROL_FILES,
                     *(item[0] for item in traffic.files(selected).values())}:
        target = Path(a.runtime["runtime_source_root"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY / relative).read_bytes())
    # The actual closed-runtime parser is the sole fixture boundary here. Its
    # exact image, Native/client, imported controls and fresh implementation
    # bindings are still checked by the new scheduling derivation itself.
    canonical = {"source": load(base.source_manifest), "collection_image_digest": base.collection_image_digest,
        "installed_client_sha256": rolling._ref(base.client_binary)["sha256"],
        "checks": {"collection": {"qualification_implementation_sha256": "9" * 64}},
        "verified_at": "2000-01-01T00:00:02Z"}
    canonical_path = a.study / "current-runtime/canonical-runtime.json"
    canonical_path.parent.mkdir()
    write(canonical_path, canonical)
    reference = rolling._ref(canonical_path)
    def reopen(ref, runtime):
        assert ref == rolling._ref(canonical_path)
        value = load(canonical_path)
        if (runtime != a.runtime or value["source"] != load(base.source_manifest)
            or value["collection_image_digest"] != base.collection_image_digest
            or value["installed_client_sha256"] != rolling._ref(base.client_binary)["sha256"]):
            raise ValueError("synthetic closed-runtime boundary binding changed")
        sources = {relative: (Path(runtime["runtime_source_root"]) / relative).read_bytes()
                   for relative in {*amendment.authority_files(budget.POLICY).values(), *schedule.CONTROL_FILES}}
        return value, sources
    monkeypatch.setattr(legacy, "reopen_runtime", reopen)
    sidecar_root = Path(load(base.qualification_spec)["qualification_sets"][0]["sidecar_root"])
    for path in sidecar_root.glob("*.json"):
        if path.name.startswith("_"): continue
        value = load(path)
        value["schema_version"] = schedule.qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
        value["implementation_receipt"]["sha256"] = "9" * 64
        write(path, value)
    def named120(value, **kwargs):
        assert kwargs["require_current_implementation"] is False
    monkeypatch.setattr(schedule.qualification, "validate_named_qualification_set_manifest", named120)
    a.monkeypatch.setattr(rolling.admission, "_now", lambda: datetime.now(UTC).isoformat())
    return SimpleNamespace(a=a, spec=base, canonical=reference, mode=mode, selected=selected,
        original_policy_root=original_policy_root,
        canary=canary, facts=facts, output=a.study / "static-schedule.json")


def capsule(c):
    return schedule.publish_schedule(c.spec, c.a.runtime, c.spec.qualification_spec,
        c.canonical, c.canonical, c.output, reason="prospective same-setting two-worker HOST contract fixture")


def parallel_plan(c, reference):
    output = c.a.study / "parallel-plan.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, output,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime, scheduling=reference,
        static_capture_amendment=c.a.output)
    return rolling.capture_spec(c.a.study, c.a.enrollment, c.spec.qualification_spec, output)


def test_current_same_setting_public_plan_preserves_full_get_and_all_slots(current):
    c = current
    protected = {path: path.read_bytes() for path in (c.a.original, c.a.target, c.a.terminal,
        c.a.get_root / "full-get-proof.json", c.a.get_root / "native/run.json", c.spec.plan_receipt)}
    reference = capsule(c)
    value = legacy.validate_schedule(reference, runtime=c.a.runtime)
    assert value["artifact_type"] == schedule.CAPSULE_TYPE
    assert value["original_canonical"] == value["current_canonical"] == c.canonical
    assert len(value["control_sources"]) == 24
    assert value["traffic_hashes"] == traffic.expected(c.selected)
    spec = parallel_plan(c, reference)
    sites, payload = rolling.verify_capture_plan(spec)
    assert len(sites) == 1 and payload["planned_trace_count"] == 320
    assert len(payload["lanes"]) == 80
    selected = [row for row in payload["lanes"] if row["mode"] == c.mode]
    assert len(selected) == 16 and selected[0]["visits_per_workload"] == 4
    assert all(row["workload_ids"] == [sites[0].workload_id] for row in selected)
    assert load(c.a.target)["resources"] == c.a.manifest["resources"]
    lane = lanes._lane({"plan_payload": payload}, selected[0]["campaign_name"])
    assert rolling.require_mode_readiness(spec, lane) == c.canary
    roots = legacy.mount_roots(reference)
    assert c.a.get_root in roots
    assert c.original_policy_root in roots and c.spec.runtime_source_root in roots
    policy = rolling.verify_policy(c.a.study)
    for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        assert any(Path(policy["runtime"][name]).is_relative_to(root) for root in roots)
    assert all(path.read_bytes() == raw for path, raw in protected.items())
    with pytest.raises(FileExistsError): capsule(c)
    with pytest.raises(ValueError, match="exact equal current"):
        legacy.validate_qualification_reuse({"sha256": "old"}, {"sha256": "current"}, reference,
            actual_image=spec.collection_image_digest)


@pytest.mark.parametrize("mutation", ["native", "client", "canonical", "control", "authority", "traffic",
    "qualifier", "qualification-source", "qualification-image", "qualification-schema",
    "qualification-implementation", "workload", "get-raw", "canary-graph"])
def test_changed_current_inputs_reject_before_capsule_or_plan(current, mutation):
    c = current
    if mutation == "native":
        value = load(rolling._open_ref(c.canonical)); value["source"]["neqo_commit"] = "e" * 40
        write(rolling._open_ref(c.canonical), value)
    elif mutation == "client": c.spec.client_binary.write_bytes(b"different client\n")
    elif mutation == "canonical": rolling._open_ref(c.canonical).write_bytes(b"{}\n")
    elif mutation == "control": (c.spec.runtime_source_root / schedule.CONTROL_FILES[0]).write_bytes(b"changed control\n")
    elif mutation == "authority": (c.spec.runtime_source_root / amendment.SOURCE_FILES["kernel_tx"]).write_bytes(b"changed authority\n")
    elif mutation == "traffic": (c.spec.runtime_source_root / next(iter(traffic.files(c.selected).values()))[0]).write_bytes(b"changed traffic\n")
    elif mutation == "qualifier": c.spec.qualification_spec.write_bytes(b"{}\n")
    elif mutation.startswith("qualification-"):
        sidecar = Path(load(c.spec.qualification_spec)["qualification_sets"][0]["sidecar_root"]) / c.a.original.name
        value = load(sidecar)
        if mutation.endswith("source"): value["qualification_source"]["lab_commit"] = "e" * 40
        elif mutation.endswith("image"): value["qualification_image_digest"] = "sha256:" + "e" * 64
        elif mutation.endswith("schema"): value["schema_version"] = 1
        else: value["implementation_receipt"]["sha256"] = "e" * 64
        write(sidecar, value)
    elif mutation == "workload": c.a.target.write_bytes(c.a.original.read_bytes())
    elif mutation == "get-raw": (c.a.get_root / "native/packets.csv").write_bytes(b"changed raw GET\n")
    else: c.facts["full_graph"]["resource_records_sha256"] = "e" * 64
    with pytest.raises((ValueError, OSError, KeyError, AssertionError)):
        capsule(c)
    assert not c.output.exists() and not (c.a.study / "parallel-plan.json").exists()


def test_all_current_input_changes_reject_in_one_closed_fixture(current):
    """Exercise every independent negative without republishing 28 fixtures."""
    c = current
    retained = {path: path.read_bytes() for path in c.a.get_root.parent.rglob("*") if path.is_file()}
    facts = copy.deepcopy(c.facts)
    for mutation in ("native", "client", "canonical", "control", "authority", "traffic", "qualifier",
                     "qualification-source", "qualification-image", "qualification-schema",
                     "qualification-implementation", "workload", "get-raw", "canary-graph"):
        test_changed_current_inputs_reject_before_capsule_or_plan(c, mutation)
        for path, raw in retained.items():
            if path.read_bytes() != raw:
                path.write_bytes(raw)
        c.facts.clear()
        c.facts.update(copy.deepcopy(facts))


@pytest.mark.parametrize("mutation", ["unknown", "credit", "contract", "past-plan", "old-runtime",
    "wrong-mode", "amendment", "traffic", "qualification", "extra-setting"])
def test_rehashed_capsule_cannot_replace_bound_scientific_contract(current, mutation):
    c = current
    reference = capsule(c)
    value = load(c.output)
    if mutation == "unknown": value["ambient_override"] = True
    elif mutation == "credit": value["scientific_credit"] = True
    elif mutation == "contract": value["contract"] = legacy.CONTRACT
    elif mutation == "past-plan":
        with pytest.raises(ValueError, match="precede"):
            legacy.validate_schedule(reference, before=value["published_at"])
        return
    elif mutation == "old-runtime": value["original_canonical"] = {"path": str(c.a.study / "old-canonical.json"), "sha256": "e" * 64}
    elif mutation == "wrong-mode": value["mode"] = "buflo" if c.mode == "front" else "front"
    elif mutation == "amendment": value["static_capture_amendment"]["sha256"] = "e" * 64
    elif mutation == "traffic": value["traffic_hashes"]["buflo_parameters_sha256"] = "e" * 64
    elif mutation == "qualification": value["qualified_inputs"]["named_manifest_sha256"] = "e" * 64
    else:
        with pytest.raises(ValueError):
            rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, c.a.study / "invalid-plan.json",
                readiness={c.mode: c.canary, "tamaraw": c.canary}, runtime_inputs=c.a.runtime,
                scheduling=reference, static_capture_amendment=c.a.output)
        return
    write(c.output, value)
    with pytest.raises(ValueError): legacy.validate_schedule(rolling._ref(c.output))


def test_all_rehashed_contract_changes_reject_in_one_closed_fixture(current):
    for mutation in ("unknown", "credit", "contract", "past-plan", "old-runtime", "wrong-mode",
                     "amendment", "traffic", "qualification", "extra-setting"):
        test_rehashed_capsule_cannot_replace_bound_scientific_contract(current, mutation)
        current.output.unlink()


def test_old_scheduling_never_selects_new_duration_traffic(current):
    c = current
    old = c.a.study / "historical-schedule.json"
    write(old, {"artifact_type": legacy.CAPSULE_TYPE})
    payload = {"study_version": 6, "static_capture_amendment": rolling._ref(c.a.output),
        "scheduling": rolling._ref(old), traffic.FIELD: budget.POLICY}
    with pytest.raises(ValueError, match="historical scheduling"):
        traffic.declared(payload)


def test_terminal_fence_and_operation_facts_watch_complete_raw_get(current):
    c = current
    files, trees = schedule.terminal_inputs(c.a.enrollment)
    assert c.a.context.root / "provenance.json" in files
    assert c.a.get_root in trees and c.a.terminal.parent in trees
    context = operations.OperationFacts()
    schedule.terminal_inputs(c.a.enrollment, _context=context)
    target = c.a.get_root / "native/run.json"
    target.chmod(target.stat().st_mode ^ 0o040)
    with pytest.raises(ValueError, match="dependency"):
        context.check()


def test_inherited_deferred_get_remains_a_raw_dependency(fixed_graph, tmp_path, monkeypatch):
    from qcsd_lab import supplied_static_admission as static
    get_root, _, parent = fixed_graph
    completed = load(get_root / "native-completed.json")
    completed["returncode"] = 1
    write(get_root / "native-completed.json", completed)
    terminal = static.record_get_deferral(parent, 1, get_root)
    child = append_context(fixed_graph, tmp_path, monkeypatch)
    enrollment = tmp_path / "closed-enrollment-seam.json"
    # A real formal enrollment also ends with an admitted site. Its public
    # validator is the boundary in this transport-only negative; the inherited
    # deferral, original context, failed process and every raw path are real.
    # The sealed context reopens this inherited terminal even when it is not
    # among the selected decisions. Its complete raw tree must remain fenced.
    payload = {"admission_root": str(child.root), "decisions": [], "parent": None}
    write(enrollment, rolling.admission._bind(rolling.ENROLLMENT_TYPE, payload))
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda *args, **kwargs: None)
    facts = operations.OperationFacts()
    files, trees = schedule.terminal_inputs(enrollment, _context=facts)
    assert get_root in trees
    assert parent.root / "provenance.json" in files and child.root / "provenance.json" in files
    assert static.verify_terminal(terminal, child)["outcome"] == "operational-deferred"
    (get_root / "new-retained-raw.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="dependency"):
        facts.check()


def test_cli_new_action_keeps_legacy_action_arguments():
    parser = cli._parser()
    flags = [part for name in ("spec", "runtime-spec", "qualification-spec", "original-canonical", "current-canonical", "output")
             for part in ("--" + name, "/fixture/" + name)] + ["--reason", "prospective fixture"]
    for action in ("scheduling", "static-scheduling"):
        assert parser.parse_args([action, *flags]).command == action


def test_full_structural_named120_reopens_on_host_without_an_image_receipt(current, monkeypatch):
    from tests.test_rapid_rolling_schedule import response_sidecar
    c = current
    q = schedule.qualification
    files = {relative: graph.digest((REPOSITORY / relative).read_bytes()) for relative in q.IMPLEMENTATION_FILES}
    implementation = {"schema_version": q.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
        "artifact_type": "qcsd-chaff-qualification-implementation", "domain": q.IMPLEMENTATION_RECEIPT_DOMAIN,
        "source": load(c.spec.source_manifest), "source_files": files,
        "installed_modules": {relative: {"path": "/engineering-installed/" + relative, "sha256": files[relative]}
                              for relative in q.IMPLEMENTATION_PYTHON_FILES},
        "installed_entrypoint": {"path": "/engineering-installed/qcsd-lab", "sha256": files["qcsd-lab"]},
        "neqo_qcsd_client": {"path": "/engineering-installed/client", "sha256": rolling._ref(c.spec.client_binary)["sha256"]}}
    implementation["sha256"] = q._implementation_aggregate(implementation)
    name = c.a.target.stem
    sidecars = Path(load(c.spec.qualification_spec)["qualification_sets"][0]["sidecar_root"])
    sidecar = response_sidecar(c.a.target, name, implementation, c.spec.collection_image_digest)
    # The generic fixture starts at Unix0. Move all three synthetic epochs
    # together beyond this prospective amendment, preserving spacing/duration
    # and reconstructing every embedded receipt and qualification digest.
    declared = datetime.fromisoformat(amendment.validate_amendment(c.a.output, enrollment=c.a.enrollment, runtime=c.a.runtime)["published_at"])
    offset = int(declared.timestamp()) * 10**9 + 10**9
    for attempt in sidecar["candidate_attempts"]:
        for epoch in attempt["connection_epochs"]:
            epoch["receipt"]["started_unix_ns"] += offset
            epoch["receipt"]["ended_unix_ns"] += offset
            epoch["receipt_object_sha256"] = q.qualification_digest(
                "qcsd-chaff-sustained-response-receipt-object-v3", [epoch["receipt"]])
        attempt["response_qualification_sha256"] = q.qualification_digest(
            "qcsd-chaff-sustained-response-qualification-v3", attempt["connection_epochs"])
    sidecar["resource"]["response_qualification_sha256"] = sidecar["candidate_attempts"][-1]["response_qualification_sha256"]
    write(sidecars / (name + ".json"), sidecar)
    monkeypatch.setattr(q, "validate_named_qualification_set_manifest", REAL_NAMED_VALIDATOR)
    def no_image(*args, **kwargs):
        raise AssertionError("HOST structural reopening must not fabricate an executed image receipt")
    monkeypatch.setattr(q, "implementation_receipt", no_image)
    named = q.build_named_qualification_set_manifest([name], qualification_set="amended",
        qualification_scope="response-only", workload_root=c.spec.workload_root, sidecar_root=sidecars,
        qualification_sidecar_schema_version=q.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        require_current_implementation=False)
    write(sidecars / "_qualification-set.json", named)
    inputs = schedule._qualified_inputs(c.spec, c.spec.qualification_spec,
        [{"workload_id": name, "workload_sha256": rolling._ref(c.a.target)["sha256"]}])
    assert inputs["implementation_sha256"] == {name: implementation["sha256"]}
    assert inputs["workloads"][name]["application_evidence"] is None
    assert inputs["workloads"][name]["original_get_proof"] == load(c.a.original)["preparation"]["static_get_evidence"]["proof"]
    # Exercise the installed dispatcher structurally with a genuinely valid
    # equal implementation; its executed-image receipt is still forbidden.
    canonical_path = rolling._open_ref(c.canonical)
    canonical = load(canonical_path)
    inventory = canonical_path.parent / "source-inventory.json"
    write(inventory, {path: {"sha256": digest} for path, digest in files.items()})
    canonical["source_inventory_sha256"] = rolling._ref(inventory)["sha256"]
    canonical["checks"]["collection"]["qualification_implementation_sha256"] = implementation["sha256"]
    write(canonical_path, canonical)
    c.canonical = rolling._ref(canonical_path)
    # A plan binds its named qualification manifest. Close a new serial plan
    # after the real structural qualification rather than mutate the old one.
    serial = c.a.study / "real-qualified-serial-plan.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, serial,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime,
        static_capture_amendment=c.a.output)
    c.spec = rolling.capture_spec(c.a.study, c.a.enrollment, c.spec.qualification_spec, serial)
    reference = capsule(c)
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, reference["path"])
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", c.spec.collection_image_digest)
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    epochs.validate_qualification_reuse(implementation, implementation)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "e" * 64)
    with pytest.raises(ValueError, match="exact equal current"):
        epochs.validate_qualification_reuse(implementation, implementation)


def test_ambient_historical_bridge_cannot_enter_current_static_hook(current, monkeypatch):
    c = current
    reference = capsule(c)
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, reference["path"])
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", c.spec.collection_image_digest)
    monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", "/engineering-historical/installation.json")
    with pytest.raises(ValueError, match="historical installation"):
        epochs.validate_qualification_reuse({}, {})
