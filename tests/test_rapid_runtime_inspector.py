"""Explicit control inspector seams, with real immutable schema1 runtime refs.

No physical operation or source/runtime receipt is changed by these cases.
Synthetic mutations are confined to dictionaries and temporary HOST fixtures.
"""
from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from qcsd_lab import rapid_runtime_inspector as inspector
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_rolling_readiness as evidence
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import chaff_qualification as qualification
from tools import rapid_rolling_capture as cli
from tests.test_supplied_static_get import actual_contract_fixture, write
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_capture_amendment import original, publish, qualifier_and_canary
from tests.test_rapid_lane_evidence import setup
from tests.test_rapid_rolling_capture import rolling_setup, _planned
from tests.test_rapid_operation_facts import scheduled

_OPERATION_READINESS_MOUNTS = evidence.readiness_mount_roots

WORKSPACE = Path(__file__).resolve().parents[3]
ACTUAL = WORKSPACE / "diagnostic-rehearsals/rapid-v6-static-parallel-nativec24-runtime-20261005-001"
ACTUAL_SHA = "a5f0b3b4408a9e7a8aaf4baa4474e2caf3ff9f75fe6db21307053623f4801361"
ORIGINAL_SHA = "895ddc3ea26b385c08e9dd145f57607eccace5d9603c6c2a8e502b050f0087ec"


def load(path):
    return evidence._json(evidence._read(path))


@pytest.fixture(scope="module")
def actual():
    canonical_path = ACTUAL / "canonical-runtime.json"
    if not canonical_path.is_file():
        pytest.skip("immutable actual c24 runtime refs are outside this portable checkout")
    reference = {"path": str(canonical_path), "sha256": ACTUAL_SHA}
    value = evidence._json(evidence._reference(reference)[1])
    original_path = evidence._reference(value["original_canonical"])[0]
    assert value["original_canonical"]["sha256"] == ORIGINAL_SHA
    original = load(original_path)
    inventory = load(ACTUAL / "source-inventory.json")
    original_inventory = load(original_path.parent / "source-inventory.json")
    native = {key: row for key, row in inventory.items() if key.startswith("neqo-qcsd/")}
    original_native = {key: row for key, row in original_inventory.items() if key.startswith("neqo-qcsd/")}
    proof = evidence._json(evidence._reference(value["client_reuse_proof"])[1])
    root = ACTUAL / "image-context/source"
    runtime = {"runtime_source_root": str(root), "module_root": str(root),
        "base_launcher": str(root / "qcsd-lab"), "host_launcher": str(root / "qcsd-lab"),
        "source_manifest": value["source_manifest"], "client_binary": value["client_binary"],
        "collection_image_digest": value["collection_image_digest"]}
    return reference, value, original_path, original, native, original_native, proof, runtime


def facts(actual, proof=None, **changes):
    _, current, path, original, native, old_native, raw, _ = actual
    args = dict(reuse=deepcopy(raw) if proof is None else proof, canonical=current,
        original=original, original_path=path, current_native=native, original_native=old_native)
    args.update(changes)
    return inspector.schema1_reuse_facts(**args)


def test_actual_schema1_derived_facts_without_inventing_receipt_fields(actual):
    proof = actual[6]
    assert not {"original_client_executable", "native_source_file_count", "copied_at"} & proof.keys()
    assert facts(actual) == {"original_client_executable": True, "native_source_file_count": 1783,
                             "copy_chronology": "actual-bound-copy-operation"}
    assert not {"original_client_executable", "native_source_file_count", "copied_at"} & proof.keys()


def test_actual_all12_and_original12_reopen_under_explicit_inspector(actual):
    reference, current, _, _, native, _, _, runtime = actual
    value, sources = schedule.reopen_runtime(reference, runtime, _inspector=True)
    assert value == current and len(value["actual_operation_completions"]) == 12
    assert len([name for name in sources if name.startswith("neqo-qcsd/")]) == len(native) == 1783


def test_historical_default_interpretation_is_not_silently_replaced(actual):
    with pytest.raises(ValueError, match="exact-client reuse"):
        schedule.reopen_runtime(actual[0], actual[7])
    with pytest.raises(ValueError, match="explicitly typed"):
        schedule.reopen_runtime(actual[0], actual[7], _inspector="yes")


@pytest.mark.parametrize("field,value", [
    ("original_client_executable", False), ("original_client_executable", 1),
    ("native_source_file_count", True), ("native_source_file_count", 1782),
    ("copied_at", "not-a-time"), ("schema_version", True),
    ("native_compilation_executed", True), ("formal_accepted_trace_count", False),
    ("producer_recipe", {"path": "/another-producer", "sha256": "0" * 64}),
    ("original_release_completion", {"path": "/another-completion", "sha256": "0" * 64}),
])
def test_schema1_present_malformed_or_substituted_facts_reject(actual, field, value):
    proof = deepcopy(actual[6])
    proof[field] = value
    with pytest.raises((ValueError, TypeError)):
        facts(actual, proof)


def test_schema1_reuse_of_reuse_and_changed_native_inventory_reject(actual):
    prior = deepcopy(actual[3])
    prior["native_artifact_action"] = "verified-exact-existing-client-reuse"
    with pytest.raises(ValueError, match="original Native authority"):
        facts(actual, original=prior)
    native = deepcopy(actual[4])
    native.pop(next(iter(native)))
    with pytest.raises(ValueError, match="original Native authority"):
        facts(actual, current_native=native)


def test_original_runtime_closure_cannot_follow_its_actual_copy_start(actual):
    prior = deepcopy(actual[3])
    prior["verified_at"] = "2100-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="close before"):
        facts(actual, original=prior)


@pytest.fixture(scope="module")
def projected_sources(actual):
    root = ACTUAL / "image-context/source"
    old = {name: evidence._read(root / name) for name in load(ACTUAL / "source-inventory.json")}
    current = dict(old)
    author = Path(__file__).resolve().parents[1]
    for name in (inspector.MODULE_FILE, *inspector.CONTROL_DEFINITIONS):
        if (author / name).is_file():
            current[name] = evidence._read(author / name)
    return old, current, actual[1]["installed_client_sha256"]


def test_actual_full_source_projection_allows_only_named_inspector_units(projected_sources):
    old, current, client = projected_sources
    result = inspector.source_changes(old, current, client_sha256=client, _dependency_closure=True)
    assert inspector.MODULE_FILE in result["changed_sources"]
    assert len(result["native_source_hashes"]) == 1783
    assert len(result["acquisition_source_groups"]) == 8
    assert set(qualification.IMPLEMENTATION_FILES) - {"qcsd-lab"} <= set(result["protected_sources"])


@pytest.mark.parametrize("path", ["src/qcsd_lab/fidelity.py", "src/qcsd_lab/chaff_qualification.py",
    "src/qcsd_lab/supplied_static_get.py", "neqo-qcsd/neqo-csdef/profiles/research-1200.toml"])
def test_projected_current_source_cannot_change_measurement_qualification_get_or_native(projected_sources, path):
    old, current, client = projected_sources
    changed = dict(current)
    changed[path] += b"\n# prospectively altered protected Source\n"
    with pytest.raises(ValueError, match="protected Source"):
        inspector.source_changes(old, changed, client_sha256=client, _dependency_closure=True)


def test_input_closure_projection_is_prospective_and_names_only_two_extra_methods(projected_sources):
    old, current, client = projected_sources
    with pytest.raises(ValueError, match="outside named control"):
        inspector.source_changes(old, current, client_sha256=client)
    result = inspector.source_changes(old, current, client_sha256=client, _dependency_closure=True)
    path = "src/qcsd_lab/rapid_operation_facts.py"
    assert result["contract"] == inspector.DEPENDENCY_CONTRACT
    assert result["changed_sources"][path]["units"] == ["OperationFacts._workload_evidence_trees", "OperationFacts.bind_canary", "OperationFacts.bind_schedule"]
    assert inspector.DEPENDENCY_CONTROL_DEFINITIONS[path] - inspector.CONTROL_DEFINITIONS[path] == {
        "OperationFacts._workload_evidence_trees", "OperationFacts.bind_canary"}
    changed = dict(current)
    changed[path] = current[path].replace(b"self._facts.clear()", b"self._facts.clear(); self._trees.clear()", 1)
    with pytest.raises(ValueError, match="outside named control"):
        inspector.source_changes(old, changed, client_sha256=client, _dependency_closure=True)
    with pytest.raises(ValueError, match="explicitly typed"):
        inspector.source_changes(old, current, client_sha256=client, _dependency_closure=1)


def test_original_nonexecutable_cannot_supply_derived_executable_fact(actual, tmp_path):
    proof, prior = deepcopy(actual[6]), deepcopy(actual[3])
    target = tmp_path / "client"
    target.write_bytes(evidence._reference(proof["original_installed_client"])[1])
    target.chmod(0o644)
    proof["original_installed_client"] = rolling._ref(target)
    prior["client_binary"] = str(target)
    with pytest.raises(ValueError, match="executable"):
        facts(actual, proof, original=prior)


def test_named_python_projection_rejects_changed_import_or_constant():
    path = "src/qcsd_lab/rapid_rolling_capture.py"
    before = b"import os\nSETTING = 4\ndef publish_plan():\n    return 1\ndef physics():\n    return 5\n"
    permitted = before.replace(b"return 1", b"return 2")
    assert inspector._python_projection(path, before)[0] == inspector._python_projection(path, permitted)[0]
    for changed in (permitted.replace(b"SETTING = 4", b"SETTING = 5"),
                    permitted.replace(b"import os", b"import subprocess"),
                    permitted.replace(b"return 5", b"return 6")):
        assert inspector._python_projection(path, before)[0] != inspector._python_projection(path, changed)[0]


def test_exact_shell_routing_projection_does_not_hide_other_shell_changes():
    before = b"start\n" + inspector.ROUTING_OLD + b"validate_same_authority\n"
    after = b"start\n" + inspector.ROUTING_NEW + b"validate_same_authority\n"
    assert inspector._routing_projection(before) == inspector._routing_projection(after)
    assert inspector._routing_projection(before) != inspector._routing_projection(after.replace(b"validate_same", b"skip_same"))
    with pytest.raises(ValueError):
        inspector._routing_projection(after.replace(b"current-static", b"any-static"))


def test_inspector_schema2_requires_exact_type_and_contract():
    value = {"schema_version": 2, "contract": inspector.CONTRACT,
             "artifact_type": "qcsd-rapid-v6-current-static-parallel-scheduling"}
    assert inspector.is_inspected(value)
    for change in ({"schema_version": True}, {"schema_version": 1}, {"contract": "legacy"}):
        assert not inspector.is_inspected({**value, **change})
    assert inspector.is_inspected({**value, "schema_version": 3, "contract": inspector.DEPENDENCY_CONTRACT})
    assert not inspector.is_inspected({**value, "schema_version": 3})
    assert not inspector.is_inspected({**value, "contract": inspector.DEPENDENCY_CONTRACT})


def test_public_inspector_command_has_explicit_both_actual_runtime_roles():
    args = cli._parser().parse_args(["static-inspector-scheduling", "--spec", "/spec", "--runtime-spec", "/runtime",
        "--qualification-spec", "/qual", "--original-canonical", "/measure", "--current-canonical", "/control",
        "--output", "/prospective", "--reason", "unchanged actual physics",
        "--copy-started", "/copy-started", "--copy-completed", "/copy-completed",
        "--copy-stdout", "/copy-out", "--copy-stderr", "/copy-err"])
    assert args.command == "static-inspector-scheduling" and args.original_canonical == Path("/measure")


@pytest.fixture
def control_case_setup(monkeypatch):
    from tests import test_supplied_static_capture_amendment as fixture
    from tests import test_supplied_static_preparation as preparation_fixture
    original_runtime = fixture.runtime
    monkeypatch.setattr(preparation_fixture, "REPOSITORY", ACTUAL / "image-context/source")
    def runtime(tmp_path):
        study, value = original_runtime(tmp_path)
        value["data_root"] = str(tmp_path)
        value["module_root"] = str(ACTUAL / "image-context/source")
        raw = (ACTUAL / "image-context/source/qcsd-lab").read_bytes()
        Path(value["base_launcher"]).write_bytes(raw)
        Path(value["host_launcher"]).write_bytes(raw)
        return study, value
    monkeypatch.setattr(fixture, "runtime", runtime)


@pytest.fixture
def control_case(control_case_setup, original, projected_sources, monkeypatch):
    """Real graph/GET/amendment/enrollment/plans, synthetic closed-image boundary.

    This deliberately claims no installed control runtime. The full actual
    runtime parser is separately exercised on a5f0/895d above; Native network,
    named120 and canary primitives here are the existing synthetic fixtures.
    """
    a = original
    publish(a, buflo=False)
    qualifier, sidecars, canary, facts = qualifier_and_canary(a)
    for phase in ("capture", "deep"):
        target = a.study / (phase + "-closed-fixture.json")
        write(target, {"completed_at": "2026-10-04T00:01:30Z"})
        canary.setdefault(phase, {})["completed"] = rolling._ref(target)
    output = a.study / "measurement-serial-plan.json"
    rolling.publish_plan(a.study, a.enrollment, qualifier, output, readiness={"front": canary},
        runtime_inputs=a.runtime, static_capture_amendment=a.output)
    base = rolling.capture_spec(a.study, a.enrollment, qualifier, output)
    old_sources, projected, _ = projected_sources
    new_sources = dict(projected)
    new_sources["qcsd-lab"] = old_sources["qcsd-lab"].replace(inspector.ROUTING_OLD, inspector.ROUTING_NEW)
    assert new_sources["qcsd-lab"] != old_sources["qcsd-lab"]
    inventory = lambda sources: {name: {"sha256": evidence._sha(raw), "executable": False}
                                 for name, raw in sources.items()}
    old_source = load(base.source_manifest)
    new_source = {**old_source, "lab_commit": "e" * 40}
    current_root = a.study / "control-source"
    current_root.mkdir()
    write(current_root / "source.json", new_source)
    (current_root / "client").write_bytes(base.client_binary.read_bytes())
    (current_root / "qcsd-lab").write_bytes(new_sources["qcsd-lab"])
    execution = a.study / "control-execution"
    shutil.copytree(base.execution_root, execution)
    (execution / "qcsd-lab").write_bytes(new_sources["qcsd-lab"])
    copied_campaigns = execution / base.campaign_dir.relative_to(base.execution_root)
    copied_workloads = execution / base.workload_root.relative_to(base.execution_root)
    copied_qualifier = a.study / "control-qualification-spec.json"
    current = {**a.runtime, "runtime_source_root": str(current_root), "module_root": str(current_root),
        "source_manifest": str(current_root / "source.json"), "client_binary": str(current_root / "client"),
        "base_launcher": str(current_root / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "execution_root": str(execution), "campaign_dir": str(copied_campaigns),
        "workload_root": str(copied_workloads), "collection_image_digest": "sha256:" + "b" * 64,
        "execution_generation": "control-test-002"}
    from qcsd_lab import rapid_capture_traffic as traffic
    from qcsd_lab import rapid_static_parallel_schedule as static
    from qcsd_lab import supplied_static_capture_amendment as amendment
    for relative in {inspector.MODULE_FILE, *inspector.CONTROL_DEFINITIONS,
                     *static.CONTROL_FILES, *amendment.SOURCE_FILES.values()}:
        target = current_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(new_sources[relative])
    for relative, _ in traffic.files(None).values():
        target = current_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(new_sources[relative])
    refs, canonicals = [], []
    for name, source, sources, impl_sha, image in (("measurement", old_source, old_sources, "9" * 64, base.collection_image_digest),
                                                 ("control", new_source, new_sources, "8" * 64, current["collection_image_digest"])):
        root = a.study / (name + "-canonical")
        root.mkdir()
        write(root / "source-inventory.json", inventory(sources))
        write(root / "build-inputs.json", {key: "same" for key in ("collection_base_image", "prepare_base_image",
            "toolchain_image", "cargo_lock_sha256", "rust_archive_sha256", "recipe_files")})
        value = {"source": source, "collection_image_digest": image,
            "installed_client_sha256": rolling._ref(base.client_binary)["sha256"],
            "checks": {"collection": {"qualification_implementation_sha256": impl_sha}},
            "source_inventory_sha256": rolling._ref(root / "source-inventory.json")["sha256"],
            "verified_at": "2000-01-01T00:00:02Z"}
        write(root / "canonical-runtime.json", value)
        refs.append(rolling._ref(root / "canonical-runtime.json")); canonicals.append(value)
    def reopen(reference, runtime, *, _inspector=False):
        assert _inspector is True
        if reference == refs[0]:
            assert runtime == a.runtime
            return canonicals[0], old_sources
        assert reference == refs[1] and runtime == current
        return canonicals[1], new_sources
    monkeypatch.setattr(schedule, "reopen_runtime", reopen)
    monkeypatch.setattr(qualification, "validate_named_qualification_set_manifest", lambda *args, **kwargs: None)
    sidecar = sidecars / (a.original.stem + ".json")
    value = load(sidecar)
    value["schema_version"] = qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
    value["implementation_receipt"]["sha256"] = "9" * 64
    value["candidate_attempts"][0]["connection_epochs"][0]["receipt"]["ended_unix_ns"] = 1791072070000000001
    write(sidecar, value)
    # Freeze the entire original named120 tree after the synthetic sidecar is
    # prepared; only the transport envelope paths change in the new execution.
    copied_set = execution / sidecars.relative_to(base.execution_root)
    shutil.rmtree(copied_set)
    shutil.copytree(sidecars, copied_set)
    copied_q = load(base.qualification_spec)
    copied_q["qualification_sets"][0]["sidecar_root"] = str(copied_set)
    copied_q["qualification_sets"][0]["manifest"] = str(copied_set / "_qualification-set.json")
    write(copied_qualifier, copied_q)
    from datetime import UTC, datetime
    copy_stem = a.study / "copy-inputs-fixture"
    copy_started = copy_stem.with_name(copy_stem.name + "-started.json")
    copy_completed = copy_stem.with_name(copy_stem.name + "-completed.json")
    copy_out = copy_stem.with_name(copy_stem.name + ".stdout.log")
    copy_err = copy_stem.with_name(copy_stem.name + ".stderr.log")
    copy_out.write_bytes(b"synthetic HOST copy recorder fixture; no actual runtime claim\n")
    copy_err.write_bytes(b"")
    write(copy_started, {"started_at": datetime.now(UTC).isoformat(), "command": ["synthetic-host-copy-fixture"]})
    write(copy_completed, {"completed_at": datetime.now(UTC).isoformat(), "returncode": 0, "elapsed_seconds": 0,
        "stdout_sha256": rolling._ref(copy_out)["sha256"], "stderr_sha256": rolling._ref(copy_err)["sha256"]})
    execution_copy = {key: rolling._ref(path) for key, path in (("started", copy_started),
        ("completed", copy_completed), ("stdout", copy_out), ("stderr", copy_err))}
    monkeypatch.setattr(rolling.admission, "_now", lambda: __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat())
    return a, base, current, refs, canary, facts, sidecar, canonicals, (old_sources, new_sources), copied_qualifier, execution_copy


def test_public_inspector_plan_readiness_roots_keep_old_producers_and_64_slots(control_case):
    a, base, current, refs, canary, facts, _, _, _, copied_qualifier, execution_copy = control_case
    from qcsd_lab import rapid_lane_evidence as lanes
    original_bytes = {path: path.read_bytes() for path in (a.original, a.target, a.terminal,
        a.enrollment, base.plan_receipt, a.output, a.get_root / "full-get-proof.json")}
    original_bytes[base.host_launcher] = base.host_launcher.read_bytes()
    ref = inspector.publish_schedule(base, current, copied_qualifier, refs[0], refs[1],
        a.study / "inspector.json", execution_copy=execution_copy,
        reason="synthetic HOST control role; no installed or physical credit")
    output = a.study / "inspected-parallel-plan.json"
    rolling.publish_plan(a.study, a.enrollment, copied_qualifier, output, readiness={"front": canary},
        runtime_inputs=current, scheduling=ref, static_capture_amendment=a.output)
    spec = rolling.capture_spec(a.study, a.enrollment, copied_qualifier, output)
    sites, payload = rolling.verify_capture_plan(spec)
    assert payload["runtime"] == current and payload["readiness"]["front"] == canary
    assert payload["static_capture_amendment"] == rolling._ref(a.output)
    assert spec.execution_root != base.execution_root
    assert spec.host_launcher.read_bytes() != base.host_launcher.read_bytes()
    assert spec.host_launcher.read_bytes() == spec.base_launcher.read_bytes()
    for mode in rolling.plan.MODES:
        assert sum(row["visits_per_workload"] * len(row["workload_ids"]) for row in payload["lanes"] if row["mode"] == mode) == 64
    lane = lanes._lane({"plan_payload": payload}, next(row["campaign_name"] for row in payload["lanes"] if row["mode"] == "front"))
    assert rolling.require_mode_readiness(spec, lane) == canary
    roots = rolling.readiness_roots(spec, lane.campaign_name)
    assert base.runtime_source_root in roots and Path(current["runtime_source_root"]) in roots and a.get_root in roots
    assert all(path.read_bytes() == raw for path, raw in original_bytes.items())
    assert facts["authority_source"]["lab_commit"] != load(spec.source_manifest)["lab_commit"]
    assert sites[0].workload_sha256 == rolling._ref(a.target)["sha256"]


def test_fresh_execution_copy_rejects_graph_campaign_named120_mode_or_envelope_mutations(control_case):
    a, base, current, _, _, _, _, _, _, qualifier, _ = control_case
    plan = rolling.lanes._payload(base.plan_receipt, rolling.lanes.PLAN_TYPE)
    expected = inspector._execution_inputs(base, current, qualifier, plan)
    workload = Path(current["workload_root"]) / a.target.name
    campaign = Path(current["campaign_dir"]) / (plan["lanes"][-1]["campaign_name"] + ".yml")
    row = load(qualifier)["qualification_sets"][0]
    named = Path(row["sidecar_root"])
    sidecar = named / (a.original.stem + ".json")
    # All mutations stay in temporary copies. The final registered campaign,
    # complete named-set inventory and ordinary Unix modes are checked too.
    for target, change in ((workload, "bytes"), (workload, "mode"),
                           (campaign, "bytes"), (campaign, "missing"),
                           (sidecar, "bytes"), (sidecar, "mode"),
                           (named / "_qualification-set.json", "missing"),
                           (Path(current["host_launcher"]), "old-launcher")):
        raw, mode = target.read_bytes(), target.stat().st_mode & 0o7777
        try:
            if change == "missing": target.unlink()
            elif change == "mode": target.chmod(mode ^ 0o020)
            elif change == "old-launcher": target.write_bytes(base.host_launcher.read_bytes())
            else: target.write_bytes(raw + b"\nmutated copy\n")
            with pytest.raises((ValueError, OSError)):
                inspector._execution_inputs(base, current, qualifier, plan)
        finally:
            target.write_bytes(raw); target.chmod(mode)
    for parent in (Path(current["workload_root"]), named):
        extra = parent / "unregistered-extra.json"
        extra.write_bytes(b"{}\n")
        try:
            with pytest.raises(ValueError):
                inspector._execution_inputs(base, current, qualifier, plan)
        finally:
            extra.unlink()
    original_q = qualifier.read_bytes()
    for kind in ("set", "manifest-path", "extra-field"):
        value = load(qualifier)
        if kind == "set": value["qualification_sets"][0]["qualification_set"] = "different"
        elif kind == "manifest-path": value["qualification_sets"][0]["manifest"] = load(base.qualification_spec)["qualification_sets"][0]["manifest"]
        else: value["qualification_sets"][0]["extra"] = True
        try:
            write(qualifier, value)
            with pytest.raises(ValueError):
                inspector._execution_inputs(base, current, qualifier, plan)
        finally:
            qualifier.write_bytes(original_q)
    with pytest.raises(ValueError, match="distinct execution"):
        inspector._execution_inputs(base, {**current, "execution_root": str(base.execution_root)}, qualifier, plan)
    assert inspector._execution_inputs(base, current, qualifier, plan) == expected


def test_copy_actual_records_and_all_producer_chronology_reject_false_success(control_case):
    _, base, _, _, canary, _, sidecar, canonicals, _, _, proof = control_case
    plan = rolling.lanes._payload(base.plan_receipt, rolling.lanes.PLAN_TYPE)
    assert inspector._copy_operation(proof, base, plan, tuple(canonicals))
    completion = Path(proof["completed"]["path"])
    original = completion.read_bytes()
    for key, value in (("returncode", 1), ("returncode", False), ("invocation_error", "failure"),
                       ("elapsed_seconds", True), ("stdout_sha256", "0" * 64),
                       ("completed_at", "2000-01-01T00:00:00Z")):
        current = load(completion); current[key] = value
        write(completion, current)
        changed = {**proof, "completed": rolling._ref(completion)}
        try:
            with pytest.raises(ValueError):
                inspector._copy_operation(changed, base, plan, tuple(canonicals))
        finally:
            completion.write_bytes(original)
    later = "2100-01-01T00:00:00Z"
    for index in (0, 1):
        values = deepcopy(canonicals); values[index]["verified_at"] = later
        with pytest.raises(ValueError, match="closed control runtime"):
            inspector._copy_operation(proof, base, plan, tuple(values))
    with pytest.raises(ValueError, match="original plan"):
        inspector._copy_operation(proof, base, {**plan, "declared_at": later}, tuple(canonicals))
    for phase in ("capture", "deep"):
        target = Path(canary[phase]["completed"]["path"]); raw = target.read_bytes()
        try:
            write(target, {"completed_at": later})
            altered = deepcopy(plan); altered["readiness"]["front"][phase]["completed"] = rolling._ref(target)
            with pytest.raises(ValueError, match="passed setting"):
                inspector._copy_operation(proof, base, altered, tuple(canonicals))
        finally:
            target.write_bytes(raw)
    raw = sidecar.read_bytes()
    try:
        value = load(sidecar)
        value["candidate_attempts"][0]["connection_epochs"][0]["receipt"]["ended_unix_ns"] = 9_999_999_999_999_999_999
        write(sidecar, value)
        with pytest.raises(ValueError, match="120-response"):
            inspector._copy_operation(proof, base, plan, tuple(canonicals))
    finally:
        sidecar.write_bytes(raw)
    assert inspector._copy_operation(proof, base, plan, tuple(canonicals))


@pytest.fixture
def hook_case(actual, projected_sources, tmp_path, monkeypatch):
    """Real implementation receipt/hook checks, synthetic future capsule boundary.

    The full prospective capsule is separately tested through public plans and
    mounts above. No current image receipt or installation is invented here:
    these temporary structural receipts exercise the installed hook protocol.
    """
    old_sources, current_sources, client = projected_sources
    new_sources = dict(current_sources)
    new_sources["qcsd-lab"] = old_sources["qcsd-lab"].replace(inspector.ROUTING_OLD, inspector.ROUTING_NEW)
    assert new_sources["qcsd-lab"] != old_sources["qcsd-lab"]
    comparison = inspector.source_changes(old_sources, new_sources, client_sha256=client, _dependency_closure=True)
    receipts, references = [], []
    for name, sources, source in (("measurement", old_sources, actual[1]["source"]),
        ("control", new_sources, {**actual[1]["source"], "lab_commit": "e" * 40})):
        files = {path: evidence._sha(sources[path]) for path in qualification.IMPLEMENTATION_FILES}
        receipt = {"schema_version": qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
            "artifact_type": "qcsd-chaff-qualification-implementation",
            "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN, "source": source,
            "source_files": files,
            "installed_modules": {path: {"path": "/opt/qcsd-venv/lib/python3.10/site-packages/" + path[4:],
                                         "sha256": files[path]} for path in qualification.IMPLEMENTATION_PYTHON_FILES},
            "installed_entrypoint": {"path": "/usr/local/bin/qcsd-lab-internal",
                                     "sha256": evidence._sha(sources["docker/collection-entrypoint"])},
            "neqo_qcsd_client": {"path": "/usr/local/bin/neqo-qcsd-client", "sha256": client}}
        receipt["sha256"] = qualification._implementation_aggregate(receipt)
        qualification._validate_implementation_receipt(receipt, require_current=False)
        root = tmp_path / name
        root.mkdir()
        write(root / "source-inventory.json", {path: {"sha256": evidence._sha(raw), "executable": False}
                                             for path, raw in sources.items()})
        write(root / "canonical-runtime.json", {"source": source, "installed_client_sha256": client,
            "checks": {"collection": {"qualification_implementation_sha256": receipt["sha256"]}},
            "source_inventory_sha256": rolling._ref(root / "source-inventory.json")["sha256"]})
        receipts.append(receipt); references.append(rolling._ref(root / "canonical-runtime.json"))
    target = tmp_path / "synthetic-closed-capsule-boundary.json"
    value = {"schema_version": 2, "artifact_type": "qcsd-rapid-v6-current-static-parallel-scheduling",
        "contract": inspector.CONTRACT, "runtime": {"collection_image_digest": "sha256:" + "b" * 64},
        "original_canonical": references[0], "current_canonical": references[1], "source_comparison": comparison}
    write(target, value)
    reference = rolling._ref(target)
    def closed(ref, **kwargs):
        assert ref == reference
        assert rolling._open_ref(ref) == target
        return value
    monkeypatch.setattr(inspector, "validate_schedule", closed)
    monkeypatch.setattr(qualification, "implementation_receipt", lambda **kwargs: receipts[1])
    monkeypatch.setenv("QCSD_RAPID_COLLECTION_COMPATIBILITY", str(target))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", value["runtime"]["collection_image_digest"])
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    return receipts, reference, value


def test_real_installed_hook_accepts_only_bound_old_measurement_and_current_control(hook_case):
    receipts, reference, value = hook_case
    assert receipts[0]["sha256"] != receipts[1]["sha256"]
    qualification._validate_implementation_receipt(receipts[0], require_current=True)
    assert receipts[0]["source"]["lab_commit"] != receipts[1]["source"]["lab_commit"]
    assert set(receipts[0]["source_files"]) == set(qualification.IMPLEMENTATION_FILES)


@pytest.mark.parametrize("kind", ["image", "native", "measurement", "entrypoint", "projection", "historical-bridge"])
def test_installed_hook_rejects_wrong_image_native_measurement_or_ambient_bridge(hook_case, monkeypatch, kind):
    receipts, reference, value = hook_case
    if kind == "image":
        monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "c" * 64)
    elif kind == "historical-bridge":
        monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", "/unrelated-installation")
    elif kind == "projection":
        value["source_comparison"]["changed_sources"]["qcsd-lab"]["units"] = ["any-shell-change"]
    else:
        current = receipts[1]
        if kind == "native":
            current["neqo_qcsd_client"]["sha256"] = "c" * 64
        elif kind == "entrypoint":
            current["installed_entrypoint"]["sha256"] = "c" * 64
        else:
            path = "src/qcsd_lab/fidelity.py"
            current["source_files"][path] = "c" * 64
            current["installed_modules"][path]["sha256"] = "c" * 64
        current["sha256"] = qualification._implementation_aggregate(current)
    with pytest.raises(ValueError):
        qualification._validate_implementation_receipt(receipts[0], require_current=True)


def test_composed_original_static_helper_uses_authenticated_parser_and_binds_module(tmp_path, monkeypatch):
    """Execute the exact two-line successor delta without editing its held base."""
    import importlib.util
    from types import SimpleNamespace
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import supplied_static_preparation as preparation
    root = WORKSPACE / "diagnostic-rehearsals/static-inspector-control-host-checks-20261005-001"
    inputs = load(root / "composition-adaptation-inputs.json")
    original_raw = evidence._reference(inputs["original_source"])[1]
    adapted_path, adapted_raw = evidence._reference(inputs["adapted_source"])
    expected = original_raw.replace(
        b'    "src/qcsd_lab/rapid_original_static_parallel_schedule.py",\n',
        b'    "src/qcsd_lab/rapid_runtime_inspector.py",\n    "src/qcsd_lab/rapid_original_static_parallel_schedule.py",\n'
    ).replace(b"legacy.reopen_runtime(current, runtime)",
              b"legacy.reopen_runtime(current, runtime, _inspector=True)")
    assert adapted_raw == expected
    spec = importlib.util.spec_from_file_location("qcsd_lab._composed_original_static_test", adapted_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.CONTROL_FILES.count(inspector.MODULE_FILE) == 1
    qualifier = tmp_path / "qualification.json"
    write(qualifier, {})
    runtime = {key: "same" for key in rolling.RUNTIME_FIELDS}
    base = SimpleNamespace(qualification_spec=qualifier, serializable=lambda: runtime)
    monkeypatch.setattr(lanes, "_check_spec", lambda value: None)
    monkeypatch.setattr(rolling, "_runtime", lambda value: dict(value))
    monkeypatch.setattr(rolling, "verify_capture_plan", lambda *args, **kwargs: (
        [SimpleNamespace(workload_id="site")], {"data_role": preparation.ROLE,
        "study_version": 6, "cohort_generation": "rolling-50", "readiness": {"undefended": {}},
        "lanes": [{"visits_per_workload": 4, "workload_ids": ["site"]}]}))
    calls = []
    class ParserReached(Exception):
        pass
    def parser(reference, actual_runtime, *, _inspector=False):
        calls.append((reference, actual_runtime, _inspector))
        raise ParserReached
    monkeypatch.setattr(schedule, "reopen_runtime", parser)
    reference = {"path": "/synthetic-current", "sha256": "0" * 64}
    with pytest.raises(ParserReached):
        module._derive(base, runtime, qualifier, reference, reference)
    assert calls == [(reference, runtime, True)]


@pytest.fixture
def operation_context_case(rolling_setup, scheduled, monkeypatch):
    """Real plan/mount/raw-dependency code with offline scientific primitives.

    Admission, named-response qualification and canary success use the existing
    tiny HOST fixtures. No installed image, physical trace or throughput pass
    is asserted by this context propagation test.
    """
    from types import SimpleNamespace
    from collections import Counter
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import rapid_operation_facts as operations
    spec, _ = _planned(rolling_setup)
    canary = {**scheduled.canary, "schema_version": 1}
    lineage = Path(canary["plan"]["path"]).parent / "lineage"
    lineage.mkdir()
    write(lineage / "original-manifest.json", {"resources": ["whole offline graph"]})
    canary_plan_path = Path(canary["plan"]["path"])
    canary_plan = load(canary_plan_path)
    canary_plan["original_workload_sha256"] = rolling._ref(lineage / "original-manifest.json")["sha256"]
    write(canary_plan_path, canary_plan)
    canary["plan"] = rolling._ref(canary_plan_path)
    payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
    payload["readiness"] = {"undefended": canary}
    spec.plan_receipt.write_bytes(lanes._json(lanes.admission._bind(lanes.PLAN_TYPE, payload)))
    lane = next(row for row in payload["lanes"] if row["mode"] == "undefended")
    lane = lanes._lane({"plan_payload": payload}, lane["campaign_name"])
    counts = Counter()
    verify_enrollment = rolling._verify_enrollment
    named = rolling.validate_named_qualification_set_manifest
    verified_canary = evidence.validate_canary
    observed_contexts = []
    def enrolled(*args, **kwargs):
        counts["enrollment"] += 1
        return verify_enrollment(*args, **kwargs)
    def qualified(*args, **kwargs):
        counts["qualification"] += 1
        observed_contexts.append(operations.current_context())
        return named(*args, **kwargs)
    def ready(*args, **kwargs):
        counts["canary"] += 1
        return verified_canary(*args, **kwargs)
    monkeypatch.setattr(rolling, "_verify_enrollment", enrolled)
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", qualified)
    monkeypatch.setattr(evidence, "validate_canary", ready)
    monkeypatch.setattr(evidence, "readiness_mount_roots", _OPERATION_READINESS_MOUNTS)
    return SimpleNamespace(spec=spec, lane=lane, counts=counts, contexts=observed_contexts,
                           dependencies=scheduled, root=rolling_setup.base.root)


def test_operation_context_plan_and_qualification_are_once_and_hook_is_scoped(operation_context_case):
    from qcsd_lab import rapid_operation_facts as operations
    case = operation_context_case
    context = operations.OperationFacts()
    first = rolling.verify_capture_plan(case.spec, _context=context)
    assert operations.current_context() is None
    with context.scope():
        assert rolling.verify_capture_plan(case.spec) == first
        assert rolling.verify_capture_plan(case.spec, _context=context) == first
    context.check()
    assert case.counts == {"enrollment": 1, "qualification": 1}
    assert case.contexts == [context]
    # Current installed qualification is a distinct semantic check.
    rolling.verify_capture_plan(case.spec, require_current=True, _context=context)
    assert case.counts == {"enrollment": 2, "qualification": 2}
    assert case.contexts == [context, context]
    assert operations.current_context() is None


def test_operation_context_serial_canary_and_real_mount_tail_share_facts(operation_context_case):
    from qcsd_lab import rapid_operation_facts as operations
    case = operation_context_case
    context = operations.OperationFacts()
    first = rolling.readiness_roots(case.spec, case.lane.campaign_name, _context=context)
    with context.scope():
        assert rolling.require_mode_readiness(case.spec, case.lane)
        assert rolling.readiness_roots(case.spec, case.lane.campaign_name) == first
    context.check()
    assert case.counts == {"enrollment": 1, "qualification": 1, "canary": 1}
    assert case.dependencies.canary_source in first
    assert case.dependencies.canary_execution in first
    assert operations.current_context() is None


def test_operation_context_new_actions_and_outside_calls_revalidate(operation_context_case):
    from qcsd_lab import rapid_operation_facts as operations
    case = operation_context_case
    for _ in range(2):
        context = operations.OperationFacts()
        rolling.verify_capture_plan(case.spec, _context=context)
        rolling.verify_capture_plan(case.spec, _context=context)
        context.check()
    assert case.counts["enrollment"] == 2
    context.begin_action()
    rolling.verify_capture_plan(case.spec, _context=context)
    rolling.verify_capture_plan(case.spec)
    rolling.verify_capture_plan(case.spec)
    assert case.counts["enrollment"] == case.counts["qualification"] == 5


@pytest.mark.parametrize("mutation", ["body", "file-mode", "file-member", "directory-mode"])
def test_operation_context_cached_canary_rejects_raw_change_after_wait(operation_context_case, mutation):
    from qcsd_lab import rapid_operation_facts as operations
    case = operation_context_case
    context = operations.OperationFacts()
    rolling.readiness_roots(case.spec, case.lane.campaign_name, _context=context)
    source = case.dependencies.canary_source
    target = source / "src/measurement.py"
    if mutation == "body":
        target.write_bytes(target.read_bytes() + b"changed after ownership wait\n")
    elif mutation == "file-mode":
        target.chmod(target.stat().st_mode ^ 0o040)
    elif mutation == "file-member":
        (source / "unexpected-member").write_bytes(b"new member\n")
    else:
        (source / "src").chmod((source / "src").stat().st_mode ^ 0o010)
    with pytest.raises(ValueError, match="changed"):
        context.check()
    assert case.counts["canary"] == 1


def test_operation_context_nested_scope_and_exception_restore_parent(operation_context_case, monkeypatch):
    from qcsd_lab import rapid_operation_facts as operations
    parent, child = operations.OperationFacts(), operations.OperationFacts()
    case = operation_context_case
    def failed(*args, **kwargs):
        assert operations.current_context() is child
        raise ValueError("retained synthetic qualification exception")
    monkeypatch.setattr(rolling, "_verify_enrollment", failed)
    with parent.scope():
        with pytest.raises(ValueError, match="synthetic qualification exception"):
            rolling.verify_capture_plan(case.spec, _context=child)
        assert operations.current_context() is parent
    assert operations.current_context() is None


@pytest.mark.parametrize("command", ["complete-lane", "verify-lane"])
def test_operation_context_cli_owns_fresh_action_and_image_fences(operation_context_case, monkeypatch, command):
    from types import SimpleNamespace
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import rapid_operation_facts as operations
    case = operation_context_case
    spec_path = case.root / "context-spec.json"
    rolling._write_spec(spec_path, case.spec)
    target = case.root / "lanes" / case.lane.campaign_name / ("intent.json" if command == "complete-lane" else "complete.json")
    args = SimpleNamespace(command=command, spec=spec_path, evidence_root=case.root,
                           intent=target, receipt=target)
    seen = []
    def image_boundary(spec, root, target, *, complete):
        context = operations.current_context()
        assert context is not None and complete is (command == "complete-lane")
        seen.append(context)
        # These unchanged callees normally start more complete reopen chains.
        rolling.verify_capture_plan(spec)
        rolling.readiness_roots(spec, case.lane.campaign_name)
        context.check()
        return {"engineering_fixture": "no Docker or installed-image claim"}
    monkeypatch.setattr(rolling, "check_lane_in_image", image_boundary)
    parent = operations.OperationFacts()
    with parent.scope():
        for _ in range(2):
            assert cli.run(args)["engineering_fixture"]
            assert operations.current_context() is parent
    assert seen[0] is not seen[1] and parent not in seen
    assert case.counts == {"enrollment": 2, "qualification": 2, "canary": 2}
    assert operations.current_context() is None


def test_operation_context_cli_closing_fence_rejects_changed_raw_dependencies(operation_context_case, monkeypatch):
    from types import SimpleNamespace
    from qcsd_lab import rapid_operation_facts as operations
    case = operation_context_case
    spec_path = case.root / "context-spec.json"
    rolling._write_spec(spec_path, case.spec)
    target = case.root / "lanes" / case.lane.campaign_name / "complete.json"
    args = SimpleNamespace(command="verify-lane", spec=spec_path, evidence_root=case.root, receipt=target)
    def boundary(*args, **kwargs):
        assert operations.current_context() is not None
        case.dependencies.canary_recipe.write_bytes(b"changed external deep helper\n")
        return {"engineering_fixture": True}
    monkeypatch.setattr(rolling, "check_lane_in_image", boundary)
    with pytest.raises(ValueError, match="changed"):
        cli.run(args)
    assert operations.current_context() is None


@pytest.fixture
def canary_under_execution_parent(request):
    return getattr(request, "param", False)


@pytest.fixture
def plan_operation_case(control_case, tmp_path, monkeypatch, canary_under_execution_parent):
    """Real public planner/Inspector/raw closure; synthetic image and science primitives.

    The original GET, preparation, amendment, enrollment, execution-copy and
    Inspector derivation remain real. Closed-image, Native named-response and
    successful scientific canary boundaries are the existing HOST fixtures.
    """
    from collections import Counter
    from types import SimpleNamespace
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import rapid_operation_facts as operations
    a, base, current, refs, canary, facts, _, _, sources, qualifier, execution_copy = control_case
    closed = base.execution_root.parent if canary_under_execution_parent else tmp_path / "immutable-canary-input"
    closed.mkdir(exist_ok=canary_under_execution_parent)
    result = base.execution_root / "results" / "fixture-canary" / "fixture-result"
    result.mkdir(parents=True)
    write(result / "experiment.json", {"engineering_fixture": "no physical or deep success claim"})
    write(closed / "plan.json", {"static_capture_amendment": rolling._ref(a.output),
        "execution_root": str(base.execution_root), "clean_runtime_root": str(base.runtime_source_root),
        "campaigns": [], "workload_id": a.target.stem, "qualification_set": "amended"})
    write(closed / "source-inventory.json", {})
    write(closed / "deep-receipt.json", {"root": "/lab/results/fixture-canary/fixture-result"})
    canary = {"plan": rolling._ref(closed / "plan.json"),
        "deep_receipt": rolling._ref(closed / "deep-receipt.json")}
    for phase in ("capture", "deep"):
        write(closed / (phase + "-started.json"), {"started_at": "2026-10-04T00:01:20Z", "command": []})
        write(closed / (phase + "-completed.json"), {"completed_at": "2026-10-04T00:01:30Z"})
        (closed / (phase + ".stdout.log")).write_bytes(b"synthetic HOST canary primitive\n")
        (closed / (phase + ".stderr.log")).write_bytes(b"")
        canary[phase] = {key: rolling._ref(closed / (phase + suffix)) for key, suffix in
            (("started", "-started.json"), ("completed", "-completed.json"),
             ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}
    payload = lanes._payload(base.plan_receipt, lanes.PLAN_TYPE)
    payload["readiness"] = {"front": canary}
    base.plan_receipt.write_bytes(lanes._json(lanes.admission._bind(lanes.PLAN_TYPE, payload)))
    capsule = inspector.publish_schedule(base, current, qualifier, refs[0], refs[1],
        a.study / "plan-context-inspector.json", execution_copy=execution_copy,
        reason="HOST context fixture; no installed or physical authority claim")
    runtime_path = a.study / "plan-context-runtime.json"
    write(runtime_path, {"schema_version": 1, "artifact_type": rolling.RUNTIME_TYPE, "inputs": current})
    readiness_path = a.study / "plan-context-readiness.json"
    write(readiness_path, {"front": canary})
    counts, contexts = Counter(), []
    derive, named, ready = inspector._derive, qualification.validate_named_qualification_set_manifest, evidence.validate_canary
    def derived(*args, **kwargs):
        counts["derive"] += 1
        contexts.append(operations.current_context())
        return derive(*args, **kwargs)
    def qualified(*args, **kwargs):
        counts["qualification"] += 1
        return named(*args, **kwargs)
    def passed(*args, **kwargs):
        counts["canary"] += 1
        return ready(*args, **kwargs)
    monkeypatch.setattr(inspector, "_derive", derived)
    monkeypatch.setattr(qualification, "validate_named_qualification_set_manifest", qualified)
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", qualified)
    monkeypatch.setattr(evidence, "validate_canary", passed)
    def args(name):
        return cli._parser().parse_args(["plan", "--evidence-root", str(a.study),
            "--enrollment", str(a.enrollment), "--qualification-spec", str(qualifier),
            "--runtime-spec", str(runtime_path), "--readiness", str(readiness_path),
            "--scheduling", capsule["path"], "--static-capture-amendment", str(a.output),
            "--output", str(a.study / (name + "-plan.json")),
            "--spec-output", str(a.study / (name + "-spec.json"))])
    return SimpleNamespace(a=a, base=base, current=current, qualifier=qualifier,
        counts=counts, contexts=contexts, args=args, closed=closed, sources=sources)


def test_plan_operation_public_scheduled_cli_derives_and_qualifies_once_per_action(plan_operation_case):
    from qcsd_lab import rapid_operation_facts as operations
    case = plan_operation_case
    parent = operations.OperationFacts()
    with parent.scope():
        for name in ("first", "second"):
            result = cli.run(case.args(name))
            assert result["planned_traces"] == 320 and result["ready_settings"] == ["front"]
            assert operations.current_context() is parent
    assert case.counts == {"derive": 2, "qualification": 2, "canary": 2}
    assert case.contexts[0] is not case.contexts[1] and parent not in case.contexts
    assert operations.current_context() is None


@pytest.mark.parametrize("mutation", ["body", "file-mode", "file-member", "directory-mode"])
def test_plan_operation_raw_change_before_publication_rejects(plan_operation_case, monkeypatch, mutation):
    from qcsd_lab import rapid_operation_facts as operations
    case = plan_operation_case
    original = rolling._render_campaign
    changed = False
    def changed_after_validation(*args, **kwargs):
        nonlocal changed
        raw = original(*args, **kwargs)
        if not changed and case.counts["canary"] == 1:
            assert operations.current_context() is not None
            target = case.closed / "capture.stdout.log"
            if mutation == "body":
                target.write_bytes(b"changed after asynchronous ownership boundary\n")
            elif mutation == "file-mode":
                target.chmod(target.stat().st_mode ^ 0o040)
            elif mutation == "file-member":
                (case.base.execution_root / "results/fixture-canary/fixture-result/unexpected-member").write_bytes(b"not a declared dependency\n")
            else:
                result = case.base.execution_root / "results/fixture-canary/fixture-result"
                result.chmod(result.stat().st_mode ^ 0o010)
            changed = True
        return raw
    monkeypatch.setattr(rolling, "_render_campaign", changed_after_validation)
    args = case.args("changed")
    with pytest.raises(ValueError, match="changed"):
        cli.run(args)
    assert changed
    assert not args.output.exists() and not args.spec_output.exists()
    assert case.counts == {"derive": 1, "qualification": 1, "canary": 1}
    assert operations.current_context() is None


@pytest.fixture
def amended_prepare_case(plan_operation_case, monkeypatch, tmp_path):
    """Real prepare/image/lineage writers; only the Docker/image boundary is synthetic.

    The isolated actuator executes the actual image-plan validator in this HOST
    process. No real installed-image or network success is asserted. Its source,
    implementation receipt, graph, plan and raw input guards execute unchanged.
    """
    import json
    import subprocess
    from types import SimpleNamespace
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import util
    case = plan_operation_case
    args = case.args("prepare-input")
    cli.run(args)
    spec = lanes.load_capture_spec(args.spec_output)
    root = Path(case.current["runtime_source_root"])
    for relative in qualification.IMPLEMENTATION_FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(case.sources[1][relative])
    metadata = load(spec.source_manifest)
    source = {**metadata, "image_digest": spec.collection_image_digest}
    files = {relative: lanes._sha((root / relative).read_bytes())
             for relative in qualification.IMPLEMENTATION_FILES}
    implementation = {"schema_version": qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
        "artifact_type": "qcsd-chaff-qualification-implementation",
        "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN, "source": metadata, "source_files": files,
        "installed_modules": {relative: {"path": "/installed/" + relative, "sha256": files[relative]}
                              for relative in qualification.IMPLEMENTATION_PYTHON_FILES},
        "installed_entrypoint": {"path": "/installed/qcsd-lab", "sha256": files["qcsd-lab"]},
        "neqo_qcsd_client": {"path": "/installed/client", "sha256": lanes._sha(spec.client_binary.read_bytes())}}
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    qualification._validate_implementation_receipt(implementation, require_current=False)
    monkeypatch.setattr(qualification, "_qualification_execution_context", lambda: (implementation, source, spec.collection_image_digest))
    monkeypatch.setattr(qualification, "_bound_neqo_client", lambda value: (spec.client_binary, lanes._sha(spec.client_binary.read_bytes())))
    monkeypatch.setattr(util, "source_metadata", lambda: source)
    monkeypatch.setenv("QCSD_LAB_ROOT", str(root))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", spec.collection_image_digest)
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", "/usr/share/qcsd-lab/source.json")
    monkeypatch.delenv("QCSD_RAPID_COLLECTION_COMPATIBILITY", raising=False)
    lock_parent = tmp_path / "private-ownership-locks"
    lock_parent.mkdir(mode=0o700)
    monkeypatch.setattr(lanes, "CAPTURE_LOCK_PARENT", lock_parent)
    calls = []
    def image(command, **kwargs):
        assert command[:2] == ["docker", "run"] and command[command.index("--network") + 1] == "none"
        calls.append(command)
        proof = lanes.executed_image_plan_check(json.loads(command[-1]))
        return subprocess.CompletedProcess(command, 0, json.dumps(proof), "synthetic isolated image actuator\n")
    monkeypatch.setattr(lanes.subprocess, "run", image)
    payload = lanes._payload(spec.plan_receipt, lanes.PLAN_TYPE)
    campaigns = [row["campaign_name"] for row in payload["lanes"] if row["mode"] == "front"][:2]
    case.counts.clear()
    return SimpleNamespace(case=case, spec=spec, spec_path=args.spec_output, campaigns=campaigns,
        root=case.a.study, output=case.a.study / "prospective-batch-authority.json", calls=calls)


def test_prepare_outputs_beside_declaration_are_not_immutable_input_members(amended_prepare_case):
    from qcsd_lab import rapid_formal_parallel as formal
    from qcsd_lab import supplied_static_capture_amendment as amendment
    case = amended_prepare_case
    assert not case.output.exists() and not (case.root / "objects").exists()
    assert formal.prepare_batch(case.spec_path, case.root, case.campaigns, case.output) == case.output
    authority = load(case.output)
    assert len(case.calls) == 1 and len(authority["lane_intents"]) == 2
    assert list(case.root.glob("image-check-*.json")) and list((case.root / "objects").iterdir())
    assert case.root == Path(load(case.case.a.target)["preparation"][amendment.FIELD]["path"]).parent
    for row in authority["lane_intents"]:
        intent = Path(row["path"])
        assert intent.is_file() and not (intent.parent / "host-start.json").exists()
    assert not any((case.spec.execution_root / "results" / name).exists() for name in case.campaigns)


@pytest.mark.parametrize("mutation", ["body", "file-mode", "member", "directory-mode"])
def test_prepare_changed_underlying_raw_inputs_reject_before_claim(amended_prepare_case, monkeypatch, mutation):
    from qcsd_lab import rapid_formal_parallel as formal
    from qcsd_lab import rapid_lane_evidence as lanes
    case = amended_prepare_case
    original = lanes._lineage_payload
    changed = False
    def after_real_output(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            raw = case.case.a.get_root / "native.stdout.log"
            if mutation == "body": raw.write_bytes(b"changed authentic raw GET log\n")
            elif mutation == "file-mode": raw.chmod(raw.stat().st_mode ^ 0o040)
            elif mutation == "member": (raw.parent / "undeclared-raw-member").write_bytes(b"extra\n")
            else: raw.parent.chmod(raw.parent.stat().st_mode ^ 0o010)
            changed = True
        return result
    monkeypatch.setattr(lanes, "_lineage_payload", after_real_output)
    with pytest.raises(ValueError):
        formal.prepare_batch(case.spec_path, case.root, case.campaigns, case.output)
    assert changed and len(case.calls) == 1
    assert list(case.root.glob("image-check-*.json")) and list((case.root / "objects").iterdir())
    assert not case.output.exists() and not (case.root / "lanes").exists()


@pytest.fixture
def same_parent_parallel_case(amended_prepare_case, monkeypatch):
    """Actual authority and public launch writers; synthetic host/image boundaries."""
    from qcsd_lab import rapid_formal_parallel as formal
    from qcsd_lab import rapid_parallel_capture as parallel
    from qcsd_lab import rapid_operation_facts as operations
    from tools import rapid_parallel_capture as launcher
    import os
    case = amended_prepare_case
    assert case.case.closed == case.case.base.execution_root.parent
    formal.prepare_batch(case.spec_path, case.root, case.campaigns, case.output)
    assert case.case.closed in case.spec.execution_root.parents
    # The fixture's clean Git/installed image and host process boundaries are
    # explicit substitutes. Authority, dependency and pre-release checks are
    # actual production code; no process, Docker or deep success is asserted.
    monkeypatch.setattr(parallel, "host_source", lambda value: (
        value["runtime"] == {key: case.spec.serializable()[key] for key in parallel.RUNTIME_KEYS}
        or (_ for _ in ()).throw(AssertionError("another declared fixture runtime"))))
    gates, children = [], []
    original_write = os.write
    def release(descriptor, value):
        gates.append(value)
        return original_write(descriptor, value)
    monkeypatch.setattr(launcher.os, "write", release)
    monkeypatch.setattr(launcher, "_process_identity", lambda pid: {"engineering_fixture_pid": pid})
    monkeypatch.setattr(launcher.os, "killpg", lambda *args: None)
    class Child:
        pid = 424242
        def __init__(self, descriptor):
            self.reader = os.dup(descriptor)
            self.done = False
        def poll(self): return 0 if self.done else None
        def wait(self):
            if not self.done: os.close(self.reader)
            self.done = True
            return 0
    def spawn(command, **kwargs):
        assert command[2] == launcher.HOST_GATE_SCRIPT and len(kwargs["pass_fds"]) == 1
        child = Child(kwargs["pass_fds"][0])
        children.append(child)
        return child
    monkeypatch.setattr(launcher.subprocess, "Popen", spawn)
    monkeypatch.setattr(parallel, "verify_results_in_image", lambda *args: {
        "valid": True, "engineering_fixture": True, "formal_accepted_trace_count": 0, "scientific_credit": False})
    case.batch_output = case.spec.execution_root / "results" / "fresh-parallel-host-fixture"
    case.batch_output.parent.mkdir(exist_ok=True)
    case.gates, case.children, case.launcher = gates, children, launcher
    case.original_result = case.case.base.execution_root / "results/fixture-canary/fixture-result"
    return case


@pytest.mark.parametrize("canary_under_execution_parent", [True], indirect=True)
def test_real_parallel_launch_accepts_its_outputs_beneath_canary_plan_parent(same_parent_parallel_case):
    case = same_parent_parallel_case
    before = {path: (path.read_bytes(), path.stat().st_mode) for path in case.original_result.rglob("*") if path.is_file()}
    result = case.launcher.launch(case.output, case.batch_output)
    assert result["engineering_fixture"] is True and case.gates == [b"G"]
    assert (case.batch_output / "operator-intent.json").is_file()
    assert (case.batch_output / "host-start.json").is_file()
    assert (case.batch_output / "host-process.json").is_file()
    assert not (case.batch_output / "blocked.json").exists()
    assert {path: (path.read_bytes(), path.stat().st_mode) for path in before} == before
    assert not any((case.spec.execution_root / "results" / name).exists() for name in case.campaigns)


@pytest.mark.parametrize("canary_under_execution_parent", [True], indirect=True)
def test_real_initialize_accepts_image_preflight_outputs_beneath_canary_plan_parent(same_parent_parallel_case):
    from urllib.parse import urlsplit
    from qcsd_lab import rapid_formal_parallel as formal
    from qcsd_lab import rapid_parallel_capture as parallel
    from qcsd_lab import rapid_lane_evidence as lanes
    from qcsd_lab import rapid_operation_facts as operations
    from qcsd_lab.rapid_runtime_epochs import _runtime_projection
    case = same_parent_parallel_case
    authority = load(case.output)
    hosts = sorted({urlsplit(origin).hostname for origin in load(case.case.a.target)["preparation"]["approved_origins"]})
    for row, campaign in zip(authority["lane_intents"], case.campaigns, strict=True):
        # Explicit synthetic DNS actuator; actual receipt validation runs below.
        write(Path(row["path"]).parent / "dns.json", {"schema_version": 1,
            "campaign": campaign, "hosts": [[host, "1.1.1.1"] for host in hosts]})
    context = operations.OperationFacts()
    formal._audit(case.output, _context=context)
    proof = lanes.executed_image_plan_check(case.spec.serializable(), _context=context)
    runtime = _runtime_projection(proof)
    digest = parallel.sha(case.output.read_bytes())
    case.batch_output.mkdir(mode=0o700)
    parallel.put(case.batch_output / "image-preflight.json", {"authority_sha256": digest,
        "worker_plan_proofs": [proof, proof], "worker_epoch_proofs": [None, None],
        "worker_runtime_proofs": [runtime, runtime], "runtime": runtime,
        "input_files": {str(case.spec_path): parallel.sha(case.spec_path.read_bytes())},
        "engineering_fixture": True, "formal_accepted_trace_count": 0, "scientific_credit": False})
    result = formal.initialize(case.output, case.batch_output, digest, [0, 2, 4, 7, 9], _context=context)
    assert result == {"pairs": [[2, 4], [7, 9]], "sidecar_cpus": [0]}
    assert (case.batch_output / "batch-intent.json").is_file()
    assert all((case.batch_output / f"lane-{index}" / "gate").is_dir() for index in (1, 2))
    assert all((case.spec.execution_root / "results" / name).is_dir() for name in case.campaigns)
    assert case.children == [] and case.gates == []


@pytest.mark.parametrize("canary_under_execution_parent", [True], indirect=True)
@pytest.mark.parametrize("mutation", ["plan-body", "raw-mode", "result-member", "result-directory-mode"])
def test_real_parallel_launch_changed_canary_rejects_before_host_release(same_parent_parallel_case, monkeypatch, mutation):
    case = same_parent_parallel_case
    spawn = case.launcher.subprocess.Popen
    def changed_at_gate(*args, **kwargs):
        child = spawn(*args, **kwargs)
        if mutation == "plan-body":
            target = case.case.closed / "plan.json"
            target.write_bytes(target.read_bytes() + b"changed after host output creation\n")
        elif mutation == "raw-mode":
            target = case.case.closed / "capture.stdout.log"
            target.chmod(target.stat().st_mode ^ 0o040)
        elif mutation == "result-member":
            (case.original_result / "unexpected-raw-member").write_bytes(b"not declared\n")
        else:
            case.original_result.chmod(case.original_result.stat().st_mode ^ 0o010)
        return child
    monkeypatch.setattr(case.launcher.subprocess, "Popen", changed_at_gate)
    with pytest.raises(ValueError, match="changed"):
        case.launcher.launch(case.output, case.batch_output)
    assert case.gates == [] and all(child.done for child in case.children)
    assert (case.batch_output / "operator-intent.json").is_file() and (case.batch_output / "blocked.json").is_file()
    assert not (case.batch_output / "host-start.json").exists()
    assert not (case.batch_output / "host-process.json").exists()
    assert not any((case.spec.execution_root / "results" / name).exists() for name in case.campaigns)
