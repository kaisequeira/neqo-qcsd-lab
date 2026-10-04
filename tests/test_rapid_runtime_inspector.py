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
    result = inspector.source_changes(old, current, client_sha256=client)
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
        inspector.source_changes(old, changed, client_sha256=client)


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
    comparison = inspector.source_changes(old_sources, new_sources, client_sha256=client)
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
