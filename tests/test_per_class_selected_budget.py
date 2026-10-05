"""HOST fixtures: actual retained q53 GET; audit/runtime writers are fixtures.

No audit of an original prefix, Native process, network, image or formal capture
is executed here. The selected raw verifier consumes the genuine complete GET.
"""
from copy import deepcopy
from pathlib import Path
import json
import sys

import pytest

from qcsd_lab import rapid_selected_budget_input as selected
from qcsd_lab import rapid_selected_capture_input as plain
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_per_class_selected_input as dispatch
from qcsd_lab import per_class_selected_capture_amendment as amendment
from qcsd_lab import rapid_additive_static_enrollment as old
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import buflo_duration_budget as duration

W = Path(__file__).resolve().parents[3]
CASE = W / "diagnostic-rehearsals/supplied-static87-budget64-context-20261005-001"
CORE = W / "diagnostic-worktrees/rapid-supplied-static-budget-successor-lab-authoring-20261005-002"
INVENTORY = W / "diagnostic-rehearsals/supplied-static-budget-get-source-closure-20261005-002/source-inventory.json"
SEED = W / "diagnostic-rehearsals/selected-additive-classes007-011-root-actual-20261005-001/study/batches/b0003/enrollment.json"
SCI = W / "diagnostic-rehearsals/supplied-static-tamaraw-formal-b08-root-actual-20261005-001/scientific-progress-000009.json"


def write(path, value):
    path.write_bytes(graph.canonical_bytes(value))
    return path


@pytest.fixture(scope="module")
def genuine_seed():
    return ledger._seed(SEED)


@pytest.fixture()
def actual_q53_input(tmp_path):
    # Only the creation audit subprocess boundary is represented by a HOST
    # fixture. Every underlying original manifest/wrapper/terminal/proof/raw
    # Native record remains a real retained, hash-bound q53 file.
    terminal_path = CASE / "attempts/candidate-000053/terminal.json"
    terminal = receipts._unpack(terminal_path.read_bytes(), selected.budget.TERMINAL_TYPE)
    original_path = selected.original.open_reference(terminal["prepared_workload"])
    manifest = json.loads(original_path.read_bytes())
    wrapper = manifest["preparation"][selected.budget.FIELD]
    context = receipts._unpack((CASE / "provenance.json").read_bytes(), selected.budget.CONTEXT_TYPE)
    active = receipts._unpack(selected.original.open_reference(context["prospective_context"]).read_bytes(), selected.budget.static.PROVENANCE_TYPE)
    candidate = active["candidates"][52]
    row = {"candidate": candidate, "manifest": selected.original.reference(original_path),
        "terminal": selected.original.reference(terminal_path), "context": selected.original.reference(CASE / "provenance.json"),
        "capture_limits": terminal["capture_limits"], "facts": {"candidate_id": candidate["candidate_id"], "outcome": "admitted"},
        "scientific_credit": False}
    started = {"schema_version": 1, "command": [sys.executable, "-I", "-B", "-c", selected._AUDIT_PROGRAM,
        str(CORE), str(CASE), str(terminal_path)], "started_at": "2026-10-05T00:00:01+00:00",
        "source_inventory": plain.reference(INVENTORY), "context": plain.reference(CASE / "provenance.json"),
        "terminal": plain.reference(terminal_path)}
    start = write(tmp_path / "audit-started.json", started)
    stdout = write(tmp_path / "audit.stdout.log", row)
    stderr = tmp_path / "audit.stderr.log"
    stderr.write_bytes(b"")
    completed = {"schema_version": 1, "returncode": 0, "elapsed_seconds": 1.0, "completed_at": "2026-10-05T00:00:02+00:00",
        "started": plain.reference(start), "stdout": plain.reference(stdout), "stderr": plain.reference(stderr)}
    end = write(tmp_path / "audit-completed.json", completed)
    audit = {"contract": selected.CONTRACT, "source_root": str(CORE), "source_inventory": plain.reference(INVENTORY),
        "program_sha256": graph.digest(selected._AUDIT_PROGRAM.encode()), "result": row,
        "started": plain.reference(start), "completed": plain.reference(end), "stdout": plain.reference(stdout), "stderr": plain.reference(stderr),
        "published_at": "2026-10-05T00:00:03+00:00", "scientific_credit": False}
    audit_path = write(tmp_path / "selection-audit.json", receipts._bind(selected.AUDIT_TYPE, audit))
    input_path = selected.publish_input(tmp_path / "input.json", audit=audit_path, candidate_id=candidate["candidate_id"])
    return input_path, original_path, row, tmp_path


def test_real_q53_selected_complete_raw_get_and_budget_role(actual_q53_input):
    path, original, row, directory = actual_q53_input
    value, manifest, proof = selected.validate_input(path)
    assert manifest == json.loads(original.read_bytes())
    assert proof["full_list_coverage"] is True
    assert len(manifest["resources"]) == proof["resource_count"]
    assert value["capture_limits"]["max_response_bytes"] == 64 * 1024 * 1024
    assert value["capture_limits"]["capture_megabytes"] == 256
    target = selected.prepare_input(path, directory / (value["workload_id"] + ".json"))
    prepared = json.loads(target.read_bytes())
    assert prepared["resources"] == manifest["resources"]
    assert selected.validate_preparation(prepared["preparation"], prepared["resources"]) == proof
    files, trees = selected.preparation_inputs(prepared["preparation"], prepared["resources"])
    assert Path(value["raw_root"]) in trees
    assert plain.reopen(value["budget_context"]) in files
    assert all(tree != CASE for tree in trees)
    assert value["measurement_runtime"] == value["declaration"]["runtime_binding"]


@pytest.mark.parametrize("field,value", [("original_role", plain.ROLE), ("direct_validator_sources", {}),
    ("scientific_credit", True), ("formal_accepted_trace_count", False)])
def test_budget_receipt_rehashed_role_source_or_credit_tamper_refuses(actual_q53_input, field, value):
    path, _, _, directory = actual_q53_input
    payload = receipts._unpack(path.read_bytes(), selected.RECEIPT_TYPE)
    payload[field] = value
    changed = write(directory / "changed-input.json", receipts._bind(selected.RECEIPT_TYPE, payload))
    with pytest.raises(ValueError):
        selected.validate_input(changed)


def test_approved_full_inventory_pin_refuses_rehashed_subset(tmp_path):
    inventory = json.loads(INVENTORY.read_bytes())
    inventory["current"] = {key: value for key, value in inventory["current"].items()
        if key in {"src/qcsd_lab/supplied_static_budget_successor.py", "src/qcsd_lab/supplied_static_preparation.py",
                   "src/qcsd_lab/supplied_static_get.py", "src/qcsd_lab/supplied_static_graph.py"}}
    changed = write(tmp_path / "subset.json", inventory)
    with pytest.raises(ValueError, match="independently closed"):
        selected._inventory(CORE, plain.reference(changed), full=True)


def test_approved_full_inventory_creation_reopens_exact_membership():
    value = selected._inventory(CORE, plain.reference(INVENTORY), full=True)
    assert len(value["current"]) == 2485


@pytest.mark.parametrize("creation", [False, True])
def test_image_reader_uses_inventory_without_original_author_directory(monkeypatch, creation):
    regular_directory = lanes._regular_directory

    def unavailable_original_source(path):
        if path == CORE:
            raise ValueError("original author Source is absent in this image layout")
        return regular_directory(path)

    monkeypatch.setattr(lanes, "_regular_directory", unavailable_original_source)
    if creation:
        with pytest.raises(ValueError, match="absent in this image layout"):
            selected._inventory(CORE, plain.reference(INVENTORY), full=True)
    else:
        value = selected._inventory(CORE, plain.reference(INVENTORY), full=False)
        assert value["author_root"] == str(CORE)
        assert len(value["current"]) == 2485


def test_actual_eleven_seed_and_scientific36_preserve_every_old_field(genuine_seed):
    batch, classes, policy = genuine_seed
    original_batch, originals, original_policy = old.verify_enrollment(SEED)
    assert batch == original_batch and policy == original_policy
    assert len(classes) == 11
    for row, original in zip(classes, originals):
        assert {key: row[key] for key in original} == original
        assert row["capture_limits"] == policy["capture_limits"]
    progress = json.loads(SCI.read_bytes())
    old._progress(progress, classes)
    assert progress["formal_accepted_trace_count"] == 36


def test_mixed_class_budgets_refuse_before_any_enrollment_write(genuine_seed):
    _, rows, _ = genuine_seed
    chosen = [deepcopy(rows[-2]), deepcopy(rows[-1])]
    chosen[-1]["capture_limits"] = selected.budget.static.capture_limits(selected.budget.RESPONSE_BYTES, 256)
    batch = {"selected_candidate_ids": [row["candidate_id"] for row in chosen]}
    with pytest.raises(ValueError, match="identical"):
        ledger.select_classes(batch, chosen, {"contract": ledger.CONTRACT})


@pytest.mark.parametrize("mode", list(rolling.plan.MODES))
def test_all_five_mode_caps_retain_per_class_response_recording(mode, genuine_seed):
    _, rows, _ = genuine_seed
    rows = [deepcopy(rows[-1])]
    rows[0]["capture_limits"] = selected.budget.static.capture_limits(selected.budget.RESPONSE_BYTES, 256)
    batch = {"selected_candidate_ids": [rows[0]["candidate_id"]]}
    chosen, limits = ledger.select_classes(batch, rows, {"contract": ledger.CONTRACT})
    effective = duration.capture_limits(mode, limits, policy=duration.POLICY if mode == "buflo" else None)
    assert effective["max_response_bytes"] == 64 * 1024 * 1024
    assert effective["capture_megabytes"] == 256
    assert chosen == rows


def test_budget_context_reservation_metadata_keeps_genuine_q53_order(genuine_seed):
    batch, classes, policy = genuine_seed
    prospective = {"seed_policy": batch["policy"]}
    context = ledger._context_metadata(prospective, CASE / "provenance.json")
    assert context["candidates"][52]["candidate_id"] == "static-32abc7fa824f03129a07545c58d7e60ecb36891bc4696db10043a74538944fee"
    assert len(context["candidates"]) == 87


@pytest.mark.parametrize("caps", [{}, {"max_response_bytes": 67108864},
    {**selected.budget.static.capture_limits(selected.budget.RESPONSE_BYTES, 256), "capture_megabytes": 64},
    {**selected.budget.static.capture_limits(selected.budget.RESPONSE_BYTES, 256), "timeout_seconds": True}])
def test_unknown_partial_mixed_or_boolean_class_caps_refuse(caps):
    with pytest.raises(ValueError):
        ledger.valid_limits(caps)


def test_front_and_buflo_derived_policy_preserves_genuine_q53_full_graph(actual_q53_input):
    path, _, _, directory = actual_q53_input
    value = selected.validate_input(path)[0]
    prepared = selected.prepare_input(path, directory / (value["workload_id"] + ".json"))
    manifest = json.loads(prepared.read_bytes())
    policies = [(amendment.old.policies(front_policy=amendment.old.capture.FRONT_RESERVE_POLICY), None),
                (amendment.old.policies(buflo_policy=amendment.old.capture.BUFLO_KERNEL_PREPARATION_POLICY), duration.POLICY)]
    for policy, duration_policy in policies:
        derived = amendment._derived(manifest, {"path": str(directory / "declaration.json"), "sha256": "a" * 64}, policy, duration_policy)
        assert derived["resources"] == manifest["resources"]
        assert derived["preparation"]["max_response_bytes"] == 64 * 1024 * 1024
        assert derived["preparation"]["expected_responses"] == manifest["preparation"]["expected_responses"]
        assert amendment.is_amended(derived["preparation"])
        assert dispatch.is_selected(manifest["preparation"])


def test_actual_q53_appends_class12_and_retains_eleven_slots_under_fixture_runtime(actual_q53_input, genuine_seed, monkeypatch):
    path, _, row, directory = actual_q53_input
    # New actual installed runtime publication is outside this HOST fixture.
    # All old membership/input/raw validators stay real; only _runtime's
    # installed provenance boundary is substituted for a fresh tmp namespace.
    monkeypatch.setattr(rolling, "_runtime", lambda value: dict(value))
    old_batch, seed_classes, old_policy = genuine_seed
    root = directory / "study"
    root.mkdir()
    runtime = {**old_policy["runtime"], "data_root": str(directory)}
    ledger.initialize(root, seed_enrollment=SEED, seed_progress=plain.reference(SCI), runtime=runtime)
    value = selected.validate_input(path)[0]
    manifest_path = selected.prepare_input(path, directory / (value["workload_id"] + ".json"))
    enrollment = ledger.enroll(root, acquisition_root=CASE,
        inputs={value["candidate_id"]: plain.reference(path)},
        prepared_workloads={value["candidate_id"]: plain.reference(manifest_path)})
    batch, classes, policy = ledger.verify_enrollment(enrollment)
    assert len(classes) == 12 and classes[:11] == seed_classes
    assert batch["seed"] == rolling._ref(SEED)
    assert batch["ordinal"] == old_batch["ordinal"] + 1
    assert classes[-1]["class_index"] == 12 and classes[-1]["candidate_id"] == row["candidate"]["candidate_id"]
    assert rolling._effective_capture_limits(batch, classes, policy)["max_response_bytes"] == 64 * 1024 * 1024
    assert rolling._verify_enrollment(enrollment) == (batch, classes, policy)
    metadata = ledger.membership_inputs(enrollment)
    assert SEED in metadata and SCI in metadata
    assert CASE / "provenance.json" in metadata
    assert all("get-candidate-000001" not in str(item) for item in metadata)
    old._progress(json.loads(SCI.read_bytes()), classes)


def test_prospective_manifest_graph_tamper_refuses_before_enrollment(actual_q53_input, genuine_seed):
    path, _, _, directory = actual_q53_input
    batch, _, _ = genuine_seed
    value = selected.validate_input(path)[0]
    manifest_path = selected.prepare_input(path, directory / (value["workload_id"] + ".json"))
    manifest = json.loads(manifest_path.read_bytes())
    manifest["resources"] = manifest["resources"][:-1]
    altered = write(directory / "altered.json", manifest)
    with pytest.raises(ValueError, match="full graph"):
        ledger._chosen({"seed_policy": batch["policy"]}, rolling._ref(CASE / "provenance.json"), plain.reference(path), plain.reference(altered))


def fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch):
    # Only the new installed-runtime receipt boundary is synthetic. Original
    # admission/raw GET, all eleven seed identities and current module bytes
    # are authenticated by their real public readers.
    path, _, _, directory = actual_q53_input
    monkeypatch.setattr(rolling, "_runtime", lambda value: dict(value))
    _, _, old_policy = genuine_seed
    source = Path(selected.__file__).resolve().parents[2]
    root = directory / "study"
    root.mkdir()
    workloads = directory / "capture-workloads"
    workloads.mkdir()
    runtime = {**old_policy["runtime"], "data_root": str(directory),
        "runtime_source_root": str(source), "module_root": str(source),
        "execution_root": str(source), "workload_root": str(workloads)}
    ledger.initialize(root, seed_enrollment=SEED, seed_progress=plain.reference(SCI), runtime=runtime)
    value = selected.validate_input(path)[0]
    manifest_path = selected.prepare_input(path, directory / (value["workload_id"] + ".json"))
    enrollment = ledger.enroll(root, acquisition_root=CASE,
        inputs={value["candidate_id"]: plain.reference(path)},
        prepared_workloads={value["candidate_id"]: plain.reference(manifest_path)})
    return enrollment, root, runtime, manifest_path


@pytest.mark.parametrize("mode", ["front", "buflo"])
def test_public_fixed_amendment_reopens_current_q53_and_exact_budget(actual_q53_input, genuine_seed, monkeypatch, mode):
    enrollment, root, runtime, original_path = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    args = {"front_policy": amendment.old.capture.FRONT_RESERVE_POLICY} if mode == "front" else {
        "buflo_policy": amendment.old.capture.BUFLO_KERNEL_PREPARATION_POLICY,
        "buflo_duration_policy": duration.POLICY}
    output = amendment.publish_amendment(enrollment, runtime, root / (mode + "-amendment.json"), **args)
    result = amendment.old.validate_amendment(output, enrollment=enrollment, runtime=runtime)
    assert result["modes"] == [mode]
    assert result["capture_limits"]["max_response_bytes"] == 64 * 1024 * 1024
    assert result["capture_limits"]["capture_megabytes"] == 256
    amended = json.loads(rolling._open_ref(result["workloads"][0]["capture_manifest"]).read_bytes())
    original = json.loads(original_path.read_bytes())
    assert amended["resources"] == original["resources"]
    assert amendment.old.validate_preparation(amended["preparation"], amended["resources"])["full_list_coverage"] is True
    files, trees = amendment.preparation_inputs(amended["preparation"])
    assert enrollment in files and Path(selected.validate_input(actual_q53_input[0])[0]["raw_root"]) in trees
    if mode == "front":
        declaration = amendment.old.receipts._unpack(rolling._open_ref(result["declaration"]).read_bytes(), amendment.DECLARATION_TYPE)
        for field, replacement in (("policies", {}), ("authority_sources", {}),
            ("capture_limits", {**declaration["capture_limits"], "capture_megabytes": 64}),
            ("traffic_artifacts", {})):
            changed = deepcopy(declaration)
            changed[field] = replacement
            altered = write(root / ("changed-" + field + ".json"), receipts._bind(amendment.DECLARATION_TYPE, changed))
            with pytest.raises(ValueError):
                amendment._declaration(altered)


def test_portable_selection_and_serial_binding_use_real_per_class_input(actual_q53_input, genuine_seed, monkeypatch):
    import importlib.util
    enrollment, root, _, original_path = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    source = Path(selected.__file__).resolve().parents[2]
    module_spec = importlib.util.spec_from_file_location("per_class_portable_fixture", source / "tools/_rapid_class_mode_flight/flight/operator.py")
    operator = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(operator)
    batch, policy, rows, manifests, roots, limits = operator.selected_inputs(enrollment, root)
    assert rows[0]["class_index"] == 12 and manifests[0] == json.loads(original_path.read_bytes())
    assert limits["max_response_bytes"] == 64 * 1024 * 1024 and limits["capture_megabytes"] == 256
    raw_root = Path(selected.validate_input(actual_q53_input[0])[0]["raw_root"])
    assert limits["max_attempts"] == 1 and any(raw_root.is_relative_to(Path(root)) for root in roots)
    for mode in ("undefended", "tamaraw", "cs-buflo"):
        assert operator.typed_canary_limits(manifests, policy, mode, None) == limits
    with pytest.raises(ValueError, match="explicit typed amendment"):
        operator.typed_canary_limits(manifests, policy, "front", None)

    fixture_spec = importlib.util.spec_from_file_location("per_class_serial_fixture", source / "tests/test_selected_capture_facts.py")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    serial_root = actual_q53_input[3] / "serial-boundary"
    serial_root.mkdir()
    spec, workload = fixture.make_spec(serial_root, manifests[0],
        cohort=enrollment, declared_role=ledger.ROLE)
    context = selected.facts.OperationFacts()
    context.bind_capture(spec)
    assert enrollment in context._files
    assert (Path(selected.validate_input(actual_q53_input[0])[0]["raw_root"]), False) in context._trees
    context.check()
    workload.write_bytes(workload.read_bytes() + b" ")
    with pytest.raises(ValueError, match="bytes or mode"):
        context.check()


def test_public_capture_spec_loader_accepts_real_per_class_enrollment_only(actual_q53_input, genuine_seed, monkeypatch):
    import importlib.util
    enrollment, _, _, original_path = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    source = Path(selected.__file__).resolve().parents[2]
    fixture_spec = importlib.util.spec_from_file_location("per_class_loader_fixture", source / "tests/test_selected_capture_facts.py")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    serial_root = actual_q53_input[3] / "public-spec-boundary"
    serial_root.mkdir()
    spec, _ = fixture.make_spec(serial_root, json.loads(original_path.read_bytes()),
        cohort=enrollment, declared_role=ledger.ROLE)
    # The old bind_capture fixture does not need a complete host layout; the
    # public loader does. Supply its exact disjoint/source launcher layout and
    # a genuinely bound plan envelope, keeping the installed-image boundary
    # explicitly synthetic.
    from dataclasses import replace
    (spec.runtime_source_root / "qcsd-lab").write_bytes(spec.base_launcher.read_bytes())
    host_launcher = spec.execution_root / "qcsd-lab"
    host_launcher.write_bytes(spec.base_launcher.read_bytes())
    qualifier_root = spec.campaign_dir.parent / "chaff-response-qualification-store/sets/loader-layout-fixture"
    qualifier_root.mkdir(parents=True)
    qualifier_manifest = write(qualifier_root / "_qualification-set.json", {
        "fixture_role": "public-loader-layout-only-no-qualification-credit"})
    write(spec.qualification_spec, {"schema_version": 1, "qualification_sets": [{
        "qualification_set": "loader-layout-fixture", "manifest": str(qualifier_manifest),
        "sidecar_root": str(qualifier_root), "prefix_spec_root": None}]})
    plan_payload = json.loads(spec.plan_receipt.read_bytes())["payload"]
    write(spec.plan_receipt, receipts._bind(lanes.PLAN_TYPE, plan_payload))
    spec = replace(spec, data_root=actual_q53_input[3], host_launcher=host_launcher)
    path = write(serial_root / "capture-spec.json", {"schema_version": 1,
        "artifact_type": "qcsd-rapid-v6-rolling-capture-spec", "inputs": spec.serializable()})
    assert lanes.load_capture_spec(path) == spec
    assert rolling._verify_enrollment(lanes.load_capture_spec(path).cohort)[1][-1]["class_index"] == 12
    bad = write(serial_root / "unknown-enrollment.json", receipts._bind("unknown-enrollment-role", {}))
    document = json.loads(path.read_bytes())
    document["inputs"]["cohort"] = str(bad)
    changed = write(serial_root / "bad-spec.json", document)
    with pytest.raises(ValueError, match="prospective enrollment authority"):
        lanes.load_capture_spec(changed)
