"""HOST protocol controls; installed runtimes/canary/group audit are synthetic.

Real schema, file references, raw closing fences and exact historical shell
projection execute here. No installed success, capture or scientific credit.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from qcsd_lab import rapid_canary_control_bridge as bridge
from qcsd_lab import rapid_rolling_readiness as ready
from qcsd_lab import qualification_delivery_compatibility as delivery
from qcsd_lab import qualification_control_authority as control
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import supplied_static_preparation as prep
from tools import rapid_rolling_capture as cli


@pytest.fixture
def case(tmp_path, monkeypatch):
    repository = Path(__file__).parents[1]
    old_root, new_root = tmp_path / "old-source", tmp_path / "new-source"
    old_root.mkdir(); new_root.mkdir()
    for name in (bridge.MODULE, "src/qcsd_lab/rapid_rolling_readiness.py", "src/qcsd_lab/rapid_rolling_capture.py"):
        target = new_root / name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((repository / name).read_bytes())
    shell = (repository / "qcsd-lab").read_bytes()
    (new_root / "qcsd-lab").write_bytes(shell)
    (old_root / "qcsd-lab").write_bytes(shell.replace(bridge.SELECTED_ENUM_LINE, b""))
    client = tmp_path / "client"; client.write_bytes(b"same compiled-client fixture")
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(ready._encoded(value))
        return {"path": str(path), "sha256": ready._sha(path.read_bytes())}
    source = {"lab_commit": "a" * 40, "lab_dirty": False, "lab_patch_sha256": ready._sha(b""),
        "neqo_commit": "c" * 40, "neqo_pinned_commit": "c" * 40, "neqo_dirty": False,
        "neqo_patch_sha256": ready._sha(b""), "image_digest": None}
    runtimes = []
    for number, root in enumerate((old_root, new_root), 1):
        runtime = {"runtime_source_root": str(root), "module_root": str(root),
            "execution_root": str(tmp_path / f"execution-{number}"), "source_manifest": str(root / "source.json"),
            "client_binary": str(client), "base_launcher": str(root / "qcsd-lab"), "host_launcher": str(root / "qcsd-lab"),
            "collection_image_digest": "sha256:" + str(number) * 64}
        Path(runtime["execution_root"]).mkdir()
        write(Path(runtime["source_manifest"]), {**source, "lab_commit": str(number) * 40})
        runtimes.append(runtime)
    old_runtime, new_runtime = runtimes
    current_inventory = write(tmp_path / "inventory.json", {"synthetic_full_inventory_boundary": True})
    result = tmp_path / "closed-result"; result.mkdir()
    manifest_ref = write(result / "manifest.json", {"preparation": {"data_role": prep.ROLE}, "resources": [{"id": 0}]})
    write(result / "experiment.json", {"configuration": {"workloads": [{"manifest": "manifest.json"}]}})
    common = {"producer": {"canonical": {"path": "original-runtime", "sha256": "a" * 64}},
        "qualification_group": {"path": "complete-five-group", "sha256": "b" * 64},
        "qualified_inputs": [{"workload_id": "fixture", "base_manifest": manifest_ref}],
        "workloads": [{"workload_id": "fixture", "max_response_bytes": 16_777_216,
            "request_header_primitive": {"method": "GET"}, "response_budget_source": {"type": "prepared-budget"}}],
        "client_sha256": ready._sha(client.read_bytes()), "producer_source": source, "producer_image": "sha256:" + "3" * 64,
        "producer_implementation_sha256": "e" * 64, delivery.POLICY_FIELD: delivery.POLICY,
        "published_at": "2026-10-05T00:00:00Z"}
    witnesses = []
    for number, runtime in enumerate(runtimes):
        document = {**deepcopy(common), "consumer": {"runtime": {key: runtime[key] for key in delivery.RUNTIME_KEYS}},
            "consumer_source": ready._json(ready._read(Path(runtime["source_manifest"]))),
            "consumer_image": runtime["collection_image_digest"]}
        witnesses.append(write(tmp_path / f"witness-{number}.json", document))
    current = ready._json(ready._read(Path(witnesses[1]["path"])))
    current.update(artifact_type=control.TYPE, original_witness=witnesses[0])
    witnesses[1] = write(Path(witnesses[1]["path"]), current)
    plan = {"clean_runtime_root": str(old_root), "execution_root": old_runtime["execution_root"],
        "canonical_runtime": {"source_inventory_sha256": "f" * 64}, "workload_sha256": manifest_ref["sha256"],
        "application_body_identity_policy": delivery.POLICY}
    plan_ref = write(tmp_path / "canary/plan.json", plan)
    def operation(name):return {key: write(tmp_path / (name + "-" + key + ".json"), {}) for key in ready.OPERATION_KEYS}
    original_canary = {"schema_version": 1, "plan": plan_ref,
        "deep_receipt": write(tmp_path / "deep.json", {}), "capture": operation("capture"), "deep": operation("deep")}
    facts = {"result_root": str(result), "source": {**source, "image_digest": old_runtime["collection_image_digest"]},
        "client_sha256": ready._sha(client.read_bytes()), "traffic_hashes": {},
        "application_body_identity_policy": delivery.POLICY, delivery.FIELD: witnesses[0], **ready.ZERO}
    # Scientific producer/installed proofs are explicit boundaries. The
    # independently invoked witness reader still authenticates each raw ref.
    monkeypatch.setattr(ready, "_validate_canary", lambda *a, **k: deepcopy(facts))
    monkeypatch.setattr(ready, "_operation", lambda *a, **k: {"end": ready._timestamp("2026-10-05T00:00:01Z")})
    monkeypatch.setattr(operations.OperationFacts, "bind_canary",
        lambda self, reference, runtime=None: self.watch_file(Path(reference["plan"]["path"])))
    monkeypatch.setattr(ready, "_bound_inventory", lambda *a: {})
    monkeypatch.setattr(ready, "_groups", lambda *a: ({"measurement": {"qcsd-lab:protected-measurement":
        {"sha256": "overwritten-by-real-projection", "executable": True}}}, {}))
    def witness(reference, **kwargs):
        path, raw = ready._reference(reference)
        context = operations.current_context()
        if context is not None: context.watch_file(path)
        return ready._json(raw), {}, {}
    monkeypatch.setattr(delivery, "validate", witness)
    monkeypatch.setattr(control, "validate", witness)
    monkeypatch.setattr(delivery, "roots", lambda reference, **kwargs: [Path(reference["path"]).parent])
    monkeypatch.setattr(control, "roots", lambda reference, **kwargs: [Path(reference["path"]).parent])
    from qcsd_lab import rapid_capture_traffic
    monkeypatch.setattr(rapid_capture_traffic, "files", lambda *a: {})
    monkeypatch.setattr(ready, "readiness_mount_roots", lambda *a, **k: [old_root])
    return SimpleNamespace(inputs={"original_canary": original_canary, "original_runtime": old_runtime,
        "current_runtime": new_runtime, "current_inventory": current_inventory, "current_witness": witnesses[1], "mode": "tamaraw"},
        output=tmp_path / "bridge.json", facts=facts, new_root=new_root, old_root=old_root, write=write)


def test_explicit_bridge_preserves_measured_witness_and_binds_new_consumer(case):
    reference = bridge.declare(case.output, **case.inputs)
    facts = bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
    assert facts[delivery.FIELD] == case.facts[delivery.FIELD]
    assert facts["source"] == case.facts["source"]
    assert facts["control_authority_witness"] == case.inputs["current_witness"]
    assert facts["authority_source"]["image_digest"] == case.inputs["current_runtime"]["collection_image_digest"]
    assert reference["schema_version"] == 3 and facts["scientific_credit"] is False
    roots = bridge.roots(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
    assert case.old_root in roots and case.new_root in roots and case.output.parent in roots


@pytest.mark.parametrize("field", ["qualification_group", "client_sha256", "workloads", "qualified_inputs", delivery.POLICY_FIELD])
def test_resealed_group_client_cap_input_or_policy_drift_refuses(case, field):
    path = Path(case.inputs["current_witness"]["path"])
    document = ready._json(path.read_bytes())
    if field == "workloads":document[field][0]["max_response_bytes"] = 64 * 1024 * 1024
    elif field == "qualified_inputs":document[field] = []
    elif field == "qualification_group":document[field]["sha256"] = "9" * 64
    else:document[field] = "changed"
    case.inputs["current_witness"] = case.write(path, document)
    with pytest.raises(ValueError, match="qualification group"):
        bridge.declare(case.output, **case.inputs)
    assert not case.output.exists()


@pytest.mark.parametrize("change", ["mode", "runtime", "module", "client"])
def test_unbound_mode_runtime_executing_module_or_client_refuses(case, change):
    if change == "mode":case.inputs["mode"] = "front"
    elif change == "runtime":case.inputs["current_runtime"]["collection_image_digest"] = "sha256:" + "7" * 64
    elif change == "module":(case.new_root / bridge.MODULE).write_bytes(b"changed actual module")
    else:Path(case.inputs["current_runtime"]["client_binary"]).write_bytes(b"changed installed client")
    with pytest.raises(ValueError):bridge.declare(case.output, **case.inputs)
    assert not case.output.exists()


def test_bridge_replay_closes_raw_witness_and_refuses_resealed_authority(case):
    reference = bridge.declare(case.output, **case.inputs)
    owner = operations.OperationFacts()
    with owner.scope():bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
    Path(case.inputs["current_witness"]["path"]).write_bytes(b"changed raw after proof")
    with pytest.raises(ValueError, match="changed"):owner.check()
    assert operations.current_context() is None


def test_registered_shell_line_cannot_move_into_another_dispatch(case):
    path = case.new_root / "qcsd-lab"
    raw = path.read_bytes().replace(bridge.SELECTED_ENUM_LINE, b"") + bridge.SELECTED_ENUM_LINE
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="exact registered dispatch"):
        bridge._groups(case.new_root, {})


def test_public_cli_is_closed_and_passes_both_runtime_roles(case, monkeypatch):
    from qcsd_lab import rapid_rolling_capture as rolling
    monkeypatch.setattr(rolling, "load_runtime", lambda p: case.inputs["original_runtime"] if p.name == "old.json" else case.inputs["current_runtime"])
    canary = case.output.parent / "canary-ref.json"; case.write(canary, case.inputs["original_canary"])
    args = cli._parser().parse_args(["canary-control-bridge", "--canary", str(canary),
        "--original-runtime-spec", "old.json", "--runtime-spec", "new.json",
        "--current-inventory", case.inputs["current_inventory"]["path"], "--mode", "tamaraw",
        "--qualification-delivery-compatibility", case.inputs["current_witness"]["path"], "--output", str(case.output)])
    assert cli.run(args)["schema_version"] == 3
    with pytest.raises(SystemExit):cli._parser().parse_args(["canary-control-bridge", "--mode", "front"])


def test_new_execution_traffic_mutation_is_fenced_before_success(case, monkeypatch):
    from qcsd_lab import rapid_capture_traffic
    relative = "traffic-fixture.json"
    path = Path(case.inputs["current_runtime"]["execution_root"]) / relative
    path.write_bytes(b"same fixed traffic fixture")
    digest = ready._sha(path.read_bytes())
    case.facts["traffic_hashes"] = {"fixture": digest}
    monkeypatch.setattr(rapid_capture_traffic, "files", lambda *a: {"fixture": (relative, digest)})
    reference = bridge.declare(case.output, **case.inputs)
    owner = operations.OperationFacts()
    with owner.scope():bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")
    path.write_bytes(b"changed traffic after proof")
    with pytest.raises(ValueError, match="changed"):owner.check()


def test_bridge_publication_must_follow_actual_old_deep_completion(case, monkeypatch):
    monkeypatch.setattr(ready, "_operation", lambda *a, **k: {"end": ready._timestamp("2099-10-05T00:00:01Z")})
    with pytest.raises(ValueError, match="publication must follow"):
        bridge.declare(case.output, **case.inputs)
    assert not case.output.exists()


def test_current_inventory_mutation_after_authenticated_read_refuses_publication(case, monkeypatch):
    inventory_path = Path(case.inputs["current_inventory"]["path"])
    def bound_inventory(reference, root):
        if reference == case.inputs["current_inventory"]:
            ready._reference(reference)
            inventory_path.write_bytes(b"changed immediately after authenticated inventory read")
        return {}
    monkeypatch.setattr(ready, "_bound_inventory", bound_inventory)
    with pytest.raises(ValueError, match="changed"):
        bridge.declare(case.output, **case.inputs)
    assert not case.output.exists()


@pytest.mark.parametrize("mutation", [None, "bytes", "mode"])
def test_source_launcher_and_execution_copy_keep_separate_refs_and_exact_bytes_modes(case, mutation):
    for name in ("original_runtime", "current_runtime"):
        runtime = case.inputs[name]
        source = Path(runtime["host_launcher"])
        copied = Path(runtime["execution_root"]) / "qcsd-lab"
        copied.write_bytes(source.read_bytes()); copied.chmod(source.stat().st_mode & 0o777)
        runtime["host_launcher"] = str(copied)
    current = Path(case.inputs["current_runtime"]["host_launcher"])
    if mutation == "bytes":current.write_bytes(b"another launcher")
    elif mutation == "mode":current.chmod((current.stat().st_mode & 0o777) ^ 0o100)
    if mutation is not None:
        with pytest.raises(ValueError, match="launcher copy bytes or mode"):
            bridge.declare(case.output, **case.inputs)
        assert not case.output.exists()
    else:
        reference = bridge.declare(case.output, **case.inputs)
        value = ready._json(ready._reference(reference[bridge.FIELD])[1])
        for row in value["qualification_binding"]["explicit_launcher_copies"].values():
            assert row["witness_launcher"]["path"] != row["capture_launcher"]["path"]
            assert row["witness_launcher"]["sha256"] == row["capture_launcher"]["sha256"]
            assert row["witness_launcher"]["mode"] == row["capture_launcher"]["mode"]
        assert bridge.validate(reference, runtime=case.inputs["current_runtime"], mode="tamaraw")["source"] == case.facts["source"]


@pytest.fixture
def authority_case(tmp_path, monkeypatch):
    """Real authority/source/implementation/epoch code, synthetic installed proof.

    The original complete group's historical proof and installed runtime are
    explicit boundaries. Exact current reader bytes, the real implementation
    aggregate, typed fields, chronology and raw closing fences execute here.
    """
    from qcsd_lab import chaff_qualification as legacy
    repository = Path(__file__).parents[1]
    names = set(legacy.IMPLEMENTATION_FILES) | delivery.EXTRA_PROTECTED
    after = {name: (repository / name).read_bytes() for name in names}
    after[delivery.MODULE] = Path(delivery.__file__).read_bytes()
    after[control.MODULE] = Path(control.__file__).read_bytes()
    after["neqo-qcsd/unchanged-fixture.rs"] = b"fn unchanged() {}\n"
    after["config/fixed-fixture.json"] = b'{"packet_size":1200}\n'
    before = deepcopy(after)
    before["qcsd-lab"] = before["qcsd-lab"].replace(control.SELECTED_ENUM_LINE, b"")
    before["src/qcsd_lab/orchestrator.py"] = control.normalize_orchestrator_imports(before["src/qcsd_lab/orchestrator.py"])
    def source(number):
        return {"lab_commit": str(number) * 40, "neqo_commit": "c" * 40,
            "neqo_pinned_commit": "c" * 40, "lab_dirty": False, "neqo_dirty": False,
            "lab_patch_sha256": legacy.EMPTY_SHA256, "neqo_patch_sha256": legacy.EMPTY_SHA256,
            "image_digest": None}
    def implementation(code, number):
        value = {"schema_version": legacy.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
            "artifact_type": "qcsd-chaff-qualification-implementation", "domain": legacy.IMPLEMENTATION_RECEIPT_DOMAIN,
            "source": source(number), "source_files": {name: ready._sha(code[name]) for name in legacy.IMPLEMENTATION_FILES},
            "installed_modules": {name: {"path": "/installed/" + name, "sha256": ready._sha(code[name])}
                                  for name in legacy.IMPLEMENTATION_PYTHON_FILES},
            "installed_entrypoint": {"path": "/usr/local/bin/qcsd-lab", "sha256": ready._sha(b"distinct console entrypoint")},
            "neqo_qcsd_client": {"path": "/usr/local/bin/neqo-qcsd-client", "sha256": "f" * 64}}
        value["sha256"] = legacy._implementation_aggregate(value)
        return value
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(ready._encoded(value))
        return delivery._ref(path)
    original_impl, current_impl = implementation(before, 1), implementation(after, 2)
    def canonical(receipt, number):
        return {"source": receipt["source"], "installed_client_sha256": receipt["neqo_qcsd_client"]["sha256"],
            "collection_image_digest": "sha256:" + str(number) * 64, "verified_at": "2025-01-01T00:00:00Z",
            "checks": {"collection": {"qualification_implementation_sha256": receipt["sha256"]}}}
    producer, current = canonical(original_impl, 1), canonical(current_impl, 2)
    roles = []
    for number, record in ((1, producer), (2, current)):
        runtime = {key: str(tmp_path / str(number) / key) for key in control.RUNTIME_KEYS}
        runtime["collection_image_digest"] = record["collection_image_digest"]
        roles.append({"canonical": write(tmp_path / str(number) / "canonical.json", record), "runtime": runtime})
    base = write(tmp_path / "bases/site.json", {"resources": [{"id": 0}], "preparation": {"data_role": prep.ROLE}})
    sidecar = write(tmp_path / "group/site.json", {"implementation_receipt": original_impl})
    group = write(tmp_path / "group/_qualification-set.json", {"workload_ids": ["site"]})
    original = {"schema_version": 1, "artifact_type": delivery.TYPE, "contract": delivery.CONTRACT,
        delivery.POLICY_FIELD: delivery.POLICY, "published_at": "2025-01-02T00:00:00Z",
        "producer": roles[0], "consumer": roles[0], "qualification_group": group,
        "qualified_inputs": [{"workload_id": "site", "base_manifest": base}],
        "workloads": [{"workload_id": "site", "base_manifest": base, "sidecar": sidecar,
            "max_response_bytes": 16_777_216, "request_header_primitive": {"method": "GET"}}],
        "client_sha256": "f" * 64, "producer_source": producer["source"], "consumer_source": producer["source"],
        "producer_image": producer["collection_image_digest"], "consumer_image": producer["collection_image_digest"],
        "producer_implementation_sha256": original_impl["sha256"], "consumer_implementation_sha256": original_impl["sha256"],
        "source_comparison": {}, **delivery.ZERO}
    original_ref = write(tmp_path / "old-witness.json", original)
    watched = tmp_path / "retained-raw"; watched.write_bytes(b"complete retained raw fixture")
    def original_validator(reference, **kwargs):
        assert reference == original_ref
        assert ready._json(ready._reference(reference)[1]) == original
        return deepcopy(original), deepcopy(original_impl), deepcopy(original_impl)
    def runtime(role):
        if role == roles[0]:return deepcopy(producer), deepcopy(before)
        assert role == roles[1]
        ready._reference(role["canonical"])
        return deepcopy(current), deepcopy(after)
    def raw_dependencies(reference, value):
        refs = [reference, value["producer"]["canonical"], value["consumer"]["canonical"], group, base, sidecar]
        return [ready._reference(ref)[0] for ref in refs] + [watched], []
    monkeypatch.setattr(delivery, "validate", original_validator)
    monkeypatch.setattr(delivery, "_runtime", runtime)
    monkeypatch.setattr(delivery, "_raw_dependencies", raw_dependencies)
    return SimpleNamespace(before=before, after=after, producer=producer, current=current, roles=roles,
        original=original, original_ref=original_ref, original_impl=original_impl, current_impl=current_impl,
        output=tmp_path / "new-authority.json", watched=watched, write=write)


def test_typed_authority_keeps_original_group_and_real_console_implementation(authority_case):
    case = authority_case
    reference = control.declare(case.output, original_witness=case.original_ref,
        consumer=case.roles[1], body_policy=delivery.POLICY)
    value, original, current = control.validate(reference, body_policy=delivery.POLICY,
        canonical=case.current, actual_image=case.current["collection_image_digest"])
    assert value["qualification_group"] == case.original["qualification_group"]
    assert value["producer_source"] == case.original["producer_source"]
    assert original == case.original_impl and current == case.current_impl
    assert current["installed_entrypoint"] == original["installed_entrypoint"]
    assert value["artifact_type"] == control.TYPE and value["scientific_credit"] is False


@pytest.mark.parametrize("field", ["qualification_group", "client_sha256", "workloads", "qualified_inputs"])
def test_typed_authority_resealed_group_client_cap_or_input_refuses(authority_case, field):
    case = authority_case
    reference = control.declare(case.output, original_witness=case.original_ref,
        consumer=case.roles[1], body_policy=delivery.POLICY)
    value = ready._json(ready._reference(reference)[1])
    if field == "workloads":value[field][0]["max_response_bytes"] = 64 * 1024 * 1024
    elif field == "qualified_inputs":value[field] = []
    elif field == "qualification_group":value[field]["sha256"] = "0" * 64
    else:value[field] = "0" * 64
    reference = case.write(case.output, value)
    with pytest.raises(ValueError, match="recomputed"):
        control.validate(reference, body_policy=delivery.POLICY)


@pytest.mark.parametrize("path", ["src/qcsd_lab/chaff_qualification.py", "neqo-qcsd/unchanged-fixture.rs", "config/fixed-fixture.json", delivery.MODULE, control.MODULE, "qcsd-lab"])
def test_authority_rejects_other_producer_native_config_reader_or_shell_changes(authority_case, path):
    changed = deepcopy(authority_case.after)
    changed[path] += b"\n# unrelated changed protected bytes\n"
    with pytest.raises(ValueError):control._source_comparison(authority_case.before, changed)


def test_authority_exact_import_projection_refuses_unnamed_alias(authority_case):
    raw = authority_case.after["src/qcsd_lab/orchestrator.py"]
    assert control.normalize_orchestrator_imports(raw) == authority_case.before["src/qcsd_lab/orchestrator.py"]
    with pytest.raises(ValueError, match="unnamed qualification import"):
        control.normalize_orchestrator_imports(raw + b"from .qualification_control_authority import arbitrary\n")


def test_authority_mutation_during_first_proof_refuses_publication(authority_case, monkeypatch):
    case = authority_case
    original = control._derive
    def changed(*args):
        result = original(*args)
        case.watched.write_bytes(b"changed during first proof")
        return result
    monkeypatch.setattr(control, "_derive", changed)
    with pytest.raises(ValueError, match="changed"):
        control.declare(case.output, original_witness=case.original_ref,
            consumer=case.roles[1], body_policy=delivery.POLICY)
    assert not case.output.exists()


def test_typed_epoch_hook_requires_matching_scope_and_real_image(authority_case, monkeypatch):
    from qcsd_lab import rapid_runtime_epochs as epochs
    case = authority_case
    reference = control.declare(case.output, original_witness=case.original_ref,
        consumer=case.roles[1], body_policy=delivery.POLICY)
    monkeypatch.setenv(control.ENV, reference["path"])
    with pytest.raises(ValueError, match="authenticated scope"):
        epochs.validate_qualification_reuse(case.original_impl, case.current_impl)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", case.current["collection_image_digest"])
    with control.qualification_context(reference, body_policy=delivery.POLICY):
        epochs.validate_qualification_reuse(case.original_impl, case.current_impl)
        with pytest.raises(ValueError, match="actual installed image"):
            control.validate_current_implementation(case.original_impl, case.current_impl, reference, actual_image=None)
    assert control._ACTIVE.get() is None


def test_authority_reader_old_artifact_and_default_delegate_exactly(authority_case, monkeypatch):
    calls = []
    marker = object()
    monkeypatch.setattr(delivery, "validate", lambda *a, **k: calls.append((a, k)) or marker)
    assert control.validate(authority_case.original_ref, body_policy=delivery.POLICY) is marker
    assert calls == [((authority_case.original_ref,), {"body_policy": delivery.POLICY, "canonical": None, "actual_image": None})]
    calls.clear()
    monkeypatch.setattr(delivery, "load_response_qualified_chaff", lambda *a, **k: calls.append((a, k)) or marker)
    assert control.load_response_qualified_chaff("sidecar", workload_id="site", require_current_implementation=True) is marker
    assert calls == [(("sidecar",), {"delivery_compatibility": None, "body_policy": None,
        "workload_id": "site", "require_current_implementation": True})]


def test_public_authority_cli_passes_exact_consumer_and_closed_policy(authority_case, monkeypatch):
    from qcsd_lab import rapid_rolling_capture as rolling
    case = authority_case
    monkeypatch.setattr(rolling, "load_runtime", lambda path: case.roles[1]["runtime"])
    args = cli._parser().parse_args(["qualification-control-authority", "--original-witness", case.original_ref["path"],
        "--runtime-spec", "current.json", "--current-canonical", case.roles[1]["canonical"]["path"],
        "--application-body-identity-policy", delivery.POLICY, "--output", str(case.output)])
    result = cli.run(args)
    assert result["witness"] == delivery._ref(case.output) and result["scientific_credit"] is False
    with pytest.raises(SystemExit):
        cli._parser().parse_args(["qualification-control-authority", "--application-body-identity-policy", "unregistered"])
