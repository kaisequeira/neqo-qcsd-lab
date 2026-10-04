"""Real static preparation/enrollment seams; synthetic Native emitter fixtures.

No actual HTTP/3, installed image, qualification or capture credit is asserted.
Only the external named-qualifier/canary primitives are substituted in plan tests.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import application_response_policy as responses
from qcsd_lab import capture_acceptance_policy as capture
from qcsd_lab import manifest as manifests
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import supplied_static_admission as admission
from qcsd_lab import supplied_static_capture_amendment as amendment
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from tests.test_supplied_static_get import actual_contract_fixture, load, write
from tests.test_supplied_static_preparation import fixed_graph, runtime, POLICIES
from tools import rapid_rolling_capture as cli

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.fixture
def original(fixed_graph, tmp_path, monkeypatch):
    get_root, arguments, context = fixed_graph
    terminal = admission.admit(context, 1, get_root, policies=POLICIES)
    study, current = runtime(tmp_path)
    # Real source guards compare the imported authority with both declared roots.
    for relative in amendment.SOURCE_FILES.values():
        path = Path(current["runtime_source_root"]) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((REPOSITORY / relative).read_bytes())
    rolling.initialize_study(context.root, study, current, supplied_static=True)
    enrollment = rolling.enroll(study)
    original_path, manifest = admission.prepared_workload(context, terminal)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:01:00Z")
    return SimpleNamespace(get_root=get_root, arguments=arguments, context=context,
        terminal=terminal, study=study, runtime=current, enrollment=enrollment,
        original=original_path, manifest=manifest,
        target=Path(current["workload_root"]) / original_path.name,
        output=study / "capture-policy-001.json", monkeypatch=monkeypatch)


def publish(a, *, front=True, buflo=True):
    return amendment.publish_amendment(a.enrollment, a.runtime, a.output,
        front_policy=capture.FRONT_RESERVE_POLICY if front else None,
        buflo_policy=capture.BUFLO_KERNEL_PREPARATION_POLICY if buflo else None)


def reseal(path, kind, payload):
    path.write_bytes(receipts._json(receipts._bind(kind, payload)))


@pytest.mark.parametrize("front,buflo,modes", [(True, True, ["front", "buflo"]),
    (True, False, ["front"]), (False, True, ["buflo"])])
def test_public_amendment_reopens_original_get_and_preserves_every_application_byte(original, front, buflo, modes):
    a = original
    protected = {path: path.read_bytes() for path in (a.original, a.terminal, a.enrollment,
        a.context.root / "provenance.json", a.get_root / "full-get-proof.json",
        a.get_root / "native/run.json", a.study / "policy.json")}
    publish(a, front=front, buflo=buflo)
    closed = amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)
    derived = load(a.target)
    assert closed["modes"] == modes
    assert closed["formal_accepted_trace_count"] == 0 and closed["scientific_credit"] is False
    assert derived["resources"] == a.manifest["resources"]
    assert derived["preparation"]["static_get_evidence"] == a.manifest["preparation"]["static_get_evidence"]
    assert derived["preparation"]["lab_source"] == a.manifest["preparation"]["lab_source"]
    assert closed["workloads"][0]["original_capture_policies"] == POLICIES
    reverted = deepcopy(derived)
    reverted["preparation"]["data_role"] = prep.ROLE
    reverted["preparation"].pop(amendment.FIELD)
    if front:
        reverted["preparation"][capture.FRONT_FIELD] = capture.FRONT_WINDOW_POLICY
    if buflo:
        reverted["preparation"].pop(capture.BUFLO_KERNEL_PREPARATION_FIELD)
    assert reverted == a.manifest
    manifests.validate_research_preparation(derived, workload_id=a.original.stem)
    manifests.runtime_manifest(derived)
    from qcsd_lab.chaff_qualification import response_only_candidate_resources
    assert response_only_candidate_resources(derived, a.original.stem)
    assert responses.validate_application_responses(derived, load(a.get_root / "native/run.json"))["resource_ids"] == [0, 1, 2]
    assert prep.validate_static_preparation(a.manifest["preparation"], a.manifest["resources"])
    assert all(path.read_bytes() == raw for path, raw in protected.items())
    assert a.get_root in amendment.preparation_roots(derived["preparation"])


@pytest.mark.parametrize("mutation", ["prune", "url", "headers", "dag", "expected-body", "policy",
    "role", "unknown-field", "null-reference", "source", "client", "raw-get", "unclosed"])
def test_amended_preparation_rejects_mutated_original_or_derived_authority(original, mutation):
    a = original
    publish(a)
    derived = load(a.target)
    if mutation == "prune": derived["resources"].pop()
    elif mutation == "url": derived["resources"][1]["url"] += "?different"
    elif mutation == "headers": derived["resources"][1]["headers"].append(["x-changed", "1"])
    elif mutation == "dag": derived["resources"][1]["depends_on"] = []
    elif mutation == "expected-body": derived["preparation"]["expected_responses"][1]["body_sha256"] = "e" * 64
    elif mutation == "policy": derived["preparation"][capture.FRONT_FIELD] = capture.FRONT_WINDOW_POLICY
    elif mutation == "role": derived["preparation"]["data_role"] = prep.ROLE
    elif mutation == "unknown-field": derived["preparation"]["arbitrary_relaxation"] = True
    elif mutation == "null-reference": derived["preparation"][amendment.FIELD] = None
    elif mutation == "source":
        (Path(a.runtime["runtime_source_root"]) / amendment.SOURCE_FILES["kernel_tx"]).write_bytes(b"changed\n")
    elif mutation == "client": Path(a.runtime["client_binary"]).write_bytes(b"different client")
    elif mutation == "raw-get":
        run = load(a.get_root / "native/run.json"); run["responses"][0]["complete"] = False
        write(a.get_root / "native/run.json", run)
    else: a.output.unlink()
    with pytest.raises((ValueError, OSError)):
        manifests.validate_research_preparation(derived, workload_id=a.original.stem)


@pytest.mark.parametrize("mutation", ["null-policy", "unknown-policy", "credit", "future", "enrollment", "mode", "row"])
def test_resealed_declaration_cannot_invent_policy_graph_or_chronology(original, mutation):
    a = original
    publish(a)
    declaration_path = a.output.with_name(a.output.stem + "-declaration.json")
    value = receipts._unpack(declaration_path.read_bytes(), amendment.DECLARATION_TYPE)
    if mutation == "null-policy": value["policies"][capture.FRONT_FIELD] = None
    elif mutation == "unknown-policy": value["policies"]["outgoing_physical_window_us"] = 50_000
    elif mutation == "credit": value["scientific_credit"] = True
    elif mutation == "future": value["published_at"] = "2026-10-05T00:00:00Z"
    elif mutation == "enrollment": value["enrollment"]["sha256"] = "e" * 64
    elif mutation == "mode": value["modes"].append("tamaraw")
    else: value["workloads"][0]["resource_records_sha256"] = "e" * 64
    reseal(declaration_path, amendment.DECLARATION_TYPE, value)
    wrapper = receipts._unpack(a.output.read_bytes(), amendment.RECEIPT_TYPE)
    wrapper["declaration"] = rolling._ref(declaration_path)
    reseal(a.output, amendment.RECEIPT_TYPE, wrapper)
    with pytest.raises(ValueError):
        amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)


def qualifier_and_canary(a):
    a.monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:02:00Z")
    sidecars = Path(a.runtime["campaign_dir"]).parent / "chaff-response-qualification-store/sets/amended"
    sidecars.mkdir(parents=True)
    named = sidecars / "_qualification-set.json"
    write(named, {"external_qualification_primitive": "synthetic HOST-only"})
    source = {**load(Path(a.runtime["source_manifest"])), "image_digest": a.runtime["collection_image_digest"]}
    write(sidecars / (a.original.stem + ".json"), {"qualification_source": source,
        "qualification_image_digest": a.runtime["collection_image_digest"],
        "implementation_receipt": {"neqo_qcsd_client": {"sha256": graph.digest(Path(a.runtime["client_binary"]).read_bytes())}},
        "candidate_attempts": [{"connection_epochs": [{"receipt": {"started_unix_ns": 1791072070000000000}}]}]})
    qualifier = a.study / "amended-qualifier.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "amended",
        "manifest": str(named), "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    reference = rolling._ref(a.output)
    canary_plan = a.study / "canary-plan.json"
    write(canary_plan, {"static_capture_amendment": reference})
    started = a.study / "canary-started.json"
    write(started, {"started_at": "2026-10-04T00:01:20Z"})
    canary = {"plan": rolling._ref(canary_plan), "capture": {"started": rolling._ref(started)}}
    facts = {"authority_source": source,
        "client_sha256": graph.digest(Path(a.runtime["client_binary"]).read_bytes()),
        "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()},
        "workload_sha256": graph.digest(a.target.read_bytes()),
        "full_graph": {"resource_records_sha256": graph.digest(graph.canonical_bytes(a.manifest["resources"]))}}
    a.monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", lambda *args, **kwargs: None)
    a.monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: facts)
    a.monkeypatch.setattr(readiness, "readiness_mount_roots", lambda *args, **kwargs: [a.study])
    return qualifier, sidecars, canary, facts


def test_real_public_plan_authorizes_only_proved_setting_and_keeps_all_64_slots(original):
    a = original
    publish(a)
    qualifier, _, canary, _ = qualifier_and_canary(a)
    output = a.study / "plan.json"
    rolling.publish_plan(a.study, a.enrollment, qualifier, output, readiness={"front": canary},
                         runtime_inputs=a.runtime, static_capture_amendment=a.output)
    spec = rolling.capture_spec(a.study, a.enrollment, qualifier, output)
    sites, payload = rolling.verify_capture_plan(spec)
    assert len(sites) == 1 and sites[0].workload_sha256 == graph.digest(a.target.read_bytes())
    assert payload["planned_trace_count"] == 320 and len(payload["lanes"]) == 80
    assert payload["data_role"] == prep.ROLE and payload["static_capture_amendment"] == rolling._ref(a.output)
    for mode in rolling.plan.MODES:
        assert sum(row["visits_per_workload"] * len(row["workload_ids"]) for row in payload["lanes"] if row["mode"] == mode) == 64
    def lane(mode):
        row = next(row for row in payload["lanes"] if row["mode"] == mode)
        return rolling.plan.Lane(**{key: tuple(value) if key == "workload_ids" else value
            for key, value in row.items() if key != "campaign_sha256"})
    assert rolling.require_mode_readiness(spec, lane("front"), before="2026-10-04T00:02:00Z") == canary
    with pytest.raises(ValueError, match="own successful current full canary"):
        rolling.require_mode_readiness(spec, lane("buflo"))
    assert a.get_root in rolling.readiness_roots(spec, lane("front").campaign_name)
    from qcsd_lab.rapid_operation_facts import OperationFacts
    # Operation-local binding reopens the amended graph using its real role.
    operation = OperationFacts()
    operation.bind_capture(spec)


@pytest.mark.parametrize("mutation", ["source", "image", "client", "before", "workload", "graph", "canary-before", "null-reference", "unready-mode"])
def test_plan_rejects_stale_qualifier_or_unsupported_canary(original, mutation):
    a = original
    publish(a)
    qualifier, sidecars, canary, facts = qualifier_and_canary(a)
    sidecar = sidecars / (a.original.stem + ".json")
    value = load(sidecar)
    if mutation == "source": value["qualification_source"]["lab_commit"] = "e" * 40
    elif mutation == "image": value["qualification_image_digest"] = "sha256:" + "e" * 64
    elif mutation == "client": value["implementation_receipt"]["neqo_qcsd_client"]["sha256"] = "e" * 64
    elif mutation == "before": value["candidate_attempts"][0]["connection_epochs"][0]["receipt"]["started_unix_ns"] = 0
    elif mutation == "workload": facts["workload_sha256"] = graph.digest(a.original.read_bytes())
    elif mutation == "graph": facts["full_graph"]["resource_records_sha256"] = "e" * 64
    elif mutation == "canary-before":
        path = rolling._open_ref(canary["capture"]["started"])
        write(path, {"started_at": "2026-10-04T00:00:01Z"})
        canary["capture"]["started"] = rolling._ref(path)
    elif mutation == "null-reference":
        path = rolling._open_ref(canary["plan"])
        write(path, {"static_capture_amendment": None}); canary["plan"] = rolling._ref(path)
    write(sidecar, value)
    with pytest.raises(ValueError):
        rolling.publish_plan(a.study, a.enrollment, qualifier, a.study / "invalid-plan.json",
            readiness={"tamaraw" if mutation == "unready-mode" else "front": canary},
            runtime_inputs=a.runtime, static_capture_amendment=a.output)


def test_creation_is_explicit_and_never_replaces_original_or_existing_target(original):
    a = original
    with pytest.raises(ValueError, match="at least one"):
        amendment.publish_amendment(a.enrollment, a.runtime, a.output)
    a.target.write_bytes(a.original.read_bytes())
    with pytest.raises(ValueError, match="never overwrites"):
        publish(a)
    assert not a.output.exists()
    a.target.unlink()
    publish(a)
    with pytest.raises(ValueError, match="fresh declaration"):
        publish(a)


def test_public_cli_defaults_and_explicit_static_policy_selectors_are_separate():
    required = ["static-amendment", "--enrollment", "/enrollment", "--runtime-spec", "/runtime", "--output", "/amendment"]
    args = cli._parser().parse_args(required + ["--front-policy", capture.FRONT_RESERVE_POLICY])
    assert args.front_policy == capture.FRONT_RESERVE_POLICY and args.buflo_policy is None
    args = cli._parser().parse_args(required + ["--buflo-policy", capture.BUFLO_KERNEL_PREPARATION_POLICY])
    assert args.buflo_policy == capture.BUFLO_KERNEL_PREPARATION_POLICY
    with pytest.raises(SystemExit): cli._parser().parse_args(required + ["--front-policy", capture.FRONT_WINDOW_POLICY])
    old = cli._parser().parse_args(["front-amendment", "--enrollment", "/enrollment", "--runtime-spec", "/runtime", "--output", "/amendment"])
    from qcsd_lab.rapid_front_capture_amendment import CAPTURE_POLICY
    assert old.capture_policy == CAPTURE_POLICY


@pytest.mark.parametrize("name", ["front_preparation_evidence", "static_evidence_transport"])
@pytest.mark.parametrize("role", ["runtime_source_root", "module_root", "imported"])
def test_new_authority_helpers_are_bound_to_each_actual_source_role(original, tmp_path, name, role):
    a = original
    if role == "module_root":
        root = tmp_path / "module-source"
        for relative in amendment.SOURCE_FILES.values():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPOSITORY / relative).read_bytes())
        a.runtime[role] = str(root)
    publish(a)
    declaration = receipts._unpack(a.output.with_name(a.output.stem + "-declaration.json").read_bytes(),
                                   amendment.DECLARATION_TYPE)
    relative = amendment.SOURCE_FILES[name]
    assert declaration["authority_sources"][name] == graph.digest((REPOSITORY / relative).read_bytes())
    if role == "imported":
        changed = tmp_path / "changed-import.py"
        changed.write_bytes((REPOSITORY / relative).read_bytes() + b"\n# altered actual imported authority\n")
        imported = amendment.import_module
        a.monkeypatch.setattr(amendment, "import_module", lambda selected:
            SimpleNamespace(__file__=str(changed)) if selected == "qcsd_lab." + name else imported(selected))
    else:
        changed = Path(a.runtime[role]) / relative
        changed.write_bytes(changed.read_bytes() + b"\n# altered frozen authority\n")
    with pytest.raises(ValueError, match="actual frozen capture source"):
        amendment.validate_amendment(a.output, enrollment=a.enrollment, runtime=a.runtime)


def test_amended_transport_covers_every_authenticated_get_context_and_runtime_path(original):
    from qcsd_lab.static_evidence_transport import manifest_roots
    from tests.test_static_evidence_transport import deep_inputs
    a = original
    publish(a)
    derived = load(a.target)
    roots = manifest_roots(derived)
    paths = [a.get_root, a.context.root, a.original, a.enrollment, a.output,
        a.output.with_name(a.output.stem + "-declaration.json")]
    paths.extend(Path(a.runtime[key]) for key in
        ("runtime_source_root", "module_root", "execution_root", "source_manifest",
         "client_binary", "base_launcher", "host_launcher"))
    assert all(any(path.is_relative_to(root) for root in roots) for path in paths)
    assert all(root.is_absolute() and root.is_dir() and not root.is_symlink() for root in roots)
    # The ordinary installed deep command must transport the same authenticated
    # roots, not just the original GET namespace or /lab source aliases.
    directory, plan, command = deep_inputs(a.study / "transport-canary", derived)
    actual = readiness._deep_command(plan, directory, "a" * 64, "front", "/lab/results/test/001", command)
    mounts = {actual[index + 1] for index, value in enumerate(actual) if value == "--volume"}
    assert all(f"{root}:{root}:ro" in mounts for root in roots)


@pytest.mark.parametrize("mutation", ["raw-get", "unclosed", "pruned"])
def test_amended_transport_cannot_mount_changed_or_unclosed_evidence(original, mutation):
    from qcsd_lab.static_evidence_transport import manifest_roots
    a = original
    publish(a)
    derived = load(a.target)
    if mutation == "raw-get":
        (a.get_root / "native/packets.csv").write_bytes(b"changed original GET\n")
    elif mutation == "unclosed":
        a.output.unlink()
    else:
        derived["resources"].pop()
    with pytest.raises((ValueError, OSError)):
        manifest_roots(derived)
