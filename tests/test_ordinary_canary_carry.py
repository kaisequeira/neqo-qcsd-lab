"""Ordinary carry contract with genuine metadata and controlled old proof/install.

The real five immutable graph refs, canary scalar configuration and protected
Source projection are exercised. Original packet/deep reconstruction and both
installation predicates are explicitly controlled HOST fixture boundaries.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace
from datetime import datetime, timezone
import sys

import pytest

from qcsd_lab import rapid_ordinary_canary_carry as carry
from qcsd_lab import rapid_rolling_readiness as ready
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab.rapid_operation_facts import OperationFacts

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
FLIGHT = WORKSPACE / "diagnostic-rehearsals/rapid-curated-tranco50-v7-b03-ordinary-parallel-nativec24-002"
OLD = WORKSPACE / "rapid-execution-ordinary-parallel-v26-20261006"


@pytest.fixture
def current(tmp_path, monkeypatch):
    original_ref = json.loads((FLIGHT / "readiness.json").read_bytes())["undefended"]
    original_spec = rolling.load_runtime(FLIGHT / "runtime-spec.json")
    original_runtime = {k: original_spec[k] for k in lanes.RUNTIME_KEYS}
    original_plan = json.loads((FLIGHT / "plan.json").read_bytes())
    deep = json.loads((FLIGHT / "undefended-deep-verification.json").read_bytes())
    result = Path(original_plan["execution_root"]) / "results" / Path(deep["root"]).relative_to("/lab/results")
    experiment = json.loads((result / "experiment.json").read_bytes())
    retained = tmp_path / "controlled-original-result"
    retained.mkdir(); (retained / "experiment.json").write_text(json.dumps(experiment))
    sample = experiment['samples'][0]
    destination = retained / sample['path'] / 'neqo/run.json'
    destination.parent.mkdir(parents=True)
    destination.write_bytes((result / sample['path'] / 'neqo/run.json').read_bytes())
    old_canonical = original_plan["canonical_runtime"]
    runtime = dict(original_spec)
    runtime.update(module_root=str(ROOT), runtime_source_root=str(ROOT))
    renewal = json.loads(Path(original_plan["ordinary_renewal"]["path"]).read_bytes())
    new_renewal = tmp_path / "current-renewal.json"
    new_renewal.write_text(json.dumps(renewal))
    sites = tuple(ordinary.OrdinarySite(row["candidate_id"], row["workload_id"],
        row["current_manifest"]["sha256"], "https://public-fixture.invalid", None, None)
        for row in renewal["rows"])
    value = {"runtime": runtime, "renewal": rolling._ref(new_renewal),
        "enrollment": renewal["enrollment"], "capture_limits": original_plan["capture_limits"]}
    input_path = tmp_path / "controlled-current-input.json"
    input_path.write_text(json.dumps(value))
    facts = {"mode": "undefended", "recorded_image_deep_reopened": True,
        "source": {**old_canonical["source"], "image_digest": old_canonical["collection_image_digest"]},
        "client_sha256": old_canonical["installed_client_sha256"],
        "result_root": str(retained), "traffic_hashes": original_plan["traffic_hashes"],
        "application_body_identity_policy": experiment["configuration"]["application_body_identity_policy"],
        "workload_sha256": original_plan["workload_sha256"]}
    new_source = {**old_canonical["source"], "lab_commit": "f" * 40}
    new_canonical = {**old_canonical, "source": new_source, "collection_image_digest": "sha256:" + "e" * 64}
    runtime["collection_image_digest"] = new_canonical["collection_image_digest"]
    input_path.write_text(json.dumps(value))
    new_ref = {"path": str(tmp_path / "controlled-current-canonical.json"), "sha256": "d" * 64, "mode": 420}
    old_ref = carry.reference(FLIGHT / "canonical-runtime.json")
    monkeypatch.setattr(carry, "_bind_runtime", lambda ref, role:
        (old_canonical if ref == old_ref else new_canonical,
         {"src/qcsd_lab/" + n: (OLD / "src/qcsd_lab" / n).read_bytes() for n in original_ref["reader_sources"]}))
    monkeypatch.setattr(carry, "_recorded_operation", lambda *args:
        ({"facts": facts, "roots": [], "read_dependencies": [], "directory_dependencies": []},
         {"completed_at": "2026-10-05T00:00:00Z"}))
    monkeypatch.setattr(rolling, "_runtime", lambda v: dict(v))
    monkeypatch.setattr(ordinary, "validate_inputs", lambda *args, **kwargs: sites)
    return {"original_ref": original_ref, "original_runtime": original_runtime,
        "old_ref": old_ref, "new_ref": new_ref, "value": value, "input": input_path,
        "facts": facts, "new_canonical": new_canonical, "sites": sites,
        "experiment": experiment, "retained": retained, "renewal": renewal,
        "new_renewal": new_renewal}


def derive(current):
    return carry._derive(current["original_ref"], current["original_runtime"], current["old_ref"],
        carry.reference(current["input"]), current["new_ref"], {})[0]


def test_genuine_graph_metadata_distinct_measured_and_authority_labels(current):
    value = derive(current)
    assert len(value["graph_bindings"]) == 5
    assert value["original_facts"]["source"]["lab_commit"] == carry.ORIGINAL_HEAD
    assert value["authority_source"]["lab_commit"] == "f" * 40
    assert len(value["mode_safe_units"]) == 6
    assert value["original_facts"]["workload_sha256"] == current["facts"]["workload_sha256"]


@pytest.mark.parametrize("drift", ["request", "caps", "body", "client", "graph"])
def test_real_metadata_condition_drift_refuses(current, drift, tmp_path):
    if drift == "request":
        current["experiment"]["samples"][0]["request_policy"] = "half-duplex"
    elif drift == "body":
        current["experiment"]["configuration"]["application_body_identity_policy"] = "exact-response-body-v1"
    elif drift == "caps":
        current["value"]["capture_limits"] = {**current["value"]["capture_limits"], "max_response_bytes": 1}
        current["input"].write_text(json.dumps(current["value"]))
    elif drift == "client":
        current["new_canonical"]["installed_client_sha256"] = "a" * 64
    else:
        renewal = copy.deepcopy(current["renewal"])
        manifest = json.loads(Path(renewal["rows"][0]["current_manifest"]["path"]).read_bytes())
        manifest["resources"].pop()
        path = tmp_path / "pruned-manifest.json"; path.write_text(json.dumps(manifest))
        renewal["rows"][0]["current_manifest"] = carry.reference(path)
        current["new_renewal"].write_text(json.dumps(renewal))
        current["value"]["renewal"] = rolling._ref(current["new_renewal"])
        current["input"].write_text(json.dumps(current["value"]))
    (current["retained"] / "experiment.json").write_text(json.dumps(current["experiment"]))
    with pytest.raises(ValueError): derive(current)


def test_code_request_drift_cannot_use_reviewed_pair(tmp_path, monkeypatch):
    name = "src/qcsd_lab/capture_session.py"
    left, right = tmp_path / "old", tmp_path / "new"
    for root, original in ((left, OLD), (right, ROOT)):
        (root / "src/qcsd_lab").mkdir(parents=True)
        (root / name).write_bytes((original / name).read_bytes())
    (right / name).write_bytes((right / name).read_bytes() + b"\n# altered request implementation\n")
    before = {"measurement": {name: {"sha256": ready._sha((left / name).read_bytes()), "executable": False}}}
    after = {"measurement": {name: {"sha256": ready._sha((right / name).read_bytes()), "executable": False}}}
    monkeypatch.setattr(ready, "_groups", lambda root, inv: (copy.deepcopy(before if root == left else after), {}))
    with pytest.raises(ValueError, match="executable request"):
        carry.protected_groups(left, right, {}, {})


def test_no_tamaraw_carry_and_strict_default_canary(current):
    ref = {"schema_version": 6, "artifact_type": carry.TYPE, "carry": {}}
    with pytest.raises(ValueError, match="only its explicit ordinary"):
        carry.validate(ref, runtime=current["original_runtime"], mode="tamaraw")
    with pytest.raises(ValueError):
        ordinary.require_canary({**current["facts"], "workload_sha256": "a" * 64}, current["sites"])


@pytest.mark.parametrize("change", ["bytes", "mode", "membership"])
def test_borrowed_operation_closes_raw_and_directory_mutations(tmp_path, change):
    directory = tmp_path / "immutable-original"; directory.mkdir()
    path = directory / "raw.bin"; path.write_bytes(b"original")
    with OperationFacts().scope() as context:
        report = {"read_dependencies": [carry.reference(path)],
                  "directory_dependencies": [carry.epoch._directory(directory)]}
        carry._close_report(report)
        if change == "bytes": path.write_bytes(b"changed")
        elif change == "mode": path.chmod(0o600)
        else: (directory / "new.bin").write_bytes(b"new")
        with pytest.raises(ValueError): context.check()


@pytest.mark.parametrize("mutation", [None, "input", "later-site", "caps", "numeric-alias"])
def test_exact_current_plan_input_all_sites_and_caps(current, mutation, tmp_path):
    facts = {"ordinary_canary_carry": carry.TYPE,
        "ordinary_carry_current_input": carry.reference(current["input"]),
        "ordinary_carry_capture_limits": current["value"]["capture_limits"],
        "ordinary_carry_sites": [{"candidate_id": site.candidate_id, "workload_id": site.workload_id,
            "workload_sha256": site.workload_sha256} for site in current["sites"]]}
    spec = SimpleNamespace(qualification_spec=current["input"])
    payload = {"capture_limits": copy.deepcopy(current["value"]["capture_limits"])}
    sites = current["sites"]
    if mutation == "input":
        changed = tmp_path / "other-input.json"; changed.write_bytes(current["input"].read_bytes())
        spec.qualification_spec = changed
    elif mutation == "later-site":
        sites = (*sites[:-1], replace(sites[-1], workload_sha256="a" * 64))
    elif mutation == "caps": payload["capture_limits"]["max_response_bytes"] = 1
    elif mutation == "numeric-alias": payload["capture_limits"]["max_attempts"] = True
    if mutation is None:
        carry.require_current_plan(facts, spec, payload, sites)
    else:
        with pytest.raises(ValueError): carry.require_current_plan(facts, spec, payload, sites)


@pytest.mark.parametrize("changed", [False, True])
def test_original_interpreter_uses_registered_binary_not_current_path(tmp_path, monkeypatch, changed):
    original = json.loads((FLIGHT / "readiness.json").read_bytes())["undefended"]
    full_runtime = rolling.load_runtime(FLIGHT / "runtime-spec.json")
    runtime = {key: full_runtime[key] for key in lanes.RUNTIME_KEYS}
    plan = json.loads((FLIGHT / "plan.json").read_bytes())
    directory = tmp_path / "original-operation"; directory.mkdir()
    command_python = str(Path("/bin/true").resolve()) if changed else plan["host_python"]
    start = {"command": [command_python, "-I", "-B", "-c", carry._PROGRAM],
        "request": carry._request(original, runtime, directory),
        "interpreter": carry.reference(Path(command_python).resolve(strict=True)),
        "started_at": datetime.now(timezone.utc).isoformat()}
    stdout = ready._encoded({"facts": {}, "roots": [], "read_dependencies": [], "directory_dependencies": []})
    end = {"returncode": 0, "completed_at": datetime.now(timezone.utc).isoformat(),
        "stdout_sha256": ready._sha(stdout), "stderr_sha256": ready._sha(b"")}
    for name, raw in {"started.json":ready._encoded(start), "completed.json":ready._encoded(end),
                      "stdout.log":stdout, "stderr.log":b""}.items(): (directory / name).write_bytes(raw)
    refs = {name:carry.reference(directory / name) for name in ("started.json", "completed.json", "stdout.log", "stderr.log")}
    # Installed Python's path is independent of the recorded HOST interpreter.
    monkeypatch.setattr(sys, "executable", "/different/current/image/python")
    if changed:
        with pytest.raises(ValueError, match="interpreter changed"):
            carry._recorded_operation(original, runtime, refs)
    else:
        assert carry._recorded_operation(original, runtime, refs)[0]["roots"] == []


def test_both_runtime_ancestor_and_external_recipe_roots(tmp_path):
    current = tmp_path / "current"; original = tmp_path / "original"; external = tmp_path / "external"
    for path in (current, original, external): path.mkdir()
    recipe = external / "reuse.py"; recipe.write_bytes(b"exact external recipe")
    parent = original / "canonical.json"; parent.write_text(json.dumps({"closure_recipe":rolling._ref(recipe)}))
    child = current / "canonical.json"; child.write_text(json.dumps({"original_canonical":rolling._ref(parent),
        "client_reuse_recipe":rolling._ref(recipe)}))
    with OperationFacts().scope() as context:
        assert carry._runtime_dependency_roots(carry.reference(child)) == {current, original, external}
        context.check()


def test_runtime_first_proof_once_and_mutation_refuses_cached_use(tmp_path, monkeypatch):
    parent = tmp_path / "canonical"; parent.mkdir()
    canonical = parent / "canonical.json"; canonical.write_text("{}")
    source = parent / "source"; source.mkdir()
    client = parent / "client"; client.write_bytes(b"client")
    launcher = source / "qcsd-lab"; launcher.write_bytes(b"launcher")
    metadata = parent / "source.json"; metadata.write_text("{}")
    runtime = {"runtime_source_root":str(source), "module_root":str(source),
        "execution_root":str(source), "source_manifest":str(metadata), "client_binary":str(client),
        "base_launcher":str(launcher), "host_launcher":str(launcher), "collection_image_digest":"sha256:"+"a"*64}
    count = []
    def original_installation_boundary(*args, **kwargs):
        count.append(True); return {"synthetic":"installation"}, {"qcsd-lab":b"launcher"}
    monkeypatch.setattr(carry.schedule, "reopen_runtime", original_installation_boundary)
    with OperationFacts().scope() as context:
        ref = carry.reference(canonical)
        assert carry._bind_runtime(ref, runtime) == carry._bind_runtime(ref, runtime)
        assert len(count) == 1
        client.write_bytes(b"changed")
        with pytest.raises(ValueError): carry._bind_runtime(ref, runtime)


def test_public_carry_publication_readiness_and_target_condition(current, tmp_path, monkeypatch):
    """Real public dispatch; original packet/install proof remains controlled.

    Genuine five-site graph refs, canary configuration and original Native run
    metadata pass the current-plan and target-condition reader unchanged.
    """
    from qcsd_lab import rapid_target_chunks as chunks
    report = {"facts": current["facts"], "roots": [], "read_dependencies": [], "directory_dependencies": []}
    Path(current["new_ref"]["path"]).write_text(json.dumps(current["new_canonical"]))
    current["new_ref"] = carry.reference(current["new_ref"]["path"])
    def controlled_original_reader(reference, runtime, audit):
        audit = Path(audit); audit.mkdir()
        old_plan = json.loads((FLIGHT / "plan.json").read_bytes())
        interpreter = carry.reference(Path(old_plan["host_python"]).resolve(strict=True))
        raw = {"started.json": ready._encoded({"command": [old_plan["host_python"]], "interpreter": interpreter}),
               "completed.json": ready._encoded({"returncode": 0}),
               "stdout.log": ready._encoded(report), "stderr.log": b""}
        for name, data in raw.items(): (audit / name).write_bytes(data)
        return report, {name: carry.reference(audit / name) for name in raw}
    monkeypatch.setattr(carry, "_run_original", controlled_original_reader)
    original_bind = OperationFacts.bind_canary
    def registered_old_boundary(self, ref, runtime):
        if ref.get("schema_version") == 5:
            assert ref == current["original_ref"] and runtime == current["original_runtime"]
            return
        return original_bind(self, ref, runtime)
    monkeypatch.setattr(OperationFacts, "bind_canary", registered_old_boundary)
    ref = carry.publish(original_canary=current["original_ref"], original_runtime=current["original_runtime"],
        original_canonical=current["old_ref"], current_input=carry.reference(current["input"]),
        current_canonical=current["new_ref"], audit_root=tmp_path / "original-audit",
        output=tmp_path / "ordinary-carry.json", reason="controlled public control-only publication",
        individual_evidence=carry.reference(WORKSPACE / 'diagnostic-rehearsals/ordinary-b03-current-runtime-serial-root-actual-20261006-001/independently-verified-batch-closed.json'))
    runtime = {key: current["value"]["runtime"][key] for key in lanes.RUNTIME_KEYS}
    facts = ready.validate_canary(ref, runtime=runtime, mode="undefended")
    roots = ready.readiness_mount_roots(ref, runtime=runtime, mode="undefended")
    original_python = Path(json.loads((FLIGHT / "plan.json").read_bytes())["host_python"])
    assert any(original_python.is_relative_to(root) for root in roots)
    assert any(original_python.resolve(strict=True).is_relative_to(root) for root in roots)
    assert facts["source"]["lab_commit"] == carry.ORIGINAL_HEAD
    assert facts["authority_source"]["lab_commit"] == "f" * 40
    assert ordinary.require_canary(facts, current["sites"]) is None
    stored = json.loads(Path(ref["carry"]["path"]).read_bytes())
    assert stored["scientific_credit"] is False and stored["formal_accepted_trace_count"] == 0
    source = tmp_path / "current-source.json"
    source.write_text(json.dumps(current["new_canonical"]["source"]))
    payload = {ordinary.FIELD: ordinary.CONTRACT, "readiness": {"undefended": ref},
        "capture_limits": current["value"]["capture_limits"],
        "application_body_identity_policy": current["facts"]["application_body_identity_policy"],
        "declared_at": datetime.now(timezone.utc).isoformat(),
        "lanes": [{"mode": "undefended", "campaign_name": "controlled-formal-lane"}]}
    full_runtime = current["value"]["runtime"]
    spec = SimpleNamespace(qualification_spec=current["input"], source_manifest=source,
        collection_image_digest=runtime["collection_image_digest"], client_binary=Path(runtime["client_binary"]),
        workload_root=Path(current["renewal"]["rows"][0]["current_manifest"]["path"]).parent,
        serializable=lambda: full_runtime)
    lane = SimpleNamespace(study_version=6, role="formal", mode="undefended")
    monkeypatch.setattr(rolling, "verify_capture_plan", lambda *args, **kwargs: (current["sites"], payload))
    monkeypatch.setattr(lanes, "_lane", lambda *args: lane)
    with OperationFacts().scope() as context:
        assert rolling.require_mode_readiness(spec, lane, _context=context) == ref
        reference, identity = chunks._condition(spec, current["sites"], payload, "undefended")
        assert reference == ref
        assert identity['primary_document_identity_policy'] == 'exact-response-body-v1'
        authority = facts['ordinary_individual_primary_authority']
        assert len(authority['individual_manifests']) == 5
        assert {row['lab_primary_policy'] for row in authority['individual_manifests']} == {'variable-primary-document-body-v1'}
        context.check()
    with pytest.raises(ValueError, match="explicit ordinary"):
        ready.validate_canary(ref, runtime=runtime, mode="tamaraw")


def test_genuine_host_interpreter_alias_and_binary_transport():
    plan = json.loads((FLIGHT / "plan.json").read_bytes())
    command = Path(plan["host_python"])
    binary = command.resolve(strict=True)
    roots = carry._interpreter_dependency_roots(str(command), carry.reference(binary))
    assert any(command.is_relative_to(root) for root in roots)
    assert any(binary.is_relative_to(root) for root in roots)
    # Follow every real symlink edge without substituting current image Python.
    queued, seen = [command], set()
    while queued:
        current = queued.pop()
        if current in seen: continue
        seen.add(current)
        for entry in (current, *current.parents):
            if entry.is_symlink():
                assert any(entry.is_relative_to(root) for root in roots)
                link = entry.readlink()
                queued.append(link if link.is_absolute() else entry.parent / link)
    with pytest.raises(ValueError, match="registered binary"):
        carry._interpreter_dependency_roots(str(command), carry.reference(Path("/bin/true").resolve(strict=True)))


@pytest.mark.parametrize('mutation', ['response-cap', 'manifest-primary', 'native-workload-source'])
def test_individual_primary_authority_refuses_cap_or_manifest_drift(current, tmp_path, mutation):
    value = derive(current)
    bindings = copy.deepcopy(value['graph_bindings'])
    caps = copy.deepcopy(value['capture_limits'])
    if mutation == 'response-cap':
        caps['max_response_bytes'] += 1
    elif mutation == 'manifest-primary':
        row = bindings[-1]
        manifest = json.loads(Path(row['authority_manifest']['path']).read_bytes())
        manifest['preparation']['primary_document_identity_policy'] = 'exact-response-body-v1'
        changed = tmp_path / 'changed-individual-policy.json'
        changed.write_text(json.dumps(manifest))
        row['authority_manifest'] = carry.reference(changed)
    else:
        sample = current['experiment']['samples'][0]
        path = current['retained'] / sample['path'] / 'neqo/run.json'
        run = json.loads(path.read_bytes())
        run['application_workload_source_hash_sha256'] = 'a' * 64
        path.write_text(json.dumps(run))
    evidence = carry.reference(WORKSPACE / 'diagnostic-rehearsals/ordinary-b03-current-runtime-serial-root-actual-20261006-001/independently-verified-batch-closed.json')
    original = json.loads((FLIGHT / 'plan.json').read_bytes())['canonical_runtime']
    with pytest.raises(ValueError):
        carry._individual_policy_authority(evidence, bindings, caps, current['experiment'],
            current['retained'], original, current['original_runtime'])


@pytest.mark.parametrize("mutation", ["time-bool", "time-value", "attempt-bool"])
def test_measured_caps_serializer_does_not_allow_changed_caps(mutation):
    value = json.loads((FLIGHT / "plan.json").read_bytes())["capture_limits"]
    changed = copy.deepcopy(value)
    if mutation == "time-bool":
        changed["settle_seconds"] = True
        with pytest.raises(ValueError): carry._measured_caps(changed)
    else:
        changed["settle_seconds" if mutation == "time-value" else "max_attempts"] = 3 if mutation == "time-value" else True
        assert carry._measured_caps(changed) != carry._measured_caps(value)


@pytest.mark.parametrize("mutation", ["defended", "extra", "schema", "numeric-bool"])
def test_actual_ordinary_native_condition_refuses_defense_or_field_drift(mutation):
    from qcsd_lab import rapid_fixed_condition_target as target
    plan = json.loads((FLIGHT / "plan.json").read_bytes())
    deep = json.loads((FLIGHT / "undefended-deep-verification.json").read_bytes())
    result = Path(plan["execution_root"]) / "results" / Path(deep["root"]).relative_to("/lab/results")
    experiment = json.loads((result / "experiment.json").read_bytes())
    run = json.loads((result / experiment["samples"][0]["path"] / "neqo/run.json").read_bytes())
    assert target.condition_identity(experiment["configuration"], run, "undefended")["resolved_configuration"] == run["resolved_configuration"]
    if mutation == "defended": run["resolved_configuration"]["defense"] = {"kind": "tamaraw"}
    elif mutation == "extra": run["resolved_configuration"]["unknown_native_field"] = 0
    elif mutation == "schema": run["resolved_configuration"]["schema_version"] = 3
    else: run["resolved_configuration"]["schema_version"] = True
    with pytest.raises(ValueError, match="defended or malformed"):
        target.condition_identity(experiment["configuration"], run, "undefended")


def test_genuine_ordinary_condition_retains_every_native_value():
    from qcsd_lab import rapid_fixed_condition_target as target
    plan = json.loads((FLIGHT / "plan.json").read_bytes())
    deep = json.loads((FLIGHT / "undefended-deep-verification.json").read_bytes())
    result = Path(plan["execution_root"]) / "results" / Path(deep["root"]).relative_to("/lab/results")
    experiment = json.loads((result / "experiment.json").read_bytes())
    run = json.loads((result / experiment["samples"][0]["path"] / "neqo/run.json").read_bytes())
    original = target.condition_identity(experiment["configuration"], run, "undefended")
    changed = copy.deepcopy(run)
    changed["resolved_configuration"]["max_stream_data_excess"] += 1
    assert target.condition_identity(experiment["configuration"], changed, "undefended") != original
    changed["resolved_configuration"] = None
    assert target.condition_identity(experiment["configuration"], changed, "undefended") != original
