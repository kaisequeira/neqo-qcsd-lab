"""HOST full-GET renewal/flight/rolling APIs; installed and network gates are synthetic."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from importlib import import_module
import shutil
import sys

import pytest

from qcsd_lab import rapid_selected_input_renewal as renewed
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import tamaraw_fixed_configuration as tamaraw
from qcsd_lab import application_response_policy as responses
from tests.test_selected_capture_input import (
    additive_case, selected_graph, REPOSITORY, load, write, qualifier_fixture,
)
from tests.test_selected_capture_amendment import flight
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture


def snapshots(case):
    runtime = case["runtime"]
    shutil.copytree(REPOSITORY / "src/qcsd_lab", Path(runtime["execution_root"]) / "src/qcsd_lab", dirs_exist_ok=True)
    shutil.copytree(REPOSITORY / "tools", Path(runtime["execution_root"]) / "tools", dirs_exist_ok=True)
    for name, relative in renewed.SOURCE_FILES.items():
        for key in ("runtime_source_root", "execution_root"):
            target = Path(runtime[key]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(Path(import_module("qcsd_lab." + name).__file__).read_bytes())
    return runtime


def publish(case, monkeypatch, mode):
    runtime = snapshots(case)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:12:30Z")
    path = case["new_study"] / "defended-renewal.json"
    fixed = tamaraw.POLICY if mode == "tamaraw" else None
    renewed.publish(case["new_enrollment"], runtime, path, mode=mode,
                    tamaraw_configuration_policy=fixed)
    return path, fixed


def canary(case, path, mode, fixed):
    directory = case["new_study"]
    plan = directory / "defended-canary-plan.json"
    write(plan, {renewed.FIELD: rolling._ref(path), "campaigns": [{"mode": mode}]})
    start = directory / "defended-capture-started.json"
    write(start, {"started_at": "2026-10-04T00:13:30Z"})
    reference = {"plan": rolling._ref(plan), "capture": {"started": rolling._ref(start)}}
    facts = {"authority_source": {**load(Path(case["runtime"]["source_manifest"])),
        "image_digest": case["runtime"]["collection_image_digest"]},
        "client_sha256": graph.digest(Path(case["runtime"]["client_binary"]).read_bytes()),
        "traffic_hashes": {key: digest for key, (_, digest) in rolling.lanes.TRAFFIC_FILES.items()},
        "application_body_identity_policy": responses.COMPLETE_APPLICATION_DELIVERY_POLICY}
    if fixed is not None:
        facts.update(tamaraw_configuration_policy=fixed,
                     tamaraw_configuration_sha256=tamaraw.configuration_sha256())
    return reference, facts


@pytest.mark.parametrize("mode", ["tamaraw", "cs-buflo"])
def test_current_full_get_to_flight_qualified_rolling_plan_preserves_admission(additive_case, monkeypatch, mode):
    case = additive_case
    retained = {p: p.read_bytes() for p in (case["new_enrollment"], case["second"]["prepared"],
        case["second"]["input"], case["second"]["raw"] / "native/run.json")}
    path, fixed = publish(case, monkeypatch, mode)
    value, _, _, _ = renewed.validate(path, enrollment=case["new_enrollment"], runtime=case["runtime"],
        mode=mode, tamaraw_configuration_policy=fixed)
    [row] = value["rows"]
    current = selected.reopen(row["current_manifest"])
    assert load(current)["resources"] == load(case["second"]["prepared"])["resources"]
    assert load(current)["preparation"]["data_role"] == selected.ROLE
    assert not value["scientific_credit"] and value["formal_accepted_trace_count"] == 0
    assert all(p.read_bytes() == raw for p, raw in retained.items())
    api = flight()
    result = api.selected_inputs(case["new_enrollment"], case["new_study"],
        selected_input_renewal=rolling._ref(path), runtime=case["runtime"], mode=mode,
        tamaraw_configuration_policy=fixed)
    assert result[2][0]["original_workload"] == rolling._ref(current)
    assert result[2][0]["full_graph"] == api.graph(load(current))
    qualifier = qualifier_fixture(case, monkeypatch)
    target = Path(case["runtime"]["workload_root"]) / current.name
    target.write_bytes(current.read_bytes())  # synthetic qualifier helper copied the old fixture
    reference, facts = canary(case, path, mode, fixed)
    monkeypatch.setattr(readiness, "validate_canary", lambda *a, **k: facts)
    plan = case["new_study"] / "defended-plan.json"
    rolling.publish_plan(case["new_study"], case["new_enrollment"], qualifier, plan,
        readiness={mode: reference}, selected_input_renewal=path,
        application_body_identity_policy=responses.COMPLETE_APPLICATION_DELIVERY_POLICY,
        tamaraw_configuration_policy=fixed)
    spec = rolling.capture_spec(case["new_study"], case["new_enrollment"], qualifier, plan)
    sites, payload = rolling.verify_capture_plan(spec)
    assert payload[renewed.FIELD] == rolling._ref(path)
    assert sites[0].workload_sha256 == rolling._ref(current)["sha256"]
    assert "static_capture_amendment" not in payload and ordinary.FIELD not in payload
    assert any(path.is_relative_to(root) for root in rolling.enrollment_roots(spec))
    spec_path = case["new_study"] / "defended-spec.json"
    rolling._write_spec(spec_path, spec)
    facts_path = case["new_study"] / "controlled-canary-facts.json"
    write(facts_path, facts)
    # The same public verifier works when imports come from the execution copy.
    from subprocess import run
    program = ("import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
        "from qcsd_lab import rapid_selected_input_renewal as r;"
        "r.selected._legacy_source=lambda root,ref:json.loads(Path(ref['path']).read_bytes());"
        "p=Path(sys.argv[2]);v=json.loads(p.read_bytes());"
        "r.validate(p,enrollment=Path(v['enrollment']['path']),runtime=v['runtime'],mode=v['mode'],"
        "tamaraw_configuration_policy=v['tamaraw_configuration_policy']);"
        "from qcsd_lab import rapid_rolling_readiness as ready;"
        "r.rolling.validate_named_qualification_set_manifest=lambda *a,**k:None;"
        "facts=json.loads(Path(sys.argv[4]).read_bytes());ready.validate_canary=lambda *a,**k:facts;"
        "r.rolling.verify_capture_plan(r.lanes.load_capture_spec(Path(sys.argv[3])));"
        "assert Path(r.__file__).is_relative_to(Path(sys.argv[1]))")
    check = run([sys.executable, "-I", "-B", "-c", program,
        str(Path(case["runtime"]["execution_root"]) / "src"), str(path), str(spec_path), str(facts_path)], capture_output=True)
    assert check.returncode == 0, check.stderr.decode()


def test_rehashed_metadata_graph_mode_source_and_runtime_mutations_rejected(additive_case, monkeypatch):
    case = additive_case
    path, fixed = publish(case, monkeypatch, "tamaraw")
    original = path.read_bytes()
    for field, value in (("mode", "cs-buflo"), ("tamaraw_configuration_policy", None),
            ("control_sources", {}), ("formal_accepted_trace_count", 1), ("runtime_artifacts", {}),
            ("capture_limits", {}), ("enrollment", rolling._ref(case["second"]["input"]))):
        changed = load(path)
        changed[field] = value
        write(path, changed)
        with pytest.raises(ValueError):
            renewed.validate(path, enrollment=case["new_enrollment"], runtime=case["runtime"],
                mode="tamaraw", tamaraw_configuration_policy=fixed)
        path.write_bytes(original)
    value = load(path)
    target = Path(case["runtime"]["workload_root"]) / (value["rows"][0]["workload_id"] + ".json")
    raw = target.read_bytes()
    for mutation in ("drop", "header", "edge", "role"):
        changed = load(target)
        if mutation == "drop": changed["resources"].pop()
        elif mutation == "header": changed["resources"][-1]["headers"].append(["x-test", "changed"])
        elif mutation == "edge": changed["resources"][-1]["depends_on"] = []
        else: changed["preparation"]["data_role"] = ordinary.INPUT_TYPE
        write(target, changed)
        with pytest.raises(ValueError):
            renewed.validate(path, enrollment=case["new_enrollment"], runtime=case["runtime"],
                mode="tamaraw", tamaraw_configuration_policy=fixed)
        target.write_bytes(raw)
    source = Path(case["runtime"]["execution_root"]) / renewed.SOURCE_FILES["rapid_selected_input_renewal"]
    raw = source.read_bytes()
    source.write_bytes(raw + b"\n# different actual execution source\n")
    with pytest.raises(ValueError, match="actual current Source"):
        renewed.validate(path, enrollment=case["new_enrollment"], runtime=case["runtime"],
            mode="tamaraw", tamaraw_configuration_policy=fixed)
    source.write_bytes(raw)
    with pytest.raises(ValueError):
        ordinary.validate_renewal(path, case["new_enrollment"])


@pytest.mark.parametrize("mode,fixed", [("undefended", None), ("front", None), ("buflo", None),
    ("tamaraw", None), ("cs-buflo", tamaraw.POLICY), ("tamaraw", "unregistered")])
def test_condition_boundary_rejects_other_modes_and_settings(mode, fixed):
    with pytest.raises(ValueError): renewed._condition(mode, fixed)


def test_stale_original_direct_source_reissues_same_get_only(additive_case, monkeypatch):
    case = additive_case
    before = case["second"]["input"].read_bytes()
    current = case["new_study"] / "changed-app-policy.py"
    current.write_bytes(Path(responses.__file__).read_bytes() + b"\n# new consumer\n")
    monkeypatch.setattr(responses, "__file__", str(current))
    case["runtime"]["module_root"] = case["runtime"]["runtime_source_root"]
    with pytest.raises(ValueError): selected.validate_input(case["second"]["input"])
    path, fixed = publish(case, monkeypatch, "tamaraw")
    value = renewed.validate(path, enrollment=case["new_enrollment"], runtime=case["runtime"],
        mode="tamaraw", tamaraw_configuration_policy=fixed)[0]
    assert value["rows"][0]["current_input"] != selected.reference(case["second"]["input"])
    selected.validate_input(selected.reopen(value["rows"][0]["current_input"]))
    assert case["second"]["input"].read_bytes() == before


@pytest.fixture
def separated_stage_case(tmp_path, monkeypatch):
    # Keep immutable fixture inputs outside the prospective output namespace,
    # as the actual operator requires; do not weaken its disjointness checks.
    import tests.test_selected_capture_input as fixtures
    inner = tmp_path / "immutable-inputs"
    inner.mkdir()
    original_runtime = fixtures.runtime
    def runtime_with_separate_outputs(path):
        study, value = original_runtime(path)
        value["data_root"] = str(tmp_path)
        return study, value
    monkeypatch.setattr(fixtures, "runtime", runtime_with_separate_outputs)
    raw = actual_contract_fixture.__wrapped__(inner)
    complete = fixed_graph.__wrapped__(raw, inner, monkeypatch)
    selected_case = selected_graph.__wrapped__(complete, inner, monkeypatch)
    return additive_case.__wrapped__(selected_case, inner, monkeypatch)


@pytest.mark.parametrize("mode", ["tamaraw", "cs-buflo"])
def test_actual_portable_stage_finalize_and_host_plan_before_physical_gates(separated_stage_case, monkeypatch, mode):
    case, api = separated_stage_case, flight()
    runtime = snapshots(case)
    source = Path(runtime["runtime_source_root"])
    shutil.copytree(REPOSITORY / "src/qcsd_lab", source / "src/qcsd_lab", dirs_exist_ok=True)
    for relative in ("config", "neqo-qcsd"):
        shutil.copytree(Path(runtime["execution_root"]) / relative, source / relative, dirs_exist_ok=True)
    build = case["new_study"] / "controlled-runtime-build"
    (build / "image-context").mkdir(parents=True)
    shutil.copytree(source, build / "image-context/source")
    (build / "runtime-export").mkdir()
    (build / "runtime-export/source.json").write_bytes(Path(runtime["source_manifest"]).read_bytes())
    (build / "runtime-export/neqo-qcsd-client").write_bytes(Path(runtime["client_binary"]).read_bytes())
    inventory = {p.relative_to(source).as_posix(): {"sha256": graph.digest(p.read_bytes()),
        "executable": bool(p.stat().st_mode & 0o111)} for p in source.rglob("*") if p.is_file()}
    write(build / "source-inventory.json", inventory)
    canonical = {"source": load(Path(runtime["source_manifest"])),
        "collection_image_digest": runtime["collection_image_digest"],
        "source_inventory_sha256": graph.digest((build / "source-inventory.json").read_bytes())}
    write(build / "canonical-runtime.json", canonical)
    # Runtime/client installation is a declared synthetic HOST boundary.
    # Staging, renewal, finalization, graph transport and Source checks are real.
    monkeypatch.setattr(api, "checked_runtime", lambda args:
        (api.ref(build / "canonical-runtime.json"), canonical, source))
    monkeypatch.setattr(api, "host_imports", lambda clean: None)
    monkeypatch.setattr(receipts, "_now", lambda: "2026-10-04T00:12:30Z")
    fixed = tamaraw.POLICY if mode == "tamaraw" else None
    output = Path(runtime["data_root"]) / (mode + "-current-flight")
    args = SimpleNamespace(name=mode + "-current-flight", campaign_seed=71, mode=mode,
        python=Path(sys.executable), enrollment=case["new_enrollment"], study_root=case["new_study"],
        output=output, runtime_build_root=build, clean_runtime_root=source,
        canonical_sha256=api.digest(api.read(build / "canonical-runtime.json")),
        expected_lab_commit=canonical["source"]["lab_commit"],
        expected_native_commit=canonical["source"]["neqo_commit"],
        application_body_identity_policy=responses.COMPLETE_APPLICATION_DELIVERY_POLICY,
        tamaraw_configuration_policy=fixed, renew_selected_inputs=True)
    before = case["new_enrollment"].read_bytes()
    api.stage(args)
    setup_args = SimpleNamespace(setup=output / "setup.json", setup_sha256=api.ref(output / "setup.json")["sha256"])
    setup, _, _, _, bindings, _ = api.checked_setup(setup_args)
    assert renewed.FIELD in setup and "ordinary_renewal" not in setup
    assert (output / "lineage/admission-originals" / case["second"]["prepared"].name).read_bytes() == case["second"]["prepared"].read_bytes()
    assert bindings[0]["original_workload"] != rolling._ref(case["second"]["prepared"])
    api.finalize(setup_args)
    plan_args = SimpleNamespace(plan=output / "plan.json", plan_sha256=api.ref(output / "plan.json")["sha256"], command="preamble-image")
    plan, _, _ = api.checked_plan(plan_args)
    assert plan[renewed.FIELD] == setup[renewed.FIELD] and plan["reuse"] is None
    commands = load(output / "commands.json")
    assert "qualify" in commands and "--selected-input-renewal" in commands["plan"]
    assert list((output / "logs").iterdir()) == []
    assert case["new_enrollment"].read_bytes() == before
    # Exact planned installed verifier transport agrees before any launch.
    deep = api.image_argv(plan, output, "verify-image", "--mode", mode, "--result", "fixture-result")
    reconstructed = readiness._deep_command(plan, output, plan_args.plan_sha256, mode, "fixture-result", deep)
    assert reconstructed == deep
