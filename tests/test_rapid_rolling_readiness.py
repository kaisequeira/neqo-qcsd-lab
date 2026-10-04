"""Offline reopening of recorded canaries; no image or scientific pass is produced."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_rolling_readiness as readiness, verification

PROJECT = Path(__file__).resolve().parents[1]


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else encoded(value))
    return path


def ref(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def operation(directory, name, command, start, end):
    logs = directory / "logs"
    stdout = write(logs / (name + ".stdout.log"), b"actual child stdout\n")
    stderr = write(logs / (name + ".stderr.log"), b"")
    started = write(logs / (name + "-started.json"), {"command": command, "cwd": None, "started_at": start})
    completed = write(logs / (name + "-completed.json"), {
        "returncode": 0, "elapsed_seconds": 1.0, "completed_at": end,
        "stdout_sha256": ref(stdout)["sha256"], "stderr_sha256": ref(stderr)["sha256"]})
    return {"started": ref(started), "completed": ref(completed), "stdout": ref(stdout), "stderr": ref(stderr)}


@pytest.fixture
def canary(tmp_path, monkeypatch):
    # These are synthetic operation/evidence records, not a real image deep pass.
    # All paths and input data are local; the validator itself is unmodified.
    directory, clean, execution = (tmp_path / name for name in ("canary", "clean", "execution"))
    for root in (directory, clean, execution):
        root.mkdir()
    source = {"image_digest": None, "lab_commit": "a" * 40, "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(), "neqo_commit": "b" * 40,
        "neqo_pinned_commit": "b" * 40, "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest()}
    source_path = write(tmp_path / "exported-source.json", source)
    client = write(tmp_path / "installed-client", b"synthetic installed binary identity\n")
    for root in (clean, execution):
        write(root / "qcsd-lab", b"synthetic immutable launcher\n")
    traffic = {}
    for key, (relative, _) in readiness.TRAFFIC_FILES.items():
        data = (PROJECT / relative).read_bytes()
        for root in (clean, execution):
            write(root / relative, data)
        traffic[key] = hashlib.sha256(data).hexdigest()
    inventory = {"qcsd-lab": {"sha256": ref(clean / "qcsd-lab")["sha256"], "executable": False}}
    inventory_path = write(directory / "source-inventory.json", inventory)
    image = "sha256:" + "c" * 64
    canonical = {"source": source, "collection_image_digest": image,
        "installed_client_sha256": ref(client)["sha256"], "installed_byte_verification_completed": True,
        "exported_source_manifest_sha256": ref(source_path)["sha256"],
        "source_inventory_sha256": ref(inventory_path)["sha256"],
        "checks": {"collection": {"source": source, "image_digest": image,
            "client_sha256": ref(client)["sha256"], "qualification_implementation_sha256": "d" * 64}}}
    canonical_path = write(directory / "canonical-runtime.json", canonical)
    resources = [{"id": 0, "url": "https://example.com/", "type": "Document", "depends_on": []},
                 {"id": 1, "url": "https://example.org/resource", "type": "Other", "depends_on": [0]}]
    expected = [{"resource_id": row["id"], "status": 200, "bytes": 10 + row["id"],
                 "body_sha256": str(row["id"] + 1) * 64} for row in resources]
    manifest = {"resources": resources, "preparation": {
        "approved_origins": ["https://example.com", "https://example.org"], "expected_responses": expected}}
    workload = "test-full-graph"
    manifest_path = write(execution / "config/workloads" / (workload + ".json"), manifest)
    original = write(directory / "lineage/original-manifest.json", manifest)
    graph = {"resource_count": 2, "resource_records_sha256": hashlib.sha256(encoded(resources)).hexdigest(),
             "origins": ["https://example.com", "https://example.org"]}
    mode, name = "undefended", "rapid-diagnostic-test-undefended"
    campaign_path = write(execution / "config/campaigns" / (name + ".yml"), b"synthetic frozen campaign\n")
    limits = {"max_response_bytes": 1048576, "timeout_seconds": 120}
    capture_command = ["env", "QCSD_LAB_COLLECTION_IMAGE=" + image,
        "QCSD_RAPID_IMAGE_SOURCE_QCSD=" + str(clean / "qcsd-lab"),
        "QCSD_RAPID_DNS_RECEIPT_PATH=" + str(directory / "dns-receipts/undefended.json"),
        str(execution / "qcsd-lab"), "run", str(campaign_path)]
    recipe, helper = write(tmp_path / "recipe.py", b"synthetic bound image verifier\n"), write(tmp_path / "helper.py", b"synthetic helper\n")
    plan = {"canonical_runtime": canonical, "canonical_runtime_sha256": ref(canonical_path)["sha256"],
        "execution_root": str(execution), "clean_runtime_root": str(clean),
        "expected_lab_commit": source["lab_commit"], "expected_native_commit": source["neqo_commit"],
        "traffic_hashes": traffic, "selection_sha256": "e" * 64,
        "workload_id": workload, "workload_sha256": ref(manifest_path)["sha256"],
        "original_workload_sha256": ref(original)["sha256"], "full_graph": graph,
        "name": "test", "recipe_sha256": ref(recipe)["sha256"], "helper_sha256": ref(helper)["sha256"],
        "campaigns": [{"mode": mode, "name": name, "visits": 1, "limits": limits,
            "campaign_relative": str(campaign_path.relative_to(execution)),
            "campaign_sha256": ref(campaign_path)["sha256"], "run_argv": capture_command}]}
    plan_path = write(directory / "plan.json", plan)
    result = execution / "results" / name / "20261004T000000Z"
    for subdir in ("inputs", "samples", "failures"):
        (result / subdir).mkdir(parents=True)
    input_path = write(result / "inputs/workloads" / (workload + ".json"), manifest)
    sample_path = "samples/test/as-defined/visit-000/undefended"
    run = {"completion_status": "complete", "error": None, "error_class": None,
        "endpoints": [{"origin": origin} for origin in graph["origins"]],
        "responses": [{**row, "url": resources[row["resource_id"]]["url"],
            "complete": True, "outcome": "succeeded"} for row in expected]}
    write(result / sample_path / "neqo/run.json", run)
    experiment = {"name": name, "purpose": "smoke", "status": "complete",
        "source": {**source, "image_digest": image},
        "summary": {"planned": 1, "accepted": 1, "failed": 0, "passed": True},
        "configuration": {"campaign_sha256": ref(campaign_path)["sha256"], "limits": limits,
            "profile": "research-1200", "request_policies": ["as-defined"],
            "defenses": [{"name": mode}], "workloads": [{"id": workload, "sha256": ref(manifest_path)["sha256"],
                "manifest": str(input_path.relative_to(result)), "visits": 1}]},
        "samples": [{"state": "accepted", "defense": mode, "workload_id": workload,
            "request_policy": "as-defined", "visit": 0, "path": sample_path}]}
    write(result / "experiment.json", experiment)
    files = verification.authoritative_files(result)
    seal = write(result / "evidence.sha256", "".join(ref(path)["sha256"] + "  " + relative + "\n"
        for relative, path in files.items()).encode())
    dns = write(directory / "dns-receipts/undefended.json", {"schema_version": 1, "campaign": name,
        "hosts": [["example.com", "93.184.216.34"], ["example.org", "93.184.216.35"]]})
    identity = [(row["resource_id"], row["status"], row["bytes"], row["body_sha256"], "succeeded") for row in expected]
    receipt = {"valid": True, "mode": mode, "purpose": "smoke", "status": "complete", "name": name,
        "accepted_samples": 1, "authoritative_files": len(files), "source": source,
        "plan_sha256": ref(plan_path)["sha256"], "canonical_runtime_sha256": ref(canonical_path)["sha256"],
        "selection_sha256": plan["selection_sha256"], "workload_sha256": ref(manifest_path)["sha256"],
        "root": "/lab/results/" + name + "/" + result.name,
        "experiment_sha256": ref(result / "experiment.json")["sha256"], "evidence_index_sha256": ref(seal)["sha256"],
        "full_graph": graph, "dns_receipt_sha256": ref(dns)["sha256"],
        "response_identity_sha256": hashlib.sha256(encoded(identity)).hexdigest(),
        "completed_at": "2026-10-04T00:00:04+00:00", **readiness.ZERO}
    receipt_path = write(directory / "undefended-deep-verification.json", receipt)
    deep_command = ["docker", "run", "--rm", "--name", "qcsd-v12-test-verify-image", "--network", "none",
        "--user", "1000:1000", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--env", "QCSD_LAB_IMAGE_DIGEST=" + image, "--env", "QCSD_LAB_ROOT=/lab",
        "--env", "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json",
        "--env", "QCSD_PUBLIC_ORIGIN_ONLY=1", "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--volume", str(clean) + ":/runtime-src:ro", "--volume", str(execution) + ":/lab:ro",
        "--volume", str(directory) + ":/diagnostic:rw", "--volume", str(recipe) + ":/recipe.py:ro",
        "--volume", str(helper) + ":/helpers.py:ro", "--workdir", "/lab", "--entrypoint", "/opt/qcsd-venv/bin/python3",
        image, "-I", "-B", "/recipe.py", "verify-image", "--plan", "/diagnostic/plan.json",
        "--plan-sha256", ref(plan_path)["sha256"], "--mode", mode, "--result", receipt["root"]]
    reference = {"schema_version": 1, "plan": ref(plan_path), "deep_receipt": ref(receipt_path),
        "capture": operation(directory, "undefended-capture", capture_command,
            "2026-10-04T00:00:01+00:00", "2026-10-04T00:00:02+00:00"),
        "deep": operation(directory, "undefended-deep", deep_command,
            "2026-10-04T00:00:03+00:00", "2026-10-04T00:00:05+00:00")}
    runtime = {"runtime_source_root": str(clean), "module_root": str(clean), "execution_root": str(execution),
        "source_manifest": str(source_path), "client_binary": str(client),
        "base_launcher": str(clean / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "collection_image_digest": image}
    monkeypatch.setattr(verification, "verify_result", lambda *a, **kw: pytest.fail("host invoked fresh deep verifier"))
    return SimpleNamespace(reference=reference, runtime=runtime, directory=directory, result=result,
        plan=plan, receipt=receipt, plan_path=plan_path, receipt_path=receipt_path, manifest=manifest,
        source_path=source_path, client=client, experiment=experiment, sample_path=sample_path)


def check(canary, mode="undefended"):
    return readiness.validate_canary(canary.reference, runtime=canary.runtime, mode=mode)


def test_reopens_one_mode_and_never_claims_fresh_deep_or_scientific_credit(canary):
    result = check(canary)
    assert result["recorded_image_deep_reopened"] is True
    assert result["fresh_deep_verification_performed"] is False
    assert result["full_graph"]["resource_count"] == 2
    assert result["source"]["image_digest"] == canary.runtime["collection_image_digest"]
    assert all(result[key] == value for key, value in readiness.ZERO.items())


@pytest.mark.parametrize("field", ["scientific_credit", "accepted_samples", "valid", "mode", "status"])
def test_rehashed_receipt_cannot_replace_a_completed_setting(canary, field):
    value = copy.deepcopy(canary.receipt)
    value[field] = {"scientific_credit": True, "accepted_samples": 0, "valid": False,
        "mode": "buflo", "status": "incomplete"}[field]
    write(canary.receipt_path, value)
    canary.reference["deep_receipt"] = ref(canary.receipt_path)
    with pytest.raises(ValueError):
        check(canary)


@pytest.mark.parametrize("path", ["experiment.json", "inputs/workloads/test-full-graph.json",
                                 "samples/test/as-defined/visit-000/undefended/neqo/run.json"])
def test_any_bound_result_byte_change_rejects(canary, path):
    target = canary.result / path
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="SHA-256"):
        check(canary)


@pytest.mark.parametrize("extra", [False, True])
def test_exact_authoritative_seal_coverage_rejects_missing_or_extra(canary, extra):
    if extra:
        write(canary.result / "failures/unlisted.json", {})
    else:
        (canary.result / canary.sample_path / "neqo/run.json").unlink()
    with pytest.raises(ValueError, match="exact authoritative"):
        check(canary)


@pytest.mark.parametrize("field", ["lab_commit", "neqo_commit", "lab_dirty"])
def test_current_source_is_not_a_similarity_bridge(canary, field):
    source = json.loads(canary.source_path.read_bytes())
    source[field] = True if field == "lab_dirty" else "f" * 40
    write(canary.source_path, source)
    with pytest.raises(ValueError, match="source"):
        check(canary)


def test_current_installed_client_identity_must_equal_canary(canary):
    canary.client.write_bytes(b"a different client")
    with pytest.raises(ValueError, match="client"):
        check(canary)


def test_current_collection_image_must_equal_canary(canary):
    canary.runtime["collection_image_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError, match="image"):
        check(canary)


@pytest.mark.parametrize("operation_name", ["capture", "deep"])
def test_actual_child_nonzero_rejects_even_a_passing_receipt(canary, operation_name):
    reference = canary.reference[operation_name]
    path = Path(reference["completed"]["path"])
    value = json.loads(path.read_bytes())
    value["returncode"] = 1
    write(path, value)
    reference["completed"] = ref(path)
    with pytest.raises(ValueError, match="successful actual"):
        check(canary)


def test_raw_operation_log_mutation_rejects(canary):
    Path(canary.reference["deep"]["stderr"]["path"]).write_bytes(b"changed error\n")
    with pytest.raises(ValueError, match="SHA-256"):
        check(canary)


@pytest.mark.parametrize("replacement", ["network", "image", "mount", "mode"])
def test_rehashed_deep_transport_cannot_change_runtime_or_mode(canary, replacement):
    reference = canary.reference["deep"]
    path = Path(reference["started"]["path"])
    value = json.loads(path.read_bytes())
    argv = value["command"]
    if replacement == "network":
        argv[argv.index("--network") + 1] = "host"
    elif replacement == "image":
        argv[argv.index("-I") - 1] = "sha256:" + "f" * 64
    elif replacement == "mount":
        argv[argv.index("--volume") + 1] = str(canary.directory) + ":/runtime-src:rw"
    else:
        argv[argv.index("--mode") + 1] = "buflo"
    write(path, value)
    reference["started"] = ref(path)
    with pytest.raises(ValueError, match="commands"):
        check(canary)


def test_missing_setting_is_not_satisfied_by_baseline(canary):
    with pytest.raises(ValueError, match="setting"):
        check(canary, "buflo")


def test_evidence_reference_cannot_follow_symlinks(canary):
    link = canary.directory / "receipt-link.json"
    link.symlink_to(canary.receipt_path)
    canary.reference["deep_receipt"] = {**ref(canary.receipt_path), "path": str(link)}
    with pytest.raises(ValueError, match="symlinks"):
        check(canary)


@pytest.mark.parametrize("field", ["accepted_samples", "authoritative_files"])
def test_boolean_receipt_counts_are_not_integer_proof(canary, field):
    value = copy.deepcopy(canary.receipt)
    value[field] = True
    write(canary.receipt_path, value)
    canary.reference["deep_receipt"] = ref(canary.receipt_path)
    with pytest.raises(ValueError):
        check(canary)


def test_resealed_missing_native_resource_cannot_become_full_graph_proof(canary):
    path = canary.result / canary.sample_path / "neqo/run.json"
    run = json.loads(path.read_bytes())
    run["responses"].pop()
    write(path, run)
    files = verification.authoritative_files(canary.result)
    seal = write(canary.result / "evidence.sha256", "".join(ref(item)["sha256"] + "  " + relative + "\n"
        for relative, item in files.items()).encode())
    receipt = copy.deepcopy(canary.receipt)
    receipt["evidence_index_sha256"] = ref(seal)["sha256"]
    write(canary.receipt_path, receipt)
    canary.reference["deep_receipt"] = ref(canary.receipt_path)
    with pytest.raises(ValueError, match="omits a full-graph resource"):
        check(canary)


def test_denies_unknown_reference_keys_and_boolean_schema(canary):
    for changed in ({**canary.reference, "caller_passed": True}, {**canary.reference, "schema_version": True}):
        with pytest.raises(ValueError, match="reference"):
            readiness.validate_canary(changed, runtime=canary.runtime, mode="undefended")


@pytest.fixture
def equivalent(canary, tmp_path):
    clean, execution = (Path(canary.runtime[key]) for key in ("runtime_source_root", "execution_root"))
    relatives = {"src/qcsd_lab/" + name + ".py" for names in readiness.DEPENDENCY_FILES.values() for name in names}
    relatives.update(readiness.STATIC_MEASUREMENT_FILES)
    relatives.update({"qcsd-lab", "src/qcsd_lab/prepare.py"})
    for relative in relatives:
        for root in (clean, execution):
            write(root / relative, (PROJECT / relative).read_bytes())
    for root in (clean, execution):
        write(root / "neqo-qcsd/Cargo.lock", b"synthetic exact Native lock\n")
        write(root / "neqo-qcsd/src/client.rs", b"synthetic exact Native source\n")
        write(root / "src/qcsd_lab/cdp_targets.py", b"old browser-only producer\n")
    inventory_path = write(canary.directory / "source-inventory.json", readiness._inventory(clean))
    canary.plan["canonical_runtime"]["source_inventory_sha256"] = ref(inventory_path)["sha256"]
    canonical_path = write(canary.directory / "canonical-runtime.json", canary.plan["canonical_runtime"])
    canary.plan["canonical_runtime_sha256"] = ref(canonical_path)["sha256"]
    write(canary.plan_path, canary.plan)
    canary.reference["plan"] = ref(canary.plan_path)
    canary.receipt["plan_sha256"] = ref(canary.plan_path)["sha256"]
    canary.receipt["canonical_runtime_sha256"] = ref(canonical_path)["sha256"]
    write(canary.receipt_path, canary.receipt)
    canary.reference["deep_receipt"] = ref(canary.receipt_path)
    start_path = Path(canary.reference["deep"]["started"]["path"])
    start = json.loads(start_path.read_bytes())
    argv = start["command"]
    argv[argv.index("--plan-sha256") + 1] = ref(canary.plan_path)["sha256"]
    write(start_path, start)
    canary.reference["deep"]["started"] = ref(start_path)
    current_root = tmp_path / "current-source"
    shutil.copytree(clean, current_root)
    # Browser production and docs can change without touching replay science.
    write(current_root / "src/qcsd_lab/cdp_targets.py", b"new browser-only producer\n")
    write(current_root / "README.md", b"new unrelated documentation\n")
    current_source = json.loads(canary.source_path.read_bytes())
    current_source["lab_commit"] = "f" * 40
    current_source_path = write(tmp_path / "current-source.json", current_source)
    current_client = write(tmp_path / "current-client", canary.client.read_bytes())
    runtime = {**canary.runtime, "runtime_source_root": str(current_root), "module_root": str(current_root),
        "execution_root": str(current_root), "source_manifest": str(current_source_path),
        "client_binary": str(current_client), "base_launcher": str(current_root / "qcsd-lab"),
        "host_launcher": str(current_root / "qcsd-lab"), "collection_image_digest": "sha256:" + "f" * 64}
    current_inventory_path = write(tmp_path / "current-inventory.json", readiness._inventory(current_root))
    capsule_path = tmp_path / "equivalence.json"
    readiness.publish_source_equivalence(canary.reference, capsule_path, original_runtime=canary.runtime,
        runtime=runtime, current_inventory=ref(current_inventory_path), mode="undefended")
    capsule = json.loads(capsule_path.read_bytes())
    reference = {**canary.reference, "schema_version": 2, "source_equivalence": ref(capsule_path)}
    return SimpleNamespace(canary=canary, runtime=runtime, reference=reference, capsule=capsule,
        capsule_path=capsule_path, current_root=current_root, current_inventory_path=current_inventory_path)


def eqcheck(equivalent):
    return readiness.validate_canary(equivalent.reference, runtime=equivalent.runtime, mode="undefended")


def eqrefresh(equivalent):
    write(equivalent.current_inventory_path, readiness._inventory(equivalent.current_root))
    equivalent.capsule["current_inventory"] = ref(equivalent.current_inventory_path)
    write(equivalent.capsule_path, equivalent.capsule)
    equivalent.reference["source_equivalence"] = ref(equivalent.capsule_path)


def test_explicit_equivalence_preserves_original_image_source_and_credit(equivalent):
    result = eqcheck(equivalent)
    assert result["source"]["lab_commit"] == "a" * 40
    assert result["source"]["image_digest"] == equivalent.canary.runtime["collection_image_digest"]
    assert result["authority_source"]["lab_commit"] == "f" * 40
    assert result["authority_source"]["image_digest"] == equivalent.runtime["collection_image_digest"]
    assert result["native_file_count"] == 3  # two fixture files plus the real immutable research profile
    assert set(result["dependency_groups"]) == {"measurement", "acceptance", "chaff", "traffic", "native"}
    assert result["fresh_deep_verification_performed"] is False
    assert result["formal_accepted_trace_count"] == result["site_credit"] == 0
    with pytest.raises(ValueError, match="source"):
        readiness.validate_canary(equivalent.canary.reference, runtime=equivalent.runtime, mode="undefended")


@pytest.mark.parametrize("relative", ["neqo-qcsd/src/client.rs", "neqo-qcsd/unlisted.rs",
    "src/qcsd_lab/fidelity.py", "src/qcsd_lab/chaff_qualification.py", "uv.lock", "qcsd-lab"])
def test_equivalence_rejects_actual_protected_bytes_even_after_inventory_rebinding(equivalent, relative):
    path = equivalent.current_root / relative
    write(path, path.read_bytes() + b"\n# changed protected bytes\n" if path.exists() else b"hidden Native code\n")
    eqrefresh(equivalent)
    with pytest.raises(ValueError, match="protected dependencies"):
        eqcheck(equivalent)


def test_equivalence_detects_unlisted_actual_native_before_group_comparison(equivalent):
    write(equivalent.current_root / "neqo-qcsd/unlisted.rs", b"hidden Native code\n")
    with pytest.raises(ValueError, match="exact runtime source bytes"):
        eqcheck(equivalent)


def test_equivalence_binds_actual_client_not_only_native_source(equivalent):
    Path(equivalent.runtime["client_binary"]).write_bytes(b"different installed binary\n")
    with pytest.raises(ValueError, match="client"):
        eqcheck(equivalent)


def test_equivalence_cannot_drop_a_dependency_group(equivalent):
    equivalent.capsule["dependency_groups"].pop("acceptance")
    write(equivalent.capsule_path, equivalent.capsule)
    equivalent.reference["source_equivalence"] = ref(equivalent.capsule_path)
    with pytest.raises(ValueError, match="reopened source roles"):
        eqcheck(equivalent)


@pytest.mark.parametrize("unit", ["_run_neqo", "NEQO_PROVENANCE_KEYS"])
def test_equivalence_binds_qualification_subprocess_and_provenance_units(equivalent, unit):
    path = equivalent.current_root / "src/qcsd_lab/prepare.py"
    raw = path.read_bytes()
    if unit == "_run_neqo":
        old = b"run(measured_command, log=log, check=False, timeout=host_timeout)"
        new = b"run(measured_command, log=log, check=True, timeout=host_timeout)"
    else:
        old, new = b'    "migration_commit",\n', b'    "wrong_migration_commit",\n'
    assert raw.count(old) == 1
    write(path, raw.replace(old, new))
    eqrefresh(equivalent)
    with pytest.raises(ValueError, match="chaff"):
        eqcheck(equivalent)


def test_equivalence_allows_browser_only_prepare_definition_without_recursive_discovery(equivalent):
    path = equivalent.current_root / "src/qcsd_lab/prepare.py"
    write(path, path.read_bytes() + b"\ndef prospective_browser_only_fixture():\n    return 'new browser code'\n")
    eqrefresh(equivalent)
    rebuilt = readiness.build_source_equivalence(equivalent.canary.reference,
        original_runtime=equivalent.canary.runtime, runtime=equivalent.runtime,
        current_inventory=ref(equivalent.current_inventory_path), mode="undefended")
    rebuilt["published_at"] = equivalent.capsule["published_at"]
    write(equivalent.capsule_path, rebuilt)
    equivalent.reference["source_equivalence"] = ref(equivalent.capsule_path)
    assert eqcheck(equivalent)["source"]["lab_commit"] == "a" * 40


def test_equivalence_only_projects_the_declared_rolling_shell_regions(equivalent):
    path = equivalent.current_root / "qcsd-lab"
    raw = path.read_bytes()
    marker = b"rapid_v2_diagnostic_pattern="
    assert raw.count(marker) == 1
    offset = raw.index(b"\n", raw.index(marker)) + 1
    write(path, raw[:offset] + b"# prospective rolling selector only\n" + raw[offset:])
    eqrefresh(equivalent)
    rebuilt = readiness.build_source_equivalence(equivalent.canary.reference,
        original_runtime=equivalent.canary.runtime, runtime=equivalent.runtime,
        current_inventory=ref(equivalent.current_inventory_path), mode="undefended")
    rebuilt["published_at"] = equivalent.capsule["published_at"]
    assert rebuilt["shell_control_units"]["original"]["selector"] != rebuilt["shell_control_units"]["current"]["selector"]
    write(equivalent.capsule_path, rebuilt)
    equivalent.reference["source_equivalence"] = ref(equivalent.capsule_path)
    assert eqcheck(equivalent)["native_file_count"] == 3


def test_equivalence_publisher_is_create_only_and_returns_actual_raw_hash(equivalent):
    previous = equivalent.capsule_path.read_bytes()
    with pytest.raises(FileExistsError, match="already claimed"):
        readiness.publish_source_equivalence(equivalent.canary.reference, equivalent.capsule_path,
            original_runtime=equivalent.canary.runtime, runtime=equivalent.runtime,
            current_inventory=ref(equivalent.current_inventory_path), mode="undefended")
    assert equivalent.capsule_path.read_bytes() == previous
    result = eqcheck(equivalent)
    assert result["source_equivalence_sha256"] == hashlib.sha256(previous).hexdigest()
    assert result["source_equivalence_published_at"] == equivalent.capsule["published_at"]


def test_qualification_subprocess_globals_cannot_be_shadowed_by_browser_changes(equivalent):
    path = equivalent.current_root / "src/qcsd_lab/prepare.py"
    write(path, path.read_bytes() + b"\ndef run(*args, **kwargs):\n    return None\n")
    eqrefresh(equivalent)
    with pytest.raises(ValueError, match="shadows a protected"):
        eqcheck(equivalent)


@pytest.mark.parametrize("role", ["original", "current"])
def test_equivalence_publisher_cannot_modify_its_frozen_source_inventory(equivalent, role):
    root = (Path(equivalent.canary.runtime["runtime_source_root"])
            if role == "original" else equivalent.current_root)
    output = root / "nested/equivalence.json"
    before = readiness._inventory(root)
    with pytest.raises(ValueError, match="outside both frozen Source"):
        readiness.publish_source_equivalence(equivalent.canary.reference, output,
            original_runtime=equivalent.canary.runtime, runtime=equivalent.runtime,
            current_inventory=ref(equivalent.current_inventory_path), mode="undefended")
    assert not output.parent.exists()
    assert readiness._inventory(root) == before
    assert eqcheck(equivalent)["source_equivalence_sha256"] == ref(equivalent.capsule_path)["sha256"]


def test_readiness_mount_roots_cover_original_records_exports_and_recipe(canary):
    roots = readiness.readiness_mount_roots(canary.reference, runtime=canary.runtime, mode="undefended")
    assert roots == sorted({canary.directory, Path(canary.runtime["runtime_source_root"]),
                            Path(canary.runtime["execution_root"]), canary.source_path.parent})
    for role in ("capture", "deep"):
        assert all(any(Path(item["path"]).is_relative_to(root) for root in roots)
                   for item in canary.reference[role].values())
    assert any(canary.result.is_relative_to(root) for root in roots)
    assert all(root.is_dir() and not root.is_symlink() for root in roots)


def test_readiness_mount_roots_reopen_both_equivalence_source_roles(equivalent):
    roots = readiness.readiness_mount_roots(equivalent.reference, runtime=equivalent.runtime, mode="undefended")
    assert equivalent.current_root in roots
    assert Path(equivalent.canary.runtime["runtime_source_root"]) in roots
    assert equivalent.canary.directory in roots
    assert equivalent.capsule_path.parent in roots
    assert equivalent.current_inventory_path.parent in roots


def test_readiness_mount_roots_reject_changed_source_before_deriving_transport(canary):
    source = json.loads(canary.source_path.read_bytes())
    source["lab_commit"] = "f" * 40
    write(canary.source_path, source)
    with pytest.raises(ValueError, match="current source"):
        readiness.readiness_mount_roots(canary.reference, runtime=canary.runtime, mode="undefended")


def test_readiness_mount_roots_reject_unbound_or_linked_runtime_directory(canary, tmp_path):
    unrelated = tmp_path / "unbound-module"
    linked = tmp_path / "linked-module"
    unrelated.mkdir()
    linked.symlink_to(unrelated, target_is_directory=True)
    for path in (tmp_path / "absent-module", linked):
        runtime = {**canary.runtime, "module_root": str(path)}
        with pytest.raises(ValueError, match="absent|symlinks"):
            readiness.readiness_mount_roots(canary.reference, runtime=runtime, mode="undefended")


def test_optional_actual_retained_baseline_reopens_without_docker(monkeypatch):
    selected = os.environ.get("QCSD_RETAINED_CANARY_ROOT")
    if selected is None:
        pytest.skip("set QCSD_RETAINED_CANARY_ROOT to explicitly select retained actual evidence")
    directory = Path(selected).resolve(strict=True)
    plan = json.loads((directory / "plan.json").read_bytes())
    clean, execution, runtime_root = (Path(plan[key]) for key in ("clean_runtime_root", "execution_root", "runtime_build_root"))
    runtime = {"runtime_source_root": str(clean), "module_root": str(clean), "execution_root": str(execution),
        "source_manifest": str(runtime_root / "runtime-export/source.json"),
        "client_binary": str(runtime_root / "runtime-export/neqo-qcsd-client"),
        "base_launcher": str(clean / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "collection_image_digest": plan["canonical_runtime"]["collection_image_digest"]}
    reference = {"schema_version": 1, "plan": ref(directory / "plan.json"),
        "deep_receipt": ref(directory / "undefended-deep-verification.json")}
    for role in ("capture", "deep"):
        reference[role] = {key: ref(directory / "logs" / ("undefended-" + role + suffix))
            for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                                ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}
    monkeypatch.setattr(verification, "verify_result", lambda *a, **kw: pytest.fail("host requested deep replay"))
    result = readiness.validate_canary(reference, runtime=runtime, mode="undefended")
    assert result["full_graph"]["resource_count"] == plan["full_graph"]["resource_count"]
    assert result["workload_sha256"] == plan["workload_sha256"]
    assert result["recorded_image_deep_reopened"] is True
