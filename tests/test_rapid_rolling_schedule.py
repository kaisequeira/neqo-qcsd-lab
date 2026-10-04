"""Real validators on small closed runtime/120-response fixture records.

Runtime commands and their stdout are synthetic offline fixtures, not actual
Docker passes. Source bytes, named qualification, implementation contracts,
unchanged-input comparisons and all reopening/chronology checks are real.
"""
from __future__ import annotations

import ast
import copy
import json
import shutil
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_rolling_readiness as evidence
from qcsd_lab.util import load_json, sha256_bytes, sha256_file
from tests.test_rapid_capture_control_compatibility import runtime as implementation_runtime
from tests.test_rapid_rolling_schedule_source import source_bytes


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else evidence._encoded(value))
    return path


def ref(path):
    return {"path": str(path), "sha256": evidence._sha(path.read_bytes())}


def response_sidecar(path, name, implementation, image):
    # Reuse just the existing deterministic response fixture definitions. The
    # containing historical test module has eager unrelated fitting fixtures;
    # importing it would require those archives for this scheduling-only test.
    selected = {"_packet_log", "_statistics", "_response_v2_receipt",
                "_response_v2_epochs", "_response_only_v2_sidecar"}
    original = Path(__file__).with_name("test_chaff_qualification.py")
    nodes = [node for node in ast.parse(original.read_bytes()).body
             if isinstance(node, ast.FunctionDef) and node.name in selected]
    assert {node.name for node in nodes} == selected
    scope = {"qualification": qualification, "copy": copy, "Path": Path,
             "load_json": load_json, "sha256_bytes": sha256_bytes, "sha256_file": sha256_file,
             "_sidecar": lambda: {"qualification_source": {**implementation["source"], "image_digest": image},
                 "implementation_receipt": implementation,
                 "neqo_provenance": {"neqo_base_commit": "d" * 40, "published_qcsd_commit": "e" * 40,
                                     "migration_commit": implementation["source"]["neqo_commit"]}}}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(original), "exec"), scope)
    return scope["_response_only_v2_sidecar"](path, name)


def freeze_runtime(root, sources, execution, *, successor):
    clean = root.parent / (root.name + "-source")
    for name, raw in sources.items():
        write(clean / name, raw)
    shutil.copytree(clean, root / "image-context/source")
    inventory = evidence._inventory(clean)
    write(root / "source-inventory.json", inventory)
    client = write(root / "runtime-export/neqo-qcsd-client", b"synthetic-executable-client-fixture\n")
    client.chmod(0o700)
    copied = write(root / "image-context/neqo-qcsd-client", client.read_bytes())
    copied.chmod(0o700)
    runtime = implementation_runtime(sources, successor=successor)
    impl = runtime["qualification_implementation"]
    impl["neqo_qcsd_client"]["sha256"] = evidence._sha(client.read_bytes())
    impl["sha256"] = qualification._implementation_aggregate(impl)
    source = impl["source"]
    source_path = write(root / "runtime-export/source.json", source)
    proofs = {}
    canonical = {"scope": "actual-installed-runtime-bytes-not-live-study-qualification",
        "source": source, "checks": proofs, "installed_byte_verification_completed": True,
        "scientific_credit": False, "formal_accepted_trace_count": 0,
        "collection_image_digest": runtime["collection_image_digest"],
        "prepare_image_digest": "sha256:" + ("9" if successor else "8") * 64,
        "source_manifest": str(source_path), "client_binary": str(client),
        "exported_source_manifest_sha256": ref(source_path)["sha256"],
        "installed_client_sha256": ref(client)["sha256"],
        "source_inventory_sha256": ref(root / "source-inventory.json")["sha256"],
        "native_artifact_action": "new-cached-native-release-build",
        "verified_at": "2000-01-01T00:02:00+00:00", "actual_operation_completions": {}}
    recipe_files = {}
    for name in ("Collection.Dockerfile", "Prepare.Dockerfile", "generate_receipts.py", "verify_installed.py"):
        recipe_files[name] = ref(write(root / "image-context" / name, b"offline-declared-producer-fixture\n"))["sha256"]
    inputs = {"source": source, "source_inventory_sha256": canonical["source_inventory_sha256"],
        "cargo_lock_sha256": evidence._sha(sources["neqo-qcsd/Cargo.lock"]), "rust_archive_sha256": "7" * 64,
        "toolchain_image": "sha256:" + "6" * 64, "recipe_files": recipe_files,
        "collection_base_image": "sha256:" + "4" * 64, "prepare_base_image": "sha256:" + "5" * 64,
        "registry": str(root / "registry"), "git_cache": str(root / "git-cache"), "target": str(root / "target")}
    write(root / "build-inputs.json", inputs)
    write(root / "image-context/build-inputs.json", inputs)
    for role in ("collection", "prepare"):
        image = canonical[role + "_image_digest"]
        write(root / (role + "-image-id.txt"), (image + "\n").encode())
        proofs[role] = {"scope": "installed-runtime-byte-and-source-verification-only", "role": role,
            "image_digest": image, "source": source, "client_sha256": ref(client)["sha256"],
            "source_metadata_raw_sha256": ref(source_path)["sha256"],
            "qualification_implementation_sha256": impl["sha256"]}
    names = {"actual-runtime-export", "release-build"} | {
        f"{role}-{step}" for role in ("collection", "prepare")
        for step in ("base-alias", "base-before", "image-build", "base-after", "installed-verification")}
    for name in names:
        stdout = evidence._encoded(proofs[name.split("-")[0]]) if name.endswith("installed-verification") else b"offline-fixture\n"
        if name in {"release-build", "actual-runtime-export"}:
            if name == "release-build":
                command = ["docker", "run", "--rm", "--name", "qcsd-response-release-" + source["lab_commit"][:12],
                    "--network", "none", "--user", "1000:1000", "--volume", f"{root / 'image-context/source/neqo-qcsd'}:/source:ro",
                    "--volume", f"{inputs['registry']}:/usr/local/cargo/registry", "--volume", f"{inputs['git_cache']}:/usr/local/cargo/git",
                    "--volume", f"{inputs['target']}:/target", "--workdir", "/source", "--env", "CARGO_TARGET_DIR=/target",
                    "--env", "NEQO_QCSD_GIT_COMMIT=" + source["neqo_commit"], "--entrypoint", "/bin/sh",
                    inputs["toolchain_image"], "-c", "cargo build --locked --offline --release -p neqo-bin --features qcsd --bin neqo-qcsd-client"]
            else:
                command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "1000:1000",
                    "--volume", f"{root / 'runtime-export'}:/export:rw", "--entrypoint", "/opt/qcsd-venv/bin/python3",
                    canonical["prepare_image_digest"], "-I", "-c", schedule.EXPORT_PROGRAM]
            write(root / ("release-command.json" if name == "release-build" else "actual-runtime-export-command.json"), command)
        else:
            role, step = name.split("-", 1)
            alias = "qcsd-response-base-" + role + ":" + inputs[role + "_base_image"].removeprefix("sha256:")
            if step == "base-alias":
                command = ["docker", "image", "tag", inputs[role + "_base_image"], alias]
            elif step in {"base-before", "base-after"}:
                command = ["docker", "image", "inspect", "--format", "{{.Id}}", alias]
            elif step == "image-build":
                command = ["docker", "build", "--pull=false", "--network", "none", "--file", role.title() + ".Dockerfile",
                    "--iidfile", str(root / (role + "-image-id.txt")), "--tag", f"qcsd-{role}:response-policy-{source['lab_commit'][:12]}",
                    "--build-arg", "LAB_COMMIT=" + source["lab_commit"], "--build-arg", "NEQO_COMMIT=" + source["neqo_commit"], "."]
            else:
                image = canonical[role + "_image_digest"]
                command = ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000", "--env", "QCSD_LAB_IMAGE_DIGEST=" + image,
                    "--env", "QCSD_LAB_ROOT=/runtime-src", "--entrypoint", "/opt/qcsd-venv/bin/python3", image,
                    "-I", "/recipe/verify_installed.py", role]
        write(root / (name + ".stdout.log"), stdout)
        write(root / (name + ".stderr.log"), b"")
        started = write(root / (name + "-started.json"), {"command": command,
            "started_at": "2000-01-01T00:00:00+00:00", "cwd": str(root / "image-context") if name.endswith("image-build") else None})
        completed = write(root / (name + "-completed.json"), {"returncode": 0, "elapsed_seconds": 1.0,
            "completed_at": "2000-01-01T00:00:01+00:00", "stdout_sha256": evidence._sha(stdout),
            "stderr_sha256": evidence._sha(b"")})
        canonical["actual_operation_completions"][name] = {"record_sha256": ref(completed)["sha256"],
            "started_record_sha256": ref(started)["sha256"], "elapsed_seconds": 1.0}
    build = write(root / "client-build.json", {"source": source, "client_sha256": ref(client)["sha256"],
        "scientific_credit": False, "release_completion": json.loads((root / "release-build-completed.json").read_bytes()),
        "release_command_sha256": ref(root / "release-command.json")["sha256"]})
    canonical["native_build_record_sha256"] = ref(build)["sha256"]
    canonical_path = write(root / "canonical-runtime.json", canonical)
    result = {"runtime_source_root": str(clean), "module_root": str(clean), "execution_root": str(execution),
        "base_launcher": str(clean / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "source_manifest": str(source_path), "client_binary": str(client),
        "collection_image_digest": canonical["collection_image_digest"]}
    write(execution / "qcsd-lab", sources["qcsd-lab"])
    return SimpleNamespace(root=root, clean=clean, runtime=result, canonical=canonical,
                           reference=ref(canonical_path), implementation=impl)


@pytest.fixture
def pair(source_bytes, tmp_path, monkeypatch):
    author = Path(__file__).parents[1]
    old_sources = dict(source_bytes)
    new_sources = {**old_sources, schedule.MODULE_FILE: (author / schedule.MODULE_FILE).read_bytes()}
    data = tmp_path / "study"
    executions = [data / "serial", data / "parallel"]
    for execution in executions:
        for relative, _ in lanes.TRAFFIC_FILES.values():
            write(execution / relative, (author / relative).read_bytes())
        write(execution / lanes.STUDY_PROFILE_FILE, (author / lanes.STUDY_PROFILE_FILE).read_bytes())
        (execution / "config/campaigns").mkdir(parents=True)
        (execution / "config/workloads").mkdir()
    before = freeze_runtime(tmp_path / "original-runtime", old_sources, executions[0], successor=False)
    after = freeze_runtime(tmp_path / "current-runtime", new_sources, executions[1], successor=True)
    name = "cloudflare-quiche-r3"
    workloads = executions[0] / "config/workloads"
    source_workload = author / "config/workloads" / (name + ".json")
    write(workloads / source_workload.name, source_workload.read_bytes())
    write(workloads / (name + "-application-response-evidence") / "fixture.json", b"retained-application-witness\n")
    # The existing deterministic fixture produces three real validated forty-
    # response epochs. No network requests or current-implementation bypass is
    # substituted for the historical validator below.
    sidecar = response_sidecar(workloads / source_workload.name, name, before.implementation,
                              before.runtime["collection_image_digest"])
    sidecar["implementation_receipt"] = before.implementation
    sides = executions[0] / "config/chaff-response-qualification-store/sets/schedule-fixture"
    write(sides / (name + ".json"), sidecar)
    named = qualification.build_named_qualification_set_manifest([name], qualification_set="schedule-fixture",
        qualification_scope="response-only", workload_root=workloads, sidecar_root=sides,
        qualification_sidecar_schema_version=qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        require_current_implementation=False)
    write(sides / "_qualification-set.json", named)
    qualifier = write(executions[0] / "config/qualification-spec.json", {"schema_version": 1,
        "qualification_sets": [{"qualification_set": "schedule-fixture",
            "manifest": "chaff-response-qualification-store/sets/schedule-fixture/_qualification-set.json",
            "sidecar_root": "chaff-response-qualification-store/sets/schedule-fixture", "prefix_spec_root": None}]})
    for folder in ("workloads", "chaff-response-qualification-store"):
        shutil.copytree(executions[0] / "config" / folder, executions[1] / "config" / folder, dirs_exist_ok=True)
    write(executions[1] / "config/qualification-spec.json", qualifier.read_bytes())
    acquisition = data / "original-admission"
    acquisition.mkdir()
    cohort = write(data / "enrollment.json", b"immutable-original-enrollment-fixture\n")
    runtime = {**after.runtime, "data_root": str(data), "workload_root": str(executions[1] / "config/workloads"),
        "campaign_dir": str(executions[1] / "config/campaigns"), "execution_generation": "parallel-001"}
    sites = [{"candidate_id": "cloudflare", "workload_id": name, "workload_sha256": ref(workloads / source_workload.name)["sha256"]}]
    campaign = b"immutable-four-visit-campaign-fixture\n"
    for execution in executions:
        write(execution / "config/campaigns/fixture-formal.yml", campaign)
    original_runtime = {**before.runtime, "data_root": str(data), "workload_root": str(workloads),
        "campaign_dir": str(executions[0] / "config/campaigns"), "execution_generation": "serial-001"}
    plan = data / "original-plan.json"
    lanes._create(data, plan, lanes.PLAN_TYPE, {"study_version": 6, "cohort_generation": "rolling-50",
        "runtime": original_runtime, "sites": sites, "qualification_spec_sha256": ref(qualifier)["sha256"],
        "lanes": [{"visits_per_workload": 4, "workload_ids": [name], "campaign_name": "fixture-formal",
                   "campaign_sha256": evidence._sha(campaign)}]})
    spec = lanes.CaptureSpec(**{key: Path(value) if key in lanes.PATH_KEYS else value for key, value in {
        **original_runtime, "acquisition_root": str(acquisition), "cohort": str(cohort),
        "qualification_spec": str(qualifier), "plan_receipt": str(plan)}.items()})
    return SimpleNamespace(before=before, after=after, spec=spec, runtime=runtime,
        qualifier=executions[1] / "config/qualification-spec.json", output=data / "scheduling.json", sides=sides)


def publish(pair):
    return schedule.publish_schedule(pair.spec, pair.runtime, pair.qualifier, pair.before.reference,
        pair.after.reference, pair.output, reason="Prospectively schedule exact qualified graphs in isolated parallel workers.")


def test_publish_after_old_serial_history_without_promoting_old_intents(pair):
    history = write(pair.spec.data_root / "lanes/old/intent.json", b"old-serial-intent-retained\n")
    old_sha = ref(history)
    reference = publish(pair)
    value = schedule.validate_schedule(reference, runtime=pair.runtime)
    assert ref(history) == old_sha
    assert value["qualified_inputs"]["named_set"] == "schedule-fixture"
    assert value["limits"] == schedule.LIMITS
    assert value["formal_accepted_trace_count"] == 0 and value["scientific_credit"] is False
    schedule.validate_qualification_reuse(pair.before.implementation, pair.after.implementation,
        reference, actual_image=pair.runtime["collection_image_digest"])
    with pytest.raises(FileExistsError):
        publish(pair)


@pytest.mark.parametrize("record", ["collection-image-build", "prepare-installed-verification", "release-build", "actual-runtime-export"])
def test_changed_actual_runtime_log_or_record_rejects_before_authority(pair, record):
    path = pair.after.root / (record + ".stderr.log")
    path.write_bytes(b"unreported-error\n")
    with pytest.raises(ValueError, match="operation|logs"):
        publish(pair)


@pytest.mark.parametrize("input_kind", ["qualification", "workload", "application", "campaign"])
def test_exact_original_qualified_bytes_cannot_change_under_new_source(pair, input_kind):
    root = Path(pair.runtime["workload_root"])
    if input_kind == "qualification":
        path = pair.qualifier.parent / "chaff-response-qualification-store/sets/schedule-fixture/cloudflare-quiche-r3.json"
    elif input_kind == "workload":
        path = root / "cloudflare-quiche-r3.json"
    elif input_kind == "application":
        path = root / "cloudflare-quiche-r3-application-response-evidence/fixture.json"
    else:
        path = Path(pair.runtime["campaign_dir"]) / "fixture-formal.yml"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        publish(pair)


def test_one_qualified_response_failure_cannot_hide_behind_named_set_pass(pair):
    sidecar_path = pair.qualifier.parent / "chaff-response-qualification-store/sets/schedule-fixture/cloudflare-quiche-r3.json"
    sidecar = json.loads(sidecar_path.read_bytes())
    sidecar["candidate_attempts"][0]["connection_epochs"][0]["receipt"]["requests"][0]["complete"] = False
    write(sidecar_path, sidecar)
    with pytest.raises(ValueError):
        publish(pair)


def test_new_parallel_plan_must_be_strictly_after_capsule_not_old_serial_history(pair):
    reference = publish(pair)
    value = schedule.validate_schedule(reference)
    when = value["published_at"]
    with pytest.raises(ValueError, match="precede"):
        schedule.validate_schedule(reference, before=when)
    new_spec = replace(pair.spec, **{key: Path(value) if key in lanes.PATH_KEYS else value
        for key, value in pair.runtime.items()}, qualification_spec=pair.qualifier)
    declared = datetime.now(UTC).isoformat()
    started = datetime.now(UTC).isoformat()
    schedule.require_schedule(reference, new_spec, declared_at=declared, started_at=started)
    with pytest.raises(ValueError, match="predates"):
        schedule.require_schedule(reference, new_spec, declared_at=declared,
                                  started_at=(datetime.fromisoformat(declared) - timedelta(seconds=1)).isoformat())


def test_resealed_capsule_cannot_replace_runtime_qualification_or_source_projection(pair):
    reference = publish(pair)
    payload = json.loads(pair.output.read_bytes())
    payload["source_comparison"]["acquisition_source_groups"]["attempt"] = {}
    write(pair.output, payload)
    with pytest.raises(ValueError, match="projections"):
        schedule.validate_schedule(ref(pair.output))
    with pytest.raises(ValueError, match="SHA-256"):
        schedule.validate_schedule(reference)


def test_installed_qualification_hook_rejects_wrong_image_and_rehashed_source(pair):
    reference = publish(pair)
    with pytest.raises(ValueError, match="another image"):
        schedule.validate_qualification_reuse(pair.before.implementation, pair.after.implementation,
            reference, actual_image=pair.spec.collection_image_digest)
    bad = copy.deepcopy(pair.after.implementation)
    bad["source"]["lab_commit"] = "0" * 40
    bad["sha256"] = qualification._implementation_aggregate(bad)
    with pytest.raises(ValueError, match="source|executable"):
        schedule.validate_qualification_reuse(pair.before.implementation, bad,
            reference, actual_image=pair.runtime["collection_image_digest"])


@pytest.mark.parametrize("role", ["original", "current", "context", "export"])
def test_capsule_publication_cannot_mutate_frozen_source_or_runtime_context(pair, role):
    roots = {"original": pair.before.clean, "current": pair.after.clean,
             "context": pair.after.root / "image-context", "export": pair.after.root / "runtime-export"}
    before = evidence._inventory(roots[role])
    pair.output = roots[role] / "prospective-capsule.json"
    with pytest.raises(ValueError, match="outside frozen"):
        publish(pair)
    assert evidence._inventory(roots[role]) == before


@pytest.mark.parametrize("operation", ["collection-installed-verification", "prepare-image-build", "actual-runtime-export", "release-build"])
def test_rehashed_wrong_producer_command_cannot_fabricate_installed_closure(pair, operation):
    started_path = pair.after.root / (operation + "-started.json")
    started = json.loads(started_path.read_bytes())
    started["command"] = ["printf", "pretend-installed-success"]
    write(started_path, started)
    pair.after.canonical["actual_operation_completions"][operation]["started_record_sha256"] = ref(started_path)["sha256"]
    canonical_path = pair.after.root / "canonical-runtime.json"
    write(canonical_path, pair.after.canonical)
    pair.after.reference = ref(canonical_path)
    with pytest.raises(ValueError, match="operation|command|actor"):
        publish(pair)


def test_real_stored_lane_geometry_requires_four_visits_without_sample_count_property(pair):
    payload = lanes._payload(pair.spec.plan_receipt, lanes.PLAN_TYPE)
    assert "sample_count" not in payload["lanes"][0]
    payload["lanes"][0]["visits_per_workload"] = True
    pair.spec.plan_receipt.unlink()
    lanes._create(pair.spec.data_root, pair.spec.plan_receipt, lanes.PLAN_TYPE, payload)
    with pytest.raises(ValueError, match="four-visit"):
        publish(pair)


def use_exact_reused_client(pair):
    current, original = pair.after, pair.before
    canonical = current.canonical
    recipe = write(current.root.parent / "reuse-producer.py", b"# offline declared producer fixture\n")
    command = ["/fixture/python3", "-I", "-B", str(recipe), "_copy", "--build-root", str(current.root)]
    for suffix in ("-started.json", "-completed.json", ".stdout.log", ".stderr.log"):
        (current.root / ("release-build" + suffix)).unlink()
    canonical["actual_operation_completions"].pop("release-build")
    write(current.root / "client-reuse-command.json", command)
    started = write(current.root / "client-reuse-started.json", {"command": command, "cwd": None,
        "started_at": "2000-01-01T00:00:00+00:00"})
    write(current.root / "client-reuse.stdout.log", b"offline-copy-fixture\n")
    write(current.root / "client-reuse.stderr.log", b"")
    completed = write(current.root / "client-reuse-completed.json", {"returncode": 0, "elapsed_seconds": 1.0,
        "completed_at": "2000-01-01T00:00:01+00:00", "stdout_sha256": ref(current.root / "client-reuse.stdout.log")["sha256"],
        "stderr_sha256": evidence._sha(b"")})
    canonical["actual_operation_completions"]["client-reuse"] = {"record_sha256": ref(completed)["sha256"],
        "started_record_sha256": ref(started)["sha256"], "elapsed_seconds": 1.0}
    old_inputs = json.loads((original.root / "build-inputs.json").read_bytes())
    proof = {"artifact_type": "qcsd-exact-existing-native-client-reuse", "source": canonical["source"],
        "client_sha256": canonical["installed_client_sha256"], "original_canonical": original.reference,
        "original_client_build": ref(original.root / "client-build.json"), "native_source_inventory_equal": True,
        "native_source_file_count": len([name for name in evidence._inventory(original.clean) if name.startswith("neqo-qcsd/")]),
        "original_build_inputs": ref(original.root / "build-inputs.json"),
        "original_installed_client": ref(Path(original.canonical["client_binary"])),
        "original_installed_source": ref(Path(original.canonical["source_manifest"])),
        "original_source_inventory": ref(original.root / "source-inventory.json"),
        "target_build_inputs": ref(current.root / "build-inputs.json"),
        "target_source_inventory": ref(current.root / "source-inventory.json"),
        "original_actual_operation_completions": original.canonical["actual_operation_completions"],
        "original_client_executable": True, "scientific_credit": False, "runtime_qualification": "not-executed",
        "copied_at": "2000-01-01T00:00:00.5+00:00", **{key: old_inputs[key] for key in (
            "toolchain_image", "cargo_lock_sha256", "rust_archive_sha256")}}
    proof_path = write(current.root / "client-reuse-proof.json", proof)
    canonical.update(native_artifact_action="verified-exact-existing-client-reuse", original_canonical=original.reference,
        original_native_build_record=ref(original.root / "client-build.json"), client_reuse_recipe=ref(recipe), client_reuse_proof=ref(proof_path))
    build = {"source": canonical["source"], "client_sha256": canonical["installed_client_sha256"],
        "scientific_credit": False, "client_reuse_proof": ref(proof_path),
        "client_reuse_completion": json.loads(completed.read_bytes())}
    write(current.root / "client-build.json", build)
    write(current.root / "image-context/client-build.json", build)
    canonical["native_build_record_sha256"] = ref(current.root / "client-build.json")["sha256"]
    write(current.root / "canonical-runtime.json", canonical)
    current.reference = ref(current.root / "canonical-runtime.json")


def test_existing_client_reuse_reopens_original_twelve_operations_and_exact_bytes(pair):
    use_exact_reused_client(pair)
    reference = publish(pair)
    assert schedule.validate_schedule(reference)["runtime"]["collection_image_digest"] == pair.runtime["collection_image_digest"]


@pytest.mark.parametrize("field", ["toolchain_image", "cargo_lock_sha256", "original_installed_client"])
def test_resealed_reuse_proof_cannot_replace_original_build_or_client(pair, field):
    use_exact_reused_client(pair)
    path = pair.after.root / "client-reuse-proof.json"
    proof = json.loads(path.read_bytes())
    proof[field] = "sha256:" + "0" * 64 if field == "toolchain_image" else "0" * 64
    write(path, proof)
    pair.after.canonical["client_reuse_proof"] = ref(path)
    build = json.loads((pair.after.root / "client-build.json").read_bytes())
    build["client_reuse_proof"] = ref(path)
    write(pair.after.root / "client-build.json", build)
    write(pair.after.root / "image-context/client-build.json", build)
    pair.after.canonical["native_build_record_sha256"] = ref(pair.after.root / "client-build.json")["sha256"]
    write(pair.after.root / "canonical-runtime.json", pair.after.canonical)
    pair.after.reference = ref(pair.after.root / "canonical-runtime.json")
    with pytest.raises(ValueError, match="reuse"):
        publish(pair)


def test_typed_installed_reuse_dispatch_retains_original_qualification_and_rejects_wrong_image(pair, monkeypatch):
    from qcsd_lab import rapid_runtime_epochs as epochs
    reference = publish(pair)
    old = copy.deepcopy(pair.before.implementation)
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, reference["path"])
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", pair.runtime["collection_image_digest"])
    epochs.validate_qualification_reuse(old, pair.after.implementation)
    assert old == pair.before.implementation
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="another image"):
        epochs.validate_qualification_reuse(old, pair.after.implementation)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", pair.runtime["collection_image_digest"])
    monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", "/unrelated-historical-installation.json")
    with pytest.raises(ValueError, match="historical installation"):
        epochs.validate_qualification_reuse(old, pair.after.implementation)


def test_schedule_transport_reopens_original_client_chain_and_exact_qualified_roots(pair):
    use_exact_reused_client(pair)
    reference = publish(pair)
    roots = set(schedule.mount_roots(reference))
    assert {pair.output.parent, pair.before.clean, pair.after.clean,
            pair.before.root, pair.after.root, pair.spec.data_root,
            pair.spec.execution_root, Path(pair.runtime["execution_root"])} <= roots
    (pair.before.root / "release-build.stderr.log").write_bytes(b"changed original build witness\n")
    with pytest.raises(ValueError, match="logs|operation"):
        schedule.mount_roots(reference)
