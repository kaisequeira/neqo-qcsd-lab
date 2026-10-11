"""Host-only selector orchestration/proof controls; no live scientific credit.

The complete GET metadata is synthetic. The actual coordinator, store, Native
preparation reader and optional deep-proof joins run; no Docker or peer runs.
"""
from contextlib import nullcontext
from copy import deepcopy
import builtins
from pathlib import Path

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_runtime as runtime_backend
from qcsd_lab import resource_study_selection as selection
from qcsd_lab import resource_study_verify as verifier
from qcsd_lab.resource_study_store import StudyStore


HOST = "alpha.example"
RUNTIME = {"client_sha256": "a" * 64, "platform": "linux/arm64",
           "collection_image_digest": "sha256:" + "a" * 64,
           "native_commit": "c" * 40, "source": {"neqo_commit": "c" * 40}}


def write(path, value):
    if path.exists():
        path.chmod(0o644)
        path.unlink()
    study.create_json(path, value)
    return inputs.sha256_file(path)


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "supplied.json"
    urls = [f"https://{HOST}/object?index={index}&kept=yes" for index in range(30)]
    write(source, [{"crUX_domain": "page.example", "resources": [
        {"resource_domain": HOST, "resource_urls": urls},
        *[{"resource_domain": f"filler-{number:02d}.example", "resource_urls": [
            f"https://filler-{number:02d}.example/object?i={index}" for index in range(20)]}
          for number in range(49)]]}])
    root = tmp_path / "study"
    study.initialize(source, root)
    selected = urls[2:22]
    path = tmp_path / "selection.json"
    digest = write(path, selection.make_manifest(root, HOST, selected))
    return root, path, digest, urls, selected


def prepare_metadata(root, candidate, attempt, *, failed_response=False):
    """Create synthetic complete proof in the unchanged installed job layout."""
    host, urls = candidate["hostname"], candidate["urls"][:20]
    base = attempt / "prepared"
    write(attempt / "job.json", {"hostname": host, "urls": candidate["urls"],
        "output": str(base), "runtime": RUNTIME})
    manifest = native._manifest(host, urls, require_twenty=True)
    write(base / "preparation-get/input.json", manifest)
    rows = [{"resource_id": row["id"], "url": row["url"], "request_headers": row["headers"],
        "response_headers": [[":status", "200"], ["content-length", "2000"]],
        "status": 200, "content_length": 2000, "bytes": 2000, "body_sha256": "b" * 64,
        "request_stream_bytes": 150, "complete": True, "outcome": "succeeded"}
        for row in manifest["resources"]]
    if failed_response:
        rows[0]["complete"] = False
    run = {"method": "GET", "request_policy": "as-defined", "seed": 0,
        "workload_hash_sha256": inputs.sha256_file(base / "preparation-get/input.json"),
        "max_response_bytes": native.MAX_RESPONSE_BYTES, "completion_status": "complete",
        "error": None, "error_class": None, "terminal_evidence_render_errors": [],
        "migration_commit": RUNTIME["native_commit"], "application_response_policy": "http-2xx-only-v1",
        "application_workload_source_hash_sha256": None, "chaff_manifest_hash_sha256": None,
        "chaff_responses": [], "resolved_configuration": {"defense": {"kind": "none"}},
        "endpoints": [{"id": 0, "origin": f"https://{host}/", "negotiated_protocol": "h3"}],
        "responses": rows}
    write(base / "preparation-get/native/run.json", run)
    write(base / "preparation-get/completed.json", {"returncode": 0, "timed_out": False,
        "client_unchanged": True, "client_sha256": RUNTIME["client_sha256"]})
    write(base / "prepared-workload.json", {**manifest, "preparation": {
        "role": native.ROLE, "runtime": RUNTIME,
        "actual_preparation_run": "preparation-get/native/run.json",
        "actual_preparation_run_sha256": inputs.sha256_file(base / "preparation-get/native/run.json"),
        "expected_responses": [{key: row[key] for key in ("resource_id", "status", "bytes", "body_sha256")}
                               for row in rows]}})
    write(base / "resources.json", manifest)
    relative = base.relative_to(root).as_posix()
    return {"hostname": host, "urls": list(urls), "runtime": RUNTIME,
        "preparation_dir": relative, "paths": {"prepared_workload": relative + "/prepared-workload.json"},
        "workload_path": relative + "/resources.json",
        "workload_sha256": inputs.sha256_file(base / "resources.json"),
        "mode_settings": {mode: {} for mode in inputs.MODES},
        "mode_policies": {mode: {} for mode in inputs.MODES},
        "mode_readiness": dict.fromkeys(inputs.MODES, True), "scientific_credit": False,
        "source_occurrences": deepcopy(candidate["source_occurrences"]),
        "files": {p.relative_to(root).as_posix(): inputs.sha256_file(p)
                  for p in base.rglob("*") if p.is_file()}}


class Backend:
    def __init__(self, root, *, failed_response=False):
        self.root, self.calls, self.failed_response = root, [], failed_response

    def prepare(self, candidate, attempt):
        self.calls.append(deepcopy(candidate))
        return prepare_metadata(self.root, candidate, attempt, failed_response=self.failed_response)


def enroll_selected(context, *, failed_response=False):
    root, path, digest, _, _ = context
    backend = Backend(root, failed_response=failed_response)
    result = study.enroll(root, RUNTIME, [HOST], backend=backend,
        resource_selection=path, resource_selection_sha256=digest)
    return backend, result


def test_exact_selection_reaches_backend_with_complete_source_occurrences(context):
    root, path, digest, full, selected = context
    original = deepcopy(study.candidate_pool(root)[HOST])
    backend, result = enroll_selected(context)
    assert result["enrollment"] == [{"hostname": HOST, "status": "enrolled", "resources": 20}]
    assert backend.calls[0]["urls"] == selected and backend.calls[0]["url_count"] == 20
    assert backend.calls[0]["source_occurrences"] == original["source_occurrences"]
    assert study.candidate_pool(root)[HOST] == original and original["urls"] == full
    enrollment = study.load(root / f"classes/{HOST}/enrollment.json")
    assert enrollment["urls"] == selected
    proof = selection.validate_selection_proof(root, enrollment)
    assert proof["manifest_sha256"] == digest and proof["scientific_credit"] is False
    assert (root / enrollment["resource_selection"]["manifest_path"]).read_bytes() == path.read_bytes()
    epochs._verify_preparation(StudyStore(root), HOST)
    assert StudyStore(root).status()["accepted_count"] == 0


def test_default_preparation_retains_full_pool_job_and_enrollment_shape(context):
    root, _, _, full, _ = context
    backend = Backend(root)
    result = study.enroll(root, RUNTIME, [HOST], backend=backend)
    assert result["enrollment"][0]["status"] == "enrolled"
    assert backend.calls[0] == study.candidate_pool(root)[HOST]
    enrollment = study.load(root / f"classes/{HOST}/enrollment.json")
    assert enrollment["urls"] == full[:20] and "resource_selection" not in enrollment
    assert not (root / "inputs/resource-selections").exists()
    job = next((root / "enrollment-attempts").rglob("job.json"))
    assert job.read_bytes() == inputs.canonical_json({"hostname": HOST, "urls": full,
        "output": str(job.parent / "prepared"), "runtime": RUNTIME})
    assert selection.selection_artifact_paths(enrollment) == {}
    assert selection.validate_selection_proof(root, enrollment) is None


@pytest.mark.parametrize("failure", ["hash", "hostname", "partial-path", "partial-hash", "multiple-hosts"])
def test_selection_preflight_refuses_before_backend_or_freeze(context, failure):
    root, path, digest, _, _ = context
    kwargs = {"resource_selection": path, "resource_selection_sha256": digest}
    hosts = [HOST]
    if failure == "hash": kwargs["resource_selection_sha256"] = "f" * 64
    elif failure == "hostname": hosts = ["filler-00.example"]
    elif failure == "partial-path": kwargs.pop("resource_selection_sha256")
    elif failure == "partial-hash": kwargs.pop("resource_selection")
    else: hosts.append("filler-00.example")
    backend = Backend(root)
    with pytest.raises(ValueError):
        study.enroll(root, RUNTIME, hosts, backend=backend, **kwargs)
    assert backend.calls == [] and not (root / "inputs/resource-selections").exists()
    assert not (root / "enrollment-attempts").exists()


@pytest.mark.parametrize("state", ["reserved", "failed", "captured", "unverified", "accepted"])
@pytest.mark.parametrize("purpose", ["pilot", "formal"])
def test_any_prior_attempt_refuses_selected_preparation(context, state, purpose):
    root, path, digest, _, _ = context
    store = StudyStore(root)
    candidate = study.candidate_pool(root)["filler-00.example"]
    store.enroll(prepare_metadata(root, candidate, root / "historical-preparation"))
    # Construct retained ledger states without inventing a matching live pilot.
    attempt = store._allocate_attempt(candidate["hostname"], "undefended")
    with store._transaction() as connection:
        connection.execute("UPDATE attempts SET state=?,kind=? WHERE attempt_id=?",
            (state, "pilot" if purpose == "pilot" else "formal", attempt["attempt_id"]))
    backend = Backend(root)
    with pytest.raises(ValueError, match="no prior attempts"):
        study.enroll(root, RUNTIME, [HOST], backend=backend,
            resource_selection=path, resource_selection_sha256=digest)
    assert backend.calls == [] and not (root / "inputs/resource-selections").exists()


def test_already_enrolled_selection_refuses_without_replacing_existing_bytes(context):
    root, path, digest, _, _ = context
    study.enroll(root, RUNTIME, [HOST], backend=Backend(root))
    original = (root / f"classes/{HOST}/enrollment.json").read_bytes()
    backend = Backend(root)
    with pytest.raises(ValueError, match="cannot replace"):
        study.enroll(root, RUNTIME, [HOST], backend=backend,
            resource_selection=path, resource_selection_sha256=digest)
    assert backend.calls == [] and (root / f"classes/{HOST}/enrollment.json").read_bytes() == original


def test_existing_sdk_job_contains_only_selected_twenty_and_failure_has_no_tail(context, monkeypatch):
    root, path, digest, full, selected = context
    jobs = []
    monkeypatch.setattr(runtime_backend, "public_ipv4", lambda host: {"selected_ipv4": "198.51.100.1"})
    monkeypatch.setattr(runtime_backend, "docker_lock", nullcontext)
    monkeypatch.setattr(runtime_backend, "_runtime_check", lambda runtime: None)

    def refuse_selected(*args, **kwargs):
        job = study.load(Path(args[args.index("--job") + 1]))
        jobs.append(job)
        raise RuntimeError("controlled first selected URL failure; no Native execution")

    monkeypatch.setattr(runtime_backend, "_docker", refuse_selected)
    result = study.enroll(root, RUNTIME, [HOST], resource_selection=path,
        resource_selection_sha256=digest)
    job_path = next((root / "enrollment-attempts").rglob("job.json"))
    assert len(jobs) == 1 and jobs[0] == {"hostname": HOST, "urls": selected,
        "output": str(job_path.parent / "prepared"),
        "runtime": RUNTIME}
    assert full[0] not in jobs[0]["urls"] and full[22] not in jobs[0]["urls"]
    assert result["enrollment"][0]["status"] == "not-enrolled"
    assert StudyStore(root).status()["enrolled_count"] == 0


@pytest.mark.parametrize("argv", [
    ["--resource-selection", "selection.json"],
    ["--resource-selection-sha256", "a" * 64],
    ["--resource-selection", "selection.json", "--resource-selection-sha256", "a" * 64],
    ["--enroll", "--runtime", "runtime.json", "--hostname", HOST, "--hostname", "bravo.example",
     "--resource-selection", "selection.json", "--resource-selection-sha256", "a" * 64],
])
def test_bad_cli_flags_leave_fresh_target_absent(tmp_path, capsys, argv):
    root = tmp_path / "never-created"
    assert study.main(["prepare", "--root", str(root), *argv]) == 1
    assert not root.exists()
    assert '"status": "refused"' in capsys.readouterr().out


@pytest.mark.parametrize("change,hosts,modes", [
    ("native", [HOST], []), ("resources", [], []),
    ("resources", ["bravo.example"], []), ("resources", [HOST], ["undefended"]),
    ("resources", [HOST], [*inputs.MODES, "buflo"]),
])
def test_ambiguous_selected_epoch_scope_refuses_before_target_creation(tmp_path, change, hosts, modes):
    root = tmp_path / "never-created"
    argv = ["prepare", "--root", str(root), "--enroll", "--runtime", "runtime.json",
        "--hostname", HOST, "--resource-selection", "selection.json", "--resource-selection-sha256", "a" * 64,
        "--epoch-of", str(tmp_path / "parent"), "--epoch-change", change]
    for host in hosts: argv += ["--affected-hostname", host]
    for mode in modes: argv += ["--affected-mode", mode]
    assert study.main(argv) == 1 and not root.exists()


def test_selected_coordinator_provenance_adds_only_one_module():
    original = study.coordinator_provenance()
    selected = study.coordinator_provenance(resource_selection=True)
    assert len(original["files"]) == 14 and len(selected["files"]) == 15
    assert original["files"]["resource_study_integrity.py"] == inputs.sha256_file(
        Path(study.__file__).with_name("resource_study_integrity.py"))
    assert "resource_study_selection.py" not in original["files"]
    assert set(selected["files"]) - set(original["files"]) == {"resource_study_selection.py"}
    assert {k: v for k, v in selected["files"].items() if k != "resource_study_selection.py"} == original["files"]
    assert selected["files"]["resource_study_selection.py"] == inputs.sha256_file(Path(selection.__file__))


def test_default_preparation_and_receipt_do_not_import_unbound_selection_code(context, monkeypatch):
    root, _, _, _, _ = context
    study.enroll(root, RUNTIME, [HOST], backend=Backend(root))
    enrollment = study.load(root / f"classes/{HOST}/enrollment.json")
    receipt = deep_receipt(root, enrollment)
    original_import = builtins.__import__

    def refuse_selection(name, *args, **kwargs):
        if name.rsplit(".", 1)[-1] == "resource_study_selection":
            raise AssertionError("historical/default reader imported unbound selector code")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_selection)
    epochs._verify_preparation(StudyStore(root), HOST)
    monkeypatch.setattr(verifier, "validate_receipt_network", lambda *args: None)
    with pytest.raises(ValueError, match="Native run did not complete coherently"):
        verifier.verify_receipt(root, receipt)


@pytest.mark.parametrize("enrollment,receipt", [
    ({"resource_selection": {}}, {}), ({"resource_selection_manifest": "partial"}, {}),
    ({"files": {"inputs/resource-selections/unknown.json": "f" * 64}}, {}),
    ({}, {"artifact_paths": {"resource_selection_manifest": "partial"}}),
])
def test_partial_selection_proof_is_detected_for_strict_lazy_reader(enrollment, receipt):
    assert verifier.selection_proof_present(enrollment, receipt) is True


@pytest.mark.parametrize("selected", [False, True])
def test_seal_inventories_selected_proof_only_and_records_actual_host_module(context, monkeypatch, selected):
    root, _, _, _, _ = context
    if selected:
        enroll_selected(context)
    else:
        study.enroll(root, RUNTIME, [HOST], backend=Backend(root))
    enrollment = study.load(root / f"classes/{HOST}/enrollment.json")
    attempt = {"hostname": HOST, "mode": "undefended", "slot": 1,
        "attempt_id": "a" * 32, "path": "synthetic-attempt"}
    capture = root / attempt["path"] / "capture"
    write(capture / "neqo/run.json", {"endpoints": [{"id": 0,
        "local_address": "192.0.2.1:43000", "remote_address": "198.51.100.1:443"}]})
    write(capture / "attempt.json", {"scope": "synthetic sealing control"})
    for relative in ("captures/direct-quic.pcapng", "traces/direct-quic.csv", "neqo/packets.csv",
                     "diagnostics/direct-quic-raw.pcapng"):
        path = capture / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic, not packet proof\n")
    checks = []

    def controlled_raw_boundary(actual_root, receipt):
        checks.append(selection.validate_selection_proof(actual_root, enrollment, receipt))
        return {"controlled_raw_boundary": True}

    monkeypatch.setattr(study, "verify_receipt", controlled_raw_boundary)
    monkeypatch.setattr(study, "validate_network_plan", lambda plan: None)
    receipt = study.load(study.seal(root, attempt, enrollment, RUNTIME, {}, pilot=True))
    expected = selection.selection_artifact_paths(enrollment)
    assert {k: v for k, v in receipt["artifact_paths"].items() if k.startswith("resource_selection_")} == expected
    assert all(receipt["files"][name] == enrollment["files"][name] for name in expected.values())
    assert len(receipt["coordinator_provenance"]["files"]) == (14 if selected else 13)
    assert len(checks) == 1 and (checks[0] is not None) is selected
    assert receipt["scientific_credit"] is False and StudyStore(root).status()["accepted_count"] == 0


def test_public_selected_prepare_uses_actual_enroll_path(context, monkeypatch, capsys):
    root, path, digest, _, selected = context
    monkeypatch.setattr(study, "runtime_identity", lambda path: deepcopy(RUNTIME))
    monkeypatch.setattr(runtime_backend, "PreparationRuntime", lambda root, runtime: Backend(root))
    assert study.main(["prepare", "--root", str(root), "--runtime", "runtime.json", "--enroll",
        "--hostname", HOST, "--resource-selection", str(path), "--resource-selection-sha256", digest]) == 0
    assert study.load(root / f"classes/{HOST}/enrollment.json")["urls"] == selected
    assert '"status": "enrolled"' in capsys.readouterr().out


def test_fresh_context_may_remain_after_bad_manifest_but_no_backend_or_admission(context, tmp_path, monkeypatch):
    root, path, _, _, _ = context
    target = tmp_path / "fresh-context"
    calls = []
    monkeypatch.setattr(study, "runtime_identity", lambda path: deepcopy(RUNTIME))
    monkeypatch.setattr(runtime_backend, "PreparationRuntime", lambda *args: calls.append(args))
    assert study.main(["prepare", "--root", str(target), "--source", str(root / "inputs/supplied-resources.json"),
        "--runtime", "runtime.json", "--enroll", "--hostname", HOST,
        "--resource-selection", str(path), "--resource-selection-sha256", "f" * 64]) == 1
    assert calls == [] and (target / "study.json").is_file()
    assert not (target / "enrollment-attempts").exists() and not (target / "epochs").exists()
    assert StudyStore(target).status()["enrolled_count"] == 0


def deep_receipt(root, enrollment):
    paths = {"enrollment": f"classes/{HOST}/enrollment.json", "workload": enrollment["workload_path"]}
    for name in ("run", "packets", "pcap", "trace", "collector"):
        relative = "raw/" + name + ".json"
        write(root / relative, {})
        paths[name] = relative
    paths.update(selection.selection_artifact_paths(enrollment))
    return {"schema_version": 1, "verified": True,
        "record_type": "qcsd-resource-domain-session-verification-v1", "acceptance": verifier.ACCEPTANCE,
        "mode": "undefended", "hostname": HOST, "workload_sha256": enrollment["workload_sha256"],
        "artifact_paths": paths, "files": {name: inputs.sha256_file(root / name) for name in paths.values()}}


@pytest.mark.parametrize("change", ["manifest", "job", "context", "input", "workload", "binding", "downgrade"])
def test_rehashed_selection_mutations_refuse_epoch_and_deep_reader(context, monkeypatch, change):
    root, _, _, _, _ = context
    enroll_selected(context)
    store = StudyStore(root)
    enrollment_path = root / f"classes/{HOST}/enrollment.json"
    enrollment = study.load(enrollment_path)
    proof = enrollment["resource_selection"]
    if change == "binding":
        proof["manifest_sha256"] = "f" * 64
    elif change == "downgrade":
        del enrollment["resource_selection"]
    else:
        relative = {"manifest": proof["manifest_path"], "job": proof["job_path"],
            "context": "inputs/candidates.json", "input": enrollment["preparation_dir"] + "/preparation-get/input.json",
            "workload": enrollment["workload_path"]}[change]
        value = study.load(root / relative)
        if change in {"manifest", "job"}: value["urls"] = list(reversed(value["urls"]))
        elif change == "context": value["unrecorded"] = True
        else: value["resources"][0]["url"] += "&changed=yes"
        enrollment["files"][relative] = write(root / relative, value)
    write(enrollment_path, enrollment)
    # Rehash the class row to isolate the semantic preparation check, rather
    # than merely demonstrating the Store's immutable enrollment SHA refusal.
    monkeypatch.setattr(epochs, "_enrollments", lambda unused: {HOST: (enrollment, None, None)})
    with pytest.raises((ValueError, KeyError)):
        epochs._verify_preparation(store, HOST)
    receipt = deep_receipt(root, enrollment)
    monkeypatch.setattr(verifier, "validate_receipt_network", lambda *args: None)
    with pytest.raises((ValueError, KeyError)):
        verifier.verify_receipt(root, receipt)


@pytest.mark.parametrize("change", ["missing-path", "missing-file", "extra-path", "wrong-path"])
def test_deep_reader_requires_complete_exact_selection_inventory(context, monkeypatch, change):
    root, _, _, _, _ = context
    enroll_selected(context)
    enrollment = study.load(root / f"classes/{HOST}/enrollment.json")
    receipt = deep_receipt(root, enrollment)
    key = "resource_selection_manifest"
    if change == "missing-path": receipt["artifact_paths"].pop(key)
    elif change == "missing-file": receipt["files"].pop(receipt["artifact_paths"][key])
    elif change == "extra-path": receipt["artifact_paths"]["resource_selection_foreign"] = receipt["artifact_paths"][key]
    else: receipt["artifact_paths"][key] = receipt["artifact_paths"]["resource_selection_job"]
    monkeypatch.setattr(verifier, "validate_receipt_network", lambda *args: None)
    with pytest.raises(ValueError, match="selection|required raw"):
        verifier.verify_receipt(root, receipt)


def test_valid_selected_proof_reaches_unchanged_native_gate(context, monkeypatch):
    root, _, _, _, _ = context
    enroll_selected(context)
    enrollment = study.load(root / f"classes/{HOST}/enrollment.json")
    receipt = deep_receipt(root, enrollment)
    monkeypatch.setattr(verifier, "validate_receipt_network", lambda *args: None)
    with pytest.raises(ValueError, match="Native run did not complete coherently"):
        verifier.verify_receipt(root, receipt)


@pytest.mark.parametrize("change", ["incomplete-response", "native-identity", "changed-input", "mutable-proof", "missing-proof"])
def test_selected_native_preparation_proof_refuses_before_enrollment(context, change):
    root, path, digest, _, _ = context

    class BadBackend(Backend):
        def prepare(self, candidate, attempt):
            enrollment = super().prepare(candidate, attempt)
            base = root / enrollment["preparation_dir"]
            run_path = base / "preparation-get/native/run.json"
            run = study.load(run_path)
            if change == "incomplete-response": run["responses"][0]["complete"] = False
            elif change == "native-identity": run["migration_commit"] = "d" * 40
            elif change == "changed-input":
                input_path = base / "preparation-get/input.json"
                value = study.load(input_path)
                value["resources"][0]["url"] += "&changed=yes"
                enrollment["files"][input_path.relative_to(root).as_posix()] = write(input_path, value)
            elif change == "mutable-proof": run_path.chmod(0o644)
            else: run_path.unlink()
            if change in {"incomplete-response", "native-identity"}:
                enrollment["files"][run_path.relative_to(root).as_posix()] = write(run_path, run)
                prepared_path = base / "prepared-workload.json"
                prepared = study.load(prepared_path)
                prepared["preparation"]["actual_preparation_run_sha256"] = inputs.sha256_file(run_path)
                enrollment["files"][prepared_path.relative_to(root).as_posix()] = write(prepared_path, prepared)
            return enrollment

    result = study.enroll(root, RUNTIME, [HOST], backend=BadBackend(root),
        resource_selection=path, resource_selection_sha256=digest)
    assert result["enrollment"][0]["status"] == "not-enrolled"
    assert StudyStore(root).status()["enrolled_count"] == 0
    assert not (root / f"classes/{HOST}/enrollment.json").exists()
