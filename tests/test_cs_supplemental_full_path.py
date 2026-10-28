"""Synthetic noncredit prepare/enroll/launch/supplemental-Raw controls.

Only subprocess.run at the original Native process boundary is simulated.
Original process recording, complete candidate classification, three distinct
five-response receipts, inventory replay, launch and supplemental Raw checks
execute production code. No packet capture or live qualification is claimed.
"""
from copy import deepcopy
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_session as collector
from qcsd_lab import chaff_qualification as chaff
from qcsd_lab import cs_supplemental_chaff as cs
from qcsd_lab import ft_supplemental_chaff as ft
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility
from qcsd_lab import resource_study_verify as raw
from qcsd_lab.resource_study_inputs import canonical_json, native_manifest, sha256_file

HOST = "fonts.synthetic-noncredit.example"
SYNTHETIC159 = "e" * 40


def put(path, value, *, raw_bytes=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if raw_bytes else canonical_json(value))
    path.chmod(0o644)


def resource(identifier, *, padding=False):
    result = {"id": identifier,
        "url": f"https://{HOST}/{'padding' if padding else 'formal'}/{identifier}",
        "type": "Other", "content_length": None if padding else 300,
        "data_length": 0 if padding else 300, "chaff_priority": False,
        "known_valid": not padding, "depends_on": [], "headers": [
            ["accept", "*/*"], ["accept-encoding", "identity"],
            ["accept-language", "en-US,en;q=0.9"]]}
    result["headers"] = chaff.project_compact_headers(result)
    return result


def response_identity(row):
    if row["id"] < cs.ID_MIN:
        return 200, 300, cs.digest((row["url"].encode() * 300)[:300])
    index = row["id"] - cs.ID_MIN
    size = (2000, 4096, 256)[index]
    status = 404 if index == 2 else 200
    return status, size, cs.digest(bytes([65 + index]) * size)


def probe_run(rows, manifest_sha, commit):
    started = time.time_ns()
    responses = []
    for row in rows:
        status, size, body_sha = response_identity(row)
        responses.append({"resource_id": row["id"], "url": row["url"],
            "request_headers": row["headers"],
            "response_headers": [[":status", str(status)], ["content-length", str(size)]],
            "status": status, "content_length": size, "bytes": size,
            "body_sha256": body_sha, "request_stream_bytes": 150,
            "complete": True, "outcome": "succeeded" if status == 200 else "failed"})
    return {"method": "GET", "request_policy": "as-defined", "seed": 0,
        "workload_hash_sha256": manifest_sha, "max_response_bytes": cs.MAX_BODY,
        "completion_status": "complete", "error": None, "error_class": None,
        "terminal_evidence_render_errors": [], "migration_commit": commit,
        "application_response_policy": "http-2xx-only-v1",
        "application_workload_source_hash_sha256": None, "chaff_manifest_hash_sha256": None,
        "chaff_responses": [], "resolved_configuration": {"defense": {"kind": "none"}},
        "started_unix_ns": started, "ended_unix_ns": started + 1,
        "endpoints": [{"id": 0, "origin": f"https://{HOST}", "negotiated_protocol": "h3"}],
        "responses": responses}


def qualification_receipt(module, prepared, pool_path, identifier, index, commit):
    pool = json.loads(pool_path.read_bytes())
    selected = next(row for row in pool["resources"] if row["id"] == identifier)
    status, size, body_sha = response_identity(selected)
    started = time.time_ns()
    observations = [{"sequence": 0, "phase": "qualification", "direction": "incoming", "udp_payload_bytes": 1500},
                    {"sequence": 1, "phase": "qualification", "direction": "outgoing", "udp_payload_bytes": 1200}]
    packet_raw = json.dumps(observations, separators=(",", ":")).encode()
    statistics = {direction: {"packet_count": count, "observed_udp_payload_max": maximum,
                              "oversized_packet_count": 0}
                  for direction, count, maximum in (("incoming", 1, 1500), ("outgoing", 1, 1200), ("total", 2, 1500))}
    prefix = "cs" if module is cs else "ft"
    receipt = {"schema_version": 1, "artifact_type": f"qcsd-{prefix}-supplemental-response-qualification",
        "invocation_id": f"synthetic-noncredit-{prefix}-{index}", "neqo_version": "synthetic-noncredit",
        "application_workload_sha256": sha256_file(prepared), "application_resource_id": 0,
        "selected_chaff_resource_id": identifier, "qualified_parallel_chaff_streams": 5,
        "method": "GET", "url": selected["url"], "request_headers": selected["headers"],
        "parallel_requests": 5, "connection_count": 1,
        "requests_opened_before_first_network_output": 5, "request_stream_bytes": 150,
        "max_response_bytes": module.MAX_BODY, "udp_payload_ceiling": 1200,
        "incoming_udp_payload_limit": 65527, "outgoing_udp_payload_ceiling": 1200,
        "started_unix_ns": started, "ended_unix_ns": started + 1,
        "completion_status": "complete", "error": None,
        "source": {"neqo_base_commit": "a" * 40, "published_qcsd_commit": "b" * 40,
                   "migration_commit": commit},
        "requests": [{"request_index": i, "stream_id": 4 * i, "request_stream_bytes": 150,
            "status": status, "content_encoding": "identity", "body_bytes": size,
            "body_sha256": body_sha, "complete": True, "outcome": "complete"} for i in range(5)],
        "packet_observations": observations, "packet_log_sha256": cs.digest(packet_raw),
        "packets": statistics, "passed": True, **module.receipt_binding(pool, sha256_file(pool_path))}
    return receipt, packet_raw


def make_case(tmp_path, monkeypatch, *, family="cs", axis="159", corrupt_qualification=None,
              native_entry=False):
    module = cs if family == "cs" else ft
    assert axis in ("158", "159", "164")
    commit = (SYNTHETIC159 if axis == "159" else
              ft.SOURCE139_NATIVE164_COMMIT if axis == "164" else ft.SOURCE132_NATIVE158_COMMIT)
    if axis == "159":
        monkeypatch.setattr(module, "SOURCE133_NATIVE159_COMMIT", SYNTHETIC159)
    root = tmp_path / f"synthetic-noncredit-{family}-{axis}"
    root.mkdir()
    client = tmp_path / f"synthetic-client-{family}-{axis}"
    client.write_bytes(b"synthetic non-executable Native boundary fixture\n")
    client.chmod(0o755)
    runtime = {"native_commit": commit, "client_sha256": sha256_file(client),
               "image_digest": "sha256:" + "a" * 64,
               "platform": "linux/arm64", "source": {"neqo_commit": commit}}
    formal = root / "classes/formal.json"
    prepared = root / "classes/prepared.json"
    urls = [resource(i)["url"] for i in range(20)]
    formal_value = native_manifest(HOST, urls, {url: 300 for url in urls})
    for row in formal_value["resources"]:
        row["headers"] = deepcopy(native.REQUEST_HEADERS)
    formal_value["resources"][0]["type"] = "Document"
    put(formal, formal_value)
    put(prepared, {**deepcopy(formal_value), "preparation": {}})
    candidates = root / "declared/candidates.json"
    discovery = root / "declared/discovery.json"
    declaration = root / "declared/input.json"
    put(candidates, {"schema_version": 1, "record_type": module.CANDIDATES, "hostname": HOST,
                     "resources": [resource(module.ID_MIN + i, padding=True) for i in range(3)]})
    put(discovery, {"synthetic_noncredit": True, "source": "explicit finite same-host metadata fixture"})
    reference = lambda path: {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}
    put(declaration, {"schema_version": 1, "record_type": module.INPUT, "policy": module.POLICY,
        "hostname": HOST, "allowed_modes": list(module.MODES), "application_manifest_sha256": sha256_file(formal),
        "candidate_manifest": reference(candidates), "discovery_provenance": reference(discovery),
        "min_body_bytes": 1200, "max_body_bytes": module.MAX_BODY, "qualification_runs": 3, "parallel_requests": 5})
    calls = []

    def process(argv, *, stdout, stderr, timeout, check):
        calls.append(argv)
        stdout.write(b"synthetic Native process boundary; no live traffic\n")
        stderr.write(b"")
        output = Path(argv[argv.index("--output-dir") + 1])
        source = Path(argv[argv.index("--workload") + 1])
        if argv[1] == "run":
            value = json.loads(source.read_bytes())
            put(output / "run.json", probe_run(value["resources"], sha256_file(source), commit))
            return SimpleNamespace(returncode=0)
        assert argv[1] == "qualify-chaff-response"
        identifier = int(argv[argv.index("--selected-chaff-resource-id") + 1])
        pool_path = Path(argv[argv.index("--supplemental-chaff-source") + 1])
        index = int(output.parent.name)
        receipt, packets = qualification_receipt(module, source, pool_path, identifier, index, commit)
        if corrupt_qualification is not None:
            corrupt_qualification(receipt, index)
        put(output / "qualification.json", receipt)
        put(output / "packets.json", packets, raw_bytes=True)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(native.subprocess, "run", process)
    original_formal, original_prepared = formal.read_bytes(), prepared.read_bytes()
    output = root / "classes/supplemental"
    if native_entry:
        assert module is cs
        # The real preparation entrypoint requires immutable selection evidence.
        formal.chmod(0o444)
        result = native.prepare_domain(HOST, urls, root / "native-domain", client=client, runtime=runtime,
            frozen_application_manifest=formal, frozen_application_manifest_sha256=sha256_file(formal),
            cs_supplemental_chaff_input=declaration, cs_supplemental_chaff_input_sha256=sha256_file(declaration))
        assert formal.read_bytes() == original_formal
        root = root / "native-domain"
        enrollment = json.loads((root / "enrollment.json").read_bytes())
        paths = enrollment["paths"]
        formal, prepared = (root / paths[key] for key in ("manifest", "prepared_workload"))
        assert formal.read_bytes() == original_formal
        assert json.loads(prepared.read_bytes())["resources"] == formal_value["resources"]
        output = (root / paths["cs_pool_source"]).parent
        result = {"binding": enrollment["cs_supplemental_chaff"]}
        _, reopened = native._enrollment(root, HOST, runtime)
        assert reopened == enrollment
    else:
        result = module.prepare(HOST, formal, prepared, declaration, sha256_file(declaration), output, client, runtime)
        paths = {"manifest": formal.relative_to(root).as_posix(),
                 "prepared_workload": prepared.relative_to(root).as_posix(),
                 **{key: Path(path).relative_to(root).as_posix() for key, path in result["paths"].items()}}
        enrollment = {"hostname": HOST, "runtime": runtime, "paths": paths,
            f"{'cs' if module is cs else 'ft'}_supplemental_chaff": result["binding"],
            "files": {path.relative_to(root).as_posix(): sha256_file(path) for path in root.rglob("*") if path.is_file()}}
        assert formal.read_bytes() == original_formal and prepared.read_bytes() == original_prepared
    prefix = "cs" if module is cs else "ft"
    binding = module.validate_enrollment(root, enrollment, full_proof=True)
    assert binding == result["binding"]
    manifest = json.loads((root / paths[f"{prefix}_chaff_manifest"]).read_bytes())
    pool = json.loads((root / paths[f"{prefix}_pool_source"]).read_bytes())
    selected = module.resource_view(manifest)
    expected = selected["chaff_qualification"]["expected_response"]
    run = {"migration_commit": commit,
        "application_workload_source_hash_sha256": sha256_file(prepared),
        "chaff_manifest_hash_sha256": binding["chaff_manifest_sha256"],
        "supplemental_chaff_policy": module.POLICY,
        "supplemental_chaff_pool_source_hash_sha256": manifest["chaff_pool_source_sha256"],
        "supplemental_chaff_selected_pool_resource_id": manifest["selected_pool_resource_id"],
        "supplemental_chaff_qualification_evidence_sha256": manifest["qualification_evidence_sha256"],
        "defense_diagnostics": {}, "chaff_responses": [{"resource_id": selected["id"], "request_id": 0,
            "url": selected["url"], "request_headers": selected["headers"],
            "request_stream_bytes": 150, "expected_request_stream_bytes": 150,
            "response_headers": [[":status", str(expected["status"])], ["content-length", str(expected["body_bytes"])]],
            "status": expected["status"], "content_encoding": expected["content_encoding"],
            "bytes": expected["body_bytes"], "body_sha256": expected["body_sha256"], "complete": True,
            "status_match": True, "content_encoding_match": True, "body_bytes_match": True,
            "body_sha256_match": True, "identity_verified": True, "outcome": "succeeded"}]}
    receipt_paths = {"workload": paths["manifest"], **module.artifact_paths(enrollment)}
    receipt = {"mode": "cs-buflo" if module is cs else "front", f"{prefix}_supplemental_chaff": binding}
    return SimpleNamespace(root=root, module=module, prefix=prefix, client=client, runtime=runtime,
        formal=formal, prepared=prepared, declaration=declaration, output=output, enrollment=enrollment,
        binding=binding, paths=receipt_paths, files=deepcopy(enrollment["files"]),
        artifact={key: root / value for key, value in receipt_paths.items()}, receipt=receipt,
        run=run, calls=calls, pool=pool, manifest=manifest)


def cs_raw(case):
    raw._verify_cs_supplemental_receipt(case.root, case.enrollment, case.receipt,
        case.paths, case.files, case.artifact, case.run)


def refresh_file(case, path, value):
    put(path, value)
    relative = path.relative_to(case.root).as_posix()
    case.enrollment["files"][relative] = sha256_file(path)
    case.files[relative] = sha256_file(path)


def rebind_synthetic_pool_chain(case):
    """Rehash a synthetic claim chain so semantic checks, not stale hashes, refuse it."""
    module = case.module
    pool_path = case.artifact[f"{case.prefix}_pool_source"]
    pool = json.loads(pool_path.read_bytes())
    evidence_path = case.artifact[f"{case.prefix}_qualification_evidence"]
    evidence = json.loads(evidence_path.read_bytes())
    for record in evidence["runs"]:
        receipt = record["receipt"]
        receipt.update(module.receipt_binding(pool, sha256_file(pool_path)))
        path = case.output / record["relative_directory"] / "native/qualification.json"
        refresh_file(case, path, receipt)
        record["receipt_sha256"] = sha256_file(path)
    evidence["chaff_pool_source_sha256"] = sha256_file(pool_path)
    evidence["response_qualification_sha256"] = chaff.qualification_digest(
        f"qcsd-{case.prefix}-supplemental-response-qualification-v1",
        [chaff._response_run_record(i, record["receipt"]) for i, record in enumerate(evidence["runs"])])
    refresh_file(case, evidence_path, evidence)
    manifest = module.derive_manifest(pool, sha256_file(pool_path), evidence, sha256_file(evidence_path))
    manifest_path = case.artifact[f"{case.prefix}_chaff_manifest"]
    refresh_file(case, manifest_path, manifest)
    binding = {"schema_version": 1, "policy": module.POLICY, "allowed_modes": list(module.MODES),
        **module.receipt_binding(pool, sha256_file(pool_path)),
        "application_workload_sha256": pool["application_workload_sha256"],
        "qualification_evidence_sha256": sha256_file(evidence_path),
        "chaff_manifest_sha256": sha256_file(manifest_path),
        "selected_pool_resource_id": manifest["selected_pool_resource_id"]}
    case.enrollment[f"{case.prefix}_supplemental_chaff"] = binding
    case.receipt[f"{case.prefix}_supplemental_chaff"] = binding
    case.run["chaff_manifest_hash_sha256"] = binding["chaff_manifest_sha256"]
    case.run["supplemental_chaff_pool_source_hash_sha256"] = sha256_file(pool_path)
    case.run["supplemental_chaff_qualification_evidence_sha256"] = sha256_file(evidence_path)


def test_actual_full_CS_prepare_inventory_launch_and_supplemental_Raw_path(tmp_path, monkeypatch):
    case = make_case(tmp_path, monkeypatch)
    assert len(case.calls) == 6  # all three candidates, including retained404, plus3×5
    assert case.manifest["schema_version"] == 8
    assert case.manifest["selected_pool_resource_id"] == cs.ID_MIN + 1
    cs_raw(case)
    parameters = tmp_path / "synthetic-parameters.json"
    put(parameters, {"synthetic_noncredit": True})
    defense = collector.Defense("cs-buflo", "cs_buflo", False, parameters_path=parameters)
    context = SimpleNamespace(qcsd_profile="research-1200", request_policy="as-defined",
        udp_payload_ceiling=1200, limits=SimpleNamespace(max_response_bytes=cs.MAX_BODY, timeout_seconds=120))
    command = collector._client_command(case.formal, case.artifact["cs_chaff_manifest"], HOST,
        defense, 7, context, tmp_path / "launch-never-executed",
        application_workload_source=case.prepared, supplemental_chaff_source=case.artifact["cs_pool_source"])
    assert command.count("--supplemental-chaff-source") == 1
    assert command[command.index("--supplemental-chaff-source") + 1] == str(case.artifact["cs_pool_source"])
    assert command[command.index("--cs-buflo-parameters") + 1] == str(parameters)
    assert len(case.calls) == 6


def test_native_prepare_domain_keeps_empty_generic_qualifier_and_only_admits_CS(tmp_path, monkeypatch):
    case = make_case(tmp_path, monkeypatch, native_entry=True)
    assert len(case.calls) == 27  #20 exact probes +whole20 replay +3padding probes +3×5
    assert case.enrollment["qualification_error"] is not None
    assert case.enrollment["paths"]["chaff_manifest"] is None
    assert case.enrollment["mode_readiness"] == {"undefended": True, "front": False,
        "tamaraw": False, "buflo": False, "cs-buflo": True}
    assert case.enrollment["scientific_credit"] is False
    assert len(json.loads(case.formal.read_bytes())["resources"]) == 20
    cs_raw(case)


@pytest.mark.parametrize("axis", ["158", "159"])
def test_retained158_and_fresh159_FT7_full_proof_remain_distinct(tmp_path, monkeypatch, axis):
    case = make_case(tmp_path, monkeypatch, family="ft", axis=axis)
    assert case.manifest["schema_version"] == 7
    collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
        case.artifact["ft_chaff_manifest"], case.artifact["ft_pool_source"], "front", case.run)
    collector._validate_chaff_response_receipts(case.run, case.artifact["ft_chaff_manifest"], "front")
    context = SimpleNamespace(qcsd_profile="research-1200", request_policy="as-defined",
        udp_payload_ceiling=1200, limits=SimpleNamespace(max_response_bytes=ft.MAX_BODY, timeout_seconds=120))
    for kind in ("front", "tamaraw"):
        command = collector._client_command(case.formal, case.artifact["ft_chaff_manifest"], HOST,
            collector.Defense(kind, kind, False), 7, context, tmp_path / f"{kind}-never-executed",
            application_workload_source=case.prepared, supplemental_chaff_source=case.artifact["ft_pool_source"])
        assert command.count("--supplemental-chaff-source") == 1
        assert command[command.index("--supplemental-chaff-source") + 1] == str(case.artifact["ft_pool_source"])
        assert command[command.index("--defense") + 1] == kind
    case.run["migration_commit"] = ft.SOURCE132_NATIVE158_COMMIT if axis == "159" else SYNTHETIC159
    with pytest.raises(ValueError):
        collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
            case.artifact["ft_chaff_manifest"], case.artifact["ft_pool_source"], "front", case.run)


@pytest.mark.parametrize("mutation", ["missing-proof", "failed-inventory", "probe-body", "successful-labelled-failed"])
def test_original_candidate_and_failed_attempt_proofs_cannot_be_omitted_or_relabelled(tmp_path, monkeypatch, mutation):
    case = make_case(tmp_path, monkeypatch)
    if mutation == "missing-proof":
        (case.output / "probes" / str(cs.ID_MIN) / "native/run.json").unlink()
    elif mutation == "failed-inventory":
        relative = (case.output / "probes" / str(cs.ID_MIN + 2) / "failure.json").relative_to(case.root).as_posix()
        del case.enrollment["files"][relative]
        del case.files[relative]
        case.paths = {key: value for key, value in case.paths.items() if value != relative}
        case.artifact = {key: value for key, value in case.artifact.items() if value != case.root / relative}
    elif mutation == "probe-body":
        path = case.output / "probes" / str(cs.ID_MIN + 1) / "native/run.json"
        value = json.loads(path.read_bytes()); value["responses"][0]["body_sha256"] = "0" * 64
        refresh_file(case, path, value)
    else:
        path = case.artifact["cs_probe_evidence"]
        value = json.loads(path.read_bytes()); value["probes"][1]["success"] = False
        refresh_file(case, path, value)
        # Rebind the immutable probe hash through pool/manifest/evidence so a
        # superficial stale digest is not the intended reason for refusal.
        pool_path = case.artifact["cs_pool_source"]
        pool = json.loads(pool_path.read_bytes()); pool["probe_evidence_sha256"] = sha256_file(path)
        refresh_file(case, pool_path, pool)
        rebind_synthetic_pool_chain(case)
    intended = "relabelled failed" if mutation == "successful-labelled-failed" else None
    with pytest.raises((ValueError, FileNotFoundError, chaff.PreparationError), match=intended):
        cs_raw(case)


@pytest.mark.parametrize("mutation", ["four-of-five", "FT-wire", "borrowed-Source", "body-mismatch"])
def test_three_independent_five_response_CS_qualifications_refuse_cheap_failure_paths(tmp_path, monkeypatch, mutation):
    def corrupt(receipt, index):
        if index != 2:
            return
        if mutation == "four-of-five":
            receipt["requests"].pop()
        elif mutation == "FT-wire":
            receipt["artifact_type"] = "qcsd-ft-supplemental-response-qualification"
        elif mutation == "borrowed-Source":
            receipt["source"]["migration_commit"] = ft.SOURCE132_NATIVE158_COMMIT
        else:
            receipt["requests"][4]["body_sha256"] = "0" * 64
    with pytest.raises((ValueError, chaff.PreparationError)):
        make_case(tmp_path, monkeypatch, corrupt_qualification=corrupt)
    failed = tmp_path / "synthetic-noncredit-cs-159/classes/supplemental/qualification/2/native/qualification.json"
    assert failed.is_file()  # Failed original output is retained, never promoted.
    assert len(json.loads((tmp_path / "synthetic-noncredit-cs-159/classes/formal.json").read_bytes())["resources"]) == 20


@pytest.mark.parametrize("mutation", ["formal20", "run-Source", "receipt-inventory", "FT-alias", "runtime-body"])
def test_CS_supplemental_Raw_refuses_changed_session_bindings(tmp_path, monkeypatch, mutation):
    case = make_case(tmp_path, monkeypatch)
    if mutation == "formal20":
        value = json.loads(case.prepared.read_bytes()); value["resources"].pop()
        refresh_file(case, case.prepared, value)
    elif mutation == "run-Source":
        case.run["migration_commit"] = ft.SOURCE132_NATIVE158_COMMIT
    elif mutation == "receipt-inventory":
        del case.files[case.paths["cs_qualification_evidence"]]
    elif mutation == "FT-alias":
        case.receipt["ft_supplemental_chaff"] = deepcopy(case.binding)
    else:
        case.run["chaff_responses"][0]["status_match"] = False
    with pytest.raises((ValueError, chaff.PreparationError)):
        cs_raw(case)


@pytest.mark.parametrize("kind", ["front", "tamaraw", "buflo"])
def test_CS8_cannot_be_used_by_another_defense(tmp_path, monkeypatch, kind):
    case = make_case(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
            case.artifact["cs_chaff_manifest"], case.artifact["cs_pool_source"], kind)
    with pytest.raises(ValueError):
        collector._validate_chaff_response_receipts(case.run, case.artifact["cs_chaff_manifest"], kind)


def test_CS_launch_refuses_missing_pool_before_a_Native_process(tmp_path, monkeypatch):
    case = make_case(tmp_path, monkeypatch)
    before = len(case.calls)
    with pytest.raises(ValueError):
        collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
            case.artifact["cs_chaff_manifest"], None, "cs_buflo")
    assert len(case.calls) == before


def test_FT7_cannot_be_relabelled_as_CS8(tmp_path, monkeypatch):
    case = make_case(tmp_path, monkeypatch, family="ft", axis="158")
    with pytest.raises(ValueError):
        collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
            case.artifact["ft_chaff_manifest"], case.artifact["ft_pool_source"], "cs_buflo")


@pytest.mark.parametrize("family,commit", [
    ("ft", ft.SOURCE132_NATIVE158_COMMIT),
    ("ft", ft.SOURCE133_NATIVE159_COMMIT),
    ("ft", ft.SOURCE139_NATIVE164_COMMIT),
    ("cs", cs.SOURCE133_NATIVE159_COMMIT),
    ("cs", cs.SOURCE139_NATIVE164_COMMIT),
])
def test_registered_supplemental_sources_retain_their_exact_runtime_identity(family, commit):
    module = ft if family == "ft" else cs
    check = module.require_registered_ft_runtime if family == "ft" else module.require_registered_cs_runtime
    runtime = {"native_commit": commit, "source": {"neqo_commit": commit}}
    assert check(runtime) is runtime
    with pytest.raises(ValueError):
        check({**runtime, "source": {"neqo_commit": "0" * 40}})
    with pytest.raises(ValueError):
        check({**runtime, "source": None})


@pytest.mark.parametrize("commit", [None, "", "g" * 40, "0" * 40,
    "c14959bbeee406dd1d909ce8aa6162c89da5bdb2",
    "b77d46df18565a46f494fca0e1fa5a4c37e4dd63"])
def test_native164_registration_does_not_admit_other_runtime_revisions(commit):
    runtime = {"native_commit": commit, "source": {"neqo_commit": commit}}
    for check in (ft.require_registered_ft_runtime, cs.require_registered_cs_runtime):
        with pytest.raises(ValueError):
            check(runtime)


def test_native164_does_not_widen_literal_historical_runtime_guards():
    assert ft.SOURCE139_NATIVE164_COMMIT == cs.SOURCE139_NATIVE164_COMMIT == \
        "c8db8c2fd57578a443d2c375495499f450ddc451"
    runtime = {"native_commit": cs.SOURCE139_NATIVE164_COMMIT,
               "source": {"neqo_commit": cs.SOURCE139_NATIVE164_COMMIT}}
    for check in (ft.require_native158_runtime, cs.require_native159_runtime):
        with pytest.raises(ValueError):
            check(runtime)


@pytest.mark.parametrize("family", ["ft", "cs"])
def test_native164_full_supplemental_proof_preserves_original20_and_own_source(
        tmp_path, monkeypatch, family):
    # This reuses only the existing explicitly synthetic Native boundary fixture;
    # no live qualification or scientific authority is created by the test.
    case = make_case(tmp_path, monkeypatch, family=family, axis="164")
    assert len(case.calls) == 6  # all3 candidate probes, including404, then3x5
    evidence = json.loads(case.artifact[f"{case.prefix}_qualification_evidence"].read_bytes())
    assert len(evidence["runs"]) == 3
    assert all(len(row["receipt"]["requests"]) == 5 for row in evidence["runs"])
    assert all(row["receipt"]["source"]["migration_commit"] == cs.SOURCE139_NATIVE164_COMMIT
               for row in evidence["runs"])
    assert len(json.loads(case.formal.read_bytes())["resources"]) == 20
    assert json.loads(case.prepared.read_bytes())["resources"] == json.loads(case.formal.read_bytes())["resources"]
    # Collector helpers take Defense.kind; the CS dispatcher translates this
    # internal spelling to the public "cs-buflo" module policy itself.
    modes = ("front", "tamaraw") if family == "ft" else ("cs_buflo",)
    for mode in modes:
        collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
            case.artifact[f"{case.prefix}_chaff_manifest"], case.artifact[f"{case.prefix}_pool_source"],
            mode, case.run)
        collector._validate_chaff_response_receipts(case.run,
            case.artifact[f"{case.prefix}_chaff_manifest"], mode)
    if family == "cs":
        cs_raw(case)
    case.run["migration_commit"] = cs.SOURCE133_NATIVE159_COMMIT
    with pytest.raises(ValueError):
        collector._validate_supplemental_pool_source_binding(case.formal, case.prepared,
            case.artifact[f"{case.prefix}_chaff_manifest"], case.artifact[f"{case.prefix}_pool_source"],
            modes[0], case.run)


def test_native164_public_CS_prepare_keeps_qualification_and_mode_boundaries(tmp_path, monkeypatch):
    case = make_case(tmp_path, monkeypatch, axis="164", native_entry=True)
    assert len(case.calls) == 27
    assert case.enrollment["scientific_credit"] is False
    assert case.enrollment["mode_readiness"] == {"undefended": True, "front": False,
        "tamaraw": False, "buflo": False, "cs-buflo": True}
    assert case.enrollment["qualification_error"] is not None
    assert case.enrollment["paths"]["chaff_manifest"] is None
    assert len(json.loads(case.formal.read_bytes())["resources"]) == 20
    cs_raw(case)


@pytest.mark.parametrize("family", ["ft", "cs"])
@pytest.mark.parametrize("mutation", ["four-of-five", "borrowed159", "wrong-wire", "body-mismatch"])
def test_native164_still_requires_each_own_complete_three_by_five_qualification(
        tmp_path, monkeypatch, family, mutation):
    def corrupt(receipt, index):
        if index != 2:
            return
        if mutation == "four-of-five":
            receipt["requests"].pop()
        elif mutation == "borrowed159":
            receipt["source"]["migration_commit"] = cs.SOURCE133_NATIVE159_COMMIT
        elif mutation == "wrong-wire":
            receipt["artifact_type"] = ("qcsd-cs-supplemental-response-qualification"
                if family == "ft" else "qcsd-ft-supplemental-response-qualification")
        else:
            receipt["requests"][4]["body_sha256"] = "0" * 64
    with pytest.raises((ValueError, chaff.PreparationError)):
        make_case(tmp_path, monkeypatch, family=family, axis="164", corrupt_qualification=corrupt)
    failed = tmp_path / f"synthetic-noncredit-{family}-164/classes/supplemental/qualification/2/native/qualification.json"
    assert failed.is_file()


def test_source139_exact_execution_is_distinct_from_literal134_and_keeps_historical_readers():
    actual = cohorts.verifier_contract()
    qualified = compatibility.qualify_execution(actual)
    prior = compatibility.prior_exact134_execution_contract()
    assert compatibility.require_supported(prior, qualified)
    assert compatibility.require_supported(actual, qualified)
    assert actual != prior
    with pytest.raises(ValueError):
        compatibility.qualify_execution(prior)
    files = compatibility.execution_files()
    assert len(files) == len(compatibility.PRIOR_EXACT134_FILES) == 189
    changed = {name for name, digest in files.items()
               if compatibility.PRIOR_EXACT134_FILES[name] != digest}
    assert changed == {"ft_supplemental_chaff.py", "cs_supplemental_chaff.py",
        "resource_study_native.py", "resource_study_runtime.py", compatibility.HELPER_NAME}
    for name in compatibility.PRIMARY_FILES:
        if name != "resource_study_native.py":
            assert actual["files"][name] == prior["files"][name]
    assert compatibility.SOURCE139_NATIVE164_COMMIT == cs.SOURCE139_NATIVE164_COMMIT
    for name in changed:
        substituted = {**files, name: "0" * 64}
        with pytest.raises(ValueError):
            compatibility.qualify_execution(compatibility._profile(substituted))
    binding = compatibility.execution_binding(prior, qualified)
    assert binding["record_type"] == compatibility.BINDING_TYPE
    assert binding["source139_Native164_supplemental_registration"] == cs.SOURCE139_NATIVE164_COMMIT
    assert binding["source139_existing_own_probe_three_by_five_qualification_and_pilot_required"] is True
    assert binding["source139_original20_application_and_old158159_evidence_preserved"] is True
