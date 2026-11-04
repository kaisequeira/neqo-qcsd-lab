"""Typed FRONT/Tamaraw padding source independent of the formal20 URLs.

Preparation and qualification never add scientific credit. A session still
needs its original complete20 working GETs and independent packet/Raw proof.
Legacy chaff schemas do not opt into this module implicitly.
"""
from __future__ import annotations

from collections.abc import Mapping
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from .resource_study_inputs import canonical_json, sha256_file

POLICY = "ft-separate-same-host-qualified-chaff-v1"
SCOPE = "response-only-separate-same-host-pool-v1"
INPUT = "qcsd-ft-supplemental-same-host-chaff-input-v1"
CANDIDATES = "qcsd-ft-supplemental-candidate-manifest"
POOL = "qcsd-ft-supplemental-prepared-chaff-pool-source"
EVIDENCE = "qcsd-ft-supplemental-qualification-evidence"
MANIFEST = "qcsd-ft-supplemental-same-host-qualified-chaff-manifest"
ID_MIN, ID_MAX = 2_147_483_648, 2_147_483_711
MAX_BODY = 16_777_216
MODES = ("front", "tamaraw")
SHA = re.compile(r"[0-9a-f]{64}\Z")
RESOURCE_KEYS = {"id", "url", "type", "content_length", "data_length",
                 "chaff_priority", "known_valid", "depends_on", "headers"}
PATH_KEYS = ("ft_supplemental_input", "ft_candidate_manifest", "ft_discovery_provenance",
             "ft_probe_evidence", "ft_pool_source", "ft_qualification_evidence", "ft_chaff_manifest")
FD9 = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")

def need(value, message):
    if not value:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate supplemental JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite supplemental JSON")))

def read(path, expected=None, *, limit=64 * 1024**2, allow_empty=False):
    p = Path(os.path.abspath(path))
    need(p.resolve(strict=True) == p and all(not q.is_symlink() for q in (p, *p.parents)),
         "canonical nonlinked supplemental artifact required")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in (0o444, 0o644)
             and (0 <= before.st_size if allow_empty else 0 < before.st_size)
             and before.st_size <= limit, "bounded owned supplemental artifact required")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(limit + 1)
        need(len(raw) == before.st_size and
             tuple(getattr(before, k) for k in FD9) == tuple(getattr(os.fstat(fd), k) for k in FD9)
             == tuple(getattr(p.lstat(), k) for k in FD9)
             and (expected is None or digest(raw) == expected), "supplemental whole bytes/SHA/FD9 changed")
        return raw
    finally:
        os.close(fd)

def within(root, relative):
    need(type(relative) is str and relative and not Path(relative).is_absolute()
         and str(Path(relative)) == relative and ".." not in Path(relative).parts,
         "canonical relative supplemental artifact required")
    return Path(root) / relative

def origin(url):
    value = urlsplit(url)
    need(value.scheme == "https" and value.hostname and value.username is None
         and value.password is None and "#" not in url, "same-host absolute HTTPS supplemental URL required")
    return value.hostname.lower(), value.port if value.port is not None else 443

def checked_input(value, formal, formal_sha, candidates, candidate_raw, discovery_raw, hostname):
    fields = {"schema_version", "record_type", "policy", "hostname", "allowed_modes",
              "application_manifest_sha256", "candidate_manifest", "discovery_provenance",
              "min_body_bytes", "max_body_bytes", "qualification_runs", "parallel_requests"}
    need(type(value) is dict and set(value) == fields and type(value["schema_version"]) is int and value["schema_version"] == 1
         and value["record_type"] == INPUT and value["policy"] == POLICY
         and value["hostname"] == hostname and value["allowed_modes"] == list(MODES)
         and value["application_manifest_sha256"] == formal_sha
         and value["min_body_bytes"] == 1200 and value["max_body_bytes"] == MAX_BODY
         and value["qualification_runs"] == 3 and value["parallel_requests"] == 5,
         "exact supplemental FT declaration required")
    for key, raw in (("candidate_manifest", candidate_raw), ("discovery_provenance", discovery_raw)):
        ref = value[key]
        need(type(ref) is dict and set(ref) == {"path", "sha256", "bytes"}
             and ref["bytes"] == len(raw) and ref["sha256"] == digest(raw),
             "supplemental declaration/source reference differs")
    resources = formal.get("resources")
    need(type(resources) is list and len(resources) == 20
         and [r["id"] for r in resources] == list(range(20)), "formal20 unchanged IDs required")
    urls = [r["url"] for r in resources]
    root_origin = origin(urls[0])
    need(root_origin[0] == hostname and len(set(urls)) == 20
         and all(origin(url) == root_origin for url in urls), "formal20 class origin differs")
    need(type(candidates) is dict and set(candidates) == {"schema_version", "record_type", "hostname", "resources"}
         and type(candidates["schema_version"]) is int and candidates["schema_version"] == 1 and candidates["record_type"] == CANDIDATES
         and candidates["hostname"] == hostname and type(candidates["resources"]) is list
         and 1 <= len(candidates["resources"]) <= 64, "finite separately declared FT candidate manifest required")
    seen = set()
    from .chaff_qualification import project_compact_headers
    for i, resource in enumerate(candidates["resources"]):
        need(type(resource) is dict and set(resource) == RESOURCE_KEYS
             and type(resource["id"]) is int and resource["id"] == ID_MIN + i
             and resource["known_valid"] is False and resource["chaff_priority"] is False
             and resource["depends_on"] == [] and resource["content_length"] is None
             and type(resource["data_length"]) is int and resource["data_length"] == 0
             and resource["url"] not in seen and resource["url"] not in urls
             and origin(resource["url"]) == root_origin
             and resource["headers"] == project_compact_headers(resource),
             "padding candidate changed ID/origin/headers or fabricated a successful body")
        seen.add(resource["url"])
    need(type(decode(discovery_raw)) is dict, "whole discovery provenance object required")
    return copy.deepcopy(candidates["resources"])

def receipt_binding(pool, pool_sha):
    return {"supplemental_chaff_policy": POLICY,
            "application_manifest_sha256": pool["application_manifest_sha256"],
            "chaff_pool_source_sha256": pool_sha,
            "candidate_manifest_sha256": pool["candidate_manifest_sha256"],
            "discovery_provenance_sha256": pool["discovery_provenance_sha256"]}

def selected(pool):
    responses = pool["expected_responses"]
    choices = sorted((r for r in responses if r["bytes"] >= 1200),
                     key=lambda r: (-r["bytes"], r["resource_id"]))
    need(choices and choices[0]["bytes"] <= MAX_BODY,
         "no deterministic completed1200-byte FT candidate within16MiB; smaller substitution refused")
    response = choices[0]
    return next(r for r in pool["resources"] if r["id"] == response["resource_id"]), response

def qualification_command(client, prepared, formal, pool_source, output, identifier):
    need(type(identifier) is int and ID_MIN <= identifier <= ID_MAX, "padding-only qualification ID required")
    return [str(client), "qualify-chaff-response", "--workload", str(prepared),
            "--application-manifest", str(formal), "--supplemental-chaff-source", str(pool_source),
            "--application-resource-id", "0", "--selected-chaff-resource-id", str(identifier),
            "--output-dir", str(output), "--timeout-seconds", "120", "--max-response-bytes",
            str(MAX_BODY), "--packet-size", "1200", "--parallel-requests", "5"]

def derive_manifest(pool, pool_sha, evidence, evidence_sha):
    from . import chaff_qualification as chaff
    resource, prepared = selected(pool)
    need(evidence.get("schema_version") == 1 and evidence.get("record_type") == EVIDENCE
         and evidence.get("policy") == POLICY and evidence.get("scientific_credit") is False
         and evidence.get("application_workload_sha256") == pool["application_workload_sha256"]
         and evidence.get("chaff_pool_source_sha256") == pool_sha
         and evidence.get("selected_pool_resource_id") == resource["id"], "FT evidence lost one explicit Source binding")
    runs = [row["receipt"] for row in evidence["runs"]]
    need(all(chaff._receipt_neqo_provenance(run)["migration_commit"] == pool["probe_native_commit"] for run in runs),
         "FT qualification and prepared probe Native Source differ")
    expected, request_size = chaff._stable_response_identity(runs,
        application_manifest_sha256=pool["application_workload_sha256"], application_resource_id=0,
        selected_chaff_resource_id=resource["id"], qualified_parallel_chaff_streams=5,
        url=resource["url"], headers=resource["headers"], resource_domain_max_response_bytes=MAX_BODY,
        ft_supplemental_binding=receipt_binding(pool, pool_sha))
    records = [chaff._response_run_record(i, run) for i, run in enumerate(runs)]
    qualification_sha = chaff.qualification_digest("qcsd-ft-supplemental-response-qualification-v1", records)
    need(expected["status"] == prepared["status"] and expected["body_bytes"] == prepared["bytes"]
         and expected["body_sha256"] == prepared["body_sha256"]
         and evidence["response_qualification_sha256"] == qualification_sha
         and evidence["expected_response"] == expected and evidence["request_stream_bytes"] == request_size,
         "FT actual15-response qualification changed its prepared identity")
    return {"schema_version": 7, "artifact_type": MANIFEST, "policy": POLICY,
        "qualification_scope": SCOPE, "application_manifest_sha256": pool["application_manifest_sha256"],
        "application_workload_sha256": pool["application_workload_sha256"], "chaff_pool_source_sha256": pool_sha,
        "candidate_manifest_sha256": pool["candidate_manifest_sha256"],
        "discovery_provenance_sha256": pool["discovery_provenance_sha256"],
        "qualification_evidence_sha256": evidence_sha, "application_resource_id": 0,
        "selected_pool_resource_id": resource["id"], "qualified_parallel_chaff_streams": 5,
        "resources": [{"resource": copy.deepcopy(resource), "chaff_qualification": {
            "schema_version": 7, "qualification_scope": SCOPE, "method": "GET",
            "request_stream_bytes": request_size, "qualified_parallel_chaff_streams": 5,
            "qualification_runs": 3, "qualified_completion_count": 15,
            "expected_response": expected, "response_qualification_sha256": qualification_sha}}]}

def prepare(hostname, formal_path, prepared_path, input_path, input_sha, output, client, runtime):
    """Only genuine Native processes create the probe and qualification facts."""
    from . import resource_study_native as native, chaff_qualification as chaff
    require_registered_ft_runtime(runtime)
    root = native._new_directory(output)
    declaration_raw = read(input_path, input_sha, limit=1024**2)
    declaration = decode(declaration_raw)
    candidate_raw = read(declaration["candidate_manifest"]["path"], declaration["candidate_manifest"]["sha256"], limit=1024**2)
    discovery_raw = read(declaration["discovery_provenance"]["path"], declaration["discovery_provenance"]["sha256"], limit=16*1024**2)
    formal_raw, prepared_raw = read(formal_path), read(prepared_path)
    resources = checked_input(declaration, decode(formal_raw), digest(formal_raw), decode(candidate_raw), candidate_raw, discovery_raw, hostname)
    paths = {"ft_supplemental_input": native._write(root/"declaration.json", declaration_raw, raw=True),
             "ft_candidate_manifest": native._write(root/"candidates.json", candidate_raw, raw=True),
             "ft_discovery_provenance": native._write(root/"discovery.json", discovery_raw, raw=True)}
    probes, responses = [], []
    for resource in resources:
        original = copy.deepcopy(resource)
        operation = native._new_directory(root/"probes"/str(resource["id"]))
        record = {"resource_id": resource["id"], "relative_directory": operation.relative_to(root).as_posix(),
                  "success": False, "failure_class": None}
        try:
            native._checked_operation(operation, {"resources": [original]}, client=client,
                runtime=runtime, client_sha256=runtime["client_sha256"], timeout=120, max_response_bytes=MAX_BODY)
        except (ValueError, OSError) as error:
            # A failed process, missing proof, malformed run or incomplete GET
            # is infrastructure/unresolved evidence, never a smaller-candidate
            # selection excuse. Only an authenticated completed HTTP failure
            # or completed empty body may be excluded from the prepared pool.
            record["error"] = str(error)
            native._write(operation/"failure.json", {"error": str(error), "scientific_credit": False})
        assessment = _assess_probe(operation, root, str(client), runtime, original, read)
        if assessment["working"]:
            need("error" not in record, "original probe failed despite a completed working response; inspect rather than omit or promote")
            response = assessment["response"]
            resource.update(known_valid=True, content_length=response["bytes"], data_length=response["bytes"])
            responses.append({"resource_id": resource["id"], "status": response["status"], "bytes": response["bytes"],
                              "body_sha256": response["body_sha256"], "complete": True})
            record["success"] = True
        else:
            need("error" in record, "completed failed probe was not refused by original working-GET predicate")
            record["failure_class"] = assessment["failure_class"]
        probes.append(record)
    probe_evidence = {"schema_version": 1, "record_type": "qcsd-ft-supplemental-candidate-probe-evidence",
                      "policy": POLICY, "original_root": str(root), "client": str(client), "runtime": runtime,
                      "probes": probes, "scientific_credit": False}
    paths["ft_probe_evidence"] = native._write(root/"probe-evidence.json", probe_evidence)
    pool = {"schema_version": 1, "artifact_type": POOL, "policy": POLICY,
        "application_manifest_sha256": digest(formal_raw), "application_workload_sha256": digest(prepared_raw),
        "candidate_manifest_sha256": digest(candidate_raw), "discovery_provenance_sha256": digest(discovery_raw),
        "probe_evidence_sha256": sha256_file(paths["ft_probe_evidence"]), "probe_native_commit": runtime["native_commit"],
        "resources": resources, "expected_responses": responses}
    paths["ft_pool_source"] = native._write(root/"pool-source.json", pool)
    resource, _ = selected(pool)
    pool_sha = sha256_file(paths["ft_pool_source"])
    runs, records = [], []
    for index in range(3):
        operation = native._new_directory(root/"qualification"/str(index))
        command = qualification_command(client, prepared_path, formal_path, paths["ft_pool_source"], operation/"native", resource["id"])
        actual = native._execute(command, operation, timeout=120, client_sha256=runtime["client_sha256"])
        need(actual["returncode"] == 0 and not actual["timed_out"] and actual["client_unchanged"],
             "actual separate FT qualification failed; no readiness or credit")
        receipt_path = operation/"native/qualification.json"
        receipt = decode(read(receipt_path))
        need(chaff._receipt_neqo_provenance(receipt)["migration_commit"] == runtime["native_commit"],
             "separate FT qualification changed Native Source")
        runs.append(receipt)
        records.append({"run_index": index, "receipt": receipt, "relative_directory": operation.relative_to(root).as_posix(),
                        "receipt_sha256": sha256_file(receipt_path)})
    expected, request_size = chaff._stable_response_identity(runs,
        application_manifest_sha256=pool["application_workload_sha256"], application_resource_id=0,
        selected_chaff_resource_id=resource["id"], qualified_parallel_chaff_streams=5,
        url=resource["url"], headers=resource["headers"], resource_domain_max_response_bytes=MAX_BODY,
        ft_supplemental_binding=receipt_binding(pool, pool_sha))
    evidence = {"schema_version": 1, "record_type": EVIDENCE, "policy": POLICY,
        "application_workload_sha256": pool["application_workload_sha256"], "chaff_pool_source_sha256": pool_sha,
        "selected_pool_resource_id": resource["id"], "original_root": str(root), "client": str(client),
        "formal_path": str(formal_path), "prepared_path": str(prepared_path), "runtime": runtime,
        "runs": records, "expected_response": expected, "request_stream_bytes": request_size,
        "response_qualification_sha256": chaff.qualification_digest("qcsd-ft-supplemental-response-qualification-v1",
             [chaff._response_run_record(i, run) for i, run in enumerate(runs)]), "scientific_credit": False}
    paths["ft_qualification_evidence"] = native._write(root/"qualification-evidence.json", evidence)
    paths["ft_chaff_manifest"] = native._write(root/"chaff-manifest.json", derive_manifest(pool, pool_sha, evidence,
        sha256_file(paths["ft_qualification_evidence"])))
    need(read(input_path, input_sha, limit=1024**2) == declaration_raw
         and read(declaration["candidate_manifest"]["path"], declaration["candidate_manifest"]["sha256"], limit=1024**2) == candidate_raw
         and read(declaration["discovery_provenance"]["path"], declaration["discovery_provenance"]["sha256"], limit=16*1024**2) == discovery_raw
         and read(formal_path) == formal_raw and read(prepared_path) == prepared_raw,
         "formal/declaration bytes changed across original FT qualification")
    binding = {"schema_version": 1, "policy": POLICY, "allowed_modes": list(MODES),
               **receipt_binding(pool, pool_sha), "application_workload_sha256": pool["application_workload_sha256"],
               "qualification_evidence_sha256": sha256_file(paths["ft_qualification_evidence"]),
               "chaff_manifest_sha256": sha256_file(paths["ft_chaff_manifest"]),
               "selected_pool_resource_id": resource["id"]}
    return {"paths": paths, "binding": binding}

def resource_view(manifest):
    need(type(manifest) is dict and manifest.get("schema_version") == 7 and manifest.get("artifact_type") == MANIFEST
         and manifest.get("policy") == POLICY and manifest.get("qualification_scope") == SCOPE
         and manifest.get("application_resource_id") == 0 and manifest.get("qualified_parallel_chaff_streams") == 5
         and type(manifest.get("resources")) is list and len(manifest["resources"]) == 1,
         "new typed separate FT manifest required")
    row = manifest["resources"][0]
    need(type(row) is dict and set(row) == {"resource", "chaff_qualification"}, "new typed FT resource view required")
    resource = copy.deepcopy(row["resource"])
    resource["chaff_qualification"] = copy.deepcopy(row["chaff_qualification"])
    return resource

def validate_enrollment(root, enrollment, *, full_proof=False):
    """Reconstruct the complete typed binding; optionally replay original runs."""
    from . import resource_study_native as native
    require_registered_ft_runtime(enrollment.get("runtime"))
    binding = enrollment.get("ft_supplemental_chaff")
    need(type(binding) is dict and binding.get("policy") == POLICY and binding.get("allowed_modes") == list(MODES),
         "explicit FT supplemental enrollment required")
    paths = enrollment["paths"]
    loaded = {}
    for key in (*PATH_KEYS, "manifest", "prepared_workload"):
        relative = paths[key]
        loaded[key] = read(within(root, relative), enrollment["files"][relative])
    declaration, candidates = decode(loaded["ft_supplemental_input"]), decode(loaded["ft_candidate_manifest"])
    formal, prepared = decode(loaded["manifest"]), decode(loaded["prepared_workload"])
    original_candidates = checked_input(declaration, formal, digest(loaded["manifest"]), candidates,
        loaded["ft_candidate_manifest"], loaded["ft_discovery_provenance"], enrollment["hostname"])
    need(prepared.get("resources") == formal["resources"] and len(formal["resources"]) == 20,
         "supplemental enrollment changed original formal20")
    pool, evidence, manifest = (decode(loaded[k]) for k in ("ft_pool_source", "ft_qualification_evidence", "ft_chaff_manifest"))
    need(pool.get("schema_version") == 1 and pool.get("artifact_type") == POOL and pool.get("policy") == POLICY
         and pool.get("application_manifest_sha256") == digest(loaded["manifest"])
         and pool.get("application_workload_sha256") == digest(loaded["prepared_workload"])
         and pool.get("candidate_manifest_sha256") == digest(loaded["ft_candidate_manifest"])
         and pool.get("discovery_provenance_sha256") == digest(loaded["ft_discovery_provenance"])
         and pool.get("probe_evidence_sha256") == digest(loaded["ft_probe_evidence"])
         and pool.get("probe_native_commit") == enrollment["runtime"]["native_commit"]
         and evidence.get("record_type") == EVIDENCE and evidence.get("schema_version") == 1
         and evidence.get("policy") == POLICY and evidence.get("runtime") == enrollment["runtime"]
         and evidence.get("scientific_credit") is False and len(evidence.get("runs", [])) == 3,
         "supplemental pool/probe/qualification Source binding changed")
    need(len(pool["resources"]) == len(original_candidates), "declared padding candidate omitted")
    by_id = {row["resource_id"]: row for row in pool["expected_responses"]}
    need(len(by_id) == len(pool["expected_responses"]), "duplicate actual padding response")
    for original, actual in zip(original_candidates, pool["resources"]):
        need(set(actual) == RESOURCE_KEYS and all(actual[k] == original[k] for k in RESOURCE_KEYS - {"known_valid", "content_length", "data_length"}),
             "prepared padding source changed URL/ID/header/dependency metadata")
        response = by_id.pop(actual["id"], None)
        need((response is not None and response["complete"] is True and type(response["status"]) is int
              and 200 <= response["status"] < 300 and type(response["bytes"]) is int and response["bytes"] > 0
              and SHA.fullmatch(response["body_sha256"]) is not None and actual["known_valid"] is True
              and actual["content_length"] == actual["data_length"] == response["bytes"])
             or (response is None and actual == original), "padding response completion was fabricated or omitted")
    need(not by_id, "prepared padding response escaped declared source")
    expected_manifest = derive_manifest(pool, digest(loaded["ft_pool_source"]), evidence, digest(loaded["ft_qualification_evidence"]))
    need(canonical_json(manifest) == canonical_json(expected_manifest), "FT manifest differs from independent actual15-response derivation")
    expected_binding = {"schema_version": 1, "policy": POLICY, "allowed_modes": list(MODES),
        **receipt_binding(pool, digest(loaded["ft_pool_source"])), "application_workload_sha256": pool["application_workload_sha256"],
        "qualification_evidence_sha256": digest(loaded["ft_qualification_evidence"]),
        "chaff_manifest_sha256": digest(loaded["ft_chaff_manifest"]), "selected_pool_resource_id": manifest["selected_pool_resource_id"]}
    need(binding == expected_binding, "explicit FT enrollment binding differs")
    if full_proof:
        ftroot = within(root, paths["ft_pool_source"]).parent
        read_artifact = _inventory_reader(root, ftroot, enrollment["files"])
        probes = decode(loaded["ft_probe_evidence"])
        need(probes["runtime"] == enrollment["runtime"] and probes["policy"] == POLICY
             and len(probes["probes"]) == len(original_candidates), "whole actual probe domain changed")
        prepared_responses = {r["resource_id"]: r for r in pool["expected_responses"]}
        for original, record in zip(original_candidates, probes["probes"]):
            need(record["resource_id"] == original["id"] and type(record["success"]) is bool
                 and record["relative_directory"] == "probes/" + str(original["id"]),
                 "actual padding probe identity/order/namespace changed")
            directory = within(ftroot, record["relative_directory"])
            assessment = _assess_probe(directory, Path(probes["original_root"]), probes["client"],
                probes["runtime"], original, read_artifact)
            need(record["success"] is assessment["working"],
                 "actual working GET was relabelled failed, or failed GET was labelled working")
            if not assessment["working"]:
                need(original["id"] not in prepared_responses and record.get("failure_class") == assessment["failure_class"],
                     "failed padding candidate lacks its authenticated original HTTP/body failure")
                failure = decode(read_artifact(directory/"failure.json"))
                need(type(record.get("error")) is str and bool(record["error"])
                     and failure == {"error": record["error"], "scientific_credit": False},
                     "original failed padding attempt record was omitted or changed")
                continue
            need(record.get("failure_class") is None, "working padding GET cannot carry a failure classification")
            actual = assessment["response"]
            need(prepared_responses[original["id"]] == {"resource_id": original["id"], "status": actual["status"],
                "bytes": actual["bytes"], "body_sha256": actual["body_sha256"], "complete": True}, "actual padding probe differs from prepared Source")
        resource, _ = selected(pool)
        for index, record in enumerate(evidence["runs"]):
            need(record["run_index"] == index, "qualification invocation order changed")
            directory = within(ftroot, record["relative_directory"])
            need(record["relative_directory"] == "qualification/" + str(index), "original FT qualification namespace changed")
            receipt_raw = read_artifact(directory/"native/qualification.json", record["receipt_sha256"])
            need(decode(receipt_raw) == record["receipt"], "original FT qualification bytes differ from full evidence")
            read_artifact(directory/"native/packets.json", record["receipt"]["packet_log_sha256"])
            process = _process(directory, evidence["runtime"], qualification_command(evidence["client"], evidence["prepared_path"],
                evidence["formal_path"], Path(evidence["original_root"])/"pool-source.json",
                Path(evidence["original_root"])/record["relative_directory"]/"native", resource["id"]), read_artifact)
            _native_process_interval(record["receipt"], process)
    return expected_binding

def _process(directory, runtime, expected_command, read_artifact=read, *, require_positive=True):
    started, completed = (decode(read_artifact(Path(directory)/name)) for name in ("started.json", "completed.json"))
    need(type(started.get("started_unix_ns")) is int and type(completed.get("completed_unix_ns")) is int
         and started["started_unix_ns"] < completed["completed_unix_ns"]
         and started["argv"] == completed["argv"] == expected_command
         and started["client_sha256"] == completed["client_sha256"] == runtime["client_sha256"]
         and type(completed["returncode"]) is int and completed["returncode"] in (0, 1)
         and (not require_positive or completed["returncode"] == 0)
         and completed["timed_out"] is False and completed["client_unchanged"] is True and completed["error"] is None
         and completed["stdout_sha256"] == digest(read_artifact(Path(directory)/"stdout.txt", limit=16*1024**2, allow_empty=True))
         and completed["stderr_sha256"] == digest(read_artifact(Path(directory)/"stderr.txt", limit=16*1024**2, allow_empty=True)),
         "original Native padding process lacks exact terminal argv/client/output evidence")
    return started, completed

def _native_process_interval(native_record, process):
    started, completed = process
    need(type(native_record.get("started_unix_ns")) is int and type(native_record.get("ended_unix_ns")) is int
         and started["started_unix_ns"] <= native_record["started_unix_ns"] < native_record["ended_unix_ns"]
         <= completed["completed_unix_ns"], "original Native record is outside its recorded process interval")

def _inventory_reader(root, ftroot, files):
    """No proof read or retained failed artifact may escape the enrolled inventory."""
    root, ftroot = Path(root), Path(ftroot)
    prefix = ftroot.relative_to(root).as_posix() + "/"
    declared = {name for name in files if name.startswith(prefix)}
    actual = set()
    for path in ftroot.rglob("*"):
        need(not path.is_symlink(), "supplemental proof inventory contains a linked artifact")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            need(relative in declared, "original failed/successful proof artifact omitted from enrollment inventory")
            read(path, files[relative], allow_empty=True)
            actual.add(relative)
    need(actual == declared, "enrolled supplemental proof artifact disappeared")
    def bound_read(path, expected=None, **options):
        relative = Path(path).relative_to(root).as_posix()
        need(relative in declared and (expected is None or expected == files[relative]),
             "original proof read lacks its exact enrolled digest")
        return read(path, files[relative], **options)
    return bound_read

def _assess_probe(directory, original_root, client, runtime, original, read_artifact):
    """Classify actual GET evidence, never a caller's success Boolean.

    Missing, interrupted, oversized, malformed or provenance-invalid attempts
    block this preparation. They are not evidence permitting URL exclusion.
    """
    from . import resource_study_native as native
    directory, original_root = Path(directory), Path(original_root)
    relative = "probes/" + str(original["id"])
    input_raw = read_artifact(directory/"input.json")
    input_value = decode(input_raw)
    need(input_value == {"resources": [original]}, "padding probe changed its exact declared request")
    process = _process(directory, runtime, native.probe_command(client,
        original_root/relative/"input.json", original_root/relative/"native", timeout=120,
        max_response_bytes=MAX_BODY), read_artifact, require_positive=False)
    run = decode(read_artifact(directory/"native/run.json"))
    _native_process_interval(run, process)
    need(run.get("method") == "GET" and run.get("request_policy") == "as-defined"
         and type(run.get("seed")) is int and run["seed"] == 0
         and run.get("workload_hash_sha256") == digest(input_raw)
         and run.get("max_response_bytes") == MAX_BODY and run.get("migration_commit") == runtime["native_commit"]
         and run.get("resolved_configuration", {}).get("defense") == {"kind": "none"}
         and run.get("application_response_policy") == "http-2xx-only-v1"
         and run.get("application_workload_source_hash_sha256") is None
         and run.get("chaff_manifest_hash_sha256") is None and run.get("chaff_responses") == []
         and all(run.get(key) is None for key in ("supplemental_chaff_policy",
             "supplemental_chaff_pool_source_hash_sha256", "supplemental_chaff_selected_pool_resource_id",
             "supplemental_chaff_qualification_evidence_sha256"))
         and run.get("terminal_evidence_render_errors") == [], "padding probe Source/input/terminal provenance changed")
    try:
        response = native.inspect_completed_run(run, input_value, manifest_sha256=digest(input_raw),
            max_response_bytes=MAX_BODY, native_commit=runtime["native_commit"])[0]
    except ValueError:
        response = None
    if response is not None:
        need(process[1]["returncode"] == 0, "working GET followed by a failed process is infrastructure failure, not an omitted URL")
        return {"working": True, "failure_class": None, "response": response}
    # Only a complete, well-formed actual HTTP failure or empty response may
    # be omitted. All other original refusals require investigation/retry.
    rows, endpoints = run.get("responses"), run.get("endpoints")
    need(type(rows) is list and len(rows) == 1 and type(endpoints) is list and len(endpoints) == 1
         and endpoints[0].get("id") == 0 and endpoints[0].get("negotiated_protocol") == "h3"
         and endpoints[0].get("origin") in ("https://" + origin(original["url"])[0],
             "https://" + origin(original["url"])[0] + "/"), "unresolved padding transport cannot exclude a candidate")
    response = rows[0]
    status, size, headers = response.get("status"), response.get("bytes"), response.get("response_headers")
    need(response.get("resource_id") == original["id"] and response.get("url") == original["url"]
         and response.get("request_headers") == original["headers"] and response.get("complete") is True
         and type(status) is int and 100 <= status < 600 and type(size) is int and 0 <= size <= MAX_BODY
         and type(response.get("body_sha256")) is str and SHA.fullmatch(response["body_sha256"]) is not None
         and (size != 0 or response["body_sha256"] == digest(b""))
         and type(response.get("request_stream_bytes")) is int and response["request_stream_bytes"] > 0
         and type(headers) is list and all(type(h) is list and len(h) == 2
             and all(type(v) is str for v in h) for h in headers)
         and [v for k, v in headers if k.lower() == ":status"] == [str(status)]
         and response.get("content_length") in (None, size)
         and run.get("completion_status") in ("complete", "error")
         and run.get("error_class") in (None, "runner-execution-v1"),
         "padding failure lacks complete authentic HTTP response evidence")
    lengths = [v for k, v in headers if k.lower() == "content-length"]
    need(not lengths or lengths == [str(size)], "failed padding response has a contradictory body extent")
    if not 200 <= status < 300:
        need(response.get("outcome") == "failed", "non2xx padding outcome is not the original failed GET")
        return {"working": False, "failure_class": "complete-http-non2xx-v1", "response": response}
    need(size == 0 and response.get("outcome") in ("succeeded", "failed"),
         "completed working padding body cannot be omitted on an unrelated run error")
    return {"working": False, "failure_class": "complete-empty-http-body-v1", "response": response}

def artifact_paths(enrollment):
    paths = {key: enrollment["paths"][key] for key in PATH_KEYS}
    paths["ft_formal_prepared_workload"] = enrollment["paths"]["prepared_workload"]
    prefix = str(Path(paths["ft_pool_source"]).parent) + "/"
    for index, relative in enumerate(sorted(p for p in enrollment["files"] if p.startswith(prefix))):
        paths[f"ft_supplemental_asset_{index:04d}"] = relative
    need(len(paths) <= 4096, "bounded complete FT proof inventory required")
    return paths

def validate_runtime_inputs(formal_path, prepared_path, chaff_path, pool_path, run, mode):
    need(mode in MODES and pool_path is not None, "separate FT source is FRONT/Tamaraw only")
    formal, prepared = decode(read(formal_path)), decode(read(prepared_path))
    manifest, pool = decode(read(chaff_path)), decode(read(pool_path))
    resource_view(manifest)
    native_commit = require_registered_ft_native_commit(pool.get("probe_native_commit"))
    need(run is None or run.get("migration_commit") == native_commit, "FT schema7 must retain the same genuine registered probe and runtime Source")
    need(formal["resources"] == prepared["resources"] and len(formal["resources"]) == 20
         and manifest["application_manifest_sha256"] == pool["application_manifest_sha256"] == sha256_file(formal_path)
         and manifest["application_workload_sha256"] == pool["application_workload_sha256"] == sha256_file(prepared_path)
         and manifest["chaff_pool_source_sha256"] == sha256_file(pool_path), "Native FT launch changed a whole Source binding")
    if run is not None:
        need(run.get("supplemental_chaff_policy") == POLICY
             and run.get("supplemental_chaff_pool_source_hash_sha256") == manifest["chaff_pool_source_sha256"]
             and run.get("supplemental_chaff_selected_pool_resource_id") == manifest["selected_pool_resource_id"]
             and run.get("supplemental_chaff_qualification_evidence_sha256") == manifest["qualification_evidence_sha256"],
             "actual Native run changed explicit FT pool/evidence identity")


# Exact new Source identity is a prerequisite, not qualification credit.
SOURCE132_NATIVE158_COMMIT = '912db786562065c4cc28abba21e20e6e6ed17fc8'
def require_native158_runtime(runtime):
    need(type(runtime) is dict and runtime.get("native_commit") == SOURCE132_NATIVE158_COMMIT
         and type(runtime.get("source")) is dict and runtime["source"].get("neqo_commit") == SOURCE132_NATIVE158_COMMIT,
         "explicit FT schema7 requires exact new Native158 runtime and Source identity")
    return runtime


# Additive future authority: old912/158 evidence stays on its literal branch.
# Root renders this only after committing and freezing genuine new Native159.
SOURCE133_NATIVE159_COMMIT = '685b9930d339a6d14c1fb7262c3b91a6ffb963ab'
def require_registered_ft_native_commit(value):
    if value == SOURCE132_NATIVE158_COMMIT:
        return value
    need(re.fullmatch(r"[0-9a-f]{40}", SOURCE133_NATIVE159_COMMIT) is not None
         and value == SOURCE133_NATIVE159_COMMIT,
         "FT schema7 requires literal historical158 or genuine separately registered159 Source")
    return value

def require_registered_ft_runtime(runtime):
    need(type(runtime) is dict, "whole actual FT runtime required")
    value = require_registered_ft_native_commit(runtime.get("native_commit"))
    if value == SOURCE132_NATIVE158_COMMIT:
        return require_native158_runtime(runtime)
    need(type(runtime.get("source")) is dict
         and runtime["source"].get("neqo_commit") == value,
         "new159 FT runtime must retain its own actual Native Source, never relabel158 evidence")
    return runtime
