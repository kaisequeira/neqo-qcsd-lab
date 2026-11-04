"""Prospective fixed-resource preparation from one complete ordinary Native GET.

This is a distinct data role. It asserts complete declared GET replay, never a
rendered browser page, challenge absence, or repeated response stability.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from . import supplied_static_get as get
from . import supplied_static_graph as graph

ROLE = "supplied-static-complete-get-preparation-v1"
COVERAGE = "all-supplied-resources-and-declared-origins-v1"
NAMESPACE = "supplied-static-recorded-execution-namespace-v1"
PRIMARY_EVIDENCE = "single-complete-get-variable-primary-evidence-v1"
RESPONSE_EVIDENCE = "single-complete-get-terminal-http-evidence-v1"
RECEIPT_TYPE = "qcsd-static-fixed-resource-preparation-v1"


def is_static(preparation: Any) -> bool:
    return isinstance(preparation, Mapping) and preparation.get("data_role") == ROLE


def reference(path: Path) -> dict[str, str]:
    path = path.absolute()
    return {"path": str(path), "sha256": graph.digest(get._read(path))}


def open_reference(value: Any) -> Path:
    get._exact(value, {"path", "sha256"}, "static reference")
    if (not isinstance(value["path"], str) or not Path(value["path"]).is_absolute()
        or ".." in Path(value["path"]).parts):
        raise ValueError("static references require absolute nonescaping paths")
    path = Path(value["path"])
    if graph.digest(get._read(path)) != value["sha256"]:
        raise ValueError("static referenced bytes changed")
    return path


def _execution_root(root: Path, mapping: Any, expected: dict[str, str], *, failed_phase: str | None = None) -> Path:
    if mapping is None:
        return root
    get._exact(mapping, {"schema_version", "record_type", "retained_root", "execution_root",
                        "outer_started", "outer_completed", "outer_stdout", "outer_stderr"}, "namespace")
    if (type(mapping["schema_version"]) is not int or mapping["schema_version"] != 1
        or mapping["record_type"] != NAMESPACE or mapping["retained_root"] != str(root)):
        raise ValueError("static execution namespace has another retained root")
    execution = Path(mapping["execution_root"])
    if not execution.is_absolute() or ".." in execution.parts:
        raise ValueError("static execution namespace must be absolute")
    started = get._load(get._read(open_reference(mapping["outer_started"])))
    completed = get._load(get._read(open_reference(mapping["outer_completed"])))
    get._exact(started, {"command", "started_at", "cwd"}, "outer started process")
    get._exact(completed, {"returncode", "completed_at", "elapsed_seconds", "stdout_sha256", "stderr_sha256"}, "outer completed process")
    if (type(completed["returncode"]) is not int
        or (completed["returncode"] != 0 if failed_phase is None else completed["returncode"] == 0)
        or type(completed["elapsed_seconds"]) not in (int, float) or completed["elapsed_seconds"] <= 0
        or completed["stdout_sha256"] != graph.digest(get._read(open_reference(mapping["outer_stdout"])))
        or completed["stderr_sha256"] != graph.digest(get._read(open_reference(mapping["outer_stderr"])))):
        raise ValueError("static namespace lacks a successful closed actual outer execution")
    command = started["command"]
    output_flag = "--get-root" if isinstance(command, list) and command.count("execute-get") == 1 else "--output-root"
    if (not isinstance(command, list) or any(not isinstance(token, str) for token in command)
        or len(command) < 3 or Path(command[0]).name != "docker" or command[1] != "run"
        or command.count(expected["image_digest"]) != 1
        or command.count(output_flag) != 1
        or command.count("--get-root") + command.count("--output-root") != 1
        or command.index(output_flag) + 1 >= len(command)
        or command[command.index(output_flag) + 1] != str(execution)):
        raise ValueError("static namespace differs from the recorded image/operator argv")
    bindings = []
    for index, token in enumerate(command):
        if token != "--mount":
            continue
        if index + 1 == len(command):
            raise ValueError("static namespace mount is incomplete")
        parts = command[index + 1].split(",")
        fields = {}
        for part in parts:
            key, _, value = part.partition("=")
            if key in fields:
                raise ValueError("static namespace mount repeats a key")
            fields[key] = value
        if fields.get("type") != "bind":
            continue
        host = Path(fields.get("src", fields.get("source", "")))
        target = Path(fields.get("dst", fields.get("target", "")))
        if not host.is_absolute() or not target.is_absolute() or ".." in (*host.parts, *target.parts):
            raise ValueError("static namespace mount paths are invalid")
        if root.is_relative_to(host):
            if "readonly" in fields or "ro" in fields:
                raise ValueError("static producer output mount was read-only")
            bindings.append(target / root.relative_to(host))
    if bindings != [execution]:
        raise ValueError("static namespace is not the unique recorded output mount")
    if failed_phase not in (None, "bootstrap", "full"):
        raise ValueError("static failed namespace phase is unknown")
    inner = root / "bootstrap" if failed_phase == "bootstrap" else root
    inner_started = get._load(get._read(inner / "native-started.json"))
    inner_completed = get._load(get._read(inner / "native-completed.json"))
    if not (get._time(started["started_at"]) <= get._time(inner_started["started_at"])
            < get._time(inner_completed["completed_at"]) <= get._time(completed["completed_at"])):
        raise ValueError("static inner GET is outside the actual mounted execution")
    return execution


def namespace_mapping(root: Path, execution_root: Path, *, started: Path, completed: Path,
                      stdout: Path, stderr: Path, expected_runtime: dict[str, str]) -> dict[str, Any]:
    value = {"schema_version": 1, "record_type": NAMESPACE, "retained_root": str(root.absolute()),
             "execution_root": str(execution_root), "outer_started": reference(started),
             "outer_completed": reference(completed), "outer_stdout": reference(stdout),
             "outer_stderr": reference(stderr)}
    _execution_root(root.absolute(), value, get.runtime_binding(expected_runtime))
    return value


def reopen_get(root: Path, *, expected_runtime: dict[str, str], source_sha256: str,
               domain: str, namespace: Any = None) -> dict[str, Any]:
    """Reconstruct original GET evidence, allowing only a recorded mount relocation.

    The original producer and its seven-file package remain unchanged. This
    branch repeats its declaration/process checks with the recorded execution
    root for argv only; its full raw Native validator runs on retained bytes.
    No scientific field, original proof, or producer Source label is rewritten.
    """
    root = root.absolute()
    expected = get.runtime_binding(expected_runtime)
    saved = get._load(get._read(root / "full-get-proof.json"))
    from . import supplied_static_bootstrap_get as bootstrap
    if saved.get("record_type") == bootstrap.PROOF_TYPE:
        return bootstrap.validate_proof(root, expected_runtime=expected, source_sha256=source_sha256,
                                        domain=domain, namespace=namespace)
    execution = _execution_root(root, namespace, expected)
    if namespace is None:
        return get.validate_proof(root, expected_runtime=expected, source_sha256=source_sha256, domain=domain)
    source = get._read(root / "source-list.json")
    manifest = get._load(get._read(root / "native-input.json"))
    binding = get._load(get._read(root / "input-binding.json"))
    graph.verify_import(source, source_sha256, domain, manifest, binding)
    if get.class_acquisition.unsafe_catalogue_domain_reason(domain) is not None:
        raise ValueError("static GET primary domain is excluded")
    declaration = get._exact(get._load(get._read(root / "declaration.json")), {
        "schema_version", "record_type", "declared_at", "source_sha256", "domain", "runtime_binding",
        "producer_role", "producer_sources", "input_binding_sha256", "native_input_sha256",
        "max_response_bytes", "timeout_seconds", "primary_claim", "public_origin_policy",
        "scientific_credit", "site_credit", "formal_accepted_trace_count"}, "declaration")
    if (type(declaration["schema_version"]) is not int or declaration["schema_version"] != 1
        or declaration["record_type"] != get.PROOF_TYPE or declaration["runtime_binding"] != expected
        or declaration["source_sha256"] != source_sha256 or declaration["domain"] != domain
        or declaration["producer_role"] != "external-declared-static-get-authority-v1"
        or declaration["producer_sources"] != get.producer_sources()
        or declaration["input_binding_sha256"] != graph.digest(get._read(root / "input-binding.json"))
        or declaration["native_input_sha256"] != graph.digest(get._read(root / "native-input.json"))
        or declaration["primary_claim"] != get.PRIMARY_CLAIM or declaration["public_origin_policy"] != get.PUBLIC_POLICY
        or declaration["scientific_credit"] is not False
        or type(declaration["site_credit"]) is not int or declaration["site_credit"] != 0
        or type(declaration["formal_accepted_trace_count"]) is not int or declaration["formal_accepted_trace_count"] != 0):
        raise ValueError("static GET original declaration/source differs")
    get._runtime(get._load(get._read(root / "runtime.json")), expected)
    started = get._exact(get._load(get._read(root / "native-started.json")), {
        "schema_version", "command", "environment", "started_at", "declaration_sha256", "client_sha256"}, "started process")
    if (type(started["schema_version"]) is not int or started["schema_version"] != 1
        or started["command"] != get.native_command(execution, declaration["max_response_bytes"], declaration["timeout_seconds"])
        or started["environment"] != {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                                        "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)}
        or started["declaration_sha256"] != graph.digest(get._read(root / "declaration.json"))
        or started["client_sha256"] != expected["client_sha256"]):
        raise ValueError("static GET actual command/environment differs from its recorded namespace")
    completed = get._exact(get._load(get._read(root / "native-completed.json")), {
        "schema_version", "returncode", "timed_out", "completed_at", "elapsed_ns", "stdout_sha256", "stderr_sha256",
        "outputs", "client_sha256", "source_manifest_sha256"}, "completed process")
    outputs = {name: graph.digest(get._read(root / "native" / name)) for name in get.FILES}
    if (type(completed["schema_version"]) is not int or completed["schema_version"] != 1
        or type(completed["returncode"]) is not int or completed["returncode"] != 0 or completed["timed_out"] is not False
        or get._number(completed["elapsed_ns"], "elapsed") < 1 or completed["outputs"] != outputs
        or completed["stdout_sha256"] != graph.digest(get._read(root / "native.stdout.log"))
        or completed["stderr_sha256"] != graph.digest(get._read(root / "native.stderr.log"))
        or completed["client_sha256"] != expected["client_sha256"]
        or completed["source_manifest_sha256"] != expected["source_manifest_sha256"]
        or not get._time(declaration["declared_at"]) <= get._time(started["started_at"]) < get._time(completed["completed_at"])):
        raise ValueError("static GET lacks its successful actual process/raw binding")
    native = get._run_proof(get._load(get._read(root / "native/run.json")), root, declaration, started, completed,
                            manifest, get._load(get._read(root / "dns.json")))
    files = {name: graph.digest(get._read(root / name)) for name in (
        "source-list.json", "native-input.json", "input-binding.json", "declaration.json", "runtime.json", "dns.json",
        "native-started.json", "native-completed.json", "native.stdout.log", "native.stderr.log",
        *["native/" + name for name in get.FILES])}
    proof = {"schema_version": 1, "record_type": get.PROOF_TYPE, "data_role": graph.INPUT_ROLE,
             "domain": domain, "source_sha256": source_sha256, "runtime_binding": expected,
             "producer_role": declaration["producer_role"], "producer_sources": declaration["producer_sources"],
             "declared_at": declaration["declared_at"], "completed_at": completed["completed_at"],
             "primary_claim": get.PRIMARY_CLAIM, "browser_discovery_claim": False, "challenge_absence_claim": False,
             "body_contents_retained": False, "resource_count": len(manifest["resources"]),
             "origin_count": len(binding["origins"]), "full_list_coverage": True, "native": native, "files": files,
             "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}
    if proof != get._load(get._read(root / "full-get-proof.json")):
        raise ValueError("static GET retained proof differs from reopened mounted raw evidence")
    return proof


def _prepared(root: Path, evidence: dict[str, Any], proof: dict[str, Any], policies: dict[str, str]) -> dict[str, Any]:
    from .application_response_policy import (APPROVED_ORIGINS_CHAFF_POLICY, COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
                                               VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
    from . import capture_acceptance_policy as capture
    from .supplied_static_bootstrap_get import PROOF_TYPE as BOOTSTRAP_TYPE
    if proof.get("record_type") != BOOTSTRAP_TYPE:
        raise ValueError("static preparation requires real primary bootstrap, not a neutral-input GET receipt")
    allowed = {capture.FIELD: capture.ACK_START_POLICY, capture.TAMARAW_FIELD: capture.TAMARAW_POLICY,
               capture.FRONT_FIELD: capture.FRONT_WINDOW_POLICY, capture.TERMINAL_PRIMARY_FIELD: capture.TERMINAL_PRIMARY_POLICY}
    if policies != allowed:
        raise ValueError("static preparation requires the explicitly fixed current traffic policy tuple")
    neutral = get._load(get._read(root / ("neutral-input.json" if proof["schema_version"] == 2 else "native-input.json")))
    run = get._load(get._read(root / "native/run.json"))
    original = get._load(get._read(root / "input-binding.json"))
    source = get._runtime(get._load(get._read(root / "runtime.json")), proof["runtime_binding"])
    resources = deepcopy(neutral["resources"])
    responses = {row["resource_id"]: row for row in run["responses"]}
    for row in resources:
        response = responses[row["id"]]
        row.update(content_length=response["bytes"], data_length=response["bytes"],
                   known_valid=200 <= response["status"] < 300, chaff_priority=False)
    primary_origin = get._origin(resources[0]["url"])
    secondary = [row for row in resources if get._origin(row["url"]) != primary_origin
                 and row["known_valid"] and responses[row["id"]]["bytes"] > 0]
    if not secondary:
        raise ValueError("static preparation needs an actual nonempty successful secondary-origin resource")
    # Require an actual HTML-labelled primary, without claiming to inspect its body.
    from .application_response_policy import _primary_content_type
    _primary_content_type(responses[0])
    response_evidence = {"schema_version": 2, "data_role": ROLE, "policy": RESPONSE_EVIDENCE,
                         "complete_get_proof_sha256": evidence["proof"]["sha256"]}
    primary_evidence = {"schema_version": 2, "data_role": ROLE, "policy": PRIMARY_EVIDENCE,
                        "complete_get_proof_sha256": evidence["proof"]["sha256"],
                        "complete_get_primary_responses": [{key: deepcopy(responses[0][key]) for key in
                            ("resource_id", "url", "status", "bytes", "body_sha256", "content_length",
                             "request_headers", "response_headers", "complete", "outcome")}]}
    declaration = get._load(get._read(root / "declaration.json"))
    from . import supplied_static_admission as admission
    context = admission.load_context(open_reference(proof["context"]).parent)
    limits = admission.context_limits(context)
    if declaration["max_response_bytes"] != limits["max_response_bytes"]:
        raise ValueError("static GET and prospective formal capture response caps differ")
    preparation = {"data_role": ROLE, "static_get_evidence": evidence,
        "source_url": resources[0]["url"], "final_url": resources[0]["url"],
        "approved_origins": original["origins"], "max_response_bytes": limits["max_response_bytes"],
        "timeout_seconds": declaration["timeout_seconds"], "complete_get_runs": 1,
        "browser_discovery_claim": False, "challenge_absence_claim": False, "response_stability_claim": False,
        "lab_source": {**source, "image_digest": proof["runtime_binding"]["image_digest"]},
        "prepare_image_digest": proof["runtime_binding"]["image_digest"], **proof["native"]["native_provenance"],
        "expected_responses": [{key: response[key] for key in ("resource_id", "status", "bytes", "body_sha256")}
                                for response in sorted(run["responses"], key=lambda row: row["resource_id"])],
        "qualified_chaff_origin_policy": APPROVED_ORIGINS_CHAFF_POLICY,
        "application_response_policy": COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        "application_response_policy_evidence": response_evidence,
        "primary_document_identity_policy": VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY,
        "primary_document_identity_evidence": primary_evidence,
        "coverage_admission": {"schema_version": 1, "policy": COVERAGE, "required_origins": original["origins"],
                               "required_resources": [{"id": row["id"], "url": row["url"]} for row in resources]},
        "udp_payload_qualification": {"schema_version": 2, "outgoing_udp_payload_ceiling": 1200,
                                      "incoming_udp_payload_limit": 65527, "runs": [proof["native"]["udp_payloads"]]},
        **policies}
    return {"preparation": preparation, "resources": resources}


def build_preparation(root: Path, *, expected_runtime: dict[str, str], source_sha256: str, domain: str,
                      policies: dict[str, str], namespace: Any = None) -> dict[str, Any]:
    root = root.absolute()
    proof = reopen_get(root, expected_runtime=expected_runtime, source_sha256=source_sha256, domain=domain, namespace=namespace)
    evidence = {"schema_version": 1, "record_type": RECEIPT_TYPE, "root": str(root),
                "proof": reference(root / "full-get-proof.json"), "runtime_binding": expected_runtime,
                "source_sha256": source_sha256, "domain": domain, "namespace": namespace}
    return _prepared(root, evidence, proof, policies)


def validate_static_preparation(value: Any, resources: list[dict[str, Any]]) -> dict[str, Any]:
    if not is_static(value):
        raise ValueError("static preparation role is absent or unknown")
    evidence = get._exact(value.get("static_get_evidence"), {"schema_version", "record_type", "root", "proof",
                         "runtime_binding", "source_sha256", "domain", "namespace"}, "preparation evidence")
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1 or evidence["record_type"] != RECEIPT_TYPE:
        raise ValueError("static preparation evidence type differs")
    root = Path(evidence["root"])
    if not root.is_absolute() or ".." in root.parts or open_reference(evidence["proof"]) != root / "full-get-proof.json":
        raise ValueError("static preparation proof namespace changed")
    proof = reopen_get(root, expected_runtime=evidence["runtime_binding"], source_sha256=evidence["source_sha256"],
                       domain=evidence["domain"], namespace=evidence["namespace"])
    from . import capture_acceptance_policy as capture
    policies = {key: value.get(key) for key in (capture.FIELD, capture.TAMARAW_FIELD, capture.FRONT_FIELD, capture.TERMINAL_PRIMARY_FIELD)}
    expected = _prepared(root, evidence, proof, policies)
    if expected != {"preparation": value, "resources": resources}:
        raise ValueError("static preparation differs from the complete original GET/resource/header/DAG evidence")
    return proof


def preparation_roots(value: Mapping[str, Any]) -> list[Path]:
    """Derive transport only; ordinary validation still reopens every raw proof."""
    evidence = value["static_get_evidence"]
    roots = {Path(evidence["root"])}
    if evidence["namespace"] is not None:
        roots.update(open_reference(evidence["namespace"][key]).parent for key in
                     ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return sorted(roots)
