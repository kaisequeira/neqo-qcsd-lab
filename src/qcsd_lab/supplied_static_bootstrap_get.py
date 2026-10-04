"""Real primary GET approval followed by one exact full-list ordinary GET.

The original neutral input is retained. Only root 0 gains known_valid, after
an actual successful strict 2xx GET; no browser or body-content claim is made.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import os
from pathlib import Path
import socket
import subprocess
import time
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from . import supplied_static_get as get
from . import supplied_static_graph as graph

PROOF_TYPE = "supplied-static-primary-bootstrapped-complete-native-get-evidence-v2"
STRICT_POLICY = "http-2xx-only-v1"
PRODUCER_ROLE = "external-declared-primary-then-complete-static-get-authority-v2"

# One known verifier transition, identified by the original immutable producer
# package d738828f825ffde67e73522cc7dc23ebf4535d278c9cc9ce6e48afdd47b3f111.
# These are original producer bytes, never replacements for current provenance.
RETAINED_PRODUCER_VERSION = "supplied-static-d738-primary-bootstrap-verifier-v1"
RETAINED_PRODUCER_SOURCES = MappingProxyType({
    "qcsd_lab.chaff_qualification": "9b5bcdefbd2c0c547c56d6590d95d2e38df81bbf65e22732447a2c50c94ad2e3",
    "qcsd_lab.class_acquisition": "062e0f4b1829f141a010027a1c2bd3f960a06bca305e91e49f20d52b971288de",
    "qcsd_lab.prepare": "b9ecb4ed9135f1613cfb356778a13e29fc7249cf273dd6bbce320d878822d12b",
    "qcsd_lab.rapid_site_admission": "8f6ba8905a8a396c80de58cfa7fdfe1b7dac60eb02a80bc0f093bb9790ad3e6d",
    "qcsd_lab.supplied_static_admission": "f33350761098c2b39811b45dd12e9fa3608483cf0de8d5761f68ab0a3d4985fc",
    "qcsd_lab.supplied_static_bootstrap_get": "a8d4181a864f24a2638bae8b3160f3bf0a2949da17e576e34a8129832f3b6db2",
    "qcsd_lab.supplied_static_get": "6969e653ff1dab76bbbea10f2654480d205a951a932c9200d431f967886cdaac",
    "qcsd_lab.supplied_static_graph": "87370d25d526a22cac7519a721aed0db19b72fa5957a353301782779409d4efa",
    "qcsd_lab.supplied_static_preparation": "087ebcea7cf8c793a82cbf40bcb0e77fb1555ba50b648c02af85e52c76641f44",
    "qcsd_lab.util": "d4d3f35cf86360c3b40b0ae21f5845444439369b0b27c86be7d0e31d2216da76",
})


def producer_sources() -> dict[str, str]:
    from . import supplied_static_admission as admission
    from . import supplied_static_preparation as preparation
    modules = {"qcsd_lab.supplied_static_bootstrap_get": Path(__file__),
               "qcsd_lab.supplied_static_admission": Path(admission.__file__),
               "qcsd_lab.supplied_static_preparation": Path(preparation.__file__),
               "qcsd_lab.rapid_site_admission": Path(admission.receipts.__file__)}
    return {**get.producer_sources(), **{name: graph.digest(get._read(path)) for name, path in modules.items()}}


def _recognized_producer_sources(recorded: Any) -> bool:
    current = producer_sources()
    if recorded == current:
        return True
    # Only the two named verifier modules change in this version. A changed
    # graph, admission, preparation or Native qualifier needs a new review.
    return (recorded == dict(RETAINED_PRODUCER_SOURCES)
            and all(current.get(name) == digest for name, digest in RETAINED_PRODUCER_SOURCES.items()
                    if name not in {"qcsd_lab.supplied_static_bootstrap_get", "qcsd_lab.supplied_static_get"}))


def _command(root: Path, max_bytes: int, timeout: int, policy: str) -> list[str]:
    value = get.native_command(root, max_bytes, timeout)
    value[value.index("--application-response-policy") + 1] = policy
    return value


def _inputs(source: bytes, digest: str, domain: str) -> tuple[dict, dict, dict, dict]:
    neutral, binding = graph.import_graph(source, digest, domain)
    bootstrap = {"resources": [deepcopy(neutral["resources"][0])]}
    full = deepcopy(neutral)
    full["resources"][0]["known_valid"] = True
    return neutral, binding, bootstrap, full


def _candidate_identity(context, domain: str) -> dict[str, int]:
    rows = [row for row in context.candidates if row["domain"] == domain]
    if len(rows) != 1:
        raise ValueError("static GET candidate is not unique in its declared queue")
    return {"candidate_queue_position": rows[0]["position"], "candidate_source_position": rows[0]["source_position"]}


def _step(root: Path, declaration: dict, manifest: dict, *, policy: str, execution: Path) -> dict[str, Any]:
    started = get._exact(get._load(get._read(root / "native-started.json")), {
        "schema_version", "command", "environment", "started_at", "declaration_sha256", "client_sha256"}, "started process")
    expected = declaration["runtime_binding"]
    if (type(started["schema_version"]) is not int or started["schema_version"] != 1
        or started["command"] != _command(execution, declaration["max_response_bytes"], declaration["timeout_seconds"], policy)
        or started["environment"] != {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                                        "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)}
        or started["declaration_sha256"] != declaration["_raw_sha256"]
        or started["client_sha256"] != expected["client_sha256"]
        or get._load(get._read(root / "native-input.json")) != manifest):
        raise ValueError("static bootstrap actual command/input/environment differs")
    completed = get._exact(get._load(get._read(root / "native-completed.json")), {
        "schema_version", "returncode", "timed_out", "completed_at", "elapsed_ns", "stdout_sha256", "stderr_sha256",
        "outputs", "client_sha256", "source_manifest_sha256"}, "completed process")
    if (type(completed["schema_version"]) is not int or completed["schema_version"] != 1
        or type(completed["returncode"]) is not int or completed["returncode"] != 0
        or completed["timed_out"] is not False or get._number(completed["elapsed_ns"], "elapsed") < 1
        or completed["outputs"] != {name: graph.digest(get._read(root / "native" / name)) for name in get.FILES}
        or completed["stdout_sha256"] != graph.digest(get._read(root / "native.stdout.log"))
        or completed["stderr_sha256"] != graph.digest(get._read(root / "native.stderr.log"))
        or completed["client_sha256"] != expected["client_sha256"]
        or completed["source_manifest_sha256"] != expected["source_manifest_sha256"]
        or not get._time(declaration["declared_at"]) <= get._time(started["started_at"]) < get._time(completed["completed_at"])):
        raise ValueError("static bootstrap lacks a successful actual process/raw closure")
    return get._run_proof(get._load(get._read(root / "native/run.json")), root, declaration, started, completed,
                          manifest, get._load(get._read(root / "dns.json")), response_policy=policy)


def build_proof(root: Path, *, expected_runtime: dict[str, str], source_sha256: str, domain: str,
                namespace: Any = None) -> dict[str, Any]:
    from . import supplied_static_admission as admission
    from . import supplied_static_preparation as preparation
    root = root.absolute()
    expected = get.runtime_binding(expected_runtime)
    execution = preparation._execution_root(root, namespace, expected)
    source = get._read(root / "source-list.json")
    neutral, binding, bootstrap, full = _inputs(source, source_sha256, domain)
    if (get._load(get._read(root / "neutral-input.json")) != neutral
        or get._load(get._read(root / "input-binding.json")) != binding
        or get.class_acquisition.unsafe_catalogue_domain_reason(domain) is not None):
        raise ValueError("static bootstrap differs from exact supplied neutral graph or public domain policy")
    declaration_raw = get._read(root / "declaration.json")
    declaration = get._exact(get._load(declaration_raw), {"schema_version", "record_type", "declared_at", "source_sha256",
        "domain", "runtime_binding", "producer_role", "producer_sources", "context", "input_binding_sha256",
        "candidate_queue_position", "candidate_source_position",
        "neutral_input_sha256", "bootstrap_input_sha256", "full_input_sha256", "max_response_bytes", "timeout_seconds",
        "primary_claim", "public_origin_policy", "scientific_credit", "site_credit", "formal_accepted_trace_count"}, "bootstrap declaration")
    context = admission.load_context(preparation.open_reference(declaration["context"]).parent)
    candidate = _candidate_identity(context, domain)
    if (type(declaration["schema_version"]) is not int or declaration["schema_version"] != 2
        or declaration["record_type"] != PROOF_TYPE or declaration["producer_role"] != PRODUCER_ROLE
        or declaration["runtime_binding"] != expected or not _recognized_producer_sources(declaration["producer_sources"])
        or declaration["source_sha256"] != source_sha256 or declaration["domain"] != domain
        or any(type(declaration[key]) is not int or declaration[key] != value for key, value in candidate.items())
        or context.provenance["runtime_binding"] != expected or context.source_bytes != source
        or declaration["max_response_bytes"] != admission.context_limits(context)["max_response_bytes"]
        or declaration["timeout_seconds"] != admission.context_limits(context)["timeout_seconds"]
        or preparation.open_reference(declaration["context"]) != context.root / "provenance.json"
        or not get._time(context.provenance["declared_at"]) <= get._time(declaration["declared_at"])
        or declaration["input_binding_sha256"] != graph.digest(get._read(root / "input-binding.json"))
        or declaration["neutral_input_sha256"] != graph.digest(get._read(root / "neutral-input.json"))
        or declaration["bootstrap_input_sha256"] != graph.digest(graph.canonical_bytes(bootstrap))
        or declaration["full_input_sha256"] != graph.digest(graph.canonical_bytes(full))
        or declaration["primary_claim"] != get.PRIMARY_CLAIM or declaration["public_origin_policy"] != get.PUBLIC_POLICY
        or declaration["scientific_credit"] is not False or type(declaration["site_credit"]) is not int or declaration["site_credit"] != 0
        or type(declaration["formal_accepted_trace_count"]) is not int or declaration["formal_accepted_trace_count"] != 0):
        raise ValueError("static bootstrap prospective context/source/input/runtime declaration differs")
    get._runtime(get._load(get._read(root / "runtime.json")), expected)
    declared = {**declaration, "_raw_sha256": graph.digest(declaration_raw)}
    primary = _step(root / "bootstrap", declared, bootstrap, policy=STRICT_POLICY, execution=execution / "bootstrap")
    if get._time(get._load(get._read(root / "bootstrap/native-completed.json"))["completed_at"]) > get._time(
            get._load(get._read(root / "native-started.json"))["started_at"]):
        raise ValueError("static full graph began before actual strict primary approval")
    native = _step(root, declared, full, policy=get.RESPONSE_POLICY, execution=execution)
    if namespace is not None:
        outer_started = get._load(get._read(preparation.open_reference(namespace["outer_started"])))
        outer_completed = get._load(get._read(preparation.open_reference(namespace["outer_completed"])))
        primary_started = get._load(get._read(root / "bootstrap/native-started.json"))
        primary_completed = get._load(get._read(root / "bootstrap/native-completed.json"))
        if not (get._time(outer_started["started_at"]) <= get._time(primary_started["started_at"])
                < get._time(primary_completed["completed_at"]) <= get._time(outer_completed["completed_at"])):
            raise ValueError("static primary bootstrap lies outside its recorded mounted execution")
    files = {name: graph.digest(get._read(root / name)) for name in
             ("source-list.json", "neutral-input.json", "input-binding.json", "runtime.json", "declaration.json")}
    for prefix in ("", "bootstrap/"):
        files.update({prefix + name: graph.digest(get._read(root / (prefix + name))) for name in
                      ("native-input.json", "dns.json", "native-started.json", "native-completed.json", "native.stdout.log", "native.stderr.log",
                       *["native/" + name for name in get.FILES])})
    completed = get._load(get._read(root / "native-completed.json"))
    return {"schema_version": 2, "record_type": PROOF_TYPE, "data_role": graph.INPUT_ROLE,
            "domain": domain, "source_sha256": source_sha256, "runtime_binding": expected, **candidate,
            "producer_role": PRODUCER_ROLE, "producer_sources": declaration["producer_sources"],
            "context": declaration["context"], "declared_at": declaration["declared_at"], "completed_at": completed["completed_at"],
            "primary_claim": get.PRIMARY_CLAIM, "browser_discovery_claim": False, "challenge_absence_claim": False,
            "body_contents_retained": False, "resource_count": len(full["resources"]), "origin_count": len(binding["origins"]),
            "full_list_coverage": True, "bootstrap_native": primary, "native": native, "files": files,
            "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}


def validate_proof(root: Path, **arguments: Any) -> dict[str, Any]:
    actual = build_proof(root, **arguments)
    if actual != get._load(get._read(root / "full-get-proof.json")):
        raise ValueError("static bootstrap retained proof differs from actual raw evidence")
    return actual


def failure_proof(root: Path, *, expected_runtime: dict[str, str], source_sha256: str,
                  domain: str, namespace: Any = None) -> dict[str, Any]:
    """Reopen a failed Native process or a proven strict primary rejection."""
    from . import supplied_static_admission as admission
    from . import supplied_static_preparation as preparation
    root = root.absolute()
    expected = get.runtime_binding(expected_runtime)
    source = get._read(root / "source-list.json")
    neutral, binding, bootstrap, full = _inputs(source, source_sha256, domain)
    raw = get._read(root / "declaration.json")
    declaration = get._load(raw)
    fields = {"schema_version", "record_type", "declared_at", "source_sha256", "domain", "runtime_binding", "producer_role",
              "candidate_queue_position", "candidate_source_position",
              "producer_sources", "context", "input_binding_sha256", "neutral_input_sha256", "bootstrap_input_sha256",
              "full_input_sha256", "max_response_bytes", "timeout_seconds", "primary_claim", "public_origin_policy",
              "scientific_credit", "site_credit", "formal_accepted_trace_count"}
    get._exact(declaration, fields, "failed declaration")
    context = admission.load_context(preparation.open_reference(declaration["context"]).parent)
    candidate = _candidate_identity(context, domain)
    if (type(declaration["schema_version"]) is not int or declaration["schema_version"] != 2
        or declaration["record_type"] != PROOF_TYPE or declaration["producer_role"] != PRODUCER_ROLE
        or not _recognized_producer_sources(declaration["producer_sources"]) or declaration["runtime_binding"] != expected
        or declaration["source_sha256"] != source_sha256 or declaration["domain"] != domain
        or any(type(declaration[key]) is not int or declaration[key] != value for key, value in candidate.items())
        or context.source_bytes != source or context.provenance["runtime_binding"] != expected
        or declaration["max_response_bytes"] != admission.context_limits(context)["max_response_bytes"]
        or declaration["timeout_seconds"] != admission.context_limits(context)["timeout_seconds"]
        or preparation.open_reference(declaration["context"]) != context.root / "provenance.json"
        or get._load(get._read(root / "neutral-input.json")) != neutral or get._load(get._read(root / "input-binding.json")) != binding
        or declaration["neutral_input_sha256"] != graph.digest(graph.canonical_bytes(neutral))
        or declaration["input_binding_sha256"] != graph.digest(graph.canonical_bytes(binding))
        or declaration["bootstrap_input_sha256"] != graph.digest(graph.canonical_bytes(bootstrap))
        or declaration["full_input_sha256"] != graph.digest(graph.canonical_bytes(full))
        or declaration["primary_claim"] != get.PRIMARY_CLAIM or declaration["public_origin_policy"] != get.PUBLIC_POLICY
        or declaration["scientific_credit"] is not False
        or type(declaration["site_credit"]) is not int or declaration["site_credit"] != 0
        or type(declaration["formal_accepted_trace_count"]) is not int or declaration["formal_accepted_trace_count"] != 0
        or not get._time(context.provenance["declared_at"]) <= get._time(declaration["declared_at"])):
        raise ValueError("static failed GET differs from prospective full-list/source/runtime inputs")
    get._runtime(get._load(get._read(root / "runtime.json")), expected)
    phase = "full" if (root / "native-started.json").exists() else "bootstrap"
    execution = preparation._execution_root(root, namespace, expected, failed_phase=phase)
    child = root if phase == "full" else root / "bootstrap"
    manifest = full if phase == "full" else bootstrap
    policy = get.RESPONSE_POLICY if phase == "full" else STRICT_POLICY
    started = get._exact(get._load(get._read(child / "native-started.json")), {
        "schema_version", "command", "environment", "started_at", "declaration_sha256", "client_sha256"}, "failed started process")
    completed = get._exact(get._load(get._read(child / "native-completed.json")), {
        "schema_version", "returncode", "timed_out", "completed_at", "elapsed_ns", "stdout_sha256", "stderr_sha256",
        "outputs", "client_sha256", "source_manifest_sha256"}, "failed completed process")
    if (type(started["schema_version"]) is not int or started["schema_version"] != 1
        or started["command"] != _command(execution if phase == "full" else execution / "bootstrap",
                                           declaration["max_response_bytes"], declaration["timeout_seconds"], policy)
        or started["environment"] != {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                                        "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)}
        or started["declaration_sha256"] != graph.digest(raw) or started["client_sha256"] != expected["client_sha256"]
        or get._load(get._read(child / "native-input.json")) != manifest
        or type(completed["schema_version"]) is not int or completed["schema_version"] != 1
        or not ((type(completed["returncode"]) is int and completed["returncode"] != 0 and completed["timed_out"] is False)
                or (completed["returncode"] is None and completed["timed_out"] is True)
                or (phase == "bootstrap" and type(completed["returncode"]) is int
                    and completed["returncode"] == 0 and completed["timed_out"] is False))
        or get._number(completed["elapsed_ns"], "elapsed") < 1
        or completed["client_sha256"] != expected["client_sha256"]
        or completed["source_manifest_sha256"] != expected["source_manifest_sha256"]
        or completed["stdout_sha256"] != graph.digest(get._read(child / "native.stdout.log"))
        or completed["stderr_sha256"] != graph.digest(get._read(child / "native.stderr.log"))
        or completed["outputs"] != {name: graph.digest(get._read(child / "native" / name)) for name in get.FILES if (child / "native" / name).is_file()}
        or not get._time(declaration["declared_at"]) <= get._time(started["started_at"]) < get._time(completed["completed_at"])):
        raise ValueError("static deferral lacks a real failed Native command/raw closure")
    if completed["returncode"] == 0:
        # Exit zero alone proves no failure. This branch must reopen all four
        # outputs and prove the complete strict non-2xx primary rejection.
        if completed["outputs"] != {name: graph.digest(get._read(child / "native" / name)) for name in get.FILES}:
            raise ValueError("static deferral lacks complete rejected-primary raw outputs")
        get._run_proof(get._load(get._read(child / "native/run.json")), child, declaration, started, completed,
                       manifest, get._load(get._read(child / "dns.json")), response_policy=STRICT_POLICY,
                       rejected_primary=True)
    if phase == "full":
        _step(root / "bootstrap", {**declaration, "_raw_sha256": graph.digest(raw)}, bootstrap,
              policy=STRICT_POLICY, execution=execution / "bootstrap")
        if get._time(get._load(get._read(root / "bootstrap/native-completed.json"))["completed_at"]) > get._time(started["started_at"]):
            raise ValueError("static failed full GET began before primary approval")
    origins = sorted({get._origin(row["url"]) for row in manifest["resources"]},
                     key=lambda origin: (urlsplit(origin).hostname, urlsplit(origin).port or 443))
    get._dns(get._load(get._read(child / "dns.json")), origins, declaration["declared_at"], started["started_at"])
    prefix = "" if phase == "full" else "bootstrap/"
    files = {name: graph.digest(get._read(root / name)) for name in
             ("source-list.json", "neutral-input.json", "input-binding.json", "runtime.json", "declaration.json")}
    files.update({prefix + name: graph.digest(get._read(child / name)) for name in
                  ("native-input.json", "dns.json", "native-started.json", "native-completed.json", "native.stdout.log", "native.stderr.log")})
    files.update({prefix + "native/" + name: digest for name, digest in completed["outputs"].items()})
    return {"phase": phase, "outcome": "operational-deferred", "files": files,
            "completed_at": completed["completed_at"], "formal_accepted_trace_count": 0, "scientific_credit": False}


def _execute_step(root: Path, declaration: dict, manifest: dict, client: Path, *, policy: str) -> None:
    get._json(root / "native-input.json", manifest)
    origins = sorted({get._origin(row["url"]) for row in manifest["resources"]}, key=lambda origin: (urlsplit(origin).hostname, urlsplit(origin).port or 443))
    observations = []
    for origin in origins:
        started = datetime.now(UTC).isoformat()
        parsed = urlsplit(origin)
        answers = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(parsed.hostname, parsed.port or 443,
                                                                           socket.AF_UNSPEC, socket.SOCK_DGRAM)))
        observations.append({"origin": origin, "started_at": started, "completed_at": datetime.now(UTC).isoformat(), "answers": answers})
    dns = {"schema_version": 1, "policy": get.PUBLIC_POLICY, "observations": observations}
    get._json(root / "dns.json", dns)
    now = datetime.now(UTC).isoformat()
    get._dns(dns, origins, declaration["declared_at"], now)
    command = _command(root, declaration["max_response_bytes"], declaration["timeout_seconds"], policy)
    expected = declaration["runtime_binding"]
    environment = {"QCSD_PUBLIC_ORIGIN_ONLY": "1", "QCSD_LAB_IMAGE_DIGEST": expected["image_digest"],
                   "QCSD_LAB_SOURCE_METADATA": str(get.util.DEFAULT_SOURCE_METADATA)}
    get.chaff_qualification._recheck_bound_neqo_client(client, expected["client_sha256"])
    get._json(root / "native-started.json", {"schema_version": 1, "command": command, "environment": environment,
          "started_at": now, "declaration_sha256": declaration["_raw_sha256"], "client_sha256": expected["client_sha256"]})
    child_env = {key: value for key, value in os.environ.items() if not key.startswith("QCSD_")}
    child_env.update(environment)
    before = time.monotonic_ns()
    code, timed_out = None, False
    try:
        with (root / "native.stdout.log").open("xb") as stdout, (root / "native.stderr.log").open("xb") as stderr:
            try:
                code = subprocess.run(command, stdout=stdout, stderr=stderr, env=child_env,
                                      timeout=get.util.neqo_host_timeout(declaration["timeout_seconds"]), check=False).returncode
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        get._json(root / "native-completed.json", {"schema_version": 1, "returncode": code, "timed_out": timed_out,
          "completed_at": datetime.now(UTC).isoformat(), "elapsed_ns": time.monotonic_ns() - before,
          "stdout_sha256": graph.digest(get._read(root / "native.stdout.log")), "stderr_sha256": graph.digest(get._read(root / "native.stderr.log")),
          "outputs": {name: graph.digest(get._read(root / "native" / name)) for name in get.FILES if (root / "native" / name).is_file()},
          "client_sha256": graph.digest(get._read(client)),
          "source_manifest_sha256": graph.digest(get._read(get.util.DEFAULT_SOURCE_METADATA))})
    if code != 0 or timed_out:
        raise ValueError("static bootstrap actual Native failed; original process/raw evidence retained")
    _step(root, declaration, manifest, policy=policy, execution=root)


def execute(context_root: Path, position: int, output_root: Path, *, max_response_bytes: int | None = None,
            timeout_seconds: int = 120) -> dict[str, Any]:
    from . import supplied_static_admission as admission
    from . import supplied_static_preparation as preparation
    context = admission.load_context(context_root)
    arguments = admission._get_arguments(context, position)
    expected, domain = arguments["expected_runtime"], arguments["domain"]
    budget = admission.context_limits(context)["max_response_bytes"]
    if max_response_bytes is None:
        max_response_bytes = budget
    if max_response_bytes != budget or type(max_response_bytes) is not int:
        raise ValueError("static GET response cap must equal its prospectively declared capture cap")
    if type(timeout_seconds) is not int or timeout_seconds != admission.context_limits(context)["timeout_seconds"]:
        raise ValueError("static GET timeout must equal its prospectively declared capture timeout")
    neutral, binding, bootstrap, full = _inputs(context.source_bytes, arguments["source_sha256"], domain)
    if get.class_acquisition.unsafe_catalogue_domain_reason(domain) is not None:
        raise ValueError("static primary domain is excluded")
    _command(output_root.absolute(), max_response_bytes, timeout_seconds, STRICT_POLICY)
    if (os.environ.get("QCSD_LAB_IMAGE_DIGEST") != expected["image_digest"]
        or os.environ.get("QCSD_LAB_SOURCE_METADATA") != str(get.util.DEFAULT_SOURCE_METADATA)):
        raise ValueError("static bootstrap must run inside its declared installed image")
    implementation, _, _ = get.chaff_qualification._qualification_execution_context()
    client, client_sha = get.chaff_qualification._bound_neqo_client(implementation)
    runtime = {"source_manifest_text": get._read(get.util.DEFAULT_SOURCE_METADATA).decode(), "qualification_implementation": implementation}
    get._runtime(runtime, expected)
    if client != get.CLIENT or client_sha != expected["client_sha256"]:
        raise ValueError("static bootstrap actual installed client differs")
    output_root = output_root.absolute()
    for protected in (context.root, client, get.util.DEFAULT_SOURCE_METADATA):
        get.util.require_disjoint_path(output_root, [protected], label="static bootstrap output")
    output_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    (output_root / "bootstrap").mkdir(mode=0o700)
    for name, raw in (("source-list.json", context.source_bytes), ("neutral-input.json", graph.canonical_bytes(neutral)),
                      ("input-binding.json", graph.canonical_bytes(binding))):
        get._write(output_root / name, raw)
    get._json(output_root / "runtime.json", runtime)
    declaration = {"schema_version": 2, "record_type": PROOF_TYPE, "declared_at": datetime.now(UTC).isoformat(),
        "source_sha256": arguments["source_sha256"], "domain": domain, "runtime_binding": expected, "producer_role": PRODUCER_ROLE,
        **_candidate_identity(context, domain),
        "producer_sources": producer_sources(), "context": preparation.reference(context.root / "provenance.json"),
        "input_binding_sha256": graph.digest(graph.canonical_bytes(binding)), "neutral_input_sha256": graph.digest(graph.canonical_bytes(neutral)),
        "bootstrap_input_sha256": graph.digest(graph.canonical_bytes(bootstrap)), "full_input_sha256": graph.digest(graph.canonical_bytes(full)),
        "max_response_bytes": max_response_bytes, "timeout_seconds": timeout_seconds, "primary_claim": get.PRIMARY_CLAIM,
        "public_origin_policy": get.PUBLIC_POLICY, "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}
    get._json(output_root / "declaration.json", declaration)
    declared = {**declaration, "_raw_sha256": graph.digest(get._read(output_root / "declaration.json"))}
    _execute_step(output_root / "bootstrap", declared, bootstrap, client, policy=STRICT_POLICY)
    _execute_step(output_root, declared, full, client, policy=get.RESPONSE_POLICY)
    if producer_sources() != declaration["producer_sources"]:
        raise ValueError("static bootstrap producer changed during execution")
    proof = build_proof(output_root, **arguments)
    get._json(output_root / "full-get-proof.json", proof)
    return proof
