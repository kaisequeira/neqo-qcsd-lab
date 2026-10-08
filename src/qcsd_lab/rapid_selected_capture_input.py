"""Direct raw proof for a prospectively selected complete resource graph.

Selection-history audit is separate from this authority. This verifier never
loads an acquisition context: it checks the selected bootstrap/full GET again,
including its exact declared inputs, processes, DNS, protocol and resources.
The writer and consumers of the new receipt are added separately; this module
does not make an original preparation acquire a new interpretation.
"""
from __future__ import annotations

from copy import deepcopy
import json
import math
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping

from . import rapid_operation_facts as facts
from . import rapid_site_admission as receipts
from . import supplied_static_bootstrap_get as bootstrap
from . import supplied_static_get as get
from . import supplied_static_graph as graph
from . import supplied_static_preparation as original
from . import whole_graph_supplement as whole

ROLE = "selected-complete-graph-direct-bootstrap-get-capture-input-v1"
RECEIPT_TYPE = "qcsd-selected-complete-graph-capture-input-v1"
CONTRACT = "selected-own-complete-bootstrap-and-get-raw-proof-with-linked-selection-audit-v1"
AUDIT_TYPE = "qcsd-selected-class-original-authority-audit-v1"
FIELDS = {"contract", "original_manifest", "original_role", "candidate_id", "workload_id",
    "canonical_sites", "selection_audit", "raw_root", "raw_inventory", "proof",
    "declaration", "namespace", "neutral", "approved_origins", "capture_limits",
    "measurement_runtime", "recorded_producer_sources", "direct_validator_sources", "direct_validator_files",
    "declared_at", "scientific_credit", "formal_accepted_trace_count"}


def is_selected(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") == ROLE


def reference(path: Path) -> dict:
    path = Path(path).absolute()
    _, item = facts._file(path)
    return {"path": str(path), **item}


def reopen(value: Any) -> Path:
    get._exact(value, {"path", "sha256", "mode"}, "selected input reference")
    if not isinstance(value["path"], str) or not Path(value["path"]).is_absolute():
        raise ValueError("selected input references require absolute regular files")
    path = Path(value["path"])
    if ".." in path.parts or type(value["mode"]) is not int or reference(path) != value:
        raise ValueError("selected input reference bytes or mode changed")
    return path


def _direct_modules():
    from . import application_response_policy as app
    from . import rapid_additive_static_enrollment as additive
    return (bootstrap, get, graph, original, whole, app, additive, __import__(__name__, fromlist=["_"]))


def direct_sources() -> dict[str, str]:
    return {module.__name__: graph.digest(get._read(Path(module.__file__))) for module in _direct_modules()}


def _compatible_direct_validator_sources(value: Mapping[str, Any], expected: Mapping[str, str]) -> bool:
    """Recognize complete historical dictionaries without relabeling a receipt."""
    recorded = value["direct_validator_sources"]
    if recorded == expected:
        return True
    from . import rapid_fixed_condition_target as fixed
    fixed._acquisition_reader_sources()
    plain_name = __name__
    whole_name = whole.__name__
    budget_name = "qcsd_lab.rapid_selected_budget_input"
    historical = []
    for whole_sha in (
            '726c0d6215830730f3938b69545f3b4acc8c727dda3b4528a34732701f8d9f07',
            'a12ba1de531fd37a4e6ab8abbc8497911ea51d4d45e54d452e3afc927058db66'):
        if (whole_sha == '726c0d6215830730f3938b69545f3b4acc8c727dda3b4528a34732701f8d9f07'
                and expected['qcsd_lab.application_response_policy'] !=
                    '8d85075852b94e7c8969fc17f141fed45b65c23bf6493fe607ca43b6a902d27e'):
            continue
        base = {**expected,
            plain_name: 'ef14e839e0c1ab1b1540a9b8c024f0e8545c1a3cf5478deec30a500134aff337',
            whole_name: whole_sha}
        if budget_name not in expected:
            historical.append(base)
        elif whole_sha == 'a12ba1de531fd37a4e6ab8abbc8497911ea51d4d45e54d452e3afc927058db66':
            historical.extend({**base, budget_name: sha} for sha in (
                'd4bbea3459cccf36217fa9897fbef4a51f73b3690151ef8aec883344e84145ca',
                '9e13ebe6eb79f066b2d96e9fc1cb90056584d4ba02f203ec8d8b42da95c57cf7',
                '6283ef9cafac972d9df8696c1c4d0249c920db855f7a83fc8fcd8fce434d079d'))
    source44 = {**expected,
        plain_name: 'f12460f830c4f4ba7a2d5c5600be59c7fd9800ee0d974692b24bba84ed356308',
        whole_name: '80bd66d3d710f5f14cf4827b43245d96af75e8ec0994418bed480e3c2a348357'}
    if budget_name in expected:
        source44[budget_name] = '3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb'
    historical.append(source44)
    source65 = {
        'qcsd_lab.application_response_policy': '817e48d727bcb5b056f37582c8c469af7070deabbd367571c2ea05b9f36ac49a',
        'qcsd_lab.rapid_additive_static_enrollment': '5404821bf1bf087493d60076d33c5769748052f6301c352dccc6dae61e630670',
        plain_name: 'ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442',
        'qcsd_lab.supplied_static_bootstrap_get': '4a53baeb9f66220b6108ea304f54dd834fc447a4cc43f58a358de018b421f692',
        'qcsd_lab.supplied_static_get': 'ce20fe5b5d60f7b268b7eb659ab56e98048d5934bc9cb3b456e2ef99c330d322',
        'qcsd_lab.supplied_static_graph': '87370d25d526a22cac7519a721aed0db19b72fa5957a353301782779409d4efa',
        'qcsd_lab.supplied_static_preparation': '087ebcea7cf8c793a82cbf40bcb0e77fb1555ba50b648c02af85e52c76641f44',
        whole_name: '4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0',
    }
    if budget_name in expected:
        source65[budget_name] = '3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb'
        source65['qcsd_lab.supplied_static_budget_successor'] = 'a297fd337517ddffc30fc6e08b5961e2556f9311cbe5f7837baa0209bcf298d1'
    if (recorded == source65 and expected == {**source65,
            plain_name: expected[plain_name],
            whole_name: 'dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98'}):
        historical.append(source65)
    if recorded not in historical:
        return False
    modules = {module.__name__: module for module in _direct_modules()}
    if budget_name in expected:
        from . import rapid_selected_budget_input as selected_budget
        modules[budget_name] = selected_budget
    for name in (plain_name, whole_name, budget_name):
        if name in expected and recorded[name] != expected[name]:
            fixed._compatible_acquisition_code(
                'src/qcsd_lab/' + name.rsplit('.', 1)[1] + '.py',
                value['direct_validator_files'][name], reference(Path(modules[name].__file__)))
    return True


def _bound_validator_files(value: Mapping[str, Any]) -> set[Path]:
    """Stable Source snapshot references; installed import paths may differ."""
    references = get._exact(value["direct_validator_files"], set(value["direct_validator_sources"]), "selected verifier files")
    files = set()
    for name, item in references.items():
        path = reopen(item)
        if item["sha256"] != value["direct_validator_sources"][name]:
            raise ValueError("selected direct verifier file differs from its imported implementation")
        files.add(path)
    return files


def _selected_get_manifests(value: Mapping[str, Any], declaration: Mapping[str, Any],
                            neutral: dict) -> tuple[dict, dict]:
    """Reconstruct the exact recorded full-GET policy, without promoting V1."""
    if value["original_role"] == whole.ROLE:
        policy = whole._declaration_manifest_policy(declaration)
        if (declaration["schema_version"] == 2
                and declaration["producer_sources"] != whole.producer_sources()):
            raise ValueError("selected required-parent GET changes its exact prospective producer")
        return whole._manifests(neutral, policy=policy)
    primary = {"resources": [deepcopy(neutral["resources"][0])]}
    full = deepcopy(neutral)
    full["resources"][0]["known_valid"] = True
    return primary, full


def _raw_selected_proof(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict:
    """Reconstruct selected process/protocol facts without preceding site GETs."""
    root = Path(value["raw_root"])
    if not root.is_absolute() or ".." in root.parts or facts._tree(root) != value["raw_inventory"]:
        raise ValueError("selected complete GET tree bytes, modes or membership changed")
    proof_path = reopen(value["proof"])
    if proof_path != root / "full-get-proof.json":
        raise ValueError("selected proof escapes its own raw GET tree")
    proof = get._load(get._read(proof_path))
    raw = get._read(root / "declaration.json")
    declaration = get._load(raw)
    neutral = get._load(get._read(root / "neutral-input.json"))
    runtime = get.runtime_binding(value["measurement_runtime"])
    limits = value["capture_limits"]
    if (declaration != value["declaration"] or neutral != value["neutral"]
            or declaration["runtime_binding"] != runtime
            or declaration["producer_sources"] != value["recorded_producer_sources"]
            or declaration["max_response_bytes"] != limits["max_response_bytes"]
            or declaration["timeout_seconds"] != limits["timeout_seconds"]
            or declaration["primary_claim"] != get.PRIMARY_CLAIM
            or declaration["public_origin_policy"] != get.PUBLIC_POLICY
            or declaration["scientific_credit"] is not False
            or type(declaration["site_credit"]) is not int or declaration["site_credit"] != 0
            or type(declaration["formal_accepted_trace_count"]) is not int
            or declaration["formal_accepted_trace_count"] != 0
            or get.class_acquisition.unsafe_catalogue_domain_reason(declaration["domain"]) is not None):
        raise ValueError("selected raw GET changed its prospective declaration/runtime/domain/caps")
    source = get._runtime(get._load(get._read(root / "runtime.json")), runtime)
    primary, full = _selected_get_manifests(value, declaration, neutral)
    if (declaration["neutral_input_sha256"] != graph.digest(graph.canonical_bytes(neutral))
            or declaration["bootstrap_input_sha256"] != graph.digest(graph.canonical_bytes(primary))
            or declaration["full_input_sha256"] != graph.digest(graph.canonical_bytes(full))):
        raise ValueError("selected GET pruned original resources, request headers or dependency edges")
    if value["original_role"] == original.ROLE:
        if proof["record_type"] != bootstrap.PROOF_TYPE or type(proof["schema_version"]) is not int or proof["schema_version"] != 2:
            raise ValueError("selected original graph requires its genuine primary bootstrap proof")
        imported, binding, _, _ = bootstrap._inputs(get._read(root / "source-list.json"), declaration["source_sha256"], declaration["domain"])
        if imported != neutral or get._load(get._read(root / "input-binding.json")) != binding:
            raise ValueError("selected supplied source import/occurrences/header/DAG binding changed")
        origins = binding["origins"]
    elif value["original_role"] == whole.ROLE:
        if proof["record_type"] != whole.PROOF_TYPE or type(proof["schema_version"]) is not int or proof["schema_version"] != 1:
            raise ValueError("selected discovered graph has another raw GET proof authority")
        if (declaration["candidate_id"] != value["candidate_id"]
                or declaration["graph_input"] != proof["graph_input"]
                or declaration["discovery_runtime"] != proof["discovery_runtime"]
                or proof["all_occurrences_and_edges_retained"] is not True):
            raise ValueError("selected whole GET changed candidate or separate discovery provenance")
        origins = value["approved_origins"]
    else:
        raise ValueError("selected input has an unsupported original preparation authority")
    namespace = value["namespace"]
    if value["original_role"] == whole.ROLE:
        if namespace is not None and namespace.get("record_type") != whole.NAMESPACE_TYPE:
            raise ValueError("selected whole GET namespace lost its original authority label")
        # Match the unchanged whole namespace reducer's ephemeral transport
        # adapter. The recorded namespace and every original Source label stay
        # byte-identical; the common reducer still checks all real raw records.
        execution = whole._execution_root(root, namespace, runtime)
    else:
        execution = original._execution_root(root, namespace, runtime)
    declared = {**declaration, "_raw_sha256": graph.digest(raw)}
    first = bootstrap._step(root / "bootstrap", declared, primary, policy=bootstrap.STRICT_POLICY, execution=execution / "bootstrap")
    native = bootstrap._step(root, declared, full, policy=get.RESPONSE_POLICY, execution=execution)
    first_start = get._load(get._read(root / "bootstrap/native-started.json"))["started_at"]
    first_end = get._load(get._read(root / "bootstrap/native-completed.json"))["completed_at"]
    full_start = get._load(get._read(root / "native-started.json"))["started_at"]
    full_end = get._load(get._read(root / "native-completed.json"))["completed_at"]
    if not get._time(first_start) < get._time(first_end) <= get._time(full_start) < get._time(full_end) <= get._time(value["declared_at"]):
        raise ValueError("selected full GET precedes its actual bootstrap or prospective receipt")
    if value["namespace"] is not None:
        ns = value["namespace"]
        start = get._load(get._read(original.open_reference(ns["outer_started"])))
        done = get._load(get._read(original.open_reference(ns["outer_completed"])))
        if not get._time(start["started_at"]) <= get._time(first_start) < get._time(full_end) <= get._time(done["completed_at"]):
            raise ValueError("selected actual Native steps escape their genuine outer process")
    if (proof["bootstrap_native"] != first or proof["native"] != native
            or proof["runtime_binding"] != runtime or proof["producer_sources"] != value["recorded_producer_sources"]
            or proof["resource_count"] != len(neutral["resources"]) or proof["full_list_coverage"] is not True
            or proof["declared_at"] != declaration["declared_at"] or proof["completed_at"] != full_end):
        raise ValueError("selected summary differs from independently re-proven process/protocol/body facts")
    for relative, digest in proof["files"].items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or graph.digest(get._read(root / path)) != digest:
            raise ValueError("selected proof raw file binding changed")
    run = get._load(get._read(root / "native/run.json"))
    responses = {row["resource_id"]: row for row in run["responses"]}
    resources = deepcopy(neutral["resources"])
    for row in resources:
        response = responses[row["id"]]
        row.update(content_length=response["bytes"], data_length=response["bytes"], known_valid=200 <= response["status"] < 300)
        if value["original_role"] == original.ROLE:
            row["chaff_priority"] = False
    if resources != manifest["resources"]:
        raise ValueError("selected capture changes a resource, header, occurrence, origin or dependency")
    from . import application_response_policy as app
    app._primary_content_type(responses[0])
    if (not 200 <= responses[0]["status"] < 300 or responses[0]["bytes"] <= 0
            or not any(get._origin(row["url"]) != get._origin(resources[0]["url"])
                and row["known_valid"] and row["data_length"] > 0 for row in resources)):
        raise ValueError("selected graph lacks a positive HTML primary or nonempty successful secondary origin")
    preparation = manifest["preparation"]
    if (preparation["approved_origins"] != origins or preparation["max_response_bytes"] != limits["max_response_bytes"]
            or preparation["timeout_seconds"] != limits["timeout_seconds"]
            or preparation["lab_source"] != {**source, "image_digest": runtime["image_digest"]}
            or preparation["expected_responses"] != [{key: row[key] for key in ("resource_id", "status", "bytes", "body_sha256")}
                for row in sorted(run["responses"], key=lambda row: row["resource_id"])]):
        raise ValueError("selected preparation relabels GET provenance, caps or full response identity")
    app.validate_prepared_response_graph(manifest)
    if facts._tree(root) != value["raw_inventory"]:
        raise ValueError("selected raw GET changed during its independent semantic verification")
    return proof


def validate_input(path: Path) -> tuple[dict, dict, dict]:
    value = receipts._unpack(get._read(path), RECEIPT_TYPE)
    get._exact(value, FIELDS, "selected complete graph input")
    if (value["contract"] != CONTRACT or value["scientific_credit"] is not False
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or not _compatible_direct_validator_sources(value, direct_sources())
            or not get._time(value["declared_at"]) <= get._time(receipts._now())):
        raise ValueError("selected input changes its direct verifier or zero-credit contract")
    _bound_validator_files(value)
    manifest = get._load(get._read(reopen(value["original_manifest"])))
    if manifest["preparation"]["data_role"] != value["original_role"]:
        raise ValueError("selected input changes its recorded original manifest role")
    # Reopen the immutable creation operation and exact selected row. Its other
    # GET histories remain an explicit audit, rather than a trace prerequisite.
    audit = read_audit(reopen(value["selection_audit"]))
    rows = [row for row in audit["result"]["classes"]
            if row["candidate"]["candidate_id"] == value["candidate_id"]]
    from .rapid_additive_static_enrollment import _aliases
    if (len(rows) != 1 or rows[0]["facts"]["outcome"] != "admitted"
            or rows[0]["manifest"] != {key: value["original_manifest"][key] for key in ("path", "sha256")}
            or value["workload_id"] != reopen(value["original_manifest"]).stem
            or value["canonical_sites"] != _aliases(rows[0]["candidate"], manifest)
            or value["capture_limits"] != rows[0]["capture_limits"]
            or not get._time(audit["published_at"]) <= get._time(value["declared_at"])):
        raise ValueError("selected input replaces its genuinely admitted class, graph, caps or chronology")
    proof = _raw_selected_proof(value, manifest)
    return value, manifest, proof


_LEGACY_PROGRAM = r'''
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path[:0]=[str(root/"src"),str(root)]
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab import supplied_static_admission as static
mode,authority=sys.argv[2],Path(sys.argv[3])
if mode=="enrollment":
    batch,classes,policy=rolling._verify_enrollment(authority)
    seed={"enrollment":rolling._ref(authority),"policy":batch["policy"],"ordinal":batch["ordinal"],
          "last_candidate_position":batch["last_candidate_position"],"classes":classes}
    selected=[]
    for cls in classes:
        context=rolling._context_for_policy(policy,Path(cls["admission_root"]))
        terminal=rolling._open_ref(cls["terminal"])
        selected.append((cls,context,terminal))
elif mode in {"whole-terminal","static-terminal"}:
    seed=None
    verifier=whole if mode=="whole-terminal" else static
    context=verifier.load_context(authority)
    terminal=Path(sys.argv[4]); facts=verifier.verify_terminal(terminal,context)
    if facts["outcome"]!="admitted": raise ValueError("selected input requires a genuine complete-GET admission")
    cls={"candidate_id":facts["candidate_id"],"terminal":rolling._ref(terminal),"admission_root":str(context.root)}
    selected=[(cls,context,terminal)]
else: raise ValueError("unknown selected authority audit mode")
rows=[]
for cls,context,terminal in selected:
    facts=rolling._verify_terminal(context,terminal)
    if facts["outcome"]!="admitted": raise ValueError("selected class is not genuinely admitted")
    manifest_path,manifest=rolling._prepared_workload(context,terminal)
    candidate=next(row for row in context.candidates if row["candidate_id"]==cls["candidate_id"])
    rows.append({"candidate":candidate,"manifest":rolling._ref(manifest_path),"terminal":rolling._ref(terminal),
        "context":rolling._ref(context.root/"provenance.json"),"capture_limits":rolling._static_context_limits(context),
        "facts":facts})
print(json.dumps({"audit_mode":mode,"seed":seed,"classes":rows,"scientific_credit":False},sort_keys=True))
'''


def _legacy_source(root: Path, source_manifest: Mapping[str, Any]) -> dict:
    """Authenticate the separately declared original scientific verifier."""
    root = root.absolute()
    source = get._load(get._read(reopen(source_manifest)))
    if (source.get("lab_dirty") is not False or source.get("neqo_dirty") is not False
            or source.get("neqo_commit") != source.get("neqo_pinned_commit")):
        raise ValueError("selected creation audit requires its actual clean pinned verifier Source")
    for directory, expected in ((root, source["lab_commit"]), (root / "neqo-qcsd", source["neqo_commit"])):
        lanes = __import__("qcsd_lab.rapid_lane_evidence", fromlist=["_"])
        lanes._regular_directory(directory)
        head = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
        clean = subprocess.run(["git", "-C", str(directory), "status", "--porcelain", "--untracked-files=all"], check=True, capture_output=True, text=True)
        if head.stdout.strip() != expected or clean.stdout.strip():
            raise ValueError("selected creation audit's original verifier Source was changed")
    return source


def audit_legacy(output: Path, *, source_root: Path, source_manifest: Mapping[str, Any],
                 enrollment: Path | None = None, context: Path | None = None, terminal: Path | None = None,
                 original_role: str = whole.ROLE) -> Path:
    """Audit old membership once, preserving its original Source and raw logs."""
    if ((enrollment is not None and (context is not None or terminal is not None))
            or (enrollment is None and (context is None or terminal is None))):
        raise ValueError("selected creation audit needs one enrollment or one whole context/terminal")
    source = _legacy_source(source_root, source_manifest)
    if original_role not in (whole.ROLE, original.ROLE):
        raise ValueError("selected audit requires an exact original static or whole authority")
    mode = "enrollment" if enrollment is not None else ("whole-terminal" if original_role == whole.ROLE else "static-terminal")
    authority = Path(enrollment if enrollment is not None else context).absolute()
    command = [sys.executable, "-I", "-B", "-c", _LEGACY_PROGRAM, str(source_root.absolute()), mode,
               str(authority), "" if terminal is None else str(terminal.absolute())]
    output = output.absolute()
    get.util.require_disjoint_path(output, [source_root, authority, *([] if terminal is None else [terminal])], label="selected creation audit")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started = {"schema_version": 1, "command": command, "started_at": receipts._now(),
        "original_source_manifest": dict(source_manifest), "original_source": source,
        "authority": reference(authority if enrollment is not None else authority / "provenance.json"),
        "terminal": None if terminal is None else reference(terminal)}
    receipts.durable_create(output / "audit-started.json", graph.canonical_bytes(started))
    before = time.monotonic()
    result = subprocess.run(command, capture_output=True, check=False)
    for name, raw in (("audit.stdout.log", result.stdout), ("audit.stderr.log", result.stderr)):
        receipts.durable_create(output / name, raw)
    completed = {"schema_version": 1, "returncode": result.returncode, "elapsed_seconds": time.monotonic() - before,
        "completed_at": receipts._now(), "started": reference(output / "audit-started.json"),
        "stdout": reference(output / "audit.stdout.log"), "stderr": reference(output / "audit.stderr.log")}
    receipts.durable_create(output / "audit-completed.json", graph.canonical_bytes(completed))
    if result.returncode != 0:
        raise ValueError("original selected-authority audit failed; attempted raw records remain")
    if _legacy_source(source_root, source_manifest) != source:
        raise ValueError("original verifier Source changed during selected creation audit")
    payload = get._load(result.stdout)
    get._exact(payload, {"audit_mode", "seed", "classes", "scientific_credit"}, "original selected audit result")
    if payload["audit_mode"] != mode or payload["scientific_credit"] is not False or not isinstance(payload["classes"], list) or not payload["classes"]:
        raise ValueError("original selected audit result changed its declared authority")
    audit = {"contract": CONTRACT, "original_source_root": str(source_root.absolute()),
        "original_source_manifest": dict(source_manifest), "legacy_program_sha256": graph.digest(_LEGACY_PROGRAM.encode()),
        "started": reference(output / "audit-started.json"), "completed": reference(output / "audit-completed.json"),
        "stdout": reference(output / "audit.stdout.log"), "stderr": reference(output / "audit.stderr.log"),
        "result": payload, "published_at": receipts._now(), "scientific_credit": False}
    path = output / "selection-audit.json"
    receipts.durable_create(path, graph.canonical_bytes(receipts._bind(AUDIT_TYPE, audit)))
    return path


def publish_input(output: Path, *, audit: Path, candidate_id: str) -> Path:
    """Publish an independent candidate input; enrollment assigns its ordinal."""
    audit_raw = read_audit(audit)
    source_root = Path(audit_raw["original_source_root"])
    _legacy_source(source_root, audit_raw["original_source_manifest"])
    rows = [row for row in audit_raw["result"]["classes"] if row["candidate"]["candidate_id"] == candidate_id]
    if len(rows) != 1 or rows[0]["facts"]["outcome"] != "admitted":
        raise ValueError("selected receipt candidate was not genuinely admitted in its bound audit")
    row = rows[0]
    original_path = original.open_reference(row["manifest"])
    manifest = get._load(get._read(original_path))
    preparation = manifest["preparation"]
    role = preparation["data_role"]
    if role not in (original.ROLE, whole.ROLE):
        raise ValueError("selected receipt supports original-budget complete static and whole graphs only")
    evidence = preparation["static_get_evidence"] if role == original.ROLE else preparation["whole_graph_get_evidence"]
    raw_root = Path(evidence["root"])
    declaration = get._load(get._read(raw_root / "declaration.json"))
    from .rapid_additive_static_enrollment import _aliases
    value = {"contract": CONTRACT, "original_manifest": reference(original_path), "original_role": role,
        "candidate_id": candidate_id, "workload_id": original_path.stem, "canonical_sites": _aliases(row["candidate"], manifest),
        "selection_audit": reference(audit), "raw_root": str(raw_root), "raw_inventory": facts._tree(raw_root),
        "proof": reference(original.open_reference(evidence["proof"])), "declaration": declaration,
        "namespace": evidence["namespace"], "neutral": get._load(get._read(raw_root / "neutral-input.json")),
        "approved_origins": preparation["approved_origins"], "capture_limits": row["capture_limits"],
        "measurement_runtime": evidence["runtime_binding"], "recorded_producer_sources": declaration["producer_sources"],
        "direct_validator_sources": direct_sources(),
        "direct_validator_files": {module.__name__: reference(Path(module.__file__)) for module in _direct_modules()},
        "declared_at": receipts._now(),
        "scientific_credit": False, "formal_accepted_trace_count": 0}
    _raw_selected_proof(value, manifest)
    output = output.absolute()
    get.util.require_disjoint_path(output, [raw_root, original_path, audit], label="selected input receipt")
    receipts.durable_create(output, graph.canonical_bytes(receipts._bind(RECEIPT_TYPE, value)))
    return output


def read_audit(path: Path) -> dict:
    """Check immutable creation records without replaying their site history."""
    value = receipts._unpack(get._read(path), AUDIT_TYPE)
    get._exact(value, {"contract", "original_source_root", "original_source_manifest", "legacy_program_sha256",
        "started", "completed", "stdout", "stderr", "result", "published_at", "scientific_credit"}, "selected creation audit")
    started = get._load(get._read(reopen(value["started"])))
    completed = get._load(get._read(reopen(value["completed"])))
    stdout = reopen(value["stdout"])
    reopen(value["stderr"])
    source = get._load(get._read(reopen(value["original_source_manifest"])))
    command = started["command"]
    if (value["contract"] != CONTRACT or value["scientific_credit"] is not False
            or value["legacy_program_sha256"] != graph.digest(_LEGACY_PROGRAM.encode())
            or not isinstance(command, list) or len(command) != 9
            or not isinstance(command[0], str) or not Path(command[0]).is_absolute()
            or command[1:6] != ["-I", "-B", "-c", _LEGACY_PROGRAM, value["original_source_root"]]
            or command[6] not in {"enrollment", "whole-terminal", "static-terminal"}
            or started["original_source"] != source or started["original_source_manifest"] != value["original_source_manifest"]
            or completed["started"] != value["started"] or completed["stdout"] != value["stdout"]
            or completed["stderr"] != value["stderr"]
            or type(completed["returncode"]) is not int or completed["returncode"] != 0
            or type(completed["elapsed_seconds"]) not in (int, float)
            or not math.isfinite(completed["elapsed_seconds"]) or completed["elapsed_seconds"] <= 0
            or get._load(get._read(stdout)) != value["result"]
            or not get._time(started["started_at"]) < get._time(completed["completed_at"]) <= get._time(value["published_at"]) <= get._time(receipts._now())):
        raise ValueError("selected audit command, original Source, raw closure or chronology changed")
    result = get._exact(value["result"], {"audit_mode", "seed", "classes", "scientific_credit"}, "selected audit result")
    if result["audit_mode"] != command[6] or result["scientific_credit"] is not False:
        raise ValueError("selected audit result has another membership authority")
    if not isinstance(result["classes"], list) or not result["classes"]:
        raise ValueError("selected audit must retain its actual admitted class rows")
    for row in result["classes"]:
        get._exact(row, {"candidate", "manifest", "terminal", "context", "capture_limits", "facts"}, "selected audited class")
        if row["facts"].get("outcome") != "admitted" or row["facts"].get("candidate_id") != row["candidate"].get("candidate_id"):
            raise ValueError("selected audit has a non-admitted or changed candidate row")
    if len({row["candidate"]["candidate_id"] for row in result["classes"]}) != len(result["classes"]):
        raise ValueError("selected audit repeats a candidate row")
    if command[6] == "enrollment":
        if (started["terminal"] is not None or command[8] != ""
                or result["seed"]["enrollment"] != {key: started["authority"][key] for key in ("path", "sha256")}
                or command[7] != started["authority"]["path"]):
            raise ValueError("selected seed audit replaced its real enrollment command")
    elif (result["seed"] is not None or command[8] != started["terminal"]["path"]
            or str(Path(command[7]) / "provenance.json") != started["authority"]["path"]):
        raise ValueError("selected supplemental audit replaced its real terminal command")
    reopen(started["authority"])
    if started["terminal"] is not None:
        reopen(started["terminal"])
    return value


def prepare_input(path: Path, output: Path) -> Path:
    """Declare a new capture role while preserving every original graph row."""
    value, manifest, _ = validate_input(path)
    output = output.absolute()
    get.util.require_disjoint_path(output, [Path(value["raw_root"]), reopen(value["original_manifest"]), path], label="selected capture manifest")
    prepared = deepcopy(manifest)
    prepared["preparation"].update(data_role=ROLE, selected_input_evidence={
        "schema_version": 1, "record_type": RECEIPT_TYPE, "receipt": reference(path)})
    receipts.durable_create(output, graph.canonical_bytes(prepared))
    return output


def audit_inputs(path: Path) -> set[Path]:
    """Reopen the exact audit metadata closure without any acquisition replay."""
    value = read_audit(path)
    files = {path.absolute()}
    files.update(reopen(value[key]) for key in
                 ("started", "completed", "stdout", "stderr", "original_source_manifest"))
    started = get._load(get._read(reopen(value["started"])))
    files.add(reopen(started["authority"]))
    if started["terminal"] is not None:
        files.add(reopen(started["terminal"]))
    return files


def validate_preparation(value: Any, resources: list[dict]) -> dict:
    if not is_selected(value):
        raise ValueError("selected preparation role is absent")
    evidence = get._exact(value.get("selected_input_evidence"), {"schema_version", "record_type", "receipt"}, "selected input evidence")
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1 or evidence["record_type"] != RECEIPT_TYPE:
        raise ValueError("selected preparation has another input receipt authority")
    _, original_manifest, proof = validate_input(reopen(evidence["receipt"]))
    expected = deepcopy(original_manifest)
    expected["preparation"].update(data_role=ROLE, selected_input_evidence=dict(evidence))
    if expected != {"preparation": dict(value), "resources": resources}:
        raise ValueError("selected capture preparation changes original policy, header, resource, origin or dependency")
    return proof


def preparation_inputs(value: Mapping[str, Any], resources: list[dict]) -> tuple[set[Path], set[Path]]:
    """Bind selected files and raw GET tree only, never a transport parent."""
    validate_preparation(value, resources)
    path = reopen(value["selected_input_evidence"]["receipt"])
    payload = receipts._unpack(get._read(path), RECEIPT_TYPE)
    files = {path, reopen(payload["original_manifest"]), reopen(payload["proof"])}
    files.update(_bound_validator_files(payload))
    # Also fence actual imported files within an operation. These installed
    # paths are not HOST volumes; transport follows the stable receipt refs.
    files.update(Path(module.__file__).absolute() for module in _direct_modules())
    files.update(audit_inputs(reopen(payload["selection_audit"])))
    namespace = payload["namespace"]
    if namespace is not None:
        files.update(original.open_reference(namespace[key]) for key in
            ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return files, {Path(payload["raw_root"])}


def preparation_roots(value: Mapping[str, Any], resources: list[dict]) -> list[Path]:
    files, trees = preparation_inputs(value, resources)
    payload = receipts._unpack(get._read(reopen(value["selected_input_evidence"]["receipt"])), RECEIPT_TYPE)
    imported = {Path(module.__file__).absolute() for module in _direct_modules()}
    files.difference_update(imported - _bound_validator_files(payload))
    return sorted(trees | {path.parent for path in files})
