"""Explicit reuse of an unchanged response qualifier by a new delivery consumer.

This witness grants only response-qualification reuse.  It never grants capture,
readiness, measurement equivalence, or a changed workload/Native primitive.
Original sidecars and their original Source/image labels remain byte-exact.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import UTC, datetime
import json
import os
from pathlib import Path

from . import chaff_qualification as legacy
from . import response_budget_qualification as budget
from . import rapid_rolling_readiness as evidence

TYPE = "qcsd-complete-delivery-response-qualification-compatibility-v1"
CONTRACT = "unchanged-original-response-producer-new-complete-delivery-consumer-v1"
FIELD = "qualification_delivery_compatibility"
POLICY_FIELD = "application_body_identity_policy"
POLICY = "complete-current-application-delivery-v1"
MODULE = "src/qcsd_lab/qualification_delivery_compatibility.py"
ENV = "QCSD_RAPID_COLLECTION_COMPATIBILITY"
ZERO = {"scientific_credit": False, "formal_accepted_trace_count": 0}
RUNTIME_KEYS = {"runtime_source_root", "module_root", "base_launcher", "host_launcher",
                "source_manifest", "client_binary", "collection_image_digest"}
_ACTIVE = ContextVar("qualification_complete_delivery_consumer", default=None)

# Named consumer units only.  The qualifier, replay/header primitives, Native,
# and all remaining implementation AST nodes are protected byte/AST dependencies.
# The selected-role units were prospectively added in d083; old static bases
# retain their original data role and cannot enter that added branch.
CONSUMER_FUNCTIONS = {
    "src/qcsd_lab/application_response_policy.py": {
        "validate_prepared_response_graph", "validate_application_responses",
        "validate_primary_document_identity_evidence", "validate_application_response_policy_evidence",
        "application_response_identity_signature", "validate_application_body_identity_policy",
        "application_body_identity_policy", "_observed_content_encoding", "_complete_delivery_endpoints",
    },
    "src/qcsd_lab/manifest.py": {"validate_research_preparation", "_validate_preparation"},
    "src/qcsd_lab/orchestrator.py": {
        "load_campaign", "_load_campaign", "_frozen_configuration",
        "_prepared_response_identity_failure", "_compare_group", "_policy_response_comparison",
        "_load_qualified_chaff_inputs", "_materialize_inputs",
    },
    "src/qcsd_lab/verification.py": {"_validate_policy_application_responses"},
    "src/qcsd_lab/experiment.py": {"_validate_configuration"},
}
POLICY_CONSTANTS = {
    "APPLICATION_BODY_IDENTITY_FIELD": POLICY_FIELD,
    "EXACT_APPLICATION_BODY_IDENTITY_POLICY": "exact-prepared-application-body-v1",
    "COMPLETE_APPLICATION_DELIVERY_POLICY": POLICY,
}
EXTRA_PROTECTED = {
    "src/qcsd_lab/response_budget_qualification.py", "src/qcsd_lab/supplied_static_get.py",
    "src/qcsd_lab/supplied_static_graph.py", "src/qcsd_lab/supplied_static_preparation.py",
    "src/qcsd_lab/supplied_static_admission.py", "src/qcsd_lab/class_acquisition.py",
    "src/qcsd_lab/supplied_static_bootstrap_get.py",
}


def _keys(value, names, label):
    if not isinstance(value, Mapping) or set(value) != set(names):
        raise ValueError(f"delivery qualification {label} has a malformed schema")


def _policy(body_policy, reference):
    if reference is not None and body_policy != POLICY:
        raise ValueError("qualification compatibility requires its explicit complete-delivery policy")
    if body_policy is not None and body_policy not in {POLICY, "exact-prepared-application-body-v1"}:
        raise ValueError("qualification compatibility has an unknown body policy")


def _ref(path):
    path = Path(path).absolute()
    return {"path": str(path), "sha256": evidence._sha(evidence._read(path))}


def _project(relative, raw):
    tree = ast.parse(raw, filename=relative)
    permitted = CONSUMER_FUNCTIONS.get(relative, set())
    retained, units = [], {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in permitted:
            if node.name in units:
                raise ValueError("delivery consumer duplicates a named function")
            units[node.name] = evidence._sha(ast.dump(node, include_attributes=False).encode())
            continue
        if relative.endswith("/application_response_policy.py") and isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if len(names) == 1 and names[0] in POLICY_CONSTANTS:
                if not isinstance(node.value, ast.Constant) or node.value.value != POLICY_CONSTANTS[names[0]]:
                    raise ValueError("delivery consumer changed its closed policy constant")
                units[names[0]] = evidence._sha(ast.dump(node, include_attributes=False).encode())
                continue
        if relative.endswith("/orchestrator.py"):
            if isinstance(node, ast.ClassDef) and node.name in {"Campaign", "Workload"}:
                for member in list(node.body):
                    if isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name) and member.target.id in {POLICY_FIELD, FIELD}:
                        if not isinstance(member.value, ast.Constant) or member.value.value is not None:
                            raise ValueError("delivery consumer policy fields must default to historical absence")
                        node.body.remove(member)
                        units[node.name + "." + member.target.id] = evidence._sha(ast.dump(member, include_attributes=False).encode())
        allowed_keys = ("LEGACY_CAMPAIGN_KEYS" if relative.endswith("/orchestrator.py")
                        else "_OPTIONAL_CONFIGURATION_KEYS" if relative.endswith("/experiment.py") else None)
        if allowed_keys is not None:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == allowed_keys for target in node.targets):
                if not isinstance(node.value, ast.Set):
                    raise ValueError("delivery consumer campaign keys have changed representation")
                for member in list(node.value.elts):
                    if isinstance(member, ast.Constant) and member.value in {POLICY_FIELD, FIELD}:
                        node.value.elts.remove(member)
                        units[allowed_keys + "." + member.value] = evidence._sha(ast.dump(member, include_attributes=False).encode())
        retained.append(node)
    protected = ast.dump(ast.Module(body=retained, type_ignores=[]), include_attributes=False).encode()
    return protected, units


def source_comparison(old, new):
    """Authenticate unchanged producer/Native/config and named consumer AST edits."""
    protected = set(legacy.IMPLEMENTATION_FILES) | EXTRA_PROTECTED
    protected.update(name for name in old if name.startswith(("neqo-qcsd/", "config/")))
    if any(name not in new for name in protected):
        raise ValueError("delivery consumer removed a qualification or Native dependency")
    if {name for name in old if name.startswith("neqo-qcsd/")} != {name for name in new if name.startswith("neqo-qcsd/")}:
        raise ValueError("delivery consumer changed the complete Native source inventory")
    changes = {}
    for name in sorted(protected):
        before, after = old[name], new[name]
        if before == after:
            continue
        if name not in CONSUMER_FUNCTIONS:
            raise ValueError(f"delivery consumer changed a qualification primitive: {name}")
        old_protected, old_units = _project(name, before)
        new_protected, new_units = _project(name, after)
        if old_protected != new_protected:
            raise ValueError(f"delivery consumer changed an unnamed implementation unit: {name}")
        changes[name] = {"before_sha256": evidence._sha(before), "after_sha256": evidence._sha(after),
                         "protected_sha256": evidence._sha(old_protected),
                         "old_units": old_units, "new_units": new_units}
    if new.get(MODULE) != evidence._read(Path(__file__)):
        raise ValueError("delivery consumer witness helper differs from its actual Source")
    return {"changed_consumer_units": changes,
            "unchanged_producer_files": {name: evidence._sha(old[name]) for name in sorted(protected) if name not in changes},
            "native_file_count": len([name for name in old if name.startswith("neqo-qcsd/")])}


def _runtime(role):
    _keys(role, {"canonical", "runtime"}, "runtime role")
    _keys(role["runtime"], RUNTIME_KEYS, "runtime inputs")
    from .rapid_rolling_schedule import reopen_runtime
    # This reader reopens the existing schema-one client-reuse evidence and all
    # twelve real installed operations; it grants no old measurement projection.
    return reopen_runtime(role["canonical"], role["runtime"], _inspector=True)


def _implementation(receipt, canonical, sources):
    legacy._validate_implementation_receipt(receipt, require_current=False)
    if (receipt["schema_version"] != legacy.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION
        or receipt["source"] != canonical["source"]
        or receipt["sha256"] != canonical["checks"]["collection"]["qualification_implementation_sha256"]
        or receipt["neqo_qcsd_client"]["sha256"] != canonical["installed_client_sha256"]
        or any(evidence._sha(sources[name]) != sha for name, sha in receipt["source_files"].items())):
        raise ValueError("delivery qualification implementation differs from its real installed runtime")


def _consumer_implementation(original, canonical, sources):
    """Derive the expected receipt and match its aggregate to real installed proof."""
    result = deepcopy(original)
    result["source"] = deepcopy(canonical["source"])
    result["source_files"] = {name: evidence._sha(sources[name]) for name in original["source_files"]}
    for name, record in result["installed_modules"].items():
        record["sha256"] = result["source_files"][name]
    result["sha256"] = legacy._implementation_aggregate(result)
    _implementation(result, canonical, sources)
    return result


def _qualified_group(group_ref, workload_refs, producer, old_sources):
    path, raw = evidence._reference(group_ref)
    group = evidence._json(raw)
    if (group.get("artifact_type") != budget.NAMED_ARTIFACT_TYPE
        or type(group.get("schema_version")) is not int or group["schema_version"] != 1
        or type(group.get("qualification_sidecar_schema_version")) is not int or group["qualification_sidecar_schema_version"] != 3
        or not isinstance(workload_refs, list) or not 1 <= len(workload_refs) <= 5):
        raise ValueError("delivery compatibility needs a complete prepared-budget response-only group")
    ids = [row["workload_id"] for row in workload_refs]
    if len(set(ids)) != len(ids) or ids != group.get("workload_ids"):
        raise ValueError("delivery compatibility changed the complete qualification group order")
    bases = [evidence._reference(row["base_manifest"])[0] for row in workload_refs]
    if len({base.parent for base in bases}) != 1 or any(base.name != identifier + ".json" for base, identifier in zip(bases, ids)):
        raise ValueError("delivery compatibility base workload layout differs")
    budget.load_named_qualification_set(path, workload_root=bases[0].parent,
        expected_workload_ids=ids, expected_qualification_scope="response-only", require_current_implementation=False)
    records, implementation = [], None
    expected_source = {**producer["source"], "image_digest": producer["collection_image_digest"]}
    for row, base in zip(workload_refs, bases):
        _keys(row, {"workload_id", "base_manifest"}, "qualified workload input")
        sidecar_path = path.parent / (row["workload_id"] + ".json")
        sidecar = evidence._json(evidence._read(sidecar_path))
        receipt = sidecar["implementation_receipt"]
        _implementation(receipt, producer, old_sources)
        if (sidecar["qualification_source"] != expected_source
            or sidecar["qualification_image_digest"] != expected_source["image_digest"]
            or sidecar["response_budget_source"] != budget._budget_source()
            or receipt["neqo_qcsd_client"]["sha256"] != producer["installed_client_sha256"]
            or implementation is not None and receipt != implementation):
            raise ValueError("delivery compatibility mixed original qualification producers or clients")
        implementation = receipt
        manifest = evidence._json(evidence._read(base))
        from .supplied_static_preparation import ROLE
        if manifest["preparation"].get("data_role") != ROLE:
            raise ValueError("delivery producer witness accepts only its original static base role")
        cap = manifest["preparation"].get("max_response_bytes")
        if type(cap) is not int or sidecar["qualification_policy"]["max_response_bytes"] != cap:
            raise ValueError("delivery compatibility changed its prepared response cap")
        named_row = group["workloads"][len(records)]
        records.append({**dict(row), "sidecar": _ref(sidecar_path),
            "runtime_manifest_sha256": named_row["runtime_manifest_sha256"], "max_response_bytes": cap,
            "request_header_primitive": deepcopy(sidecar["request_header_primitive"]),
            "response_budget_source": deepcopy(sidecar["response_budget_source"])})
    if len({row["max_response_bytes"] for row in records}) != 1:
        raise ValueError("delivery compatibility cannot combine different prepared response caps")
    return records, implementation


def _derive(producer, consumer, group_ref, workloads):
    old, old_sources = _runtime(producer)
    new, new_sources = _runtime(consumer)
    if (old["installed_client_sha256"] != new["installed_client_sha256"]
        or old["source"]["neqo_commit"] != new["source"]["neqo_commit"]):
        raise ValueError("delivery compatibility changed the actual Native/client bytes")
    comparison = source_comparison(old_sources, new_sources)
    records, old_impl = _qualified_group(group_ref, workloads, old, old_sources)
    current_impl = _consumer_implementation(old_impl, new, new_sources)
    return {"workloads": records, "source_comparison": comparison,
            "producer_implementation_sha256": old_impl["sha256"],
            "consumer_implementation_sha256": current_impl["sha256"],
            "client_sha256": old["installed_client_sha256"], "producer_source": old["source"],
            "consumer_source": new["source"], "producer_image": old["collection_image_digest"],
            "consumer_image": new["collection_image_digest"]}, old_impl, current_impl


def declare(output, *, producer, consumer, qualification_group, workloads, body_policy):
    _policy(body_policy, qualification_group)
    from .rapid_operation_facts import OperationFacts
    context = OperationFacts()
    dependencies = {"producer": producer, "consumer": consumer,
                    "qualification_group": qualification_group, "qualified_inputs": workloads}
    files, trees = _raw_dependencies(qualification_group, dependencies)
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() or destination in files or any(destination.is_relative_to(root) for root in trees):
        raise ValueError("delivery qualification witness needs a fresh external destination")
    with context.scope():
        _bind(context, qualification_group, dependencies)
        facts, _, _ = _derive(producer, consumer, qualification_group, workloads)
        value = {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT,
                 POLICY_FIELD: body_policy, "producer": producer, "consumer": consumer,
                 "qualification_group": qualification_group, "qualified_inputs": workloads,
                 "published_at": datetime.now(UTC).isoformat(), **facts, **ZERO}
        context.check()
        from .util import durable_create
        durable_create(destination, evidence._encoded(value))
    return _ref(output)


def _raw_dependencies(reference, value):
    """Select sealed references only; never scan active acquisition attempts."""
    files, trees = {evidence._reference(reference)[0]}, set()
    seen_contexts, seen_gets = set(), set()

    def record(ref):
        path, raw = evidence._reference(ref)
        files.add(path)
        return path, evidence._json(raw)

    def namespace(value):
        if value is not None:
            for name in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"):
                files.add(evidence._reference(value[name])[0])

    def static_context(ref):
        path, raw = evidence._reference(ref)
        files.add(path)
        if path in seen_contexts:
            return
        seen_contexts.add(path)
        from . import supplied_static_admission as admission
        declared = admission.receipts._unpack(raw, admission.PROVENANCE_TYPE)
        for name in ("source_list", "profile", "candidate_order"):
            files.add(evidence._reference(declared[name])[0])
        if declared["parent_context"] is not None:
            static_context(declared["parent_context"])
        for terminal_ref in declared["inherited_terminals"]:
            terminal, terminal_raw = evidence._reference(terminal_ref)
            files.add(terminal)
            terminal_value = admission.receipts._unpack(terminal_raw, admission.TERMINAL_TYPE)
            if terminal_value["prepared_workload"] is not None:
                prepared, prepared_raw = evidence._reference(terminal_value["prepared_workload"])
                files.add(prepared)
                static_preparation(evidence._json(prepared_raw)["preparation"])
            if terminal_value["get_evidence_root"] is not None:
                trees.add(Path(terminal_value["get_evidence_root"]))
            namespace(terminal_value["namespace"])

    def static_preparation(preparation):
        from .supplied_static_preparation import ROLE
        if preparation.get("data_role") != ROLE:
            raise ValueError("delivery qualification dependency closure requires the original static role")
        original = preparation["static_get_evidence"]
        root = Path(original["root"])
        trees.add(root)
        namespace(original["namespace"])
        proof_path, proof = record(original["proof"])
        if proof_path != root / "full-get-proof.json":
            raise ValueError("delivery qualification raw GET proof moved outside its original namespace")
        if root not in seen_gets:
            seen_gets.add(root)
            static_context(proof["context"])

    for role in (value["producer"], value["consumer"]):
        canonical_path, raw = evidence._reference(role["canonical"])
        trees.add(canonical_path.parent)
        for name in ("runtime_source_root", "module_root"):
            trees.add(Path(role["runtime"][name]))
        for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
            files.add(Path(role["runtime"][name]))
        runtime_record = evidence._json(raw)
        seen = set()
        while runtime_record.get("original_canonical") is not None:
            parent, parent_raw = evidence._reference(runtime_record["original_canonical"])
            if parent in seen:
                raise ValueError("delivery qualification runtime raw dependency contains a cycle")
            seen.add(parent)
            trees.add(parent.parent)
            runtime_record = evidence._json(parent_raw)
    group_path = evidence._reference(value["qualification_group"])[0]
    trees.add(group_path.parent)
    for row in value["qualified_inputs"]:
        path, raw = evidence._reference(row["base_manifest"])
        files.add(path)
        manifest = evidence._json(raw)
        static_preparation(manifest.get("preparation", {}))
    return sorted(files), sorted(trees)


def _bind(context, reference, value):
    """Bind immutable raw dependencies before memoizing an original validator."""
    files, trees = _raw_dependencies(reference, value)
    for path in files:
        context.watch_file(path)
    for path in trees:
        context.watch_tree(path, ignore_git=True)
    for path in (Path(__file__), Path(budget.__file__), Path(legacy.__file__)):
        context.watch_file(path)


def roots(reference, *, body_policy):
    """Authenticated read-only transport roots, distinct from immutable fences."""
    value, _, _ = validate(reference, body_policy=body_policy)
    files, trees = _raw_dependencies(reference, value)
    selected = {Path(path).absolute() for path in trees} | {Path(path).absolute().parent for path in files}
    return sorted(root for root in selected
                  if not any(root != parent and root.is_relative_to(parent) for parent in selected))


def validate(reference, *, body_policy, canonical=None, actual_image=None):
    _policy(body_policy, reference)
    path, raw = evidence._reference(reference)
    value = evidence._json(raw)
    facts_names = {"workloads", "source_comparison", "producer_implementation_sha256", "consumer_implementation_sha256",
                   "client_sha256", "producer_source", "consumer_source", "producer_image", "consumer_image"}
    _keys(value, {"schema_version", "artifact_type", "contract", POLICY_FIELD, "producer", "consumer",
                  "qualification_group", "qualified_inputs", "published_at", *facts_names, *ZERO}, "witness")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["artifact_type"] != TYPE or value["contract"] != CONTRACT or value[POLICY_FIELD] != POLICY
        or any(type(value[name]) is not type(expected) or value[name] != expected for name, expected in ZERO.items())):
        raise ValueError("delivery qualification witness has another contract or credit")
    published = evidence._timestamp(value["published_at"])
    if published > datetime.now(UTC):
        raise ValueError("delivery qualification witness is future-dated")
    from .rapid_operation_facts import current_context
    context = current_context()
    key = (TYPE, reference["path"], reference["sha256"])
    if context is not None:
        _bind(context, reference, value)
    if context is not None and context.has(key):
        facts, old_impl, current_impl = context.get(key)
    else:
        facts, old_impl, current_impl = _derive(value["producer"], value["consumer"], value["qualification_group"], value["qualified_inputs"])
        if context is not None:
            context.remember(key, (facts, old_impl, current_impl))
    if any(value[name] != facts[name] for name in facts_names):
        raise ValueError("delivery qualification witness changed its recomputed producer/consumer bindings")
    for role in (value["producer"], value["consumer"]):
        record = evidence._json(evidence._reference(role["canonical"])[1])
        if evidence._timestamp(record["verified_at"]) > published:
            raise ValueError("delivery qualification witness predates its actual installed runtime")
    if canonical is not None and canonical != evidence._json(evidence._reference(value["consumer"]["canonical"])[1]):
        raise ValueError("delivery qualification witness selects another consumer runtime")
    if actual_image is not None and actual_image != value["consumer_image"]:
        raise ValueError("delivery qualification witness selects another actual installed image")
    return value, old_impl, current_impl


def validate_sidecar(sidecar, canonical, *, workload_id, workload_sha256, reference, body_policy):
    value, original, _ = validate(reference, body_policy=body_policy, canonical=canonical)
    matches = [row for row in value["workloads"] if row["workload_id"] == workload_id]
    if (len(matches) != 1 or matches[0]["base_manifest"]["sha256"] != workload_sha256
        or evidence._sha(budget.canonical_bytes(sidecar)) != matches[0]["sidecar"]["sha256"]
        or sidecar.get("implementation_receipt") != original):
        raise ValueError("delivery qualification selected a changed or unlisted original sidecar/base")
    return value


@contextmanager
def qualification_context(reference, *, body_policy):
    """Only an explicitly selected campaign/plan can enter the installed hook."""
    _policy(body_policy, reference)
    if reference is None:
        yield
        return
    from .rapid_operation_facts import OperationFacts, current_context
    context = current_context()
    owned = context is None
    if owned:
        context = OperationFacts()
    active = _ACTIVE.get()
    if active is not None and active != (reference, body_policy):
        raise ValueError("delivery qualification cannot nest a different campaign authority")
    previous = os.environ.get(ENV)
    if previous is not None and previous != reference["path"]:
        raise ValueError("delivery qualification cannot replace another runtime authority")
    with context.scope():
        validate(reference, body_policy=body_policy, actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"))
        token = _ACTIVE.set((deepcopy(reference), body_policy))
        os.environ[ENV] = reference["path"]
        try:
            yield
            # An owner closes fresh bytes/modes/membership before accepting its
            # operation. Nested readers only borrow this same action's facts.
            if owned:
                context.check()
        finally:
            _ACTIVE.reset(token)
            if previous is None:
                os.environ.pop(ENV, None)
            else:
                os.environ[ENV] = previous


def validate_current_implementation(original, current, reference, *, actual_image):
    active = _ACTIVE.get()
    if active is None or active != (reference, POLICY):
        raise ValueError("ambient compatibility cannot select a delivery qualification consumer")
    if not isinstance(actual_image, str) or evidence._IMAGE.fullmatch(actual_image) is None:
        raise ValueError("delivery qualification needs its actual current installed image")
    value, expected_original, expected_current = validate(reference, body_policy=POLICY, actual_image=actual_image)
    if original != expected_original or current != expected_current:
        raise ValueError("delivery qualification changed its original/current executed implementation")
    return value


def load_named_qualification_set(path, *, delivery_compatibility=None, body_policy=None, **kwargs):
    with qualification_context(delivery_compatibility, body_policy=body_policy):
        result = budget.load_named_qualification_set(path, **kwargs)
        if delivery_compatibility is not None:
            _listed_inputs(result.workload_ids, workload_root=kwargs["workload_root"],
                sidecar_root=kwargs.get("sidecar_root") or Path(path).parent,
                reference=delivery_compatibility, body_policy=body_policy)
        return result


def load_response_qualified_chaff(path, *, delivery_compatibility=None, body_policy=None, **kwargs):
    with qualification_context(delivery_compatibility, body_policy=body_policy):
        if delivery_compatibility is not None:
            _listed_inputs([kwargs["workload_id"]], workload_root=Path(kwargs["base_manifest_path"]).parent,
                sidecar_root=Path(path).parent, reference=delivery_compatibility, body_policy=body_policy)
        return budget.load_response_qualified_chaff(path, **kwargs)


def publish_named_qualification_set(workload_ids, *, delivery_compatibility=None, body_policy=None, **kwargs):
    with qualification_context(delivery_compatibility, body_policy=body_policy):
        if delivery_compatibility is not None:
            _listed_inputs(workload_ids, workload_root=kwargs["workload_root"],
                sidecar_root=kwargs["sidecar_root"], reference=delivery_compatibility, body_policy=body_policy)
            from .rapid_operation_facts import current_context
            current_context().check()
        return budget.publish_named_qualification_set(workload_ids, **kwargs)


def _listed_inputs(ids, *, workload_root, sidecar_root, reference, body_policy):
    value, _, _ = validate(reference, body_policy=body_policy)
    selected = [row for row in value["workloads"] if row["workload_id"] in ids]
    if [row["workload_id"] for row in selected] != list(ids):
        raise ValueError("delivery qualification consumer changed the declared group order or membership")
    from .rapid_operation_facts import current_context
    context = current_context()
    for row in selected:
        base = Path(workload_root) / (row["workload_id"] + ".json")
        sidecar = Path(sidecar_root) / base.name
        if context is not None:
            context.watch_file(base)
            context.watch_file(sidecar)
        evidence._read(base, row["base_manifest"]["sha256"])
        evidence._read(sidecar, row["sidecar"]["sha256"])


def main(argv=None):
    """Portable HOST entrypoint; declaration requires already closed runtimes."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    declaration = commands.add_parser("declare")
    declaration.add_argument("--input", type=Path, required=True)
    declaration.add_argument("--input-sha256", required=True)
    declaration.add_argument("--output", type=Path, required=True)
    for name in ("check", "roots"):
        item = commands.add_parser(name)
        item.add_argument("--witness", type=Path, required=True)
        item.add_argument("--witness-sha256", required=True)
        item.add_argument("--body-policy", required=True)
    args = parser.parse_args(argv)
    if args.command == "declare":
        raw = evidence._read(args.input, args.input_sha256)
        value = evidence._json(raw)
        _keys(value, {"schema_version", POLICY_FIELD, "producer", "consumer", "qualification_group", "workloads"}, "declaration input")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("delivery qualification declaration input has another schema")
        reference = declare(args.output, producer=value["producer"], consumer=value["consumer"],
            qualification_group=value["qualification_group"], workloads=value["workloads"],
            body_policy=value[POLICY_FIELD])
        print(json.dumps({"witness": reference, "scope": "qualification-only-no-capture-equivalence", **ZERO}, sort_keys=True))
    else:
        reference = {"path": str(args.witness.absolute()), "sha256": args.witness_sha256}
        if args.command == "roots":
            print(json.dumps([str(path) for path in roots(reference, body_policy=args.body_policy)]))
        else:
            value, _, _ = validate(reference, body_policy=args.body_policy)
            print(json.dumps({"witness": reference, "workload_count": len(value["workloads"]),
                "original_producer_labels_retained": True, "scope": "qualification-only-no-capture-equivalence", **ZERO}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
