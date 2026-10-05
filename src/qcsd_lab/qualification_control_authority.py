"""Typed qualification consumer authority for one exact control predicate.

Historical witnesses delegate to the byte-exact historical delivery helper.
New authorities retain its complete original group and prove a real installed
consumer. No qualifier, response, Native or chaff primitive is waived.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
import os

from . import qualification_delivery_compatibility as old
from . import rapid_rolling_readiness as evidence
from .rapid_operation_facts import OperationFacts, current_context
from .util import durable_create

TYPE = "qcsd-qualification-single-predicate-control-authority-v1"
CONTRACT = "original-complete-group-exact-selected-control-predicate-v1"
MODULE = "src/qcsd_lab/qualification_control_authority.py"
FIELD, POLICY_FIELD, POLICY = old.FIELD, old.POLICY_FIELD, old.POLICY
ENV = old.ENV
RUNTIME_KEYS = old.RUNTIME_KEYS
_ACTIVE = ContextVar("qualification_single_predicate_control_authority", default=None)
IMPORT_PREFIX = b"from .qualification_control_authority import "
ORIGINAL_IMPORT_PREFIX = b"from .qualification_delivery_compatibility import "
SELECTED_ENUM_LINE = b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-selected-parallel-scheduling" ||\n'
SELECTED_ENUM_CONTEXT = (b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-static-parallel-scheduling" ||\n'
    + SELECTED_ENUM_LINE + b'          "${rapid_scheduling_kind}" == "qcsd-rapid-v6-current-original-static-parallel-scheduling" ]]; then\n')
# Exact imported symbol/alias syntax; all surrounding bytes stay protected.
ORCHESTRATOR_IMPORTS = (
    b"validate as validate_delivery_compatibility",
    b"load_named_qualification_set, load_response_qualified_chaff",
    b"load_response_qualified_chaff", b"load_named_qualification_set",
)
FACTS = {"producer", "qualification_group", "qualified_inputs", "workloads", "client_sha256",
    "producer_source", "producer_image", "producer_implementation_sha256", "consumer_source",
    "consumer_image", "consumer_implementation_sha256", "source_comparison"}
KEYS = {"schema_version", "artifact_type", "contract", "original_witness", "consumer",
    POLICY_FIELD, "published_at", *FACTS, *old.ZERO}


def normalize_orchestrator_imports(raw):
    for suffix in ORCHESTRATOR_IMPORTS:
        current = IMPORT_PREFIX + suffix + b"\n"
        if raw.count(current) not in (0, 1):
            raise ValueError("control authority repeats a named qualification import")
        raw = raw.replace(current, ORIGINAL_IMPORT_PREFIX + suffix + b"\n")
    if IMPORT_PREFIX in raw:
        raise ValueError("control authority changed an unnamed qualification import")
    return raw


def _source_comparison(before, after):
    protected = set(old.legacy.IMPLEMENTATION_FILES) | old.EXTRA_PROTECTED
    protected.update(name for name in before if name.startswith(("neqo-qcsd/", "config/")))
    if any(name not in after for name in protected):
        raise ValueError("control authority removed an original qualification dependency")
    if {x for x in before if x.startswith("neqo-qcsd/")} != {x for x in after if x.startswith("neqo-qcsd/")}:
        raise ValueError("control authority changed the full Native source inventory")
    changes = {}
    for name in sorted(protected):
        a, b = before[name], after[name]
        if a == b:continue
        if name == "qcsd-lab":
            for raw in (a, b):
                if raw.count(SELECTED_ENUM_LINE) not in (0, 1) or (SELECTED_ENUM_LINE in raw and raw.count(SELECTED_ENUM_CONTEXT) != 1):
                    raise ValueError("control authority changed the registered shell predicate")
            if a.replace(SELECTED_ENUM_LINE, b"") != b.replace(SELECTED_ENUM_LINE, b""):
                raise ValueError("control authority changed other qualification launcher bytes")
            retained = a.replace(SELECTED_ENUM_LINE, b"")
            old_units, new_units = {}, {}
        else:
            if name not in old.CONSUMER_FUNCTIONS:
                raise ValueError("control authority changed an original qualification primitive")
            if name == "src/qcsd_lab/orchestrator.py":
                a, b = normalize_orchestrator_imports(a), normalize_orchestrator_imports(b)
            retained, old_units = old._project(name, a)
            current, new_units = old._project(name, b)
            if retained != current:
                raise ValueError("control authority changed unnamed qualification implementation")
        changes[name] = {"before_sha256": evidence._sha(before[name]), "after_sha256": evidence._sha(after[name]),
            "protected_sha256": evidence._sha(retained), "old_units": old_units, "new_units": new_units}
    for name, module in ((MODULE, Path(__file__)), (old.MODULE, Path(old.__file__))):
        if after.get(name) != evidence._read(module):
            raise ValueError("control authority executing reader differs from actual current Source")
    return {"changed_consumer_units": changes, "native_file_count": len([x for x in before if x.startswith("neqo-qcsd/")]),
        "unchanged_producer_files": {x: evidence._sha(before[x]) for x in sorted(protected) if x not in changes}}


def _derive(original_witness, consumer):
    original, implementation, _ = old.validate(original_witness, body_policy=POLICY)
    producer, sources = old._runtime(original["producer"])
    current, current_sources = old._runtime(consumer)
    if (producer["installed_client_sha256"] != current["installed_client_sha256"]
        or producer["source"]["neqo_commit"] != current["source"]["neqo_commit"]):
        raise ValueError("control authority changed the original Native/client")
    comparison = _source_comparison(sources, current_sources)
    expected = old._consumer_implementation(implementation, current, current_sources)
    facts = {name: deepcopy(original[name]) for name in ("producer", "qualification_group", "qualified_inputs",
        "workloads", "client_sha256", "producer_source", "producer_image", "producer_implementation_sha256")}
    facts.update(consumer_source=current["source"], consumer_image=current["collection_image_digest"],
                 consumer_implementation_sha256=expected["sha256"], source_comparison=comparison)
    return facts, implementation, expected


def _bind(context, reference, value):
    old._bind(context, reference, value)
    context.watch_file(evidence._reference(value["original_witness"])[0])
    original, _, _ = old.validate(value["original_witness"], body_policy=POLICY)
    old._bind(context, value["original_witness"], original)
    context.watch_file(Path(__file__))


def declare(output, *, original_witness, consumer, body_policy):
    old._policy(body_policy, original_witness)
    if body_policy != POLICY:raise ValueError("control authority requires complete-delivery policy")
    context = OperationFacts()
    with context.scope():
        # Select the exact original/current raw closure before the first proof.
        # The historical reader authenticates this original artifact during
        # _bind; the seed changes only the separately supplied consumer role.
        seed = evidence._json(evidence._reference(original_witness)[1])
        _bind(context, original_witness, {**seed, "original_witness": original_witness,
                                        "consumer": consumer})
        facts, _, _ = _derive(original_witness, consumer)
        value = {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT,
            "original_witness": original_witness, "consumer": consumer, POLICY_FIELD: POLICY,
            "published_at": datetime.now(UTC).isoformat(), **facts, **old.ZERO}
        original = old.validate(original_witness, body_policy=POLICY)[0]
        canonical = evidence._json(evidence._reference(consumer["canonical"])[1])
        if (evidence._timestamp(original["published_at"]) >= evidence._timestamp(value["published_at"])
            or evidence._timestamp(canonical["verified_at"]) >= evidence._timestamp(value["published_at"])):
            raise ValueError("control authority predates original witness or actual current runtime")
        _bind(context, original_witness, value)
        destination = Path(output).absolute()
        files, trees = old._raw_dependencies(original_witness, value)
        if destination in files or any(destination.is_relative_to(root) for root in trees):
            raise ValueError("control authority needs a fresh external publication namespace")
        context.check()
        durable_create(destination, evidence._encoded(value))
        return old._ref(destination)


def is_authority(reference):
    if reference is None:return False
    return evidence._json(evidence._reference(reference)[1]).get("artifact_type") == TYPE


def validate(reference, *, body_policy, canonical=None, actual_image=None):
    if not is_authority(reference):
        return old.validate(reference, body_policy=body_policy, canonical=canonical, actual_image=actual_image)
    old._policy(body_policy, reference)
    if body_policy != POLICY:raise ValueError("control authority has another body policy")
    _, raw = evidence._reference(reference); value = evidence._json(raw)
    old._keys(value, KEYS, "typed control authority")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["contract"] != CONTRACT
        or value[POLICY_FIELD] != POLICY or any(type(value[x]) is not type(y) or value[x] != y for x, y in old.ZERO.items())):
        raise ValueError("control qualification authority has another exact contract or credit")
    context = current_context()
    if context is None:
        context = OperationFacts()
        with context.scope():
            result = validate(reference, body_policy=body_policy, canonical=canonical, actual_image=actual_image)
            context.check();return result
    _bind(context, reference, value)
    key = (TYPE, reference["path"], reference["sha256"])
    facts, original, current = context.get(key) if context.has(key) else context.remember(key, _derive(value["original_witness"], value["consumer"]))
    if any(value[name] != facts[name] for name in FACTS):raise ValueError("control authority changed its recomputed original/current facts")
    published = evidence._timestamp(value["published_at"])
    old_value = old.validate(value["original_witness"], body_policy=POLICY)[0]
    actual = evidence._json(evidence._reference(value["consumer"]["canonical"])[1])
    if (published > datetime.now(UTC) or evidence._timestamp(old_value["published_at"]) >= published
        or evidence._timestamp(actual["verified_at"]) >= published):
        raise ValueError("control authority has invalid actual publication chronology")
    if canonical is not None and actual != canonical:raise ValueError("control authority selected another current canonical")
    if actual_image is not None and actual_image != value["consumer_image"]:raise ValueError("control authority selected another actual image")
    return value, original, current


def roots(reference, *, body_policy):
    if not is_authority(reference):return old.roots(reference, body_policy=body_policy)
    value, _, _ = validate(reference, body_policy=body_policy)
    files, trees = old._raw_dependencies(reference, value)
    selected = {Path(p).absolute() for p in trees} | {Path(p).absolute().parent for p in files}
    selected.update(old.roots(value["original_witness"], body_policy=body_policy))
    return sorted(p for p in selected if not any(p != root and p.is_relative_to(root) for root in selected))


def validate_sidecar(sidecar, canonical, *, workload_id, workload_sha256, reference, body_policy):
    if not is_authority(reference):return old.validate_sidecar(sidecar, canonical, workload_id=workload_id,
        workload_sha256=workload_sha256, reference=reference, body_policy=body_policy)
    value, original, _ = validate(reference, body_policy=body_policy, canonical=canonical)
    matches = [row for row in value["workloads"] if row["workload_id"] == workload_id]
    if (len(matches) != 1 or matches[0]["base_manifest"]["sha256"] != workload_sha256
        or evidence._sha(old.budget.canonical_bytes(sidecar)) != matches[0]["sidecar"]["sha256"]
        or sidecar.get("implementation_receipt") != original):
        raise ValueError("control authority changed original sidecar or prepared base")
    return value


@contextmanager
def qualification_context(reference, *, body_policy):
    if not is_authority(reference):
        with old.qualification_context(reference, body_policy=body_policy):yield
        return
    context = current_context(); owned = context is None
    if owned:context = OperationFacts()
    active, previous = _ACTIVE.get(), os.environ.get(ENV)
    if active is not None and active != (reference, body_policy):raise ValueError("control authority cannot replace active qualification scope")
    if previous is not None and previous != reference["path"]:raise ValueError("control authority cannot replace ambient runtime authority")
    with context.scope():
        validate(reference, body_policy=body_policy, actual_image=os.environ.get("QCSD_LAB_IMAGE_DIGEST"))
        token = _ACTIVE.set((deepcopy(reference), body_policy));os.environ[ENV] = reference["path"]
        try:
            yield
            if owned:context.check()
        finally:
            _ACTIVE.reset(token)
            if previous is None:os.environ.pop(ENV, None)
            else:os.environ[ENV] = previous


def validate_current_implementation(original, current, reference, *, actual_image):
    if _ACTIVE.get() != (reference, POLICY):raise ValueError("ambient control qualification authority is not an authenticated scope")
    if not isinstance(actual_image, str) or evidence._IMAGE.fullmatch(actual_image) is None:raise ValueError("control authority needs actual installed image")
    value, expected_old, expected_new = validate(reference, body_policy=POLICY, actual_image=actual_image)
    if original != expected_old or current != expected_new:raise ValueError("control authority changed original/current executed implementation")
    return value


def _listed_inputs(ids, *, workload_root, sidecar_root, reference, body_policy):
    value, _, _ = validate(reference, body_policy=body_policy)
    rows = [row for row in value["workloads"] if row["workload_id"] in ids]
    if [row["workload_id"] for row in rows] != list(ids):raise ValueError("control authority changed group order or membership")
    for row in rows:
        base, sidecar = Path(workload_root) / (row["workload_id"] + ".json"), Path(sidecar_root) / (row["workload_id"] + ".json")
        context = current_context()
        if context is not None:context.watch_file(base);context.watch_file(sidecar)
        evidence._read(base, row["base_manifest"]["sha256"]);evidence._read(sidecar, row["sidecar"]["sha256"])


def load_named_qualification_set(path, *, delivery_compatibility=None, body_policy=None, **kwargs):
    if not is_authority(delivery_compatibility):return old.load_named_qualification_set(path, delivery_compatibility=delivery_compatibility, body_policy=body_policy, **kwargs)
    with qualification_context(delivery_compatibility, body_policy=body_policy):
        result = old.budget.load_named_qualification_set(path, **kwargs)
        _listed_inputs(result.workload_ids, workload_root=kwargs["workload_root"], sidecar_root=kwargs.get("sidecar_root") or Path(path).parent, reference=delivery_compatibility, body_policy=body_policy)
        return result


def load_response_qualified_chaff(path, *, delivery_compatibility=None, body_policy=None, **kwargs):
    if not is_authority(delivery_compatibility):return old.load_response_qualified_chaff(path, delivery_compatibility=delivery_compatibility, body_policy=body_policy, **kwargs)
    with qualification_context(delivery_compatibility, body_policy=body_policy):
        _listed_inputs([kwargs["workload_id"]], workload_root=Path(kwargs["base_manifest_path"]).parent, sidecar_root=Path(path).parent, reference=delivery_compatibility, body_policy=body_policy)
        return old.budget.load_response_qualified_chaff(path, **kwargs)


def publish_named_qualification_set(workload_ids, *, delivery_compatibility=None, body_policy=None, **kwargs):
    if not is_authority(delivery_compatibility):return old.publish_named_qualification_set(workload_ids, delivery_compatibility=delivery_compatibility, body_policy=body_policy, **kwargs)
    with qualification_context(delivery_compatibility, body_policy=body_policy):
        _listed_inputs(workload_ids, workload_root=kwargs["workload_root"], sidecar_root=kwargs["sidecar_root"], reference=delivery_compatibility, body_policy=body_policy)
        current_context().check()
        return old.budget.publish_named_qualification_set(workload_ids, **kwargs)
