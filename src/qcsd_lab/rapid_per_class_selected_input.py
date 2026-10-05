"""Closed dispatch across unchanged plain V1 and new selected budget inputs."""
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from . import rapid_selected_capture_input as plain
from . import rapid_selected_budget_input as budget
from . import rapid_per_class_selected_enrollment as ledger
from . import supplied_static_get as get
from . import rapid_site_admission as receipts

ROLE = ledger.ROLE
reference = plain.reference
reopen = plain.reopen


def is_selected(value: Any) -> bool:
    return plain.is_selected(value) or budget.is_selected(value)


def module_for_preparation(value: Mapping[str, Any]):
    if plain.is_selected(value):
        return plain
    if budget.is_selected(value):
        return budget
    raise ValueError("per-class input has an unknown selected role")


def receipt_ref(value: Mapping[str, Any]) -> dict:
    module = module_for_preparation(value)
    field = "selected_input_evidence" if module is plain else budget.FIELD
    return value[field]["receipt"]


def wrap(manifest: dict, ref: Mapping[str, Any]) -> dict:
    module = ledger.input_module(ref)
    field = "selected_input_evidence" if module is plain else budget.FIELD
    result = deepcopy(manifest)
    result["preparation"].update(data_role=module.ROLE, **{field: {
        "schema_version": 1, "record_type": module.RECEIPT_TYPE, "receipt": dict(ref)}})
    return result


def validate_input(path: Path):
    return ledger.input_module(reference(path)).validate_input(path)


def validate_preparation(value: Mapping[str, Any], resources: list[dict]):
    return module_for_preparation(value).validate_preparation(value, resources)


def preparation_inputs(value: Mapping[str, Any], resources: list[dict]):
    return module_for_preparation(value).preparation_inputs(value, resources)


def audit_inputs(path: Path) -> set[Path]:
    if get._load(get._read(path)).get("receipt_type") == plain.AUDIT_TYPE:
        return plain.audit_inputs(path)
    value = budget.read_audit(path)
    return {path.absolute(), *(reopen(value[key]) for key in
        ("started", "completed", "stdout", "stderr", "source_inventory"))}


def current_sources(ref: Mapping[str, Any]) -> dict:
    return ledger.input_module(ref).direct_sources()


def publish_input(output: Path, *, audit: Path, candidate_id: str) -> Path:
    kind = get._load(get._read(audit)).get("receipt_type")
    if kind == plain.AUDIT_TYPE:
        return plain.publish_input(output, audit=audit, candidate_id=candidate_id)
    if kind == budget.AUDIT_TYPE:
        return budget.publish_input(output, audit=audit, candidate_id=candidate_id)
    raise ValueError("per-class renewal refuses an unknown original audit")


def prepare_input(path: Path, output: Path) -> Path:
    return ledger.input_module(reference(path)).prepare_input(path, output)


def payload(path: Path) -> dict:
    module = ledger.input_module(reference(path))
    return receipts._unpack(get._read(path), module.RECEIPT_TYPE)
