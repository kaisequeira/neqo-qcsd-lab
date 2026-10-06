"""An ordered subset of an authenticated current enrollment batch.

This control selects complete class records. It grants no admission, response
qualification, capture or progress credit and never changes a resource graph.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIELD = "enrolled_subgroup"
TYPE = "qcsd-authenticated-current-enrollment-subgroup-v1"


def select_rows(batch, classes, indices):
    ids = batch["selected_candidate_ids"]
    tail = classes[-len(ids):]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 5 or [row["candidate_id"] for row in tail] != ids:
        raise ValueError("subgroup requires the exact authenticated current enrollment tail")
    if (not isinstance(indices, (list, tuple)) or not 1 <= len(indices) <= len(tail)
            or any(type(index) is not int for index in indices)
            or len(set(indices)) != len(indices)):
        raise ValueError("subgroup class indices must be distinct exact integers")
    chosen = [row for row in tail if row["class_index"] in indices]
    if [row["class_index"] for row in chosen] != list(indices):
        raise ValueError("subgroup must retain current-batch class membership and enrollment order")
    return chosen


def declare(enrollment: Path, batch, classes, indices):
    from . import rapid_rolling_capture as rolling
    rows = select_rows(batch, classes, indices)
    return {"artifact_type": TYPE, "enrollment": rolling._ref(Path(enrollment)),
        "batch_ordinal": batch["ordinal"], "class_indices": list(indices),
        "classes": [{"class_index": row["class_index"], "candidate_id": row["candidate_id"],
            "workload_id": row["workload_id"], "class_record_sha256": hashlib.sha256(json.dumps(
                row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()}
            for row in rows]}


def validate(value, enrollment: Path, batch, classes):
    if not isinstance(value, dict) or json.dumps(value, sort_keys=True, allow_nan=False) != json.dumps(
            declare(enrollment, batch, classes, value.get("class_indices")), sort_keys=True, allow_nan=False):
        raise ValueError("subgroup changed its original enrollment, class records or ordered selection")
    # Python equality must not treat booleans or floating ordinals as integers.
    if type(value["batch_ordinal"]) is not int:
        raise ValueError("subgroup batch ordinal must be an exact integer")
    return select_rows(batch, classes, value["class_indices"])


def require_canary(reference, value):
    from . import rapid_rolling_capture as rolling
    from . import rapid_lane_evidence as lanes
    if not isinstance(reference, dict) or "plan" not in reference:
        raise ValueError("subgroup requires its own authenticated full-group canary plan")
    document = lanes._load(lanes._read(rolling._open_ref(reference["plan"])))
    if document.get(FIELD) != value:
        raise ValueError("subgroup canary and formal plan select different enrolled classes")
