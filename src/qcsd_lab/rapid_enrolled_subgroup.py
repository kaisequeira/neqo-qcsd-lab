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

def input_roots(reference, value):
    """Derive only read-only metadata transport for a current typed subgroup.

    Enrollment and complete class records retain their original validators.
    Parent directories carry authenticated files; only declared immutable
    Source trees are watched as trees, so later study outputs are not inputs.
    """
    from . import rapid_rolling_capture as rolling
    from . import rapid_additive_static_enrollment as additive
    from . import rapid_per_class_selected_enrollment as per_class
    from .rapid_operation_facts import OperationFacts, current_context
    from .static_evidence_transport import _path

    context = current_context()
    if context is None:
        with OperationFacts().scope() as context:
            return input_roots(reference, value)
    enrollment = _path(rolling._open_ref(reference))
    context.watch_file(enrollment)
    batch, classes, policy = rolling._verify_enrollment(enrollment)
    validate(value, enrollment, batch, classes)
    if not isinstance(policy, dict):
        raise ValueError("subgroup transport requires a selected enrollment policy")
    if policy.get("contract") == per_class.CONTRACT:
        from . import per_class_selected_capture_amendment as metadata
    elif policy.get("contract") == additive.CONTRACT:
        from . import selected_capture_amendment as metadata
    else:
        raise ValueError("subgroup transport encountered an unsupported enrollment policy")
    files, trees = metadata.metadata_inputs(enrollment, batch, classes, policy)
    files = {_path(Path(path)) for path in files} | {enrollment}
    trees = {_path(Path(path), directory=True) for path in trees}
    for path in sorted(files):
        context.watch_file(path)
    for path in sorted(trees):
        context.watch_tree(path, ignore_git=True)
    # Reopen the typed authority after registering every returned dependency.
    # The collectors own private file observations; these checks close the
    # interval before their observations were added to this owning action.
    reopened_files, reopened_trees = metadata.metadata_inputs(enrollment, batch, classes, policy)
    if (set(map(Path, reopened_files)) | {enrollment} != files
            or set(map(Path, reopened_trees)) != trees):
        raise ValueError("subgroup transport metadata membership changed")
    roots = trees | {_path(path.parent, directory=True) for path in files}
    roots = sorted(root for root in roots
                   if not any(root != parent and root.is_relative_to(parent) for parent in roots))
    context.check()
    return roots
