"""Optional HOST oracle for a real mixed-budget per-class enrollment."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab.rapid_operation_facts import OperationFacts


@pytest.fixture
def enrollment() -> Path:
    value = os.environ.get("QCSD_PER_CLASS_21_ENROLLMENT")
    if value is None:
        pytest.skip("real per-class enrollment oracle is not configured")
    return Path(value)


def _classes(reference):
    facts = OperationFacts()
    facts.begin_action()
    with facts.scope():
        rows, dependencies = target._classes(reference)
        facts.check()
    return rows, dependencies


def test_real_per_class_membership_keeps_all_graphs_and_budgets(enrollment):
    reference = target.reference(enrollment)
    rows, dependencies = _classes(reference)

    assert [row["class_index"] for row in rows] == list(range(1, 22))
    assert len(dependencies["files"]) > 0
    assert all(row["original_graph_sha256"] == target.membership.graph_identity(
        Path(row["original_manifest"]["path"])) for row in rows)
    assert [row["capture_limits"]["max_response_bytes"] for row in rows] == [16 * 1024 * 1024] * 18 + [64 * 1024 * 1024] * 3
    assert [row["capture_limits"]["capture_megabytes"] for row in rows] == [64] * 18 + [256] * 3


@pytest.mark.parametrize("field", ["sha256", "mode"])
def test_real_per_class_membership_rejects_changed_reference(enrollment, field):
    reference = target.reference(enrollment)
    reference[field] = "0" * 64 if field == "sha256" else reference["mode"] ^ 0o100
    with pytest.raises(ValueError):
        _classes(reference)
