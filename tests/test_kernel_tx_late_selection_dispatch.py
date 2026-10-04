from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qcsd_lab import buflo_handoff, experiment
from qcsd_lab.util import atomic_json
from tests.test_experiment import _sample
from tests.test_kernel_tx_late_selection import _modern, _run


def _accepted_run(tmp_path: Path):
    sample = {
        **_sample(), "state": "accepted", "defense": "buflo",
        "runtime_kind": "buflo", "baseline": False,
    }
    run = {**_run(_modern()), "terminal_evidence_render_errors": []}
    atomic_json(tmp_path / sample["path"] / "neqo/run.json", run)
    return sample, run


def test_schema_twenty_handoff_requires_actual_valid_raw_receipt() -> None:
    run = _run(_modern())
    required, raw = buflo_handoff._runner_kernel_tx_requirement(run, runtime_kind="buflo")
    assert required and raw is run["runner_wakeup_metrics"]["buflo_kernel_tx"]
    changed = copy.deepcopy(run)
    del changed["runner_wakeup_metrics"]["buflo_kernel_tx"]
    with pytest.raises(ValueError, match="has no raw runner receipt"):
        buflo_handoff._runner_kernel_tx_requirement(changed, runtime_kind="buflo")
    changed = copy.deepcopy(run)
    changed["runner_wakeup_metrics"]["buflo_kernel_tx"]["protected_selection_wait"]["entries"][0]["clock_read_attempts"] += 1
    with pytest.raises(ValueError, match="pairing is invalid"):
        buflo_handoff._runner_kernel_tx_requirement(changed, runtime_kind="buflo")
    with pytest.raises(ValueError, match="non-kernel handoff sample"):
        buflo_handoff._runner_kernel_tx_requirement(run, runtime_kind="cs_buflo")


def test_schema_twenty_accepted_result_still_requires_wire_and_scheduler_sidecars(tmp_path: Path) -> None:
    sample, _run_value = _accepted_run(tmp_path)
    with pytest.raises(ValueError, match="lacks its evidence sidecar"):
        experiment.validate_accepted_kernel_tx_evidence(tmp_path, sample)
    with pytest.raises(ValueError, match="lacks its scheduler runtime receipt"):
        experiment.validate_accepted_scheduler_runtime_receipt(
            tmp_path, {"configuration": {"evidence_role": "formal"}}, sample,
        )


def test_schema_twenty_does_not_widen_current_cs_buflo_schema(tmp_path: Path) -> None:
    sample, _run_value = _accepted_run(tmp_path)
    sample.update(defense="cs-buflo", runtime_kind="cs_buflo")
    with pytest.raises(ValueError, match="CS-BuFLO sample requires runner-wakeup schema 10"):
        experiment.validate_accepted_scheduler_runtime_receipt(
            tmp_path, {"configuration": {"evidence_role": "formal"}}, sample,
        )
