"""Genuine renewal reference shapes, with original membership proof controlled.

The positive reads the ten actual immutable renewal input/manifest files. It
does not replay admission, canary, GET, installation, or packet validators.
Negative controls copy one real file before changing its bytes or full mode.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_additive_static_enrollment as additive
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_ordinary_parallel_schedule as parallel
from qcsd_lab import rapid_per_class_selected_enrollment as per_class
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab.rapid_operation_facts import OperationFacts


WORKSPACE = Path(__file__).resolve().parents[3]
ACTUAL_RENEWAL = WORKSPACE / "diagnostic-rehearsals/ordinary-parallel-b03-canary-root-actual-20261006-002/renewal/ordinary-renewal.json"


def setup_inputs(tmp_path, monkeypatch, *, copied=False):
    value = json.loads(ACTUAL_RENEWAL.read_bytes())
    assert len(value["rows"]) == 5
    assert all(set(row[name]) == {"path", "sha256", "mode"}
               for row in value["rows"] for name in ("current_input", "current_manifest"))
    if copied:
        value = copy.deepcopy(value)
        old = value["rows"][0]["current_input"]
        path = tmp_path / "copied-current-input.json"
        path.write_bytes(Path(old["path"]).read_bytes())
        path.chmod(old["mode"])
        value["rows"][0]["current_input"] = selected.reference(path)
        renewal = tmp_path / "copied-renewal.json"
        renewal.write_text(json.dumps(value))
    else:
        renewal = ACTUAL_RENEWAL
    qspec = tmp_path / "ordinary-input.json"
    qspec.write_text(json.dumps({"renewal": rolling._ref(renewal)}))
    receipt = rolling._write(tmp_path / "plan.json", lanes.PLAN_TYPE, {})
    cohort = Path(value["enrollment"]["path"])
    spec = SimpleNamespace(cohort=cohort, qualification_spec=qspec, plan_receipt=receipt)
    monkeypatch.setattr(per_class, "enrollment_kind", lambda path: False)
    monkeypatch.setattr(additive, "enrollment_kind", lambda path: True)
    monkeypatch.setattr(additive, "membership_inputs", lambda path: {cohort})
    monkeypatch.setattr(OperationFacts, "bind_capture", lambda own, base:
        [own.watch_file(path) for path in (base.cohort, base.qualification_spec, base.plan_receipt)])
    return spec, value


def test_genuine_five_site_renewal_three_field_refs(tmp_path, monkeypatch):
    spec, value = setup_inputs(tmp_path, monkeypatch)
    with OperationFacts().scope() as context:
        files, trees = parallel.input_dependencies(spec, (), _context=context)
        expected = {Path(row[name]["path"]) for row in value["rows"]
                    for name in ("current_input", "current_manifest")}
        assert len(expected) == 10 and expected <= files and trees == set()
        context.check()


@pytest.mark.parametrize("changed", ["bytes", "mode"])
def test_renewal_ref_drift_refuses_before_use(tmp_path, monkeypatch, changed):
    spec, value = setup_inputs(tmp_path, monkeypatch, copied=True)
    path = Path(value["rows"][0]["current_input"]["path"])
    if changed == "bytes":
        path.write_bytes(path.read_bytes() + b" ")
    else:
        path.chmod(path.stat().st_mode & 0o7777 ^ 0o100)
    with OperationFacts().scope() as context:
        with pytest.raises(ValueError):
            parallel.input_dependencies(spec, (), _context=context)


@pytest.mark.parametrize("changed", ["bytes", "mode"])
def test_renewal_ref_drift_at_closing_fence(tmp_path, monkeypatch, changed):
    spec, value = setup_inputs(tmp_path, monkeypatch, copied=True)
    path = Path(value["rows"][0]["current_input"]["path"])
    with OperationFacts().scope() as context:
        parallel.input_dependencies(spec, (), _context=context)
        if changed == "bytes":
            path.write_bytes(path.read_bytes() + b" ")
        else:
            path.chmod(path.stat().st_mode & 0o7777 ^ 0o100)
        with pytest.raises(ValueError):
            context.check()
