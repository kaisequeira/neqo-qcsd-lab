"""Actual startup spec parsing must not enter the scientific validator.

The imported fixture supplies real clean Git/file bindings. Its intentionally
unqualified inputs never gain capture or scientific authority.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_undefended_capture as ordinary
from tests.test_rapid_parallel_lifecycle_inputs import context, check, put, ref


def reseal(context, value):
    put(context.spec_path, value)
    context.value["lane_specs"] = [ref(context.spec_path), ref(context.spec_path)]
    context.value["capture_spec"] = context.value["lane_specs"][0]
    put(context.path, context.value)


@pytest.mark.parametrize("layout", ["ordinary", "ordinary-workers", "fixed-target-workers"])
def test_lifecycle_checks_real_spec_without_scientific_layout_admission(context, monkeypatch, layout):
    put(context.spec_path.parent / "qualification.json", {"artifact_type": ordinary.INPUT_TYPE})
    put(context.spec_path.parent / "plan.json", {"fixture_layout": layout})
    calls = []

    def scientific_layout(*args, **kwargs):
        calls.append("scientific-layout")
        raise RuntimeError("full graph reproof belongs after lifecycle admission")

    monkeypatch.setattr(lanes, "_qualification_layout", scientific_layout)
    # The former startup API demonstrably enters that expensive boundary for
    # these same sealed inputs. Startup must not call it under READY's deadline.
    with pytest.raises(RuntimeError, match="after lifecycle admission"):
        lanes.load_capture_spec(context.spec_path)
    assert calls == ["scientific-layout"]
    calls.clear()
    assert check(context) is None
    assert calls == []
    assert not (context.evidence / "deep-verification.json").exists()


@pytest.mark.parametrize("change", ["unknown-field", "boolean-version", "wrong-type",
    "unknown-input", "missing-input", "empty-path", "non-string-path",
    "invalid-image", "non-string-generation", "invalid-generation"])
def test_lifecycle_refuses_resealed_malformed_capture_specs(context, change):
    value = deepcopy(json.loads(context.spec_path.read_bytes()))
    if change == "unknown-field":
        value["unregistered"] = True
    elif change == "boolean-version":
        value["schema_version"] = True
    elif change == "wrong-type":
        value["artifact_type"] = "unregistered"
    elif change == "unknown-input":
        value["inputs"]["unregistered"] = True
    elif change == "missing-input":
        value["inputs"].pop("cohort")
    elif change in {"empty-path", "non-string-path"}:
        value["inputs"]["cohort"] = "" if change == "empty-path" else 7
    elif change == "invalid-image":
        value["inputs"]["collection_image_digest"] = "mutable-tag"
    elif change == "non-string-generation":
        value["inputs"]["execution_generation"] = True
    else:
        value["inputs"]["execution_generation"] = "unregistered/generation"
    reseal(context, value)
    with pytest.raises(ValueError, match="capture spec"):
        check(context)


def test_lifecycle_preserves_portable_relative_spec_resolution(context):
    value = json.loads(context.spec_path.read_bytes())
    expected = context.module._lifecycle_spec_inputs(context.spec_path)
    for key in ("cohort", "qualification_spec", "plan_receipt", "source_manifest", "client_binary"):
        value["inputs"][key] = Path(value["inputs"][key]).name
    reseal(context, value)
    assert context.module._lifecycle_spec_inputs(context.spec_path) == expected
    assert check(context) is None


def test_lifecycle_refuses_duplicate_capture_spec_keys_even_when_resealed(context):
    raw = context.spec_path.read_text()
    context.spec_path.write_text(raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
    context.value["lane_specs"] = [ref(context.spec_path), ref(context.spec_path)]
    context.value["capture_spec"] = context.value["lane_specs"][0]
    put(context.path, context.value)
    with pytest.raises(ValueError, match="repeats a key"):
        check(context)
