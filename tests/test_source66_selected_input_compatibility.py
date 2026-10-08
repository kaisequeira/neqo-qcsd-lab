"""Exact Source65 selected-input reuse; HOST controls grant no trace credit.

The complete source tuples below are authenticated from the held Source65
class17/class18 receipts. Source-file fixtures restore exact predecessor bytes;
the structural manifest controls do not claim a Native run or GET result.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_selected_budget_input as budget
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import whole_graph_supplement as whole
from tests.test_whole_get_required_parent_policy import neutral_graph

OLD_SELECTED = "ba8caa645d219a52eb1e177285bb7e9f9198a1b59c46fdb37692f95206230442"
NEW_SELECTED = "72933db93fef22fd599dce35b2ae27dd2f525b112bc6140134540d1f1cad1fb1"
OLD_WHOLE = "4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0"
SOURCE65 = {
    "qcsd_lab.application_response_policy": "817e48d727bcb5b056f37582c8c469af7070deabbd367571c2ea05b9f36ac49a",
    "qcsd_lab.rapid_additive_static_enrollment": "5404821bf1bf087493d60076d33c5769748052f6301c352dccc6dae61e630670",
    selected.__name__: OLD_SELECTED,
    "qcsd_lab.supplied_static_bootstrap_get": "4a53baeb9f66220b6108ea304f54dd834fc447a4cc43f58a358de018b421f692",
    "qcsd_lab.supplied_static_get": "ce20fe5b5d60f7b268b7eb659ab56e98048d5934bc9cb3b456e2ef99c330d322",
    "qcsd_lab.supplied_static_graph": "87370d25d526a22cac7519a721aed0db19b72fa5957a353301782779409d4efa",
    "qcsd_lab.supplied_static_preparation": "087ebcea7cf8c793a82cbf40bcb0e77fb1555ba50b648c02af85e52c76641f44",
    whole.__name__: OLD_WHOLE,
}
BUDGET_SOURCES = {
    budget.__name__: "3f03bae31b667535adab316fea98cc34f19bf9292bc1b041f428eb3a02dee3cb",
    "qcsd_lab.supplied_static_budget_successor": "a297fd337517ddffc30fc6e08b5961e2556f9311cbe5f7837baa0209bcf298d1",
}


def historical_sources(tmp_path, typed=False):
    """Reconstruct full byte-identical Source65 files, never relabel current code."""
    sources = {**SOURCE65, **(BUDGET_SOURCES if typed else {})}
    modules = budget._modules() if typed else selected._direct_modules()
    refs = {}
    for module in modules:
        raw = Path(module.__file__).read_bytes()
        if module.__name__ == selected.__name__:
            assert hashlib.sha256(raw).hexdigest() == NEW_SELECTED
            raw = fixed._source65_selected_input_source_projection(raw)
        elif module.__name__ == whole.__name__:
            raw = fixed._required_parent_get_source_projection(raw)
        assert hashlib.sha256(raw).hexdigest() == sources[module.__name__]
        path = tmp_path / "source65/src/qcsd_lab" / Path(module.__file__).name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
        refs[module.__name__] = selected.reference(path)
    assert set(refs) == set(sources)
    return {"direct_validator_sources": sources, "direct_validator_files": refs}


@pytest.mark.parametrize("typed", [False, True])
def test_exact_complete_source65_dictionary_retains_original_labels(tmp_path, typed):
    value = historical_sources(tmp_path, typed)
    before = deepcopy(value)
    expected = budget.direct_sources() if typed else selected.direct_sources()
    assert selected._compatible_direct_validator_sources(value, expected)
    assert selected._bound_validator_files(value) == {
        Path(item["path"]) for item in value["direct_validator_files"].values()}
    assert value == before
    assert value["direct_validator_sources"][selected.__name__] == OLD_SELECTED
    assert value["direct_validator_sources"][whole.__name__] == OLD_WHOLE


@pytest.mark.parametrize("typed", [False, True])
@pytest.mark.parametrize("mutation", [
    "unknown-whole", "missing", "extra", "selected-hybrid", "application-hybrid", "budget-hybrid"])
def test_source65_incomplete_or_invented_family_is_refused(tmp_path, typed, mutation):
    value = historical_sources(tmp_path, typed)
    expected = budget.direct_sources() if typed else selected.direct_sources()
    assert selected._compatible_direct_validator_sources(value, expected)
    sources = value["direct_validator_sources"]
    if mutation == "unknown-whole":
        sources[whole.__name__] = "0" * 64
    elif mutation == "missing":
        sources.pop("qcsd_lab.supplied_static_graph")
    elif mutation == "extra":
        sources["qcsd_lab.unknown"] = "0" * 64
    elif mutation == "selected-hybrid":
        sources[selected.__name__] = expected[selected.__name__]
    elif mutation == "application-hybrid":
        sources["qcsd_lab.application_response_policy"] = "0" * 64
    else:
        sources[budget.__name__] = "0" * 64
    assert not selected._compatible_direct_validator_sources(value, expected)


@pytest.mark.parametrize("name", [selected.__name__, whole.__name__])
@pytest.mark.parametrize("mutation", ["bytes", "full-mode"])
def test_source65_recorded_verifier_bytes_and_full_mode_remain_guarded(tmp_path, name, mutation):
    value = historical_sources(tmp_path)
    expected = selected.direct_sources()
    assert selected._compatible_direct_validator_sources(value, expected)
    path = Path(value["direct_validator_files"][name]["path"])
    if mutation == "bytes":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path.chmod(0o444)
    value["direct_validator_files"][name] = selected.reference(path)
    with pytest.raises(ValueError):
        selected._compatible_direct_validator_sources(value, expected)


@pytest.mark.parametrize("role", [whole.ROLE, selected.original.ROLE])
def test_legacy_selected_manifest_stays_exact_root_only(role):
    neutral = neutral_graph()
    before = deepcopy(neutral)
    declaration = {"schema_version": 1} if role == whole.ROLE else {"schema_version": 2}
    primary, full = selected._selected_get_manifests({"original_role": role}, declaration, neutral)
    expected = deepcopy(neutral)
    expected["resources"][0]["known_valid"] = True
    assert primary == {"resources": [before["resources"][0]]}
    assert full == expected and neutral == before


def prospective_declaration():
    return {"schema_version": 2,
        "manifest_policy": whole.REQUIRED_PARENT_MANIFEST_POLICY,
        "producer_sources": whole.producer_sources()}


def test_required_parent_selected_manifest_uses_exact_current_policy_and_preserves_every_row():
    neutral = neutral_graph()
    before = deepcopy(neutral)
    primary, full = selected._selected_get_manifests(
        {"original_role": whole.ROLE}, prospective_declaration(), neutral)
    assert [row["known_valid"] for row in full["resources"]] == [True, True, False, True, False]
    expected = deepcopy(before)
    for identifier in (0, 1, 3):
        expected["resources"][identifier]["known_valid"] = True
    assert full == expected and primary == {"resources": [before["resources"][0]]}
    assert full["resources"][1]["url"] == full["resources"][2]["url"]
    assert full["resources"][2]["depends_on"] == [1]
    assert neutral == before


@pytest.mark.parametrize("mutation", ["v1-promotion", "missing-policy", "unknown-policy",
    "retained-producer", "unknown-producer", "promoted-neutral-parent", "chaff-neutral"])
def test_selected_required_parent_policy_and_producer_cannot_be_reinterpreted(mutation):
    declaration, neutral = prospective_declaration(), neutral_graph()
    selected._selected_get_manifests({"original_role": whole.ROLE}, declaration, neutral)
    if mutation == "v1-promotion":
        declaration["schema_version"] = 1
    elif mutation == "missing-policy":
        declaration.pop("manifest_policy")
    elif mutation == "unknown-policy":
        declaration["manifest_policy"] = whole.LEGACY_MANIFEST_POLICY
    elif mutation == "retained-producer":
        declaration["producer_sources"][whole.__name__] = OLD_WHOLE
    elif mutation == "unknown-producer":
        declaration["producer_sources"][whole.__name__] = "0" * 64
    elif mutation == "promoted-neutral-parent":
        neutral["resources"][1]["known_valid"] = True
    else:
        neutral["resources"][2]["chaff_priority"] = True
    with pytest.raises(ValueError):
        selected._selected_get_manifests({"original_role": whole.ROLE}, declaration, neutral)


@pytest.mark.parametrize("basename,digest", [
    ("static-52b5bdba6837247ad5ed8a51896a395c6b6c0ca453b7cdc1cf339fc65b432ddf-input.json",
     "e6e084911eebd2f4c71ab92a836172d02f55a765959f9be7745a77025f0bcb91"),
    ("static-cc1221c3ac871c061d50fc1d177b0473a5b356fa6837e656a8928a6f037e65ab-input.json",
     "a953d32b8b60f79cea9ae0c524cf7c6bc45431fbe7ed2f278ad4dd8f6591b9a3")])
def test_optional_authentic_source65_receipt_dictionary_only(basename, digest):
    """Read authentic zero-credit metadata; do not claim full raw GET verification."""
    configured = os.environ.get("QCSD_SOURCE65_SELECTED_INPUT_ROOT")
    if configured is None:
        pytest.skip("authentic Source65 selected-input root was not supplied")
    path = Path(configured) / basename
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    assert path.stat().st_mode & 0o7777 == 0o600
    value = selected.receipts._unpack(raw, selected.RECEIPT_TYPE)
    before = deepcopy(value)
    assert value["direct_validator_sources"] == SOURCE65
    assert value["scientific_credit"] is False and value["formal_accepted_trace_count"] == 0
    assert selected._compatible_direct_validator_sources(value, selected.direct_sources())
    selected._bound_validator_files(value)
    assert value == before
