"""The new graph reader retains the exact earlier whole-GET Source pair."""
from copy import deepcopy
import os
from pathlib import Path

import pytest
from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import whole_graph_supplement as whole


SOURCE46_INPUT = "a95019161d069fda019de74768a13283a4a37d89fc6cddab0b2ddd0b52540245"
SOURCE46_SUPPLEMENT = "72a3e7030356955033fefab3703abe895c4fdb264910ea9c4d40ca398f175052"
PREDECESSORS = Path(__file__).parent / "fixtures/v9_reader_predecessors"


def test_exact_source46_get_pair_reopens_without_relabeling():
    current = whole.producer_sources()
    historical = {**current, "qcsd_lab.whole_graph_input": SOURCE46_INPUT,
                  whole.__name__: SOURCE46_SUPPLEMENT}
    original = deepcopy(historical)
    assert whole._recognized_producer_sources(historical)
    assert historical == original
    assert whole._recognized_producer_sources(current)

    changed = dict(historical)
    changed[whole.__name__] = current[whole.__name__]
    assert not whole._recognized_producer_sources(changed)
    changed = dict(historical)
    changed["qcsd_lab.whole_graph_input"] = current["qcsd_lab.whole_graph_input"]
    assert not whole._recognized_producer_sources(changed)


def test_source43_to_current_reader_guard_retains_protected_code_and_full_modes():
    current = Path(whole.__file__)
    before = fixed.reference(PREDECESSORS / "whole_graph_supplement.py")
    after = fixed.reference(current)
    assert fixed._compatible_acquisition_code("src/qcsd_lab/whole_graph_supplement.py", before, after)
    assert fixed._compatible_code_ref("target",
        fixed.reference(PREDECESSORS / "rapid_fixed_condition_target.py"),
        fixed.reference(Path(fixed.__file__)))
    readers = fixed._acquisition_reader_sources()
    assert readers["src/qcsd_lab/whole_graph_input.py"]["mode"] == 0o644
    assert readers["src/qcsd_lab/whole_graph_supplement.py"]["sha256"] == after["sha256"]


def test_actual_clean_source46_reader_ancestry_retains_protected_code():
    raw = os.environ.get("QCSD_SOURCE46_ROOT")
    if raw is None:
        pytest.skip("QCSD_SOURCE46_ROOT is not bound to an immutable clean Source46 checkout")
    source46 = Path(raw)
    old_supplement = fixed.reference(source46 / "src/qcsd_lab/whole_graph_supplement.py")
    old_target = fixed.reference(source46 / "src/qcsd_lab/rapid_fixed_condition_target.py")
    old_input = fixed.reference(source46 / "src/qcsd_lab/whole_graph_input.py")
    assert old_supplement["sha256"] == SOURCE46_SUPPLEMENT
    assert old_input["sha256"] == SOURCE46_INPUT
    assert old_target["sha256"] == "38b58853b7788608ad7601f927a4a924d7257641f1e373d3c288dd228b93b705"
    assert {old_input["mode"], old_supplement["mode"], old_target["mode"]} == {0o644}
    current = Path(fixed.__file__).parent
    assert fixed._compatible_acquisition_code("src/qcsd_lab/whole_graph_supplement.py",
        old_supplement, fixed.reference(current / "whole_graph_supplement.py"))
    assert fixed._compatible_code_ref("target", old_target,
        fixed.reference(current / "rapid_fixed_condition_target.py"))
