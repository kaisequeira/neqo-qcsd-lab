"""Zero-credit join from sealed compact captures through evaluation input.

The tiny synthetic corpus exercises the real result seal, handoff exporter,
handoff verifier, evaluation loader, temporal split, and Panchenko backend.
External capture, cohort, and classifier runtime authority remain fixtures.
"""

from pathlib import Path

import pytest

import tests.test_class_handoff as handoff_fixture
from tests.test_class_capture_handoff_dry_run import (
    _export_and_verify,
    _sealed_compact_results,
)
from qcsd_lab.class_evaluation import (
    _Dimensions,
    _load_class_handoff,
    adaptive_temporal_splits,
    run_class_attacks,
)
from qcsd_lab.class_handoff import CLASSIFIER_FIELDS


def test_sealed_capture_handoff_loads_and_runs_temporal_classifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff_dimensions, receipts = _sealed_compact_results(tmp_path, monkeypatch)
    handoff = _export_and_verify(tmp_path, handoff_dimensions, receipts)
    evaluation_dimensions = _Dimensions(
        study_id=handoff_dimensions.study_id,
        classes=handoff_dimensions.class_count,
        modes=handoff_dimensions.modes,
        blocks=handoff_dimensions.block_count,
        visits_per_block=handoff_dimensions.visits_per_block,
    )

    def verify_handoff(path: Path, deep: bool) -> Path:
        return handoff_fixture._verify_class_handoff(
            path,
            dimensions=handoff_dimensions,
            deep=deep,
            source_verifier=lambda root: next(
                receipt for receipt in receipts if receipt.root == root.resolve()
            ),
            trace_extractor=handoff_fixture._trace,
            classic_pcap_writer=handoff_fixture._classic_writer,
            correctness_validator=handoff_fixture._correctness_validator,
            performance_extractor=handoff_fixture._performance_extractor,
            cohort_loader=handoff_fixture._cohort_loader,
            assembly_validator=handoff_fixture._assembly_validator,
        )

    dataset = _load_class_handoff(
        handoff,
        dimensions=evaluation_dimensions,
        handoff_verifier=verify_handoff,
        cohort_loader=handoff_fixture._cohort_loader,
        assembly_validator=handoff_fixture._assembly_validator,
        deep_verify=True,
    )
    assert len(dataset.samples) == evaluation_dimensions.sample_count == 12
    assert {sample.split for sample in dataset.samples} == {"train", "validation", "test"}
    assert all(sample.trace for sample in dataset.samples)
    assert all(
        tuple(packet.__dataclass_fields__)
        == ("relative_time_ns", "direction", "length_bytes")
        for sample in dataset.samples
        for packet in sample.trace
    )
    assert CLASSIFIER_FIELDS == (
        "relative_time_ns",
        "direction",
        "observer_frame_length_bytes",
    )
    assert len(adaptive_temporal_splits(dataset)) == 2
    attack = run_class_attacks(
        dataset,
        attacks=("panchenko",),
        include_secondary=False,
        formal=False,
    )
    assert len(attack.results) == 8
    assert all(result.test_samples == 2 for result in attack.results)
