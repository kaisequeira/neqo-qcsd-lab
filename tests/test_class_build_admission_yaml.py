from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from qcsd_lab import class_campaigns
from qcsd_lab.class_build_admission import (
    _campaign_carrier_scalars,
    _CampaignSubsetParser,
)
from qcsd_lab.class_successor import _successor_campaign_documents

_CARRIER_KEYS = (
    "parameters",
    "chaff_qualification_set",
    "class_study_cohort_assembly",
    "evidence_role",
    "class_study_successor",
)


def _safe_load_carriers(text: str) -> dict[str, list[str]]:
    document = yaml.safe_load(text)
    assert isinstance(document, Mapping)
    role = document.get("evidence_role")
    assert isinstance(role, str) and role
    selected = {key: [] for key in _CARRIER_KEYS}
    selected["evidence_role"].append(role)

    pending: list[tuple[object, bool]] = [(document, True)]
    while pending:
        value, root = pending.pop()
        if isinstance(value, Mapping):
            for key, item in reversed(tuple(value.items())):
                if key == "evidence_role":
                    assert root
                elif key in selected:
                    assert isinstance(item, str) and item
                    selected[key].append(item)
                pending.append((item, False))
        elif isinstance(value, list):
            pending.extend((item, False) for item in reversed(value))
    return selected


def _normalise_non_string_scalars(value: object) -> object:
    """Match the admission parser's intentionally value-blind scalar model."""

    if isinstance(value, Mapping):
        return {key: _normalise_non_string_scalars(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise_non_string_scalars(item) for item in value]
    return value if isinstance(value, str) else None


def _base_campaigns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, dict[str, Any]]:
    cohort = tmp_path / "cohort.json"
    assembly = tmp_path / "cohort-assembly.json"
    cohort.write_text("{}\n", encoding="utf-8")
    assembly.write_text("{}\n", encoding="utf-8")
    pilot = tuple(SimpleNamespace(candidate_id=f"tranco-{rank:07d}") for rank in range(1, 121))
    selection = SimpleNamespace(pilot=pilot, final=pilot[:100])
    monkeypatch.setattr(
        class_campaigns,
        "load_study_receipt",
        lambda _path: ({}, selection),
    )
    monkeypatch.setattr(
        class_campaigns,
        "validate_cohort_assembly_receipt",
        lambda _value, *, cohort: None,
    )
    return class_campaigns.campaign_documents(
        cohort,
        cohort_assembly_receipt=assembly,
    )


def test_restricted_yaml_matches_all_generated_campaign_inventories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _base_campaigns(tmp_path, monkeypatch)
    successor_study = "classifier-multiorigin100-v2-g01-0123456789ab"
    successor = _successor_campaign_documents(
        study_id=successor_study,
        workload_ids=tuple(f"tranco-{rank:07d}" for rank in range(1, 101)),
        qualification_set=f"{successor_study}-final-full",
        restart_root=tmp_path / successor_study,
    )

    assert len(base) == 24
    assert len(successor) == 22
    for name, document in (*base.items(), *successor.items()):
        encoded = yaml.safe_dump(document, sort_keys=False, width=100)
        loaded = yaml.safe_load(encoded)
        assert _CampaignSubsetParser(encoded).parse() == _normalise_non_string_scalars(loaded), name
        assert _campaign_carrier_scalars(encoded) == _safe_load_carriers(encoded), name


def test_restricted_yaml_rejects_compact_nested_block_sequence() -> None:
    encoded = yaml.safe_dump(
        {
            "evidence_role": "formal",
            "nested": [[{"parameters": "/lab/alternate/traffic-morphing.json"}]],
        },
        sort_keys=False,
        width=100,
    )
    assert "- - parameters:" in encoded

    with pytest.raises(ValueError):
        _campaign_carrier_scalars(encoded)


@pytest.mark.parametrize(
    "spelling",
    (
        "1.0e+20",
        ".inf",
        ".nan",
        "0x10",
        "1:20",
        "2026-09-07",
    ),
)
def test_restricted_yaml_rejects_implicit_non_string_authority_scalars(
    spelling: str,
) -> None:
    loaded = yaml.safe_load(f"authority: {spelling}\n")
    assert not isinstance(loaded["authority"], str)

    with pytest.raises(ValueError):
        _campaign_carrier_scalars(
            "evidence_role: formal\n"
            "defenses:\n"
            "- name: traffic-morphing\n"
            f"  parameters: {spelling}\n"
        )

    quoted = yaml.safe_dump(
        {"evidence_role": "formal", "parameters": spelling},
        sort_keys=False,
        width=100,
    )
    assert _campaign_carrier_scalars(quoted)["parameters"] == [spelling]
