import json
from pathlib import Path

import pytest
import yaml

from qcsd_lab.util import source_metadata


def test_source_metadata_reads_baked_image_record(tmp_path, monkeypatch):
    record = {
        "development_build": True,
        "lab_commit": "a" * 40,
        "lab_dirty": True,
        "lab_patch_sha256": "b" * 64,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": "d" * 64,
    }
    path = tmp_path / "source.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(path))
    assert source_metadata() == record
    assert "schema_version" not in source_metadata()


def test_source_metadata_rejects_unknown_fields(tmp_path, monkeypatch):
    path = tmp_path / "source.json"
    path.write_text('{"obsolete": true}', encoding="utf-8")
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(path))
    with pytest.raises(ValueError, match="invalid source metadata"):
        source_metadata()


def test_only_qcsd_workflow_remains_with_bounded_triggers():
    root = Path(__file__).parents[1]
    workflows = sorted((root / "neqo-qcsd/.github/workflows").glob("*.yml"))
    assert [path.name for path in workflows] == ["qcsd.yml"]
    workflow = yaml.load(workflows[0].read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    triggers = workflow["on"]
    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
