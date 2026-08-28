from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from qcsd_lab import runtime_provenance


ROOT = Path(__file__).resolve().parents[1]
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _source_manifest(path: Path) -> None:
    sources = [
        ROOT / ".dockerignore",
        ROOT / "Dockerfile",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
        ROOT / "tools/build_class_catalogue.py",
        *sorted((ROOT / "src/qcsd_lab").rglob("*.py")),
    ]
    value = {
        source.relative_to(ROOT).as_posix(): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in sources
    }
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _source_metadata(path: Path) -> None:
    value = {
        "image_digest": None,
        "lab_commit": "1" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": "2" * 40,
        "neqo_pinned_commit": "2" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_runtime_receipt_binds_every_installed_module_and_catalogue_tool(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    tool = tmp_path / "qcsd-build-class-catalogue"
    entrypoint = tmp_path / "qcsd-lab-internal"
    _source_manifest(manifest)
    _source_metadata(metadata)
    shutil.copyfile(ROOT / "tools/build_class_catalogue.py", tool)
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    entrypoint.chmod(0o755)

    receipt = runtime_provenance.build_runtime_receipt(
        manifest,
        metadata,
        destination,
        catalogue_tool=tool,
        entrypoint=entrypoint,
    )

    expected_modules = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src/qcsd_lab").rglob("*.py")
    }
    assert set(receipt["installed_modules"]) == expected_modules
    assert {
        path for path in expected_modules if Path(path).name.startswith("class_")
    } == {
        path
        for path in receipt["installed_modules"]
        if Path(path).name.startswith("class_")
    }
    assert runtime_provenance._REQUIRED_CLASS_MODULES.issubset(
        receipt["installed_modules"]
    )
    assert receipt["installed_tools"] == {
        "tools/build_class_catalogue.py": {
            "path": str(tool),
            "sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
        }
    }
    assert runtime_provenance.validate_runtime_receipt(destination) == receipt


def test_runtime_receipt_rejects_post_build_tool_mutation(tmp_path: Path) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    tool = tmp_path / "qcsd-build-class-catalogue"
    entrypoint = tmp_path / "qcsd-lab-internal"
    _source_manifest(manifest)
    _source_metadata(metadata)
    shutil.copyfile(ROOT / "tools/build_class_catalogue.py", tool)
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    entrypoint.chmod(0o755)
    runtime_provenance.build_runtime_receipt(
        manifest,
        metadata,
        destination,
        catalogue_tool=tool,
        entrypoint=entrypoint,
    )
    tool.write_text("changed\n", encoding="utf-8")

    with pytest.raises(ValueError, match="differs from its runtime receipt"):
        runtime_provenance.validate_runtime_receipt(destination)


def test_runtime_receipt_requires_clean_gitlink_matched_source(tmp_path: Path) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    tool = tmp_path / "qcsd-build-class-catalogue"
    entrypoint = tmp_path / "qcsd-lab-internal"
    _source_manifest(manifest)
    _source_metadata(metadata)
    value = json.loads(metadata.read_text(encoding="utf-8"))
    value["lab_dirty"] = True
    metadata.write_text(json.dumps(value), encoding="utf-8")
    shutil.copyfile(ROOT / "tools/build_class_catalogue.py", tool)
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    entrypoint.chmod(0o755)

    with pytest.raises(ValueError, match="not clean and pinned"):
        runtime_provenance.build_runtime_receipt(
            manifest,
            metadata,
            destination,
            catalogue_tool=tool,
            entrypoint=entrypoint,
        )


def test_runtime_source_manifest_cannot_omit_a_class_study_module(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "source-files.json"
    _source_manifest(manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    omitted = next(iter(sorted(runtime_provenance._REQUIRED_CLASS_MODULES)))
    value.pop(omitted)
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="source-file inventory is invalid"):
        runtime_provenance._source_file_manifest(manifest)
