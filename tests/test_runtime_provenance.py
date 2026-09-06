from __future__ import annotations

import copy
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
        ROOT / "tools/browser_egress_qualification.py",
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


def _installed_runtime_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    catalogue = tmp_path / "qcsd-build-class-catalogue"
    browser_egress = tmp_path / "qcsd-browser-egress-qualification"
    entrypoint = tmp_path / "qcsd-lab-internal"
    shutil.copyfile(ROOT / "tools/build_class_catalogue.py", catalogue)
    shutil.copyfile(ROOT / "tools/browser_egress_qualification.py", browser_egress)
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for path in (catalogue, browser_egress, entrypoint):
        path.chmod(0o755)
    return catalogue, browser_egress, entrypoint


def test_runtime_receipt_binds_every_installed_module_and_runtime_tool(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    _source_manifest(manifest)
    _source_metadata(metadata)
    catalogue, browser_egress, entrypoint = _installed_runtime_files(tmp_path)

    receipt = runtime_provenance.build_runtime_receipt(
        manifest,
        metadata,
        destination,
        catalogue_tool=catalogue,
        browser_egress_tool=browser_egress,
        entrypoint=entrypoint,
    )

    assert receipt["schema_version"] == 2
    assert receipt["domain"] == "qcsd-python-runtime-implementation-v2"
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
            "path": str(catalogue),
            "sha256": hashlib.sha256(catalogue.read_bytes()).hexdigest(),
        },
        "tools/browser_egress_qualification.py": {
            "path": str(browser_egress),
            "sha256": hashlib.sha256(browser_egress.read_bytes()).hexdigest(),
        },
    }
    assert runtime_provenance.validate_runtime_receipt(destination) == receipt


def test_legacy_runtime_receipt_remains_exact_and_cannot_satisfy_current_image(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    _source_manifest(manifest)
    _source_metadata(metadata)
    catalogue, browser_egress, entrypoint = _installed_runtime_files(tmp_path)
    current = runtime_provenance.build_runtime_receipt(
        manifest,
        metadata,
        destination,
        catalogue_tool=catalogue,
        browser_egress_tool=browser_egress,
        entrypoint=entrypoint,
    )
    legacy = copy.deepcopy(current)
    legacy["schema_version"] = runtime_provenance.LEGACY_RUNTIME_RECEIPT_SCHEMA_VERSION
    legacy["domain"] = runtime_provenance.LEGACY_RUNTIME_RECEIPT_DOMAIN
    legacy["source_files"].pop("tools/browser_egress_qualification.py")
    legacy["installed_tools"].pop("tools/browser_egress_qualification.py")
    legacy["payload_sha256"] = runtime_provenance._payload_sha256(
        legacy, domain=runtime_provenance.LEGACY_RUNTIME_RECEIPT_DOMAIN
    )
    destination.write_text(
        json.dumps(legacy, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    assert runtime_provenance.validate_runtime_receipt(destination) == legacy
    with pytest.raises(ValueError, match="identity"):
        runtime_provenance.validate_runtime_receipt(
            destination,
            required_schema_version=runtime_provenance.RUNTIME_RECEIPT_SCHEMA_VERSION,
        )

    cross_version = copy.deepcopy(current)
    cross_version["schema_version"] = 1
    cross_version["domain"] = runtime_provenance.LEGACY_RUNTIME_RECEIPT_DOMAIN
    cross_version["payload_sha256"] = runtime_provenance._payload_sha256(
        cross_version, domain=runtime_provenance.LEGACY_RUNTIME_RECEIPT_DOMAIN
    )
    destination.write_text(
        json.dumps(cross_version, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="tool inventory is incomplete"):
        runtime_provenance.validate_runtime_receipt(destination)

    boolean_alias = copy.deepcopy(legacy)
    boolean_alias["schema_version"] = True
    boolean_alias["payload_sha256"] = runtime_provenance._payload_sha256(
        boolean_alias, domain=runtime_provenance.LEGACY_RUNTIME_RECEIPT_DOMAIN
    )
    destination.write_text(
        json.dumps(boolean_alias, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="identity"):
        runtime_provenance.validate_runtime_receipt(destination)


@pytest.mark.parametrize("mutated_tool", ["catalogue", "browser-egress"])
def test_runtime_receipt_rejects_post_build_tool_mutation(
    tmp_path: Path, mutated_tool: str
) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    _source_manifest(manifest)
    _source_metadata(metadata)
    catalogue, browser_egress, entrypoint = _installed_runtime_files(tmp_path)
    runtime_provenance.build_runtime_receipt(
        manifest,
        metadata,
        destination,
        catalogue_tool=catalogue,
        browser_egress_tool=browser_egress,
        entrypoint=entrypoint,
    )
    changed = catalogue if mutated_tool == "catalogue" else browser_egress
    changed.write_text("changed\n", encoding="utf-8")

    with pytest.raises(ValueError, match="differs from its runtime receipt"):
        runtime_provenance.validate_runtime_receipt(destination)


def test_runtime_receipt_requires_clean_gitlink_matched_source(tmp_path: Path) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    _source_manifest(manifest)
    _source_metadata(metadata)
    value = json.loads(metadata.read_text(encoding="utf-8"))
    value["lab_dirty"] = True
    metadata.write_text(json.dumps(value), encoding="utf-8")
    catalogue, browser_egress, entrypoint = _installed_runtime_files(tmp_path)

    with pytest.raises(ValueError, match="not clean and pinned"):
        runtime_provenance.build_runtime_receipt(
            manifest,
            metadata,
            destination,
            catalogue_tool=catalogue,
            browser_egress_tool=browser_egress,
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


@pytest.mark.parametrize("omitted", sorted(runtime_provenance._REQUIRED_TOOL_SOURCES))
def test_runtime_source_manifest_cannot_omit_an_installed_tool(
    tmp_path: Path, omitted: str
) -> None:
    manifest = tmp_path / "source-files.json"
    _source_manifest(manifest)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value.pop(omitted)
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="source-file inventory is invalid"):
        runtime_provenance._source_file_manifest(manifest)


def test_runtime_receipt_rejects_browser_tool_installation_copy_mismatch(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "source-files.json"
    metadata = tmp_path / "source.json"
    destination = tmp_path / "runtime.json"
    _source_manifest(manifest)
    _source_metadata(metadata)
    catalogue, browser_egress, entrypoint = _installed_runtime_files(tmp_path)
    browser_egress.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")

    with pytest.raises(
        ValueError, match="installed browser-egress qualification tool differs"
    ):
        runtime_provenance.build_runtime_receipt(
            manifest,
            metadata,
            destination,
            catalogue_tool=catalogue,
            browser_egress_tool=browser_egress,
            entrypoint=entrypoint,
        )
