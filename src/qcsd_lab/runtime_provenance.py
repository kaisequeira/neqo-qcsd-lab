"""Build and verify the installed Python surface of QCSD runtime images."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .util import SOURCE_METADATA_KEYS, sha256_file


RUNTIME_RECEIPT_TYPE = "qcsd-python-runtime-implementation"
RUNTIME_RECEIPT_DOMAIN = "qcsd-python-runtime-implementation-v1"
RUNTIME_RECEIPT_SCHEMA_VERSION = 1
DEFAULT_RUNTIME_RECEIPT = Path(
    "/usr/share/qcsd-lab/python-runtime-implementation.json"
)
DEFAULT_CATALOGUE_TOOL = Path("/usr/local/bin/qcsd-build-class-catalogue")
DEFAULT_ENTRYPOINT = Path("/usr/local/bin/qcsd-lab-internal")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_MODULE_PREFIX = "src/qcsd_lab/"
_CATALOGUE_TOOL_SOURCE = "tools/build_class_catalogue.py"
_REQUIRED_CLASS_MODULES = {
    f"{_MODULE_PREFIX}{name}.py"
    for name in (
        "class_acquisition",
        "class_attestation",
        "class_campaigns",
        "class_catalogue",
        "class_cohort",
        "class_evaluation",
        "class_fitting",
        "class_handoff",
        "class_layout",
        "class_pipeline",
        "class_study",
        "class_successor",
    )
}
_RECEIPT_KEYS = {
    "schema_version",
    "artifact_type",
    "domain",
    "source",
    "source_files",
    "installed_modules",
    "installed_tools",
    "installed_entrypoint",
    "payload_sha256",
}


def build_runtime_receipt(
    source_manifest_path: Path,
    source_metadata_path: Path,
    destination: Path = DEFAULT_RUNTIME_RECEIPT,
    *,
    catalogue_tool: Path = DEFAULT_CATALOGUE_TOOL,
    entrypoint: Path = DEFAULT_ENTRYPOINT,
) -> dict[str, Any]:
    """Bind every packaged module and standalone catalogue tool to source bytes."""

    source_files = _source_file_manifest(source_manifest_path)
    source = _source_metadata(source_metadata_path)
    package = _installed_package_root()
    installed_modules: dict[str, dict[str, str]] = {}
    for source_path, source_sha256 in source_files.items():
        if not source_path.startswith(_MODULE_PREFIX):
            continue
        relative = source_path.removeprefix(_MODULE_PREFIX)
        installed = package / relative
        installed_sha256 = _regular_file_sha256(installed, "installed Python module")
        if installed_sha256 != source_sha256:
            raise ValueError(f"installed Python module differs from source: {source_path}")
        installed_modules[source_path] = {
            "path": str(installed),
            "sha256": installed_sha256,
        }
    expected_modules = {
        path for path in source_files if path.startswith(_MODULE_PREFIX)
    }
    if (
        set(installed_modules) != expected_modules
        or expected_modules != _installed_module_inventory(package)
        or not installed_modules
    ):
        raise ValueError("installed Python module inventory is incomplete")
    tool_sha256 = _regular_executable_sha256(catalogue_tool, "class catalogue tool")
    if tool_sha256 != source_files.get(_CATALOGUE_TOOL_SOURCE):
        raise ValueError("installed class catalogue tool differs from source")
    receipt: dict[str, Any] = {
        "schema_version": RUNTIME_RECEIPT_SCHEMA_VERSION,
        "artifact_type": RUNTIME_RECEIPT_TYPE,
        "domain": RUNTIME_RECEIPT_DOMAIN,
        "source": source,
        "source_files": source_files,
        "installed_modules": installed_modules,
        "installed_tools": {
            _CATALOGUE_TOOL_SOURCE: {
                "path": str(catalogue_tool),
                "sha256": tool_sha256,
            }
        },
        "installed_entrypoint": {
            "path": str(entrypoint),
            "sha256": _regular_executable_sha256(
                entrypoint, "installed QCSD entrypoint"
            ),
        },
    }
    receipt["payload_sha256"] = _payload_sha256(receipt)
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    output = Path(destination)
    if output.is_symlink():
        raise ValueError("Python runtime receipt destination cannot be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)
    validate_runtime_receipt(output)
    return receipt


def validate_runtime_receipt(path: Path = DEFAULT_RUNTIME_RECEIPT) -> dict[str, Any]:
    """Re-hash every installed byte named by one runtime receipt."""

    receipt_path = Path(path)
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("Python runtime implementation receipt is unavailable")
    try:
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("Python runtime implementation receipt is invalid") from error
    if (
        not isinstance(value, Mapping)
        or set(value) != _RECEIPT_KEYS
        or value.get("schema_version") != RUNTIME_RECEIPT_SCHEMA_VERSION
        or value.get("artifact_type") != RUNTIME_RECEIPT_TYPE
        or value.get("domain") != RUNTIME_RECEIPT_DOMAIN
        or value.get("payload_sha256") != _payload_sha256(value)
    ):
        raise ValueError("Python runtime implementation receipt identity is invalid")
    source_files = _source_files(value.get("source_files"))
    _validate_source(value.get("source"))
    expected_modules = {
        source for source in source_files if source.startswith(_MODULE_PREFIX)
    }
    if expected_modules != _installed_module_inventory(_installed_package_root()):
        raise ValueError("installed Python module inventory is incomplete")
    modules = _installed_records(
        value.get("installed_modules"),
        expected=expected_modules,
        label="installed Python module",
    )
    tools = _installed_records(
        value.get("installed_tools"),
        expected={_CATALOGUE_TOOL_SOURCE},
        label="installed Python tool",
    )
    entrypoint = _installed_record(
        value.get("installed_entrypoint"), "installed QCSD entrypoint"
    )
    for source_path, record in modules.items():
        if record["sha256"] != source_files[source_path]:
            raise ValueError(f"installed runtime byte differs from source: {source_path}")
        _require_recorded_file(record, source_path)
    for source_path, record in tools.items():
        if record["sha256"] != source_files[source_path]:
            raise ValueError(f"installed runtime byte differs from source: {source_path}")
        _require_recorded_file(record, source_path, executable=True)
    _require_recorded_file(
        entrypoint, "installed QCSD entrypoint", executable=True
    )
    return dict(value)


def _source_file_manifest(path: Path) -> dict[str, str]:
    manifest_path = Path(path)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Python runtime source manifest is unavailable")
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("Python runtime source manifest is invalid") from error
    return _source_files(value)


def _source_files(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("Python runtime source-file inventory is invalid")
    files = dict(value)
    required = {
        ".dockerignore",
        "Dockerfile",
        "pyproject.toml",
        "uv.lock",
        _CATALOGUE_TOOL_SOURCE,
        *_REQUIRED_CLASS_MODULES,
    }
    modules = {path for path in files if path.startswith(_MODULE_PREFIX)}
    if (
        not required.issubset(files)
        or not modules
        or any(
            not isinstance(path, str)
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            for path, digest in files.items()
        )
    ):
        raise ValueError("Python runtime source-file inventory is invalid")
    return files


def _source_metadata(path: Path) -> dict[str, Any]:
    source_path = Path(path)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("Python runtime source metadata is unavailable")
    try:
        value = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("Python runtime source metadata is invalid") from error
    _validate_source(value)
    return dict(value)


def _validate_source(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != SOURCE_METADATA_KEYS:
        raise ValueError("Python runtime source metadata is invalid")
    image_digest = value.get("image_digest")
    if (
        value.get("lab_dirty") is not False
        or value.get("neqo_dirty") is not False
        or value.get("lab_patch_sha256") != _EMPTY_SHA256
        or value.get("neqo_patch_sha256") != _EMPTY_SHA256
        or value.get("neqo_commit") != value.get("neqo_pinned_commit")
        or any(
            not isinstance(value.get(field), str)
            or _COMMIT.fullmatch(str(value[field])) is None
            for field in ("lab_commit", "neqo_commit", "neqo_pinned_commit")
        )
        or (
            image_digest is not None
            and (
                not isinstance(image_digest, str)
                or _IMAGE_DIGEST.fullmatch(image_digest) is None
            )
        )
    ):
        raise ValueError("Python runtime source metadata is not clean and pinned")


def _installed_records(
    value: object,
    *,
    expected: set[str],
    label: str,
) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{label} inventory is incomplete")
    return {key: _installed_record(record, label) for key, record in value.items()}


def _installed_record(value: object, label: str) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"path", "sha256"}
        or not isinstance(value.get("path"), str)
        or not Path(str(value["path"])).is_absolute()
        or not isinstance(value.get("sha256"), str)
        or _DIGEST.fullmatch(str(value["sha256"])) is None
    ):
        raise ValueError(f"{label} receipt is invalid")
    return {"path": str(value["path"]), "sha256": str(value["sha256"])}


def _require_recorded_file(
    record: Mapping[str, str], label: str, *, executable: bool = False
) -> None:
    path = Path(record["path"])
    observed = (
        _regular_executable_sha256(path, label)
        if executable
        else _regular_file_sha256(path, label)
    )
    if observed != record["sha256"]:
        raise ValueError(f"{label} differs from its runtime receipt")


def _regular_file_sha256(path: Path, label: str) -> str:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{label} is not a regular file")
    return sha256_file(candidate)


def _regular_executable_sha256(path: Path, label: str) -> str:
    candidate = Path(path)
    digest = _regular_file_sha256(candidate, label)
    if not os.access(candidate, os.X_OK):
        raise ValueError(f"{label} is not executable")
    return digest


def _installed_package_root() -> Path:
    specification = importlib.util.find_spec("qcsd_lab")
    locations = None if specification is None else specification.submodule_search_locations
    if locations is None:
        raise ValueError("installed qcsd_lab package is unavailable")
    roots = tuple(locations)
    if len(roots) != 1:
        raise ValueError("installed qcsd_lab package root is ambiguous")
    root = Path(roots[0])
    if root.is_symlink() or not root.is_dir():
        raise ValueError("installed qcsd_lab package root is invalid")
    return root


def _installed_module_inventory(root: Path) -> set[str]:
    modules: set[str] = set()
    for path in root.rglob("*.py"):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"installed Python module is not a regular file: {path}")
        modules.add(_MODULE_PREFIX + path.relative_to(root).as_posix())
    return modules


def _payload_sha256(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "payload_sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(RUNTIME_RECEIPT_DOMAIN.encode() + b"\0" + encoded).hexdigest()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source-manifest", required=True, type=Path)
    build.add_argument("--source-metadata", required=True, type=Path)
    build.add_argument("--destination", default=DEFAULT_RUNTIME_RECEIPT, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", default=DEFAULT_RUNTIME_RECEIPT, type=Path)
    arguments = parser.parse_args(argv)
    if arguments.action == "build":
        build_runtime_receipt(
            arguments.source_manifest,
            arguments.source_metadata,
            arguments.destination,
        )
    else:
        validate_runtime_receipt(arguments.receipt)


if __name__ == "__main__":  # pragma: no cover - exercised in image builds.
    main()
