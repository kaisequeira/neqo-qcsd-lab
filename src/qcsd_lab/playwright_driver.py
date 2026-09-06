"""Fail-closed ownership patch for Playwright's pinned Chromium driver.

Playwright normally auto-attaches to and resumes iframe and worker targets.  QCSD
must own those targets while it installs its recursive CDP instrumentation, so the
prepare image applies this narrowly versioned patch once at image-build time.  Live
commands only verify the immutable receipt and installed driver bytes.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import fsync_directory

PLAYWRIGHT_VERSION = "1.57.0"
EXPECTED_CHROMIUM_REVISION = "1200"
EXPECTED_CHROMIUM_VERSION = "143.0.7499.4"
EXPECTED_CHROMIUM_VERSION_OUTPUT = f"Chromium {EXPECTED_CHROMIUM_VERSION}"
SUPPORTED_ARCHITECTURE = "aarch64"
EXPECTED_CHROMIUM_SHA256 = "6f72e258e11d85ec413b1671422c83d65af9f9ddcbc811657a43700b324ce928"
EXPECTED_BROWSERS_JSON_SHA256 = "b509d013de89d621a142818e0937de356fbb0169096922c08581a4f83e463b8e"
CHROMIUM_ARCHIVE_URL = (
    "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1200/"
    "chromium-linux-arm64.zip"
)
CHROMIUM_ARCHIVE_SHA256 = "e73eeb680312e96d4f8fbca589ad42e3fb719178b4bdd8707f9fe796123bf48b"
PLAYWRIGHT_PACKAGE_TREE_DOMAIN = "qcsd-playwright-package-tree-v1"
EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE = {
    "sha256": "416eaaa5ab61707e218d6e62de946c343f823e988327a8ebe41cb675a41ae90b",
    "file_count": 401,
    "total_bytes": 131_856_713,
}
EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE = {
    "sha256": "2a233521c12cfc6612d2ebcb535ab8cf24a5554e36ad1f367097f70bdfbec07e",
    "file_count": 401,
    "total_bytes": 131_857_569,
}
CHROMIUM_DISTRIBUTION_TREE_DOMAIN = "qcsd-chromium-distribution-tree-v1"
EXPECTED_CHROMIUM_DISTRIBUTION_TREE = {
    "sha256": "d5cd88dc445b6d4af2f220552e09f3180d22fed4142164c1b8b595cdecf014b5",
    "file_count": 466,
    "total_bytes": 616_583_533,
}
EXPECTED_PLAYWRIGHT_DRIVER_CONTENT_SHA256 = (
    "f2f774b92c6074dcab28bc5a0afa13b43c70e372057558b7246d4ba168602d51"
)
EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256 = (
    "926b894666e6b5d6dcdb31dc28d581a9cb22eba1f6dc924be74b49402c44e3c3"
)
EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256 = (
    "7194034787b5c1c34ffd88d62cf9969b1510fca7955a0ed7b7c3168f23a8bfb2"
)
CHROMIUM_SHARED_WORKER_PAUSE_FIX_COMMIT = "0606a60db66fc14d6fd76c8d532392b26504b308"
CHROMIUM_SHARED_WORKER_PAUSE_FIX_POSITION = 1_529_406
RECEIPT_SCHEMA_VERSION = 6
RECEIPT_TYPE = "qcsd-playwright-cdp-ownership"
RECEIPT_DOMAIN = "qcsd-playwright-cdp-ownership-v6"
CONTENT_DOMAIN = "qcsd-playwright-cdp-driver-content-v6"
OWNERSHIP_POLICY = "qcsd-conditional-exclusive-recursive-cdp-target-ownership-v6"
OWNERSHIP_MARKER_NAME = "QCSD_EXCLUSIVE_CDP_TARGET_OWNERSHIP"
OWNERSHIP_MARKER_VALUE = "1"
# These are the ambient switches read by the pinned Python/Node driver which can
# replace the local process, alter Chromium launch arguments, or change target,
# navigation, proxy, or service-worker handling.  Chromium itself receives the
# separate exact child environment below.  Build/download-only and diagnostic
# variables which cannot affect this launch path are deliberately not included.
FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES = (
    "NODE_OPTIONS",
    "NODE_PATH",
    "PLAYWRIGHT_NODEJS_PATH",
    "PLAYWRIGHT_NODEJS_PORT",
    "PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK",
    "PLAYWRIGHT_DISABLE_SERVICE_WORKER_CONSOLE",
    "PLAYWRIGHT_DISABLE_SERVICE_WORKER_NETWORK",
    "PLAYWRIGHT_HOST_PLATFORM_OVERRIDE",
    "PLAYWRIGHT_LEGACY_SCREENSHOT",
    "PLAYWRIGHT_SKIP_NAVIGATION_CHECK",
    "PWDEBUG",
    "PW_CHROMIUM_ATTACH_TO_OTHER",
    "SELENIUM_REMOTE_CAPABILITIES",
    "SELENIUM_REMOTE_HEADERS",
    "SELENIUM_REMOTE_URL",
)
CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE = "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
_CHROMIUM_CHILD_ENVIRONMENT_ITEMS = (
    ("HOME", "/nonexistent"),
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    ("TMPDIR", "/tmp"),
    ("TZ", "UTC"),
)
CHROMIUM_CHILD_ENVIRONMENT = dict(_CHROMIUM_CHILD_ENVIRONMENT_ITEMS)
OWNERSHIP_POLICY_RECEIPT = {
    "name": OWNERSHIP_POLICY,
    "activation_environment_variable": OWNERSHIP_MARKER_NAME,
    "activation_value": OWNERSHIP_MARKER_VALUE,
    "inactive_semantics": "native-playwright-unfiltered-auto-attach",
    "driver_start_environment_lock": "held-only-through-sync-playwright-enter",
    "forbidden_driver_environment_variables": list(FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES),
    "chromium_child_environment": dict(_CHROMIUM_CHILD_ENVIRONMENT_ITEMS),
    "shared_worker_pause_fix": {
        "chromium_commit": CHROMIUM_SHARED_WORKER_PAUSE_FIX_COMMIT,
        "chromium_position": CHROMIUM_SHARED_WORKER_PAUSE_FIX_POSITION,
        "required_semantics": "wait-for-debugger-on-start-holds-new-shared-worker",
    },
    "browser_service_containment": {
        "dns_over_https_policy": {"DnsOverHttpsMode": "off"},
        "network_prediction_policy": {"NetworkPredictionOptions": 2},
        "same_approved_origin_speculation_prefetch_required": True,
        "ordinary_playwright_launch": True,
    },
}
DEFAULT_RECEIPT = Path("/usr/share/qcsd-lab/playwright-cdp-ownership.json")
DEFAULT_BROWSER_ROOT = Path("/opt/qcsd-playwright")
DEFAULT_CONFIGURED_EXECUTABLE = Path("/usr/local/bin/qcsd-chromium")
_DRIVER_RELATIVE_ROOT = Path("driver/package/lib/server/chromium")
DEFAULT_RESOLVED_EXECUTABLE = (
    DEFAULT_BROWSER_ROOT
    / f"chromium-{EXPECTED_CHROMIUM_REVISION}"
    / "chrome-linux"
    / "chrome"
)
DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER = Path("/usr/local/libexec/qcsd-chromium-child")
DEFAULT_CHROMIUM_MANAGED_POLICY = Path(
    "/etc/chromium/policies/managed/qcsd-network-prediction.json"
)
DEFAULT_CHROMIUM_ALTERNATE_POLICY_ROOTS = (
    Path("/etc/opt/chrome/policies"),
    Path("/etc/chromium-browser/policies"),
)
CHROMIUM_NETWORK_PREDICTION_ENABLED_CONTROL = 0
CHROMIUM_NETWORK_PREDICTION_NEVER = 2
EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256 = (
    "da91275fe972e3ca89815abfc2abaa6000631ea4f3b79179d1dc02780addef4d"
)
EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256 = (
    "8293900f406510aaf6eb23ae7123d8c7321d91a00c98646671b21f58dbf41526"
)
EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256 = (
    "4566be4f014df0cfd45cf8bdeb4333b341bf4c666139e364992306c12873df03"
)
CHROMIUM_DNS_OVER_HTTPS_MODE = "off"
CHROMIUM_SUBPROCESS_WRAPPER_MODE = 0o555
CHROMIUM_MANAGED_POLICY_MODE = 0o444
DEFAULT_PLAYWRIGHT_PACKAGE_ROOT = Path("/opt/qcsd-venv/lib/python3.11/site-packages/playwright")
DEFAULT_DRIVER_ROOT = DEFAULT_PLAYWRIGHT_PACKAGE_ROOT / _DRIVER_RELATIVE_ROOT
_DIGEST_LENGTH = 64
_ATTACH_EXPRESSION = b"{ autoAttach: true, waitForDebuggerOnStart: true, flatten: true }"
_REPLACEMENT_COUNT = 2
_OWNERSHIP_ENVIRONMENT_LOCK = threading.RLock()
_VALIDATION_CACHE_LOCK = threading.Lock()
_DEFAULT_VALIDATION_CACHE: tuple[int, bytes] | None = None


@dataclass(frozen=True)
class _DriverFileSpec:
    filename: str
    pre_patch_sha256: str
    post_patch_sha256: str
    excluded_target_types: tuple[str, ...]


_FILE_SPECS = (
    _DriverFileSpec(
        filename="crBrowser.js",
        pre_patch_sha256=("c72c8906948a54a3d78049148c53c1bacd9dd54cbe2fce48e4e2ad7d032a03b2"),
        post_patch_sha256=("ec4f6badc590bc3928b8a148c9e6afa2232e34ab779f41e66a9a2803d09315ba"),
        excluded_target_types=("iframe", "worker", "shared_worker", "tab"),
    ),
    _DriverFileSpec(
        filename="crPage.js",
        pre_patch_sha256=("71aab16b0912f23cb9aa3095b8072bfc6fbd6e47e4e13a7be3684b796aa1cd28"),
        post_patch_sha256=("718c618ff2342acba85b88efe4f87d3a0c6ded00a61829409b387f9eebd0a79e"),
        excluded_target_types=("iframe", "worker", "shared_worker"),
    ),
)
_RECEIPT_KEYS = {
    "schema_version",
    "artifact_type",
    "domain",
    "policy",
    "playwright_version",
    "files",
    "browser_manifest",
    "chromium_executable",
    "playwright_package_tree",
    "chromium_distribution_tree",
    "chromium_subprocess_wrapper",
    "chromium_managed_policy",
    "content_sha256",
    "payload_sha256",
}
_BROWSER_MANIFEST_KEYS = {
    "path",
    "sha256",
    "chromium_revision",
    "chromium_version",
    "chromium_headless_shell_revision",
    "chromium_headless_shell_version",
}
_EXECUTABLE_KEYS = {
    "architecture",
    "configured_path",
    "symlink_target",
    "resolved_path",
    "sha256",
    "version_output",
}
_PLAYWRIGHT_TREE_KEYS = {"domain", "root", "pre_patch", "post_patch"}
_CHROMIUM_TREE_KEYS = {
    "domain",
    "root",
    "archive_url",
    "archive_sha256",
    "sha256",
    "file_count",
    "total_bytes",
}
_TREE_IDENTITY_KEYS = {"sha256", "file_count", "total_bytes"}
_RUNTIME_FILE_KEYS = {"path", "sha256", "mode"}
_MANAGED_POLICY_KEYS = _RUNTIME_FILE_KEYS | {
    "managed_directory_file_count",
    "sole_managed_policy",
}
_FILE_RECORD_KEYS = {
    "path",
    "pre_patch_sha256",
    "post_patch_sha256",
    "replacement_count",
    "excluded_target_types",
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _compact_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _payload_sha256(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "payload_sha256"}
    return _sha256(RECEIPT_DOMAIN.encode() + b"\0" + _compact_json(payload))


def _replacement(excluded_target_types: Sequence[str]) -> bytes:
    filters = ", ".join(
        f'{{ type: "{target_type}", exclude: true }}' for target_type in excluded_target_types
    )
    return (
        "{ autoAttach: true, waitForDebuggerOnStart: true, flatten: true, "
        f'...(process.env.{OWNERSHIP_MARKER_NAME} === "{OWNERSHIP_MARKER_VALUE}" ? '
        f"{{ filter: [{filters}, {{}}] }} : {{}}) }}"
    ).encode()


def chromium_child_environment() -> dict[str, str]:
    """Return the complete, fixed environment for a Chromium child process."""

    return dict(_CHROMIUM_CHILD_ENVIRONMENT_ITEMS)


def pinned_chromium_executable_path() -> str:
    """Return the immutable launch path after rejecting an in-process override.

    The configured environment variable is useful as declarative image metadata,
    but it must never be a mutable source of the executable passed to Playwright.
    An absent variable is equivalent to the pinned default; a present value must
    match it byte-for-byte.
    """

    expected = str(DEFAULT_CONFIGURED_EXECUTABLE)
    configured = os.environ.get(CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE)
    if configured not in (None, expected):
        raise ValueError(
            f"{CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE} must be absent or exactly {expected!r}"
        )
    return expected


def _reject_driver_environment_overrides() -> None:
    present = [name for name in FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES if name in os.environ]
    if present:
        raise ValueError(
            "Playwright driver environment overrides are forbidden: " + ", ".join(present)
        )


@contextlib.contextmanager
def playwright_driver_session(
    sync_playwright_factory: Callable[[], Any],
    *,
    exclusive: bool,
) -> Iterator[Any]:
    """Start one driver with the exact ownership marker, then release the lock.

    ``os.environ`` is process-global, so starts are serialized only until the
    Node driver has inherited its environment.  The browser/driver lifetime is
    deliberately outside the lock, allowing acquisition batches to overlap.
    """

    manager: Any
    with _OWNERSHIP_ENVIRONMENT_LOCK:
        _reject_driver_environment_overrides()
        pinned_chromium_executable_path()
        marker_was_present = OWNERSHIP_MARKER_NAME in os.environ
        previous = os.environ.get(OWNERSHIP_MARKER_NAME)
        if previous not in (None, OWNERSHIP_MARKER_VALUE):
            raise ValueError(
                f"{OWNERSHIP_MARKER_NAME} must be absent or exactly {OWNERSHIP_MARKER_VALUE!r}"
            )
        if exclusive:
            os.environ[OWNERSHIP_MARKER_NAME] = OWNERSHIP_MARKER_VALUE
        else:
            os.environ.pop(OWNERSHIP_MARKER_NAME, None)
        try:
            manager = sync_playwright_factory()
            playwright = manager.__enter__()
        finally:
            if marker_was_present:
                assert previous is not None
                os.environ[OWNERSHIP_MARKER_NAME] = previous
            else:
                os.environ.pop(OWNERSHIP_MARKER_NAME, None)

    try:
        yield playwright
    except BaseException:
        if not manager.__exit__(*sys.exc_info()):
            raise
    else:
        manager.__exit__(None, None, None)


def _require_version(installed_version: str | None) -> str:
    if installed_version is None:
        try:
            installed_version = importlib.metadata.version("playwright")
        except importlib.metadata.PackageNotFoundError as error:
            raise ValueError("pinned Playwright distribution is unavailable") from error
    if installed_version != PLAYWRIGHT_VERSION:
        raise ValueError(
            "Playwright driver ownership patch requires exactly "
            f"Playwright {PLAYWRIGHT_VERSION}, found {installed_version}"
        )
    return installed_version


def _installed_driver_root(driver_root: Path | None) -> Path:
    if driver_root is None:
        specification = importlib.util.find_spec("playwright")
        locations = None if specification is None else specification.submodule_search_locations
        if locations is None:
            raise ValueError("installed Playwright package is unavailable")
        roots = tuple(locations)
        if len(roots) != 1:
            raise ValueError("installed Playwright package root is ambiguous")
        driver_root = Path(roots[0]) / _DRIVER_RELATIVE_ROOT
    root = Path(driver_root).absolute()
    try:
        metadata = root.lstat()
    except OSError as error:
        raise ValueError("Playwright Chromium driver root is unavailable") from error
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Playwright Chromium driver root is not a regular directory")
    return root


def _safe_directory(
    path: Path,
    *,
    label: str,
    expected_owner_uid: int,
) -> os.stat_result:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {candidate}") from error
    if candidate.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} is not a regular directory: {candidate}")
    if metadata.st_uid != expected_owner_uid:
        raise ValueError(f"{label} is not owned by uid {expected_owner_uid}: {candidate}")
    if metadata.st_mode & 0o022:
        raise ValueError(f"{label} is group/world-writable: {candidate}")
    return metadata


def _safe_ancestor_chain(
    path: Path,
    *,
    boundary: Path,
    label: str,
    expected_owner_uid: int,
) -> None:
    candidate = Path(path).absolute()
    root = Path(boundary).absolute()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} escapes its trusted root: {candidate}") from error
    current = candidate.parent
    while True:
        _safe_directory(
            current,
            label=f"{label} ancestor",
            expected_owner_uid=expected_owner_uid,
        )
        if current == root:
            break
        if current == current.parent:
            raise ValueError(f"{label} has no trusted ancestor boundary")
        current = current.parent


def _open_regular_file(
    path: Path,
    *,
    label: str,
    expected_owner_uid: int,
) -> tuple[Any, os.stat_result]:
    candidate = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {candidate}") from error
    stream = os.fdopen(descriptor, "rb")
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        stream.close()
        raise ValueError(f"{label} is not a regular file: {candidate}")
    if metadata.st_uid != expected_owner_uid:
        stream.close()
        raise ValueError(f"{label} is not owned by uid {expected_owner_uid}: {candidate}")
    if metadata.st_mode & 0o022:
        stream.close()
        raise ValueError(f"{label} is group/world-writable: {candidate}")
    return stream, metadata


def _regular_file(
    path: Path,
    *,
    label: str,
    expected_owner_uid: int,
) -> tuple[bytes, os.stat_result]:
    stream, metadata = _open_regular_file(
        path,
        label=label,
        expected_owner_uid=expected_owner_uid,
    )
    try:
        content = stream.read()
    except OSError as error:
        raise ValueError(f"{label} cannot be read: {path}") from error
    finally:
        stream.close()
    return content, metadata


def _sha256_regular_file(
    path: Path,
    *,
    label: str,
    expected_owner_uid: int,
) -> tuple[str, os.stat_result]:
    stream, metadata = _open_regular_file(
        path,
        label=label,
        expected_owner_uid=expected_owner_uid,
    )
    digest = hashlib.sha256()
    try:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    except OSError as error:
        raise ValueError(f"{label} cannot be read: {path}") from error
    finally:
        stream.close()
    return digest.hexdigest(), metadata


def _tree_identity(
    root: Path,
    *,
    domain: str,
    label: str,
    expected_owner_uid: int,
) -> dict[str, int | str]:
    tree_root = Path(root).absolute()
    _safe_directory(
        tree_root,
        label=f"{label} root",
        expected_owner_uid=expected_owner_uid,
    )
    _safe_directory(
        tree_root.parent,
        label=f"{label} parent",
        expected_owner_uid=expected_owner_uid,
    )
    records: list[dict[str, int | str]] = []
    try:
        entries = sorted(
            tree_root.rglob("*"),
            key=lambda item: item.relative_to(tree_root).as_posix(),
        )
    except OSError as error:
        raise ValueError(f"{label} cannot be enumerated: {tree_root}") from error
    for entry in entries:
        relative = entry.relative_to(tree_root).as_posix()
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise ValueError(f"{label} entry is unavailable: {entry}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{label} contains a symlink: {entry}")
        if stat.S_ISDIR(metadata.st_mode):
            _safe_directory(
                entry,
                label=f"{label} directory",
                expected_owner_uid=expected_owner_uid,
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} contains a non-regular entry: {entry}")
        digest, current_metadata = _sha256_regular_file(
            entry,
            label=f"{label} file",
            expected_owner_uid=expected_owner_uid,
        )
        records.append({"path": relative, "sha256": digest, "size": current_metadata.st_size})
    canonical = _compact_json(records)
    return {
        "sha256": _sha256(domain.encode() + b"\0" + canonical),
        "file_count": len(records),
        "total_bytes": sum(int(record["size"]) for record in records),
    }


def _require_tree_identity(
    observed: Mapping[str, int | str],
    expected: Mapping[str, int | str],
    *,
    label: str,
) -> None:
    if set(observed) != _TREE_IDENTITY_KEYS or dict(observed) != dict(expected):
        raise ValueError(f"{label} identity differs from the pinned tree")


def _bound_runtime_file(
    path: Path | None,
    *,
    default_path: Path,
    expected_sha256: str,
    expected_mode: int,
    label: str,
    expected_owner_uid: int,
) -> dict[str, object]:
    candidate = default_path if path is None else Path(path).absolute()
    if not candidate.is_absolute():  # pragma: no cover - ``absolute`` is defensive.
        raise ValueError(f"{label} path is not absolute")
    _safe_ancestor_chain(
        candidate,
        boundary=candidate.parent,
        label=label,
        expected_owner_uid=expected_owner_uid,
    )
    content, metadata = _regular_file(
        candidate,
        label=label,
        expected_owner_uid=expected_owner_uid,
    )
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError(f"{label} hash is invalid")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise ValueError(f"{label} mode is invalid")
    return {
        "path": str(candidate),
        "sha256": expected_sha256,
        "mode": f"0o{expected_mode:o}",
    }


def _browser_service_containment_files(
    *,
    subprocess_wrapper: Path | None,
    managed_policy: Path | None,
    expected_owner_uid: int,
    expected_network_prediction_option: int = CHROMIUM_NETWORK_PREDICTION_NEVER,
) -> tuple[dict[str, object], dict[str, object]]:
    wrapper = _bound_runtime_file(
        subprocess_wrapper,
        default_path=DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER,
        expected_sha256=EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256,
        expected_mode=CHROMIUM_SUBPROCESS_WRAPPER_MODE,
        label="Chromium subprocess wrapper",
        expected_owner_uid=expected_owner_uid,
    )
    if expected_network_prediction_option == CHROMIUM_NETWORK_PREDICTION_NEVER:
        policy_sha256 = EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256
    elif (
        expected_network_prediction_option
        == CHROMIUM_NETWORK_PREDICTION_ENABLED_CONTROL
    ):
        policy_sha256 = EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256
    else:
        raise ValueError("Chromium network-prediction policy option is invalid")
    policy = _bound_runtime_file(
        managed_policy,
        default_path=DEFAULT_CHROMIUM_MANAGED_POLICY,
        expected_sha256=policy_sha256,
        expected_mode=CHROMIUM_MANAGED_POLICY_MODE,
        label="Chromium managed policy",
        expected_owner_uid=expected_owner_uid,
    )
    policy_path = Path(str(policy["path"]))
    try:
        policy_value = json.loads(policy_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Chromium managed policy is invalid JSON") from error
    if policy_value != {
        "DnsOverHttpsMode": CHROMIUM_DNS_OVER_HTTPS_MODE,
        "NetworkPredictionOptions": expected_network_prediction_option,
    }:
        raise ValueError("Chromium managed browser-egress policy is invalid")
    try:
        managed_entries = tuple(policy_path.parent.iterdir())
    except OSError as error:
        raise ValueError("Chromium managed-policy directory cannot be enumerated") from error
    if managed_entries != (policy_path,):
        raise ValueError("Chromium managed-policy directory must contain only the pinned policy")
    policy.update(
        {
            "managed_directory_file_count": 1,
            "sole_managed_policy": True,
        }
    )
    return wrapper, policy


def _browser_manifest(
    root: Path,
    *,
    expected_owner_uid: int,
) -> tuple[dict[str, str], bytes]:
    path = root.parents[2] / "browsers.json"
    _safe_ancestor_chain(
        path,
        boundary=root.parents[4],
        label="Playwright browsers.json",
        expected_owner_uid=expected_owner_uid,
    )
    content, _ = _regular_file(
        path,
        label="Playwright browsers.json",
        expected_owner_uid=expected_owner_uid,
    )
    if _sha256(content) != EXPECTED_BROWSERS_JSON_SHA256:
        raise ValueError(
            f"Playwright browsers.json differs from the pinned {PLAYWRIGHT_VERSION} manifest"
        )
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Playwright browsers.json is invalid JSON") from error
    browsers = value.get("browsers") if isinstance(value, Mapping) else None
    if not isinstance(browsers, list):
        raise ValueError(  # noqa: TRY004 - invalid immutable artifact, not a caller type.
            "Playwright browsers.json browser inventory is invalid"
        )
    selected: dict[str, Mapping[str, object]] = {}
    for name in ("chromium", "chromium-headless-shell"):
        matches = [
            browser
            for browser in browsers
            if isinstance(browser, Mapping) and browser.get("name") == name
        ]
        if len(matches) != 1:
            raise ValueError(f"Playwright browsers.json has no unique {name} record")
        selected[name] = matches[0]
    if any(
        browser.get("revision") != EXPECTED_CHROMIUM_REVISION
        or browser.get("browserVersion") != EXPECTED_CHROMIUM_VERSION
        for browser in selected.values()
    ):
        raise ValueError("Playwright Chromium declaration differs from the pinned revision")
    return (
        {
            "path": str(path),
            "sha256": EXPECTED_BROWSERS_JSON_SHA256,
            "chromium_revision": EXPECTED_CHROMIUM_REVISION,
            "chromium_version": EXPECTED_CHROMIUM_VERSION,
            "chromium_headless_shell_revision": EXPECTED_CHROMIUM_REVISION,
            "chromium_headless_shell_version": EXPECTED_CHROMIUM_VERSION,
        },
        content,
    )


def _chromium_executable(
    configured_executable: Path | None,
    *,
    expected_resolved_executable: Path | None,
    subprocess_wrapper: Path | None,
    managed_policy: Path | None,
    machine: str | None,
    expected_owner_uid: int,
    expected_network_prediction_option: int = CHROMIUM_NETWORK_PREDICTION_NEVER,
) -> tuple[
    dict[str, str],
    dict[str, int | str],
    dict[str, object],
    dict[str, object],
]:
    architecture = platform.machine() if machine is None else machine
    if architecture != SUPPORTED_ARCHITECTURE:
        raise ValueError(
            "pinned Playwright Chromium is supported only on "
            f"{SUPPORTED_ARCHITECTURE}; found {architecture}"
        )
    if configured_executable is None:
        configured_executable = Path(pinned_chromium_executable_path())
    configured = Path(configured_executable)
    if not configured.is_absolute():
        raise ValueError("configured Playwright Chromium executable path is not absolute")
    expected_resolved = (
        DEFAULT_RESOLVED_EXECUTABLE
        if expected_resolved_executable is None
        else Path(expected_resolved_executable).absolute()
    )
    try:
        link_metadata = configured.lstat()
    except OSError as error:
        raise ValueError("configured Playwright Chromium executable is unavailable") from error
    if not stat.S_ISLNK(link_metadata.st_mode):
        raise ValueError("configured Playwright Chromium executable is not a symlink")
    if link_metadata.st_uid != expected_owner_uid:
        raise ValueError(
            f"configured Playwright Chromium executable is not owned by uid {expected_owner_uid}"
        )
    _safe_directory(
        configured.parent,
        label="configured Playwright Chromium executable parent",
        expected_owner_uid=expected_owner_uid,
    )
    symlink_target = os.readlink(configured)
    if symlink_target != str(expected_resolved):
        raise ValueError("configured Playwright Chromium symlink target is invalid")
    try:
        resolved = configured.resolve(strict=True)
    except OSError as error:
        raise ValueError("configured Playwright Chromium symlink cannot be resolved") from error
    if resolved != expected_resolved:
        raise ValueError("resolved Playwright Chromium executable path is invalid")
    distribution_root = resolved.parents[1]
    _safe_ancestor_chain(
        resolved,
        boundary=distribution_root,
        label="resolved Playwright Chromium executable",
        expected_owner_uid=expected_owner_uid,
    )
    executable_sha256, metadata = _sha256_regular_file(
        resolved,
        label="resolved Playwright Chromium executable",
        expected_owner_uid=expected_owner_uid,
    )
    if not metadata.st_mode & 0o111:
        raise ValueError("resolved Playwright Chromium executable is not executable")
    expected_sha256 = EXPECTED_CHROMIUM_SHA256
    if executable_sha256 != expected_sha256:
        raise ValueError("resolved Playwright Chromium executable hash is invalid")
    distribution_identity = _tree_identity(
        distribution_root,
        domain=CHROMIUM_DISTRIBUTION_TREE_DOMAIN,
        label="Playwright Chromium distribution",
        expected_owner_uid=expected_owner_uid,
    )
    _require_tree_identity(
        distribution_identity,
        EXPECTED_CHROMIUM_DISTRIBUTION_TREE,
        label="Playwright Chromium distribution",
    )
    try:
        completed = subprocess.run(
            [str(configured), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30.0,
            env=chromium_child_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Playwright Chromium version observation failed") from error
    version_output = completed.stdout.strip()
    if (
        completed.returncode != 0
        or completed.stderr.strip()
        or version_output != EXPECTED_CHROMIUM_VERSION_OUTPUT
    ):
        raise ValueError("Playwright Chromium version observation is invalid")
    wrapper, policy = _browser_service_containment_files(
        subprocess_wrapper=subprocess_wrapper,
        managed_policy=managed_policy,
        expected_owner_uid=expected_owner_uid,
        expected_network_prediction_option=expected_network_prediction_option,
    )
    return (
        {
            "architecture": architecture,
            "configured_path": str(configured),
            "symlink_target": symlink_target,
            "resolved_path": str(resolved),
            "sha256": expected_sha256,
            "version_output": version_output,
        },
        {
            "domain": CHROMIUM_DISTRIBUTION_TREE_DOMAIN,
            "root": str(distribution_root),
            "archive_url": CHROMIUM_ARCHIVE_URL,
            "archive_sha256": CHROMIUM_ARCHIVE_SHA256,
            **distribution_identity,
        },
        wrapper,
        policy,
    )


def _content_sha256(
    *,
    version: str,
    paths: Mapping[str, Path],
    file_sha256s: Mapping[str, str],
    browser_manifest: Mapping[str, str],
    chromium_executable: Mapping[str, str],
    playwright_package_tree: Mapping[str, object],
    chromium_distribution_tree: Mapping[str, object],
    chromium_subprocess_wrapper: Mapping[str, object],
    chromium_managed_policy: Mapping[str, object],
) -> str:
    inventory = {
        "playwright_version": version,
        "files": {
            filename: {"path": str(paths[filename]), "sha256": file_sha256s[filename]}
            for filename in sorted(file_sha256s)
        },
        "browser_manifest": {
            "path": browser_manifest["path"],
            "sha256": browser_manifest["sha256"],
        },
        "chromium_executable": {
            key: chromium_executable[key]
            for key in (
                "architecture",
                "configured_path",
                "symlink_target",
                "resolved_path",
                "sha256",
                "version_output",
            )
        },
        "playwright_package_tree": dict(playwright_package_tree),
        "chromium_distribution_tree": dict(chromium_distribution_tree),
        "chromium_subprocess_wrapper": dict(chromium_subprocess_wrapper),
        "chromium_managed_policy": dict(chromium_managed_policy),
    }
    return _sha256(CONTENT_DOMAIN.encode() + b"\0" + _compact_json(inventory))


def expected_playwright_driver_receipt() -> dict[str, Any]:
    """Return the exact receipt expected at the immutable production paths."""

    paths = {
        specification.filename: DEFAULT_DRIVER_ROOT / specification.filename
        for specification in _FILE_SPECS
    }
    files = {
        specification.filename: {
            "path": str(paths[specification.filename]),
            "pre_patch_sha256": specification.pre_patch_sha256,
            "post_patch_sha256": specification.post_patch_sha256,
            "replacement_count": _REPLACEMENT_COUNT,
            "excluded_target_types": list(specification.excluded_target_types),
        }
        for specification in _FILE_SPECS
    }
    browser_manifest = {
        "path": str(DEFAULT_PLAYWRIGHT_PACKAGE_ROOT / "driver/package/browsers.json"),
        "sha256": EXPECTED_BROWSERS_JSON_SHA256,
        "chromium_revision": EXPECTED_CHROMIUM_REVISION,
        "chromium_version": EXPECTED_CHROMIUM_VERSION,
        "chromium_headless_shell_revision": EXPECTED_CHROMIUM_REVISION,
        "chromium_headless_shell_version": EXPECTED_CHROMIUM_VERSION,
    }
    chromium_executable = {
        "architecture": SUPPORTED_ARCHITECTURE,
        "configured_path": str(DEFAULT_CONFIGURED_EXECUTABLE),
        "symlink_target": str(DEFAULT_RESOLVED_EXECUTABLE),
        "resolved_path": str(DEFAULT_RESOLVED_EXECUTABLE),
        "sha256": EXPECTED_CHROMIUM_SHA256,
        "version_output": EXPECTED_CHROMIUM_VERSION_OUTPUT,
    }
    playwright_package_tree = {
        "domain": PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        "root": str(DEFAULT_PLAYWRIGHT_PACKAGE_ROOT),
        "pre_patch": dict(EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE),
        "post_patch": dict(EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE),
    }
    chromium_distribution_tree = {
        "domain": CHROMIUM_DISTRIBUTION_TREE_DOMAIN,
        "root": str(DEFAULT_RESOLVED_EXECUTABLE.parents[1]),
        "archive_url": CHROMIUM_ARCHIVE_URL,
        "archive_sha256": CHROMIUM_ARCHIVE_SHA256,
        **EXPECTED_CHROMIUM_DISTRIBUTION_TREE,
    }
    chromium_subprocess_wrapper = {
        "path": str(DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER),
        "sha256": EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256,
        "mode": f"0o{CHROMIUM_SUBPROCESS_WRAPPER_MODE:o}",
    }
    chromium_managed_policy = {
        "path": str(DEFAULT_CHROMIUM_MANAGED_POLICY),
        "sha256": EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256,
        "mode": f"0o{CHROMIUM_MANAGED_POLICY_MODE:o}",
        "managed_directory_file_count": 1,
        "sole_managed_policy": True,
    }
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "domain": RECEIPT_DOMAIN,
        "policy": json.loads(_compact_json(OWNERSHIP_POLICY_RECEIPT)),
        "playwright_version": PLAYWRIGHT_VERSION,
        "files": files,
        "browser_manifest": browser_manifest,
        "chromium_executable": chromium_executable,
        "playwright_package_tree": playwright_package_tree,
        "chromium_distribution_tree": chromium_distribution_tree,
        "chromium_subprocess_wrapper": chromium_subprocess_wrapper,
        "chromium_managed_policy": chromium_managed_policy,
        "content_sha256": _content_sha256(
            version=PLAYWRIGHT_VERSION,
            paths=paths,
            file_sha256s={
                specification.filename: specification.post_patch_sha256
                for specification in _FILE_SPECS
            },
            browser_manifest=browser_manifest,
            chromium_executable=chromium_executable,
            playwright_package_tree=playwright_package_tree,
            chromium_distribution_tree=chromium_distribution_tree,
            chromium_subprocess_wrapper=chromium_subprocess_wrapper,
            chromium_managed_policy=chromium_managed_policy,
        ),
    }
    receipt["payload_sha256"] = _payload_sha256(receipt)
    return receipt


_EXPECTED_DEFAULT_RECEIPT = expected_playwright_driver_receipt()
if (
    _EXPECTED_DEFAULT_RECEIPT["content_sha256"] != EXPECTED_PLAYWRIGHT_DRIVER_CONTENT_SHA256
    or _EXPECTED_DEFAULT_RECEIPT["payload_sha256"] != EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256
    or _sha256(_canonical_json(_EXPECTED_DEFAULT_RECEIPT))
    != EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256
):  # pragma: no cover - a source-constant consistency invariant.
    raise RuntimeError("default Playwright driver receipt constants are inconsistent")
EXPECTED_PLAYWRIGHT_DRIVER_BINDING = {
    "receipt_sha256": EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
    "payload_sha256": EXPECTED_PLAYWRIGHT_DRIVER_PAYLOAD_SHA256,
    "content_sha256": EXPECTED_PLAYWRIGHT_DRIVER_CONTENT_SHA256,
    "policy": json.loads(_compact_json(OWNERSHIP_POLICY_RECEIPT)),
    "browsers_json_sha256": EXPECTED_BROWSERS_JSON_SHA256,
    "chromium_executable_sha256": EXPECTED_CHROMIUM_SHA256,
}


def expected_browser_tool_identity() -> dict[str, Any]:
    """Return the exact browser identity permitted in acquisition evidence."""

    return {
        "schema_version": 1,
        "name": "playwright-chromium",
        "playwright_version": PLAYWRIGHT_VERSION,
        "chromium_revision": EXPECTED_CHROMIUM_REVISION,
        "chromium_version": EXPECTED_CHROMIUM_VERSION,
        "configured_executable_path": str(DEFAULT_CONFIGURED_EXECUTABLE),
        "playwright_driver": json.loads(_compact_json(EXPECTED_PLAYWRIGHT_DRIVER_BINDING)),
    }


def _atomic_replace(path: Path, value: bytes, metadata: os.stat_result) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}.qcsd-playwright-",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), stat.S_IMODE(metadata.st_mode))
            if output.fileno() >= 0 and (
                metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid()
            ):
                os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
        temporary = None
        fsync_directory(path.parent)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _unlink_if_identity(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) != identity:
        raise RuntimeError(f"refusing to remove replaced transaction output: {path}")
    path.unlink()
    fsync_directory(path.parent)


def _durable_readonly_create(
    path: Path,
    value: bytes,
    *,
    owner_uid: int,
) -> tuple[int, int]:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Playwright ownership receipt is create-only: {destination}")
    parent = destination.parent
    _safe_directory(
        parent,
        label="Playwright ownership receipt parent",
        expected_owner_uid=owner_uid,
    )
    temporary: Path | None = None
    published_identity: tuple[int, int] | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=parent,
            prefix=f".{destination.name}.qcsd-playwright-",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o444)
            output_metadata = os.fstat(output.fileno())
            if output_metadata.st_uid != owner_uid:
                raise ValueError(f"Playwright ownership receipt cannot be owned by uid {owner_uid}")
            published_identity = (output_metadata.st_dev, output_metadata.st_ino)
        os.link(temporary, destination)
        fsync_directory(parent)
        return published_identity
    except Exception:
        if published_identity is not None and destination.exists():
            _unlink_if_identity(destination, published_identity)
        raise
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def patch_playwright_driver(
    receipt_path: Path = DEFAULT_RECEIPT,
    *,
    driver_root: Path | None = None,
    installed_version: str | None = None,
    configured_executable: Path | None = None,
    expected_resolved_executable: Path | None = None,
    subprocess_wrapper: Path | None = None,
    managed_policy: Path | None = None,
    machine: str | None = None,
    expected_owner_uid: int = 0,
) -> dict[str, Any]:
    """Apply the exact pinned patch once and publish its create-only receipt."""

    if os.geteuid() != expected_owner_uid:
        raise ValueError(f"Playwright driver patch must run as uid {expected_owner_uid}")
    destination = Path(receipt_path).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Playwright ownership receipt is create-only: {destination}")
    _safe_directory(
        destination.parent,
        label="Playwright ownership receipt parent",
        expected_owner_uid=expected_owner_uid,
    )
    version = _require_version(installed_version)
    root = _installed_driver_root(driver_root)
    package_root = root.parents[4]
    pre_patch_tree_identity = _tree_identity(
        package_root,
        domain=PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        label="Playwright package",
        expected_owner_uid=expected_owner_uid,
    )
    _require_tree_identity(
        pre_patch_tree_identity,
        EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE,
        label="Playwright pre-patch package",
    )
    browser_manifest, _ = _browser_manifest(
        root,
        expected_owner_uid=expected_owner_uid,
    )
    (
        chromium_executable,
        chromium_distribution_tree,
        chromium_subprocess_wrapper,
        chromium_managed_policy,
    ) = _chromium_executable(
        configured_executable,
        expected_resolved_executable=expected_resolved_executable,
        subprocess_wrapper=subprocess_wrapper,
        managed_policy=managed_policy,
        machine=machine,
        expected_owner_uid=expected_owner_uid,
    )
    originals: dict[str, bytes] = {}
    patched: dict[str, bytes] = {}
    metadata: dict[str, os.stat_result] = {}
    paths: dict[str, Path] = {}
    for specification in _FILE_SPECS:
        path = root / specification.filename
        source, source_metadata = _regular_file(
            path,
            label=f"Playwright {specification.filename}",
            expected_owner_uid=expected_owner_uid,
        )
        replacement = _replacement(specification.excluded_target_types)
        if (
            _sha256(source) != specification.pre_patch_sha256
            or source.count(_ATTACH_EXPRESSION) != _REPLACEMENT_COUNT
            or replacement in source
        ):
            raise ValueError(
                f"Playwright {specification.filename} is not the exact unpatched "
                f"{PLAYWRIGHT_VERSION} preimage"
            )
        result = source.replace(_ATTACH_EXPRESSION, replacement)
        if (
            _sha256(result) != specification.post_patch_sha256
            or result.count(_ATTACH_EXPRESSION) != 0
            or result.count(replacement) != _REPLACEMENT_COUNT
        ):
            raise ValueError(
                f"Playwright {specification.filename} patch output differs from policy"
            )
        paths[specification.filename] = path
        originals[specification.filename] = source
        patched[specification.filename] = result
        metadata[specification.filename] = source_metadata

    replaced: list[str] = []
    receipt_identity: tuple[int, int] | None = None
    try:
        for specification in _FILE_SPECS:
            filename = specification.filename
            current, _ = _regular_file(
                paths[filename],
                label=f"Playwright {filename}",
                expected_owner_uid=expected_owner_uid,
            )
            if current != originals[filename]:
                raise ValueError(f"Playwright {filename} changed during patch preflight")
            replaced.append(filename)
            _atomic_replace(paths[filename], patched[filename], metadata[filename])

        post_patch_tree_identity = _tree_identity(
            package_root,
            domain=PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
            label="Playwright package",
            expected_owner_uid=expected_owner_uid,
        )
        _require_tree_identity(
            post_patch_tree_identity,
            EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE,
            label="Playwright post-patch package",
        )
        playwright_package_tree = {
            "domain": PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
            "root": str(package_root),
            "pre_patch": dict(EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE),
            "post_patch": dict(post_patch_tree_identity),
        }

        files = {
            specification.filename: {
                "path": str(paths[specification.filename]),
                "pre_patch_sha256": specification.pre_patch_sha256,
                "post_patch_sha256": specification.post_patch_sha256,
                "replacement_count": _REPLACEMENT_COUNT,
                "excluded_target_types": list(specification.excluded_target_types),
            }
            for specification in _FILE_SPECS
        }
        receipt: dict[str, Any] = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "artifact_type": RECEIPT_TYPE,
            "domain": RECEIPT_DOMAIN,
            "policy": OWNERSHIP_POLICY_RECEIPT,
            "playwright_version": version,
            "files": files,
            "browser_manifest": browser_manifest,
            "chromium_executable": chromium_executable,
            "playwright_package_tree": playwright_package_tree,
            "chromium_distribution_tree": chromium_distribution_tree,
            "chromium_subprocess_wrapper": chromium_subprocess_wrapper,
            "chromium_managed_policy": chromium_managed_policy,
            "content_sha256": _content_sha256(
                version=version,
                paths=paths,
                file_sha256s={filename: _sha256(content) for filename, content in patched.items()},
                browser_manifest=browser_manifest,
                chromium_executable=chromium_executable,
                playwright_package_tree=playwright_package_tree,
                chromium_distribution_tree=chromium_distribution_tree,
                chromium_subprocess_wrapper=chromium_subprocess_wrapper,
                chromium_managed_policy=chromium_managed_policy,
            ),
        }
        receipt["payload_sha256"] = _payload_sha256(receipt)
        receipt_identity = _durable_readonly_create(
            destination,
            _canonical_json(receipt),
            owner_uid=expected_owner_uid,
        )
        return validate_playwright_driver(
            destination,
            driver_root=root,
            installed_version=version,
            configured_executable=Path(chromium_executable["configured_path"]),
            expected_resolved_executable=Path(chromium_executable["resolved_path"]),
            subprocess_wrapper=Path(chromium_subprocess_wrapper["path"]),
            managed_policy=Path(chromium_managed_policy["path"]),
            machine=chromium_executable["architecture"],
            expected_owner_uid=expected_owner_uid,
        )
    except Exception:
        try:
            if receipt_identity is not None:
                _unlink_if_identity(destination, receipt_identity)
        finally:
            for filename in reversed(replaced):
                _atomic_replace(paths[filename], originals[filename], metadata[filename])
        raise


def validate_playwright_driver(
    receipt_path: Path = DEFAULT_RECEIPT,
    *,
    driver_root: Path | None = None,
    installed_version: str | None = None,
    configured_executable: Path | None = None,
    expected_resolved_executable: Path | None = None,
    subprocess_wrapper: Path | None = None,
    managed_policy: Path | None = None,
    machine: str | None = None,
    expected_owner_uid: int = 0,
) -> dict[str, Any]:
    """Verify the receipt, package version, ownership policy, and patched bytes."""

    version = _require_version(installed_version)
    root = _installed_driver_root(driver_root)
    package_root = root.parents[4]
    post_patch_tree_identity = _tree_identity(
        package_root,
        domain=PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        label="Playwright package",
        expected_owner_uid=expected_owner_uid,
    )
    _require_tree_identity(
        post_patch_tree_identity,
        EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE,
        label="Playwright post-patch package",
    )
    playwright_package_tree = {
        "domain": PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        "root": str(package_root),
        "pre_patch": dict(EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE),
        "post_patch": dict(post_patch_tree_identity),
    }
    browser_manifest, _ = _browser_manifest(
        root,
        expected_owner_uid=expected_owner_uid,
    )
    (
        chromium_executable,
        chromium_distribution_tree,
        chromium_subprocess_wrapper,
        chromium_managed_policy,
    ) = _chromium_executable(
        configured_executable,
        expected_resolved_executable=expected_resolved_executable,
        subprocess_wrapper=subprocess_wrapper,
        managed_policy=managed_policy,
        machine=machine,
        expected_owner_uid=expected_owner_uid,
    )
    destination = Path(receipt_path).absolute()
    _safe_directory(
        destination.parent,
        label="Playwright ownership receipt parent",
        expected_owner_uid=expected_owner_uid,
    )
    raw, receipt_metadata = _regular_file(
        destination,
        label="Playwright ownership receipt",
        expected_owner_uid=expected_owner_uid,
    )
    if receipt_metadata.st_mode & 0o222:
        raise ValueError("Playwright ownership receipt is writable")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Playwright ownership receipt is invalid JSON") from error
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_KEYS:
        raise ValueError("Playwright ownership receipt structure is invalid")
    if raw != _canonical_json(value):
        raise ValueError("Playwright ownership receipt is not canonical JSON")
    if (
        value.get("schema_version") != RECEIPT_SCHEMA_VERSION
        or value.get("artifact_type") != RECEIPT_TYPE
        or value.get("domain") != RECEIPT_DOMAIN
        or value.get("policy") != OWNERSHIP_POLICY_RECEIPT
        or value.get("playwright_version") != version
        or value.get("browser_manifest") != browser_manifest
        or value.get("chromium_executable") != chromium_executable
        or value.get("playwright_package_tree") != playwright_package_tree
        or value.get("chromium_distribution_tree") != chromium_distribution_tree
        or value.get("chromium_subprocess_wrapper") != chromium_subprocess_wrapper
        or value.get("chromium_managed_policy") != chromium_managed_policy
        or value.get("payload_sha256") != _payload_sha256(value)
    ):
        raise ValueError("Playwright ownership receipt identity is invalid")

    recorded_manifest = value.get("browser_manifest")
    recorded_executable = value.get("chromium_executable")
    recorded_playwright_tree = value.get("playwright_package_tree")
    recorded_chromium_tree = value.get("chromium_distribution_tree")
    recorded_subprocess_wrapper = value.get("chromium_subprocess_wrapper")
    recorded_managed_policy = value.get("chromium_managed_policy")
    if (
        not isinstance(recorded_manifest, Mapping)
        or set(recorded_manifest) != _BROWSER_MANIFEST_KEYS
        or not isinstance(recorded_executable, Mapping)
        or set(recorded_executable) != _EXECUTABLE_KEYS
        or not isinstance(recorded_playwright_tree, Mapping)
        or set(recorded_playwright_tree) != _PLAYWRIGHT_TREE_KEYS
        or not isinstance(recorded_playwright_tree.get("pre_patch"), Mapping)
        or set(recorded_playwright_tree["pre_patch"]) != _TREE_IDENTITY_KEYS
        or not isinstance(recorded_playwright_tree.get("post_patch"), Mapping)
        or set(recorded_playwright_tree["post_patch"]) != _TREE_IDENTITY_KEYS
        or not isinstance(recorded_chromium_tree, Mapping)
        or set(recorded_chromium_tree) != _CHROMIUM_TREE_KEYS
        or not isinstance(recorded_subprocess_wrapper, Mapping)
        or set(recorded_subprocess_wrapper) != _RUNTIME_FILE_KEYS
        or not isinstance(recorded_managed_policy, Mapping)
        or set(recorded_managed_policy) != _MANAGED_POLICY_KEYS
    ):
        raise ValueError("Playwright browser runtime receipt binding is invalid")
    records = value.get("files")
    if not isinstance(records, Mapping) or set(records) != {
        specification.filename for specification in _FILE_SPECS
    }:
        raise ValueError("Playwright ownership receipt file inventory is invalid")
    paths: dict[str, Path] = {}
    contents: dict[str, bytes] = {}
    for specification in _FILE_SPECS:
        filename = specification.filename
        record = records.get(filename)
        expected_path = root / filename
        if (
            not isinstance(record, Mapping)
            or set(record) != _FILE_RECORD_KEYS
            or record.get("path") != str(expected_path)
            or record.get("pre_patch_sha256") != specification.pre_patch_sha256
            or record.get("post_patch_sha256") != specification.post_patch_sha256
            or record.get("replacement_count") != _REPLACEMENT_COUNT
            or record.get("excluded_target_types") != list(specification.excluded_target_types)
        ):
            raise ValueError(f"Playwright {filename} receipt binding is invalid")
        content, _ = _regular_file(
            expected_path,
            label=f"Playwright {filename}",
            expected_owner_uid=expected_owner_uid,
        )
        replacement = _replacement(specification.excluded_target_types)
        if (
            _sha256(content) != specification.post_patch_sha256
            or content.count(_ATTACH_EXPRESSION) != 0
            or content.count(replacement) != _REPLACEMENT_COUNT
        ):
            raise ValueError(f"Playwright {filename} patched content is invalid")
        paths[filename] = expected_path
        contents[filename] = content
    content_sha256 = value.get("content_sha256")
    if (
        not isinstance(content_sha256, str)
        or len(content_sha256) != _DIGEST_LENGTH
        or content_sha256
        != _content_sha256(
            version=version,
            paths=paths,
            file_sha256s={filename: _sha256(content) for filename, content in contents.items()},
            browser_manifest=browser_manifest,
            chromium_executable=chromium_executable,
            playwright_package_tree=playwright_package_tree,
            chromium_distribution_tree=chromium_distribution_tree,
            chromium_subprocess_wrapper=chromium_subprocess_wrapper,
            chromium_managed_policy=chromium_managed_policy,
        )
    ):
        raise ValueError("Playwright ownership receipt content hash is invalid")
    return dict(value)


def _require_effectively_readonly(path: Path, *, label: str) -> None:
    try:
        path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {path}") from error
    try:
        writable = os.access(path, os.W_OK, effective_ids=True)
    except (NotImplementedError, TypeError):  # pragma: no cover - Linux supports this.
        writable = os.access(path, os.W_OK)
    if writable:
        raise ValueError(f"{label} is writable by the runtime process: {path}")


def _require_effectively_readonly_ancestors(
    path: Path,
    *,
    label: str,
    expected_owner_uid: int = 0,
) -> None:
    current = Path(path).absolute().parent
    while True:
        _safe_directory(
            current,
            label=f"{label} ancestor",
            expected_owner_uid=expected_owner_uid,
        )
        _require_effectively_readonly(current, label=f"{label} ancestor")
        if current == current.parent:
            return
        current = current.parent


def _require_default_runtime_immutability() -> int:
    effective_uid = os.geteuid()
    if effective_uid == 0:
        return effective_uid
    for path, label in (
        (DEFAULT_PLAYWRIGHT_PACKAGE_ROOT, "Playwright package"),
        (DEFAULT_RESOLVED_EXECUTABLE.parents[1], "Playwright Chromium distribution"),
        (DEFAULT_RECEIPT, "Playwright receipt"),
        (DEFAULT_CONFIGURED_EXECUTABLE, "configured Chromium executable"),
        (DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER, "Chromium subprocess wrapper"),
        (DEFAULT_CHROMIUM_MANAGED_POLICY, "Chromium managed policy"),
    ):
        _require_effectively_readonly_ancestors(path, label=label)
    for root, label in (
        (DEFAULT_PLAYWRIGHT_PACKAGE_ROOT, "Playwright package"),
        (DEFAULT_RESOLVED_EXECUTABLE.parents[1], "Playwright Chromium distribution"),
    ):
        _require_effectively_readonly(root.parent, label=f"{label} parent")
        _require_effectively_readonly(root, label=f"{label} root")
        try:
            entries = root.rglob("*")
            for entry in entries:
                _require_effectively_readonly(entry, label=f"{label} entry")
        except OSError as error:
            raise ValueError(f"{label} immutability cannot be established") from error
    for path, label in (
        (DEFAULT_RECEIPT.parent, "Playwright receipt parent"),
        (DEFAULT_RECEIPT, "Playwright receipt"),
        (DEFAULT_CONFIGURED_EXECUTABLE.parent, "configured Chromium parent"),
        (DEFAULT_CONFIGURED_EXECUTABLE, "configured Chromium executable"),
        (DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER.parent, "Chromium subprocess wrapper parent"),
        (DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER, "Chromium subprocess wrapper"),
        (DEFAULT_CHROMIUM_MANAGED_POLICY.parent, "Chromium managed policy parent"),
        (DEFAULT_CHROMIUM_MANAGED_POLICY, "Chromium managed policy"),
    ):
        _require_effectively_readonly(path, label=label)
    return effective_uid


def _runtime_policy_directory_inventory(
    *,
    managed_policy: Path | None = None,
    expected_owner_uid: int = 0,
    alternate_policy_roots: Sequence[Path] | None = None,
) -> list[dict[str, object]]:
    """Reject every unbound Chromium policy root consulted by this build."""

    managed_policy = (
        DEFAULT_CHROMIUM_MANAGED_POLICY
        if managed_policy is None
        else Path(managed_policy).absolute()
    )
    managed = managed_policy.parent
    recommended = managed.parent / "recommended"
    _safe_directory(
        managed,
        label="Chromium managed-policy directory",
        expected_owner_uid=expected_owner_uid,
    )
    try:
        managed_entries = tuple(managed.iterdir())
    except OSError as error:
        raise ValueError("Chromium managed-policy directory cannot be read") from error
    if len(managed_entries) != 1 or managed_entries[0] != managed_policy:
        raise ValueError(
            "Chromium managed-policy directory must contain only the bound policy"
        )
    _regular_file(
        managed_policy,
        label="Chromium managed policy",
        expected_owner_uid=expected_owner_uid,
    )
    _safe_directory(
        recommended,
        label="Chromium recommended-policy directory",
        expected_owner_uid=expected_owner_uid,
    )
    if tuple(recommended.iterdir()):
        raise ValueError("Chromium recommended-policy directory must be empty")
    inventory: list[dict[str, object]] = [
        {
            "path": str(managed),
            "state": "sole-managed-policy",
            "file_count": 1,
        },
        {
            "path": str(recommended),
            "state": "empty-directory",
            "file_count": 0,
        },
    ]
    alternate_roots = (
        tuple(Path(path).absolute() for path in alternate_policy_roots)
        if alternate_policy_roots is not None
        else (
            DEFAULT_CHROMIUM_ALTERNATE_POLICY_ROOTS
            if managed_policy == DEFAULT_CHROMIUM_MANAGED_POLICY
            else ()
        )
    )
    for path in alternate_roots:
        if path.exists() or path.is_symlink():
            raise ValueError(f"unbranded Chromium alternate policy root must be absent: {path}")
        inventory.append({"path": str(path), "state": "absent", "file_count": 0})
    return inventory


def validate_qualification_playwright_driver_once(
    *, expected_network_prediction_option: int
) -> dict[str, Any]:
    """Validate a production driver with one exact qualification policy mount.

    Value 2 is the immutable production policy.  Value 0 is accepted only by
    this qualification-named API: the signed production ownership receipt is
    still checked byte-for-byte, while the currently mounted managed policy is
    independently required to be the exact read-only positive-control file.
    """

    if expected_network_prediction_option == CHROMIUM_NETWORK_PREDICTION_NEVER:
        receipt = validate_default_playwright_driver_once()
        active_policy = dict(receipt["chromium_managed_policy"])
    elif (
        expected_network_prediction_option
        == CHROMIUM_NETWORK_PREDICTION_ENABLED_CONTROL
    ):
        _reject_driver_environment_overrides()
        pinned_chromium_executable_path()
        version = _require_version(None)
        root = _installed_driver_root(None)
        package_root = root.parents[4]
        _require_tree_identity(
            _tree_identity(
                package_root,
                domain=PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
                label="Playwright package",
                expected_owner_uid=0,
            ),
            EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE,
            label="Playwright post-patch package",
        )
        browser_manifest, _ = _browser_manifest(root, expected_owner_uid=0)
        (
            executable,
            distribution,
            wrapper,
            active_policy,
        ) = _chromium_executable(
            None,
            expected_resolved_executable=None,
            subprocess_wrapper=None,
            managed_policy=None,
            machine=None,
            expected_owner_uid=0,
            expected_network_prediction_option=expected_network_prediction_option,
        )
        expected_receipt = expected_playwright_driver_receipt()
        raw, metadata = _regular_file(
            DEFAULT_RECEIPT,
            label="Playwright ownership receipt",
            expected_owner_uid=0,
        )
        if (
            metadata.st_mode & 0o222
            or raw != _canonical_json(expected_receipt)
            or _sha256(raw) != EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256
        ):
            raise ValueError("Playwright production receipt is invalid under control policy")
        for specification in _FILE_SPECS:
            content, _ = _regular_file(
                root / specification.filename,
                label=f"Playwright {specification.filename}",
                expected_owner_uid=0,
            )
            replacement = _replacement(specification.excluded_target_types)
            if (
                _sha256(content) != specification.post_patch_sha256
                or content.count(_ATTACH_EXPRESSION) != 0
                or content.count(replacement) != _REPLACEMENT_COUNT
            ):
                raise ValueError("Playwright patched driver differs under control policy")
        if (
            version != PLAYWRIGHT_VERSION
            or browser_manifest != expected_receipt["browser_manifest"]
            or executable != expected_receipt["chromium_executable"]
            or distribution != expected_receipt["chromium_distribution_tree"]
            or wrapper != expected_receipt["chromium_subprocess_wrapper"]
        ):
            raise ValueError("Playwright browser identity differs under control policy")
        _require_default_runtime_immutability()
        receipt = expected_receipt
    else:
        raise ValueError("qualification network-prediction option must be exactly 0 or 2")

    inventory = _runtime_policy_directory_inventory()
    return {
        "schema_version": 1,
        "artifact_type": "qcsd-playwright-qualification-runtime",
        "production_receipt_sha256": EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
        "production_receipt_payload_sha256": receipt["payload_sha256"],
        "active_managed_policy": active_policy,
        "dns_over_https_mode": CHROMIUM_DNS_OVER_HTTPS_MODE,
        "network_prediction_options": expected_network_prediction_option,
        "semantics": (
            "never-predict"
            if expected_network_prediction_option == CHROMIUM_NETWORK_PREDICTION_NEVER
            else "predict-on-any-connection-qualification-control"
        ),
        "policy_directory_inventory": inventory,
        "qualification_only_policy_substitution": (
            expected_network_prediction_option
            == CHROMIUM_NETWORK_PREDICTION_ENABLED_CONTROL
        ),
    }


def validate_default_playwright_driver_once() -> dict[str, Any]:
    """Validate and cache only the effectively immutable production layout."""

    global _DEFAULT_VALIDATION_CACHE
    with _VALIDATION_CACHE_LOCK:
        # This check deliberately precedes the cache branch.  A caller cannot
        # validate once and then redirect a later browser launch through a
        # process-local environment mutation.
        pinned_chromium_executable_path()
        # Chromium consults every policy root independently.  Recheck the
        # complete directory inventory before the cache branch so a policy
        # introduced after initial admission cannot affect a later launch.
        _runtime_policy_directory_inventory()
        effective_uid = os.geteuid()
        if (
            _DEFAULT_VALIDATION_CACHE is not None
            and _DEFAULT_VALIDATION_CACHE[0] == effective_uid
            and effective_uid != 0
        ):
            return json.loads(_DEFAULT_VALIDATION_CACHE[1])

        receipt = validate_playwright_driver()
        expected = expected_playwright_driver_receipt()
        if receipt != expected:
            raise ValueError("Playwright driver receipt is not the exact production receipt")
        receipt_sha256, _ = _sha256_regular_file(
            DEFAULT_RECEIPT,
            label="Playwright ownership receipt",
            expected_owner_uid=0,
        )
        if receipt_sha256 != EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256:
            raise ValueError("Playwright driver receipt file hash is not the production hash")
        effective_uid = _require_default_runtime_immutability()
        canonical = _canonical_json(receipt)
        if effective_uid != 0:
            _DEFAULT_VALIDATION_CACHE = (effective_uid, canonical)
        else:
            _DEFAULT_VALIDATION_CACHE = None
        return json.loads(canonical)


def reset_playwright_driver_validation_cache() -> None:
    """Clear the process-local validation cache (used by isolated tests)."""

    global _DEFAULT_VALIDATION_CACHE
    with _VALIDATION_CACHE_LOCK:
        _DEFAULT_VALIDATION_CACHE = None


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("patch")
    commands.add_parser("verify")
    arguments = parser.parse_args(argv)
    if arguments.action == "patch":
        patch_playwright_driver()
    else:
        validate_playwright_driver()


if __name__ == "__main__":  # pragma: no cover - exercised in image builds.
    main()
