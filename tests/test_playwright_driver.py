from __future__ import annotations

import copy
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from qcsd_lab import playwright_driver


@pytest.fixture(autouse=True)
def _reset_validation_cache():
    playwright_driver.reset_playwright_driver_validation_cache()
    yield
    playwright_driver.reset_playwright_driver_validation_cache()


@dataclass(frozen=True)
class DriverFixture:
    package_root: Path
    driver_root: Path
    distribution_root: Path
    receipt: Path
    configured_executable: Path
    resolved_executable: Path
    subprocess_wrapper: Path
    managed_policy: Path
    originals: dict[str, bytes]
    patched: dict[str, bytes]

    @property
    def arguments(self) -> dict[str, object]:
        return {
            "driver_root": self.driver_root,
            "installed_version": playwright_driver.PLAYWRIGHT_VERSION,
            "configured_executable": self.configured_executable,
            "expected_resolved_executable": self.resolved_executable,
            "subprocess_wrapper": self.subprocess_wrapper,
            "managed_policy": self.managed_policy,
            "machine": playwright_driver.SUPPORTED_ARCHITECTURE,
            "expected_owner_uid": os.geteuid(),
        }


@pytest.fixture
def driver_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DriverFixture:
    package_root = tmp_path / "site-packages/playwright"
    driver_root = package_root / "driver/package/lib/server/chromium"
    driver_root.mkdir(parents=True)

    specifications = []
    originals: dict[str, bytes] = {}
    patched: dict[str, bytes] = {}
    for filename, excluded in (
        ("crBrowser.js", ("iframe", "worker", "shared_worker", "tab")),
        ("crPage.js", ("iframe", "worker", "shared_worker")),
    ):
        source = (
            f"// {filename}\nfirst(".encode()
            + playwright_driver._ATTACH_EXPRESSION
            + b");\nsecond("
            + playwright_driver._ATTACH_EXPRESSION
            + b");\n"
        )
        result = source.replace(
            playwright_driver._ATTACH_EXPRESSION,
            playwright_driver._replacement(excluded),
        )
        specifications.append(
            playwright_driver._DriverFileSpec(
                filename=filename,
                pre_patch_sha256=playwright_driver._sha256(source),
                post_patch_sha256=playwright_driver._sha256(result),
                excluded_target_types=excluded,
            )
        )
        (driver_root / filename).write_bytes(source)
        originals[filename] = source
        patched[filename] = result
    monkeypatch.setattr(playwright_driver, "_FILE_SPECS", tuple(specifications))

    manifest = package_root / "driver/package/browsers.json"
    manifest_value = {
        "browsers": [
            {
                "name": "chromium",
                "revision": playwright_driver.EXPECTED_CHROMIUM_REVISION,
                "installByDefault": True,
                "browserVersion": playwright_driver.EXPECTED_CHROMIUM_VERSION,
            },
            {
                "name": "chromium-headless-shell",
                "revision": playwright_driver.EXPECTED_CHROMIUM_REVISION,
                "installByDefault": True,
                "browserVersion": playwright_driver.EXPECTED_CHROMIUM_VERSION,
            },
        ]
    }
    manifest.write_text(json.dumps(manifest_value) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_BROWSERS_JSON_SHA256",
        playwright_driver._sha256(manifest.read_bytes()),
    )

    pre_patch_tree = playwright_driver._tree_identity(
        package_root,
        domain=playwright_driver.PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        label="test Playwright package",
        expected_owner_uid=os.geteuid(),
    )
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE",
        pre_patch_tree,
    )
    for filename, content in patched.items():
        (driver_root / filename).write_bytes(content)
    post_patch_tree = playwright_driver._tree_identity(
        package_root,
        domain=playwright_driver.PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        label="test Playwright package",
        expected_owner_uid=os.geteuid(),
    )
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE",
        post_patch_tree,
    )
    for filename, content in originals.items():
        (driver_root / filename).write_bytes(content)

    distribution_root = tmp_path / "browser/chromium_headless_shell-1200"
    resolved_executable = distribution_root / "chrome-linux/headless_shell"
    resolved_executable.parent.mkdir(parents=True)
    resolved_executable.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{playwright_driver.EXPECTED_CHROMIUM_VERSION_OUTPUT}'\n",
        encoding="utf-8",
    )
    resolved_executable.chmod(0o755)
    (resolved_executable.parent / "resources.pak").write_bytes(b"bound resource\n")
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_CHROMIUM_SHA256",
        playwright_driver._sha256(resolved_executable.read_bytes()),
    )
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_CHROMIUM_DISTRIBUTION_TREE",
        playwright_driver._tree_identity(
            distribution_root,
            domain=playwright_driver.CHROMIUM_DISTRIBUTION_TREE_DOMAIN,
            label="test Chromium distribution",
            expected_owner_uid=os.geteuid(),
        ),
    )
    configured_executable = tmp_path / "bin/qcsd-chromium"
    configured_executable.parent.mkdir()
    configured_executable.symlink_to(resolved_executable)

    subprocess_wrapper = tmp_path / "runtime/libexec/qcsd-chromium-child"
    subprocess_wrapper.parent.mkdir(parents=True)
    subprocess_wrapper.write_bytes(b"#!/bin/sh\nexec /fixture/chromium --disable-crashpad-for-testing \"$@\"\n")
    subprocess_wrapper.chmod(0o555)
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256",
        playwright_driver._sha256(subprocess_wrapper.read_bytes()),
    )
    managed_policy = tmp_path / "runtime/policies/managed/qcsd-network-prediction.json"
    managed_policy.parent.mkdir(parents=True)
    managed_policy.write_bytes(
        b'{"DnsOverHttpsMode":"off","NetworkPredictionOptions":2}\n'
    )
    managed_policy.chmod(0o444)
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256",
        playwright_driver._sha256(managed_policy.read_bytes()),
    )

    return DriverFixture(
        package_root=package_root,
        driver_root=driver_root,
        distribution_root=distribution_root,
        receipt=tmp_path / "receipts/playwright-cdp-ownership.json",
        configured_executable=configured_executable,
        resolved_executable=resolved_executable,
        subprocess_wrapper=subprocess_wrapper,
        managed_policy=managed_policy,
        originals=originals,
        patched=patched,
    )


def _patch(fixture: DriverFixture) -> dict[str, object]:
    fixture.receipt.parent.mkdir(exist_ok=True)
    return playwright_driver.patch_playwright_driver(
        fixture.receipt,
        **fixture.arguments,
    )


def _verify(fixture: DriverFixture) -> dict[str, object]:
    return playwright_driver.validate_playwright_driver(
        fixture.receipt,
        **fixture.arguments,
    )


def test_production_contract_matches_pinned_playwright_and_live_prototype() -> None:
    specifications = {value.filename: value for value in playwright_driver._FILE_SPECS}

    assert playwright_driver.PLAYWRIGHT_VERSION == "1.57.0"
    assert playwright_driver.EXPECTED_CHROMIUM_REVISION == "1200"
    assert playwright_driver.EXPECTED_CHROMIUM_VERSION == "143.0.7499.4"
    assert playwright_driver.SUPPORTED_ARCHITECTURE == "aarch64"
    assert playwright_driver.RECEIPT_SCHEMA_VERSION == 6
    assert playwright_driver.CHROMIUM_SHARED_WORKER_PAUSE_FIX_COMMIT == (
        "0606a60db66fc14d6fd76c8d532392b26504b308"
    )
    assert playwright_driver.CHROMIUM_SHARED_WORKER_PAUSE_FIX_POSITION == 1_529_406
    assert playwright_driver.OWNERSHIP_POLICY_RECEIPT["shared_worker_pause_fix"] == {
        "chromium_commit": "0606a60db66fc14d6fd76c8d532392b26504b308",
        "chromium_position": 1_529_406,
        "required_semantics": "wait-for-debugger-on-start-holds-new-shared-worker",
    }
    assert playwright_driver.EXPECTED_BROWSERS_JSON_SHA256 == (
        "b509d013de89d621a142818e0937de356fbb0169096922c08581a4f83e463b8e"
    )
    assert playwright_driver.EXPECTED_CHROMIUM_SHA256 == (
        "6f72e258e11d85ec413b1671422c83d65af9f9ddcbc811657a43700b324ce928"
    )
    assert playwright_driver.CHROMIUM_ARCHIVE_URL == (
        "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1200/"
        "chromium-linux-arm64.zip"
    )
    assert playwright_driver.CHROMIUM_ARCHIVE_SHA256 == (
        "e73eeb680312e96d4f8fbca589ad42e3fb719178b4bdd8707f9fe796123bf48b"
    )
    assert playwright_driver.EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE == {
        "sha256": "416eaaa5ab61707e218d6e62de946c343f823e988327a8ebe41cb675a41ae90b",
        "file_count": 401,
        "total_bytes": 131_856_713,
    }
    assert playwright_driver.EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE == {
        "sha256": "2a233521c12cfc6612d2ebcb535ab8cf24a5554e36ad1f367097f70bdfbec07e",
        "file_count": 401,
        "total_bytes": 131_857_569,
    }
    assert playwright_driver.EXPECTED_CHROMIUM_DISTRIBUTION_TREE == {
        "sha256": "d5cd88dc445b6d4af2f220552e09f3180d22fed4142164c1b8b595cdecf014b5",
        "file_count": 466,
        "total_bytes": 616_583_533,
    }
    assert playwright_driver.CHROMIUM_CHILD_ENVIRONMENT == {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    assert playwright_driver.CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE == (
        "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
    )
    assert playwright_driver.FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES == (
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
    assert playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_BINDING == {
        "receipt_sha256": ("7194034787b5c1c34ffd88d62cf9969b1510fca7955a0ed7b7c3168f23a8bfb2"),
        "payload_sha256": ("926b894666e6b5d6dcdb31dc28d581a9cb22eba1f6dc924be74b49402c44e3c3"),
        "content_sha256": ("f2f774b92c6074dcab28bc5a0afa13b43c70e372057558b7246d4ba168602d51"),
        "policy": playwright_driver.OWNERSHIP_POLICY_RECEIPT,
        "browsers_json_sha256": playwright_driver.EXPECTED_BROWSERS_JSON_SHA256,
        "chromium_executable_sha256": playwright_driver.EXPECTED_CHROMIUM_SHA256,
    }
    assert playwright_driver.expected_browser_tool_identity() == {
        "schema_version": 1,
        "name": "playwright-chromium",
        "playwright_version": "1.57.0",
        "chromium_revision": "1200",
        "chromium_version": "143.0.7499.4",
        "configured_executable_path": "/usr/local/bin/qcsd-chromium",
        "playwright_driver": playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_BINDING,
    }
    assert specifications["crPage.js"].pre_patch_sha256 == (
        "71aab16b0912f23cb9aa3095b8072bfc6fbd6e47e4e13a7be3684b796aa1cd28"
    )
    assert specifications["crPage.js"].post_patch_sha256 == (
        "718c618ff2342acba85b88efe4f87d3a0c6ded00a61829409b387f9eebd0a79e"
    )
    assert specifications["crBrowser.js"].pre_patch_sha256 == (
        "c72c8906948a54a3d78049148c53c1bacd9dd54cbe2fce48e4e2ad7d032a03b2"
    )
    assert specifications["crBrowser.js"].post_patch_sha256 == (
        "ec4f6badc590bc3928b8a148c9e6afa2232e34ab779f41e66a9a2803d09315ba"
    )
    assert specifications["crPage.js"].excluded_target_types == (
        "iframe",
        "worker",
        "shared_worker",
    )
    assert specifications["crBrowser.js"].excluded_target_types == (
        "iframe",
        "worker",
        "shared_worker",
        "tab",
    )
    replacement = playwright_driver._replacement(specifications["crPage.js"].excluded_target_types)
    assert b'process.env.QCSD_EXCLUSIVE_CDP_TARGET_OWNERSHIP === "1"' in replacement
    assert replacement.endswith(b": {}) }")


def test_driver_session_starts_with_exact_markers_and_lifetimes_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = playwright_driver.OWNERSHIP_MARKER_NAME
    monkeypatch.setenv(name, playwright_driver.OWNERSHIP_MARKER_VALUE)
    observations: dict[str, str | None] = {}
    lifetime_barrier = threading.Barrier(2)

    class Manager:
        def __init__(self, label: str) -> None:
            self.label = label

        def __enter__(self) -> str:
            observations[self.label] = os.environ.get(name)
            return self.label

        def __exit__(self, *_args: object) -> None:
            return None

    def run(label: str, *, exclusive: bool) -> None:
        with playwright_driver.playwright_driver_session(
            lambda: Manager(label),
            exclusive=exclusive,
        ) as started:
            assert started == label
            lifetime_barrier.wait(timeout=2)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(run, "active", exclusive=True),
            executor.submit(run, "inactive", exclusive=False),
        )
        for future in futures:
            future.result(timeout=3)

    assert observations == {"active": "1", "inactive": None}
    assert os.environ[name] == playwright_driver.OWNERSHIP_MARKER_VALUE


def test_driver_session_rejects_overrides_and_restores_marker_on_start_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = playwright_driver.OWNERSHIP_MARKER_NAME
    monkeypatch.setenv(name, "true")
    with (
        pytest.raises(ValueError, match="must be absent or exactly '1'"),
        playwright_driver.playwright_driver_session(lambda: None, exclusive=True),
    ):
        raise AssertionError("must not enter")
    assert os.environ[name] == "true"

    monkeypatch.delenv(name)

    def failing_factory() -> object:
        assert os.environ[name] == playwright_driver.OWNERSHIP_MARKER_VALUE
        raise RuntimeError("deliberate")

    with (
        pytest.raises(RuntimeError, match="deliberate"),
        playwright_driver.playwright_driver_session(
            failing_factory,
            exclusive=True,
        ),
    ):
        raise AssertionError("must not enter")
    assert name not in os.environ


@pytest.mark.parametrize(
    "override",
    playwright_driver.FORBIDDEN_DRIVER_ENVIRONMENT_VARIABLES,
)
def test_driver_session_rejects_every_ambient_driver_override_before_start(
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    starts = 0

    def forbidden_factory() -> object:
        nonlocal starts
        starts += 1
        raise AssertionError("driver factory must not run")

    monkeypatch.setenv(override, "attacker-controlled")
    with (
        pytest.raises(ValueError, match=override),
        playwright_driver.playwright_driver_session(
            forbidden_factory,
            exclusive=False,
        ),
    ):
        raise AssertionError("must not enter")

    assert starts == 0


def test_chromium_child_environment_is_fixed_and_detached_from_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/nss/lib")
    child = playwright_driver.chromium_child_environment()

    assert child == playwright_driver.CHROMIUM_CHILD_ENVIRONMENT
    assert "LD_LIBRARY_PATH" not in child
    child["HOME"] = "/tampered"
    assert playwright_driver.chromium_child_environment()["HOME"] == "/nonexistent"


def test_qualification_policy_validator_accepts_only_exact_zero_or_two(
    driver_fixture: DriverFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = os.geteuid()
    wrapper, policy = playwright_driver._browser_service_containment_files(
        subprocess_wrapper=driver_fixture.subprocess_wrapper,
        managed_policy=driver_fixture.managed_policy,
        expected_owner_uid=owner,
        expected_network_prediction_option=2,
    )
    assert wrapper["sha256"] == playwright_driver.EXPECTED_CHROMIUM_SUBPROCESS_WRAPPER_SHA256
    assert policy["sha256"] == playwright_driver.EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256

    driver_fixture.managed_policy.chmod(0o644)
    driver_fixture.managed_policy.write_bytes(
        b'{"DnsOverHttpsMode":"off","NetworkPredictionOptions":0}\n'
    )
    driver_fixture.managed_policy.chmod(0o444)
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256",
        playwright_driver._sha256(driver_fixture.managed_policy.read_bytes()),
    )
    _wrapper, control = playwright_driver._browser_service_containment_files(
        subprocess_wrapper=driver_fixture.subprocess_wrapper,
        managed_policy=driver_fixture.managed_policy,
        expected_owner_uid=owner,
        expected_network_prediction_option=0,
    )
    assert control["sha256"] == playwright_driver.EXPECTED_CHROMIUM_CONTROL_POLICY_SHA256
    with pytest.raises(ValueError, match="option"):
        playwright_driver._browser_service_containment_files(
            subprocess_wrapper=driver_fixture.subprocess_wrapper,
            managed_policy=driver_fixture.managed_policy,
            expected_owner_uid=owner,
            expected_network_prediction_option=1,
        )
    with pytest.raises(ValueError, match="hash|policy"):
        playwright_driver._browser_service_containment_files(
            subprocess_wrapper=driver_fixture.subprocess_wrapper,
            managed_policy=driver_fixture.managed_policy,
            expected_owner_uid=owner,
            expected_network_prediction_option=2,
        )


@pytest.mark.parametrize(
    "policy_value",
    (
        {"NetworkPredictionOptions": 2},
        {"DnsOverHttpsMode": "automatic", "NetworkPredictionOptions": 2},
        {"DnsOverHttpsMode": "secure", "NetworkPredictionOptions": 2},
    ),
)
def test_managed_policy_requires_explicit_dns_over_https_off(
    driver_fixture: DriverFixture,
    monkeypatch: pytest.MonkeyPatch,
    policy_value: dict[str, object],
) -> None:
    driver_fixture.managed_policy.chmod(0o644)
    driver_fixture.managed_policy.write_text(
        json.dumps(policy_value, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    driver_fixture.managed_policy.chmod(0o444)
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_CHROMIUM_MANAGED_POLICY_SHA256",
        playwright_driver._sha256(driver_fixture.managed_policy.read_bytes()),
    )

    with pytest.raises(ValueError, match="browser-egress policy"):
        playwright_driver._browser_service_containment_files(
            subprocess_wrapper=driver_fixture.subprocess_wrapper,
            managed_policy=driver_fixture.managed_policy,
            expected_owner_uid=os.geteuid(),
            expected_network_prediction_option=2,
        )


def test_policy_root_inventory_requires_empty_recommended_and_no_sibling_policy(
    driver_fixture: DriverFixture,
) -> None:
    recommended = driver_fixture.managed_policy.parent.parent / "recommended"
    recommended.mkdir()
    inventory = playwright_driver._runtime_policy_directory_inventory(
        managed_policy=driver_fixture.managed_policy,
        expected_owner_uid=os.geteuid(),
    )
    assert inventory == [
        {
            "path": str(driver_fixture.managed_policy.parent),
            "state": "sole-managed-policy",
            "file_count": 1,
        },
        {
            "path": str(recommended),
            "state": "empty-directory",
            "file_count": 0,
        },
    ]
    managed_sibling = driver_fixture.managed_policy.parent / "attacker.json"
    managed_sibling.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="only the bound policy"):
        playwright_driver._runtime_policy_directory_inventory(
            managed_policy=driver_fixture.managed_policy,
            expected_owner_uid=os.geteuid(),
        )
    managed_sibling.unlink()
    sibling = recommended / "attacker.json"
    sibling.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be empty"):
        playwright_driver._runtime_policy_directory_inventory(
            managed_policy=driver_fixture.managed_policy,
            expected_owner_uid=os.geteuid(),
        )


def test_pinned_chromium_executable_path_rejects_every_nondefault_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = playwright_driver.CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE
    expected = str(playwright_driver.DEFAULT_CONFIGURED_EXECUTABLE)

    monkeypatch.delenv(name, raising=False)
    assert playwright_driver.pinned_chromium_executable_path() == expected
    monkeypatch.setenv(name, expected)
    assert playwright_driver.pinned_chromium_executable_path() == expected

    for invalid in ("", "/tmp/other-chromium", expected + " "):
        monkeypatch.setenv(name, invalid)
        with pytest.raises(ValueError, match=name):
            playwright_driver.pinned_chromium_executable_path()


def test_default_validation_cache_is_exact_isolated_and_nonroot_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = playwright_driver.expected_playwright_driver_receipt()
    validations = 0
    policy_inventories = 0

    def validate() -> dict[str, object]:
        nonlocal validations
        validations += 1
        return copy.deepcopy(expected)

    monkeypatch.setattr(playwright_driver, "validate_playwright_driver", validate)
    def inventory() -> list[dict[str, object]]:
        nonlocal policy_inventories
        policy_inventories += 1
        return []

    monkeypatch.setattr(
        playwright_driver, "_runtime_policy_directory_inventory", inventory
    )
    monkeypatch.setattr(playwright_driver.os, "geteuid", lambda: 1_000)
    monkeypatch.setattr(
        playwright_driver,
        "_sha256_regular_file",
        lambda *_args, **_kwargs: (
            playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
            None,
        ),
    )
    monkeypatch.setattr(
        playwright_driver,
        "_require_default_runtime_immutability",
        lambda: 1_000,
    )

    first = playwright_driver.validate_default_playwright_driver_once()
    first["schema_version"] = -1
    second = playwright_driver.validate_default_playwright_driver_once()

    assert validations == 1
    assert policy_inventories == 2
    assert second == expected

    playwright_driver.reset_playwright_driver_validation_cache()
    monkeypatch.setattr(
        playwright_driver,
        "_require_default_runtime_immutability",
        lambda: 0,
    )
    playwright_driver.validate_default_playwright_driver_once()
    playwright_driver.validate_default_playwright_driver_once()
    assert validations == 3
    assert policy_inventories == 4


def test_default_validation_cache_rechecks_executable_environment_on_every_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = playwright_driver.expected_playwright_driver_receipt()
    validations = 0

    def validate() -> dict[str, object]:
        nonlocal validations
        validations += 1
        return copy.deepcopy(expected)

    monkeypatch.setattr(playwright_driver, "validate_playwright_driver", validate)
    monkeypatch.setattr(
        playwright_driver, "_runtime_policy_directory_inventory", lambda: []
    )
    monkeypatch.setattr(playwright_driver.os, "geteuid", lambda: 1_000)
    monkeypatch.setattr(
        playwright_driver,
        "_sha256_regular_file",
        lambda *_args, **_kwargs: (
            playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
            None,
        ),
    )
    monkeypatch.setattr(
        playwright_driver,
        "_require_default_runtime_immutability",
        lambda: 1_000,
    )
    name = playwright_driver.CHROMIUM_EXECUTABLE_ENVIRONMENT_VARIABLE
    monkeypatch.setenv(name, str(playwright_driver.DEFAULT_CONFIGURED_EXECUTABLE))

    assert playwright_driver.validate_default_playwright_driver_once() == expected
    assert validations == 1
    monkeypatch.setenv(name, "/tmp/post-cache-substitution")
    with pytest.raises(ValueError, match=name):
        playwright_driver.validate_default_playwright_driver_once()
    assert validations == 1


@pytest.mark.parametrize("failure", ["receipt", "receipt-hash", "writable"])
def test_default_validation_cache_fails_closed_before_caching(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    receipt = playwright_driver.expected_playwright_driver_receipt()
    if failure == "receipt":
        receipt["schema_version"] = -1
    monkeypatch.setattr(
        playwright_driver,
        "validate_playwright_driver",
        lambda: copy.deepcopy(receipt),
    )
    monkeypatch.setattr(
        playwright_driver, "_runtime_policy_directory_inventory", lambda: []
    )
    monkeypatch.setattr(playwright_driver.os, "geteuid", lambda: 1_000)
    monkeypatch.setattr(
        playwright_driver,
        "_sha256_regular_file",
        lambda *_args, **_kwargs: (
            "0" * 64
            if failure == "receipt-hash"
            else playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
            None,
        ),
    )

    def immutability() -> int:
        if failure == "writable":
            raise ValueError("writable by runtime")
        return 1_000

    monkeypatch.setattr(
        playwright_driver,
        "_require_default_runtime_immutability",
        immutability,
    )

    with pytest.raises(ValueError, match="exact production|production hash|writable"):
        playwright_driver.validate_default_playwright_driver_once()
    assert playwright_driver._DEFAULT_VALIDATION_CACHE is None


@pytest.mark.parametrize("rogue_root", ["recommended", "alternate"])
def test_default_validation_cache_rechecks_every_policy_root_before_return(
    driver_fixture: DriverFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rogue_root: str,
) -> None:
    expected = playwright_driver.expected_playwright_driver_receipt()
    owner_uid = os.geteuid()
    recommended = driver_fixture.managed_policy.parent.parent / "recommended"
    recommended.mkdir()
    alternates = (
        tmp_path / "alternate-chrome-policies",
        tmp_path / "alternate-chromium-policies",
    )
    real_inventory = playwright_driver._runtime_policy_directory_inventory

    def inventory() -> list[dict[str, object]]:
        return real_inventory(
            managed_policy=driver_fixture.managed_policy,
            expected_owner_uid=owner_uid,
            alternate_policy_roots=alternates,
        )

    monkeypatch.setattr(
        playwright_driver, "_runtime_policy_directory_inventory", inventory
    )
    monkeypatch.setattr(
        playwright_driver,
        "validate_playwright_driver",
        lambda: copy.deepcopy(expected),
    )
    monkeypatch.setattr(playwright_driver.os, "geteuid", lambda: 1_000)
    monkeypatch.setattr(
        playwright_driver,
        "_sha256_regular_file",
        lambda *_args, **_kwargs: (
            playwright_driver.EXPECTED_PLAYWRIGHT_DRIVER_RECEIPT_SHA256,
            None,
        ),
    )
    monkeypatch.setattr(
        playwright_driver, "_require_default_runtime_immutability", lambda: 1_000
    )

    assert playwright_driver.validate_default_playwright_driver_once() == expected
    if rogue_root == "recommended":
        (recommended / "attacker.json").write_text("{}\n", encoding="utf-8")
        message = "must be empty"
    else:
        alternates[0].mkdir()
        message = "alternate policy root must be absent"
    with pytest.raises(ValueError, match=message):
        playwright_driver.validate_default_playwright_driver_once()


def test_default_cache_ancestor_check_rejects_writable_intermediate(
    tmp_path: Path,
) -> None:
    writable = tmp_path / "writable-intermediate"
    safe = writable / "safe-parent"
    safe.mkdir(parents=True)
    leaf = safe / "bound-file"
    leaf.write_bytes(b"bound\n")
    writable.chmod(0o777)
    safe.chmod(0o555)
    try:
        with pytest.raises(ValueError, match="writable-intermediate"):
            playwright_driver._require_effectively_readonly_ancestors(
                leaf,
                label="test binding",
                expected_owner_uid=os.geteuid(),
            )
    finally:
        safe.chmod(0o755)
        writable.chmod(0o755)


def test_patch_is_exact_create_only_and_receipt_is_canonical(
    driver_fixture: DriverFixture,
) -> None:
    receipt = _patch(driver_fixture)

    assert receipt == _verify(driver_fixture)
    assert driver_fixture.receipt.read_bytes() == playwright_driver._canonical_json(receipt)
    assert driver_fixture.receipt.stat().st_uid == os.geteuid()
    assert driver_fixture.receipt.stat().st_mode & 0o222 == 0
    assert receipt["payload_sha256"] == playwright_driver._payload_sha256(receipt)
    assert receipt["policy"] == playwright_driver.OWNERSHIP_POLICY_RECEIPT
    assert receipt["schema_version"] == 6
    assert receipt["browser_manifest"]["chromium_revision"] == "1200"
    assert receipt["chromium_executable"]["version_output"] == ("Chromium 143.0.7499.4")
    assert receipt["playwright_package_tree"] == {
        "domain": playwright_driver.PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
        "root": str(driver_fixture.package_root),
        "pre_patch": playwright_driver.EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE,
        "post_patch": playwright_driver.EXPECTED_PLAYWRIGHT_PACKAGE_POST_PATCH_TREE,
    }
    assert receipt["chromium_distribution_tree"] == {
        "domain": playwright_driver.CHROMIUM_DISTRIBUTION_TREE_DOMAIN,
        "root": str(driver_fixture.distribution_root),
        "archive_url": playwright_driver.CHROMIUM_ARCHIVE_URL,
        "archive_sha256": playwright_driver.CHROMIUM_ARCHIVE_SHA256,
        **playwright_driver.EXPECTED_CHROMIUM_DISTRIBUTION_TREE,
    }
    for filename, expected in driver_fixture.patched.items():
        assert (driver_fixture.driver_root / filename).read_bytes() == expected
        assert expected.count(playwright_driver._ATTACH_EXPRESSION) == 0

    with pytest.raises(FileExistsError, match="create-only"):
        playwright_driver.patch_playwright_driver(
            driver_fixture.receipt,
            **driver_fixture.arguments,
        )


def test_expected_receipt_builder_matches_patch_at_selected_default_layout(
    driver_fixture: DriverFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        playwright_driver,
        "DEFAULT_PLAYWRIGHT_PACKAGE_ROOT",
        driver_fixture.package_root,
    )
    monkeypatch.setattr(playwright_driver, "DEFAULT_DRIVER_ROOT", driver_fixture.driver_root)
    monkeypatch.setattr(
        playwright_driver,
        "DEFAULT_CONFIGURED_EXECUTABLE",
        driver_fixture.configured_executable,
    )
    monkeypatch.setattr(
        playwright_driver,
        "DEFAULT_RESOLVED_EXECUTABLE",
        driver_fixture.resolved_executable,
    )
    monkeypatch.setattr(
        playwright_driver,
        "DEFAULT_CHROMIUM_SUBPROCESS_WRAPPER",
        driver_fixture.subprocess_wrapper,
    )
    monkeypatch.setattr(
        playwright_driver,
        "DEFAULT_CHROMIUM_MANAGED_POLICY",
        driver_fixture.managed_policy,
    )

    actual = _patch(driver_fixture)
    expected = playwright_driver.expected_playwright_driver_receipt()

    assert actual == expected
    assert playwright_driver._sha256(
        playwright_driver._canonical_json(actual)
    ) == playwright_driver._sha256(playwright_driver._canonical_json(expected))


@pytest.mark.parametrize("state", ["wrong", "already-patched", "partial"])
def test_patch_rejects_wrong_already_or_partially_patched_driver_without_mutation(
    driver_fixture: DriverFixture,
    state: str,
) -> None:
    browser = driver_fixture.driver_root / "crBrowser.js"
    page = driver_fixture.driver_root / "crPage.js"
    if state == "wrong":
        browser.write_bytes(driver_fixture.originals["crBrowser.js"] + b"// drift\n")
    elif state == "already-patched":
        browser.write_bytes(driver_fixture.patched["crBrowser.js"])
        page.write_bytes(driver_fixture.patched["crPage.js"])
    else:
        browser.write_bytes(driver_fixture.patched["crBrowser.js"])
    before = {path: path.read_bytes() for path in (browser, page)}
    driver_fixture.receipt.parent.mkdir()

    with pytest.raises(ValueError, match="pinned tree|exact unpatched"):
        playwright_driver.patch_playwright_driver(
            driver_fixture.receipt,
            **driver_fixture.arguments,
        )

    assert not driver_fixture.receipt.exists()
    assert {path: path.read_bytes() for path in (browser, page)} == before


def test_patch_rejects_non_exact_replacement_count(
    driver_fixture: DriverFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = playwright_driver._FILE_SPECS[0]
    path = driver_fixture.driver_root / first.filename
    source = b"only(" + playwright_driver._ATTACH_EXPRESSION + b")\n"
    result = source.replace(
        playwright_driver._ATTACH_EXPRESSION,
        playwright_driver._replacement(first.excluded_target_types),
    )
    path.write_bytes(source)
    monkeypatch.setattr(
        playwright_driver,
        "_FILE_SPECS",
        (
            playwright_driver._DriverFileSpec(
                filename=first.filename,
                pre_patch_sha256=playwright_driver._sha256(source),
                post_patch_sha256=playwright_driver._sha256(result),
                excluded_target_types=first.excluded_target_types,
            ),
            *playwright_driver._FILE_SPECS[1:],
        ),
    )
    monkeypatch.setattr(
        playwright_driver,
        "EXPECTED_PLAYWRIGHT_PACKAGE_PRE_PATCH_TREE",
        playwright_driver._tree_identity(
            driver_fixture.package_root,
            domain=playwright_driver.PLAYWRIGHT_PACKAGE_TREE_DOMAIN,
            label="test Playwright package",
            expected_owner_uid=os.geteuid(),
        ),
    )
    driver_fixture.receipt.parent.mkdir()

    with pytest.raises(ValueError, match="exact unpatched"):
        playwright_driver.patch_playwright_driver(
            driver_fixture.receipt,
            **driver_fixture.arguments,
        )

    assert path.read_bytes() == source
    assert not driver_fixture.receipt.exists()


def test_existing_receipt_is_rejected_before_driver_mutation(
    driver_fixture: DriverFixture,
) -> None:
    driver_fixture.receipt.parent.mkdir()
    driver_fixture.receipt.write_bytes(b"preserve me")

    with pytest.raises(FileExistsError, match="create-only"):
        playwright_driver.patch_playwright_driver(
            driver_fixture.receipt,
            **driver_fixture.arguments,
        )

    assert driver_fixture.receipt.read_bytes() == b"preserve me"
    for filename, expected in driver_fixture.originals.items():
        assert (driver_fixture.driver_root / filename).read_bytes() == expected


def test_wrong_playwright_version_and_architecture_fail_before_mutation(
    driver_fixture: DriverFixture,
) -> None:
    driver_fixture.receipt.parent.mkdir()
    arguments = dict(driver_fixture.arguments)
    arguments["installed_version"] = "1.53.0"
    with pytest.raises(ValueError, match="requires exactly Playwright 1.57.0"):
        playwright_driver.patch_playwright_driver(driver_fixture.receipt, **arguments)

    arguments = dict(driver_fixture.arguments)
    arguments["machine"] = "x86_64"
    with pytest.raises(ValueError, match="supported only on aarch64"):
        playwright_driver.patch_playwright_driver(driver_fixture.receipt, **arguments)

    for filename, expected in driver_fixture.originals.items():
        assert (driver_fixture.driver_root / filename).read_bytes() == expected


def test_patch_requires_the_configured_receipt_owner(
    driver_fixture: DriverFixture,
) -> None:
    driver_fixture.receipt.parent.mkdir()
    arguments = dict(driver_fixture.arguments)
    arguments["expected_owner_uid"] = os.geteuid() + 1

    with pytest.raises(ValueError, match="patch must run as uid"):
        playwright_driver.patch_playwright_driver(driver_fixture.receipt, **arguments)

    assert not driver_fixture.receipt.exists()
    for filename, expected in driver_fixture.originals.items():
        assert (driver_fixture.driver_root / filename).read_bytes() == expected


@pytest.mark.parametrize(
    "target",
    ["driver", "manifest", "package-extra", "executable", "browser-extra", "receipt"],
)
def test_verifier_rejects_every_bound_surface_tamper(
    driver_fixture: DriverFixture,
    target: str,
) -> None:
    _patch(driver_fixture)
    if target == "driver":
        path = driver_fixture.driver_root / "crPage.js"
        path.write_bytes(path.read_bytes() + b"// tamper\n")
    elif target == "manifest":
        path = driver_fixture.driver_root.parents[2] / "browsers.json"
        path.write_bytes(path.read_bytes() + b" ")
    elif target == "package-extra":
        (driver_fixture.package_root / "unreceipted.js").write_bytes(b"tamper\n")
    elif target == "executable":
        driver_fixture.resolved_executable.write_bytes(
            driver_fixture.resolved_executable.read_bytes() + b"# tamper\n"
        )
    elif target == "browser-extra":
        (driver_fixture.distribution_root / "unreceipted.pak").write_bytes(b"tamper\n")
    else:
        driver_fixture.receipt.chmod(0o644)
        value = json.loads(driver_fixture.receipt.read_text(encoding="utf-8"))
        value["policy"] = "tampered"
        driver_fixture.receipt.write_bytes(playwright_driver._canonical_json(value))
        driver_fixture.receipt.chmod(0o444)

    with pytest.raises(ValueError):
        _verify(driver_fixture)


@pytest.mark.parametrize("kind", ["file", "directory", "ancestor", "symlink"])
def test_verifier_rejects_unsafe_tree_entries(
    driver_fixture: DriverFixture,
    kind: str,
) -> None:
    _patch(driver_fixture)
    if kind == "file":
        target = driver_fixture.driver_root / "crPage.js"
        target.chmod(0o666)
    elif kind == "directory":
        target = driver_fixture.driver_root.parent
        target.chmod(0o777)
    elif kind == "ancestor":
        target = driver_fixture.package_root.parent
        target.chmod(0o777)
    else:
        target = driver_fixture.package_root / "unexpected-link"
        target.symlink_to(driver_fixture.driver_root / "crPage.js")

    with pytest.raises(ValueError, match="group/world-writable|contains a symlink"):
        _verify(driver_fixture)


def test_failed_post_publish_validation_removes_receipt_and_rolls_back(
    driver_fixture: DriverFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver_fixture.receipt.parent.mkdir()
    monkeypatch.setattr(
        playwright_driver,
        "validate_playwright_driver",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("post-publish failure")),
    )

    with pytest.raises(RuntimeError, match="post-publish failure"):
        playwright_driver.patch_playwright_driver(
            driver_fixture.receipt,
            **driver_fixture.arguments,
        )

    assert not driver_fixture.receipt.exists()
    for filename, expected in driver_fixture.originals.items():
        assert (driver_fixture.driver_root / filename).read_bytes() == expected


def test_failed_driver_directory_sync_rolls_back_replaced_file(
    driver_fixture: DriverFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver_fixture.receipt.parent.mkdir()
    calls = 0
    real_fsync_directory = playwright_driver.fsync_directory

    def fail_first_sync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("driver sync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(playwright_driver, "fsync_directory", fail_first_sync)
    with pytest.raises(OSError, match="driver sync failure"):
        playwright_driver.patch_playwright_driver(
            driver_fixture.receipt,
            **driver_fixture.arguments,
        )

    assert not driver_fixture.receipt.exists()
    for filename, expected in driver_fixture.originals.items():
        assert (driver_fixture.driver_root / filename).read_bytes() == expected


def test_failed_receipt_directory_sync_removes_published_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "receipt.json"
    calls = 0

    def fail_first_sync(_path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("sync failure")

    monkeypatch.setattr(playwright_driver, "fsync_directory", fail_first_sync)
    with pytest.raises(OSError, match="sync failure"):
        playwright_driver._durable_readonly_create(
            destination,
            b"{}\n",
            owner_uid=os.geteuid(),
        )

    assert not destination.exists()
    assert not tuple(tmp_path.glob(".receipt.json.qcsd-playwright-*"))


def test_verifier_rejects_writable_or_noncanonical_receipt(
    driver_fixture: DriverFixture,
) -> None:
    _patch(driver_fixture)
    driver_fixture.receipt.chmod(0o644)
    with pytest.raises(ValueError, match="receipt is writable"):
        _verify(driver_fixture)

    value = json.loads(driver_fixture.receipt.read_text(encoding="utf-8"))
    driver_fixture.receipt.write_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    )
    driver_fixture.receipt.chmod(0o444)
    with pytest.raises(ValueError, match="not canonical JSON"):
        _verify(driver_fixture)


def test_verifier_is_read_only_and_rejects_retargeted_executable(
    driver_fixture: DriverFixture,
) -> None:
    _patch(driver_fixture)
    observed = {
        path: path.read_bytes()
        for path in (
            driver_fixture.receipt,
            driver_fixture.driver_root / "crBrowser.js",
            driver_fixture.driver_root / "crPage.js",
            driver_fixture.driver_root.parents[2] / "browsers.json",
            driver_fixture.resolved_executable,
        )
    }

    _verify(driver_fixture)
    assert {path: path.read_bytes() for path in observed} == observed

    replacement = driver_fixture.resolved_executable.with_name("replacement")
    replacement.write_bytes(driver_fixture.resolved_executable.read_bytes())
    replacement.chmod(0o755)
    driver_fixture.configured_executable.unlink()
    driver_fixture.configured_executable.symlink_to(replacement)
    with pytest.raises(ValueError, match="symlink target is invalid"):
        _verify(driver_fixture)


def test_cli_dispatches_only_patch_or_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[str] = []
    monkeypatch.setattr(
        playwright_driver,
        "patch_playwright_driver",
        lambda: observed.append("patch"),
    )
    monkeypatch.setattr(
        playwright_driver,
        "validate_playwright_driver",
        lambda: observed.append("verify"),
    )

    playwright_driver.main(["patch"])
    playwright_driver.main(["verify"])

    assert observed == ["patch", "verify"]
