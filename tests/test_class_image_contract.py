from __future__ import annotations

from pathlib import Path

from qcsd_lab import playwright_driver, runtime_provenance
from qcsd_lab.chaff_qualification import IMPLEMENTATION_PYTHON_FILES


ROOT = Path(__file__).resolve().parents[1]


def test_docker_runtime_receipt_covers_all_python_modules_and_installed_tools() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    modules = tuple(sorted((ROOT / "src/qcsd_lab").rglob("*.py")))
    class_modules = tuple(path for path in modules if path.name.startswith("class_"))

    assert runtime_provenance.RUNTIME_RECEIPT_SCHEMA_VERSION == 2
    assert runtime_provenance.RUNTIME_RECEIPT_DOMAIN.endswith("-v2")
    assert class_modules
    assert '*sorted((root / "src/qcsd_lab").rglob("*.py"))' in dockerfile
    assert 'path.startswith("src/qcsd_lab/class_")' in dockerfile
    assert "tools/build_class_catalogue.py" in dockerfile
    assert "COPY tools/build_class_catalogue.py ./tools/build_class_catalogue.py" in dockerfile
    assert "/usr/local/bin/qcsd-build-class-catalogue" in dockerfile
    assert "qcsd-build-class-catalogue --help >/dev/null" in dockerfile
    assert "tools/browser_egress_qualification.py" in dockerfile
    assert (
        "COPY tools/browser_egress_qualification.py "
        "./tools/browser_egress_qualification.py"
    ) in dockerfile
    assert "/usr/local/bin/qcsd-browser-egress-qualification" in dockerfile
    assert "qcsd-browser-egress-qualification --help >/dev/null" in dockerfile
    browser_install = dockerfile.index(
        "install -m 0755 tools/browser_egress_qualification.py"
    )
    runtime_receipt = dockerfile.index("qcsd_lab.runtime_provenance build")
    assert browser_install < runtime_receipt
    assert "qcsd_lab.runtime_provenance build" in dockerfile
    assert dockerfile.count("qcsd_lab.runtime_provenance verify") == 3
    assert "/usr/share/qcsd-lab/python-runtime-implementation.json" in dockerfile


def test_class_runtime_uses_separate_receipt_without_changing_qualification_schema() -> None:
    assert not any(Path(path).name.startswith("class_") for path in IMPLEMENTATION_PYTHON_FILES)
    assert "src/qcsd_lab/runtime_provenance.py" not in IMPLEMENTATION_PYTHON_FILES
    assert all((ROOT / path).is_file() for path in IMPLEMENTATION_PYTHON_FILES)


def test_prepare_and_collection_images_have_required_acquisition_and_evaluation_stacks() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    chromium_stage = dockerfile.split(
        "FROM ${DEBIAN_IMAGE} AS chromium-browser", maxsplit=1
    )[1].split("FROM ${DEBIAN_IMAGE} AS source-metadata", maxsplit=1)[0]
    collection = dockerfile.split("FROM lab-runtime AS collection", maxsplit=1)[1].split(
        "FROM lab-runtime AS reference", maxsplit=1
    )[0]
    prepare = dockerfile.split("FROM collection AS prepare", maxsplit=1)[1]

    assert "--extra test --extra evaluation" in collection
    assert "default-jre-headless" in collection
    assert "COPY --from=weka-builder" in collection
    assert "COPY --from=osad-builder" in collection
    assert 'import sklearn; assert sklearn.__version__ == "1.9.0"' in collection
    assert "--extra test --extra evaluation --extra discovery" in prepare
    assert "import playwright.sync_api" in prepare
    assert "PLAYWRIGHT_BROWSERS_PATH=/opt/qcsd-playwright" in prepare
    assert "python3 -m playwright install-deps chromium" in prepare
    archive_sha256 = playwright_driver.CHROMIUM_ARCHIVE_SHA256
    archive_url = (
        "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1200/"
        "chromium-linux-arm64.zip"
    )
    assert archive_url == playwright_driver.CHROMIUM_ARCHIVE_URL
    assert playwright_driver.EXPECTED_CHROMIUM_SHA256 == (
        "6f72e258e11d85ec413b1671422c83d65af9f9ddcbc811657a43700b324ce928"
    )
    assert f"ADD --checksum=sha256:{archive_sha256}" in chromium_stage
    assert archive_url in chromium_stage
    assert dockerfile.count(archive_url) == 1
    assert f"{archive_sha256} \\" in chromium_stage
    assert "/tmp/chromium.zip | sha256sum -c -" in chromium_stage
    assert "if len(files) != 466" in chromium_stage
    assert "python3 -m playwright install --only-shell" not in dockerfile
    assert "python3 -m playwright install chromium" not in dockerfile
    assert "COPY --from=chromium-browser" in prepare
    assert "chromium-1200/chrome-linux/chrome" in prepare
    assert "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/local/bin/qcsd-chromium" in prepare
    patch = prepare.index("python3 -m qcsd_lab.playwright_driver patch")
    verify = prepare.index("python3 -m qcsd_lab.playwright_driver verify")
    runtime_verify = prepare.index("python3 -m qcsd_lab.runtime_provenance verify")
    assert patch < verify < runtime_verify
    assert "/usr/share/qcsd-lab/playwright-cdp-ownership.json" in (
        ROOT / "src/qcsd_lab/playwright_driver.py"
    ).read_text(encoding="utf-8")


def test_prepare_image_installs_browser_egress_roles_and_packet_tools() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    prepare = dockerfile.split("FROM collection AS prepare", maxsplit=1)[1]

    assert "root / \"tools/browser_egress_qualification.py\"" in dockerfile
    assert (
        "COPY tools/browser_egress_qualification.py "
        "./tools/browser_egress_qualification.py"
    ) in dockerfile
    assert (
        "install -m 0755 tools/browser_egress_qualification.py \\\n"
        "      /usr/local/bin/qcsd-browser-egress-qualification"
    ) in dockerfile
    for config in (
        "browser-egress-qualification-v1.json",
        "browser-egress-chromium-argv-v1.json",
    ):
        assert f'root / "config/class-study/v1/{config}"' in dockerfile
        assert f"COPY config/class-study/v1/{config}" in dockerfile
        assert f"test -r /opt/qcsd-lab/config/class-study/v1/{config}" in prepare
    assert "apt-get install -y --no-install-recommends openssl" in prepare
    assert "/usr/bin/dumpcap --version >/dev/null" in prepare
    assert "/usr/bin/tshark --version >/dev/null" in prepare
    assert "/usr/local/bin/qcsd-browser-egress-qualification --help >/dev/null" in prepare
    assert (
        "COPY --chown=0:0 --chmod=0444 \\\n"
        "    config/class-study/v1/browser-egress-fixture-cert-v1.pem"
    ) in prepare
    assert (
        "COPY --chown=0:0 --chmod=0400 \\\n"
        "    config/class-study/v1/browser-egress-fixture-key-v1.pem"
    ) in prepare
    assert (
        "COPY --chmod=0444 \\\n"
        "    config/class-study/v1/chromium-network-prediction-positive-control-v1.json"
    ) in prepare


def test_wrapper_selects_prepare_for_acquisition_and_keeps_workspace_read_only() -> None:
    launcher = (ROOT / "qcsd-lab").read_text(encoding="utf-8")

    assert '"${class_study_action}" == acquisition-*' in launcher
    assert 'image="${PREPARE_IMAGE}"' in launcher
    assert '--volume "${ROOT}:/lab:ro"' in launcher
    assert 'container+=(--volume "${class_write_root}:${class_write_container}:rw")' in launcher
    acquisition_run = launcher.split("    acquisition-run)", maxsplit=1)[1].split(
        "      ;;", maxsplit=1
    )[0]
    assert 'class_guarded_rw_dirs "${class_path_hosts[--workload-root]}"' in acquisition_run
    assert 'class_direct_rw_dirs "${class_path_hosts[--workload-root]}"' not in acquisition_run
    assert 'echo "class-study rejects a blanket workspace read-write mount"' in launcher
    assert '--volume "${ROOT}:/lab:rw"' not in launcher
    assert '--env "QCSD_PUBLIC_ORIGIN_ONLY=1"' in launcher


def test_unprivileged_class_runtime_has_identity_zero_caps_and_direct_tini() -> None:
    launcher = (ROOT / "qcsd-lab").read_text(encoding="utf-8")
    runtime_policy = launcher.split(
        'if [[ "${1:-}" == "class-study" &&\n      ! ( ( "${class_study_action}" == "capture" ||',
        maxsplit=1,
    )[1].split("\nelif [[", maxsplit=1)[0]

    # An explicit container identity is required for every writable overlay.
    # The former --user-only path then entered collection-entrypoint without
    # its required UID/GID environment and failed before the coordinator ran.
    assert '--user "$(id -u):$(id -g)"' in runtime_policy
    assert "--cap-drop ALL" in runtime_policy
    assert "--cap-add" not in runtime_policy
    assert "NET_ADMIN" not in runtime_policy
    assert "NET_RAW" not in runtime_policy
    assert "--entrypoint /usr/bin/tini" in runtime_policy
    assert "class_image_command=(-- /usr/local/bin/qcsd-lab-internal)" in runtime_policy

    # Every class-study launch site must supply the direct command after the
    # image.  The array is empty for privileged capture/resume, preserving the
    # image's normal collection-entrypoint in those two cases.
    assert "class_image_command=()" in launcher
    assert launcher.count('"${class_image_command[@]}" "${class_container_args[@]}"') == 3


def test_class_runtime_privilege_and_network_boundaries_remain_exact() -> None:
    launcher = (ROOT / "qcsd-lab").read_text(encoding="utf-8")
    runtime_policy = launcher.split(
        'if [[ "${1:-}" == "class-study" &&\n      ! ( ( "${class_study_action}" == "capture" ||',
        maxsplit=1,
    )[1].split("\nfi", maxsplit=1)[0]
    privileged_fallback = runtime_policy.rsplit("\nelse\n", maxsplit=1)[1]

    assert '"${class_study_action}" == "resume"' in runtime_policy
    assert '"${class_study_execute}" == "1"' in runtime_policy
    assert "--cap-add NET_RAW --cap-add NET_ADMIN" in privileged_fallback
    assert "--cap-add SETUID --cap-add SETGID --cap-add SETPCAP" in privileged_fallback
    assert '--env "QCSD_LAB_UID=$(id -u)"' in privileged_fallback
    assert '--env "QCSD_LAB_GID=$(id -g)"' in privileged_fallback

    network_policy = launcher.split('network_mode="bridge"', maxsplit=1)[1].split(
        'if [[ "${1:-}" == "class-study" &&', maxsplit=1
    )[0]
    assert '"${class_study_action}" != "acquisition-run"' in network_policy
    assert '"${class_study_action}" == "qualify-prefix"' in network_policy
    assert '"${class_study_live}" == "1"' in network_policy
    assert '"${class_study_action}" == "capture"' in network_policy
    assert '"${class_study_action}" == "resume"' in network_policy
    assert '"${class_study_execute}" == "1"' in network_policy
