from __future__ import annotations

from pathlib import Path

from qcsd_lab.chaff_qualification import IMPLEMENTATION_PYTHON_FILES


ROOT = Path(__file__).resolve().parents[1]


def test_docker_runtime_receipt_covers_all_python_modules_and_catalogue_tool() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    modules = tuple(sorted((ROOT / "src/qcsd_lab").rglob("*.py")))
    class_modules = tuple(path for path in modules if path.name.startswith("class_"))

    assert class_modules
    assert '*sorted((root / "src/qcsd_lab").rglob("*.py"))' in dockerfile
    assert 'path.startswith("src/qcsd_lab/class_")' in dockerfile
    assert "tools/build_class_catalogue.py" in dockerfile
    assert "COPY tools/build_class_catalogue.py ./tools/build_class_catalogue.py" in dockerfile
    assert "/usr/local/bin/qcsd-build-class-catalogue" in dockerfile
    assert "qcsd-build-class-catalogue --help >/dev/null" in dockerfile
    assert "qcsd_lab.runtime_provenance build" in dockerfile
    assert dockerfile.count("qcsd_lab.runtime_provenance verify") == 3
    assert "/usr/share/qcsd-lab/python-runtime-implementation.json" in dockerfile


def test_class_runtime_uses_separate_receipt_without_changing_qualification_schema() -> None:
    assert not any(
        Path(path).name.startswith("class_") for path in IMPLEMENTATION_PYTHON_FILES
    )
    assert "src/qcsd_lab/runtime_provenance.py" not in IMPLEMENTATION_PYTHON_FILES
    assert all((ROOT / path).is_file() for path in IMPLEMENTATION_PYTHON_FILES)


def test_prepare_and_collection_images_have_required_acquisition_and_evaluation_stacks() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    collection = dockerfile.split("FROM lab-runtime AS collection", maxsplit=1)[1].split(
        "FROM lab-runtime AS reference", maxsplit=1
    )[0]
    prepare = dockerfile.split("FROM collection AS prepare", maxsplit=1)[1]

    assert "--extra test --extra evaluation" in collection
    assert "default-jre-headless" in collection
    assert "COPY --from=weka-builder" in collection
    assert "COPY --from=osad-builder" in collection
    assert 'import sklearn; assert sklearn.__version__ == "1.9.0"' in collection
    assert "chromium fonts-liberation" in prepare
    assert "--extra test --extra evaluation --extra discovery" in prepare
    assert "import playwright.sync_api" in prepare
    assert "/usr/bin/chromium --version >/dev/null" in prepare
    assert "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium" in prepare


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
