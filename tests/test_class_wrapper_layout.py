from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qcsd_lab import class_attestation, class_layout
from qcsd_lab.class_layout import class_study_layout


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "qcsd-lab"
PYTHON_PATH = str(Path(sys.executable).parent)


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(LAUNCHER), "class-study", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _run_class_host_path(value: str) -> subprocess.CompletedProcess[str]:
    source = LAUNCHER.read_text(encoding="utf-8")
    function = source.split("class_host_path() {", maxsplit=1)[1].split(
        "\n}\n\nclass_container_path()", maxsplit=1
    )[0]
    script = f'class_host_path() {{{function}\n}}\nclass_host_path "$1"'
    return subprocess.run(
        ["bash", "-c", script, "wrapper-test", value],
        cwd=ROOT,
        env={"ROOT": str(ROOT)},
        check=False,
        capture_output=True,
        text=True,
    )


def _lock_function_source() -> str:
    source = LAUNCHER.read_text(encoding="utf-8")

    def function(name: str) -> str:
        body = source.split(f"{name}() {{", maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]
        return f"{name}() {{{body}\n}}\n"

    return function("class_require_directory") + function("class_acquire_acquisition_lock")


@pytest.mark.parametrize(
    ("arguments", "message"),
    (
        (
            ("campaigns", "--campaign-root", "config/campaigns"),
            "campaign root must use the canonical path",
        ),
        (
            (
                "cohort",
                "--stage",
                "pilot",
                "--cohort",
                "config/classifier-cohort.json",
            ),
            "cohort must use the canonical path",
        ),
        (
            (
                "fit-numeric",
                "--stage",
                "pilot",
                "--artifacts-root",
                "config",
            ),
            "artifact root must use the canonical path",
        ),
        (
            (
                "qualify-prefix",
                "--qualification-publication-root",
                "config/chaff-qualification-store",
            ),
            "qualification publication root must use the canonical path",
        ),
        (
            (
                "prefix-specs",
                "--stage",
                "pilot",
                "--numeric-bundle",
                "artifacts/classifier-multiorigin100-v1-authoritative-fitting-numeric",
            ),
            "numeric bundle must use the canonical path",
        ),
        (
            (
                "campaigns",
                "--stage",
                "authoritative",
                "--numeric-bundle",
                "artifacts/classifier-multiorigin100-v1-authoritative-fitting-numeric",
            ),
            "numeric bundle must use the canonical path",
        ),
        (
            (
                "readiness",
                "--qualification-sidecar-root",
                "config/chaff-qualification-store/sets/"
                "classifier-multiorigin100-v1-pilot120-full-v1",
            ),
            "qualification sidecar root must use the canonical path",
        ),
    ),
)
def test_wrapper_rejects_alternate_fresh_layout_paths(
    arguments: tuple[str, ...],
    message: str,
) -> None:
    result = _run(*arguments)

    assert result.returncode == 2
    assert message in result.stderr
    assert "Missing image" not in result.stderr


@pytest.mark.parametrize(
    ("arguments", "returncode", "message"),
    (
        (
            (
                "acquisition-status",
                "--acquisition-root",
                "artifacts/alternate-acquisition",
            ),
            1,
            "acquisition-status requires scoped request authority",
        ),
        (
            ("stability", "--stability-root", "artifacts/alternate-stability"),
            2,
            "stability root must use the canonical path",
        ),
    ),
)
def test_wrapper_rejects_alternate_acquisition_roots(
    arguments: tuple[str, ...], returncode: int, message: str
) -> None:
    result = _run(*arguments)

    assert result.returncode == returncode
    assert message in result.stderr


def test_class_host_path_translates_exact_container_prefix() -> None:
    accepted = _run_class_host_path("/lab/config/class-study/v1/study.json")
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout.strip() == str(ROOT / "config/class-study/v1/study.json")

    root = _run_class_host_path("/lab")
    assert root.returncode != 0
    assert "rejects the /lab container root" in root.stderr

    escaped = _run_class_host_path("/lab/../../outside")
    assert escaped.returncode != 0
    assert "outside the Lab root" in escaped.stderr


def test_acquisition_lock_accepts_the_exact_inherited_locked_descriptor(
    tmp_path: Path,
) -> None:
    (tmp_path / ".class-study-acquisition.lock").write_bytes(b"")
    script = (
        _lock_function_source()
        + r"""
exec {held_fd}<>"$1/.class-study-acquisition.lock"
flock -n "$held_fd"
QCSD_CLASS_ACQUISITION_LOCK_FD="$held_fd"
class_acquire_acquisition_lock "$1"
printf '%s\n' "$class_acquisition_lock_fd"
"""
    )
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script, "lock-test", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().isdigit()


def test_acquisition_lock_rejects_wrong_inode_symlink_and_contention(
    tmp_path: Path,
) -> None:
    function_source = _lock_function_source()
    lock = tmp_path / ".class-study-acquisition.lock"
    other = tmp_path / "other.lock"
    lock.write_bytes(b"")
    other.write_bytes(b"")
    wrong_inode = subprocess.run(
        [
            "bash",
            "-euo",
            "pipefail",
            "-c",
            function_source
            + r"""
exec {wrong_fd}<>"$1/other.lock"
flock -n "$wrong_fd"
QCSD_CLASS_ACQUISITION_LOCK_FD="$wrong_fd"
class_acquire_acquisition_lock "$1"
""",
            "lock-test",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert wrong_inode.returncode != 0
    assert "descriptor is invalid" in wrong_inode.stderr

    lock.unlink()
    lock.symlink_to(other)
    symlink = subprocess.run(
        [
            "bash",
            "-euo",
            "pipefail",
            "-c",
            function_source + 'class_acquire_acquisition_lock "$1"\n',
            "lock-test",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert symlink.returncode != 0
    assert "regular non-symlink" in symlink.stderr

    lock.unlink()
    lock.write_bytes(b"")
    contention = subprocess.run(
        [
            "bash",
            "-euo",
            "pipefail",
            "-c",
            function_source
            + r"""
exec {held_fd}<>"$1/.class-study-acquisition.lock"
flock -n "$held_fd"
unset QCSD_CLASS_ACQUISITION_LOCK_FD
class_acquire_acquisition_lock "$1"
""",
            "lock-test",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert contention.returncode != 0
    assert "holds the runner lock" in contention.stderr


@pytest.mark.parametrize(
    "arguments",
    (
        ("class-study", "--help"),
        ("class-study", "status", "--help"),
        ("buflo-study", "--help"),
        ("buflo-study", "verify", "--help"),
    ),
)
def test_nested_help_bypasses_docker_and_study_state(
    arguments: tuple[str, ...],
) -> None:
    environment = {
        "PATH": f"{PYTHON_PATH}:/usr/bin:/bin",
        "QCSD_LAB_COLLECTION_IMAGE": "deliberately-missing-help-image",
        "QCSD_LAB_PREPARE_IMAGE": "deliberately-missing-help-image",
        "QCSD_LAB_REFERENCE_IMAGE": "deliberately-missing-help-image",
    }
    result = subprocess.run(
        [str(LAUNCHER), *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "usage: qcsd-lab" in result.stdout
    if arguments == ("class-study", "--help"):
        assert "acquisition-watch" in result.stdout
    assert "Missing image" not in result.stderr
    assert "Docker" not in result.stderr


def test_acquisition_watch_help_is_host_only_and_bypasses_docker() -> None:
    environment = {
        "PATH": f"{PYTHON_PATH}:/usr/bin:/bin",
        "QCSD_LAB_COLLECTION_IMAGE": "deliberately-missing-watch-image",
        "QCSD_LAB_PREPARE_IMAGE": "deliberately-missing-watch-image",
        "QCSD_LAB_REFERENCE_IMAGE": "deliberately-missing-watch-image",
    }
    result = subprocess.run(
        [str(LAUNCHER), "class-study", "acquisition-watch", "--help"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Supervise the canonical classifier-multiorigin100-v1 acquisition" in (result.stdout)
    assert "--heartbeat-seconds" in result.stdout
    assert "Missing image" not in result.stderr
    assert "Docker" not in result.stderr


def test_acquisition_watch_delegates_only_its_supported_host_arguments() -> None:
    environment = {
        "PATH": f"{PYTHON_PATH}:/usr/bin:/bin",
        "QCSD_LAB_PREPARE_IMAGE": "deliberately-missing-watch-image",
    }
    invalid_heartbeat = subprocess.run(
        [
            str(LAUNCHER),
            "class-study",
            "acquisition-watch",
            "--heartbeat-seconds",
            "0",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    unsupported = subprocess.run(
        [str(LAUNCHER), "class-study", "acquisition-watch", "--acquisition-root", "x"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert invalid_heartbeat.returncode == 1
    assert "heartbeat must be a finite number in [1, 5]" in invalid_heartbeat.stderr
    assert "Docker" not in invalid_heartbeat.stderr
    assert unsupported.returncode == 2
    assert "unrecognized arguments: --acquisition-root x" in unsupported.stderr
    assert "Docker" not in unsupported.stderr


def test_wrapper_derives_layout_from_python_and_exempts_frozen_actions() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")

    assert "from qcsd_lab.class_layout import (" in source
    assert "    class_study_layout," in source
    assert '"campaign_root",' in source
    assert '"workload_root",' in source
    assert '"pilot_numeric_root",' in source
    assert '"authoritative_final_root",' in source
    assert '"pilot_qualification_set_root",' in source
    fresh_roles = source.split("class_fresh_layout=0", maxsplit=1)[1].split("esac", maxsplit=1)[0]
    assert "resume" not in fresh_roles
    assert "verify" not in fresh_roles


def test_prospective_contract_paths_match_the_canonical_layout() -> None:
    layout = class_study_layout()
    contract = json.loads((ROOT / "config/class-study/v1/study.json").read_text(encoding="utf-8"))[
        "canonical_workspace_layout"
    ]
    fields = {
        "config_root": layout.config_root,
        "campaign_root": layout.campaign_root,
        "workload_root": layout.workload_root,
        "study_config_root": layout.study_config_root,
        "defense_params_root": layout.defense_params_root,
        "artifacts_root": layout.artifacts_root,
        "acquisition_root": layout.acquisition_root,
        "stability_root": layout.stability_root,
        "pilot_numeric_root": layout.pilot_numeric_root,
        "pilot_final_root": layout.pilot_final_root,
        "pilot_prefix_root": layout.pilot_prefix_root,
        "authoritative_numeric_root": layout.authoritative_numeric_root,
        "authoritative_final_root": layout.authoritative_final_root,
        "authoritative_prefix_root": layout.authoritative_prefix_root,
        "qualification_sets_root": layout.qualification_sets_root,
        "pilot_qualification_set_root": layout.pilot_qualification_set_root,
        "final_qualification_set_root": layout.final_qualification_set_root,
    }

    assert contract["source"] == "qcsd_lab.class_layout"
    for field, path in fields.items():
        assert contract[field] == path.relative_to(ROOT).as_posix()
    assert contract["pilot_cohort"] == (
        "config/class-study/v1/" + class_layout.PILOT_COHORT_FILENAME
    )
    assert contract["pilot_cohort_assembly"] == (
        "config/class-study/v1/" + class_layout.PILOT_COHORT_ASSEMBLY_FILENAME
    )
    assert contract["authoritative_cohort"] == (
        "config/class-study/v1/" + class_layout.AUTHORITATIVE_COHORT_FILENAME
    )
    assert contract["authoritative_cohort_assembly"] == (
        "config/class-study/v1/" + class_layout.AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
    )
    assert contract["final_selection"] == (
        "config/class-study/v1/" + class_layout.FINAL_SELECTION_FILENAME
    )


def test_prospective_contract_tracks_current_foundation_gates() -> None:
    contract = json.loads(
        (ROOT / "config/class-study/v1/study.json").read_text(encoding="utf-8")
    )

    assert contract["authority_gates"]["foundation"]["reconstructed_gates"] == list(
        class_attestation._FOUNDATION_GATES
    )
    assert contract["authority_gates"]["acquisition"]["reconstructed_gates"] == list(
        class_attestation._ACQUISITION_AUTHORITY_GATES
    )
    assert "public-page-acquisition" not in contract["authority_gates"]["foundation"]["required_before"]
    assert contract["authority_gates"]["acquisition"]["promotion_authority"] is False


@pytest.mark.parametrize(
    ("arguments", "expected"),
    (
        (
            ("cohort", "--stage", "pilot", "--cohort", "config/class-study/v1/wrong.json"),
            "cohort must use the canonical path",
        ),
        (
            (
                "cohort",
                "--stage",
                "authoritative",
                "--cohort-assembly",
                "config/class-study/v1/wrong.json",
            ),
            "cohort assembly must use the canonical path",
        ),
        (
            (
                "campaigns",
                "--stage",
                "pilot",
                "--pilot-cohort",
                "config/class-study/v1/wrong.json",
            ),
            "pilot cohort must use the canonical path",
        ),
        (
            (
                "cohort",
                "--stage",
                "authoritative",
                "--final-selection",
                "config/class-study/v1/wrong.json",
            ),
            "final-selection must use the canonical path",
        ),
    ),
)
def test_wrapper_rejects_noncanonical_receipt_filenames(
    arguments: tuple[str, ...], expected: str
) -> None:
    result = _run(*arguments)

    assert result.returncode == 2
    assert expected in result.stderr
    assert "Missing image" not in result.stderr


def test_wrapper_requires_explicit_resumable_dlsvm_cache_before_docker() -> None:
    result = _run(
        "evaluate",
        "--handoff",
        "handoffs/classifier-multiorigin100-v1",
        "--destination",
        "artifacts/classifier-multiorigin100-v1-evaluation.json",
    )

    assert result.returncode == 2
    assert "requires --dlsvm-cache-directory" in result.stderr
    assert "Missing image" not in result.stderr


@pytest.mark.parametrize("action", ("evaluate", "comparison-review", "attest"))
def test_wrapper_requires_explicit_dlsvm_wall_budget_before_docker(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", raising=False)
    result = _run(
        action,
        "--handoff",
        "handoffs/classifier-multiorigin100-v1",
        "--destination",
        "artifacts/classifier-multiorigin100-v1-evaluation.json",
        "--dlsvm-cache-directory",
        "artifacts/classifier-multiorigin100-v1-dlsvm-cache",
    )

    assert result.returncode == 2
    assert f"class-study {action} requires QCSD_DLSVM_AVAILABLE_WALL_SECONDS" in result.stderr
    assert "Missing image" not in result.stderr


@pytest.mark.parametrize(
    "arguments",
    (
        (
            "verify",
            "--target",
            "artifacts/classifier-multiorigin100-v1-evaluation.json",
            "--handoff",
            "handoffs/classifier-multiorigin100-v1",
        ),
        (
            "status",
            "--evaluation-receipt",
            "artifacts/classifier-multiorigin100-v1-evaluation.json",
        ),
        (
            "status",
            "--comparison-review",
            "artifacts/classifier-multiorigin100-v1-comparison-review.json",
        ),
        (
            "status",
            "--validation-attestation",
            "artifacts/classifier-multiorigin100-v1-validation-attestation.json",
        ),
        (
            "verify",
            "--target",
            "artifacts/classifier-multiorigin100-v1-comparison-review.json",
        ),
        (
            "verify",
            "--target",
            "artifacts/classifier-multiorigin100-v1-validation-attestation.json",
        ),
    ),
)
def test_wrapper_requires_dlsvm_wall_budget_for_deep_replay_paths(
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
) -> None:
    monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", raising=False)
    result = _run(*arguments)

    assert result.returncode == 2
    assert "requires QCSD_DLSVM_AVAILABLE_WALL_SECONDS" in result.stderr
    assert "Missing image" not in result.stderr


@pytest.mark.parametrize("action", ("evaluate", "verify"))
def test_focused_wrapper_requires_dlsvm_wall_budget_before_docker(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", raising=False)
    result = subprocess.run(
        [str(LAUNCHER), "buflo-study", action],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert f"buflo-study {action} requires --dlsvm-wall-seconds" in result.stderr
    assert "Missing image" not in result.stderr


def test_analyze_attestation_requires_dlsvm_wall_budget_before_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("QCSD_DLSVM_AVAILABLE_WALL_SECONDS", raising=False)
    result = subprocess.run(
        [
            str(LAUNCHER),
            "analyze",
            "results/formal",
            "--validation-attestation",
            "artifacts/validation-attestation.json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "analyze --validation-attestation requires" in result.stderr
    assert "Missing image" not in result.stderr


def test_only_exact_generated_v1_config_evidence_is_ignored() -> None:
    expected_patterns = {
        "config/classifier-multiorigin100-v1-campaigns/",
        "config/chaff-qualification-store/sets/classifier-multiorigin100-v1-pilot120-full-v1/",
        "config/chaff-qualification-store/sets/classifier-multiorigin100-v1-final100-full-v1/",
        "config/class-study/v1/classifier-multiorigin100-v1-pilot-cohort.json",
        "config/class-study/v1/classifier-multiorigin100-v1-pilot-cohort-assembly.json",
        "config/class-study/v1/classifier-multiorigin100-v1-cohort.json",
        "config/class-study/v1/classifier-multiorigin100-v1-cohort-assembly.json",
        "config/class-study/v1/classifier-multiorigin100-v1-final-selection.json",
        "config/workloads/tranco-[0-9][0-9][0-9][0-9][0-9][0-9][0-9].json",
    }
    for ignore_file in (ROOT / ".gitignore", ROOT / ".dockerignore"):
        patterns = {
            line.removeprefix("/")
            for line in ignore_file.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        assert expected_patterns.issubset(patterns)
        assert "config/class-study/v1/" not in patterns
        assert "config/workloads/*.json" not in patterns

    ignored = subprocess.run(
        [
            "git",
            "check-ignore",
            "--no-index",
            "--stdin",
        ],
        cwd=ROOT,
        input="\n".join(
            (
                "config/workloads/tranco-0000001.json",
                "config/classifier-multiorigin100-v1-campaigns/formal.yml",
                "config/class-study/v1/classifier-multiorigin100-v1-pilot-cohort.json",
                "config/class-study/v1/classifier-multiorigin100-v1-cohort-assembly.json",
                "config/class-study/v1/classifier-multiorigin100-v1-final-selection.json",
                "config/chaff-qualification-store/sets/"
                "classifier-multiorigin100-v1-final100-full-v1/_qualification-set.json",
            )
        )
        + "\n",
        check=False,
        capture_output=True,
        text=True,
    )
    assert ignored.returncode == 0
    assert len(ignored.stdout.splitlines()) == 6

    for path in (
        "config/workloads/tranco-000001.json",
        "config/workloads/not-tranco-0000001.json",
        "config/classifier-multiorigin100-v2-campaigns/formal.yml",
        "config/class-study/v1/arbitrary-cohort.json",
        "config/chaff-qualification-store/sets/arbitrary/_qualification-set.json",
    ):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", path],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, path
