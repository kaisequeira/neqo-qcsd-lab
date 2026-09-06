from __future__ import annotations

import copy
import ast
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import qcsd_lab.cli as cli
from qcsd_lab.orchestrator import CampaignIncomplete
from qcsd_lab.util import atomic_text, sha256_file


def _embedded_python(launcher: str, function: str) -> str:
    body = launcher.split(f"{function}() {{", 1)[1]
    return body.split("python3 -I -c '\n", 1)[1].split('\n\' "$1"', 1)[0]


def _run_embedded_python(
    tmp_path: Path,
    code: str,
    before: dict,
    after: dict,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-c", code, str(before_path), str(after_path), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def test_internal_cli_contains_only_container_workflow_boundaries():
    choices = set(cli.parser()._subparsers._group_actions[0].choices)
    assert choices == {
        "prepare",
        "derive-chaff-prefix-specs",
        "qualify-chaff",
        "qualify-response-chaff",
        "run",
        "resume",
        "verify",
        "analyze",
        "fit",
        "buflo-study",
        "class-study",
        "test",
    }


@pytest.mark.parametrize(
    "removed",
    [
        "discover",
        "probe",
        "collect",
        "dataset",
        "doctor",
        "plot",
        "report",
    ],
)
def test_removed_or_deferred_commands_are_rejected(removed):
    with pytest.raises(SystemExit) as exit_status:
        cli.parser().parse_args([removed])
    assert exit_status.value.code == 2


def test_run_resume_and_verify_have_no_mode_flags():
    command_parsers = cli.parser()._subparsers._group_actions[0].choices
    assert {action.dest for action in command_parsers["run"]._actions} == {
        "help",
        "campaign",
    }
    assert {action.dest for action in command_parsers["resume"]._actions} == {
        "help",
        "result",
    }
    assert {action.dest for action in command_parsers["verify"]._actions} == {
        "help",
        "target",
    }
    response = command_parsers["qualify-response-chaff"]
    workload_ids = next(action for action in response._actions if action.dest == "workload_ids")
    assert workload_ids.nargs == 5
    qualification_set = next(
        action for action in response._actions if action.dest == "qualification_set"
    )
    assert qualification_set.option_strings == ["--set"]


def test_prepare_complete_coverage_is_explicit_and_opt_in():
    legacy = cli.parser().parse_args(
        ["prepare", "example", "https://page.test/", "https://page.test"]
    )
    strict = cli.parser().parse_args(
        [
            "prepare",
            "example-r2",
            "https://page.test/",
            "https://page.test",
            "https://cdn.test",
            "--require-complete-coverage",
        ]
    )

    assert legacy.require_complete_coverage is False
    assert strict.require_complete_coverage is True
    assert strict.approved_origins == ["https://page.test", "https://cdn.test"]


def test_buflo_cohort_version_is_positive_unique_and_defaults_to_one():
    assert cli.parser().parse_args(["buflo-study", "reference"]).cohort_version == 1
    assert (
        cli.parser().parse_args(
            ["buflo-study", "reference", "--cohort-version=2"]
        ).cohort_version
        == 2
    )
    for arguments in (
        ["buflo-study", "reference", "--cohort-version", "0"],
        ["buflo-study", "reference", "--cohort-version=-1"],
        ["buflo-study", "reference", "--cohort-version", "01"],
        [
            "buflo-study",
            "reference",
            "--cohort-version",
            "2",
            "--cohort-version=3",
        ],
    ):
        with pytest.raises(SystemExit) as exit_status:
            cli.parser().parse_args(arguments)
        assert exit_status.value.code == 2


def test_class_acquisition_batch_size_defaults_to_two_and_is_bounded() -> None:
    parser = cli.parser()
    assert parser.parse_args(["class-study", "acquisition-run"]).acquisition_max_candidates == 2
    assert (
        parser.parse_args(
            ["class-study", "acquisition-run", "--acquisition-max-candidates", "1"]
        ).acquisition_max_candidates
        == 1
    )
    for value in ("0", "3"):
        with pytest.raises(SystemExit) as exit_status:
            parser.parse_args(
                ["class-study", "acquisition-run", "--acquisition-max-candidates", value]
            )
        assert exit_status.value.code == 2


def test_class_foundation_cli_forwards_pinned_cdp_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    pinned = tmp_path / "pinned-cdp-execution-v23.json"
    browser_egress = tmp_path / "browser-egress-qualification-v23"
    observed: dict[str, object] = {}

    def run(action: str, **kwargs: object) -> SimpleNamespace:
        observed.update(action=action, **kwargs)
        return SimpleNamespace(
            status="complete",
            as_dict=lambda: {"action": action, "status": "complete"},
        )

    monkeypatch.setattr(pipeline, "run_class_study_action", run)

    cli.main(
        [
            "class-study",
            "foundation",
            "--pinned-cdp-receipt",
            str(pinned),
            "--browser-egress-qualification-root",
            str(browser_egress),
        ]
    )

    assert observed["action"] == "foundation"
    assert observed["pinned_cdp_receipt"] == pinned.absolute()
    assert observed["browser_egress_qualification_root"] == browser_egress.absolute()
    capsys.readouterr()


def test_class_status_cli_preserves_pilot_and_authoritative_fitting_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    observed: dict[str, object] = {}

    def run(action: str, **kwargs: object) -> SimpleNamespace:
        observed.update(action=action, **kwargs)
        return SimpleNamespace(
            status="complete",
            as_dict=lambda: {"action": action, "status": "complete"},
        )

    monkeypatch.setattr(pipeline, "run_class_study_action", run)
    artifacts = {
        "numeric": tuple(tmp_path / f"numeric-{stage}" for stage in ("pilot", "authoritative")),
        "prefix": tuple(tmp_path / f"prefix-{stage}" for stage in ("pilot", "authoritative")),
        "qualification": tuple(
            tmp_path / f"qualification-{stage}.json"
            for stage in ("pilot", "authoritative")
        ),
        "final": tuple(tmp_path / f"final-{stage}" for stage in ("pilot", "authoritative")),
    }
    arguments = ["class-study", "status"]
    for option, key in (
        ("--numeric-bundle", "numeric"),
        ("--prefix-spec-root", "prefix"),
        ("--qualification-manifest", "qualification"),
        ("--final-bundle", "final"),
    ):
        for path in artifacts[key]:
            arguments.extend((option, str(path)))

    cli.main(arguments)

    assert observed["action"] == "status"
    assert observed["numeric_bundle_roots"] == tuple(
        path.absolute() for path in artifacts["numeric"]
    )
    assert observed["prefix_spec_roots"] == tuple(
        path.absolute() for path in artifacts["prefix"]
    )
    assert observed["qualification_manifests"] == tuple(
        path.absolute() for path in artifacts["qualification"]
    )
    assert observed["final_bundle_roots"] == tuple(
        path.absolute() for path in artifacts["final"]
    )
    assert observed["numeric_bundle_root"] is None
    assert observed["prefix_spec_root"] is None
    assert observed["qualification_manifest"] is None
    assert observed["final_bundle_root"] is None
    capsys.readouterr()


def test_class_non_status_cli_rejects_repeated_singular_fitting_artifact(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as captured:
        cli.main(
            [
                "class-study",
                "prefix-specs",
                "--numeric-bundle",
                str(tmp_path / "one"),
                "--numeric-bundle",
                str(tmp_path / "two"),
            ]
        )

    assert captured.value.code == 1
    assert "accepts --numeric-bundle at most once" in capsys.readouterr().err


@pytest.mark.parametrize("action", ("prefix-specs", "qualify-prefix", "verify"))
def test_class_fitting_consumers_forward_explicit_capture_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    action: str,
) -> None:
    import qcsd_lab.class_pipeline as pipeline

    source = tmp_path / "fitting-result"
    observed: dict[str, object] = {}

    def run(selected_action: str, **kwargs: object) -> SimpleNamespace:
        observed.update(action=selected_action, **kwargs)
        return SimpleNamespace(
            status="complete",
            as_dict=lambda: {"action": selected_action, "status": "complete"},
        )

    monkeypatch.setattr(pipeline, "run_class_study_action", run)
    arguments = [
        "class-study",
        action,
        "--stage",
        "pilot",
        "--capture-result",
        str(source),
    ]
    if action == "verify":
        arguments.extend(("--target", str(tmp_path / "numeric")))
    cli.main(arguments)

    assert observed["action"] == action
    assert observed["stage"] == "pilot"
    assert observed["capture_result"] == source.absolute()
    capsys.readouterr()


def test_launcher_routes_only_consolidated_public_commands():
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    assert (
        "{lifecycle-recover|build|prepare|derive-chaff-prefix-specs|qualify-chaff|qualify-response-chaff|run|resume|verify|analyze|fit|buflo-study|class-study|etf-probe|test}"
        in launcher
    )
    assert (
        'run|resume|verify|analyze|fit|buflo-study|class-study|test) '
        'image="${COLLECTION_IMAGE}"' in launcher
    )
    assert launcher.count("start_capture_acceptance_server") == 3
    assert "ethtool -K eth0 gro off gso off tso off tx-udp-segmentation off" in launcher
    assert "--cap-drop ALL" in launcher
    assert 'network_mode="none"' in launcher
    assert '--network "${network_mode}"' in launcher
    assert "verify_fit_neqo_checkout" in launcher
    acquisition_watch = launcher.split(
        'if [[ "${1:-}" == "class-study" && "${2:-}" == "acquisition-watch" ]]', 1
    )[1].split("\nfi", 1)[0]
    assert 'exec /usr/bin/python3 -I "${ROOT}/tools/class_acquisition_watch.py"' in acquisition_watch
    assert ".venv/bin/python" not in acquisition_watch
    assert 'git -C "${ROOT}" rev-parse HEAD:neqo-qcsd' in launcher
    assert 'git -C "${ROOT}" ls-files --stage -- neqo-qcsd' in launcher
    assert 'git -C "${ROOT}/neqo-qcsd" status --porcelain --untracked-files=all' in launcher
    assert 'if [[ "${1:-}" == "fit" ]]' in launcher
    pinned_cdp = launcher.rsplit(
        'if [[ "${1:-}" == "test" && "${2:-}" == "pinned-cdp" ]]; then', 1
    )[-1].split("\nfi", 1)[0]
    assert 'image="${PREPARE_IMAGE}"' not in pinned_cdp
    assert 'QCSD_PINNED_CDP_EXPECTED_UID=${qcsd_invoking_uid}' in pinned_cdp
    assert 'QCSD_PINNED_CDP_EXPECTED_GID=${qcsd_invoking_gid}' in pinned_cdp
    assert '--entrypoint /usr/bin/tini' in pinned_cdp
    assert '/opt/qcsd-venv/bin/python3 -m qcsd_lab.pinned_cdp' in pinned_cdp
    assert '/usr/bin/timeout --signal=TERM --kill-after=10s 120s' in pinned_cdp
    assert '--build-execution-receipt "${pinned_cdp_build_container}"' in pinned_cdp
    assert '--destination "${pinned_cdp_destination_container}"' in pinned_cdp
    assert "pytest" not in pinned_cdp
    assert 'qcsd_run_attached_docker "${container[@]}"' in pinned_cdp


def test_launcher_rejects_root_split_ids_and_dac_override_before_helper_load() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(
        encoding="utf-8"
    )
    admission = launcher.split("qcsd_status_uid=()", maxsplit=1)[1].split(
        "readonly qcsd_invoking_uid qcsd_invoking_gid", maxsplit=1
    )[0]

    assert 'done </proc/self/status' in admission
    assert "${#qcsd_status_uid[@]} != 4" in admission
    assert "${#qcsd_status_gid[@]} != 4" in admission
    assert '"${qcsd_invoking_uid}" == 0' in admission
    assert '"${qcsd_invoking_gid}" == 0' in admission
    for capability in ("CapInh:", "CapPrm:", "CapEff:", "CapAmb:"):
        assert capability in admission
    assert "[2367aAbBeEfF]$" in admission
    assert "without CAP_DAC_OVERRIDE" in admission
    assert launcher.index("qcsd_status_uid=()") < launcher.index(
        'source "${DOCKER_SUPERVISOR}"'
    )


def test_lifecycle_recover_is_host_only_guarded_reconciliation() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    branch = launcher.split(
        'elif [[ "${1:-}" == "lifecycle-recover" ]]; then', 1
    )[1].split(
        'elif [[ "${1:-}" != "class-study"', 1
    )[0]
    assert branch.count("require_docker") == 1
    assert "require_submodule" not in branch
    assert "qcsd_run_" not in branch
    assert "docker " not in branch
    assert "exit 0" in branch
    assert branch.index("require_docker") < branch.index("exit 0")

    rejected = subprocess.run(
        [launcher_path, "lifecycle-recover", "unexpected"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert rejected.stderr == "lifecycle-recover accepts no arguments\n"


def test_launcher_selects_prepare_image_only_for_pinned_cdp_test() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")
    selection = launcher.split('case "${1:-}" in', 1)[1].split(
        'if ! _qcsd_docker_api image inspect', 1
    )[0]
    assert 'test) image="${COLLECTION_IMAGE}"' in selection
    assert '"${2:-}" == "pinned-cdp"' in selection
    assert 'image="${PREPARE_IMAGE}"' in selection
    fit_preflight = launcher.split("verify_fit_neqo_checkout() {", 1)[1].split("\n}", 1)[0]
    assert 'v["neqo_dirty"]' in fit_preflight
    assert 'v["neqo_patch_sha256"]' in fit_preflight
    assert 'git -C "${ROOT}" status' not in fit_preflight
    assert 'git -C "${ROOT}/neqo-qcsd" status' in fit_preflight
    assert '"${head_gitlink}" != "${image_neqo}"' in fit_preflight
    assert '"${index_gitlink}" != "${image_neqo}"' in fit_preflight

    help_result = subprocess.run(
        [launcher_path, "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0
    assert "Usage: qcsd-lab" in help_result.stderr
    assert '"${image_neqo_dirty}" != "false"' in fit_preflight
    usage_contract = launcher.split("usage() {", 1)[1].split("\n}", 1)[0]
    public_command_guards = set(re.findall(r'\[\[ "\$\{1:-\}" == "([a-z][a-z0-9-]*)"', launcher))
    for removed in ("discover", "probe", "collect", "dataset"):
        token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(token, usage_contract) is None
        assert removed not in public_command_guards
    for removed in ("--dev", "--dry-run"):
        token = rf"(?<![A-Za-z0-9_-]){re.escape(removed)}(?![A-Za-z0-9_-])"
        assert re.search(token, launcher) is None


def test_browser_egress_launcher_contract_is_canonical_and_prepare_bound() -> None:
    launcher_path = Path(__file__).parents[1] / "qcsd-lab"
    launcher = launcher_path.read_text(encoding="utf-8")

    assert '"${2:-}" == "browser-egress"' in launcher
    assert 'create|resume|verify)' in launcher
    assert (
        'browser_egress_result_relative="artifacts/buflo-study/'
        'browser-egress-qualification-v${browser_egress_cohort_version}"'
    ) in launcher
    assert (
        'browser_egress_build_relative="artifacts/buflo-study/'
        'build-execution-v${browser_egress_cohort_version}.json"'
    ) in launcher
    assert 'PREPARE_IMAGE="${browser_egress_prepare_image}"' in launcher
    assert 'verify_qualification_checkout "test browser-egress ${browser_egress_action}"' in launcher
    assert "test browser-egress create requires an absent create-only result root" in launcher
    assert "test browser-egress resume rejects a finalized qualification" not in launcher
    assert "test browser-egress verify requires final.json" not in launcher
    assert "browser_egress_reconcile_filesystem" in launcher
    assert (
        'admit-resume --cohort-version "${browser_egress_cohort_version}"' in launcher
    )
    # Python's bool is an int subclass, and integer 0/1 compare equal to
    # False/True. Both shell-side publication boundaries must nevertheless
    # require the producer's exact JSON Boolean and integer schema types.
    assert launcher.count('type(value.get("assembled")) is not bool') == 2
    assert launcher.count('type(value.get("schema_version")) is not int') >= 2

    help_result = subprocess.run(
        [launcher_path, "test", "browser-egress", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert help_result.returncode == 0
    assert help_result.stderr == ""
    assert "{create|resume|verify}" in help_result.stdout

    rejected = subprocess.run(
        [launcher_path, "test", "browser-egress", "invented"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert "requires exactly one action" in rejected.stderr


@pytest.mark.parametrize(
    ("marker", "end_marker"),
    [
        (
            'browser_egress_prevalidate_fields_output="$(python3 -I -c \'\n',
            '\n\' "${browser_egress_attempt_scratch}/prevalidate.json")"',
        ),
        (
            'browser_egress_assemble_fields_output="$(python3 -I -c \'\n',
            '\n\' "${browser_egress_attempt_scratch}/assemble.json")"',
        ),
    ],
)
def test_browser_egress_shell_publication_parsers_require_exact_json_types(
    tmp_path: Path,
    marker: str,
    end_marker: str,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    code = launcher.split(marker, maxsplit=1)[1].split(end_marker, maxsplit=1)[0]
    receipt = tmp_path / "receipt.json"

    def parse(value: dict) -> subprocess.CompletedProcess[str]:
        receipt.write_text(json.dumps(value), encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", "-c", code, str(receipt)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

    accepted = parse({"schema_version": 1, "assembled": True})
    assert accepted.returncode == 0
    assert accepted.stdout == "passed\n"
    assert accepted.stderr == ""

    for malformed in (
        {"schema_version": 1, "assembled": 1},
        {"schema_version": True, "assembled": True},
        {"schema_version": 1, "assembled": True, "unexpected": None},
    ):
        rejected = parse(malformed)
        assert rejected.returncode != 0
        assert rejected.stdout == ""
        assert "result is malformed" in rejected.stderr


def test_browser_egress_launcher_freezes_five_role_packet_topology() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    block = launcher.split(
        'if [[ "${1:-}" == "test" && "${2:-}" == "browser-egress" &&\n'
        '      ( "${browser_egress_action}" == "create" ||',
        maxsplit=1,
    )[1].split(
        'if [[ "${1:-}" == "test" && "${2:-}" == "pinned-cdp" ]]; then',
        maxsplit=1,
    )[0]

    assert "--internal --ipv6" in block
    assert "--subnet 172.30.98.0/24" in block
    assert "--subnet fd00:71:63:73:64:98::/96" in block
    assert "--dns 172.30.98.53 --dns fd00:71:63:73:64:98:0:53" in block
    for role in ("browser", "observer", "fixture", "forbidden_sink", "dns_sink"):
        assert block.count(f"--label org.qcsd.role={role}") == 1
    assert "tcp-sink" not in block
    assert "udp-sink" not in block
    assert "forbidden-sink --vector-id" in block
    assert '--network "container:${browser_egress_browser_id}" --user 0:0' in block
    assert "--cap-drop ALL --cap-add NET_RAW" in block
    assert '--user "${qcsd_invoking_uid}:${qcsd_invoking_gid}"' in block
    assert "requires a numeric non-root invoking UID and GID" in block
    assert "browser_egress_cleanup_topology" in block


def test_browser_egress_signal_coordinated_roles_are_direct_tini_children() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    role_common = launcher.split("browser_egress_role_common=(", maxsplit=1)[1].split(
        "\n    )", maxsplit=1
    )[0]
    observer = launcher.split(
        'docker run --name "${browser_egress_name_prefix}-observer"', maxsplit=1
    )[1].split(
        'docker run --name "${browser_egress_name_prefix}-fixture"', maxsplit=1
    )[0]

    assert "/usr/bin/timeout" not in role_common
    assert '"${browser_egress_tool}"' in role_common
    assert "/usr/bin/timeout" not in observer
    assert '"${browser_egress_tool}" observer' in observer
    assert "_qcsd_docker_api wait" not in launcher
    exit_wait = launcher.split(
        "browser_egress_wait_exit_code() {", maxsplit=1
    )[1].split("\n}", maxsplit=1)[0]
    assert "deadline=$((SECONDS + 120))" in exit_wait
    assert "_qcsd_docker_api container inspect --format" in exit_wait
    assert "exited|dead)" in exit_wait
    assert "exit code is invalid" in exit_wait

    tool = (
        Path(__file__).parents[1] / "tools/browser_egress_qualification.py"
    ).read_text(encoding="utf-8")
    assert "SIGNAL_COORDINATED_ROLE_DEADLINE_SECONDS = 115.0" in tool
    assert "deadline = time.monotonic() + float(timeout_seconds)" in tool
    assert "os._exit(SIGNAL_COORDINATED_ROLE_TIMEOUT_EXIT_CODE)" in tool
    assert "_run_signal_coordinated_role(args.function, args)" in tool


def test_browser_egress_internal_role_watchdog_cancels_or_exits_124() -> None:
    tool_path = Path(__file__).parents[1] / "tools/browser_egress_qualification.py"
    namespace = runpy.run_path(str(tool_path), run_name="qcsd_browser_egress_watchdog_test")
    run_role = namespace["_run_signal_coordinated_role"]
    called: list[bool] = []
    run_role(lambda _args: called.append(True), SimpleNamespace(), timeout_seconds=1)
    assert called == [True]

    expired = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy,time; "
                f"v=runpy.run_path({str(tool_path)!r},run_name='qcsd_watchdog_expiry'); "
                "v['_run_signal_coordinated_role'](lambda _: time.sleep(10),None,"
                "timeout_seconds=0.05)"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )
    assert expired.returncode == 124, (expired.stdout, expired.stderr)
    assert expired.stdout == ""
    assert expired.stderr == "browser-egress role exceeded its monotonic hard deadline\n"


def test_real_docker_tini_direct_child_receives_all_browser_egress_phase_signals() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    probe = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Docker daemon is unavailable")
    image = os.environ.get(
        "QCSD_BROWSER_EGRESS_SIGNAL_TEST_IMAGE", "neqo-qcsd-lab-prepare:local"
    )
    image_probe = subprocess.run(
        [docker, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if image_probe.returncode != 0:
        pytest.skip(f"browser-egress signal-test image is unavailable: {image}")

    name = f"qcsd-browser-egress-signal-test-{os.getpid()}-{uuid.uuid4().hex}"
    program = (
        "import json,signal,time\n"
        "seen=[]\n"
        "def receive(number, _frame):\n"
        "    name=signal.Signals(number).name\n"
        "    seen.append(name)\n"
        "    print('SIGNAL '+name,flush=True)\n"
        "for item in (signal.SIGUSR1,signal.SIGUSR2,signal.SIGHUP,signal.SIGTERM):\n"
        "    signal.signal(item,receive)\n"
        "print('READY',flush=True)\n"
        "deadline=time.monotonic()+15\n"
        "while len(seen)<4 and time.monotonic()<deadline:\n"
        "    time.sleep(0.01)\n"
        "print(json.dumps({'signals':seen},sort_keys=True),flush=True)\n"
        "raise SystemExit(0 if len(seen)==4 else 124)\n"
    )
    try:
        launched = subprocess.run(
            [
                docker,
                "run",
                "--detach",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "/usr/bin/tini",
                image,
                "--",
                "/usr/bin/python3",
                "-c",
                program,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )
        assert launched.returncode == 0, (launched.stdout, launched.stderr)
        deadline = time.monotonic() + 10
        logs = ""
        while time.monotonic() < deadline:
            logs = subprocess.run(
                [docker, "logs", name], capture_output=True, text=True, check=False
            ).stdout
            if "READY\n" in logs:
                break
            time.sleep(0.05)
        assert "READY\n" in logs

        for phase_signal in ("USR1", "USR2", "HUP", "TERM"):
            delivered = subprocess.run(
                [docker, "kill", "--signal", phase_signal, name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
            )
            assert delivered.returncode == 0, (delivered.stdout, delivered.stderr)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                logs = subprocess.run(
                    [docker, "logs", name], capture_output=True, text=True, check=False
                ).stdout
                if f"SIGNAL SIG{phase_signal}\n" in logs:
                    break
                time.sleep(0.05)
            assert f"SIGNAL SIG{phase_signal}\n" in logs

        waited = subprocess.run(
            [docker, "wait", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
        assert waited.returncode == 0 and waited.stdout == "0\n", (
            waited.stdout,
            waited.stderr,
        )
        final_logs = subprocess.run(
            [docker, "logs", name], capture_output=True, text=True, check=False
        ).stdout.splitlines()
        assert json.loads(final_logs[-1]) == {
            "signals": ["SIGUSR1", "SIGUSR2", "SIGHUP", "SIGTERM"]
        }
    finally:
        subprocess.run(
            [docker, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )


def test_browser_egress_observer_protocol_copies_closed_pcap_before_exit() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    measured = launcher.split(
        '_qcsd_docker_api kill --signal USR2 "${browser_egress_observer_id}"',
        maxsplit=1,
    )[1].split(
        '_qcsd_docker_api logs "${browser_egress_browser_id}"',
        maxsplit=1,
    )[0]

    grace = measured.index("qcsd-browser-egress-grace.ready")
    fixture_stop = measured.index(
        'for browser_egress_role_id in "${browser_egress_fixture_id}"'
    )
    finish = measured.index('kill --signal HUP "${browser_egress_observer_id}"')
    receipt = measured.index("qcsd-browser-egress-receipt.ready")
    copy = measured.index(
        'cp "${browser_egress_observer_id}:/tmp/capture.pcapng"'
    )
    stop = measured.index('kill --signal TERM "${browser_egress_observer_id}"')
    wait = measured.index(
        'browser_egress_observer_exit="$(browser_egress_wait_exit_code'
    )
    assert grace < fixture_stop < finish < receipt < copy < stop < wait


def test_browser_egress_staged_readiness_and_subject_ack_are_ordered(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    vector_loop = launcher.split(
        'browser_egress_policy_volume_name=""', maxsplit=1
    )[1].split("    browser_egress_finished_at=", maxsplit=1)[0]
    cursor = 0
    for role, variable in (
        ("browser", "browser_egress_browser_id"),
        ("observer", "browser_egress_observer_id"),
        ("fixture", "browser_egress_fixture_id"),
        ("forbidden_sink", "browser_egress_forbidden_id"),
        ("dns_sink", "browser_egress_dns_id"),
    ):
        launch = vector_loop.index(f"--label org.qcsd.role={role}", cursor)
        ready = vector_loop.index(
            f'browser_egress_wait_healthy "${{{variable}}}"', launch
        )
        assert launch < ready
        cursor = ready
    observer_signal = vector_loop.index(
        'kill --signal USR1 "${browser_egress_observer_id}"', cursor
    )
    subject_ack = vector_loop.index(
        "/tmp/qcsd-browser-egress-subject-started.ready", observer_signal
    )
    browser_signal = vector_loop.index(
        'kill --signal USR1 "${browser_egress_browser_id}"', subject_ack
    )
    assert cursor < observer_signal < subject_ack < browser_signal

    healthy = "browser_egress_wait_healthy() {" + launcher.split(
        "browser_egress_wait_healthy() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_cleanup_topology()", maxsplit=1)[0] + "\n}\n"
    marker = "browser_egress_wait_container_marker() {" + launcher.split(
        "browser_egress_wait_container_marker() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_wait_exit_code()", maxsplit=1)[0] + "\n}\n"
    log = tmp_path / "barriers.log"
    script = tmp_path / "barriers.sh"
    script.write_text(
        "set -euo pipefail\n"
        + healthy
        + marker
        + f"LOG={str(log)!r}\n"
        + "_qcsd_docker_api() {\n"
        + "  if [[ \"$1 $2\" == \"container inspect\" ]]; then\n"
        + "    if [[ \"$3\" == \"--format\" && \"$4\" == *Health* ]]; then\n"
        + "      sleep 0.15; echo healthy\n"
        + "    else echo running; fi\n"
        + "  elif [[ \"$1\" == exec ]]; then\n"
        + "    sleep 0.15; return 0\n"
        + "  else return 2; fi\n"
        + "}\n"
        + "for role in browser observer fixture forbidden dns; do\n"
        + "  browser_egress_wait_healthy \"$role\"\n"
        + "  echo \"ready-$role\" >>\"$LOG\"\n"
        + "done\n"
        + "echo observer-signal >>\"$LOG\"\n"
        + "browser_egress_wait_container_marker observer /tmp/marker subject\n"
        + "echo subject-ack >>\"$LOG\"\n"
        + "echo browser-signal >>\"$LOG\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        "ready-browser",
        "ready-observer",
        "ready-fixture",
        "ready-forbidden",
        "ready-dns",
        "observer-signal",
        "subject-ack",
        "browser-signal",
    ]


def test_browser_egress_policy_volume_and_fixture_tls_shell_contract_is_exact() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    vector_loop = launcher.split(
        'browser_egress_policy_volume_name=""', maxsplit=1
    )[1].split("    browser_egress_finished_at=", maxsplit=1)[0]
    mask = (
        "--tmpfs /opt/qcsd-lab/config/class-study/v1:"
        "ro,nosuid,nodev,noexec,mode=000"
    )

    assert "_qcsd_docker_api volume create" in vector_loop
    assert vector_loop.index("QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES+=(") < (
        vector_loop.index("_qcsd_docker_api volume create")
    )
    assert "--label org.qcsd.role=policy_volume" in vector_loop
    assert "--network none" in vector_loop
    assert "--label org.qcsd.role=policy_seed" in vector_loop
    assert '--user 0:0' in vector_loop
    assert "--cap-drop ALL --security-opt no-new-privileges:true --read-only" in vector_loop
    assert '--volume "${browser_egress_policy_volume_name}:/qcsd-policy:rw"' in vector_loop
    assert (
        '--volume "${browser_egress_policy_volume_name}:'
        '/etc/chromium/policies/managed:ro"'
    ) in vector_loop
    assert "install -o 0 -g 0 -m 0444" in vector_loop
    assert "sync -f \"$target\"" in vector_loop
    assert vector_loop.count(mask) == 5

    fixture_launch = vector_loop.split(
        '--label org.qcsd.role=fixture', maxsplit=1
    )[0].rsplit("qcsd_run_detached_docker", maxsplit=1)[1]
    assert mask not in fixture_launch
    for role in ("browser", "observer", "forbidden_sink", "dns_sink"):
        role_marker = f"--label org.qcsd.role={role}"
        role_launch = vector_loop.split(role_marker, maxsplit=1)[0].rsplit(
            "qcsd_run_detached_docker", maxsplit=1
        )[1]
        assert mask in role_launch

    volume_inspect = vector_loop.index(
        '_qcsd_docker_api volume inspect "${browser_egress_policy_volume_name}"'
    )
    runtime_projection = vector_loop.index("project-runtime")
    assert volume_inspect < runtime_projection

    cleanup = launcher.split("browser_egress_cleanup_topology() {", maxsplit=1)[1].split(
        "\n}\n\nbrowser_egress_exit_cleanup()", maxsplit=1
    )[0]
    assert cleanup.index("network rm") < cleanup.index("volume rm")
    assert "volume ls --quiet" in cleanup
    assert '--filter "name=^${volume_name}$"' in cleanup


def test_browser_egress_live_daemon_is_admitted_at_every_evidence_boundary() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")

    projection = launcher.split(
        "browser_egress_live_docker_binding() {", maxsplit=1
    )[1].split("\n}", maxsplit=1)[0]
    assert "_qcsd_docker_api version --format '{{json .}}'" in projection
    assert "_qcsd_docker_api info --format '{{json .}}'" in projection
    assert "live-docker-binding" in projection
    assert '"${_QCSD_DOCKER_PINNED_CONTEXT}"' in projection
    assert '"${_QCSD_DOCKER_PINNED_HOST}"' in projection
    assert '"${_QCSD_DOCKER_PINNED_SERVER_ID}"' in projection

    assert launcher.count(
        '--live-docker-json "${browser_egress_live_docker_json}"'
    ) == 7
    assert (
        'browser_egress_live_docker_json="$(browser_egress_live_docker_binding)"'
        in launcher
    )


def test_browser_egress_stale_topology_wrapper_retires_only_validated_ids(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = "browser_egress_retire_stale_topology() {" + launcher.split(
        "browser_egress_retire_stale_topology() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_record_failed_attempt()", maxsplit=1)[0] + "\n}\n"
    observer = "1" * 64
    browser = "2" * 64
    network = "3" * 64
    state = tmp_path / "state"
    state.mkdir()
    (state / observer).touch()
    (state / browser).touch()
    (state / network).touch()
    log = tmp_path / "removed.log"
    script = tmp_path / "stale-wrapper.sh"
    script.write_text(
        "set -euo pipefail\n"
        + function
        + f"STATE={str(state)!r}\nLOG={str(log)!r}\n"
        + f"OBSERVER={observer!r}\nBROWSER={browser!r}\nNETWORK={network!r}\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\nimage_id=image\n"
        + "_qcsd_docker_api() {\n"
        + "  if [[ \"$1 $2\" == \"ps --all\" ]]; then\n"
        + "    [[ ! -e \"$STATE/$OBSERVER\" ]] || echo \"$OBSERVER\"\n"
        + "    [[ ! -e \"$STATE/$BROWSER\" ]] || echo \"$BROWSER\"\n"
        + "  elif [[ \"$1 $2\" == \"container inspect\" ]]; then echo '[]'\n"
        + "  elif [[ \"$1 $2\" == \"container rm\" && \"$3\" == \"--force\" ]]; then\n"
        + "    [[ \"$4\" == \"$OBSERVER\" || \"$4\" == \"$BROWSER\" ]]\n"
        + "    echo \"container $4\" >>\"$LOG\"; rm \"$STATE/$4\"\n"
        + "  elif [[ \"$1 $2\" == \"network ls\" ]]; then\n"
        + "    [[ ! -e \"$STATE/$NETWORK\" ]] || echo \"$NETWORK\"\n"
        + "  elif [[ \"$1 $2\" == \"network inspect\" ]]; then\n"
        + "    [[ -e \"$STATE/$NETWORK\" ]] || return 1; echo '[{}]'\n"
        + "  elif [[ \"$1 $2\" == \"network rm\" ]]; then\n"
        + "    [[ \"$3\" == \"$NETWORK\" ]]; echo \"network $3\" >>\"$LOG\"; rm \"$STATE/$3\"\n"
        + "  elif [[ \"$1 $2\" == \"volume ls\" ]]; then :\n"
        + "  else return 2; fi\n"
        + "}\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n output=$1\n"
        + "  output=\"{\\\"schema_version\\\":1,\\\"container_ids\\\":[\\\"$OBSERVER\\\",\\\"$BROWSER\\\"],\\\"network_id\\\":\\\"$NETWORK\\\",\\\"volume_name\\\":null}\"\n"
        + "}\n"
        + "qcsd_run_attached_docker() { return 99; }\n"
        + "browser_egress_retire_stale_topology '{\"schema_version\":1}'\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"container {observer}",
        f"container {browser}",
        f"network {network}",
    ]
    assert "prune" not in function


def test_browser_egress_stale_topology_wrapper_retires_bound_policy_volume_last(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = "browser_egress_retire_stale_topology() {" + launcher.split(
        "browser_egress_retire_stale_topology() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_record_failed_attempt()", maxsplit=1)[0] + "\n}\n"
    container = "1" * 64
    network = "2" * 64
    volume = f"qcsd-be-{'3' * 32}-policy0"
    state = tmp_path / "state"
    state.mkdir()
    for name in (container, network, volume):
        (state / name).touch()
    log = tmp_path / "removed.log"
    script = tmp_path / "stale-volume-wrapper.sh"
    script.write_text(
        "set -euo pipefail\n"
        + function
        + f"STATE={str(state)!r}\nLOG={str(log)!r}\n"
        + f"CONTAINER={container!r}\nNETWORK={network!r}\nVOLUME={volume!r}\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\nimage_id=image\n"
        + "_qcsd_docker_api() {\n"
        + "  if [[ \"$1 $2\" == \"ps --all\" ]]; then\n"
        + "    [[ ! -e \"$STATE/$CONTAINER\" ]] || echo \"$CONTAINER\"\n"
        + "  elif [[ \"$1 $2\" == \"container inspect\" ]]; then echo '[]'\n"
        + "  elif [[ \"$1 $2\" == \"container rm\" && \"$3\" == \"--force\" ]]; then\n"
        + "    [[ \"$4\" == \"$CONTAINER\" ]]; echo \"container $4\" >>\"$LOG\"; rm \"$STATE/$4\"\n"
        + "  elif [[ \"$1 $2\" == \"network ls\" ]]; then\n"
        + "    [[ ! -e \"$STATE/$NETWORK\" ]] || echo \"$NETWORK\"\n"
        + "  elif [[ \"$1 $2\" == \"network inspect\" ]]; then echo '[{}]'\n"
        + "  elif [[ \"$1 $2\" == \"network rm\" ]]; then\n"
        + "    echo \"network $3\" >>\"$LOG\"; rm \"$STATE/$3\"\n"
        + "  elif [[ \"$1 $2\" == \"volume ls\" ]]; then\n"
        + "    [[ ! -e \"$STATE/$VOLUME\" ]] || echo \"$VOLUME\"\n"
        + "  elif [[ \"$1 $2\" == \"volume inspect\" ]]; then echo '[{}]'\n"
        + "  elif [[ \"$1 $2\" == \"volume rm\" ]]; then\n"
        + "    echo \"volume $3\" >>\"$LOG\"; rm \"$STATE/$3\"\n"
        + "  else return 2; fi\n"
        + "}\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n output=$1\n"
        + "  output=\"{\\\"schema_version\\\":1,\\\"container_ids\\\":[\\\"$CONTAINER\\\"],\\\"network_id\\\":\\\"$NETWORK\\\",\\\"volume_name\\\":\\\"$VOLUME\\\"}\"\n"
        + "}\n"
        + "browser_egress_retire_stale_topology '{\"schema_version\":1}'\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"container {container}",
        f"network {network}",
        f"volume {volume}",
    ]


def test_browser_egress_cleanup_returns_and_err_path_seals_after_cleanup(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    cleanup = "browser_egress_cleanup_topology() {" + launcher.split(
        "browser_egress_cleanup_topology() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_exit_cleanup()", maxsplit=1)[0] + "\n}\n"
    record = "browser_egress_record_failed_attempt() {" + launcher.split(
        "browser_egress_record_failed_attempt() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_live_docker_json=", maxsplit=1)[0] + "\n}\n"

    normal = tmp_path / "normal-cleanup.sh"
    normal.write_text(
        "set -euo pipefail\n"
        + cleanup
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(c1)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=(n1)\n"
        + "_qcsd_docker_api() { :; }\n"
        + "qcsd_retire_docker_handoff() { :; }\n"
        + "browser_egress_cleanup_topology\n"
        + "echo vector-2-proceeded\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(normal)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "vector-2-proceeded\n"

    result_root = tmp_path / "result"
    attempt = result_root / "evidence/001--constructor--page--websocket/attempt-1"
    attempts = result_root / "attempts"
    scratch = tmp_path / "scratch"
    attempt.mkdir(parents=True)
    attempts.mkdir()
    scratch.mkdir()
    (scratch / "next.json").write_text("{}\n", encoding="utf-8")
    log = tmp_path / "failure-order.log"
    failed = tmp_path / "err-cleanup.sh"
    failed.write_text(
        "set -Eeuo pipefail\n"
        + cleanup
        + record
        + f"LOG={str(log)!r}\nROOT=/lab\nimage_id=image\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + f"browser_egress_result_host={str(result_root)!r}\n"
        + "browser_egress_result_container=/lab/result\n"
        + f"browser_egress_attempt_evidence_host={str(attempt)!r}\n"
        + f"browser_egress_evidence_host={str(attempt / 'capture.pcapng')!r}\n"
        + f"browser_egress_scratch={str(scratch)!r}\n"
        + f"browser_egress_attempt_scratch={str(scratch)!r}\n"
        + "browser_egress_causal_inputs_ready=0\n"
        + "browser_egress_vector_ordinal=1\n"
        + "browser_egress_vector_id=constructor--page--websocket\n"
        + "browser_egress_attempt_number=1\n"
        + "browser_egress_started_at=2026-09-06T00:00:00Z\n"
        + "browser_egress_failure_verdict=operational-failure\n"
        + "browser_egress_failure_code=docker-start-failed\n"
        + "browser_egress_failure_stage=network-create\n"
        + "browser_egress_tool=/tool\n"
        + "browser_egress_browser_id=\n"
        + "browser_egress_observer_id=\n"
        + "browser_egress_fixture_id=\n"
        + "browser_egress_forbidden_id=\n"
        + "browser_egress_dns_id=\n"
        + "browser_egress_network_id=\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(stale)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=()\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=()\n"
        + "_qcsd_docker_api() { echo cleanup >>\"$LOG\"; }\n"
        + "qcsd_retire_docker_handoff() { :; }\n"
        + "browser_egress_preserve_causal_evidence() { :; }\n"
        + "qcsd_run_attached_docker() { echo record-failure >>\"$LOG\"; }\n"
        + "trap browser_egress_record_failed_attempt ERR\n"
        + "false\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(failed)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == [
        "cleanup",
        "record-failure",
    ]

    no_seal = tmp_path / "err-cleanup-no-seal.sh"
    no_seal_text = failed.read_text(encoding="utf-8").replace(
        "qcsd_retire_docker_handoff() { :; }",
        "qcsd_retire_docker_handoff() { return 1; }",
    )
    assert no_seal_text != failed.read_text(encoding="utf-8")
    no_seal.write_text(no_seal_text, encoding="utf-8")
    log.unlink()
    completed = subprocess.run(
        ["bash", str(no_seal)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert log.read_text(encoding="utf-8").splitlines() == ["cleanup"]
    assert "left its attempt outstanding after teardown failed" in completed.stderr


def test_browser_egress_cleanup_retains_every_unproved_docker_identity(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    cleanup = "browser_egress_cleanup_topology() {" + launcher.split(
        "browser_egress_cleanup_topology() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_exit_cleanup()", maxsplit=1)[0] + "\n}\n"
    script = tmp_path / "retained-cleanup.sh"
    script.write_text(
        "set -euo pipefail\n"
        + cleanup
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=(c1 c2)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=(n1)\n"
        + "QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=(v1)\n"
        + "_qcsd_docker_api() {\n"
        + "  if [[ \"$1 $2\" == \"volume ls\" ]]; then echo v1; return 0; fi\n"
        + "  return 1\n"
        + "}\n"
        + "qcsd_retire_docker_handoff() { [[ \"$2\" == c2 ]]; }\n"
        + "if browser_egress_cleanup_topology; then exit 90; fi\n"
        + "printf 'containers=%s\\n' \"${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[*]}\"\n"
        + "printf 'networks=%s\\n' \"${QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS[*]}\"\n"
        + "printf 'volumes=%s\\n' \"${QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES[*]}\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout.splitlines() == [
        "containers=c1",
        "networks=n1",
        "volumes=v1",
    ]


def test_browser_egress_causal_promotion_is_idempotent_and_rejects_substitution(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    preserve = "browser_egress_preserve_causal_evidence() {" + launcher.split(
        "browser_egress_preserve_causal_evidence() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_record_failed_attempt()", maxsplit=1)[0] + "\n}\n"
    vector_id = "constructor--page--websocket"
    source = tmp_path / "attempt-input"
    evidence = tmp_path / "attempt-evidence"
    source.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    for name in ("actor", "capture", "dns", "fixture", "forbidden", "runtime"):
        value = {"schema_version": 1, "name": name}
        if name != "runtime":
            value["vector_id"] = vector_id
        (source / f"{name}.json").write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    # Model death after the first create-only publication.  The exact matching
    # file is accepted and the remaining finite inventory is completed.
    first = (source / "actor.json").read_bytes()
    (evidence / "causal-actor.json").write_bytes(first)
    (evidence / "causal-actor.json").chmod(0o600)
    script = tmp_path / "promote.sh"
    script.write_text(
        "set -euo pipefail\n"
        + preserve
        + "browser_egress_causal_inputs_ready=1\n"
        + f"browser_egress_attempt_scratch={str(source)!r}\n"
        + f"browser_egress_attempt_evidence_host={str(evidence)!r}\n"
        + f"browser_egress_vector_id={vector_id!r}\n"
        + "browser_egress_preserve_causal_evidence\n",
        encoding="utf-8",
    )
    for _ in range(2):
        completed = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
        )
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert sorted(path.name for path in evidence.iterdir()) == [
        "causal-actor.json",
        "causal-capture.json",
        "causal-dns.json",
        "causal-fixture.json",
        "causal-forbidden.json",
        "causal-runtime.json",
    ]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in evidence.iterdir())

    (evidence / "causal-actor.json").unlink()
    (evidence / "causal-actor.json").symlink_to(source / "actor.json")
    rejected = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert rejected.returncode != 0
    assert "causal evidence conflicts" in rejected.stderr
    assert (source / "actor.json").exists()


def test_browser_egress_resume_chronology_and_phase_mounts_are_fail_closed() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    block = launcher.split("browser_egress_coordinator_prefix=(", maxsplit=1)[1].split(
        'if [[ "${1:-}" == "test" && "${2:-}" == "pinned-cdp" ]]', maxsplit=1
    )[0]
    prefix = block.split("browser_egress_coordinator_suffix=(", maxsplit=1)[0]
    assert "browser_egress_result_host" not in prefix
    assert "browser_egress_coordinator_base" not in block
    assert (
        '--volume "${browser_egress_result_host}:${browser_egress_result_container}:ro"'
        in block
    )
    assert (
        '--volume "${browser_egress_result_host}/attempt-intents:'
        '${browser_egress_result_container}/attempt-intents:rw"'
        in block
    )
    assert "browser_egress_prior_intent" in block
    assert "browser_egress_recovery_mounts" in block
    assert "browser_egress_recovery_attempt_host" in block
    assert "browser_egress_recovery_result" in block

    reconcile = block.index("browser_egress_reconcile_filesystem")
    admit = block.index("admit-resume --cohort-version")
    retire = block.index("browser_egress_retire_stale_topology")
    recover = block.index("recover-resume --cohort-version")
    next_vector = block.index('"${browser_egress_coordinator_suffix[@]}" next')
    begin = block.index("begin-attempt --result-root")
    network = block.index("docker network create")
    runtime = block.index("project-runtime")
    prevalidate = block.index('"${browser_egress_tool}" assemble', runtime)
    teardown = block.index("browser_egress_cleanup_topology || false", runtime)
    assemble = block.index('"${browser_egress_tool}" assemble', prevalidate + 1)
    assert reconcile < admit < retire < recover < next_vector < begin < network
    assert runtime < prevalidate < teardown < assemble
    assert "--validate-only" in block[runtime:teardown]
    assert "attempt-status" in block[assemble:]
    assert (
        block.index("browser_egress_causal_inputs_ready=0", assemble)
        < block.index("attempt-status", assemble)
        < block.index("browser_egress_causal_inputs_ready=1", assemble)
    )
    assert "qcsd_run_attached_docker docker container rm" not in launcher
    assert "_qcsd_docker_api container rm --force" in launcher


@pytest.mark.parametrize("residue_kind", ("none", "intent", "recovery"))
def test_browser_egress_reconcile_mounts_are_phase_minimal(
    tmp_path: Path, residue_kind: str
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    function = "browser_egress_reconcile_filesystem() {" + launcher.split(
        "browser_egress_reconcile_filesystem() {", maxsplit=1
    )[1].split("\n}\n\nbrowser_egress_retire_stale_topology()", maxsplit=1)[0] + "\n}\n"
    root = tmp_path / "qualification"
    for directory in (root, root / "attempts", root / "attempt-intents", root / "evidence"):
        directory.mkdir(mode=0o700)
    (root / "foundation.json").write_text("{}\n", encoding="utf-8")
    (root / "experiment.json").write_text("{}\n", encoding="utf-8")
    if residue_kind == "intent":
        (root / "attempt-intents/.intent-0001.json.deadbeef.qcsd-tmp").write_text(
            "{}\n", encoding="utf-8"
        )
    elif residue_kind == "recovery":
        recovery = root / (
            "evidence/001--constructor--page--websocket/attempt-1/"
            ".resume-recovery.json.deadbeef.qcsd-tmp"
        )
        recovery.parent.mkdir(mode=0o700, parents=True)
        recovery.write_text("{}\n", encoding="utf-8")
    log = tmp_path / "argv.log"
    script = (
        "set -euo pipefail\n"
        + function
        + f"browser_egress_result_host={str(root)!r}\n"
        + "browser_egress_result_container=/lab/result\n"
        + "browser_egress_cohort_version=71\n"
        + "browser_egress_build_container=/lab/build.json\n"
        + "browser_egress_live_docker_json='{}'\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + "image_id=sha256:test\nROOT=/lab\n"
        + f"LOG={str(log)!r}\n"
        + "qcsd_run_attached_docker() { printf '%s\\n' \"$@\" >\"$LOG\"; }\n"
        + "browser_egress_reconcile_filesystem\n"
    )
    completed = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, completed.stderr
    arguments = log.read_text(encoding="utf-8").splitlines()
    if residue_kind == "none":
        assert f"{root}:/lab/result:ro" in arguments
        assert f"{root}:/lab/result:rw" not in arguments
    else:
        assert f"{root}:/lab/result:rw" in arguments
        assert f"{root / 'evidence'}:/lab/result/evidence:ro" in arguments
        assert f"{root / 'attempts'}:/lab/result/attempts:ro" in arguments
        if residue_kind == "intent":
            assert (
                f"{root / 'attempt-intents'}:/lab/result/attempt-intents:ro"
                not in arguments
            )
        else:
            assert (
                f"{root / 'attempt-intents'}:/lab/result/attempt-intents:ro"
                in arguments
            )
            assert (
                f"{recovery.parent}:"
                "/lab/result/evidence/001--constructor--page--websocket/attempt-1:rw"
                in arguments
            )
        assert f"{root / 'foundation.json'}:/lab/result/foundation.json:ro" in arguments
        assert f"{root / 'experiment.json'}:/lab/result/experiment.json:ro" in arguments


def test_browser_egress_ledger_writes_protect_prior_evidence() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")

    assert "browser_egress_foundation_mounts" in launcher
    assert 'find "${browser_egress_result_parent}" -mindepth 1 -maxdepth 1 -print0' in launcher
    assert "browser_egress_append_mounts" in launcher
    assert (
        '"${browser_egress_result_host}/foundation.json:'
        '${browser_egress_result_container}/foundation.json:ro"'
    ) in launcher
    assert (
        '"${browser_egress_result_host}/evidence:'
        '${browser_egress_result_container}/evidence:ro"'
    ) in launcher
    assert "browser_egress_finalize_mounts" in launcher
    assert "browser_egress_record_failed_attempt" in launcher
    assert '"${browser_egress_attempt_evidence_host}:' in launcher
    assert "record-failure" in launcher
    assert "trap browser_egress_record_failed_attempt ERR" in launcher
    assert "umask 077" in launcher
    assert 'mkdir --mode=0700 -- "${browser_egress_attempt_evidence_host}"' in launcher
    assert 'chmod 0600 -- "${browser_egress_evidence_host}"' in launcher


def test_browser_egress_tool_freezes_execution_verification_and_role_phases() -> None:
    tool = (
        Path(__file__).parents[1] / "tools/browser_egress_qualification.py"
    ).read_text(encoding="utf-8")

    assert tool.count("FoundationVerificationMode.EXECUTION") >= 2
    assert "FoundationVerificationMode.PORTABLE_REPLAY" not in tool
    assert 'commands.add_parser("record-failure")' in tool
    assert 'commands.add_parser("reconcile-filesystem")' in tool
    assert 'GRACE_READY_PATH.write_text("ready\\n"' in tool
    assert 'RECEIPT_READY_PATH.write_text("ready\\n"' in tool
    observer = tool.split("def _observer(", maxsplit=1)[1].split(
        "\ndef _foundation(", maxsplit=1
    )[0]
    assert observer.index("observer.mark_reporting_grace_finished()") < observer.index(
        "_wait(finish_capture)"
    ) < observer.index("observer.finish(") < observer.index("_wait(stopped)")
    assert "BrowserFixtureServer(" in tool and "vector=vector" in tool
    assert "combine_sink_receipt(" in tool
    assert '"role": "fixture"' in tool
    assert '"dns_servers": host.get("Dns") or []' in tool
    assert 'expected_raw_cap_add = ["CAP_NET_RAW"] if role == "observer" else []' in tool
    assert "raw_cap_add != expected_raw_cap_add" in tool
    assert "~NOTFOUND" not in tool
    assert tool.count("launch_qualification_browser(") == 1
    tree = ast.parse(tool)
    forbidden_launch_attributes = {
        "launch",
        "launch_persistent_context",
        "connect",
        "connect_over_cdp",
    }
    assert not [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_launch_attributes
    ]
    assert '"arguments": effective_arguments["arguments"]' not in tool
    assert '"--no-sandbox",' not in tool
    assert "_BROWSER_SERVICE_EXPRESSION" not in tool
    assert "execute_live_browser_action(vector=vector, realm=realm)" in tool
    assert "['fixture_http']" not in tool
    assert 'page.goto(f"{primary}/", wait_until="load")' in tool
    actor = tool.split("def _actor(", maxsplit=1)[1].split(
        "\nclass _PlaywrightRealm", maxsplit=1
    )[0]
    assert actor.index("_launch_vector_browser(") < actor.index(
        "browser.new_context("
    )
    assert "browser_configuration_observation" in tool
    assert 'projection["observed_required_switches"].count(' in tool
    assert 'vector.surface == "reporting-nel-live"' in tool
    assert 'output["reporting_live_dwell_finished_ns"]' in tool
    assert 'times["browser-started"] = actor["browser_started_ns"]' in tool
    assert 'times["browser-exited"] = actor["browser_exited_ns"]' in tool


@pytest.mark.parametrize(
    ("published", "verdict"),
    ((False, None), (True, "passed"), (True, "operational-failure")),
)
def test_browser_egress_attempt_status_reports_only_the_exact_ledger_head(
    monkeypatch: pytest.MonkeyPatch,
    published: bool,
    verdict: str | None,
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_attempt_status_test",
    )
    function = namespace["_attempt_status"]
    globals_ = function.__globals__
    vector = globals_["vector_by_id"]("constructor--page--websocket")
    plan = {
        "schema_version": 1,
        "complete": False,
        "vector": vector.as_dict(),
        "global_ordinal": 1,
        "attempt_number": 1,
        "previous_result_sha256": "0" * 64,
    }
    attempts = []
    if published:
        attempts.append(
            {
                "global_ordinal": 1,
                "attempt_number": 1,
                "vector_id": vector.vector_id,
                "verdict": verdict,
            }
        )
    checkpoint = {
        "status": "running",
        "next_vector_ordinal": 1 if not published else 2,
        "chain_head_sha256": "0" * 64,
        "attempts": attempts,
    }
    monkeypatch.setitem(globals_, "_object", lambda *args, **kwargs: plan)
    monkeypatch.setitem(globals_, "load_checkpoint", lambda *args, **kwargs: checkpoint)
    emitted: list[dict] = []
    monkeypatch.setitem(globals_, "_emit", emitted.append)
    function(
        SimpleNamespace(
            result_root=Path("/result"),
            next_json=Path("/next.json"),
            vector_id=vector.vector_id,
        )
    )
    assert emitted == [
        {
            "schema_version": 1,
            "published": published,
            "verdict": verdict,
            "checkpoint": checkpoint,
        }
    ]


def test_browser_egress_lost_append_and_status_output_cannot_contaminate_evidence(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    flow = "browser_egress_assemble_command_status=0" + launcher.split(
        "browser_egress_assemble_command_status=0", maxsplit=1
    )[1].split("    trap - ERR\n    rm -rf", maxsplit=1)[0] + "    trap - ERR\n"
    scratch = tmp_path / "attempt"
    scratch.mkdir()
    (scratch / "next.json").write_text("{}\n", encoding="utf-8")
    err_marker = tmp_path / "err-handler-ran"
    causal_state = tmp_path / "causal-state"
    script = tmp_path / "lost-output.sh"
    script.write_text(
        "set -Eeuo pipefail\n"
        + f"ERR_MARKER={str(err_marker)!r}\nCAUSAL_STATE={str(causal_state)!r}\n"
        + "trap 'touch \"$ERR_MARKER\"' ERR\n"
        + "trap 'printf \"%s\\n\" \"$browser_egress_causal_inputs_ready\" >\"$CAUSAL_STATE\"' EXIT\n"
        + "qcsd_invoking_uid=1000\nqcsd_invoking_gid=1000\n"
        + "image_id=image\nROOT=/lab\nbrowser_egress_tool=/tool\n"
        + "browser_egress_result_container=/lab/result\n"
        + f"browser_egress_attempt_scratch={str(scratch)!r}\n"
        + "browser_egress_append_mounts=()\n"
        + "browser_egress_vector_id=constructor--page--websocket\n"
        + "browser_egress_started_at=2026-09-06T00:00:00Z\n"
        + "browser_egress_finished_at=2026-09-06T00:00:01Z\n"
        + "browser_egress_causal_inputs_ready=1\n"
        + "browser_egress_failure_verdict=semantic-failure\n"
        + "browser_egress_failure_code=semantic-observation-failed\n"
        + "browser_egress_failure_stage=result-assembly\n"
        + "qcsd_capture_attached_docker_output() {\n"
        + "  local -n captured=$1; shift; captured=''\n"
        + "  [[ \" $* \" != *' attempt-status '* ]] || return 73\n"
        + "  return 72\n"
        + "}\n"
        + flow,
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 1, (completed.stdout, completed.stderr)
    assert not err_marker.exists()
    assert causal_state.read_text(encoding="utf-8") == "0\n"
    assert not list(tmp_path.rglob("causal-*.json"))
    assert "could not reconcile ambiguous result publication" in completed.stderr


def test_browser_egress_projection_accepts_only_real_docker_capability_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_tool_test",
    )
    project = namespace["_docker_projection"]
    image_id = "sha256:" + "a" * 64
    vector_id = "browser-service--browser--dns-prefetch"
    attempt_topology = {
        "cohort_version": 71,
        "foundation_payload_sha256": "b" * 64,
        "global_ordinal": 1,
        "attempt_number": 1,
        "topology_token": "c" * 32,
    }
    labels = {
        "org.qcsd.owner": "qcsd-lab",
        "org.qcsd.study": "classifier-multiorigin100-v1",
        "org.qcsd.qualification": "browser-egress-qualification-v1",
        "org.qcsd.vector": vector_id,
        "org.qcsd.cohort-version": "71",
        "org.qcsd.foundation": "b" * 64,
        "org.qcsd.global-ordinal": "1",
        "org.qcsd.attempt-number": "1",
        "org.qcsd.topology-token": "c" * 32,
    }
    supervised_labels = {
        **labels,
        "org.qcsd.supervisor.instance": "e" * 32,
    }
    network = {
        "Id": "f" * 64,
        "Name": "qcsd-browser-egress-v1",
        "Driver": "bridge",
        "Internal": True,
        "Attachable": False,
        "EnableIPv6": True,
        "IPAM": {
            "Config": [
                {"Subnet": "172.30.98.0/24"},
                {"Subnet": "fd00:71:63:73:64:98::/96"},
            ]
        },
        "Labels": supervised_labels,
    }
    addresses = {
        "browser": ("172.30.98.10", "fd00:71:63:73:64:98:0:10"),
        "fixture": ("172.30.98.11", "fd00:71:63:73:64:98:0:11"),
        "forbidden_sink": ("172.30.98.20", "fd00:71:63:73:64:98:0:20"),
        "dns_sink": ("172.30.98.53", "fd00:71:63:73:64:98:0:53"),
    }
    roles = ("browser", "observer", "fixture", "forbidden_sink", "dns_sink")
    endpoint_ids = {
        role: str(index + 5) * 64
        for index, role in enumerate(roles)
        if role != "observer"
    }
    containers = []
    for index, role in enumerate(roles, 1):
        attachment = {}
        if role != "observer":
            ipv4, ipv6 = addresses[role]
            attachment = {
                "qcsd-browser-egress-v1": {
                    "NetworkID": network["Id"],
                    "EndpointID": endpoint_ids[role],
                    "IPAddress": ipv4,
                    "GlobalIPv6Address": ipv6,
                }
            }
        containers.append(
            {
                "Id": str(index) * 64,
                "Name": f"/qcsd-be-{'c' * 32}-{ {'forbidden_sink': 'forbidden', 'dns_sink': 'dns'}.get(role, role) }",
                "Image": image_id,
                "Config": {
                    "User": "1000:1000" if role == "browser" else "0:0",
                    "Labels": {**supervised_labels, "org.qcsd.role": role},
                },
                "HostConfig": {
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "CapAdd": ["CAP_NET_RAW"] if role == "observer" else None,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "NetworkMode": (
                        "container:" + "1" * 64
                        if role == "observer"
                        else "qcsd-browser-egress-v1"
                    ),
                    "Tmpfs": {
                        "/tmp": "rw,nosuid,nodev,mode=1777",
                        **(
                            {
                                "/opt/qcsd-lab/config/class-study/v1": (
                                    "ro,nosuid,nodev,noexec,mode=000"
                                )
                            }
                            if role != "fixture"
                            else {}
                        ),
                    },
                    "Dns": (
                        ["172.30.98.53", "fd00:71:63:73:64:98:0:53"]
                        if role == "browser"
                        else None
                    ),
                },
                "NetworkSettings": {"Networks": attachment},
                "Mounts": [],
                "State": {"Running": False, "ExitCode": 0, "Status": "exited"},
            }
        )
    network["Containers"] = {
        container["Id"]: {
            "EndpointID": endpoint_ids[role],
            "IPv4Address": f"{addresses[role][0]}/24",
            "IPv6Address": f"{addresses[role][1]}/96",
        }
        for role, container in zip(roles, containers, strict=True)
        if role != "observer"
    }

    value = project(
        network,
        containers,
        None,
        vector_id=vector_id,
        prepare_image_id=image_id,
        browser_uid=1000,
        browser_gid=1000,
        attempt_topology=attempt_topology,
        docker_root_dir="/var/lib/docker",
        policy_file_inventory=None,
    )
    assert value["containers"]["observer"]["cap_add"] == ["CAP_NET_RAW"]
    assert set(value["network"]["members"]) == {
        "browser",
        "fixture",
        "forbidden_sink",
        "dns_sink",
    }

    stale = namespace["_stale_topology_cleanup_plan"]
    stale(
        SimpleNamespace(
            resume_plan_json=json.dumps(
                {
                    "schema_version": 1,
                    "checkpoint_publish_lag": False,
                    "checkpoint_status": "running",
                    "prepare_image_id": image_id,
                    "docker_root_dir": "/var/lib/docker",
                    "cleanup": {
                        "vector_id": vector_id,
                        "global_ordinal": 1,
                        "attempt_number": 1,
                        "evidence_directory": (
                            "evidence/083--browser-service--browser--dns-prefetch/"
                            "attempt-1"
                        ),
                        "topology_token": "c" * 32,
                        "cohort_version": 71,
                        "foundation_payload_sha256": "b" * 64,
                        "outstanding": True,
                    },
                }
            ),
            network_inspect_json=json.dumps([network]),
            container_inspect_json=json.dumps(containers),
            volume_inspect_json="null",
        )
    )
    cleanup = json.loads(capsys.readouterr().out)
    assert cleanup["container_ids"][0] == "2" * 64
    assert cleanup["network_id"] == network["Id"]

    completed_plan = {
        "schema_version": 1,
        "checkpoint_publish_lag": False,
        "checkpoint_status": "running",
        "prepare_image_id": image_id,
        "docker_root_dir": "/var/lib/docker",
        "cleanup": {
            "vector_id": vector_id,
            "global_ordinal": 1,
            "attempt_number": 1,
            "evidence_directory": (
                "evidence/083--browser-service--browser--dns-prefetch/attempt-1"
            ),
            "topology_token": "c" * 32,
            "cohort_version": 71,
            "foundation_payload_sha256": "b" * 64,
            "outstanding": False,
        },
    }
    stale(
        SimpleNamespace(
            resume_plan_json=json.dumps(completed_plan),
            network_inspect_json="null",
            container_inspect_json="[]",
            volume_inspect_json="null",
        )
    )
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 1,
        "container_ids": [],
        "network_id": None,
        "volume_name": None,
    }
    with pytest.raises(ValueError, match="outstanding attempt"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(completed_plan),
                network_inspect_json=json.dumps([network]),
                container_inspect_json=json.dumps(containers),
                volume_inspect_json="null",
            )
        )

    mixed_token = copy.deepcopy(containers)
    mixed_token[0]["Config"]["Labels"]["org.qcsd.topology-token"] = "d" * 32
    with pytest.raises(ValueError, match="labels"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(
                    {**completed_plan, "cleanup": {**completed_plan["cleanup"], "outstanding": True}}
                ),
                network_inspect_json=json.dumps([network]),
                container_inspect_json=json.dumps(mixed_token),
                volume_inspect_json="null",
            )
        )

    extra_attachment = copy.deepcopy(containers)
    extra_attachment[0]["NetworkSettings"]["Networks"]["unrelated"] = {
        "NetworkID": "e" * 64,
        "EndpointID": "d" * 64,
        "IPAddress": "192.0.2.2",
        "GlobalIPv6Address": "2001:db8::2",
    }
    with pytest.raises(ValueError, match="network attachment"):
        project(
            network,
            extra_attachment,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    extra_member = copy.deepcopy(network)
    extra_member["Containers"]["c" * 64] = {
        "EndpointID": "b" * 64,
        "IPv4Address": "192.0.2.3/24",
        "IPv6Address": "2001:db8::3/96",
    }
    with pytest.raises(ValueError, match="exact four roles"):
        project(
            extra_member,
            containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )

    npo0_vector = (
        "browser-service-control--off-the-record--speculation-prefetch-enabled"
    )
    npo0_labels = {**labels, "org.qcsd.vector": npo0_vector}
    npo0_supervised_labels = {
        **npo0_labels,
        "org.qcsd.supervisor.instance": "e" * 32,
    }
    npo0_network = copy.deepcopy(network)
    npo0_network["Labels"] = npo0_supervised_labels
    npo0_containers = copy.deepcopy(containers)
    for container in npo0_containers:
        role = container["Config"]["Labels"]["org.qcsd.role"]
        container["Config"]["Labels"] = {
            **npo0_supervised_labels,
            "org.qcsd.role": role,
        }
    volume_name = f"qcsd-be-{'c' * 32}-policy0"
    npo0_containers[0]["Mounts"] = [
        {
            "Type": "volume",
            "Name": volume_name,
            "Destination": "/etc/chromium/policies/managed",
            "RW": False,
        }
    ]
    policy_inventory = [
        {
            "path": "/etc/chromium/policies/managed/qcsd-network-prediction.json",
            "name": "qcsd-network-prediction.json",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "mode": "0o444",
            "nlink": 1,
            "size_bytes": 56,
            "sha256": "4566be4f014df0cfd45cf8bdeb4333b341bf4c666139e364992306c12873df03",
        }
    ]
    raw_volume = [
        {
            "Name": volume_name,
            "Driver": "local",
            "Scope": "local",
            "Labels": {**npo0_labels, "org.qcsd.role": "policy_volume"},
            "Options": {},
            "Mountpoint": f"/var/lib/docker/volumes/{volume_name}/_data",
        }
    ]
    npo0_projection = project(
        npo0_network,
        npo0_containers,
        raw_volume,
        vector_id=npo0_vector,
        prepare_image_id=image_id,
        browser_uid=1000,
        browser_gid=1000,
        attempt_topology=attempt_topology,
        docker_root_dir="/var/lib/docker",
        policy_file_inventory=policy_inventory,
    )
    assert npo0_projection["policy_volume"]["name"] == volume_name
    assert "Mountpoint" not in json.dumps(npo0_projection)
    npo0_resume = {
        "schema_version": 1,
        "checkpoint_publish_lag": False,
        "checkpoint_status": "running",
        "prepare_image_id": image_id,
        "docker_root_dir": "/var/lib/docker",
        "cleanup": {
            "vector_id": npo0_vector,
            "global_ordinal": 1,
            "attempt_number": 1,
            "evidence_directory": f"evidence/097--{npo0_vector}/attempt-1",
            "topology_token": "c" * 32,
            "cohort_version": 71,
            "foundation_payload_sha256": "b" * 64,
            "outstanding": True,
        },
    }
    stale(
        SimpleNamespace(
            resume_plan_json=json.dumps(npo0_resume),
            network_inspect_json=json.dumps([npo0_network]),
            container_inspect_json=json.dumps(npo0_containers),
            volume_inspect_json=json.dumps(raw_volume),
        )
    )
    npo0_cleanup = json.loads(capsys.readouterr().out)
    assert npo0_cleanup["volume_name"] == volume_name

    hostile_volume = copy.deepcopy(raw_volume)
    hostile_volume[0]["Labels"]["org.qcsd.topology-token"] = "d" * 32
    with pytest.raises(ValueError, match="safely attributable"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(npo0_resume),
                network_inspect_json=json.dumps([npo0_network]),
                container_inspect_json=json.dumps(npo0_containers),
                volume_inspect_json=json.dumps(hostile_volume),
            )
        )
    with pytest.raises(ValueError, match="no bound policy volume"):
        stale(
            SimpleNamespace(
                resume_plan_json=json.dumps(npo0_resume),
                network_inspect_json=json.dumps([npo0_network]),
                container_inspect_json=json.dumps(npo0_containers),
                volume_inspect_json="null",
            )
        )

    containers[1]["HostConfig"]["CapAdd"] = ["NET_RAW"]
    with pytest.raises(ValueError, match="raw Docker capabilities"):
        project(
            network,
            containers,
            None,
            vector_id=vector_id,
            prepare_image_id=image_id,
            browser_uid=1000,
            browser_gid=1000,
            attempt_topology=attempt_topology,
            docker_root_dir="/var/lib/docker",
            policy_file_inventory=None,
        )


@pytest.mark.parametrize(
    ("failure_stage", "expected_code"),
    (
        ("runtime", "runtime-binding-failed"),
        ("sink", "sink-reconciliation-failed"),
        ("fixture", "fixture-observation-failed"),
        ("capture", "capture-process-failed"),
        ("packet", "packet-policy-failed"),
        ("semantic", "semantic-observation-failed"),
        ("validate-only", None),
    ),
)
def test_browser_egress_assemble_classifies_exact_failure_stage(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    expected_code: str,
) -> None:
    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_classifier_test",
    )
    assemble = namespace["_assemble"]
    globals_ = assemble.__globals__
    vector_id = "browser-service--browser--dns-prefetch"
    actor = {
        "schema_version": 1,
        "role": "actor",
        "vector_id": vector_id,
        "browser_started_ns": 3,
        "browser_exited_ns": 7,
        "prearm_verified_ns": 4,
        "actor_result": {"started_ns": 5, "finished_ns": 6, "measurement": {}},
        "effective_argv": {},
        "driver_runtime": {},
        "policy_volume_file_inventory": None,
        "child_environment": {},
    }
    forbidden = {
        "schema_version": 1,
        "role": "forbidden-sink",
        "vector_id": vector_id,
        "ready_ns": 1,
        "stopped_ns": 8,
        "tcp": {},
        "udp": {},
    }
    dns = {
        "schema_version": 1,
        "role": "dns-sink",
        "vector_id": vector_id,
        "ready_ns": 2,
        "stopped_ns": 8,
        "receipt": {},
    }
    fixture = {
        "schema_version": 1,
        "role": "fixture",
        "vector_id": vector_id,
        "tls_material": {},
        "receipt": {"chronology": {"ready_ns": 1, "stopped_ns": 8}},
    }
    capture = {
        "schema_version": 1,
        "role": "observer",
        "vector_id": vector_id,
        "receipt": {
            "capture_process": {
                "exit_code": 0,
                "packets_dropped_by_kernel": 0,
                "packets_dropped_by_interface": 0,
            },
            "chronology": {
                "observer_ready_ns": 1,
                "subject_started_ns": 3,
                "subject_exited_ns": 7,
                "reporting_grace_finished_ns": 8,
                "observer_stopped_ns": 9,
            },
            "analysis": {},
        },
    }
    roles = {
        "actor role": actor,
        "forbidden sink role": forbidden,
        "DNS sink role": dns,
        "fixture role": fixture,
        "observer role": capture,
    }
    monkeypatch.setitem(
        globals_,
        "_object",
        lambda path, label: (
            {"global_ordinal": 1, "attempt_number": 1}
            if label == "next-vector plan"
            else {}
        ),
    )
    monkeypatch.setitem(globals_, "validate_hash_bound_receipt", lambda *args, **kwargs: {})
    monkeypatch.setitem(globals_, "_sole_stdout_object", lambda path, label: roles[label])
    monkeypatch.setitem(
        globals_,
        "validate_runtime_binding",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("runtime"))
        if failure_stage == "runtime"
        else {},
    )
    monkeypatch.setitem(
        globals_,
        "combine_sink_receipt",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("sink"))
        if failure_stage == "sink"
        else {"chronology": {
            "forbidden_ready_ns": 1,
            "dns_ready_ns": 2,
            "forbidden_stopped_ns": 8,
            "dns_stopped_ns": 8,
        }},
    )
    monkeypatch.setitem(globals_, "validate_sink_receipt", lambda *args, **kwargs: {})
    monkeypatch.setitem(
        globals_,
        "assemble_live_semantic_observation",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("semantic"))
        if failure_stage == "semantic"
        else {},
    )
    monkeypatch.setitem(
        globals_,
        "validate_fixture_observation",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("fixture"))
        if failure_stage == "fixture"
        else {},
    )
    if failure_stage == "capture":
        capture["role"] = "wrong"

    def validate_capture(*args, **kwargs):
        if failure_stage == "packet":
            raise ValueError("browser-egress packet policy failed at forbidden_tcp_initial_syn")
        return {}

    monkeypatch.setitem(globals_, "validate_capture_receipt", validate_capture)
    monkeypatch.setitem(
        globals_, "reconcile_sink_and_packet_evidence", lambda **kwargs: None
    )
    monkeypatch.setitem(
        globals_,
        "append_result",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("validate-only assembly mutated the ledger")
        ),
    )
    emitted: list[dict] = []
    monkeypatch.setitem(globals_, "_emit", emitted.append)
    args = SimpleNamespace(
        result_root=Path("/result"),
        next_json=Path("/next"),
        actor_json=Path("/actor"),
        forbidden_json=Path("/forbidden"),
        dns_json=Path("/dns"),
        fixture_json=Path("/fixture"),
        capture_json=Path("/capture"),
        runtime_json=Path("/runtime"),
        vector_id=vector_id,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        validate_only=failure_stage == "validate-only",
    )
    assemble(args)
    if failure_stage == "validate-only":
        assert emitted == [{"schema_version": 1, "assembled": True}]
    else:
        assert emitted == [
            {"schema_version": 1, "assembled": False, "failure_code": expected_code}
        ]


def test_launcher_raw_index_verifier_rejects_clean_filter_forgery(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.email", "test@example.invalid"], check=True)
    (checkout / "payload").write_bytes(b"clean")
    (checkout / ".gitattributes").write_text("payload filter=hide\n", encoding="ascii")
    subprocess.run(["git", "-C", checkout, "add", "."], check=True)
    subprocess.run(["git", "-C", checkout, "commit", "-qm", "initial"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "filter.hide.clean", "printf clean"],
        check=True,
    )
    # Keep the size equal to the committed payload so Git consults the clean
    # filter instead of rejecting the cached entry from size metadata alone.
    (checkout / "payload").write_bytes(b"evil!")
    status = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
    )
    assert status.stdout == b"", "the fixture must reproduce Git clean-filter hiding"

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split(
        'if [[ "${1:-}" == "-h"', 1
    )[0]
    command = "_qcsd_trusted_git() {" + functions + "\n_qcsd_verify_git_index_bytes \"$1\"\n"
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_checkout_binding_rejects_local_worktree_redirect(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    alternate = tmp_path / "alternate"
    checkout.mkdir()
    alternate.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", checkout, "config", "core.worktree", str(alternate)],
        check=True,
    )
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split(
        "_qcsd_verify_git_index_bytes() {", 1
    )[0]
    command = (
        "_qcsd_trusted_git() {"
        + functions
        + '\n_qcsd_verify_git_checkout_binding "$1" "$1/.git"\n'
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_checkout_binding_rejects_hidden_untracked_source(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    exclude = checkout / ".git/info/exclude"
    exclude.write_text("hidden.py\n", encoding="ascii")
    (checkout / "hidden.py").write_text("raise RuntimeError('in build context')\n")
    status = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
    )
    assert status.stdout == b"", "the fixture must hide the untracked source from Git"
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split(
        "_qcsd_verify_git_index_bytes() {", 1
    )[0]
    command = (
        "_qcsd_trusted_git() {"
        + functions
        + '\n_qcsd_verify_git_checkout_binding "$1" "$1/.git"\n'
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_raw_index_verifier_rejects_intermediate_symlink(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.email", "test@example.invalid"], check=True)
    nested = checkout / "nested"
    nested.mkdir()
    (nested / "payload").write_bytes(b"clean")
    subprocess.run(["git", "-C", checkout, "add", "."], check=True)
    subprocess.run(["git", "-C", checkout, "commit", "-qm", "initial"], check=True)
    moved = tmp_path / "moved"
    nested.rename(moved)
    nested.symlink_to(moved, target_is_directory=True)

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    functions = launcher.split("_qcsd_trusted_git() {", 1)[1].split(
        'if [[ "${1:-}" == "-h"', 1
    )[0]
    command = "_qcsd_trusted_git() {" + functions + "\n_qcsd_verify_git_index_bytes \"$1\"\n"
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_launcher_trusted_git_ignores_replace_refs(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "-C", checkout, "init", "-q"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", checkout, "config", "user.email", "test@example.invalid"], check=True)
    payload = checkout / "payload"
    payload.write_text("original\n")
    subprocess.run(["git", "-C", checkout, "add", "payload"], check=True)
    subprocess.run(["git", "-C", checkout, "commit", "-qm", "original"], check=True)
    original = subprocess.check_output(["git", "-C", checkout, "rev-parse", "HEAD"], text=True).strip()
    payload.write_text("replacement\n")
    subprocess.run(["git", "-C", checkout, "commit", "-qam", "replacement"], check=True)
    replacement = subprocess.check_output(["git", "-C", checkout, "rev-parse", "HEAD"], text=True).strip()
    subprocess.run(["git", "-C", checkout, "reset", "--soft", original], check=True)
    subprocess.run(["git", "-C", checkout, "replace", original, replacement], check=True)
    forged = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain"],
        check=True,
        capture_output=True,
    )
    assert forged.stdout == b"", "the fixture must reproduce replace-ref clean forgery"

    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    trusted = launcher.split("_qcsd_trusted_git() {", 1)[1].split("\n}", 1)[0]
    command = '_qcsd_trusted_git() {' + trusted + '\n}\n_qcsd_trusted_git -C "$1" status --porcelain\n'
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", command, "verify", str(checkout)],
        check=True,
        capture_output=True,
    )
    assert result.stdout != b""


def test_acquisition_actions_repeat_exact_scoped_validation_across_go() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    scope_call = '"${class_watch_scope_recovery[@]}" >/dev/null'
    assert launcher.count(scope_call) == 2
    scope_setup = launcher.index("class_watch_scope_recovery=(")
    first_call = launcher.index(scope_call, scope_setup)
    admission_branch = launcher.index(
        '"${class_study_action}" == "acquisition-admission" ]]; then', first_call
    )
    guardian = launcher.index("require_docker", admission_branch)
    assert first_call < guardian
    require_body = launcher.split("require_docker() {", 1)[1].split("\n}", 1)[0]
    assert require_body.index("_qcsd_validate_lifecycle_guardian") < require_body.index(
        scope_call
    )
    assert "--recover-stale-scopes-internal" in launcher[scope_setup:first_call]
    assert "_qcsd_docker_api" not in launcher[scope_setup:first_call]
    assert "qcsd_run_" not in launcher[scope_setup:first_call]


def test_acquisition_scope_digest_binds_current_argv_before_recovery() -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    digest = launcher.index('class_watch_current_action_sha256="$(')
    comparison = launcher.index(
        "scoped request action does not match current argv",
        digest,
    )
    recovery = launcher.index("class_watch_scope_recovery=(", comparison)

    assert '["/usr/bin/bash", *sys.argv[1:]]' in launcher[digest:comparison]
    assert '"${ROOT}/qcsd-lab" "${QCSD_ORIGINAL_ARGV[@]}"' in launcher[
        digest:comparison
    ]
    assert '"${QCSD_CLASS_WATCH_ACTION_SHA256}"' in launcher[digest:comparison]
    assert comparison < recovery


def test_launcher_grants_results_write_access_only_to_result_writers():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    mount = '--volume "${ROOT}/results:/lab/results:rw"'
    assert launcher.count(mount) == 1
    results_gate = launcher.split(
        'if [[ "${1:-}" == "run" || "${1:-}" == "resume" || "${1:-}" == "analyze" ]]',
        1,
    )[1].split("\nfi", 1)[0]
    assert mount in results_gate
    base_container = launcher.split("container=(", 1)[1].split("\n)", 1)[0]
    assert mount not in base_container


def test_launcher_never_creates_qualification_evidence_and_mounts_least_privilege():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert 'mkdir -p "${ROOT}/config/chaff-prefix-specs"' not in launcher
    assert 'mkdir -p "${ROOT}/config/chaff-qualification-store"' not in launcher
    assert 'if [[ "${1:-}" == "qualify-chaff" ]]' in launcher
    assert '"${ROOT}/config/chaff-prefix-specs/v2"' in launcher
    assert '"${ROOT}/config/chaff-qualification-store"' in launcher
    assert '[[ ! -d "${required_directory}" || -L "${required_directory}" ]]' in launcher
    qualification_mounts = launcher.split(
        'if [[ "${1:-}" == "qualify-chaff" ]]; then\n  container+=(', 1
    )[-1].split("\nfi", 1)[0]
    assert '--volume "${ROOT}/config/workloads:/lab/config/workloads:ro"' in qualification_mounts
    assert (
        '--volume "${ROOT}/config/chaff-prefix-specs:/lab/config/chaff-prefix-specs:ro"'
        in qualification_mounts
    )
    assert (
        '--volume "${ROOT}/config/chaff-qualification-store:'
        '/lab/config/chaff-qualification-store:rw"' in qualification_mounts
    )
    assert (
        '--volume "${qualification_child}:'
        '/lab/config/chaff-qualification-store/${qualification_name}:ro"' in qualification_mounts
    )
    assert "validate_qualification_store_delta" in launcher
    assert "changed pre-existing qualification evidence" in launcher
    assert "outside the exact schema-two cohort" in launcher
    assert "outside one hidden candidate" in launcher


def test_qualification_store_delta_validator_executes_publication_states(tmp_path):
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_qualification_store_delta")
    existing = {
        ".gitkeep": {"type": "file", "sha256": "a" * 64},
        "v1": {"type": "directory"},
        "v1/historical.json": {"type": "file", "sha256": "b" * 64},
    }
    ids = (
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    )
    cohort = {"v2": {"type": "directory"}} | {
        f"v2/{workload}.json": {"type": "file", "sha256": "c" * 64} for workload in ids
    }
    published = _run_embedded_python(tmp_path, validator, existing, existing | cohort, "0")
    assert published.returncode == 0, published.stderr

    unchanged_failure = _run_embedded_python(tmp_path, validator, existing, existing, "7")
    assert unchanged_failure.returncode == 0, unchanged_failure.stderr

    candidate = {
        ".v2.qcsd-batch-proof": {"type": "directory"},
        ".v2.qcsd-batch-proof/run.log": {"type": "file", "sha256": "d" * 64},
    }
    retained_failure = _run_embedded_python(
        tmp_path, validator, existing, existing | candidate, "7"
    )
    assert retained_failure.returncode == 0, retained_failure.stderr

    mutated = dict(existing)
    mutated["v1/historical.json"] = {"type": "file", "sha256": "e" * 64}
    changed_history = _run_embedded_python(tmp_path, validator, existing, mutated, "7")
    assert changed_history.returncode != 0
    assert "pre-existing qualification evidence" in changed_history.stderr

    unauthorized = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | {"unexpected": {"type": "directory"}},
        "7",
    )
    assert unauthorized.returncode != 0
    assert "outside one hidden candidate" in unauthorized.stderr


def test_launcher_response_qualification_is_exact_five_and_least_privilege() -> None:
    root = Path(__file__).parents[1]
    launcher = (root / "qcsd-lab").read_text(encoding="utf-8")
    sets_marker = root / "config/chaff-response-qualification-store/sets/.gitkeep"
    assert sets_marker.is_file() and not sets_marker.is_symlink()
    assert "qualify-response-chaff requires exactly five workload IDs" in launcher
    assert '"${ROOT}/config/chaff-response-qualification-store"' in launcher
    assert "config/chaff-response-qualification-store/v2" in launcher
    mounts = launcher.split(
        'if [[ "${1:-}" == "qualify-response-chaff" ]]; then\n  container+=(', 1
    )[-1].split('if [[ "${1:-}" == "fit" ]]; then', 1)[0]
    assert '--volume "${ROOT}/config/workloads:/lab/config/workloads:ro"' in mounts
    assert (
        '--volume "${ROOT}/config/chaff-response-qualification-store:'
        '/lab/config/chaff-response-qualification-store:rw"' in mounts
    )
    assert (
        '--volume "${ROOT}/config/chaff-response-qualification-store:'
        '/lab/config/chaff-response-qualification-store:ro"' in mounts
    )
    assert (
        '--volume "${response_qualification_sets_root}:'
        '/lab/config/chaff-response-qualification-store/sets:rw"' in mounts
    )
    assert (
        '--volume "${response_qualification_child}:'
        '/lab/config/chaff-response-qualification-store/${response_qualification_name}:ro"'
        in mounts
    )
    assert (
        '--volume "${existing_response_set}:'
        '/lab/config/chaff-response-qualification-store/sets/${existing_response_set_name}:ro"'
        in mounts
    )
    assert "response_qualification_set_explicit" in launcher
    assert "requires absent set target" in launcher
    assert "validate_response_qualification_store_delta" in launcher


def test_response_qualification_delta_validator_enforces_dynamic_exact_five(
    tmp_path: Path,
) -> None:
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_response_qualification_store_delta")
    existing = {".gitkeep": {"type": "file", "sha256": "a" * 64}}
    ids = ("alpha", "bravo", "charlie", "delta", "echo")
    cohort = {"v2": {"type": "directory"}} | {
        f"v2/{workload}.json": {"type": "file", "sha256": "b" * 64} for workload in ids
    }

    published = _run_embedded_python(
        tmp_path, validator, existing, existing | cohort, "0", "legacy", "", *ids
    )
    assert published.returncode == 0, published.stderr

    candidate = {
        ".v2.qcsd-batch-proof": {"type": "directory"},
        ".v2.qcsd-batch-proof/response-0.log": {
            "type": "file",
            "sha256": "c" * 64,
        },
    }
    retained = _run_embedded_python(
        tmp_path, validator, existing, existing | candidate, "7", "legacy", "", *ids
    )
    assert retained.returncode == 0, retained.stderr

    partial = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | {"v2": {"type": "directory"}},
        "0",
        "legacy",
        "",
        *ids,
    )
    assert partial.returncode != 0
    assert "outside the exact schema-two cohort" in partial.stderr

    duplicate_ids = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing,
        "7",
        "legacy",
        "",
        *ids[:4],
        ids[0],
    )
    assert duplicate_ids.returncode != 0
    assert "workload cohort is invalid" in duplicate_ids.stderr

    named_existing = existing | {"sets": {"type": "directory"}}
    named_target = {"sets/cohort-v1": {"type": "directory"}} | {
        f"sets/cohort-v1/{workload}.json": {"type": "file", "sha256": "d" * 64} for workload in ids
    }
    named_published = _run_embedded_python(
        tmp_path,
        validator,
        named_existing,
        named_existing | named_target,
        "0",
        "set",
        "cohort-v1",
        *ids,
    )
    assert named_published.returncode == 0, named_published.stderr

    named_candidate = {
        "sets/.cohort-v1.qcsd-batch-proof": {"type": "directory"},
        "sets/.cohort-v1.qcsd-batch-proof/response-0.log": {
            "type": "file",
            "sha256": "e" * 64,
        },
    }
    named_retained = _run_embedded_python(
        tmp_path,
        validator,
        named_existing,
        named_existing | named_candidate,
        "7",
        "set",
        "cohort-v1",
        *ids,
    )
    assert named_retained.returncode == 0, named_retained.stderr

    mixed_target = dict(named_target)
    mixed_target["sets/other-v1/alpha.json"] = {"type": "file", "sha256": "f" * 64}
    mixed = _run_embedded_python(
        tmp_path,
        validator,
        named_existing,
        named_existing | mixed_target,
        "0",
        "set",
        "cohort-v1",
        *ids,
    )
    assert mixed.returncode != 0
    assert "outside the exact schema-two cohort" in mixed.stderr


def test_launcher_audits_the_exact_prefix_derivation_config_delta():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    assert 'guarded_root="${ROOT}/config"' in launcher
    assert '[[ ! -d "${guarded_root}" || -L "${guarded_root}" ]]' in launcher
    assert launcher.index('[[ ! -d "${guarded_root}" || -L "${guarded_root}" ]]') < (
        launcher.index('mkdir -p "${ROOT}/results"')
    )
    common_mkdir = 'mkdir -p "${ROOT}/results" "${ROOT}/artifacts" "${ROOT}/config/workloads"'
    assert launcher.count(common_mkdir) == 1
    assert f"else\n  {common_mkdir}\nfi" in launcher
    assert '[[ -e "${ROOT}/config/chaff-prefix-specs/v2"' in launcher
    derivation_mounts = launcher.split(
        'if [[ "${1:-}" == "derive-chaff-prefix-specs" ]]; then\n  container+=(', 1
    )[-1].split("\nfi", 1)[0]
    assert (
        '--volume "${ROOT}/config/chaff-prefix-specs:'
        '/lab/config/chaff-prefix-specs:rw"' in derivation_mounts
    )
    assert '--volume "${ROOT}/config:/lab/config:rw"' not in launcher
    assert (
        '--volume "${prefix_spec_child}:'
        '/lab/config/chaff-prefix-specs/${prefix_spec_name}:ro"' in derivation_mounts
    )
    assert '"chaff-prefix-specs/v2": "directory"' in launcher
    assert "snapshot_regular_tree" in launcher
    assert "validate_prefix_derivation_delta" in launcher
    assert 'snapshot_regular_tree "${ROOT}/config"' in launcher
    assert "changed a pre-existing config input" in launcher
    assert "changed files outside the exact-six output" in launcher
    assert "output type is invalid" in launcher
    assert 'raise SystemExit(f"{label} rejects symlink: {relative}")' in launcher
    assert 'raise SystemExit(f"{label} rejects special entry: {relative}")' in launcher
    for workload_id in (
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    ):
        assert workload_id in launcher


def test_prefix_derivation_delta_validator_executes_publication_states(tmp_path):
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_prefix_derivation_delta")
    existing = {
        "workloads": {"type": "directory"},
        "workloads/historical.json": {"type": "file", "sha256": "a" * 64},
        "chaff-prefix-specs": {"type": "directory"},
        "chaff-prefix-specs/v1.json": {"type": "file", "sha256": "b" * 64},
    }
    ids = (
        "apache-traffic-server-docs-r3",
        "bootstrap-introduction-r3",
        "cloudflare-quiche-r3",
        "getbootstrap-home-r3",
        "nghttp2-ngtcp2-r3",
        "nginx-quic-r3",
    )
    cohort = {"chaff-prefix-specs/v2": {"type": "directory"}} | {
        f"chaff-prefix-specs/v2/{workload}.json": {
            "type": "file",
            "sha256": "c" * 64,
        }
        for workload in ids
    }
    published = _run_embedded_python(tmp_path, validator, existing, existing | cohort, "0")
    assert published.returncode == 0, published.stderr

    unchanged_failure = _run_embedded_python(tmp_path, validator, existing, existing, "7")
    assert unchanged_failure.returncode == 0, unchanged_failure.stderr

    partial_failure = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | {"chaff-prefix-specs/v2": {"type": "directory"}},
        "7",
    )
    assert partial_failure.returncode != 0
    assert "failed derive-chaff-prefix-specs changed" in partial_failure.stderr

    mutated = dict(existing)
    mutated["workloads/historical.json"] = {"type": "file", "sha256": "d" * 64}
    changed_input = _run_embedded_python(tmp_path, validator, existing, mutated, "7")
    assert changed_input.returncode != 0
    assert "pre-existing config input" in changed_input.stderr


def test_launcher_protects_preexisting_artifacts_during_fit_and_audits_delta():
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    fit_mount = launcher.split('container+=(--volume "${ROOT}/artifacts:/lab/artifacts:rw")', 1)[
        1
    ].split("\nfi", 1)[0]
    fit_mount = 'container+=(--volume "${ROOT}/artifacts:/lab/artifacts:rw")' + fit_mount
    assert '--volume "${ROOT}/artifacts:/lab/artifacts:rw"' in fit_mount
    assert '--volume "${artifact_child}:/lab/artifacts/${artifact_name}:ro"' in fit_mount
    assert '[[ ! "${artifact_name}" =~ ^[A-Za-z0-9._-]+$ ]]' in fit_mount
    assert 'find "${ROOT}/artifacts" -mindepth 1 -maxdepth 1 -print0' in fit_mount
    assert "snapshot_regular_tree" in launcher
    assert "validate_fit_artifact_delta" in launcher
    assert "fit changed a pre-existing artifact" in launcher
    assert "fit changed files outside the exact four-file bundle" in launcher
    assert "idempotent fit changed the pre-existing artifact tree" in launcher
    assert "fit_canonical_preexisting=1" in launcher
    for filename in (
        "provenance.json",
        "traffic-morphing.json",
        "walkie-talkie.json",
        "wtf-pad.json",
    ):
        assert f'"research-1200/{filename}": "file"' in launcher


def test_fit_artifact_delta_validator_executes_all_publication_states(tmp_path):
    launcher = (Path(__file__).parents[1] / "qcsd-lab").read_text(encoding="utf-8")
    validator = _embedded_python(launcher, "validate_fit_artifact_delta")
    existing = {"README.md": {"type": "file", "sha256": "a" * 64}}
    bundle = {
        "research-1200": {"type": "directory"},
        "research-1200/provenance.json": {"type": "file", "sha256": "b" * 64},
        "research-1200/traffic-morphing.json": {
            "type": "file",
            "sha256": "c" * 64,
        },
        "research-1200/walkie-talkie.json": {
            "type": "file",
            "sha256": "d" * 64,
        },
        "research-1200/wtf-pad.json": {"type": "file", "sha256": "e" * 64},
    }

    created = _run_embedded_python(tmp_path, validator, existing, existing | bundle, "0", "0")
    assert created.returncode == 0, created.stderr

    failed_without_delta = _run_embedded_python(tmp_path, validator, existing, existing, "0", "7")
    assert failed_without_delta.returncode == 0, failed_without_delta.stderr

    preexisting = existing | bundle
    idempotent = _run_embedded_python(tmp_path, validator, preexisting, preexisting, "1", "0")
    assert idempotent.returncode == 0, idempotent.stderr

    unauthorized = _run_embedded_python(
        tmp_path,
        validator,
        existing,
        existing | bundle | {"unexpected": {"type": "directory"}},
        "0",
        "0",
    )
    assert unauthorized.returncode != 0
    assert "outside the exact four-file bundle" in unauthorized.stderr

    failed_with_delta = _run_embedded_python(
        tmp_path, validator, existing, existing | bundle, "0", "7"
    )
    assert failed_with_delta.returncode != 0
    assert "failed fit changed the artifact tree" in failed_with_delta.stderr


def test_collection_image_builds_offline_validator_with_exact_neqo_commit():
    root = Path(__file__).parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --from=source-metadata /source-metadata.json" in dockerfile
    assert 'test "${#neqo_commit}" -eq 40' in dockerfile
    assert 'NEQO_QCSD_GIT_COMMIT="${neqo_commit}" cargo build --locked --release' in dockerfile
    assert "--bin qcsd-validate-parameters" in dockerfile
    assert "target/release/qcsd-validate-parameters /out/bin/" in dockerfile
    assert (
        "install -m 0755 /opt/qcsd-venv/bin/qcsd-lab-internal "
        "/usr/local/bin/qcsd-lab-internal"
    ) in dockerfile
    assert "ln -s /opt/qcsd-venv/bin/qcsd-lab-internal" not in dockerfile
    # A persistent target cache can reuse a feature-specific dependency artifact
    # after its source changes, producing two binaries from different revisions.
    assert "qcsd-cargo-target" not in dockerfile
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    assert "artifacts/*" in dockerignore


def test_incomplete_run_exits_cleanly_with_one_result_path(monkeypatch, capsys):
    root = Path("/lab/results/campaign/20260719T061311Z")

    def incomplete(_campaign, _results):
        raise CampaignIncomplete(root)

    monkeypatch.setattr(cli, "run_campaign", incomplete)
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["run", "campaign.yml"])
    assert exit_status.value.code == 1
    captured = capsys.readouterr()
    assert captured.err == f"campaign incomplete; evidence retained at {root}\n"
    assert captured.out == f"{root}\n"


def test_response_qualification_cli_forwards_named_set(monkeypatch, capsys):
    import qcsd_lab.chaff_qualification as qualification

    observed = {}

    def qualify(workload_ids, **kwargs):
        observed["workload_ids"] = tuple(workload_ids)
        observed.update(kwargs)
        return ()

    monkeypatch.setattr(qualification, "qualify_all_response_chaff", qualify)
    workload_ids = ("alpha", "bravo", "charlie", "delta", "echo")

    cli.main(
        [
            "qualify-response-chaff",
            "--set",
            "classifier-multiorigin5-v1",
            *workload_ids,
        ]
    )

    assert observed["workload_ids"] == workload_ids
    assert observed["qualification_set"] == "classifier-multiorigin5-v1"
    assert json.loads(capsys.readouterr().out) == {}


def test_verify_routes_yaml_to_preflight(monkeypatch, capsys, tmp_path):
    campaign = tmp_path / "campaign.yml"
    campaign.write_text("schema: 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "preflight_campaign", lambda path: {"valid": path == campaign})

    cli.main(["verify", str(campaign)])

    assert json.loads(capsys.readouterr().out) == {"valid": True}


def test_verify_reports_partial_artifact_bundle_as_a_bundle_error(capsys, tmp_path):
    partial = tmp_path / "research-1200"
    partial.mkdir()
    atomic_text(partial / "traffic-morphing.json", "{}\n")

    with pytest.raises(SystemExit) as exit_status:
        cli.main(["verify", str(partial)])

    assert exit_status.value.code == 1
    assert "artifact bundle file set mismatch" in capsys.readouterr().err


def test_verify_routes_missing_fixed_artifact_path_to_bundle_verification(capsys, tmp_path):
    missing = tmp_path / "research-1200"
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["verify", str(missing)])
    assert exit_status.value.code == 1
    assert "artifact bundle is not a regular directory" in capsys.readouterr().err


def test_fit_prints_bundle_root_and_receipt_sha256(monkeypatch, capsys, tmp_path):
    import qcsd_lab.fitting as fitting

    bundle = tmp_path / "artifacts/research-1200"
    bundle.mkdir(parents=True)
    atomic_text(bundle / "provenance.json", "sealed receipt\n")
    monkeypatch.setattr(fitting, "fit_result", lambda _result, artifacts_root: bundle)

    cli.main(["fit", str(tmp_path / "result")])

    assert json.loads(capsys.readouterr().out) == {
        "root": str(bundle),
        "provenance_sha256": sha256_file(bundle / "provenance.json"),
    }


def test_test_live_sets_acceptance_environment(monkeypatch):
    observed = {}

    def run(command, *, cwd, env, check):
        observed.update(command=command, cwd=cwd, env=env, check=check)
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr(cli.subprocess, "run", run)
    with pytest.raises(SystemExit) as exit_status:
        cli.main(["test", "live"])
    assert exit_status.value.code == 0
    assert observed["env"]["QCSD_RUN_CAPTURE_ACCEPTANCE"] == "1"
    assert observed["command"][-3:] == ["pytest", "-p", "no:cacheprovider"]
