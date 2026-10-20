"""Exercise actual prepare CLI routing without preparation, runtime or SQL.

The parser, version/selection flag predicates and main dispatch are real.
Runtime authentication and the enrollment side effect are explicit spy leaves;
the existing resource-version input tests cover those original validators.
No fixture here claims a prepared root, admission, GET, pilot or study credit.
"""
import json
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study as study


@pytest.fixture
def prepare_cli(tmp_path, monkeypatch):
    root = tmp_path / "initialized-input-root"
    (root / "inputs").mkdir(parents=True)
    (root / "study.json").write_text("{}\n")
    context = root / "inputs/resource-version-input-context.json"
    context.write_text("{}\n")
    runtime_path = tmp_path / "original-canonical-runtime.json"
    input_path = tmp_path / "explicit-resource-version-input.json"
    digest = "a" * 64
    runtime = {"explicit_spy_runtime": True}
    runtime_calls, enroll_calls = [], []

    class PlanOnlyStore:
        def __init__(self, actual_root):
            assert actual_root == root

        def plan(self):
            return {}

    def runtime_identity(actual_path):
        assert actual_path == runtime_path
        runtime_calls.append(actual_path)
        return runtime

    def enroll(actual_root, actual_runtime, hosts, **kwargs):
        enroll_calls.append((actual_root, actual_runtime, list(hosts), kwargs))
        return {"routing_spy_completed": True}

    monkeypatch.setattr(study, "StudyStore", PlanOnlyStore)
    monkeypatch.setattr(study, "runtime_identity", runtime_identity)
    monkeypatch.setattr(study, "enroll", enroll)
    common = ["prepare", "--root", str(root), "--runtime", str(runtime_path),
              "--hostname", "www.clarin.com", "--enroll"]
    version = ["--resource-version-input", str(input_path),
               "--resource-version-input-sha256", digest]
    return SimpleNamespace(root=root, context=context, runtime_path=runtime_path,
        input_path=input_path, digest=digest, runtime=runtime, common=common,
        version=version, runtime_calls=runtime_calls, enroll_calls=enroll_calls)


def test_actual_main_forwards_both_version_operands_without_resource_selection(prepare_cli, capsys):
    case = prepare_cli
    assert study.main(case.common + case.version) == 0
    assert json.loads(capsys.readouterr().out) == {"routing_spy_completed": True}
    assert case.runtime_calls == [case.runtime_path]
    assert case.enroll_calls == [(case.root, case.runtime, ["www.clarin.com"], {
        "resource_version_input": case.input_path,
        "resource_version_input_sha256": case.digest})]


def test_actual_main_ordinary_prepare_keeps_the_original_no_version_call(prepare_cli, capsys):
    case = prepare_cli
    case.context.unlink()
    assert study.main(case.common) == 0
    assert json.loads(capsys.readouterr().out) == {"routing_spy_completed": True}
    assert case.runtime_calls == [case.runtime_path]
    assert case.enroll_calls == [(case.root, case.runtime, ["www.clarin.com"], {})]


@pytest.mark.parametrize("mutation", [
    "missing-input", "missing-sha", "missing-runtime", "missing-enroll",
    "missing-host", "two-hosts", "missing-context", "resource-selection",
    "frozen-manifest", "buflo-cap",
])
def test_actual_main_refuses_mismatched_version_cli_before_runtime_or_enrollment(
        prepare_cli, capsys, mutation):
    case = prepare_cli
    args = case.common + case.version
    if mutation in ("missing-input", "missing-sha", "missing-runtime", "missing-host"):
        flag = {"missing-input": "--resource-version-input",
                "missing-sha": "--resource-version-input-sha256",
                "missing-runtime": "--runtime", "missing-host": "--hostname"}[mutation]
        index = args.index(flag)
        del args[index:index + 2]
    elif mutation == "missing-enroll":
        args.remove("--enroll")
    elif mutation == "two-hosts":
        args += ["--hostname", "other.example"]
    elif mutation == "missing-context":
        case.context.unlink()
    elif mutation == "resource-selection":
        args += ["--resource-selection", str(case.input_path),
                 "--resource-selection-sha256", case.digest]
    elif mutation == "frozen-manifest":
        args += ["--frozen-application-manifest", str(case.input_path),
                 "--frozen-application-manifest-sha256", case.digest]
    elif mutation == "buflo-cap":
        args += ["--buflo-chaff-cap-bytes", "65536"]
    else:
        raise AssertionError(mutation)
    assert study.main(args) == 1
    refusal = json.loads(capsys.readouterr().out)
    assert refusal == {"status": "refused", "reason":
        "resource-version prepare requires an initialized fresh root, exact input/runtime/host, and ordinary preparation",
        "error": "ValueError"}
    assert case.runtime_calls == []
    assert case.enroll_calls == []
