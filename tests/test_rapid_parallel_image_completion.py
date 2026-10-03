"""Exercise host image dispatch with real local children, without Docker.

The retained capture/installed proof payloads are explicit engineering fixtures.
Actual subprocess stdout, stderr, status and operation/input closure are real.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys

import pytest

from qcsd_lab import rapid_parallel_capture as parallel, verification
from qcsd_lab.rapid_lane_evidence import HOST_GATE_SCRIPT
from tests.test_rapid_parallel_capture import context, _released, _write


PROJECT = Path(__file__).resolve().parents[1]
LOCAL_CHILD = (
    "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1])); "
    "sys.stderr.buffer.write(bytes.fromhex(sys.argv[2])); "
    "raise SystemExit(int(sys.argv[3]))"
)


@pytest.fixture
def image_context(context, monkeypatch):
    execution = Path(context.authority["runtime"]["execution_root"])
    output = execution / "results" / "image-completion"
    output.parent.mkdir()
    context.output.rename(output)
    context.output = output
    # The inventory really traverses source, tools, config and result evidence.
    for relative in ("src/qcsd_lab/control.py", "tools/rapid_parallel_capture.py"):
        path = context.runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# declared engineering source fixture\n")
    qualifier = execution / "config/qualified/receipt.json"
    _write(qualifier, {"engineering_fixture": True, "scientific_credit": False})
    result_seal = output / "retained-result/evidence.sha256"
    result_seal.parent.mkdir()
    result_seal.write_bytes(b"retained engineering capture seal fixture\n")
    _released(context)
    command = [context.authority["runtime"]["host_launcher"],
               "parallel-diagnostic-run", str(context.path), str(output)]
    started = parallel.load(output / "batch-launch.json")["started_at"]
    _write(output / "operator-intent.json", {
        "command": command, "authority_sha256": context.digest})
    _write(output / "host-start.json", {
        "command": command, "authority_sha256": context.digest,
        "started_at": started, "gate_script_sha256": parallel.sha(HOST_GATE_SCRIPT.encode()),
        "host": {"argv": [sys.executable, "-c", HOST_GATE_SCRIPT, json.dumps(command), "3"]}})
    (output / "host.stdout").write_bytes(b"retained capture closure fixture\n")
    (output / "host.stderr").write_bytes(b"")
    _write(output / "host-process.json", {
        "command": command, "started_at": started, "completed_at": parallel.now(), "returncode": 0,
        "host_start_sha256": parallel.sha(parallel.read(output / "host-start.json")),
        "stdout_sha256": parallel.sha(parallel.read(output / "host.stdout")),
        "stderr_sha256": parallel.sha(parallel.read(output / "host.stderr"))})
    context.host_checks = []
    def declared_host(value):
        assert value == context.authority
        context.host_checks.append(value)
    monkeypatch.setattr(parallel, "host_source", declared_host)
    def forbidden(*_args, **_kwargs):
        pytest.fail("diagnostic host must not load campaigns or run ordinary deep verification")
    monkeypatch.setattr(parallel, "_campaigns", forbidden)
    monkeypatch.setattr(verification, "verify_result", forbidden)
    context.result_seal = result_seal
    context.qualifier = qualifier
    return context


def installed_payload(context, valid=True):
    runtime = context.authority["runtime"]
    return {"schema_version": 1, "authority_sha256": context.digest,
        "preflight": {"authority_sha256": context.digest, "runtime": {
            "collection_image_digest": runtime["collection_image_digest"],
            "source_manifest_sha256": parallel.sha(parallel.read(Path(runtime["source_manifest"]))),
            "client_sha256": parallel.sha(parallel.read(Path(runtime["client_binary"])))}},
        "result": {"schema_version": 1, "lanes": [
            {"campaign": "buflo", "valid": valid, "accepted": int(valid)},
            {"campaign": "cs-buflo", "valid": valid, "accepted": int(valid)}],
            "valid": valid, "host_returncode": 0,
            "formal_accepted_trace_count": 0, "scientific_credit": False}}


def local_executor(monkeypatch, raw, *, returncode=0, mutate=None, spawn_error=False):
    real_run = subprocess.run
    calls = []
    stderr_bytes = b"actual local verification child stderr\n"
    def run(command, *, stdin, stdout, stderr, check):
        calls.append(list(command))
        assert stdin == subprocess.DEVNULL and check is False
        assert not stdout.closed and not stderr.closed
        assert Path(stdout.name).name == "stdout.log" and Path(stderr.name).name == "stderr.log"
        assert stdout.mode == stderr.mode == "xb"
        if spawn_error:
            return real_run([str(Path(stdout.name).parent / "absent-executable")],
                stdin=stdin, stdout=stdout, stderr=stderr, check=check)
        process = real_run([sys.executable, "-I", "-B", "-c", LOCAL_CHILD,
            raw.hex(), stderr_bytes.hex(), str(returncode)],
            stdin=stdin, stdout=stdout, stderr=stderr, check=check)
        if mutate is not None:
            mutate()
        return process
    monkeypatch.setattr(parallel.subprocess, "run", run)
    return calls, stderr_bytes


def closed_operation(context, expected_returncode, expected_stdout, expected_stderr):
    operation = context.output / "image-verification-000001"
    started = parallel.load(operation / "started.json")
    completed = parallel.load(operation / "completed.json")
    assert started["command"] == completed["command"] == parallel.result_verification_command(context.path, context.output)
    assert started["authority_sha256"] == context.digest
    assert completed["returncode"] == expected_returncode
    assert completed["started_at"] == started["started_at"] <= completed["completed_at"]
    for name in ("started.json", "stdout.log", "stderr.log"):
        key = {"started.json": "started_sha256", "stdout.log": "stdout_sha256", "stderr.log": "stderr_sha256"}[name]
        assert completed[key] == parallel.sha(parallel.read(operation / name))
    assert (operation / "stdout.log").read_bytes() == expected_stdout
    assert (operation / "stderr.log").read_bytes() == expected_stderr
    assert started["formal_accepted_trace_count"] == completed["formal_accepted_trace_count"] == 0
    assert started["scientific_credit"] is completed["scientific_credit"] is False
    assert not (context.output / "deep-verification.json").exists()
    return started, completed


@pytest.mark.parametrize("valid", [True, False])
def test_image_completion_uses_installed_module_and_closes_actual_child(image_context, monkeypatch, valid):
    context = image_context
    payload = installed_payload(context, valid)
    raw = (json.dumps(payload) + "\n").encode()
    calls, stderr = local_executor(monkeypatch, raw, returncode=0 if valid else 1)
    result = parallel.verify_results_in_image(context.path, context.output)
    assert result == payload["result"] and result["valid"] is valid
    assert context.host_checks == [context.authority]
    started, completed = closed_operation(context, 0 if valid else 1, raw, stderr)
    assert completed["invocation_error"] is completed["inventory_error"] is None
    assert started["input_files"] == completed["input_files_after"]
    for path in (context.path, context.workload, context.qualifier, context.result_seal,
                 context.runtime / "src/qcsd_lab/control.py", context.runtime / "tools/rapid_parallel_capture.py",
                 context.output / "host-process.json", context.output / "lane-1/gate/host-partition.json"):
        assert started["input_files"][str(path)] == parallel.sha(parallel.read(path))
    command = calls[0]
    assert command[:3] == ["docker", "run", "--rm"]
    assert [command[command.index(key) + 1] for key in ("--network", "--cap-drop", "--security-opt")] == [
        "none", "ALL", "no-new-privileges"]
    assert "--read-only" in command
    volumes = [command[i + 1] for i, item in enumerate(command[:-1]) if item == "--volume"]
    runtime = context.authority["runtime"]
    expected_roots = {runtime["runtime_source_root"], runtime["execution_root"],
        str(Path(runtime["source_manifest"]).parent), str(Path(runtime["client_binary"]).parent), str(context.path.parent)}
    assert set(volumes) == {f"{root}:{root}:ro" for root in expected_roots}
    assert command[command.index("--tmpfs") + 1].startswith("/tmp:")
    position = command.index("--entrypoint")
    assert command[position:position + 9] == ["--entrypoint", "/opt/qcsd-venv/bin/python3",
        runtime["collection_image_digest"], "-I", "-B", "-m", "qcsd_lab.rapid_parallel_capture",
        "verify-installed", "--authority"]
    assert command[-5:] == [str(context.path), "--output", str(context.output), "--sha256", context.digest]


@pytest.mark.parametrize("mutation", ["authority", "image", "source", "client", "schema-type", "preflight-type",
    "runtime-type", "valid-type", "credit-type", "credit", "scientific", "status", "malformed", "payload-type"])
def test_installed_identity_type_and_status_failures_preserve_closed_child(image_context, monkeypatch, mutation):
    context = image_context
    payload = installed_payload(context)
    returncode = 0
    if mutation == "authority": payload["authority_sha256"] = "0" * 64
    elif mutation in {"image", "source", "client"}:
        field = {"image": "collection_image_digest", "source": "source_manifest_sha256", "client": "client_sha256"}[mutation]
        payload["preflight"]["runtime"][field] = "0" * 64
    elif mutation == "schema-type": payload["schema_version"] = True
    elif mutation == "preflight-type": payload["preflight"] = []
    elif mutation == "runtime-type": payload["preflight"]["runtime"] = []
    elif mutation == "valid-type": payload["result"]["valid"] = 1
    elif mutation == "credit-type": payload["result"]["formal_accepted_trace_count"] = False
    elif mutation == "credit": payload["result"]["formal_accepted_trace_count"] = 1
    elif mutation == "scientific": payload["result"]["scientific_credit"] = True
    elif mutation == "status": returncode = 7
    elif mutation == "payload-type": payload = []
    raw = b"not JSON\n" if mutation == "malformed" else (json.dumps(payload) + "\n").encode()
    _, stderr = local_executor(monkeypatch, raw, returncode=returncode)
    with pytest.raises(ValueError):
        parallel.verify_results_in_image(context.path, context.output)
    started, completed = closed_operation(context, returncode, raw, stderr)
    assert started["input_files"] == completed["input_files_after"]


@pytest.mark.parametrize("changed", ["workload", "qualifier", "source", "result", "host-log"])
def test_inputs_changed_during_real_child_are_recorded_then_rejected(image_context, monkeypatch, changed):
    context = image_context
    raw = (json.dumps(installed_payload(context)) + "\n").encode()
    target = {"workload": context.workload, "qualifier": context.qualifier,
        "source": context.runtime / "src/qcsd_lab/control.py", "result": context.result_seal,
        "host-log": context.output / "host.stdout"}[changed]
    _, stderr = local_executor(monkeypatch, raw, mutate=lambda: target.write_bytes(target.read_bytes() + b"changed\n"))
    with pytest.raises(ValueError, match="inputs changed"):
        parallel.verify_results_in_image(context.path, context.output)
    started, completed = closed_operation(context, 0, raw, stderr)
    assert started["input_files"][str(target)] != completed["input_files_after"][str(target)]


def test_failed_post_inventory_retains_actual_terminal_logs(image_context, monkeypatch):
    context = image_context
    raw = (json.dumps(installed_payload(context)) + "\n").encode()
    link = context.output / "unexpected-link"
    _, stderr = local_executor(monkeypatch, raw, mutate=lambda: link.symlink_to(context.workload))
    with pytest.raises(ValueError, match="symlink"):
        parallel.verify_results_in_image(context.path, context.output)
    _, completed = closed_operation(context, 0, raw, stderr)
    assert completed["input_files_after"] is None and "symlink" in completed["inventory_error"]


def test_actual_spawn_error_has_null_status_and_retained_empty_logs(image_context, monkeypatch):
    local_executor(monkeypatch, b"", spawn_error=True)
    with pytest.raises(FileNotFoundError):
        parallel.verify_results_in_image(image_context.path, image_context.output)
    started, completed = closed_operation(image_context, None, b"", b"")
    assert "FileNotFoundError" in completed["invocation_error"]
    assert completed["inventory_error"] is None
    assert started["input_files"] == completed["input_files_after"]


def test_changed_recorded_host_output_blocks_before_image_process(image_context, monkeypatch):
    image_context.output.joinpath("host.stdout").write_bytes(b"changed retained host output\n")
    calls, _ = local_executor(monkeypatch, b"{}")
    with pytest.raises(ValueError, match="actual host process"):
        parallel.verify_results_in_image(image_context.path, image_context.output)
    assert calls == [] and not list(image_context.output.glob("image-verification-*"))


@pytest.mark.parametrize("valid", [True, False])
def test_installed_cli_and_real_module_footer_propagate_status(valid):
    # Execute the actual argparse action and the actual module footer in a child.
    # Only installed proof/deep capture boundaries are supplied as fixtures.
    script = """
import ast,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from qcsd_lab import rapid_parallel_capture as module
valid=json.loads(sys.argv[2]); calls=[]
def preflight(path,digest):
    calls.append('preflight'); assert str(path)=='/fixture/authority.json' and digest=='a'*64
    return {'authority_sha256':digest}
def verify(path,output):
    calls.append('verify'); assert calls==['preflight','verify'] and str(output)=='/fixture/results'
    return {'valid':valid,'formal_accepted_trace_count':0,'scientific_credit':False}
module.image_preflight=preflight; module.verify_results=verify
path=Path(module.__file__); tree=ast.parse(path.read_text()); footer=tree.body[-1]
assert isinstance(footer,ast.If)
sys.argv=[str(path),'verify-installed','--authority','/fixture/authority.json','--output','/fixture/results','--sha256','a'*64]
module.__dict__['__name__']='__main__'
exec(compile(ast.Module(body=[footer],type_ignores=[]),str(path),'exec'),module.__dict__)
"""
    process = subprocess.run([sys.executable, "-I", "-B", "-c", script,
        str(PROJECT / "src"), json.dumps(valid)], capture_output=True, check=False)
    assert process.returncode == (0 if valid else 1), process.stderr.decode()
    assert process.stderr == b""
    payload = json.loads(process.stdout)
    assert payload["authority_sha256"] == "a" * 64 and payload["result"]["valid"] is valid


def test_formal_dispatch_still_uses_its_official_verifier_without_diagnostic_image(monkeypatch, tmp_path):
    # Dispatch identity only: formal authority/lifecycle closure has its own suite.
    value = {"artifact_type": "qcsd-two-worker-formal-lane-authority"}
    result = {"formal_dispatch_fixture": True}
    calls = []
    monkeypatch.setattr(parallel, "authority", lambda path: value)
    monkeypatch.setattr(parallel, "verify_results", lambda path, output: calls.append((path, output)) or result)
    monkeypatch.setattr(parallel, "host_source", lambda value: pytest.fail("formal dispatched as diagnostic"))
    assert parallel.verify_results_in_image(tmp_path / "authority", tmp_path / "output") is result
    assert calls == [(tmp_path / "authority", tmp_path / "output")]


@pytest.mark.parametrize("valid", [True, False])
def test_operator_verify_action_uses_image_dispatch(image_context, monkeypatch, capsys, valid):
    spec = importlib.util.spec_from_file_location("image_completion_operator", PROJECT / "tools/rapid_parallel_capture.py")
    operator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(operator)
    calls = []
    result = installed_payload(image_context, valid)["result"]
    monkeypatch.setattr(parallel, "verify_results_in_image", lambda path, output: calls.append((path, output)) or result)
    monkeypatch.setattr(parallel, "verify_results", lambda *_args: pytest.fail("operator verified diagnostic on host"))
    status = operator.main(["verify", "--authority", str(image_context.path), "--output", str(image_context.output)])
    assert status == (0 if valid else 1)
    assert calls == [(image_context.path, image_context.output)]
    assert json.loads(capsys.readouterr().out) == result


def test_real_operator_host_gate_closes_and_restores_signals_before_image_dispatch(context, monkeypatch):
    spec = importlib.util.spec_from_file_location("image_completion_launch_operator", PROJECT / "tools/rapid_parallel_capture.py")
    operator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(operator)
    execution = Path(context.authority["runtime"]["execution_root"])
    (execution / "results").mkdir()
    output = execution / "results" / "harmless-gated-host"
    launcher_bytes = b"#!/bin/sh\nprintf '%s\\n' 'actual harmless engineering host child'\n"
    for key in ("base_launcher", "host_launcher"):
        launcher = Path(context.authority["runtime"][key])
        launcher.write_bytes(launcher_bytes)
        launcher.chmod(0o700)
    monkeypatch.setattr(parallel, "host_source", lambda value: None)
    previous = {watched: signal.getsignal(watched) for watched in (signal.SIGINT, signal.SIGTERM)}
    calls = []
    result = {"schema_version": 1, "valid": True, "lanes": [],
              "formal_accepted_trace_count": 0, "scientific_credit": False}
    def image_dispatch(path, observed_output):
        assert (path, observed_output) == (context.path, output)
        assert all(signal.getsignal(watched) is handler for watched, handler in previous.items())
        parallel.verify_operator_closure(path, output, parallel.authority(path))
        process = parallel.load(output / "host-process.json")
        assert process["returncode"] == 0
        assert (output / "host.stdout").read_bytes() == b"actual harmless engineering host child\n"
        assert (output / "host.stderr").read_bytes() == b""
        assert process["stdout_sha256"] == parallel.sha(parallel.read(output / "host.stdout"))
        assert process["stderr_sha256"] == parallel.sha(parallel.read(output / "host.stderr"))
        assert process["host_start_sha256"] == parallel.sha(parallel.read(output / "host-start.json"))
        assert not (output / "deep-verification.json").exists()
        calls.append(process)
        return result
    monkeypatch.setattr(parallel, "verify_results_in_image", image_dispatch)
    monkeypatch.setattr(parallel, "verify_results", lambda *_args: pytest.fail("launch completion ran diagnostic verifier on host"))
    assert operator.launch(context.path, output) == result
    assert len(calls) == 1 and parallel.load(output / "deep-verification.json") == result
    assert not (output / "blocked.json").exists()
    assert all(signal.getsignal(watched) is handler for watched, handler in previous.items())
