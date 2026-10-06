"""Execute the real worker environment transport without Docker or traffic.

The rolling generator reads real local intent/plan files. Scientific plan and
readiness boundaries are controlled; this proves only launch argv construction.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_formal_parallel as formal


ROOT = Path(__file__).resolve().parents[1]
ROLLING = "QCSD_RAPID_ROLLING_LAUNCH_INPUT"
EPOCH = "QCSD_RAPID_EPOCH_LAUNCH_INPUT"
COMPATIBILITY = "QCSD_RAPID_COLLECTION_COMPATIBILITY"


def _function(source, name):
    begin = source.index(name + "() {\n")
    end = source.index("\n}\n", begin) + 3
    return source[begin:end]


def _segments():
    source = (ROOT / "qcsd-lab").read_text()
    begin = source.index("container=(\n  docker run")
    end = source.index('if [[ "${1:-}" == "test"', begin)
    base = source[begin:end]
    begin = source.index('      parallel_formal_worker_inputs="$(parallel_python formal-inputs')
    end = source.index('      parallel_formal_worker_rows_text=', begin)
    return source, base, source[begin:end]


def _run(tmp_path, environments, *, version="v6", formal_run=True,
         historical=False, duplicate=False, missing=False):
    source, base, replace = _segments()
    if historical:
        begin = base.index("  if (( parallel_formal )); then\n")
        end = base.index('  for rapid_pin_row in "${rapid_public_hosts[@]}"', begin)
        base = base[:begin] + base[end:]
    inputs = []
    for index, environment in enumerate(environments):
        path = tmp_path / f"inputs-{index}.json"
        path.write_text(json.dumps({"environment": environment}))
        inputs.append(path)
    key = ROLLING if version == "v6" else EPOCH
    lines = [
        "set -euo pipefail",
        'runtime=(--read-only --env QCSD_CAPTURE_CLIENT_CPU=0 --env QCSD_CAPTURE_ORCHESTRATOR_CPU=1)',
        'network_mode=fixture-network', 'image_id=sha256:fixture',
        "ROOT=" + shlex.quote(str(ROOT)),
        'rapid_capture=1', 'rapid_image_shell_host=/fixture/qcsd-lab',
        'rapid_static_evidence_args=()',
        'rapid_compatibility_args=(--env ' + shlex.quote(COMPATIBILITY + "=" + environments[0][COMPATIBILITY]) + ')',
        'rapid_public_hosts=()', 'rapid_capture_version=' + shlex.quote(version),
        'parallel_formal=' + str(int(formal_run)), 'parallel_authority=/fixture/authority.json',
        'parallel_prepared_arguments=()',
        _function(source, "parallel_environment_rows"),
        _function(source, "replace_container_environment"),
        "parallel_python() { cat -- \"${input_paths[parallel_index]}\"; }",
        "input_paths=(" + " ".join(shlex.quote(str(path)) for path in inputs) + ")",
    ]
    if not missing:
        lines.append(key + "=" + shlex.quote(environments[0][key]))
    lines.extend([base, 'parallel_base_container=("${container[@]}")'])
    if duplicate:
        lines.append('parallel_base_container+=(--env ' + shlex.quote(key + "=duplicate") + ')')
    if formal_run:
        lines.extend([
            "for parallel_index in 0 1; do",
            '  container=("${parallel_base_container[@]}")', replace,
            '  printf \'%s\\0\' "${container[@]}"',
            '  printf \'%s\\0\' __END_WORKER__', "done",
        ])
    else:
        lines.append('printf \'%s\\0\' "${container[@]}"')
    script = tmp_path / "array-only.sh"
    script.write_text("\n".join(lines) + "\n")
    return subprocess.run(["/bin/bash", str(script)], capture_output=True, timeout=30)


def _workers(result):
    workers, current = [], []
    for argument in result.stdout.decode().split("\0"):
        if argument == "__END_WORKER__":
            workers.append(current)
            current = []
        elif argument:
            current.append(argument)
    return workers


def _environments(tmp_path):
    capsule = tmp_path / "capsule.json"
    formal.shared.put(capsule, {"controlled_scheduling_boundary": True})
    environments = []
    for index in range(2):
        lane_root = tmp_path / f"lane-{index}"
        lane_root.mkdir()
        intent, plan = lane_root / "intent.json", lane_root / "plan.json"
        formal.shared.put(intent, {"lane": index, "authority": "controlled-authority"})
        formal.ordinary._create(lane_root, plan, formal.ordinary.PLAN_TYPE,
                                {"scheduling": {"path": str(capsule),
                                 "sha256": formal.shared.sha(formal.shared.read(capsule))}})
        spec = SimpleNamespace(plan_receipt=plan,
                               serializable=lambda index=index: {"lane": index, "image": "controlled-image"})
        fact = (spec, lane_root, intent, {}, {},
                SimpleNamespace(study_version=6, campaign_name=f"lane-{index}"), ())
        environments.append(formal.worker_environment({"installation": None}, index,
                            fact=fact, _readiness_roots=[lane_root]))
    return environments


def test_actual_rolling_generator_and_shell_bind_each_worker_intent(tmp_path):
    environments = _environments(tmp_path)
    result = _run(tmp_path, environments)
    assert result.returncode == 0, result.stderr.decode()
    workers = _workers(result)
    assert len(workers) == 2
    for index, arguments in enumerate(workers):
        for key, value in environments[index].items():
            assert arguments.count(key + "=" + value) == 1
            position = arguments.index(key + "=" + value)
            assert arguments[position - 1] == "--env"
        binding = json.loads(environments[index][ROLLING])
        assert binding["spec"]["lane"] == index
        assert binding["intent"] == str(tmp_path / f"lane-{index}/intent.json")
        assert binding["intent_sha256"] == formal.shared.sha(formal.shared.read(Path(binding["intent"])))
        assert binding["root"] == str(tmp_path / f"lane-{index}")
        assert binding["readiness_mount_roots"] == [str(tmp_path / f"lane-{index}")]
        assert environments[1 - index][ROLLING] not in arguments


def test_historical_shell_reproduces_actual_zero_entry_refusal(tmp_path):
    result = _run(tmp_path, _environments(tmp_path), historical=True)
    assert result.returncode != 0
    assert f"expected one {ROLLING} environment, observed 0" in result.stderr.decode()
    assert not result.stdout


def test_duplicate_rolling_binding_retains_exact_one_refusal(tmp_path):
    result = _run(tmp_path, _environments(tmp_path), duplicate=True)
    assert result.returncode != 0
    assert f"expected one {ROLLING} environment, observed 2" in result.stderr.decode()
    assert not result.stdout


def test_missing_authenticated_host_binding_refuses_before_worker_transport(tmp_path):
    result = _run(tmp_path, _environments(tmp_path), missing=True)
    assert result.returncode != 0
    assert ROLLING in result.stderr.decode()
    assert not result.stdout


def test_unmarked_serial_array_keeps_original_environment(tmp_path):
    result = _run(tmp_path, _environments(tmp_path), formal_run=False)
    assert result.returncode == 0, result.stderr.decode()
    assert not any(argument.startswith(ROLLING + "=") or argument.startswith(EPOCH + "=")
                   for argument in result.stdout.decode().split("\0"))


def test_formal_epoch_route_has_each_declared_worker_binding(tmp_path):
    environments = [{COMPATIBILITY: "/fixture/capsule.json", EPOCH: json.dumps({"worker": index})}
                    for index in range(2)]
    result = _run(tmp_path, environments, version="v5")
    assert result.returncode == 0, result.stderr.decode()
    for index, arguments in enumerate(_workers(result)):
        assert arguments.count(EPOCH + "=" + environments[index][EPOCH]) == 1
        assert not any(argument.startswith(ROLLING + "=") for argument in arguments)


def test_worker_projection_still_refuses_unsupported_environment(tmp_path):
    environments = _environments(tmp_path)
    environments[0]["UNDECLARED"] = "value"
    result = _run(tmp_path, environments)
    assert result.returncode != 0
    assert "undeclared control input" in result.stderr.decode()
    assert not result.stdout
