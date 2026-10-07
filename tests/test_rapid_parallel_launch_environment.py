"""Execute the real worker environment transport without Docker or traffic.

The rolling generator reads real local intent/plan files. Scientific plan and
readiness boundaries are controlled; this proves only launch argv construction.
"""
from __future__ import annotations

import hashlib
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
    worker_inputs = source[begin:end]
    begin = source.index('      if [[ -n "${QCSD_RAPID_FAST_CERTIFICATE_SHA256:-}" ]]; then\n'
                         '        replace_container_environment QCSD_RAPID_FAST_CERTIFICATE_PATH')
    end = source.index('      parallel_formal_worker_inputs=', begin)
    return source, base, source[begin:end], worker_inputs


def _actual_issuer_block(source):
    begin = source.index('  if (( parallel_formal )); then\n'
                         '    unset QCSD_RAPID_FAST_CERTIFICATE_PATH QCSD_RAPID_FAST_CERTIFICATE_SHA256')
    end = source.index('  parallel_authority_sha256="$(sha256sum -- "${parallel_authority}")"', begin)
    return source[begin:end]


def _run_issued_public_workers(tmp_path, *, issue="valid", duplicate=False):
    """Execute the actual issuer, base argv and both kernel-TX worker projections."""
    source, base, fast_replace, replace = _segments()
    environments = _environments(tmp_path)
    inputs = []
    for index, environment in enumerate(environments):
        path = tmp_path / f"issued-inputs-{index}.json"
        path.write_text(json.dumps({"environment": environment}))
        inputs.append(path)
    output = tmp_path / "results/issued-flight"
    output.mkdir(parents=True)
    certificate = output / "fast-launch-certificate.json"
    certificate.write_bytes(b"controlled issuer output\n")
    digest = hashlib.sha256(certificate.read_bytes()).hexdigest()
    first = {"campaign_path": "/fixture/first.yml",
             "fast_launch_certificate_path": str(certificate),
             "fast_launch_certificate_sha256": digest}
    if issue == "missing-path":
        del first["fast_launch_certificate_path"]
    elif issue == "missing-sha":
        del first["fast_launch_certificate_sha256"]
    elif issue == "wrong-sha":
        first["fast_launch_certificate_sha256"] = "0" * 64
    issuer = tmp_path / "formal-entry-inputs.json"
    issuer.write_text(json.dumps(first))
    lines = [
        "set -euo pipefail", "unset QCSD_RAPID_FAST_CERTIFICATE_PATH QCSD_RAPID_FAST_CERTIFICATE_SHA256",
        "parallel_formal=1", "parallel_authority=/fixture/authority.json",
        "parallel_output=" + shlex.quote(str(output)),
        "parallel_fast_container_env=()",
        "issuer_file=" + shlex.quote(str(issuer)),
        "input_paths=(" + " ".join(shlex.quote(str(path)) for path in inputs) + ")",
        'parallel_python() { if [[ "$1" == formal-entry-inputs ]]; then cat -- "$issuer_file"; '
        'else cat -- "${input_paths[parallel_index]}"; fi; }',
        _actual_issuer_block(source),
        'printf "ISSUER_CLOSED\\n" >&2',
        'runtime=(--read-only --env QCSD_CAPTURE_CLIENT_CPU=0 --env QCSD_CAPTURE_ORCHESTRATOR_CPU=1)',
        'network_mode=fixture-network', 'image_id=sha256:fixture',
        "ROOT=" + shlex.quote(str(ROOT)), 'rapid_capture=1',
        'rapid_image_shell_host=/fixture/qcsd-lab', 'rapid_static_evidence_args=()',
        'rapid_compatibility_args=(--env ' + shlex.quote(COMPATIBILITY + "=" + environments[0][COMPATIBILITY]) + ')',
        'rapid_public_hosts=()', 'rapid_capture_version=v6',
        "QCSD_RAPID_ROLLING_LAUNCH_INPUT=" + shlex.quote(environments[0][ROLLING]),
        'parallel_prepared_sha256=',
        _function(source, "parallel_environment_rows"),
        _function(source, "replace_container_environment"),
        base, 'parallel_base_container=("${container[@]}")',
    ]
    if duplicate:
        lines.append('parallel_base_container+=(--env QCSD_RAPID_FAST_CERTIFICATE_PATH=duplicate)')
    lines.extend((
        'for parallel_index in 0 1; do',
        '  container=("${parallel_base_container[@]}")',
        fast_replace, replace,
        '  printf \'%s\\0\' "${container[@]}"',
        '  printf \'%s\\0\' __END_WORKER__',
        'done',
    ))
    script = tmp_path / "issued-public-worker-argv.sh"
    script.write_text("\n".join(lines) + "\n")
    result = subprocess.run(["/bin/bash", str(script)], capture_output=True, timeout=30)
    return result, certificate, digest


def _run(tmp_path, environments, *, version="v6", formal_run=True,
         historical=False, duplicate=False, missing=False,
         fast_certificate=None, duplicate_certificate=False):
    source, base, fast_replace, replace = _segments()
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
        "unset QCSD_RAPID_FAST_CERTIFICATE_PATH QCSD_RAPID_FAST_CERTIFICATE_SHA256",
        'runtime=(--read-only --env QCSD_CAPTURE_CLIENT_CPU=0 --env QCSD_CAPTURE_ORCHESTRATOR_CPU=1)',
        'network_mode=fixture-network', 'image_id=sha256:fixture',
        "ROOT=" + shlex.quote(str(ROOT)),
        'rapid_capture=1', 'rapid_image_shell_host=/fixture/qcsd-lab',
        'rapid_static_evidence_args=()',
        'rapid_compatibility_args=(--env ' + shlex.quote(COMPATIBILITY + "=" + environments[0][COMPATIBILITY]) + ')',
        'rapid_public_hosts=()', 'rapid_capture_version=' + shlex.quote(version),
        'parallel_formal=' + str(int(formal_run)), 'parallel_authority=/fixture/authority.json',
        'parallel_prepared_arguments=()',
        'parallel_prepared_sha256=', 'parallel_output=/fixture/output',
        'parallel_fast_container_env=()',
        _function(source, "parallel_environment_rows"),
        _function(source, "replace_container_environment"),
        "parallel_python() { cat -- \"${input_paths[parallel_index]}\"; }",
        "input_paths=(" + " ".join(shlex.quote(str(path)) for path in inputs) + ")",
    ]
    if not missing:
        lines.append(key + "=" + shlex.quote(environments[0][key]))
    if fast_certificate is not None:
        path, digest = fast_certificate
        lines.extend([
            "QCSD_RAPID_FAST_CERTIFICATE_PATH=" + shlex.quote(path),
            "QCSD_RAPID_FAST_CERTIFICATE_SHA256=" + shlex.quote(digest),
            "parallel_fast_container_env=(--env " + shlex.quote("QCSD_RAPID_FAST_CERTIFICATE_PATH=" + path) +
            " --env " + shlex.quote("QCSD_RAPID_FAST_CERTIFICATE_SHA256=" + digest) + ")",
        ])
    lines.extend([base, 'parallel_base_container=("${container[@]}")'])
    if duplicate:
        lines.append('parallel_base_container+=(--env ' + shlex.quote(key + "=duplicate") + ')')
    if duplicate_certificate:
        lines.append('parallel_base_container+=(--env QCSD_RAPID_FAST_CERTIFICATE_PATH=duplicate)')
    if formal_run:
        lines.extend([
            "for parallel_index in 0 1; do",
            '  container=("${parallel_base_container[@]}")', fast_replace, replace,
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


def test_issued_certificate_pair_reaches_both_public_worker_argv_exactly_once(tmp_path):
    path = str(tmp_path / "fast-launch-certificate.json")
    digest = "a" * 64
    result = _run(tmp_path, _environments(tmp_path), fast_certificate=(path, digest))
    assert result.returncode == 0, result.stderr.decode()
    for arguments in _workers(result):
        for value in ("QCSD_RAPID_FAST_CERTIFICATE_PATH=" + path,
                      "QCSD_RAPID_FAST_CERTIFICATE_SHA256=" + digest):
            assert arguments.count(value) == 1
            assert arguments[arguments.index(value) - 1] == "--env"


def test_real_issuer_to_both_public_worker_argv_carries_one_certificate_pair(tmp_path):
    result, certificate, digest = _run_issued_public_workers(tmp_path)
    assert result.returncode == 0, result.stderr.decode()
    assert "ISSUER_CLOSED" in result.stderr.decode()
    workers = _workers(result)
    assert len(workers) == 2
    for arguments in workers:
        for value in ("QCSD_RAPID_FAST_CERTIFICATE_PATH=" + str(certificate),
                      "QCSD_RAPID_FAST_CERTIFICATE_SHA256=" + digest):
            assert arguments.count(value) == 1
            assert arguments[arguments.index(value) - 1] == "--env"


@pytest.mark.parametrize("issue", ("missing-path", "missing-sha", "wrong-sha"))
def test_real_issuer_refuses_partial_or_changed_certificate_before_preflight(tmp_path, issue):
    result, _certificate, _digest = _run_issued_public_workers(tmp_path, issue=issue)
    assert result.returncode != 0
    assert "ISSUER_CLOSED" not in result.stderr.decode()
    assert not result.stdout


def test_real_issuer_refuses_duplicate_worker_certificate_before_actuation(tmp_path):
    result, _certificate, _digest = _run_issued_public_workers(tmp_path, duplicate=True)
    assert result.returncode != 0
    assert "ISSUER_CLOSED" in result.stderr.decode()
    assert "expected one QCSD_RAPID_FAST_CERTIFICATE_PATH environment, observed 2" in result.stderr.decode()
    assert not result.stdout


def test_public_worker_refuses_duplicate_certificate_environment(tmp_path):
    result = _run(tmp_path, _environments(tmp_path),
                  fast_certificate=(str(tmp_path / "fast-launch-certificate.json"), "a" * 64),
                  duplicate_certificate=True)
    assert result.returncode != 0
    assert "expected one QCSD_RAPID_FAST_CERTIFICATE_PATH environment, observed 2" in result.stderr.decode()
    assert not result.stdout


@pytest.mark.parametrize("change", ("missing-path", "missing-digest", "wrong-digest"))
def test_issuer_certificate_is_checked_before_expensive_preflight(tmp_path, change):
    source = (ROOT / "qcsd-lab").read_text()
    begin = source.index('      # Refuse a lost or partial issuer result before the costly image')
    end = source.index('    fi\n  elif ! parallel_first_campaign=', begin)
    guard = source[begin:end]
    certificate = tmp_path / "fast-launch-certificate.json"
    certificate.write_bytes(b"issued frame\n")
    import hashlib
    digest = hashlib.sha256(certificate.read_bytes()).hexdigest()
    path = str(certificate)
    if change == "missing-path":
        path = str(tmp_path / "absent-certificate.json")
    elif change == "missing-digest":
        digest = ""
    else:
        digest = "0" * 64
    script = "\n".join(("set -euo pipefail",
        "QCSD_RAPID_FAST_CERTIFICATE_PATH=" + shlex.quote(path),
        "QCSD_RAPID_FAST_CERTIFICATE_SHA256=" + shlex.quote(digest),
        guard, "printf 'costly-preflight-reached\\n'"))
    result = subprocess.run(["/bin/bash", "-c", script], text=True,
                            capture_output=True, timeout=10, check=False)
    assert result.returncode != 0
    assert "costly-preflight-reached" not in result.stdout


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
