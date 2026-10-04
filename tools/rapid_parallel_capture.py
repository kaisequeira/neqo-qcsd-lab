#!/usr/bin/env python3
"""Run/reopen an opt-in two-worker batch with its explicitly typed authority."""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab.rapid_lane_evidence import HOST_GATE_SCRIPT, _process_identity


def _host_authority(path: Path, *, _context=None) -> dict:
    """Reject another checkout before reopening the scientific authority."""
    value = parallel.load(path)
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1 or value.get("artifact_type") not in {
            parallel.AUTHORITY_TYPE, "qcsd-two-worker-formal-lane-authority"}):
        raise ValueError("parallel operator authority type or schema differs")
    parallel._runtime_authority(value)
    parallel.host_source(value)
    value = parallel.authority(path, _context=_context)
    # Full reopening may be lengthy. Preserve the original boundary check.
    parallel.host_source(value)
    return value


def launch(authority_path: Path, output: Path) -> dict:
    from qcsd_lab.rapid_operation_facts import OperationFacts
    context = OperationFacts()
    parallel.read(authority_path)
    authority_path = authority_path.resolve(strict=True)
    value = _host_authority(authority_path, _context=context)
    authority_digest = parallel.sha(parallel.read(authority_path))
    output = output.absolute()
    execution = Path(value["runtime"]["execution_root"])
    if (not output.is_relative_to(execution / "results") or ".." in output.parts
        or output.exists() or output.is_symlink()):
        raise ValueError("parallel output must be a fresh child beneath the execution results directory")
    parallel.regular_dir(output.parent)
    context.check()
    output.mkdir(mode=0o700)
    command = [value["runtime"]["host_launcher"], parallel.launch_action(value), str(authority_path), str(output)]
    parallel.put(output / "operator-intent.json", {"schema_version": 1, "command": command,
        "authority_sha256": authority_digest, "created_at": parallel.now(),
        "operator_implementation_sha256": parallel.sha(parallel.read(Path(__file__))),
        "formal_accepted_trace_count": 0, "scientific_credit": False})
    env = {key: item for key, item in os.environ.items() if not key.startswith("QCSD_")}
    env.update(QCSD_LAB_COLLECTION_IMAGE=value["runtime"]["collection_image_digest"],
        QCSD_RAPID_IMAGE_SOURCE_QCSD=value["runtime"]["base_launcher"],
        QCSD_PARALLEL_AUTHORITY_SHA256=authority_digest,
        QCSD_RAPID_DNS_RECEIPT_PATH=str(output / "dns-pins.json"), PYTHONDONTWRITEBYTECODE="1")
    if value["artifact_type"] != parallel.AUTHORITY_TYPE:
        from qcsd_lab.rapid_formal_parallel import _audit, worker_environment
        _, facts = _audit(authority_path, _context=context)
        env.update(worker_environment(value, 0, fact=facts[0], _context=context))
        # Archived execution roots have no venv and the launcher seals PATH.
        # Carry the operator's actual project interpreter only for formal work.
        env["QCSD_PARALLEL_HOST_PYTHON"] = sys.executable
    read_fd, write_fd = os.pipe()
    child = None
    started = parallel.now()
    previous = {}
    try:
        with (output / "host.stdout").open("xb") as stdout, (output / "host.stderr").open("xb") as stderr:
            child = subprocess.Popen([sys.executable, "-c", HOST_GATE_SCRIPT, json.dumps(command), str(read_fd)],
                env=env, stdout=stdout, stderr=stderr, pass_fds=(read_fd,), start_new_session=True)
            os.close(read_fd)
            read_fd = -1
            if parallel.sha(parallel.read(authority_path)) != authority_digest:
                raise ValueError("parallel authority changed before the actual host gate release")
            context.check()
            parallel.put(output / "host-start.json", {"schema_version": 1, "command": command,
                "authority_sha256": authority_digest, "started_at": started,
                "host": _process_identity(child.pid), "operator": _process_identity(os.getpid()),
                "gate_script_sha256": parallel.sha(HOST_GATE_SCRIPT.encode())})
            os.write(write_fd, b"G")
            os.close(write_fd)
            write_fd = -1
            def forward(signum, _frame):
                if child.poll() is None:
                    os.killpg(child.pid, signum)
            for watched in (signal.SIGINT, signal.SIGTERM):
                previous[watched] = signal.signal(watched, forward)
            returncode = child.wait()
        parallel.put(output / "host-process.json", {"schema_version": 1, "command": command,
            "started_at": started, "completed_at": parallel.now(), "returncode": returncode,
            "host_start_sha256": parallel.sha(parallel.read(output / "host-start.json")),
            "stdout_sha256": parallel.sha(parallel.read(output / "host.stdout")),
            "stderr_sha256": parallel.sha(parallel.read(output / "host.stderr")),
            "formal_accepted_trace_count": 0, "scientific_credit": False})
        # The capture child has closed. Its forwarding handler must not consume
        # signals intended for the following installed verification process.
        for watched, handler in previous.items():
            signal.signal(watched, handler)
        previous.clear()
        result = parallel.verify_results_in_image(authority_path, output)
        parallel.put(output / "deep-verification.json", result)
        return result
    except BaseException as error:
        if write_fd >= 0:
            os.close(write_fd)
            write_fd = -1
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGINT)
            child.wait()
        parallel.put(output / "blocked.json", {"schema_version": 1, "observed_at": parallel.now(),
            "exception_type": type(error).__name__, "message": str(error),
            "formal_accepted_trace_count": 0, "scientific_credit": False})
        raise
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)
        for watched, handler in previous.items():
            signal.signal(watched, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("launch", "verify", "retire-session"))
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        parallel.read(args.authority)
        args.authority = args.authority.resolve(strict=True)
        args.output = args.output.absolute()
        if args.action == "launch":
            result = launch(args.authority, args.output)
        elif args.action == "retire-session":
            result = parallel.retire_session(args.authority.absolute(), args.output.absolute())
        else:
            parallel._require_result_birth(args.output)
            _host_authority(args.authority)
            result = parallel.verify_results_in_image(args.authority, args.output)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"parallel capture: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("valid", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
