from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .campaign import NEQO_CLIENT, collect_campaign
from .discover import discover
from .manifest import write_frozen_manifest
from .plotting import plot_samples
from .report import create_report
from .util import LAB_ROOT, git_commit, run


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="qcsd-lab", description="Live QCSD capture laboratory")
    commands = root.add_subparsers(dest="command", required=True)

    commands.add_parser("doctor", help="check the collection environment")

    discovery = commands.add_parser("discover", help="freeze public browser request definitions")
    discovery.add_argument("--url", action="append", required=True)
    discovery.add_argument("--output", type=Path, required=True)
    discovery.add_argument("--timeout-ms", type=int, default=60_000)
    discovery.add_argument("--force", action="store_true")

    probe = commands.add_parser("probe", help="preflight a discovered workload with Neqo HTTP/3")
    probe.add_argument("--input-manifest", type=Path, required=True)
    probe.add_argument("--output", type=Path, required=True)
    probe.add_argument("--max-bytes", type=int, default=1_048_576)
    probe.add_argument("--timeout-seconds", type=int, default=30)
    probe.add_argument("--force", action="store_true")
    probe.add_argument(
        "--keep-unavailable",
        action="store_true",
        help="retain resources that did not pass direct HTTP/3 preflight",
    )

    collect = commands.add_parser("collect", help="run a versioned sequential campaign")
    collect.add_argument("--campaign", type=Path, required=True)
    collect.add_argument("--results", type=Path, default=Path("/lab/results"))
    collect.add_argument("--force", action="store_true")

    plot = commands.add_parser("plot", help="render observer, exactness, rate, and comparison plots")
    plot.add_argument("samples", type=Path, nargs="+")
    plot.add_argument("--output", type=Path, required=True)
    plot.add_argument("--bin-ms", type=int, default=50)

    report = commands.add_parser("report", help="aggregate campaign samples")
    report.add_argument("--results", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)

    test = commands.add_parser("test", help="run deterministic lab tests")
    test.add_argument("--local-acceptance", action="store_true")
    test.add_argument("--capture-acceptance", action="store_true")
    test.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.command == "doctor":
        _doctor()
    elif args.command == "discover":
        digest = discover(args.url, args.output, timeout_ms=args.timeout_ms, force=args.force)
        print(f"wrote {args.output} ({digest})")
    elif args.command == "probe":
        _probe(args)
    elif args.command == "collect":
        root = collect_campaign(args.campaign.resolve(), args.results.resolve(), force=args.force)
        print(root)
    elif args.command == "plot":
        plot_samples([sample.resolve() for sample in args.samples], args.output.resolve(), bin_ms=args.bin_ms)
        print(args.output)
    elif args.command == "report":
        create_report(args.results.resolve(), args.output.resolve())
        print(args.output)
    elif args.command == "test":
        environment = os.environ.copy()
        if args.local_acceptance:
            environment["QCSD_RUN_LOCAL_ACCEPTANCE"] = "1"
        if args.capture_acceptance:
            environment["QCSD_RUN_CAPTURE_ACCEPTANCE"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", *args.pytest_args],
            cwd=LAB_ROOT,
            env=environment,
            check=False,
        )
        raise SystemExit(result.returncode)


def _doctor() -> None:
    required = ["dumpcap", "tshark", "capinfos", "ethtool", "git", "neqo-qcsd-client"]
    missing = [program for program in required if shutil.which(program) is None]
    report = {
        "ok": not missing,
        "missing": missing,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "unknown"),
        "lab_commit": git_commit(LAB_ROOT),
        "neqo_commit": git_commit(LAB_ROOT / "third_party/neqo-qcsd"),
        "nss": {
            "version": os.environ.get("NSS_VERSION", "unknown"),
            "revision": os.environ.get("NSS_REVISION", "unknown"),
        },
        "nspr": {
            "version": os.environ.get("NSPR_VERSION", "unknown"),
            "revision": os.environ.get("NSPR_REVISION", "unknown"),
        },
        "versions": {},
    }
    status = Path("/proc/self/status")
    if status.exists():
        report["capabilities"] = {
            key: value
            for line in status.read_text(encoding="utf-8").splitlines()
            if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"))
            for key, value in [line.split(":", 1)]
        }
    for program in required:
        if program not in missing:
            version = run([program, "--version"], check=False)
            report["versions"][program] = version.stdout.splitlines()[0] if version.stdout else "unknown"
    interface = os.environ.get("QCSD_LAB_INTERFACE", "eth0")
    report["interface"] = run(["ip", "-details", "link", "show", interface], check=False).stdout
    report["offloads"] = run(["ethtool", "-k", interface], check=False).stdout
    print(json.dumps(report, indent=2))
    if missing:
        raise SystemExit(1)


def _probe(args: argparse.Namespace) -> None:
    if args.output.exists() and not args.force:
        print(
            f"{args.output} is immutable; choose a new version or pass --force",
            file=sys.stderr,
        )
        raise SystemExit(1)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="qcsd-probe-", dir=args.output.parent) as directory:
        temporary_output = Path(directory) / "resolved.json"
        result = run(
            [
                NEQO_CLIENT,
                "probe",
                "--input-manifest",
                str(args.input_manifest),
                "--output",
                str(temporary_output),
                "--max-bytes",
                str(args.max_bytes),
                "--timeout-seconds",
                str(args.timeout_seconds),
            ],
            log=args.output.with_suffix(args.output.suffix + ".log"),
            check=False,
        )
        if result.returncode:
            raise SystemExit(result.returncode)
        resolved = json.loads(temporary_output.read_text(encoding="utf-8"))
    if not args.keep_unavailable:
        available = {
            resource["id"] for resource in resolved["resources"] if resource.get("known_valid")
        }
        changed = True
        while changed:
            retained = {
                resource["id"]
                for resource in resolved["resources"]
                if resource["id"] in available
                and set(resource.get("depends_on", [])) <= available
            }
            changed = retained != available
            available = retained
        resolved["resources"] = [
            resource for resource in resolved["resources"] if resource["id"] in available
        ]
        if not resolved["resources"]:
            print("preflight left no directly fetchable HTTP/3 resources", file=sys.stderr)
            raise SystemExit(1)
    digest = write_frozen_manifest(args.output, resolved, force=args.force)
    print(f"wrote {args.output} ({digest})")


if __name__ == "__main__":
    main()
