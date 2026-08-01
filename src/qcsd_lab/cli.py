from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .campaign import CampaignIncomplete, NEQO_CLIENT, collect_campaign
from .dataset import DatasetValidationError, validate_dataset
from .discover import discover
from .manifest import runtime_manifest, validate_manifest, write_frozen_manifest
from .util import LAB_ROOT, run


RESPONSE_STABILITY_RUNS = 3
RESPONSE_STABILITY_INTERVAL_SECONDS = 30


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="qcsd-lab", description="Live QCSD capture laboratory")
    commands = root.add_subparsers(dest="command", required=True)

    discovery = commands.add_parser("discover", help="freeze public browser request definitions")
    discovery.add_argument("--url", action="append", required=True)
    discovery.add_argument(
        "--allow-origin",
        action="append",
        required=True,
        help="explicit HTTPS origin approved for replay (repeatable)",
    )
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

    collect = commands.add_parser("collect", help="run a sequential capture campaign")
    collect.add_argument("--campaign", type=Path, required=True)
    collect.add_argument("--network-condition")
    collect.add_argument("--results", type=Path, default=Path("/lab/results"))
    collect.add_argument("--resume", type=Path, help="resume an existing result root")

    dataset = commands.add_parser("dataset", help="validate a captured classifier dataset")
    dataset_commands = dataset.add_subparsers(dest="dataset_command", required=True)
    validate = dataset_commands.add_parser(
        "validate", help="validate dataset invariants and PCAP traces"
    )
    validate.add_argument("root", type=Path)
    test = commands.add_parser("test", help="run deterministic lab tests")
    test.add_argument("--capture-acceptance", action="store_true")
    return root


def main(argv: list[str] | None = None) -> None:
    argument_parser = parser()
    args, extra = argument_parser.parse_known_args(argv)
    if extra and args.command != "test":
        argument_parser.error(f"unrecognized arguments: {' '.join(extra)}")
    if args.command == "discover":
        digest = discover(
            args.url,
            args.output,
            allow_origins=args.allow_origin,
            timeout_ms=args.timeout_ms,
            force=args.force,
        )
        print(f"wrote {args.output} ({digest})")
    elif args.command == "probe":
        _probe(args)
    elif args.command == "collect":
        try:
            root = collect_campaign(
                args.campaign.resolve(),
                args.results.resolve(),
                network_condition=args.network_condition,
                resume=args.resume.resolve() if args.resume else None,
            )
        except CampaignIncomplete as error:
            print(error, file=sys.stderr)
            raise SystemExit(1) from None
        print(root)
    elif args.command == "dataset":
        if args.dataset_command == "validate":
            try:
                result = validate_dataset(args.root.resolve())
            except DatasetValidationError as error:
                print(json.dumps({"valid": False, "errors": error.errors}, indent=2))
                raise SystemExit(1) from None
            print(json.dumps(result, indent=2))
    elif args.command == "test":
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *extra],
            cwd=LAB_ROOT,
            check=False,
        )
        raise SystemExit(result.returncode)


def _probe(args: argparse.Namespace) -> None:
    if args.output.exists() and not args.force:
        print(
            f"{args.output} is immutable; choose a new version or pass --force",
            file=sys.stderr,
        )
        raise SystemExit(1)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = json.loads(args.input_manifest.read_text(encoding="utf-8"))
    validate_manifest(source)
    with tempfile.TemporaryDirectory(prefix="qcsd-probe-", dir=args.output.parent) as directory:
        runtime_input = Path(directory) / "input.json"
        runtime_input.write_text(
            json.dumps(runtime_manifest(source), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary_output = Path(directory) / "resolved.json"
        result = run(
            [
                NEQO_CLIENT,
                "probe",
                "--input-manifest",
                str(runtime_input),
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
            if result.stdout:
                print(result.stdout, file=sys.stderr, end="")
            raise SystemExit(result.returncode)
        resolved = json.loads(temporary_output.read_text(encoding="utf-8"))
        try:
            resolved = resolve_probe_output(
                source, resolved, keep_unavailable=args.keep_unavailable
            )
        except ValueError as error:
            if str(error) == "preflight left no directly fetchable HTTP/3 resources":
                print("preflight left no directly fetchable HTTP/3 resources", file=sys.stderr)
                raise SystemExit(1)
            raise
        if resolved.get("replay") is not None:
            stability = _probe_response_stability(
                resolved,
                Path(directory),
                max_bytes=args.max_bytes,
                timeout_seconds=args.timeout_seconds,
            )
            resolved["replay"]["response_stability"] = stability
            required = {resource["id"] for resource in resolved["resources"]}
            unstable = required - set(stability["stable_resource_ids"])
            if unstable:
                ids = ", ".join(map(str, sorted(unstable)))
                print(
                    f"preflight found changing responses for resource IDs: {ids}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
    digest = write_frozen_manifest(args.output, resolved, force=args.force)
    print(f"wrote {args.output} ({digest})")


def _probe_response_stability(
    manifest: dict, directory: Path, *, max_bytes: int, timeout_seconds: int
) -> dict:
    runtime_input = directory / "stability-input.json"
    runtime_input.write_text(
        json.dumps(runtime_manifest(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    runs: list[dict] = []
    for index in range(RESPONSE_STABILITY_RUNS):
        if index:
            time.sleep(RESPONSE_STABILITY_INTERVAL_SECONDS)
        output = directory / f"stability-{index}"
        result = run(
            [
                NEQO_CLIENT,
                "run",
                "--workload",
                str(runtime_input),
                "--profile",
                "live",
                "--defense",
                "none",
                "--seed",
                "0",
                "--output-dir",
                str(output),
                "--max-response-bytes",
                str(max_bytes),
                "--timeout-seconds",
                str(timeout_seconds),
            ],
            log=directory / f"stability-{index}.log",
            check=False,
        )
        if result.returncode:
            if result.stdout:
                print(result.stdout, file=sys.stderr, end="")
            raise SystemExit(result.returncode)
        runs.append(json.loads((output / "run.json").read_text(encoding="utf-8")))
    return response_stability_evidence(runs)


def response_stability_evidence(runs: list[dict]) -> dict:
    """Report resources whose complete response identity repeats exactly."""

    if len(runs) < 2:
        raise ValueError("response stability requires at least two runs")
    signatures: list[dict[int, tuple]] = []
    for run_data in runs:
        if run_data.get("completion_status") != "complete":
            signatures.append({})
            continue
        signatures.append(
            {
                int(response["resource_id"]): (
                    response.get("status"),
                    response.get("bytes"),
                    response.get("body_sha256"),
                    response.get("outcome"),
                    response.get("complete"),
                )
                for response in run_data.get("responses", [])
                if response.get("complete") is True and response.get("outcome") == "succeeded"
            }
        )
    all_ids = set().union(*(set(signature) for signature in signatures))
    stable = [
        resource_id
        for resource_id in sorted(all_ids)
        if all(
            resource_id in signature and signature[resource_id] == signatures[0].get(resource_id)
            for signature in signatures
        )
    ]
    return {"runs": len(runs), "stable_resource_ids": stable}


def resolve_probe_output(source: dict, resolved: dict, *, keep_unavailable: bool) -> dict:
    """Merge independent probe results while preserving the source graph audit."""

    unavailable = [
        resource for resource in resolved["resources"] if not resource.get("known_valid")
    ]
    if not keep_unavailable:
        available = {
            resource["id"] for resource in resolved["resources"] if resource.get("known_valid")
        }
        resolved["resources"] = [
            {
                **resource,
                "depends_on": [
                    dependency
                    for dependency in resource.get("depends_on", [])
                    if dependency in available
                ],
            }
            for resource in resolved["resources"]
            if resource["id"] in available
        ]
        if not resolved["resources"]:
            raise ValueError("preflight left no directly fetchable HTTP/3 resources")
    replay = source.get("replay")
    if replay is not None:
        resolved["replay"] = dict(replay)
        resolved["replay"]["exclusions"] = [
            *replay.get("exclusions", []),
            *(
                {"url": resource["url"], "reason": "HTTP/3 preflight unavailable"}
                for resource in unavailable
            ),
        ]
    validate_manifest(resolved)
    return resolved


if __name__ == "__main__":
    main()
