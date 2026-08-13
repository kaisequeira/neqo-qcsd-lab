from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .orchestrator import (
    CampaignIncomplete,
    preflight_campaign,
    resume_campaign,
    run_campaign,
)
from .util import LAB_ROOT


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="qcsd-lab",
        description="Prepare, run, verify, and analyze QCSD experiments",
    )
    commands = root.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser(
        "prepare",
        help="freeze one browser-discovered workload after Neqo HTTP/3 preflight",
    )
    prepare.add_argument("id")
    prepare.add_argument("url")
    prepare.add_argument("approved_origins", nargs="+")

    commands.add_parser(
        "qualify-chaff",
        help="atomically qualify compact HTTP/3 chaff for the sealed six-workload cohort",
    )

    commands.add_parser(
        "derive-chaff-prefix-specs",
        help="create the six standalone numeric prefix-pack qualification specs",
    )

    run = commands.add_parser("run", help="execute a new sequential campaign")
    run.add_argument("campaign", type=Path)

    resume = commands.add_parser("resume", help="continue one exact interrupted result")
    resume.add_argument("result", type=Path)

    verify = commands.add_parser("verify", help="verify a campaign or sealed result")
    verify.add_argument("target", type=Path)

    analyze = commands.add_parser("analyze", help="regenerate derived analysis from evidence")
    analyze.add_argument("result", type=Path)

    fit = commands.add_parser("fit", help="fit the fixed research-1200 defense artifact bundle")
    fit.add_argument("result", type=Path)

    test = commands.add_parser("test", help="run deterministic or controlled live tests")
    test.add_argument("suite", nargs="?", choices=("live",), default=None)
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.command == "prepare":
        from .prepare import PreparationError, prepare_workload

        try:
            prepared = prepare_workload(
                args.id,
                args.url,
                args.approved_origins,
                output_root=Path(
                    os.environ.get("QCSD_WORKLOAD_ROOT", str(LAB_ROOT / "config/workloads"))
                ),
            )
        except (FileExistsError, OSError, PreparationError, RuntimeError, ValueError) as error:
            _fail(error)
        print(prepared.path)
        return
    if args.command == "qualify-chaff":
        from .chaff_qualification import qualify_all_chaff
        from .prepare import PreparationError

        try:
            qualified = qualify_all_chaff(
                workload_root=Path(
                    os.environ.get("QCSD_WORKLOAD_ROOT", str(LAB_ROOT / "config/workloads"))
                ),
                qualification_store=Path(
                    os.environ.get(
                        "QCSD_CHAFF_QUALIFICATION_STORE",
                        str(LAB_ROOT / "config/chaff-qualification-store"),
                    )
                ),
                prefix_spec_root=Path(
                    os.environ.get(
                        "QCSD_CHAFF_PREFIX_SPEC_ROOT",
                        str(LAB_ROOT / "config/chaff-prefix-specs"),
                    )
                ),
            )
        except (FileExistsError, OSError, PreparationError, RuntimeError, ValueError) as error:
            _fail(error)
        print(
            json.dumps(
                {
                    str(item.path): {
                        "sha256": item.sha256,
                        "derived_chaff_manifest_sha256": item.manifest_sha256,
                    }
                    for item in qualified
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "derive-chaff-prefix-specs":
        from .chaff_qualification import (
            SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE,
            derive_prefix_pack_specs,
        )

        try:
            paths = derive_prefix_pack_specs(
                source_path=Path(
                    os.environ.get(
                        "QCSD_SCHEMA_FIVE_WALKIE_TALKIE",
                        str(LAB_ROOT / SCHEMA_FIVE_WALKIE_TALKIE_ARCHIVE),
                    )
                ),
                destination_root=Path(
                    os.environ.get(
                        "QCSD_CHAFF_PREFIX_SPEC_ROOT",
                        str(LAB_ROOT / "config/chaff-prefix-specs"),
                    )
                ),
            )
        except (FileExistsError, OSError, RuntimeError, ValueError) as error:
            _fail(error)
        from .util import sha256_file

        print(
            json.dumps(
                {str(path): sha256_file(path) for path in paths},
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "run":
        results = Path(os.environ.get("QCSD_RESULTS_ROOT", str(LAB_ROOT / "results")))
        try:
            root = run_campaign(args.campaign.resolve(), results.resolve())
        except CampaignIncomplete as error:
            print(error, file=sys.stderr)
            print(error.root)
            raise SystemExit(1) from None
        except (OSError, ValueError) as error:
            _fail(error)
        print(root)
        return
    if args.command == "resume":
        try:
            root = resume_campaign(args.result.resolve())
        except CampaignIncomplete as error:
            print(error, file=sys.stderr)
            print(error.root)
            raise SystemExit(1) from None
        except (OSError, ValueError) as error:
            _fail(error)
        print(root)
        return
    if args.command == "verify":
        target = args.target.resolve()
        try:
            if target.suffix.lower() in {".yml", ".yaml"}:
                result = preflight_campaign(target)
            else:
                from .fitting import is_artifact_bundle_candidate, verify_artifact_bundle

                if is_artifact_bundle_candidate(target):
                    result = verify_artifact_bundle(target).as_dict()
                else:
                    from .verification import verify_result

                    result = verify_result(target).as_dict()
        except (OSError, ValueError) as error:
            _fail(error)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.command == "analyze":
        from .analysis import analyze_result

        try:
            outputs = analyze_result(args.result.resolve()).as_dict()
        except (OSError, ValueError) as error:
            _fail(error)
        print(json.dumps(outputs, indent=2, sort_keys=True))
        return
    if args.command == "fit":
        from .fitting import fit_result

        try:
            output = fit_result(
                args.result.resolve(),
                artifacts_root=Path(
                    os.environ.get("QCSD_ARTIFACTS_ROOT", str(LAB_ROOT / "artifacts"))
                ),
            )
        except (OSError, ValueError) as error:
            _fail(error)
        from .util import sha256_file

        print(
            json.dumps(
                {
                    "root": str(output),
                    "provenance_sha256": sha256_file(output / "provenance.json"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "test":
        environment = dict(os.environ)
        if args.suite == "live":
            environment["QCSD_RUN_CAPTURE_ACCEPTANCE"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"],
            cwd=LAB_ROOT,
            env=environment,
            check=False,
        )
        raise SystemExit(result.returncode)
    raise AssertionError(f"unhandled command: {args.command}")


def _fail(error: Exception) -> None:
    print(str(error), file=sys.stderr)
    raise SystemExit(1) from None
