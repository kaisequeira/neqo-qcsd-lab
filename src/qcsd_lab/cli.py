from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .acquisition_timing import MAX_CANDIDATES_PER_ACTION
from .orchestrator import (
    CampaignIncomplete,
    preflight_campaign,
    resume_campaign,
    run_campaign,
)
from .util import LAB_ROOT


class _SinglePositiveInteger(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        marker = f"_{self.dest}_specified"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} may be supplied only once")
        try:
            value = int(str(values))
        except ValueError:
            parser.error(f"{option_string} must be a positive integer")
        if value < 1 or str(values) != str(value):
            parser.error(f"{option_string} must be a positive integer")
        setattr(namespace, self.dest, value)
        setattr(namespace, marker, True)


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
    prepare.add_argument(
        "--require-complete-coverage",
        action="store_true",
        help=(
            "require every approved origin and browser-rendered HTTPS GET to survive "
            "HTTP/3 preparation"
        ),
    )

    commands.add_parser(
        "qualify-chaff",
        help="atomically qualify compact HTTP/3 chaff for the sealed six-workload cohort",
    )
    response_qualification = commands.add_parser(
        "qualify-response-chaff",
        help="atomically response-qualify an explicit five-workload FRONT/Tamaraw cohort",
    )
    response_qualification.add_argument(
        "--set",
        dest="qualification_set",
        help="publish under config/chaff-response-qualification-store/sets/SET",
    )
    response_qualification.add_argument("workload_ids", nargs=5)

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
    analyze.add_argument("--validation-attestation", type=Path)

    fit = commands.add_parser("fit", help="fit the fixed research-1200 defense artifact bundle")
    fit.add_argument("result", type=Path)

    buflo = commands.add_parser(
        "buflo-study",
        help="validate and coordinate the candidate BuFLO/CS-BuFLO study",
    )
    buflo.add_argument(
        "action",
        choices=(
            "reference",
            "qualify",
            "historical-snapshot",
            "freeze-cohort",
            "code-gate",
            "capture",
            "export",
            "evaluate",
            "verify",
        ),
    )
    buflo.add_argument(
        "--stage", choices=("controlled", "regression", "smoke", "rehearsal", "formal")
    )
    buflo.add_argument("--block", type=int)
    buflo.add_argument("--result", dest="result_roots", action="append", type=Path, default=[])
    buflo.add_argument(
        "--controlled-result",
        dest="controlled_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    buflo.add_argument(
        "--regression-result",
        dest="regression_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    buflo.add_argument(
        "--formal-result",
        dest="formal_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    buflo.add_argument("--smoke-result", type=Path)
    buflo.add_argument("--rehearsal-result", type=Path)
    buflo.add_argument("--handoff", type=Path)
    buflo.add_argument("--destination", type=Path)
    buflo.add_argument("--formal", action="store_true")
    buflo.add_argument("--bootstrap-draws", type=int, default=10_000)
    buflo.add_argument("--dlsvm-wall-seconds", type=float)
    buflo.add_argument("--reference-root", type=Path)
    buflo.add_argument("--reference-receipt", type=Path)
    buflo.add_argument("--qualification-receipt", type=Path)
    buflo.add_argument("--capture-admission", type=Path)
    buflo.add_argument("--formal-cohort", type=Path)
    buflo.add_argument("--historical-pre-snapshot", type=Path)
    buflo.add_argument("--historical-post-snapshot", type=Path)
    buflo.add_argument("--evaluation-receipt", type=Path)
    buflo.add_argument("--comparison-review", type=Path)
    buflo.add_argument("--code-gate-receipt", type=Path)
    buflo.add_argument("--attestation", type=Path)
    buflo.add_argument("--snapshot-phase", choices=("pre-formal", "post-formal"))
    buflo.add_argument("--cohort-id")
    buflo.add_argument(
        "--cohort-version",
        action=_SinglePositiveInteger,
        default=1,
    )
    buflo.add_argument("--formal-window-hours", type=float)
    buflo.add_argument("--local-netem-profile", help=argparse.SUPPRESS)
    buflo.add_argument("--network-name", help=argparse.SUPPRESS)
    buflo.add_argument("--server-one-qdisc-b64", help=argparse.SUPPRESS)
    buflo.add_argument("--server-two-qdisc-b64", help=argparse.SUPPRESS)
    buflo.add_argument("--controlled-network-evidence-b64", help=argparse.SUPPRESS)

    class_study = commands.add_parser(
        "class-study",
        help="coordinate the evidence-ordered 100-class classifier study",
    )
    class_study.add_argument(
        "action",
        choices=(
            "status",
            "acquisition-authority",
            "acquisition-init",
            "acquisition-run",
            "acquisition-status",
            "acquisition-complete",
            "stability",
            "cohort",
            "campaigns",
            "fit-numeric",
            "prefix-specs",
            "qualify-prefix",
            "finalize-fitting",
            "capture",
            "resume",
            "export",
            "evaluate",
            "foundation",
            "readiness",
            "historical-snapshot",
            "comparison-review",
            "attest",
            "successor-policy",
            "successor-decision",
            "successor-restart",
            "successor-verify",
            "verify",
        ),
    )
    class_study.add_argument("--stage", choices=("pilot", "authoritative"))
    class_study.add_argument("--candidate-catalogue", type=Path)
    class_study.add_argument("--acquisition-root", type=Path)
    class_study.add_argument("--acquisition-started-at")
    class_study.add_argument(
        "--acquisition-browser-tool", default="playwright-chromium"
    )
    class_study.add_argument(
        "--acquisition-max-candidates",
        type=int,
        choices=range(1, MAX_CANDIDATES_PER_ACTION + 1),
        default=MAX_CANDIDATES_PER_ACTION,
    )
    class_study.add_argument("--acquisition-timeout-ms", type=int, default=60_000)
    class_study.add_argument("--stability-root", type=Path)
    class_study.add_argument("--stability-input", type=Path)
    class_study.add_argument("--workload-root", type=Path)
    class_study.add_argument("--acquisition-completion", type=Path)
    class_study.add_argument("--pilot-cohort", type=Path)
    class_study.add_argument("--pilot-cohort-assembly", type=Path)
    class_study.add_argument("--final-cohort", type=Path)
    class_study.add_argument("--final-cohort-assembly", type=Path)
    class_study.add_argument("--cohort", type=Path)
    class_study.add_argument("--cohort-assembly", type=Path)
    class_study.add_argument("--final-selection", type=Path)
    class_study.add_argument("--campaign-root", type=Path)
    class_study.add_argument("--campaign", type=Path)
    class_study.add_argument("--results-root", type=Path)
    class_study.add_argument("--capture-result", type=Path)
    class_study.add_argument(
        "--result", dest="result_roots", action="append", type=Path, default=[]
    )
    class_study.add_argument(
        "--regression-result",
        dest="regression_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument(
        "--controlled-result",
        dest="controlled_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument(
        "--canary-result",
        dest="canary_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument(
        "--formal-result",
        dest="formal_result_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument("--artifacts-root", type=Path)
    class_study.add_argument(
        "--numeric-bundle",
        dest="numeric_bundle_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument(
        "--prefix-spec-root",
        dest="prefix_spec_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument("--qualification-checkpoint", type=Path)
    class_study.add_argument("--qualification-sidecar-root", type=Path)
    class_study.add_argument("--qualification-publication-root", type=Path)
    class_study.add_argument(
        "--qualification-manifest",
        dest="qualification_manifests",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument("--qualification-workload")
    class_study.add_argument("--qualify-all-pending", action="store_true")
    class_study.add_argument(
        "--final-bundle",
        dest="final_bundle_roots",
        action="append",
        type=Path,
        default=[],
    )
    class_study.add_argument("--handoff", type=Path)
    class_study.add_argument("--evaluation-receipt", type=Path)
    class_study.add_argument("--cohort-version", action=_SinglePositiveInteger)
    class_study.add_argument("--build-execution-receipt", type=Path)
    class_study.add_argument("--pinned-cdp-receipt", type=Path)
    class_study.add_argument("--browser-egress-qualification-root", type=Path)
    class_study.add_argument("--reference-receipt", type=Path)
    class_study.add_argument("--code-gate-receipt", type=Path)
    class_study.add_argument("--controlled-qualification-receipt", type=Path)
    class_study.add_argument("--pilot-fitting-result", type=Path)
    class_study.add_argument("--pilot-compatibility-result", type=Path)
    class_study.add_argument("--authoritative-fitting-result", type=Path)
    class_study.add_argument("--certification-result", type=Path)
    class_study.add_argument("--foundation-attestation", type=Path)
    class_study.add_argument("--acquisition-authority", type=Path)
    class_study.add_argument("--readiness-attestation", type=Path)
    class_study.add_argument("--historical-pre-snapshot", type=Path)
    class_study.add_argument("--historical-post-snapshot", type=Path)
    class_study.add_argument(
        "--snapshot-phase", choices=("pre-formal", "post-formal")
    )
    class_study.add_argument("--comparison-review", type=Path)
    class_study.add_argument("--validation-attestation", type=Path)
    class_study.add_argument("--successor-policy", type=Path)
    class_study.add_argument("--successor-decision", type=Path)
    class_study.add_argument("--successor-restart", type=Path)
    class_study.add_argument("--comparison-review-input", type=Path)
    class_study.add_argument("--reviewer")
    class_study.add_argument("--reviewed-at")
    class_study.add_argument("--destination", type=Path)
    class_study.add_argument("--target", type=Path)
    class_study.add_argument(
        "--execute",
        action="store_true",
        help="launch or resume capture after prerequisite and preflight validation",
    )
    class_study.add_argument(
        "--shallow",
        action="store_true",
        help="skip raw-PCAP replay while retaining closed-inventory verification",
    )
    class_study.add_argument(
        "--dlsvm-cache-directory",
        type=Path,
        help=(
            "explicit persistent read-write DLSVM cache (required by formal "
            "class-study evaluation for interruption-safe reuse)"
        ),
    )

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
                require_complete_coverage=args.require_complete_coverage,
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
                        str(LAB_ROOT / "config/chaff-prefix-specs/v2"),
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
    if args.command == "qualify-response-chaff":
        from .chaff_qualification import qualify_all_response_chaff
        from .prepare import PreparationError

        try:
            qualified = qualify_all_response_chaff(
                args.workload_ids,
                qualification_set=args.qualification_set,
                workload_root=Path(
                    os.environ.get("QCSD_WORKLOAD_ROOT", str(LAB_ROOT / "config/workloads"))
                ),
                qualification_store=Path(
                    os.environ.get(
                        "QCSD_CHAFF_RESPONSE_QUALIFICATION_STORE",
                        str(LAB_ROOT / "config/chaff-response-qualification-store"),
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
                        str(LAB_ROOT / "config/chaff-prefix-specs/v2"),
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
            outputs = analyze_result(
                args.result.resolve(),
                validation_attestation=(
                    args.validation_attestation.resolve()
                    if args.validation_attestation is not None
                    else None
                ),
            ).as_dict()
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
    if args.command == "buflo-study":
        from .buflo_study import run_study_action

        try:
            result = run_study_action(
                args.action,
                stage=args.stage,
                block=args.block,
                result_roots=tuple(path.resolve() for path in args.result_roots),
                controlled_result_roots=tuple(
                    path.resolve() for path in args.controlled_result_roots
                ),
                regression_result_roots=tuple(
                    path.resolve() for path in args.regression_result_roots
                ),
                formal_result_roots=tuple(
                    path.resolve() for path in args.formal_result_roots
                ),
                smoke_result_root=(
                    args.smoke_result.resolve() if args.smoke_result is not None else None
                ),
                rehearsal_result_root=(
                    args.rehearsal_result.resolve()
                    if args.rehearsal_result is not None
                    else None
                ),
                handoff=args.handoff.resolve() if args.handoff is not None else None,
                destination=(
                    args.destination.absolute() if args.destination is not None else None
                ),
                formal=args.formal,
                bootstrap_draws=args.bootstrap_draws,
                dlsvm_available_wall_seconds=args.dlsvm_wall_seconds,
                reference_root=(
                    args.reference_root.resolve() if args.reference_root is not None else None
                ),
                reference_receipt=(
                    args.reference_receipt.resolve()
                    if args.reference_receipt is not None
                    else None
                ),
                qualification_receipt=(
                    args.qualification_receipt.resolve()
                    if args.qualification_receipt is not None
                    else None
                ),
                capture_admission=(
                    args.capture_admission.resolve()
                    if args.capture_admission is not None
                    else None
                ),
                formal_cohort_manifest=(
                    args.formal_cohort.resolve() if args.formal_cohort is not None else None
                ),
                historical_pre_snapshot=(
                    args.historical_pre_snapshot.resolve()
                    if args.historical_pre_snapshot is not None
                    else None
                ),
                historical_post_snapshot=(
                    args.historical_post_snapshot.resolve()
                    if args.historical_post_snapshot is not None
                    else None
                ),
                evaluation_receipt=(
                    args.evaluation_receipt.resolve()
                    if args.evaluation_receipt is not None
                    else None
                ),
                comparison_review=(
                    args.comparison_review.resolve()
                    if args.comparison_review is not None
                    else None
                ),
                code_gate_receipt=(
                    args.code_gate_receipt.resolve()
                    if args.code_gate_receipt is not None
                    else None
                ),
                attestation=(
                    args.attestation.resolve() if args.attestation is not None else None
                ),
                snapshot_phase=args.snapshot_phase,
                cohort_id=args.cohort_id,
                cohort_version=args.cohort_version,
                formal_window_hours=args.formal_window_hours,
                local_netem_profile=args.local_netem_profile,
                network_name=args.network_name,
                server_one_qdisc_b64=args.server_one_qdisc_b64,
                server_two_qdisc_b64=args.server_two_qdisc_b64,
                controlled_network_evidence_b64=args.controlled_network_evidence_b64,
            )
        except (FileExistsError, OSError, RuntimeError, ValueError) as error:
            _fail(error)
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
        if result.status == "blocked":
            raise SystemExit(1)
        return
    if args.command == "class-study":
        from .class_pipeline import run_class_study_action

        def absolute(path: Path | None) -> Path | None:
            return path.absolute() if path is not None else None

        try:
            status_artifacts = {
                "numeric_bundle_roots": tuple(
                    path.absolute() for path in args.numeric_bundle_roots
                ),
                "prefix_spec_roots": tuple(
                    path.absolute() for path in args.prefix_spec_roots
                ),
                "qualification_manifests": tuple(
                    path.absolute() for path in args.qualification_manifests
                ),
                "final_bundle_roots": tuple(
                    path.absolute() for path in args.final_bundle_roots
                ),
            }
            if args.action != "status":
                repeated = [
                    option
                    for option, values in (
                        ("--numeric-bundle", status_artifacts["numeric_bundle_roots"]),
                        ("--prefix-spec-root", status_artifacts["prefix_spec_roots"]),
                        (
                            "--qualification-manifest",
                            status_artifacts["qualification_manifests"],
                        ),
                        ("--final-bundle", status_artifacts["final_bundle_roots"]),
                    )
                    if len(values) > 1
                ]
                if repeated:
                    raise ValueError(
                        f"class-study {args.action} accepts {', '.join(repeated)} at most once"
                    )

            def singular(name: str) -> Path | None:
                values = status_artifacts[name]
                return values[0] if len(values) == 1 else None

            result = run_class_study_action(
                args.action,
                stage=args.stage,
                candidate_catalogue_path=absolute(args.candidate_catalogue),
                acquisition_root=absolute(args.acquisition_root),
                acquisition_started_at=args.acquisition_started_at,
                acquisition_browser_tool=args.acquisition_browser_tool,
                acquisition_max_candidates=args.acquisition_max_candidates,
                acquisition_timeout_ms=args.acquisition_timeout_ms,
                stability_root=absolute(args.stability_root),
                stability_input=absolute(args.stability_input),
                workload_root=absolute(args.workload_root),
                acquisition_completion_path=absolute(args.acquisition_completion),
                pilot_cohort_receipt_path=absolute(args.pilot_cohort),
                pilot_cohort_assembly_path=absolute(args.pilot_cohort_assembly),
                final_cohort_receipt_path=absolute(args.final_cohort),
                final_cohort_assembly_path=absolute(args.final_cohort_assembly),
                cohort_receipt_path=absolute(args.cohort),
                cohort_assembly_path=absolute(args.cohort_assembly),
                final_selection_path=absolute(args.final_selection),
                campaign_root=absolute(args.campaign_root),
                campaign=absolute(args.campaign),
                results_root=absolute(args.results_root),
                capture_result=absolute(args.capture_result),
                result_roots=tuple(path.absolute() for path in args.result_roots),
                regression_result_roots=tuple(
                    path.absolute() for path in args.regression_result_roots
                ),
                controlled_result_roots=tuple(
                    path.absolute() for path in args.controlled_result_roots
                ),
                canary_result_roots=tuple(
                    path.absolute() for path in args.canary_result_roots
                ),
                formal_result_roots=tuple(
                    path.absolute() for path in args.formal_result_roots
                ),
                artifacts_root=absolute(args.artifacts_root),
                numeric_bundle_root=singular("numeric_bundle_roots"),
                numeric_bundle_roots=status_artifacts["numeric_bundle_roots"],
                prefix_spec_root=singular("prefix_spec_roots"),
                prefix_spec_roots=status_artifacts["prefix_spec_roots"],
                qualification_checkpoint=absolute(args.qualification_checkpoint),
                qualification_sidecar_root=absolute(args.qualification_sidecar_root),
                qualification_publication_root=absolute(
                    args.qualification_publication_root
                ),
                qualification_manifest=singular("qualification_manifests"),
                qualification_manifests=status_artifacts["qualification_manifests"],
                qualification_workload=args.qualification_workload,
                qualify_all_pending=args.qualify_all_pending,
                final_bundle_root=singular("final_bundle_roots"),
                final_bundle_roots=status_artifacts["final_bundle_roots"],
                handoff=absolute(args.handoff),
                evaluation_receipt=absolute(args.evaluation_receipt),
                cohort_version=args.cohort_version,
                build_execution_receipt=absolute(args.build_execution_receipt),
                pinned_cdp_receipt=absolute(args.pinned_cdp_receipt),
                browser_egress_qualification_root=absolute(
                    args.browser_egress_qualification_root
                ),
                reference_receipt=absolute(args.reference_receipt),
                code_gate_receipt=absolute(args.code_gate_receipt),
                controlled_qualification_receipt=absolute(
                    args.controlled_qualification_receipt
                ),
                pilot_fitting_result=absolute(args.pilot_fitting_result),
                pilot_compatibility_result=absolute(
                    args.pilot_compatibility_result
                ),
                authoritative_fitting_result=absolute(
                    args.authoritative_fitting_result
                ),
                certification_result=absolute(args.certification_result),
                foundation_attestation=absolute(args.foundation_attestation),
                acquisition_authority=absolute(args.acquisition_authority),
                readiness_attestation=absolute(args.readiness_attestation),
                historical_pre_snapshot=absolute(args.historical_pre_snapshot),
                historical_post_snapshot=absolute(args.historical_post_snapshot),
                snapshot_phase=args.snapshot_phase,
                comparison_review=absolute(args.comparison_review),
                validation_attestation=absolute(args.validation_attestation),
                successor_policy=absolute(args.successor_policy),
                successor_decision=absolute(args.successor_decision),
                successor_restart=absolute(args.successor_restart),
                comparison_review_input=absolute(args.comparison_review_input),
                reviewer=args.reviewer,
                reviewed_at=args.reviewed_at,
                destination=absolute(args.destination),
                target=absolute(args.target),
                execute=args.execute,
                deep=not args.shallow,
                dlsvm_cache_directory=absolute(args.dlsvm_cache_directory),
            )
        except CampaignIncomplete as error:
            print(error, file=sys.stderr)
            print(error.root)
            raise SystemExit(1) from None
        except (FileExistsError, OSError, RuntimeError, TypeError, ValueError) as error:
            _fail(error)
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
        if result.status == "blocked":
            raise SystemExit(1)
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
