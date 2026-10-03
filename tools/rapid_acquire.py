#!/usr/bin/env python3
"""Run the prospective rapid-v5 site acquisition path with retained attempts.

Run inside the frozen prepare image for navigate, probe-page and prepare.
Inspection, explicit human review, sealing and cohort assembly run on the host.
This command collects site eligibility evidence, never formal traffic samples.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from qcsd_lab import rapid_site_admission as admission


def _module(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("implementation snapshots use NAME=PATH")
    return name, Path(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="freeze the profile, image source and implementation snapshots")
    initialize.add_argument("root", type=Path)
    for argument in ("profile", "source", "source-receipt", "catalogue", "source-manifest"):
        initialize.add_argument(f"--{argument}", type=Path, required=True)
    initialize.add_argument("--admission-image-digest", required=True)
    initialize.add_argument("--not-before-utc", required=True, help="independent prospective profile publication time")
    initialize.add_argument("--selection-amendment", type=Path,
                            help="create a separate acquisition under a prospective selection amendment")
    initialize.add_argument("--root-screen-context", type=Path,
                            help="retain the original acquisition context's unchanged root-survey runtime only")
    initialize.add_argument("--root-screen-runtime-proof", type=Path,
                            help="original canonical-runtime.json with sibling actual prepare installed-verification records")
    initialize.add_argument("--root-screen-runtime-proof-sha256",
                            help="independently verified SHA-256 of that original installed-runtime proof")
    initialize.add_argument("--browser-policy-module", action="append", type=_module, default=[],
                            help="independent amended browser policy implementation snapshot NAME=PATH")
    initialize.add_argument("--collector-module", action="append", type=_module, default=[],
                            help="independent revision 3 collector and executable snapshot NAME=PATH")
    initialize.add_argument("--attempt-module", action="append", type=_module, default=[],
                            help="independent revision 4–11 unsuccessful live-attempt snapshot NAME=PATH (5+ response helper; 7+ chaff selector; 8+ capture acceptance helper)")
    for group in sorted(admission.IMPLEMENTATION_GROUPS):
        initialize.add_argument(f"--{group}-module", action="append", type=_module, required=True)
    for name, help_text in (
        ("status", "reopen all retained attempts and show the next fixed-order candidate"),
        ("review", "record a named human's explicit safety decision for an exact page"),
        ("navigate", "observe deterministic candidate-boundary navigation"),
        ("probe-page", "run before/exact-page/after controlled HTTP/3 probes"),
        ("screen-page", "record the amended frozen public URL/domain rules for the exact H3 page"),
        ("prepare", "run live complete-coverage preparation and three immediate replay checks"),
        ("seal", "independently reopen evidence and produce a site decision"),
        ("cohort", "select the first ten or fifty eligible sites from the verified ordered prefix"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("root", type=Path)
        if name not in {"status", "cohort"}:
            command.add_argument("--candidate", help="defaults to the next candidate in the fixed profile order")
        if name in {"probe-page", "prepare", "screen-page"}:
            command.add_argument("--navigation", type=Path, required=True)
        if name in {"prepare", "seal"}:
            command.add_argument("--human-review", type=Path)
            command.add_argument("--automated-screen", type=Path,
                                 help="distinct automatic URL/domain screen; requires selection amendment revision 2 or later")
        if name == "review":
            command.add_argument("--reviewed-url", required=True)
            command.add_argument("--reviewer", required=True)
            command.add_argument("--decision", choices=("approved-public-page", "excluded-public-page"), required=True)
            command.add_argument("--reason", choices=("adult-explicit-content", "gambling-content"))
            command.add_argument("--human-confirmed", action="store_true", required=True,
                                 help="the named human has actually reviewed this page")
        elif name == "probe-page":
            command.add_argument("--selected-page-ordinal", type=int, required=True)
        elif name in {"prepare", "screen-page"}:
            command.add_argument("--page-h3", type=Path, required=True)
            if name == "screen-page":
                command.add_argument("--selected-page-ordinal", type=int, required=True)
        elif name == "seal":
            command.add_argument("--root-log", type=Path, action="append", default=[])
            command.add_argument("--reviewed-url")
            command.add_argument("--preparation", type=Path)
            command.add_argument("--browser-policy-failure", type=Path,
                                 help="explicitly seal a fresh typed browser policy deferral under an amended context")
            command.add_argument("--page-policy-failure", type=Path,
                                 help="explicitly seal an independently proved typed navigation/preparation policy deferral")
            command.add_argument("--collector-failure", type=Path,
                                 help="explicit revision 3 zero-credit deferral from one fresh exact collector failure")
            command.add_argument("--attempt-failure", type=Path,
                                 help="explicit revision 4 zero-credit deferral from one source-bound unsuccessful live call")
            command.add_argument("--defer-root", action="store_true",
                                 help="record an exact policy-authorized zero-credit root deferral, including visibly operational DNS misses")
        elif name == "cohort":
            command.add_argument("--generation", choices=("launch-10", "final-50"), required=True)
    return parser


def _next_candidate(context: admission.AdmissionContext, requested: str | None) -> str:
    status = admission.acquisition_status(context)
    candidate = status["next_candidate"]
    if candidate is None:
        raise ValueError("the frozen candidate list is exhausted")
    if requested is not None and requested != candidate["candidate_id"]:
        raise ValueError("the ordered driver cannot skip the next unresolved candidate")
    return candidate["candidate_id"]


def _frozen_paths(context: admission.AdmissionContext) -> dict[str, Path]:
    payload = admission._unpack(admission._read(context.root / "provenance.json"), admission.PROVENANCE_TYPE)
    return {key: admission._child(context.root, reference) for key, reference in payload["inputs"].items()}


def _v4_probe_page(context, candidate_id, attempt, navigation, ordinal, kwargs):
    """Observe the actual page call; independently failed controls always stop."""
    from qcsd_lab import h3_prebaseline
    from qcsd_lab.rapid_page_evidence import (
        produce_selected_page_h3_receipt, verify_selected_page_h3_receipt,
        verify_navigation_receipt, _probe_class, _time,
    )
    from qcsd_lab.rapid_attempt_failure_evidence import begin_attempt_action
    from qcsd_lab.rapid_page_evidence import _validate_runtime
    nav = verify_navigation_receipt(navigation,
        profile_receipt=admission._load(context.profile_bytes), source_bytes=context.source_bytes,
        catalogue_bytes=context.catalogue_bytes, candidate_id=candidate_id,
        execution_binding=context.execution_binding,
        expected_implementation_hashes=context.mounted_module_hashes["navigation"],
        not_before_utc=context.not_before_utc)
    if type(ordinal) is not int or not 0 <= ordinal < len(nav["pages"]):
        raise ValueError("selected-page ordinal is outside deterministic navigation")
    action = admission._attempt_action(context.candidate(candidate_id),
        probe_page={"url": nav["pages"][ordinal].url, "selected_page_ordinal": ordinal})
    runtime = begin_attempt_action(context.execution_binding, context.mounted_module_hashes[admission.ATTEMPT_GROUP],
                                   context.attempt_not_before_utc)
    if _validate_runtime(runtime, context.execution_binding) != dict(context.expected_runtime_source):
        raise ValueError("page probe runtime differs from independent admission source")
    if h3_prebaseline.os.environ.get("QCSD_PUBLIC_ORIGIN_ONLY") != "1":
        raise ValueError("live page probe requires public-origin-only policy")
    observations, caught = [], []
    page_started = None
    def probe(url):
        nonlocal page_started
        if len(observations) != 1:
            result = h3_prebaseline._run_one(url)  # Control failures are outside the observer.
        else:
            begin_attempt_action(context.execution_binding, context.mounted_module_hashes[admission.ATTEMPT_GROUP],
                                 context.attempt_not_before_utc)
            page_started = admission._now()
            try:
                result = h3_prebaseline._run_one(url)
            except Exception as error:
                if admission.blocking_backend_failure(error):
                    raise
                caught.append(error)
                result = None
        observations.append(result)
        return result
    produce_selected_page_h3_receipt(navigation_receipt=navigation, selected_page_ordinal=ordinal,
        expected_navigation_implementation_hashes=context.mounted_module_hashes["navigation"],
        not_before_utc=context.not_before_utc, probe=probe, **kwargs)
    payload = admission._load(admission._read(kwargs["output"]))["payload"]
    start, end = _time(payload["started_at"]), _time(payload["completed_at"])
    control = admission.profile.V5_TRIAGE_POLICY["control_url"]
    if (_probe_class(payload["control_before"], control, start, end)[0] != "known-valid"
        or _probe_class(payload["control_after"], control, start, end)[0] != "known-valid"):
        raise ValueError("selected-page H3 controls did not pass; no unsuccessful-attempt terminal")
    selected = (_probe_class(payload["exact_page_probe"], action["url"], start, end)
                if payload["exact_page_probe"] is not None else None)
    if selected is not None and selected[0] == "known-valid":
        if begin_attempt_action(context.execution_binding, context.mounted_module_hashes[admission.ATTEMPT_GROUP],
                                context.attempt_not_before_utc) != runtime:
            raise ValueError("page probe runtime changed during successful operation")
        verify_selected_page_h3_receipt(kwargs["output"], navigation_receipt=navigation,
            profile_receipt=admission._load(context.profile_bytes), source_bytes=context.source_bytes,
            catalogue_bytes=context.catalogue_bytes, candidate_id=candidate_id,
            execution_binding=context.execution_binding,
            expected_navigation_implementation_hashes=context.mounted_module_hashes["navigation"],
            expected_implementation_hashes=context.mounted_module_hashes["page"],
            not_before_utc=context.not_before_utc)
        admission.write_checkpoint(context)
        return kwargs["output"]
    raw = {key: payload[key] for key in ("started_at", "completed_at", "control_before", "exact_page_probe", "control_after")}
    raw_path = attempt / "controlled-unsuccessful-page-probe.json"
    admission.durable_create(raw_path, admission._json(raw))
    if not caught:
        try:
            raise admission.UnsuccessfulControlledPageProbe("controlled exact-page backend observation did not succeed")
        except admission.UnsuccessfulControlledPageProbe as error:
            caught.append(error)
    output = admission.retain_unsuccessful_attempt_failure(attempt / "attempt-failure.json", context,
        candidate_id=candidate_id, error=caught[0], action=action, started_at=page_started,
        runtime=runtime, inputs={"navigation": navigation, "controlled_probe": raw_path})
    admission.write_checkpoint(context)
    return output


def _page_action(context: admission.AdmissionContext, candidate_id: str, args: argparse.Namespace) -> Path:
    from qcsd_lab.rapid_page_evidence import (
        produce_navigation_receipt, produce_selected_page_h3_receipt,
        verify_navigation_receipt, verify_selected_page_h3_receipt,
    )
    inputs = _frozen_paths(context)
    attempt = admission._new_attempt(context, candidate_id, args.command)
    output = attempt / (("navigation-observation.json" if context.selection_amendment_bytes is not None
                         else "navigation.json") if args.command == "navigate" else "page-h3.json")
    kwargs = dict(output=output, profile=inputs["profile"], source=inputs["source"],
                  catalogue=inputs["catalogue"], candidate_id=candidate_id,
                  execution_binding=context.execution_binding)
    verifier_kwargs = dict(profile_receipt=admission._load(context.profile_bytes),
                           source_bytes=context.source_bytes, catalogue_bytes=context.catalogue_bytes,
                           candidate_id=candidate_id, execution_binding=context.execution_binding,
                           not_before_utc=context.not_before_utc)
    action_started_at = admission._now()
    action_runtime = None
    collector_runtime = None
    try:
        if args.command == "navigate" and context.selection_amendment_revision in {2, 3}:
            action_runtime = admission.begin_page_policy_action(context)
        if args.command == "navigate" and context.selection_amendment_revision == 3:
            collector_runtime = admission.begin_operational_collector_action(context)
        if args.command == "navigate":
            if context.selection_amendment_revision in {4, 5, 6, 7, 8, 9, 10, 11}:
                backend = admission.ObservedLiveBackend(admission.ExistingAcquisitionBackend(), context,
                    candidate_id, attempt, admission._attempt_action(context.candidate(candidate_id)))
                produce_navigation_receipt(backend=backend, **kwargs)
                verify_navigation_receipt(output, expected_implementation_hashes=context.mounted_module_hashes["navigation"],
                                          **verifier_kwargs)
            elif context.selection_amendment_bytes is not None:
                from qcsd_lab.rapid_browser_policy_evidence import (
                    BROWSER_POLICY_FAILURE_RECEIPT_TYPE, produce_navigation_policy_observation,
                )
                observation = produce_navigation_policy_observation(
                    policy_amendment_sha256=context.selection_amendment_sha256,
                    expected_implementation_hashes=context.mounted_module_hashes[admission.BROWSER_POLICY_GROUP],
                    not_before_utc=context.browser_policy_not_before_utc, **kwargs,
                )
                if observation["receipt_type"] == BROWSER_POLICY_FAILURE_RECEIPT_TYPE:
                    admission.browser_policy_failure_facts(output, context, candidate_id)
                else:
                    verify_navigation_receipt(output, expected_implementation_hashes=context.mounted_module_hashes["navigation"],
                                              **verifier_kwargs)
            else:
                produce_navigation_receipt(**kwargs)
                verify_navigation_receipt(output, expected_implementation_hashes=context.mounted_module_hashes["navigation"],
                                          **verifier_kwargs)
        else:
            navigation_reference = admission.import_evidence(context.root, args.navigation)
            navigation = admission._child(context.root, navigation_reference)
            admission.durable_create(attempt / "inputs.json", admission._json({"navigation": navigation_reference}))
            if context.selection_amendment_revision in {4, 5, 6, 7, 8, 9, 10, 11}:
                return _v4_probe_page(context, candidate_id, attempt, navigation, args.selected_page_ordinal, kwargs)
            produce_selected_page_h3_receipt(navigation_receipt=navigation,
                selected_page_ordinal=args.selected_page_ordinal,
                expected_navigation_implementation_hashes=context.mounted_module_hashes["navigation"],
                not_before_utc=context.not_before_utc, **kwargs)
            verify_selected_page_h3_receipt(
                output, navigation_receipt=navigation,
                expected_navigation_implementation_hashes=context.mounted_module_hashes["navigation"],
                expected_implementation_hashes=context.mounted_module_hashes["page"], **verifier_kwargs,
            )
    except Exception as error:
        if isinstance(error, admission.ObservedUnsuccessfulLiveAttempt):
            admission.write_checkpoint(context)
            return error.proof
        if collector_runtime is not None:
            from qcsd_lab.rapid_collector_failure_evidence import is_collector_failure
            if is_collector_failure(error):
                try:
                    failure_output = admission.retain_operational_collector_failure(
                        attempt / "collector-failure.json", context, candidate_id=candidate_id, error=error,
                        action_kind="catalogue-boundary-navigation", started_at=action_started_at, runtime=collector_runtime,
                    )
                except Exception as validation_error:
                    admission.durable_create(attempt / "operational-error.json", admission._json({
                        "stage": "navigation-collector-proof-validation", "exception_type": type(validation_error).__name__,
                        "message": str(validation_error), "completed_at": admission._now(),
                        "retryable": True, "scientific_credit": False,
                    }))
                    admission.write_checkpoint(context)
                    raise
                admission.write_checkpoint(context)
                return failure_output
        if action_runtime is not None and admission.is_page_policy_failure(error, action_kind="catalogue-boundary-navigation"):
            try:
                failure_output = admission.retain_page_policy_failure(
                    attempt / "page-policy-failure.json", context, candidate_id=candidate_id, error=error,
                    action_kind="catalogue-boundary-navigation", started_at=action_started_at, runtime=action_runtime,
                )
            except Exception as validation_error:
                admission.durable_create(attempt / "operational-error.json", admission._json({
                    "stage": "navigation-policy-proof-validation", "exception_type": type(validation_error).__name__,
                    "message": str(validation_error), "completed_at": admission._now(),
                    "retryable": True, "scientific_credit": False,
                }))
                admission.write_checkpoint(context)
                raise
            admission.write_checkpoint(context)
            return failure_output
        admission.durable_create(attempt / "operational-error.json", admission._json({
            "stage": args.command, "exception_type": type(error).__name__, "message": str(error),
            "completed_at": admission._now(), "retryable": True, "scientific_credit": False,
        }))
        admission.write_checkpoint(context)
        raise
    admission.write_checkpoint(context)
    return output


def run(args: argparse.Namespace) -> Any:
    if args.command == "init":
        module_sources = {}
        for group in sorted(admission.IMPLEMENTATION_GROUPS):
            items = getattr(args, f"{group}_module")
            if len(dict(items)) != len(items):
                raise ValueError("implementation snapshot name repeats")
            module_sources[group] = dict(items)
        if args.browser_policy_module:
            if len(dict(args.browser_policy_module)) != len(args.browser_policy_module):
                raise ValueError("browser policy implementation snapshot name repeats")
            module_sources[admission.BROWSER_POLICY_GROUP] = dict(args.browser_policy_module)
        if args.collector_module:
            if len(dict(args.collector_module)) != len(args.collector_module):
                raise ValueError("collector implementation snapshot name repeats")
            module_sources[admission.COLLECTOR_GROUP] = dict(args.collector_module)
        if args.attempt_module:
            if len(dict(args.attempt_module)) != len(args.attempt_module):
                raise ValueError("attempt observer implementation snapshot name repeats")
            module_sources[admission.ATTEMPT_GROUP] = dict(args.attempt_module)
        context = admission.initialize_acquisition(
            args.root, profile_path=args.profile, source=args.source, source_receipt=args.source_receipt,
            catalogue=args.catalogue, source_manifest=args.source_manifest,
            admission_image_digest=args.admission_image_digest,
            not_before_utc=datetime.fromisoformat(args.not_before_utc.replace("Z", "+00:00")),
            module_sources=module_sources,
            selection_amendment=args.selection_amendment,
            root_screen_context=args.root_screen_context,
            root_screen_runtime_proof=args.root_screen_runtime_proof,
            root_screen_runtime_proof_sha256=args.root_screen_runtime_proof_sha256,
        )
        return admission.acquisition_status(context)
    context = admission.load_admission_context(args.root)
    if args.command == "status":
        return admission.acquisition_status(context)
    with admission.acquisition_lock(context.root):
        if args.command == "cohort":
            return {"cohort": str(admission.build_acquisition_cohort(context, args.generation)),
                    "capture_authority": "none-requires-separate-live-capture-readiness"}
        candidate_id = _next_candidate(context, args.candidate)
        if args.command == "review":
            attempt = admission._new_attempt(context, candidate_id, "human-review")
            output = attempt / "human-review.json"
            admission.produce_human_review(
                output, context, candidate_id=candidate_id, reviewed_url=args.reviewed_url,
                reviewer=args.reviewer, decision=args.decision, reason=args.reason,
                human_confirmed=args.human_confirmed,
            )
            admission.write_checkpoint(context)
        elif args.command in {"navigate", "probe-page"}:
            output = _page_action(context, candidate_id, args)
        elif args.command == "screen-page":
            attempt = admission._new_attempt(context, candidate_id, "automated-url-domain-screen")
            output = attempt / "automated-screen.json"
            try:
                admission.produce_automated_site_screen(
                    output, context, candidate_id=candidate_id, navigation=args.navigation,
                    page_h3=args.page_h3, selected_page_ordinal=args.selected_page_ordinal,
                )
            except Exception as error:
                admission.durable_create(attempt / "operational-error.json", admission._json({
                    "stage": "automated-url-domain-screen", "exception_type": type(error).__name__,
                    "message": str(error), "completed_at": admission._now(), "retryable": True, "scientific_credit": False,
                }))
                admission.write_checkpoint(context)
                raise
            admission.write_checkpoint(context)
        elif args.command == "prepare":
            output = admission.prepare_site(
                context, candidate_id=candidate_id, navigation=args.navigation,
                page_h3=args.page_h3, human_review=args.human_review,
                automated_screen=args.automated_screen,
            )
        elif args.command == "seal":
            output = admission.produce_site_terminal(
                context, candidate_id=candidate_id, root_surveys=args.root_log,
                human_review=args.human_review, reviewed_url=args.reviewed_url,
                preparation=args.preparation, defer_root=args.defer_root,
                browser_policy_failure=args.browser_policy_failure,
                automated_screen=args.automated_screen, page_policy_failure=args.page_policy_failure,
                collector_failure=args.collector_failure,
                attempt_failure=args.attempt_failure,
            )
        else:
            raise AssertionError("unsupported acquisition action")
        return {"candidate_id": candidate_id, "evidence": str(output),
                "scientific_credit": False, "status": admission.acquisition_status(context)}


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"rapid acquisition: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
