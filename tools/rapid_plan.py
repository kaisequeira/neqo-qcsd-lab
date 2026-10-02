#!/usr/bin/env python3
"""Publish and reopen rapid-v5 lanes from independently verified site evidence.

This writes campaign documents, not traffic or capture authority. Qualification
spec paths are relative to the spec file unless explicitly absolute. Keep the
spec and its referenced qualification evidence alongside the acquisition data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_site_admission as admission

PLAN_TYPE = "qcsd-rapid-v5-lane-plan"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _qualification_spec(path: Path) -> tuple[list[dict[str, Any]], str]:
    raw = admission._read(path)
    value = admission._load(raw)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "qualification_sets"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or not isinstance(value["qualification_sets"], list)):
        raise ValueError("qualification spec needs schema_version 1 and qualification_sets")
    result = []
    for row in value["qualification_sets"]:
        if not isinstance(row, dict) or set(row) != {
            "qualification_set", "manifest", "sidecar_root", "prefix_spec_root"
        }:
            raise ValueError("qualification spec shard fields are invalid")
        resolved = dict(row)
        for key in ("manifest", "sidecar_root", "prefix_spec_root"):
            reference = row[key]
            if key == "prefix_spec_root" and reference is None:
                continue
            if not isinstance(reference, str) or not reference:
                raise ValueError("qualification spec paths must be nonempty strings")
            target = Path(reference)
            resolved[key] = target if target.is_absolute() else path.absolute().parent / target
        result.append(resolved)
    return result, _sha(raw)


def _inputs(args: argparse.Namespace) -> tuple[Any, tuple[plan.Site, ...], plan.FrozenBindings, str, str]:
    context = admission.load_admission_context(args.root)
    cohort_raw = admission._read(args.cohort)
    cohort = admission._load(cohort_raw)
    generation = cohort.get("payload", {}).get("generation") if isinstance(cohort, dict) else None
    if generation not in {"launch-10", "final-50"}:
        raise ValueError("rapid planning needs a launch-10 or final-50 cohort")
    qualification_sets, spec_sha = _qualification_spec(args.qualification_spec)
    # Reopens ordered terminals, full workload graphs and all named qualifiers.
    sites = admission.qualified_capture_sites(
        context, args.cohort, workload_root=args.workload_root,
        qualification_sets=qualification_sets,
    )
    provenance = admission._unpack(
        admission._read(context.root / "provenance.json"), admission.PROVENANCE_TYPE,
    )
    profile_path = admission._child(context.root, provenance["inputs"]["profile"])
    bindings = plan.FrozenBindings(
        profile_path, _sha(context.profile_bytes), args.cohort, _sha(cohort_raw), 5,
        admission._child(context.root, provenance["inputs"]["selection_amendment"])
        if getattr(context, "selection_amendment_bytes", None) is not None else None,
        getattr(context, "selection_amendment_sha256", None),
    )
    return context, sites, bindings, generation, spec_sha


def _payload(context: Any, sites: tuple[plan.Site, ...], bindings: plan.FrozenBindings,
             generation: str, spec_sha: str, lanes: tuple[plan.Lane, ...],
             campaign_hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "study_version": 5,
        "cohort_generation": generation,
        "acquisition_provenance_sha256": context.provenance_sha256,
        "bindings": bindings.digests(),
        "qualification_spec_sha256": spec_sha,
        "sites": [asdict(site) for site in sites],
        "lanes": [{**asdict(lane), "workload_ids": list(lane.workload_ids),
                   "campaign_sha256": campaign_hashes[lane.campaign_name]}
                  for lane in lanes],
        "planned_trace_count": sum(lane.sample_count for lane in lanes),
        "formal_accepted_trace_count": 0,
        "scientific_credit": False,
        "capture_authority": "none-requires-bound-launch-and-deep-verified-results",
    }


def _ensure_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError("rapid plan destination is create-only")
    if not path.parent.is_dir() or any(part.is_symlink() for part in path.parents):
        raise ValueError("rapid plan parent must be an existing directory without symlinks")


def run(args: argparse.Namespace) -> dict[str, Any]:
    context, sites, bindings, generation, spec_sha = _inputs(args)
    final = generation == "final-50"
    lanes = plan.plan_lanes(sites, final=final, study_version=5)
    if args.command == "successor":
        if args.lane not in {lane.logical_name for lane in lanes}:
            raise ValueError("successor must name one registered logical lane")
        base = next(lane for lane in lanes if lane.logical_name == args.lane)
        lanes = (plan.successor_lane(base, args.generation),)
    if args.command in {"publish", "successor"}:
        _ensure_output(args.output)
        if args.command == "successor":
            lane = lanes[0]
            hashes = {lane.campaign_name: plan.materialize_successor_campaign(
                args.campaign_dir, sites, lane, bindings=bindings,
                workload_root=args.workload_root,
            )}
        else:
            hashes = plan.materialize_lane_campaigns(
                args.campaign_dir, sites, final=final, bindings=bindings,
                workload_root=args.workload_root,
            )
        payload = _payload(context, sites, bindings, generation, spec_sha, lanes, hashes)
        admission.durable_create(args.output, admission._json(admission._bind(PLAN_TYPE, payload)))
        return {"plan": str(args.output), "plan_sha256": _sha(admission._read(args.output)),
                "lane_count": len(lanes), "planned_trace_count": payload["planned_trace_count"],
                "formal_accepted_trace_count": 0, "scientific_credit": False}
    stored = admission._unpack(admission._read(args.output), PLAN_TYPE)
    rows = stored.get("lanes")
    if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("rapid plan has no lane inventory")
    if len(rows) == 1 and rows[0].get("generation", 1) > 1:
        row = rows[0]
        base = next((lane for lane in lanes if lane.logical_name == plan._campaign_name(
            row["role"], row["block"], row["shard"], row["mode"], 1, 5,
        )), None)
        if base is None:
            raise ValueError("rapid successor plan is outside the registered grid")
        lanes = (plan.successor_lane(base, row["generation"]),)
    plan._check_bindings(bindings)
    plan._check_workload_files(sites, args.workload_root)
    hashes = {}
    for lane in lanes:
        raw = admission._read(args.campaign_dir / f"{lane.campaign_name}.yml")
        if raw != plan.render_lane_campaign(lane, sites):
            raise ValueError("rapid campaign bytes differ from the frozen lane grid")
        if lane.generation > 1:
            predecessor = replace(
                lane, generation=lane.generation - 1,
                campaign_name=plan._campaign_name(
                    lane.role, lane.block, lane.shard, lane.mode, lane.generation - 1, 5,
                ),
            )
            if admission._read(args.campaign_dir / f"{predecessor.campaign_name}.yml") != plan.render_lane_campaign(predecessor, sites):
                raise ValueError("rapid predecessor campaign bytes changed")
        hashes[lane.campaign_name] = _sha(raw)
    expected = _payload(context, sites, bindings, generation, spec_sha, lanes, hashes)
    if admission._json(stored) != admission._json(expected):
        raise ValueError("rapid plan differs from reopened acquisition and qualification evidence")
    return {"valid": True, "lane_count": len(lanes),
            "planned_trace_count": expected["planned_trace_count"],
            "formal_accepted_trace_count": 0, "scientific_credit": False}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("publish", "verify", "successor"):
        command = commands.add_parser(name)
        command.add_argument("root", type=Path, help="frozen rapid acquisition root")
        for flag in ("cohort", "qualification-spec", "workload-root", "campaign-dir", "output"):
            command.add_argument(f"--{flag}", type=Path, required=True)
        if name == "successor":
            command.add_argument("--lane", required=True, help="generation-one logical campaign name")
            command.add_argument("--generation", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"rapid plan: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
