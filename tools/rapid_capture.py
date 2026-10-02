#!/usr/bin/env python3
"""Launch/reopen rapid lanes and publish/reopen the final auditable corpus.

The operator spec uses paths relative to its own location. Launches are
serialized and create-only; recovery supplies a published successor plan and
its immediate predecessor intent. Generic resume is deliberately unavailable.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from qcsd_lab import rapid_lane_evidence as evidence


CLOSURE_SCRIPT = """
import json,sys
from pathlib import Path
from qcsd_lab import rapid_lane_evidence as e
value=json.loads(sys.argv[1])
spec=e.CaptureSpec(**{k:Path(v) if k in e.PATH_KEYS else v for k,v in value['spec'].items()})
root=Path(value['evidence_root'])
if value['action']=='publish':
    result=e.publish_corpus_manifest(spec,root,Path(value['path']))
else:
    result=e.verify_corpus_manifest(e._load(e._read(Path(value['path']))),spec=spec,evidence_root=root)
print(json.dumps(result,sort_keys=True,allow_nan=False))
""".strip()


def closure_command(spec, root, path, *, publish):
    command = evidence.image_check_command(spec)
    index = command.index("--entrypoint")
    mount = f"{root}:{root}:{'rw' if publish else 'ro'}"
    matching = [position + 1 for position, item in enumerate(command[:index])
                if item == "--volume" and command[position + 1].split(":")[1] == str(root)]
    if matching:
        command[matching[0]] = mount
    else:
        command[index:index] = ["--volume", mount]
    command[-2:] = [CLOSURE_SCRIPT, json.dumps({"spec": spec.serializable(), "evidence_root": str(root),
                                             "path": str(path), "action": "publish" if publish else "verify"}, sort_keys=True)]
    return command


def run(args):
    spec = evidence.load_capture_spec(args.spec)
    root = evidence._regular_directory(args.evidence_root)
    if args.command == "launch":
        path = evidence.launch_lane(spec, root, args.lane, predecessor_intent=args.predecessor_intent)
        facts = evidence.verify_launch_receipt(path, spec=spec, evidence_root=root)
        return {"receipt": str(path), **facts}
    if args.command == "verify-lane":
        # Actual image validation is performed again rather than accepting a
        # native host's caller-supplied qualification eligibility flag.
        evidence.check_bound_image(spec, root)
        return evidence.verify_launch_receipt(args.receipt, spec=spec, evidence_root=root)
    if args.command == "complete-lane":
        evidence.check_bound_image(spec, root)
        path = evidence.complete_lane(spec, root, args.intent)
        return {"receipt": str(path), **evidence.verify_launch_receipt(path, spec=spec, evidence_root=root)}
    if args.command == "retire-lane":
        path = evidence.retire_lane(spec, root, args.intent)
        return {"receipt": str(path), "scientific_credit": False, "formal_accepted_trace_count": 0}
    publish = args.command == "publish-manifest"
    target = args.output if publish else args.manifest
    if not target.absolute().is_relative_to(root):
        raise ValueError("corpus manifest must remain beneath its explicit evidence root")
    result = subprocess.run(closure_command(spec, root, target.absolute(), publish=publish),
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    execution = {"command": closure_command(spec, root, target.absolute(), publish=publish),
                 "returncode": result.returncode, "stdout": evidence._put_object(root, result.stdout.encode()),
                 "stderr": evidence._put_object(root, result.stderr.encode())}
    evidence.durable_create(root / f"corpus-check-{evidence._sha(evidence._json(execution))}.json", evidence._json(execution))
    if result.returncode:
        raise ValueError("actual bound-image corpus closure failed; raw output retained")
    facts = evidence._load(result.stdout.encode())
    if facts.get("valid") is not True or type(facts.get("accepted")) is not int or facts["accepted"] != 16_000:
        raise ValueError("actual corpus closure did not independently verify all 16,000 traces")
    return facts


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("launch", "verify-lane", "complete-lane", "retire-lane", "publish-manifest", "verify-manifest"):
        command = commands.add_parser(name)
        command.add_argument("--spec", type=Path, required=True)
        command.add_argument("--evidence-root", type=Path, required=True)
        if name == "launch":
            command.add_argument("--lane", required=True)
            command.add_argument("--predecessor-intent", type=Path)
        elif name == "verify-lane":
            command.add_argument("--receipt", type=Path, required=True)
        elif name in {"complete-lane", "retire-lane"}:
            command.add_argument("--intent", type=Path, required=True)
        elif name == "publish-manifest":
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv=None):
    try:
        result = run(_parser().parse_args(argv))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"rapid capture: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
