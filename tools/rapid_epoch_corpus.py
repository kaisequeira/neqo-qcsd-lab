"""Portable HOST reader for exact original Source epochs and final 16K coverage."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys


def _ref(path: Path) -> dict:
    from qcsd_lab.rapid_epoch_corpus import reference
    return reference(path.absolute())


def main(argv=None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from qcsd_lab import rapid_epoch_corpus as corpus
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    source = commands.add_parser("source")
    source.add_argument("--source", type=Path, required=True)
    source.add_argument("--lab-head", required=True)
    source.add_argument("--native-head", required=True)
    source.add_argument("--output", type=Path, required=True)
    for action in ("audit", "audit-partial"):
        audit = commands.add_parser(action)
        audit.add_argument("--final-enrollment", type=Path, required=True)
        audit.add_argument("--membership-source", type=Path, required=True)
        audit.add_argument("--epoch-source", type=Path, action="append", default=[])
        audit.add_argument("--lane-closure", type=Path, action="append", required=True)
        audit.add_argument("--prior-progress", type=Path, action="append", required=True)
        audit.add_argument("--output-root", type=Path, required=True)
        if action == "audit-partial":
            audit.add_argument("--partial-progress", type=Path, action="append", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--audit", type=Path, required=True)
    publish.add_argument("--output", type=Path, required=True)
    publish_partial = commands.add_parser("publish-partial")
    publish_partial.add_argument("--audit", type=Path, required=True)
    publish_partial.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == "source":
        result = corpus.bind_source(args.source.absolute(), args.lab_head, args.native_head, args.output)
    elif args.action == "audit":
        result = corpus.audit(_ref(args.final_enrollment), _ref(args.membership_source),
                              [_ref(path) for path in args.epoch_source], [_ref(path) for path in args.lane_closure],
                              [_ref(path) for path in args.prior_progress], args.output_root)
    elif args.action == "audit-partial":
        result = corpus.audit_with_partials(_ref(args.final_enrollment), _ref(args.membership_source),
            [_ref(path) for path in args.epoch_source], [_ref(path) for path in args.lane_closure],
            [_ref(path) for path in args.prior_progress], [_ref(path) for path in args.partial_progress], args.output_root)
    elif args.action == "publish-partial":
        result = corpus.publish_with_partials(_ref(args.audit), args.output)
    else:
        result = corpus.publish(_ref(args.audit), args.output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
