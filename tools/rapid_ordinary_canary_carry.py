#!/usr/bin/env python3
"""HOST-only ordinary carry declaration and public read-only verification."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from qcsd_lab import rapid_ordinary_canary_carry as carry
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    publish = sub.add_parser("publish")
    for name in ("original-readiness", "original-runtime-spec", "original-canonical", "current-input", "current-canonical", "audit-root", "output"):
        publish.add_argument("--" + name, type=Path, required=True)
    publish.add_argument("--reason", required=True)
    publish.add_argument("--individual-evidence", type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("--reference", type=Path, required=True)
    verify.add_argument("--runtime-spec", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "publish":
        original = lanes._load(lanes._read(args.original_readiness))
        if set(original) != {"undefended"}:
            raise ValueError("ordinary carry requires one exact original ordinary readiness entry")
        spec = rolling.load_runtime(args.original_runtime_spec)
        runtime = {key: spec[key] for key in lanes.RUNTIME_KEYS}
        value = carry.publish(original_canary=original["undefended"], original_runtime=runtime,
            original_canonical=carry.reference(args.original_canonical),
            current_input=carry.reference(args.current_input), current_canonical=carry.reference(args.current_canonical),
            audit_root=args.audit_root, output=args.output, reason=args.reason,
            individual_evidence=None if args.individual_evidence is None else carry.reference(args.individual_evidence))
        print(json.dumps({"undefended": value}, sort_keys=True))
    else:
        reference = lanes._load(lanes._read(args.reference))
        if set(reference) != {"undefended"}:
            raise ValueError("ordinary carry verifier requires one exact ordinary readiness entry")
        spec = rolling.load_runtime(args.runtime_spec)
        result = carry.validate(reference["undefended"], runtime={key: spec[key] for key in lanes.RUNTIME_KEYS}, mode="undefended")
        print(json.dumps({"valid": True, "measured_source": result["source"],
            "current_authority_source": result["authority_source"], "scientific_credit": False,
            "formal_accepted_trace_count": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
