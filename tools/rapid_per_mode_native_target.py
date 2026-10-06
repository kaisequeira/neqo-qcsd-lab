#!/usr/bin/env python3
"""Declare finite Native epochs and join original fixed-target proofs on HOST."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parents[1] / "src"))
from qcsd_lab import rapid_per_mode_native_target as reader
from qcsd_lab.rapid_operation_facts import OperationFacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    target = actions.add_parser("target")
    initial = actions.add_parser("initialize-progress")
    append = actions.add_parser("append-progress")
    check = actions.add_parser("check")
    chunk = actions.add_parser("chunk-inputs")
    final = actions.add_parser("publish-final")
    def bound(action, *names):
        for name in names:
            action.add_argument("--" + name, type=Path, required=True)
            action.add_argument("--" + name + "-sha256", required=True)
    def optional(action, name):
        action.add_argument("--" + name, type=Path)
        action.add_argument("--" + name + "-sha256")
    bound(target, "request")
    bound(initial, "target", "mode-progress"); optional(initial, "previous-progress")
    bound(append, "progress", "mode-progress"); optional(append, "target")
    for action in (check, chunk, final): bound(action, "progress")
    for action in (target, initial, append, chunk, final): action.add_argument("--output", type=Path, required=True)
    chunk.add_argument("--classes", nargs="+", type=int, required=True)
    chunk.add_argument("--mode", choices=reader.MODES, required=True)
    chunk.add_argument("--epoch-index", type=int, required=True)
    chunk.add_argument("--maximum", type=int, default=16)
    args = parser.parse_args(argv)
    try:
        context = OperationFacts(); context.begin_action()
        with context.scope():
            reader.fixed.reference(Path(__file__))
            def ref(name):
                path = getattr(args, name.replace("-", "_")); digest = getattr(args, name.replace("-", "_") + "_sha256")
                if (path is None) != (digest is None): raise ValueError("both reference flags are required")
                if path is None: return None
                value = reader.fixed.reference(path.absolute())
                if value["sha256"] != digest: raise ValueError("epoch public input digest differs")
                return value
            def data(name): return json.loads(reader.fixed._open(ref(name)).read_bytes())
            if args.action == "target":
                request = data("request")
                if not isinstance(request, dict) or set(request) not in (
                    {"namespace", "mode_targets", "carry_progress"},
                    {"namespace", "mode_targets", "carry_progress", "parent"}):
                    raise ValueError("epoch target request has another schema")
                result = reader.publish_target(**request, output=args.output.absolute())
            elif args.action == "initialize-progress":
                result = reader.initialize_progress(target=ref("target"), mode_progress=data("mode-progress"),
                    previous_progress=ref("previous-progress"), output=args.output.absolute())
            elif args.action == "append-progress":
                result = reader.append_progress(progress=ref("progress"), mode_progress=data("mode-progress"),
                    target=ref("target"), output=args.output.absolute())
            elif args.action == "chunk-inputs":
                result = reader.publish_chunk_inputs(ref("progress"), args.classes, args.mode,
                    epoch_index=args.epoch_index, maximum=args.maximum, output=args.output.absolute())
            elif args.action == "publish-final": result = reader.publish_final(ref("progress"), args.output.absolute())
            else:
                value = reader.validate_progress(ref("progress"))
                result = {"target_id": value["target_id"], "classes": len(value["classes"]),
                    "target_accepted_count": value["target_accepted_count"], "final_target": reader.TOTAL,
                    "aggregate_status": value["aggregate_status"], "original_source_labels_retained": True}
            reader.fixed._check_action(); context.check()
        print(json.dumps({"operation": args.action, "status": "closed", "result": result}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"operation": args.action, "status": "refused", "error_type": type(error).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__": raise SystemExit(main())
