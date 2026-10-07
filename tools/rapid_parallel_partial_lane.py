#!/usr/bin/env python3
"""Read-only prospective partial proof of original terminal PARALLEL workers."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).absolute().parents[1]/"src"))
from qcsd_lab import rapid_parallel_partial_lane as reader

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest="action",required=True)
    bind=actions.add_parser("bind-reader")
    bind.add_argument("--source-root",type=Path,required=True)
    bind.add_argument("--lab-head",required=True);bind.add_argument("--native-head",required=True)
    bind.add_argument("--output",type=Path,required=True)
    declare=actions.add_parser("declare")
    for name in ("source-binding","reader-binding","spec","intent"):
        declare.add_argument("--"+name,type=Path,required=True)
        declare.add_argument("--"+name+"-sha256",required=True)
    for name in ("evidence-root","result","audit-root","output"):
        declare.add_argument("--"+name,type=Path,required=True)
    declare.add_argument("--allow-root-offline-endpoint-replay",action="store_true")
    verify=actions.add_parser("verify")
    verify.add_argument("--receipt",type=Path,required=True)
    verify.add_argument("--receipt-sha256",required=True)
    verify.add_argument("--audit-root",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        def ref(name):
            attribute=name.replace("-","_")
            value=reader.reference(getattr(args,attribute).absolute())
            if value["sha256"]!=getattr(args,attribute+"_sha256"):
                raise ValueError("parallel partial public input digest differs")
            return value
        if args.action=="bind-reader":
            result=reader.bind_reader(root=args.source_root.absolute(),lab_head=args.lab_head,
                native_head=args.native_head,output=args.output.absolute())
        elif args.action=="declare":
            ref("spec");ref("intent")
            result=reader.declare(source_binding=ref("source-binding"),reader_binding=ref("reader-binding"),
                spec=args.spec.absolute(),evidence_root=args.evidence_root.absolute(),intent=args.intent.absolute(),
                result=args.result.absolute(),audit_root=args.audit_root.absolute(),output=args.output.absolute(),
                root_offline_endpoint_replay=args.allow_root_offline_endpoint_replay)
            ref("spec");ref("intent")
        else:
            result=reader.verify(ref("receipt"),audit_root=args.audit_root.absolute())
        print(json.dumps({"operation":args.action,"status":"closed","result":result},sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({"operation":args.action,"status":"refused","error_type":type(error).__name__,
            "error":str(error)},sort_keys=True))
        return 1

if __name__=="__main__":
    raise SystemExit(main())
