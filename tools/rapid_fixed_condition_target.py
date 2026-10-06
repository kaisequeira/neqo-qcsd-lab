#!/usr/bin/env python3
"""Declare fixed conditions and audit original verified slots without actuation."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).absolute().parents[1]/'src'))
from qcsd_lab import rapid_fixed_condition_target as reader


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    condition=actions.add_parser('condition')
    target=actions.add_parser('target')
    complete=actions.add_parser('audit-complete')
    partial=actions.add_parser('audit-partial')
    initial=actions.add_parser('initialize-progress')
    append=actions.add_parser('append-progress')
    check=actions.add_parser('check')
    chunk=actions.add_parser('chunk-inputs')
    final=actions.add_parser('publish-final')
    def bound(action,*names):
        for name in names:
            action.add_argument('--'+name,type=Path,required=True)
            action.add_argument('--'+name+'-sha256',required=True)
    bound(condition,'configuration','run');condition.add_argument('--mode',choices=reader.MODES,required=True)
    bound(target,'request');bound(complete,'source-binding','closures');bound(partial,'receipt')
    bound(initial,'target','proofs');bound(append,'progress','proofs')
    append.add_argument('--target',type=Path);append.add_argument('--target-sha256')
    for p in (check,chunk,final):bound(p,'progress')
    chunk.add_argument('--classes',nargs='+',type=int,required=True)
    chunk.add_argument('--mode',choices=reader.MODES,required=True)
    chunk.add_argument('--maximum',type=int,default=16)
    for p in (condition,target,complete,partial,initial,append,chunk,final):
        p.add_argument('--output',type=Path,required=True)
    for p in (complete,partial):p.add_argument('--audit-root',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        def ref(name):
            path=getattr(args,name.replace('-','_'));value=reader.reference(path.absolute())
            if value['sha256']!=getattr(args,name.replace('-','_')+'_sha256'):
                raise ValueError('fixed condition public input digest differs')
            return value
        def data(name):return json.loads(reader._open(ref(name)).read_bytes())
        from qcsd_lab.rapid_operation_facts import OperationFacts
        context=OperationFacts();context.begin_action()
        with context.scope():
            if args.action=='condition':
                result=reader.describe_condition(ref('configuration'),ref('run'),args.mode,args.output.absolute())
            elif args.action=='target':
                request=data('request')
                if not isinstance(request,dict) or set(request) not in (
                    {'namespace','enrollment','conditions','native_head','client_sha256','history'},
                    {'namespace','enrollment','conditions','native_head','client_sha256','history','parent'}):
                    raise ValueError('fixed condition target request has another schema')
                result=reader.publish_target(**request,output=args.output.absolute())
            elif args.action=='audit-complete':
                result=reader.audit_complete(source_binding=ref('source-binding'),closures=data('closures'),
                    audit_root=args.audit_root.absolute(),output=args.output.absolute())
            elif args.action=='audit-partial':
                result=reader.audit_partial(receipt=ref('receipt'),audit_root=args.audit_root.absolute(),output=args.output.absolute())
            elif args.action=='initialize-progress':
                result=reader.initialize_progress(target=ref('target'),proofs=data('proofs'),output=args.output.absolute())
            elif args.action=='append-progress':
                if (args.target is None)!=(args.target_sha256 is None):
                    raise ValueError('fixed condition extension requires both target reference flags')
                result=reader.append_progress(progress=ref('progress'),proofs=data('proofs'),
                    target=None if args.target is None else ref('target'),output=args.output.absolute())
            elif args.action=='chunk-inputs':
                result=reader.publish_chunk_inputs(ref('progress'),args.classes,args.mode,
                    maximum=args.maximum,output=args.output.absolute())
            elif args.action=='publish-final':result=reader.publish_final(ref('progress'),args.output.absolute())
            else:
                value=reader.validate_progress(ref('progress'))
                result={'target_id':value['target_id'],'classes':len(value['classes']),
                    'target_accepted_count':value['target_accepted_count'],'final_target':reader.TOTAL,
                    'aggregate_status':value['aggregate_status'],'history_counts_as_target_credit':False}
            reader._check_action();context.check()
        print(json.dumps({'operation':args.action,'status':'closed','result':result},sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({'operation':args.action,'status':'refused','error_type':type(error).__name__,
            'error_message':str(error)},sort_keys=True))
        return 1


if __name__=='__main__':raise SystemExit(main())
