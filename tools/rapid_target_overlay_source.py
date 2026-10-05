#!/usr/bin/env python3
"""Register reviewed measurement code separately from an installed runtime."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).absolute().parents[1]/'src'))
from qcsd_lab import rapid_target_overlay_source as reader
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab.rapid_operation_facts import OperationFacts


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    declare=actions.add_parser('bind-source')
    declare.add_argument('--module-root',type=Path,required=True)
    for name in ('module-publication','runtime-source-binding'):
        declare.add_argument('--'+name,type=Path,required=True)
        declare.add_argument('--'+name+'-sha256',required=True)
    declare.add_argument('--output',type=Path,required=True)
    check=actions.add_parser('check')
    check.add_argument('--source-binding',type=Path,required=True)
    check.add_argument('--source-binding-sha256',required=True)
    args=parser.parse_args(argv)
    try:
        def reference(name):
            value=target.reference(getattr(args,name.replace('-','_')).absolute())
            if value['sha256']!=getattr(args,name.replace('-','_')+'_sha256'):
                raise ValueError('overlay public input digest differs')
            return value
        context=OperationFacts();context.begin_action()
        with context.scope():
            if args.action=='bind-source':
                result=reader.bind_source(module_root=args.module_root.absolute(),
                    module_publication=reference('module-publication'),
                    runtime_source_binding=reference('runtime-source-binding'),output=args.output.absolute())
            else:
                source=reader._source(reference('source-binding'))
                result={'module_lab_head':source['lab_head'],
                    'runtime_lab_head':source['binding']['runtime_identity']['source']['lab_commit'],
                    'native_head':source['native_head'],'module_installed_claim':False,'scientific_credit':False}
            target._check_action();context.check()
        print(json.dumps({'operation':args.action,'status':'closed','result':result},sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({'operation':args.action,'status':'refused','error_type':type(error).__name__},sort_keys=True))
        return 1


if __name__=='__main__':raise SystemExit(main())
