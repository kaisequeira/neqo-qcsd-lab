#!/usr/bin/env python3
"""HOST declaration/verification; physical discovery remains Root-only."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).absolute().parent))
import action_facts
import graph_input as graph


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    actions=parser.add_subparsers(dest='action',required=True)
    declare=actions.add_parser('declare-continuation')
    for key in ('original-plan','original-root','actors-prefix','output'):
        declare.add_argument('--'+key,type=Path,required=True)
    next_plan=actions.add_parser('declare')
    for key in ('previous-plan','previous-batch','output'):
        next_plan.add_argument('--'+key,type=Path,required=True)
    next_plan.add_argument('--count',type=int,required=True)
    check=actions.add_parser('check');check.add_argument('--plan',type=Path,required=True)
    verify=actions.add_parser('verify-input');verify.add_argument('--input',type=Path,required=True)
    discover=actions.add_parser('discover')
    discover.add_argument('--plan',type=Path,required=True);discover.add_argument('--candidate-index',type=int,required=True)
    discover.add_argument('--output',type=Path,required=True)
    run=actions.add_parser('run')
    for key in ('plan','output','recorder'):run.add_argument('--'+key,type=Path,required=True)
    run.add_argument('--container-prefix',required=True)
    run.add_argument('--plan-sha256',required=True)
    args=parser.parse_args()
    try:
        with action_facts.action():
            if args.action=='declare-continuation':
                result={'plan':str(graph.declare(args.original_plan,args.original_root,args.actors_prefix,args.output))}
            elif args.action=='declare':
                result={'plan':str(graph.declare_next(args.previous_plan,args.previous_batch,args.count,args.output))}
            elif args.action=='check':result={'candidate_count':len(graph.check_plan(args.plan)['candidates'])}
            elif args.action=='verify-input':result=graph.verify_input(args.input)
            elif args.action=='discover':return graph.discover(args.plan,args.candidate_index,args.output)
            else:
                import controller
                result={'batch':str(controller.run(args.plan,args.plan_sha256,args.output,args.container_prefix,args.recorder))}
            print(json.dumps({'status':'closed','action':args.action,**result,**graph.ZERO},sort_keys=True))
            return 0
    except Exception as error:
        print(json.dumps({'status':'refused','action':args.action,'error_type':type(error).__name__,**graph.ZERO},sort_keys=True))
        return 1


if __name__=='__main__':raise SystemExit(main())
