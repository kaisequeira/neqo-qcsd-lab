#!/usr/bin/env python3
"""Publish bounded current chunks from authenticated fixed-condition progress."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parents[1] / 'src'))
from qcsd_lab import rapid_target_chunks as chunks
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab.rapid_operation_facts import OperationFacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    policy = actions.add_parser('policy')
    plan = actions.add_parser('plan')
    check = actions.add_parser('check')
    recover = actions.add_parser('successor')
    def bound(action, name):
        action.add_argument('--' + name, type=Path, required=True)
        action.add_argument('--' + name + '-sha256', required=True)
    for action in (policy, plan, check, recover): bound(action, 'spec')
    bound(policy, 'chunk-inputs'); bound(policy, 'canonical')
    bound(plan, 'policy')
    for action in (policy, plan, recover): action.add_argument('--output', type=Path, required=True)
    for action in (plan, recover): action.add_argument('--spec-output', type=Path, required=True)
    recover.add_argument('--lane', required=True)
    recover.add_argument('--generation', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        context = OperationFacts(); context.begin_action()
        with context.scope():
            def ref(name):
                key = name.replace('-', '_')
                observed = target.reference(getattr(args, key).absolute())
                if observed['sha256'] != getattr(args, key + '_sha256'):
                    raise ValueError('target chunk public reference digest differs')
                return observed
            spec = lanes.load_capture_spec(target._open(ref('spec')))
            if args.action == 'policy':
                path = chunks.publish_policy(spec, ref('chunk-inputs'), ref('canonical'), args.output.absolute())
                result = {'policy': target.reference(path), 'scientific_credit': False}
            elif args.action == 'check':
                _, value = rolling.verify_capture_plan(spec, require_current=True, _context=context)
                if chunks.FIELD not in value:
                    raise ValueError('target chunk check cannot substitute an old four-visit or SCI plan')
                result = {'planned_trace_count': value['planned_trace_count'],
                    'target_chunk_policy': value[chunks.FIELD], 'scientific_credit': False}
            else:
                path = (chunks.publish_plan(spec, ref('policy'), args.output.absolute(), _context=context)
                        if args.action == 'plan' else chunks.publish_successor(spec, args.lane,
                            args.generation, args.output.absolute()))
                candidate = replace(spec, plan_receipt=path)
                rolling.verify_capture_plan(candidate, require_current=True, _context=context)
                target._check_action()
                rolling._write_spec(args.spec_output.absolute(), candidate)
                result = {'plan': target.reference(path), 'spec': target.reference(args.spec_output.absolute()),
                    'scientific_credit': False}
            target._check_action()
        print(json.dumps({'operation': args.action, 'status': 'closed', 'result': result}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'operation': args.action, 'status': 'refused', 'error_type': type(error).__name__}, sort_keys=True))
        return 1


if __name__ == '__main__': raise SystemExit(main())
