#!/usr/bin/env python3
"""Canonical-homepage V13 declaration, discovery and independent reopening."""
from pathlib import Path
import argparse
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('_qcsd_whole_graph_producer_v13', HERE / 'graph_input.py')
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    declare = actions.add_parser('declare')
    for name in ('previous-plan', 'previous-batch', 'output'):
        declare.add_argument('--' + name, type=Path, required=True)
    declare.add_argument('--count', type=int, required=True)
    check = actions.add_parser('check'); check.add_argument('--plan', type=Path, required=True)
    verify = actions.add_parser('verify-input'); verify.add_argument('--input', type=Path, required=True)
    failed = actions.add_parser('verify-failure'); failed.add_argument('--failure', type=Path, required=True)
    verify_batch = actions.add_parser('verify-batch')
    verify_batch.add_argument('--plan', type=Path, required=True); verify_batch.add_argument('--batch', type=Path, required=True)
    discovery = actions.add_parser('discover')
    discovery.add_argument('--plan', type=Path, required=True)
    discovery.add_argument('--candidate-index', type=int, required=True); discovery.add_argument('--output', type=Path, required=True)
    discovery.add_argument('--host-validation', type=Path, required=True)
    validate = actions.add_parser('validate')
    for name in ('plan', 'output', 'recorder'):
        validate.add_argument('--' + name, type=Path, required=True)
    prebirth = actions.add_parser('check-physical')
    prebirth.add_argument('--plan', type=Path, required=True); prebirth.add_argument('--host-validation', type=Path, required=True)
    run = actions.add_parser('run')
    for name in ('plan', 'output', 'recorder'):
        run.add_argument('--' + name, type=Path, required=True)
    run.add_argument('--plan-sha256', required=True); run.add_argument('--container-prefix', required=True)
    transport = actions.add_parser('transport'); transport.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'declare':
            result = {'plan': str(graph.declare_next(args.previous_plan, args.previous_batch, args.count, args.output))}
        elif args.action == 'check':
            result = {'candidate_count': len(graph.check_plan(args.plan)['candidates'])}
        elif args.action == 'verify-input':
            result = graph.verify_input(args.input)
        elif args.action == 'verify-failure':
            result = graph.verify_failure(args.failure)
        elif args.action == 'verify-batch':
            result = {'batch': graph.reference(args.batch)}
            graph.verify_batch(args.batch, graph.check_plan(args.plan))
        elif args.action == 'transport':
            result = {'read_only_roots': [str(path) for path in graph.transport_roots(graph.check_plan(args.plan))]}
        elif args.action == 'validate':
            result = {'host_validation': str(graph.validate(args.plan, args.output, args.recorder))}
        elif args.action == 'check-physical':
            result = {'candidate_count': len(graph.physical_plan(args.plan, args.host_validation)['candidates'])}
        elif args.action == 'discover':
            return graph.discover(args.plan, args.candidate_index, args.output, args.host_validation)
        else:
            result = {'batch': str(graph.run(args.plan, args.plan_sha256, args.output, args.container_prefix, args.recorder))}
        print(json.dumps({'status': 'closed', 'action': args.action, **result, **graph.ZERO}, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'refused', 'action': args.action, 'error_type': type(error).__name__,
            'error_detail': str(error)[:512], **graph.ZERO}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
