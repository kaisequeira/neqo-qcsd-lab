#!/usr/bin/env python3
"""Read-only installed-release proof and separate incomplete-chunk trace receipts."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parents[1] / 'src'))
from qcsd_lab import rapid_chunk_partial_lane as reader


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    actions = p.add_subparsers(dest='action', required=True)
    source = actions.add_parser('bind-source')
    for name in ('source-root', 'canonical', 'runtime', 'audit-root', 'output'):
        source.add_argument('--' + name, type=Path, required=True)
    for name in ('canonical-sha256', 'runtime-sha256'):
        source.add_argument('--' + name, required=True)
    portable = actions.add_parser('bind-source-v2')
    for name in ('source-root', 'canonical', 'runtime', 'audit-root', 'output'):
        portable.add_argument('--' + name, type=Path, required=True)
    for name in ('canonical-sha256', 'runtime-sha256'):
        portable.add_argument('--' + name, required=True)
    declare = actions.add_parser('declare')
    for name in ('source-binding', 'spec', 'evidence-root', 'intent', 'result', 'audit-root', 'output'):
        declare.add_argument('--' + name, type=Path, required=True)
    verify = actions.add_parser('verify')
    for name in ('receipt', 'audit-root'):
        verify.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.action in ('bind-source', 'bind-source-v2'):
            canonical, runtime = reader.reference(args.canonical.absolute()), reader.reference(args.runtime.absolute())
            if canonical['sha256'] != args.canonical_sha256 or runtime['sha256'] != args.runtime_sha256:
                raise ValueError('chunk partial installed input digest differs')
            binder = reader.bind_source if args.action == 'bind-source' else reader.bind_portable_source
            result = binder(root=args.source_root.absolute(), canonical=canonical,
                runtime=json.loads(reader.reopen(runtime).read_bytes()), audit_root=args.audit_root.absolute(),
                output=args.output.absolute())
            if reader.reference(args.runtime.absolute()) != runtime:
                raise ValueError('chunk partial runtime declaration changed')
        elif args.action == 'declare':
            result = reader.declare(source_binding=reader.reference(args.source_binding.absolute()), spec=args.spec.absolute(),
                evidence_root=args.evidence_root.absolute(), intent=args.intent.absolute(), result=args.result.absolute(),
                audit_root=args.audit_root.absolute(), output=args.output.absolute())
        else:
            verified = reader.verify(reader.reference(args.receipt.absolute()), audit_root=args.audit_root.absolute())
            result = {key: verified[key] for key in ('accepted_count', 'registered_layout', 'slot_start', 'slot_count',
                'aggregate_status', 'lane_pass_claim', 'aggregate_formal_credit', 'fresh_deep_operation')}
        print(json.dumps({'operation': args.action, 'status': 'closed', 'result': result}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'operation': args.action, 'status': 'refused',
            'error_type': type(error).__name__, 'error': str(error)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
