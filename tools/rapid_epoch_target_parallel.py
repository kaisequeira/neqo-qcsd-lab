"""Portable declared Native-epoch worker authority; executes no traffic."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_epoch_target_parallel_schedule as workers
from qcsd_lab import rapid_rolling_capture as rolling


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capsule', 'plan', 'check', 'successor'))
    parser.add_argument('--spec', type=Path, required=True); parser.add_argument('--spec-sha256', required=True)
    parser.add_argument('--canonical', type=Path); parser.add_argument('--canonical-sha256')
    parser.add_argument('--capsule', type=Path); parser.add_argument('--capsule-sha256')
    parser.add_argument('--output', type=Path); parser.add_argument('--spec-output', type=Path)
    parser.add_argument('--lane'); parser.add_argument('--generation', type=int)
    args = parser.parse_args(argv)
    def pin(path, digest):
        if path is None or digest is None: raise ValueError('explicit hash-bound input required')
        ref = target.reference(path)
        if ref['sha256'] != digest: raise ValueError('input bytes differ')
        return ref
    try:
        pin(args.spec, args.spec_sha256); spec = lanes.load_capture_spec(args.spec)
        if args.action != 'check' and args.output is None:
            raise ValueError('fresh authority output required')
        if args.action in ('plan', 'successor') and (args.spec_output is None
                or args.spec_output.exists() or args.spec_output.is_symlink()):
            raise ValueError('fresh specification output required')
        if args.action == 'capsule':
            ref = pin(args.canonical, args.canonical_sha256)
            canonical = rolling._ref(Path(ref['path']))
            result = workers.publish_schedule(spec, {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS},
                spec.qualification_spec, canonical, canonical, args.output,
                reason='prospective same-mode declared Native-epoch independent workers')
        elif args.action == 'plan':
            ref = pin(args.capsule, args.capsule_sha256)
            path = workers.publish_plan(spec, rolling._ref(Path(ref['path'])), args.output)
            spec = replace(spec, plan_receipt=path); workers.verify_plan(spec)
            rolling._write_spec(args.spec_output, spec); result = target.reference(path)
        elif args.action == 'successor':
            path = workers.publish_successor(spec, args.lane, args.generation, args.output)
            spec = replace(spec, plan_receipt=path); workers.verify_plan(spec)
            rolling._write_spec(args.spec_output, spec); result = target.reference(path)
        else:
            workers.verify_plan(spec, require_current=True); result = target.reference(spec.plan_receipt)
        print(json.dumps({'status': 'closed', 'action': args.action, 'reference': result, 'scientific_credit': False}, sort_keys=True))
        return 0
    except (ValueError, TypeError, OSError, KeyError) as error:
        print(json.dumps({'status': 'refused', 'action': args.action, 'error_type': type(error).__name__}))
        return 1


if __name__ == '__main__': raise SystemExit(main())
