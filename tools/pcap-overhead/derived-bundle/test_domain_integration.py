"""Synthetic schema integration: pass --domain-script PATH to reviewed source."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

import numpy as np
import build_bundle as bundle


def digest(data):
    return hashlib.sha256(data).hexdigest()


def table(rows):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


class SyntheticAggregate:
    CONDITIONS = bundle.MODES

    @staticmethod
    def cohort_data(records, defense, domain, field, sessions, **kwargs):
        return np.asarray(records[defense, domain, field], dtype=float), {}, {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain-script', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('domain_bootstrap_synthetic_check', args.domain_script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    domains = ['fixture-a.invalid', 'fixture-b.invalid']
    records = {(mode, domain, field): [2., 3., 4.]
               for mode in bundle.MODES for domain in domains for field in ('ip_bytes', 'span_seconds')}
    rows = module.calculate(SyntheticAggregate, records, domains, 100, np.random.default_rng(12), sessions=3)
    assert len(rows) == 10 and all(r['status'] == 'complete' for r in rows)
    summary = [{'defense': r['defense'], 'metric': r['metric'], 'domains': 2,
                'provisional': 'False', 'macro_overhead_pct': r['macro_overhead_pct']} for r in rows]
    detail = [{'defense': r['defense'], 'metric': r['metric'], 'domain': d} for r in rows for d in domains]
    manifest = table([{'defense': mode, 'domain': domain, 'session': session}
                      for mode in bundle.MODES for domain in domains for session in range(1, 4)])
    quality = {'status': 'complete', 'manifest_sha256': digest(manifest),
               'metric_rows_content_sha256': 'b' * 64, 'analysis_script_sha256': bundle.AGGREGATE_SHA,
               'accepted_metric_rows': len(bundle.MODES) * len(domains) * 3}
    qbytes, sbytes, dbytes, data = json.dumps(quality).encode(), table(summary), table(detail), table(rows)
    script_sha = bundle.sha_file(args.domain_script)
    provenance = {'status': 'complete', 'manifest_sha256': quality['manifest_sha256'],
                  'metric_rows_content_sha256': quality['metric_rows_content_sha256'],
                  'primary_aggregate_sha256': bundle.AGGREGATE_SHA,
                  'captured_records': quality['accepted_metric_rows'], 'analysis_script_sha256': script_sha,
                  'primary_quality_sha256': digest(qbytes), 'primary_summary_sha256': digest(sbytes),
                  'primary_domain_table_sha256': digest(dbytes), 'output_csv_sha256': digest(data),
                  'primary_domain_rows_checked': 20, 'primary_domain_rows_unavailable': 0,
                  'seed': 12, 'replicates': 100, 'numpy_version': np.__version__, 'python_version': 'synthetic',
                  'random_generator': 'numpy.random.default_rng', 'method': 'synthetic', 'scope': 'synthetic'}
    bundle.validate_domain_bootstrap(provenance, quality, script_sha, data, qbytes, sbytes, dbytes, manifest)
    print('Synthetic real-generator integration: 10 rows and 20 domain comparisons validated.')


if __name__ == '__main__':
    main()
