# Independent audit of primary point estimates

This study-specific audit independently recomputes the final dataset's primary point estimates from the per-capture SQLite metrics and compares them with the aggregator's domain and overall CSVs. It checks valid counts, per-domain cohort means, absolute differences and percentage overheads, equal-domain mean overheads, pooled ratios of domain means, and equal-domain absolute means. It never assumes captures are paired.

The tool is pinned to the final 120,000-capture manifest and aggregator version used in the study. Before reporting any result it requires the complete balanced manifest, matching capture identities, hashes and sizes, an empty extractor error table, complete aggregate quality/provenance, and the same canonical SQLite snapshot hash as the aggregate. The audit records input table hashes and will not overwrite its output. A comparison with missing domain estimates is marked `passed_with_unavailable`, with the affected coverage reported; it is not a complete comparison.

Run from this directory after completing the full extraction and primary aggregation:

```sh
python3 audit.py \
  --manifest /path/to/session-manifest.csv \
  --database /path/to/full-metrics.sqlite3 \
  --aggregate-dir /path/to/complete-aggregate-output \
  --output /path/to/new-audit-report.json
```

Exit code 0 means no arithmetic differences were found, including the explicitly qualified `passed_with_unavailable` status; inspect status and coverage. Exit code 1 means the completed comparison found discrepancies; exit code 2 means a prerequisite or input failed and no audit report was created. Numbers are compared with relative tolerance `1e-10` and absolute tolerance `1e-8` to accommodate floating-point summation differences. Inputs must be kept stable during the audit.

The calculations use extractor results, not raw PCAPs. This check therefore does not independently validate packet parsing, reported packet identity or timestamps, uncertainty intervals, the scientific comparability of live captures, the fidelity of a defense, or application completion times. The trace-span metric is first to last observed packet. Independent packet-level checks and review of uncertainty and quality exclusions remain necessary.

## Synthetic tests

Python 3 suffices for the unit tests; the integration test also requires NumPy as specified in the parent toolkit's requirements.

```sh
python3 -m unittest -v test_audit
python3 test_against_aggregator.py
```

The integration test writes only temporary synthetic input and tables. It compares the independent calculations to the pinned aggregator's actual CSV writer and snapshot hash, verifies exclusions and detects a deliberately changed value. It uses two domains and three synthetic sessions per cohort; the displayed expected cohort-size field is set to 400 for compatibility with this audit's fixed final-study design. These fixtures are not study results.
