# UTC-day packet-count eligibility check

The primary aggregator accepts a record for analysis only when its packet count
is positive, finite and numeric. The UTC-day sensitivity implementation does
not independently enforce this criterion. This read-only check determines
whether any record in the final 120,000-capture metrics census could be affected
by that particular mismatch. It does not modify or repair either analysis.

First independently verify the manifest, capture identities and hashes, and
metrics snapshot. This script does **not** perform those identity checks. It opens
the SQLite database read-only in one transaction, refuses an incomplete census,
a nonempty extractor error table or a changed canonical row hash without reporting
partial counts, and classifies every record by the primary packet-count rule.
Use the matching primary and independent-census canonical snapshot hash.

```sh
python3 -m unittest -v test_check_day_packet_count_eligibility
python3 check_day_packet_count_eligibility.py --database METRICS.sqlite3 \
  --expected-snapshot CANONICAL_METRIC_ROWS_SHA256
```

The output is one JSON object. Exit status 0 means every row passed this one
criterion; 1 means one or more require review; 2 means the check could not run.
A pass does not establish general metric quality, manifest identity, timing
accuracy, UTC-day independence, or confidence-interval validity.
