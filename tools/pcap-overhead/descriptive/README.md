# Final-PCAP descriptive distributions and time sensitivity

This **secondary** analysis complements the primary
[PCAP overhead toolkit](../README.md).
It reads only the final manifest and the verified per-session measurements
extracted from the final PCAP/PCAPNG files. It does not use historical runtime,
receipt or application-completion measurements. It does not read or alter any
packet capture or modify the metrics database.

The program refuses an incomplete census. It checks that the prior public
aggregator's `quality.json` reports 120,000 accepted rows and zero extraction
errors; that the provided manifest and aggregate source match the recorded
SHA-256 hashes; and that a fresh, transaction-consistent read of the metrics
database reproduces the recorded content digest, with no identity errors. It
also independently replicates each public aggregator eligibility decision for
IP bytes and trace span and stops on any mismatch.

## Run after the full aggregation

Use Python 3.9 or newer and NumPy 1.22 or newer; for exact numerical
reproducibility use the NumPy version recorded in the completed aggregate's
`quality.json`. From the `tools/pcap-overhead/descriptive` directory of the
same public toolkit checkout as `aggregate.py`:

```sh
python -m unittest -v test_describe
python describe.py \
  --manifest session-manifest.csv \
  --database metrics.sqlite3 \
  --quality aggregate-results/quality.json \
  --aggregate ../aggregate.py \
  --output descriptive-results
```

The named inputs can be recreated from the final handoff using the
public extractor and aggregator. The final handoff's manifest SHA-256 for this
study is `ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf`.
The public aggregator and the copy that produced `quality.json` must be byte
identical. Output is written only to a new or empty directory. The synthetic
tests contain fabricated values and are not study results.

## Output and interpretation

- `session-distributions-by-cohort.csv`: each defense/domain's valid sample
  count, exclusions, total, mean, p05, p25, median, p75, p90, p95, p99 and max
  for IP bytes and observed trace span. Percentiles use NumPy's linear/R7 rule.
- `session-distributions-by-condition.csv`: the same measures across all
  available valid sessions of each condition. This pooled descriptive view
  weights every valid session equally and must not be mistaken for an
  equal-domain estimand when the number of excluded sessions differs.
- `sensitivity-by-domain.csv` and `sensitivity-overall.csv`: independent
  cohort mean, median and upper-1%-trimmed-mean comparisons. Trimming removes
  `floor(n × 0.01)` of the largest valid observations independently from each
  cohort. Mean ratio percentages are `100 × (defense mean / undefended mean −
  1)`. Median and trimmed comparisons are exploratory robustness checks, not
  replacements for the primary mean-based estimates or their bootstrap CIs.
  Overall sensitivity ratios average the eligible domains equally and report
  how many of the 50 domains were eligible for each denominator.
- `capture-epochs-by-cohort.csv` and `capture-epoch-offsets-by-domain.csv`:
  first-packet UTC time ranges and quantiles, offsets between defended and
  undefended median start times, range overlap or gap, and numbers of UTC days
  and sessions represented in both cohorts. They come from the captures' own
  timestamps. Missing or unconvertible timestamps are counted.
- `shared-utc-day-sensitivity.csv` and `shared-utc-day-summary.csv`: a
  further exploratory within-domain ratio of independent cohort means using
  only sessions whose first packet falls on a UTC calendar day represented in
  both conditions. It reports all valid sessions, valid sessions with usable
  epochs, shared-day counts and the subset actually compared. Days are weighted
  by their observed session counts, not equally; means are not session-paired.
- `descriptive-provenance.json`: manifest, metrics snapshot, aggregator and
  descriptive-script hashes, versions and interpretation constraints.

Capture first-packet times reflect the recorded clock; sorting packets cannot
correct clock error. Overlapping ranges or sharing a UTC calendar day do not
establish the same time of day, identical resource bodies, routes or network
conditions. A negative or positive sensitivity difference is not a causal
estimate. Small or absent shared-day subsets can be unrepresentative; report
their sizes and avoid generalizing a reduced-domain summary to all classes.

IP-byte counts measure observed network-layer traffic, including captured
retransmissions and defense traffic. `observed_span` is earliest-to-latest
captured packet, which may include setup, acknowledgments, padding or teardown;
it is not application-completion or browser page-load latency. The PCAPs do
not themselves identify every encrypted byte as real or dummy, demonstrate
defense fidelity, or measure classification effectiveness. The sensitivity
outputs therefore cannot establish either privacy or user-perceived latency.
