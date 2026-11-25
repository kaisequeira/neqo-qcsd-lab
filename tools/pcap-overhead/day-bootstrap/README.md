# Exploratory UTC-day cluster sensitivity

This optional, **final-PCAP-only** analysis complements the primary
[PCAP overhead toolkit](../README.md). It reads the final manifest and the
verified per-session measurements extracted from the final captures. It does
not read historical runtime, receipt or application-completion records, and
does not alter the packet captures or metrics database. It produces no
classification or privacy-effectiveness result.

The primary study tables compare the mean IP bytes and observed packet-trace
span of separately captured defended and undefended cohorts within each domain,
using within-cohort session bootstrap intervals. Sessions obtained on the same
day could share network, resource and machine conditions; an independent
session bootstrap does not model this possible dependence. This supplementary
analysis explores what changes when **whole UTC-day groups** are resampled
instead. It does not replace the primary estimates or validate their coverage.

## Inputs, gates and running

Use Python 3.9 or newer and NumPy 1.22 or newer; for exact numerical
reproducibility use the NumPy version in the completed aggregate's
`quality.json`. From this directory in the same toolkit checkout:

```sh
python -m unittest -v test_day_bootstrap
python day_bootstrap.py \
  --manifest session-manifest.csv \
  --database metrics.sqlite3 \
  --quality aggregate-results/quality.json \
  --aggregate ../aggregate.py \
  --output utc-day-results \
  --bootstrap 2000 --seed 20261125
```

Only a completed **120,000-capture** aggregate with zero extraction errors
and no identity flags is accepted. The script checks the manifest and aggregate
source SHA-256 against `quality.json`, reconstructs a transaction-consistent
metrics snapshot with the public aggregator, and verifies its content hash and
all 120,000 manifest identities. It refuses a nonempty output directory. The
fixture tests construct fabricated values and do not produce study findings.

## Procedure and interpretation

For each defense, domain and metric (`ip_bytes` or `observed_span`), apply the
same validity rules as the primary aggregate. Group eligible sessions by the
UTC calendar day of the first captured packet. Count missing timestamps and
excluded metrics explicitly. Compare each defended cohort with its undefended
cohort **within the same domain**; neither session numbers nor UTC-day groups
are treated as matched pairs. Invalid, missing or zero baseline denominators
are reported rather than replaced.

For a computationally eligible comparison, independently draw, with
replacement, as many whole observed UTC-day clusters as were observed in each
cohort. Retain all sessions in each drawn cluster and calculate a
session-weighted cohort mean: clusters with more sessions contribute more
observations when drawn. Compute the defended-to-undefended mean ratio minus
one for each draw; the 2.5th and 97.5th percentiles form an **exploratory
day-cluster percentile interval**. The default is 2,000 draws, using the
explicitly recorded seed. As the bootstrap cohort sizes may vary, this is not
equivalent to an unweighted mean of daily means.

The software requires **at least two distinct observed days in each cohort**
to compute an interval. Two is only a computational minimum, **not a claim
that a two-day interval is reliable**. Each eligible domain with fewer than
five observed days in either cohort is flagged, as is each with fewer than 30
days. These are descriptive warning thresholds, not claims that any number of
days establishes adequate inference. Literature cautions that
cluster inference can be unreliable with few clusters; it does not validate
this particular ad hoc bootstrap or the independence of these data. See
[Cameron, Gelbach and Miller, Bootstrap-Based Improvements for Inference with
Clustered Errors](https://www.nber.org/papers/t0344) and
[MacKinnon, Nielsen and Webb, Cluster-robust inference](https://doi.org/10.1016/j.jeconom.2022.04.001).

`utc-day-cluster-by-domain.csv` includes both cohorts' valid and invalid
metric counts, missing epochs, epoch-eligible counts, number of UTC days,
session-weighted means, point ratio, eligibility/status, percentile range,
finite draws, and under-five and under-30-day flags. Percentile ranges do not
establish 95% confidence coverage for these data. If either cohort has too few days, the interval is
left blank. `utc-day-cluster-eligible-subset-summary.csv` reports status counts,
the number of eligible domains, numbers with missing timestamps or few days,
and the equal-domain mean of eligible ratios, plus an exploratory bootstrap
percentile range **for that eligible subset only**.
Unless `all_domains_eligible` is true, do not label this as an all-50-domain
estimate. Even with all domains eligible, its interpretation remains conditional
on the observed classes and cluster assumptions. `utc-day-cluster-provenance.json`
records seed, repetitions, software versions, hashes and scope.

Distinct UTC days do not prove statistical independence, comparable live
resource bodies, comparable network routes or valid capture clocks. A day is
an arbitrary coarse grouping and can split a continuous run at midnight. This
approach resamples days **independently between conditions and between domains**;
it does not represent shared same-day network shocks across these strata. It
also cannot repair collection-time confounding, outcome-dependent selection,
or an inaccurate timestamp. In particular, do not pool an eligible-subset
interval with the primary all-domain session bootstrap as if the two had the
same target population.

When a valid metric has no usable first-packet epoch it cannot be assigned to a
day and is excluded from this sensitivity. The affected cohort means therefore
target the epoch-available subset and may differ from the primary all-valid-
session means. Both the per-domain missing counts and eligible-subset summary
identify this restriction. UTC-day arithmetic preserves the source timestamp's
decimal precision across midnight; a timestamp outside the supported calendar
range is reported missing rather than forced into a day.

IP datagram bytes describe captured network-layer traffic, including observed
retransmissions; PCAP container bytes are not used. Observed span is the
earliest-to-latest captured packet and may include setup, padding and teardown;
it is **not** application-completion time or browser page-load latency.
