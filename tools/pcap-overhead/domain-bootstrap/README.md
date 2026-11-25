# Exploratory domain-resampling sensitivity

This code supplements, and does not change, the primary fixed-50-domain session-bootstrap intervals. It compares two exploratory resampling choices for the equal-domain average of the five defended-versus-undefended per-domain percentages:

1. **Domain-only:** resample entire per-domain percentage estimates with replacement. Each selected estimate retains its defended and undefended domain cohort means together; sessions are not resampled inside this method.
2. **Two-stage:** resample domains with replacement, then, for every selected domain occurrence, independently resample the defended and undefended sessions in that domain and calculate the ratio again. Each repeated occurrence gets a fresh pair of within-domain resamples. This differs from the original primary aggregator's secondary domain-cluster field, which reuses a single within-domain draw when the same domain is chosen more than once. The primary fixed-domain session intervals and point estimates are unaffected by that implementation detail.

These are **methodological sensitivities, not verified confidence coverage or causal inference**. Domains were purposively selected and may not represent a domain population; live sessions may be temporally dependent and nonexchangeable. Two-stage resampling can count within-cluster variation more than once and overestimate variance. Ng, Grieve and Carpenter, [*Two-stage nonparametric bootstrap sampling with shrinkage correction for clustered data*](https://journals.sagepub.com/doi/pdf/10.1177/1536867X1301300111), *The Stata Journal* 13(1), 2013, §2.4, discuss that possibility and a correction for their clustered-trial setting; this code does not implement that correction or claim its assumptions fit this study.

## Inputs and use

Use Python 3 and NumPy with the exact version recorded in the output provenance. Supply the final 120,000-entry `session-manifest.csv`, the PCAP-derived metrics SQLite database, the **same complete primary run's** `quality.json` and its sibling `overall-overheads.csv` and `domain-overheads.csv`, and the pinned primary `aggregate.py`. The quality, source, manifest, complete identity-matched census and canonical database snapshot must agree before output. Each eligible per-domain count, cohort mean, absolute difference and ratio must match the primary domain table; the equal-domain point values must match the primary summary. These checks do not independently read the PCAPs or assess defense fidelity.

```sh
python3 domain_bootstrap.py --manifest session-manifest.csv --database metrics.sqlite3 \
  --quality PRIMARY_RESULTS/quality.json --aggregate aggregate.py \
  --output exploratory-domain-bootstrap --seed 20261125 --replicates 2000
python3 -m unittest -v test_domain_bootstrap
```

The output directory must not already exist. The CSV gives one row per defense and primary metric, its fixed-50 point estimate, separate percentile bounds for the two sensitivity methods, domain and replicate coverage, and zero-denominator accounting. Two-stage replicates with a zero resampled baseline in any selected occurrence are undefined; the displayed bounds use finite replicates and become conditional on those finite draws. Missing or zero-baseline cohorts make the comparison unavailable; no zero or small artificial denominator is substituted. The provenance JSON records exact input and script hashes, snapshot, seed, replicate count, Python and NumPy versions and caveats. Intervals describe neither user page-load time nor classifier performance.
