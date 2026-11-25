# Review draft from complete PCAP-only study results

This small standard-library utility produces a **review draft**, not a
published conclusion, from the existing final-PCAP aggregation, descriptive
tables and figure provenance. It neither reads captures nor accesses Drive. It
does not use application-completion logs, old handoff metadata, or classifier
results.

## Requirements and execution

Python 3.9 or later is sufficient. Start from the [public PCAP-only toolkit](https://github.com/kaisequeira/neqo-qcsd-lab/tree/main/tools/pcap-overhead)
and complete its extraction, aggregate, descriptive and figure commands. Then:

```sh
python -m unittest -v test_build_report
python build_report.py \
  --manifest session-manifest.csv \
  --aggregate COMPLETED_AGGREGATE_DIRECTORY \
  --descriptive COMPLETED_DESCRIPTIVE_DIRECTORY \
  --figures COMPLETED_FIGURE_DIRECTORY \
  --output NEW_REVIEW_DRAFT.md
```

The output path must not already exist. This utility does not upload or publish
anything. A researcher should inspect all input quality flags, tables, figures,
the generated text and factual historical notes before publishing the draft.
The tests create visibly marked synthetic fixtures in temporary directories;
their values are fabricated and are not study results.

## Input and consistency safeguards

The normal CLI requires a completed 120,000-capture, six-condition, 50-domain,
400-session-per-domain census, zero extractor errors or identity flags, and
matching pinned original manifest, canonical metric-row snapshot,
aggregate-code and figure input hashes. The supplied final manifest itself
must hash to `ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf`.
The descriptive and figure provenance must identify the same
completed metrics snapshot. Figure SVG and PDF files must exist. It verifies
condition-level capture-quality counts, unique and complete domain/condition
keys for the two primary metrics, per-cohort counts, baseline and defended
means, domain-level ratios, macro and pooled summaries, domain percentiles,
interval ordering and requested/valid bootstrap counts. Missing cohorts,
non-finite values, absent denominators or inconsistent tables stop the draft
rather than silently creating results.

The program checks relationships among derived tables, but cannot independently
prove that the measurements themselves were obtained correctly. It does not
rerun the extraction or bootstrap. Reproduce the pipeline from the final
manifest and actual PCAPs, compare checksums and inspect the included QA record
when independent verification is needed. Inspect all per-domain exclusions and
shared-day records; the rendered report is not a replacement for the source
tables. Actual plots and source tables must be published and linked separately.

## How to interpret the draft

- Primary volume is observed IP datagram bytes, including captured protocol
  traffic and retransmissions; PCAP file size is not network usage.
- Time is the first-to-last observed packet-trace span. It is not user-facing
  response completion or browser page-load time. Encrypted PCAPs do not label
  all application versus padding packets.
- Defended and undefended observations are separately recorded and unpaired;
  assigning identical session numbers does not make visits comparable pairs.
- The equal-domain mean of domain percentages and the pooled ratio of cohort
  means have different weighting. Both, their fixed-domain session-bootstrap
  intervals, domain-cluster intervals, absolute means and domain spread appear.
  Valid versus requested bootstrap replicate counts are explicit.
- Domain-cluster intervals describe an assumption about a hypothetical domain
  population, not a guarantee of representative sampling. Neither bootstrap
  fixes time, route, live-resource, workload or selection confounding.
- Sensitivities compare unpaired medians, separately upper-trimmed means, and
  sessions sharing recorded UTC calendar days. A shared day does not imply the
  same hour, payload, route or experiment conditions. Missing data and the
  subset selected for this exploratory check are reported.
- Historical implementation/failure documents are linked for context. They
  do not supply the numeric outcomes and are not asserted to be final-cohort
  failure rates. Privacy effectiveness and classification remain future work.
