# Exploratory UTC-day sensitivity: review-draft builder

This standard-library program creates a **local review draft**, not a
publication, from the completed PCAP-only UTC-day cluster analysis. It reads
no captures, runtime records, receipts or classifier outputs. It reports
eligibility, under-five/under-30-day warnings, missing-epoch coverage, subset
point estimates and bootstrap percentile ranges; it never calls an incomplete
subset an all-50-domain result.

## Produce and validate two outputs

First complete the primary final-PCAP extraction and aggregation using the
[public toolkit](https://github.com/kaisequeira/neqo-qcsd-lab/tree/main/tools/pcap-overhead).
Keep the original completed UTC-day output. Separately rerun the exact
[UTC-day analysis](https://github.com/kaisequeira/neqo-qcsd-lab/tree/main/tools/pcap-overhead/day-bootstrap)
with the same complete metrics snapshot, final manifest, code, seed, number
of draws, Python version and NumPy version recorded in its
`utc-day-cluster-provenance.json`:

```sh
python day_bootstrap.py --manifest session-manifest.csv \
  --database metrics.sqlite3 --quality aggregate-results/quality.json \
  --aggregate ../aggregate.py --output independent-day-results \
  --bootstrap 2000 --seed 20261125
```

The values shown are the study defaults; use the original provenance values
if they differ. Run the two analyses as distinct executions, writing to
different directories. To create a draft, from the directory containing this
builder supply both directories, the final handoff manifest, the exact public
aggregate and day-bootstrap source files, and the primary `quality.json`:

```sh
python -m unittest -v test_build_day_report
python build_day_report.py --manifest session-manifest.csv \
  --quality aggregate-results/quality.json --aggregate PATH_TO/aggregate.py \
  --day-code PATH_TO/day_bootstrap.py --day-output ORIGINAL_DAY_RESULTS \
  --independent-day-output independent-day-results \
  --output NEW_REVIEW_DRAFT.md
```

The output file must not exist or be inside either input directory. The
builder verifies the pinned manifest and source hashes, complete balanced
design, identity/error status, matching metric-snapshot identity, seed and
versions. It compares independently generated domain and summary CSVs
byte-for-byte, checks that the files are distinct rather than hard links,
validates all domain/defense/metric identities, denominators, ranges, warning
counts and subset summary values, and checks for input changes during the
read. Both table hashes are printed in the draft. The byte comparison detects
disagreement; it cannot prove that the second directory was genuinely
generated independently rather than copied. A rerun of the same code is also
not independent-method validation.

## Scientific interpretation

Dates come only from first-packet timestamps in final captures. Each condition
and domain is grouped and resampled independently; all sessions in each
sampled day retain their session weights. Two distinct days per compared
cohort are merely a computational minimum. Fewer-than-five and fewer-than-30
flags are descriptive warnings, not thresholds proving reliability. The 2.5th
and 97.5th percentiles are exploratory bootstrap percentile ranges, not
established confidence coverage for this study. Distinct days may still be
dependent; separate cohort resampling does not model shared same-day or
cross-domain shocks, and does not fix changing live content, noncontemporaneous
collection, capture-clock errors, routes, outcome selection or confounding.

The output reports eligible domains, excluded statuses and missing epochs for
each defense and metric. When no domains qualify, the comparison is
**unavailable**, not zero. Any summary with fewer than 50 qualifying domains
is explicitly an eligible-subset result. The IP metric is captured network
traffic, not PCAP file size or necessarily application payload. The observed
first-to-last packet span can include setup, acknowledgments, padding and
teardown, and is **not application-completion or page-load latency**. No
classifier result or privacy-effectiveness claim is generated.

Review the draft against the full domain table, primary results and actual
figure provenance before using it. The code cannot establish that the input
extractor measured the captures correctly; independently reproduce those
measurements from the final handoff. It cannot determine which encrypted
packets are useful traffic or padding.

The standard tests use synthetic in-memory rows and temporary files. An
optional end-to-end synthetic test reruns the supplied real day-bootstrap
code on 120,000 fabricated keys; it requires NumPy but **never** reads study
data or contacts Drive:

```sh
NEQO_DAY_CODE=PATH_TO/day_bootstrap.py python -m unittest -v test_build_day_report
```

## Optional local one-shot watcher

`watch_independent_day.py` is a Unix-only helper for an already-running local
analysis. It waits for both the original primary aggregation and the original
day sensitivity to report `complete`. It checks the pinned manifest, public
source hashes and original output provenance, verifies the rerun interpreter's
Python and NumPy versions, and actually invokes `day_bootstrap.py` again on the
verified metrics snapshot. It then runs this draft builder against the first
and second output directories. It does **not** copy the first CSVs as a rerun,
access Drive, publish or change either input. The only output is a new local
review-draft directory and state file.

The watcher uses an advisory lock, a persisted at-most-once start marker and
a per-process timeout. Do not clear a `started`, `failed` or terminal marker
without first inspecting the process, state and existing output; an
interrupted run may have partially completed. A merely `waiting` watcher can
be restarted with the same arguments. It is a detached process rather than a
system service and does not automatically survive a reboot. Use `--help` for
the required paths to the manifest, database, original aggregator and day
state files, code, Python executable and an empty state directory. Tests run
without NumPy or network access:

```sh
python -m unittest -v test_watch_independent_day
```

On macOS, an optional bounded idle-sleep assertion can be attached to an
already launched watcher using `caffeinate -i -t 14400 -w WATCHER_PID`. It
changes no persistent system setting; the assertion expires at the timeout or
when the watched process exits. Do not wipe the capture machine or its study
storage while its metrics snapshot and output jobs are still needed.
