# Package and restore the final PCAP-derived results

This standard-library utility prepares a **compact derived-results ZIP**, not a
second copy of the 120,000 packet captures. It is intended for use only after
the full census, aggregation, descriptive/day sensitivities and figures have
completed and the report and its underlying evidence have been reviewed. It
does not access Drive, modify captures or publish results.

The final session manifest and resource roster, per-session PCAP-derived
metrics, primary and secondary tables, independent census QA, figure PDFs/SVGs,
and supplied and generated report text are included. Packet payloads,
historical runtime or application-completion outcomes, classification results,
credentials, and local machine paths are excluded.

## Preconditions and building

Use Python 3.9 or later, the final handoff's `session-manifest.csv` and
`resources.csv`, the completed metrics SQLite database and the output
directories of the public `aggregate.py`, `descriptive/describe.py`,
`day-bootstrap/day_bootstrap.py` and `figures/plot_results.py`. Run the public
`census-qa/verify_metrics.py` independently on the completed database to create
its `verified_full` JSON. Inspect the quality and exclusions, figures and report
before deciding to distribute them. From this directory in the public toolkit:

```sh
python3 -m unittest -v test_build_bundle test_restore_metrics
python3 build_bundle.py \
  --manifest session-manifest.csv --resources resources.csv \
  --database metrics.sqlite3 --aggregate AGGREGATE_DIR \
  --descriptive DESCRIPTIVE_DIR --day DAY_CLUSTER_DIR --figures FIGURE_DIR \
  --census-qa VERIFIED_FULL_CENSUS.json \
  --report-builder ../report/build_report.py \
  --reviewed-report REPORT_TO_DISTRIBUTE.md \
  --reviewed-report-sha256 SUPPLIED_REPORT_SHA256 \
  --output NEW_DERIVED_RESULTS.zip
```

To include the optional whole-capture clean UDP/443 candidate sensitivity, add
both `--clean-tuple CLEAN_TUPLE_RESULTS_DIR` and
`--clean-tuple-script ../clean-tuple-sensitivity/clean_tuple_sensitivity.py`.
The complete sensitivity must have been run on the same final manifest and
metric snapshot using the same aggregate implementation. The exporter binds the
script bytes, verifies the sensitivity's identity, eligibility counts, exclusions,
primary-table joins, and summary arithmetic, and includes the three result files
and exact sensitivity script under `results/clean-tuple/`. Strict ZIP checks and
restore accept either all four optional members or none, reject changed/missing
members or inconsistent provenance, and remain compatible with prior bundles
that omit this sensitivity. The source hash and table checks do not establish
scientific correctness; independently review the implementation and estimates.
This is a selected whole-capture comparison, not a way to subtract unrelated
packets, identify the intended flow, or remove selection or temporal bias.
The included script is a source record, not runnable from its ZIP location:
run the published toolkit copy, or place the exact script in the toolkit's
`clean-tuple-sensitivity/` subdirectory with the matching `aggregate.py` in
the parent directory. The quality JSON records both script hashes.

Compute `SUPPLIED_REPORT_SHA256` independently from the exact report file and
pass the lowercase hexadecimal value. The argument name identifies the report
intended for review; a matching hash **only binds its bytes**. It does not prove
that any person or agent reviewed the report, that the text is scientifically
correct, or that its claims are supported. The ZIP includes both the supplied
report and the report builder's canonical generated review draft for comparison.
Human or agent review remains necessary before publication.

The program refuses to overwrite an output, and checks the pinned manifest,
resources, aggregation, descriptive, figure, day-sensitivity, report-builder
and independent-verifier identities. It requires 120,000 manifest-matched
records, all six expected condition counts, zero database errors, no identity
defects, consistent result provenance and input hashes, complete tables, and a
matching `verified_full` census. The report builder independently rechecks
cohort counts, ratios, means, intervals and figure input provenance. The exporter
checks day-sensitivity subset counts and point summaries. It will reject
unreviewed metric schema changes or obvious personal filesystem paths in text.

The canonical row stream is rehashed in a consistent SQLite read transaction;
its hash must equal the primary `quality.json` snapshot hash. A temporary ZIP is
built, checked for CRC, member inventory and every member SHA-256, then copied
to a newly and exclusively created output and rehashed. Output is not an
instruction to publish: separately inspect its tables, figures, prose and
quality flags. Independently rerun the published statistical and plotting code
against the PCAP-derived data if deeper verification is required; the exporter
does not recompute bootstrap or plot content and no checksum proves authorship
or scientific validity.

## Contents and restoring the derived metrics

- `inputs/` has the exact final manifest and resource roster.
- `measurements/session-metrics.csv` is the readable per-session table.
- `measurements/session-metrics-canonical.jsonl` contains the exact ordered
  six-field rows hashed by the aggregator; its SHA-256 equals
  `metric_rows_content_sha256` in `results/aggregate/quality.json`. The sixth
  field is the original metric JSON **string**, preserving its bytes.
- `results/` includes primary, descriptive and exploratory day-cluster tables,
  quality/exclusion records and the independent full-census QA report. If
  supplied, `results/clean-tuple/` holds the clean-capture sensitivity and its
  exact analysis source.
- `figures/` contains the SVG/PDF figures and their input provenance.
- `report/` contains the supplied report and the builder's unmodified draft.
- `bundle-provenance.json` and `SHA256SUMS.txt` record code, input and member
  hashes. The checksum list covers every other archive member.

To reconstruct a **new** aggregation-compatible SQLite database from the
derived JSONL and readable CSV, without accessing PCAPs:

```sh
python3 restore_metrics.py --bundle FINAL_DERIVED_RESULTS.zip --output NEW_METRICS.sqlite3
```

The restore tool refuses to overwrite output, verifies ZIP CRC, strict member
inventory and hashes, the pinned handoff, full-census QA and final snapshot,
and checks every canonical row against its readable CSV row and final manifest.
It creates an empty extractor-error table, matching manifest/schema metadata,
and performs a SQLite integrity check. It does not recreate packet captures,
classifications or historical application data. A failed restore removes only
the new output file it created.

Checksums detect unintentional changes; an untrusted publisher could replace
both data and checksums. For independent evidence, re-extract measurements
from the final PCAPs using the [public PCAP toolkit](../README.md), compare
manifest and canonical snapshot hashes, and review any exclusions. IP-byte
volume includes observed protocol traffic and retransmissions; the trace span
is first-to-last observed packet, **not** application-completion latency.
Unpaired live captures, changing resources and collection times constrain
causal and cross-study interpretation.
