# PCAP-overhead results figures

This utility creates two publication-oriented figures from the verified output
of the [final-PCAP aggregation toolkit](https://github.com/kaisequeira/neqo-qcsd-lab/tree/ad08e42c5bf591ea8d3f6ad5e831912a54cfe08a/tools/pcap-overhead).
It does not read captures, historical runtime metadata, classification results,
or the optional MAL timing map. It does not change the inputs.

## Requirements and invocation

Use Python 3.9 or later and install the tested plotting dependencies in an
isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v test_plot_results
python plot_results.py --results AGGREGATION_OUTPUT --output FIGURE_OUTPUT
```

`AGGREGATION_OUTPUT` must be a completed run of `aggregate.py` containing
`quality.json`, `overall-overheads.csv`, and `domain-overheads.csv`.
`FIGURE_OUTPUT` must be new or empty. For each of two figures, the script writes
PDF, SVG and PNG versions plus `figure-provenance.json` containing input SHA-256s,
script SHA-256, package versions, the source manifest SHA-256 and row counts.
Rendered PDF/SVG bytes may differ across environments or export times even when
the underlying numerical inputs and estimates are identical.

Default safeguards require: complete status; 120,000 accepted manifest rows;
zero extraction errors and identity flags; all five defenses for both metrics;
the same 50 resource domains in each comparison; 400 expected baseline and 400
expected defended sessions per domain; internally consistent domain and summary
means; finite ordered intervals; and valid nonzero cohort sample counts. The
actual per-metric sample counts and excluded counts are printed on the summary
figure. A metric may have exclusions while the hash-verified capture census is
complete; consult the source `cohort-exclusions.csv` and quality report.

For synthetic tests only, `--synthetic-fixture` permits a reduced non-study
input and marks **every** figure with a synthetic-data watermark. The
`--allow-incomplete` option additionally permits provisional-status input but
never removes the 120,000-row/50-domain gate for real study input; a provisional
plot is watermarked. The test suite constructs fabricated values in temporary
directories. No synthetic figure is a study result.

## Reading the figures

`01-overall-overheads` plots two distinct estimands for each defense and each
metric: the equally weighted mean of domain-level overhead percentages, and the
ratio of the sums of per-domain defended and baseline cohort means. Whiskers are
the 95% **within-cohort session-bootstrap** intervals for the fixed observed
domains; they are not intervals over a population of websites or a causal
guarantee. Labels give both estimates, valid defended/baseline sample totals and
the corresponding excluded sample totals. The estimates are based on independent
cohorts, not pairing sessions with the same filename.

`02-domain-spread` shows each domain's ratio of defended and undefended cohort
means, its median, and its 5th–95th percentile interval over the **observed
domain values**. That interval describes dispersion and is not a confidence
interval. Points are deterministically jittered for legibility.

IP bytes sum observed IP datagram lengths and include captured protocol traffic
and retransmissions. They are not PCAP-container file sizes or application
payload bytes. The timing metric is the first-to-last **observed packet-trace
span**. Padding, ACKs, setup or teardown can extend it, and it is not measured
application completion or page-load latency. Results describe this resource-host
dataset; live content changes, noncontemporaneous conditions, selected capture
successes, capture-point limitations and configuration differences prevent an
unqualified causal claim. Neither a low overhead nor a defense label establishes
privacy effectiveness; classification is separate future work.

Each panel uses its own x-axis. For an absolute observed range above 1,000%, the
axis uses a symmetric logarithmic transform, linear within ±100% and logarithmic
outside; it is explicitly labelled and retains negative values. Exact values are
printed on the summary plot. Percentages can be large when the undefended mean
is very small; inspect the underlying per-domain table and absolute seconds/bytes
before drawing conclusions. No bars or intervals are clipped by design.
