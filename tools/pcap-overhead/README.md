# Six-defense traffic measurement: reproducible extractor

The extractor reads the final handoff `session-manifest.csv` and measures each
selected standalone PCAP/PCAPNG. It hashes the exact input stream and accepts
results only when its SHA-256 and size match the manifest and both Wireshark
tools parse it successfully. It keeps compact metrics in a SQLite database;
it does not write packet captures or modify the data source.

## Files and code identity

* `extract_metrics.py` is the portable version with configurable tool and input
  paths. It enforces the study's Wireshark 4.4.20 unless explicitly overridden,
  records tool versions, manifest hash and its own SHA-256 in the database,
  and uses the same v2 metric definitions as the study run.
* `test_extract_metrics.py` constructs synthetic captures to check IPv4, IPv6,
  IPv6 extension headers, fragmentation, PCAPNG multiple interfaces, single and
  ambiguous UDP tuples, truncation, malformed lengths, non-IP frames, nested
  IP, oversized tool stderr, and timeouts. It does not contact Drive.
* The exact historical study-run script is preserved in the [private research
  evidence package](https://drive.google.com/file/d/1jSGmRL1bBXW50RD0ZNY22Ssjud9qltKm/view) with SHA-256
  `f683d084cbd9530cf2d0453e65ecd1d949bfe9418b09eb86871961efcfa26f7e`.
  Use the portable `extract_metrics.py` for a new run.

The final handoff manifest is the `session-manifest.csv` at the root of the
[six-defense dataset](https://drive.google.com/drive/folders/1mE0wM6ZJ7AoJli-9d0ckRnShO2bWVdNQ).
The manifest used in the study run has SHA-256
`ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf`.
Check the manifest checksum before analysing. The extractor also records it and
rejects an incompatible manifest when resuming.

## Requirements and running

Use Python 3.9 or later on a Unix-like system and Wireshark 4.4.20's `capinfos`
and `tshark`, both on `PATH`. No Python packages are needed. Place the capture
files under `<capture-root>/<defense>/<domain>/<filename>` matching the
manifest, then:

```sh
python3 test_extract_metrics.py
python3 extract_metrics.py --manifest session-manifest.csv --db metrics.sqlite3 \
  --baseline CAPTURE_ROOT --workers 12 --timeout 120 --retries 2
```

If the captures are in Drive rather than on local storage, a separately
authenticated, loopback-only HTTP reader can serve the same folder layout. For
example, after configuring a suitable rclone remote, run in a separate process:

```sh
rclone serve http STUDY_REMOTE: --drive-root-folder-id FINAL_HANDOFF_FOLDER_ID \
  --addr 127.0.0.1:48239 --dir-cache-time 30m
```

Then use `--base-url http://127.0.0.1:48239` in place of `--baseline`, or supply
both to use local files where present and stream the rest. The portable
extractor accepts only loopback HTTP; rclone authentication and any credentials
must remain outside the dataset and results. No particular remote configuration
or machine path is assumed. `--capinfos` and `--tshark` select non-PATH tools.

The default job cycles through domains and defenses in blocks of 20 sessions.
Results are checkpointed in SQLite after each block of at most eight tasks per
worker; a database lock prevents two writers. Repeat the same command to skip
verified rows and retry errors. `--defense` and `--domain` restrict a run;
`--limit` is for labelled pilots. Per-file deadlines kill stuck parser process
groups, stderr is drained and capped, transient errors are retried, and the
run stops at `--max-errors` for inspection. Watch printed progress and the
`errors` table. Completion means **120,000 verified sessions**, not merely that
the process exited; inspect errors and counts per cohort.

## Meaning and quality controls

`ip_bytes` is the sum of all observed IP datagram lengths: the IPv4 total-length
field or IPv6 payload length plus the 40-byte base header. IPv6 extensions,
fragment datagrams and retransmissions count as observed. These totals cover
all captured IP traffic, not a proven application-only tuple. Where any frame
is truncated, non-IP, nested IP, malformed, IPv6 zero-payload, or lacks an
identifiable Ethernet header, `ip_valid` is false. Frame-level packet count,
capture-reported original frame lengths (`packet_bytes`) and min-to-max timestamp span remain
available for such hash-verified captures. The reported original frame length can
exceed the actually captured length in truncated records; the frame-byte analysis
excludes truncated or unknown-truncation captures. The code cross-checks packet count
and frame bytes independently between capinfos and tshark.

The optional `udp443_*` measures are reported only when exactly one observed
UDP five-tuple has one port 443 endpoint and traffic appears in both directions.
They describe that observed tuple, not proof that the peer is the intended
resource host; other captured IP bytes are recorded separately. Ambiguous
tuples are flagged and receive no directional total. Direction is not inferred
from packet order. `span_seconds` is the earliest-to-latest observed packet
timestamp, including padding and teardown, and is **not application completion
or browser page-load time**. `capture_bytes` is the size of the PCAP container,
not network traffic volume. Capture-point details, live-resource changes,
retransmissions, packet drops and time-of-day effects constrain interpretation.
No classification, defense-fidelity or causal-effect result follows from these
measurements alone.

---

## Statistical aggregation

This analysis consumes the packet extractor's **hash-checked per-capture**
SQLite records; it does not read, modify or copy the packet dataset. The final
study comparisons are descriptive of 50 resource-host classes and their
selected HTTP/3 sessions. They are not full page-load tests and do not establish
defense security, fidelity, usability or reliability by themselves.

## Inputs

- The final handoff `session-manifest.csv`, with 120,000 distinct
  `(defense,domain,session)` rows, file IDs, sizes and SHA-256 hashes.
- The extractor SQLite database, `metrics(defense, domain, session,
  drive_file_id, sha256, result_json)` with a unique key and an `errors`
  table. Each accepted JSON row must have `status=ok`, matching ID, hash and
  capture-file size. Its bytes must have been independently hashed while read.
- Optional: the final MAL BuFLO timing map, cross-checked against manifest Drive IDs. It is a supplemental source of configuration labels only; the main PCAP metrics and results do not require or consume it.

`ip_bytes` sums IP datagram lengths for all IP traffic visible at the capture
point. It includes observed retransmissions and fragments; it does not by itself
prove that every packet belongs to the desired QUIC flow or represents useful
application bytes. It excludes link-layer and physical-layer overhead. IP rows
are used only when extractor `ip_valid` is true, after its protocol/truncation
checks. `packet_bytes` is the sum of capture-reported original **frame** lengths, not the PCAP container size. A record's original frame length can exceed its actually captured length. Frame sensitivity comparisons exclude truncated or unknown-truncation captures and require matching, unambiguous encapsulation.

`observed_span` is the last observed packet time minus the first observed packet
time for the capture. It can include setup, padding tail, retransmission and
teardown, and is **not** user-visible load time, a browser page-load time, or
the last-real-packet definition used by some published defenses. Span analysis
here excludes rows without verified ascending capture timestamps. The same final-PCAP span measure is used for every defense and the baseline.

## Estimands and uncertainty

For each defense and domain, estimate `100 × (mean(defended) /
mean(undefended) - 1)`. Independently resample sessions within each
defense/domain for 95% percentile bootstrap intervals. Equal session numbers
do not identify a paired experiment: no row-by-row pairing is used. The macro
summary is the arithmetic mean of the domain percentages; the pooled summary is
`100 × (sum(domain defended means) / sum(domain baseline means) - 1)` and weights
domains by their baseline volume/time. Pooled cohort **means**, rather than raw
sums, avoid changing domain weights merely because exclusions differ. Report
these distinct estimands and absolute differences along with 5th/50th/95th
percentiles across domains.

The session-bootstrap intervals condition on the observed fixed domains. A
separate interval additionally resamples domains; it is relevant only under a
superpopulation interpretation of these domains and does not prove
representativeness. Neither interval eliminates workload differences, temporal
drift, response variation, dependence between captures, system load or
success-selection bias. When the optional supplemental timing map is supplied, the MAL 5 ms/20 ms estimates are separate strata of one domain, each compared with the same domain's undefended cohort. Their observations are not paired by session number. These subgroup labels are not derived from PCAPs and are not required for core results.

## Run

Requires Python 3.11+ and NumPy 2.3.5. NumPy 2.3.5 was used for this development;
store exact Python and NumPy versions, the bootstrap seed and the input hashes
with any published result. With portable input filenames in the current working
directory:

```sh
python aggregate.py --manifest session-manifest.csv \
  --database metrics.sqlite3 \
  --output results-20261125 --seed 20261125 --bootstrap 2000
python -m unittest -v test_aggregate
```

The output directory must be new or empty to prevent stale output surviving a
rerun. The code reads the database in a single SQLite read transaction and
records a deterministic SHA-256 over its sorted raw metric rows, plus the input
manifest/script hashes, the optional timing-map hash and software versions. `quality.json` records
the observed census, extractor errors and protocol flags;
`cohort-exclusions.csv` gives reasons and counts by metric and domain. Output
`domain-overheads.csv`, `overall-overheads.csv` and `mal-buflo-variants.csv`
are emitted only where relevant valid cohorts exist.

Results are **provisional** until all manifest sessions are present and identity
checks and extraction errors are resolved. By default, overall summaries are
withheld if a defense lacks a valid comparison for any of the expected 50
domains. `--allow-incomplete` emits a clearly marked interim summary over
available *complete cohorts*; it is not a 50-domain result. Metric-invalid
observations are excluded and reported, not set to zero. A cohort with zero
valid observations, zero baseline mean, an unresolved identity, or incompatible
frame encapsulation cannot produce a valid percentage. Never drop a slow or
large observation merely for being an outlier.

The literature basis and interpretation boundaries are in the study's
[defense-overhead methodology and practicality reference](https://drive.google.com/file/d/1J_WjNax8tIs57md4HN8bFKD32C8V2sg4/view).


For supplemental MAL configuration strata only, add `--mal-timing mal-buflo-timing-map.csv` and use a new output directory. The main estimates and bootstrap intervals remain exactly unchanged when these labels are provided.

The extractor needs Python 3.9+ and Wireshark as above; the statistical aggregator requires Python 3.11+ and NumPy 2.3.5 (`python -m pip install -r requirements.txt`).
