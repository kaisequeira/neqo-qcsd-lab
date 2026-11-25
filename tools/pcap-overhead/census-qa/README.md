# Read-only PCAP measurement census consistency verifier

This standard-library Python 3.9+ tool independently checks the recorded
per-session measurements against the published six-condition session manifest.
It does **not** re-read packet captures, re-compute packet bytes, establish
scientific eligibility, or calculate defense overhead. Packet-level extraction
and independently spot-checking PCAP parsers remain separate checks.

```sh
python -m unittest -v test_verify_metrics
python verify_metrics.py --manifest session-manifest.csv --database metrics.sqlite3 \
  --output new-census-quality.json
```

The input manifest must match the final handoff SHA-256
`ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf`
and contain six conditions × 50 domains × sessions 1–400, with unique file
IDs. The SQLite input is opened read-only inside a consistent transaction and
must bind to that manifest and the `2026-11-25-ip-frame-direction-v2` metrics
schema. The output is created exclusively: an existing report is not replaced.

It checks session identity, PCAP SHA and size against the manifest; JSON and
database identity consistency; capture counts and nonnegative byte metrics;
IP-valid claims against stored parser flags; UDP/443 directional byte
accounting; and first/last epochs against recorded span using decimal arithmetic
to one nanosecond. It enumerates quality flags and formats per condition. Its
canonical metric-row snapshot hash follows the public aggregator's exact
ordered-JSON-lines convention, allowing comparison to `quality.json` once
aggregation has completed. Epoch decimal digits in the report describe
**displayed digits**, not proof of the interface clock resolution or accuracy.

`verified_full` means every manifest identity was present, the recorded fields
were internally consistent, and the extractor error table was empty at that
snapshot. `verified_partial` means the running dataset was incomplete or had
recorded extractor errors. `verification_failed` means an identity or internal
structural inconsistency was found. Quality flags (such as a truncated or
non-IP capture) are reported for exclusion analysis and do not alone imply an
identity verification failure. None of these statuses means all PCAPs have been
independently downloaded and hashed again by this tool.
