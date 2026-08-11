# Result directory

Every new lab run uses one authoritative format:

```text
results/<campaign>/<run-id>/
  experiment.json
  evidence.sha256
  inputs/
  samples/
    <workload>/<policy>/visit-000/<defence>/
      capture.pcapng
      neqo/
        run.json
        packets.csv
        events.csv
        schedule.csv
  failures/
  derived/
    summary.csv
    plots/
    report.html
```

`experiment.json` is the only state and diagnostic record.
`evidence.sha256` seals `experiment.json`, frozen `inputs/`, accepted
`samples/`, and retained `failures/`. `derived/` is deliberately unsealed and
can be deleted and reconstructed with `analyze`.

The timestamp directories `20260719T141832Z` and `20260731T140827Z`, when
present, are historical snapshots from retired writers. They are not accepted
by `run`, `resume`, `verify`, or `analyze`, and no active code writes their
`campaign.json`, `SHA256SUMS`, classifier, dataset, split, projection, JSONL,
fidelity sidecar, qlog, PDF, resolved-workload copy, or old metrics formats.

`LEGACY_RESULT_DELETION_MANIFEST.json`, when present, records the earlier
historical-preservation decision. It is not part of the active result schema.

The workspace-level `../../results.zip` is also historical, but it is not an
experiment result at all. It is a catalogue of browser-observed request graphs
used to choose candidates for `prepare`. Only a successfully prepared
`config/workloads/<id>.json` may enter a campaign.

Fitted runtime files live separately under `artifacts/research-1200/`. That
four-file bundle is verified through its common `provenance.json`; it is not a
result directory and does not receive an `evidence.sha256`.
