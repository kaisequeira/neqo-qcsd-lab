# Result directory

New lab runs use only this layout:

```text
results/<campaign>/<run-id>/experiment.json
```

If present, the timestamp-named directories `20260719T141832Z` and
`20260731T140827Z` are preserved historical snapshots from the retired
workflows. They are not accepted by `run`, `resume`, `verify`, or `analyze`, and
no active code writes their `campaign.json`, `SHA256SUMS`, classifier, dataset,
split, projection, JSONL, or old metrics files.

When present locally, `LEGACY_RESULT_DELETION_MANIFEST.json` records the earlier
preservation decision. Keep or archive those snapshots only as historical
data; every new authoritative result is identified by `experiment.json` and
`evidence.sha256`.
