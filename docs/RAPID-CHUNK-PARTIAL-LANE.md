# Individual traces from an incomplete slot chunk

`tools/rapid_chunk_partial_lane.py` is a separate, create-only evidence reader.
It does not launch capture or pass an incomplete lane. The historical
`rapid_partial_lane` contract remains unchanged.

The new source binding accepts a clean paired Git release authenticated by an
actual installed canonical runtime, with all twelve installed operations and
original Native/client provenance reopened by the executing reader’s trusted current runtime validator. The
proposed measurement release cannot supply its own registration decision.
Release heads come from that authenticated runtime, without a new literal
commit registration for each publication. Full tracked bytes and permission
modes must equal the Git release and installed Source inventory. The executing
reader/delegate/chunk parser/util files are separately bound.

`declare` executes the original, unchanged isolated deep verification program.
That program authenticates the launch intent, lineage, exact current runtime,
full input graphs, caps, frozen configuration, qualification and readiness,
DNS proof, sealed result and each accepted trace's original independent deep
checks. The new wrapper requires a genuine registered `ChunkLane`, its exact
plan and slot policy observed by that proof. Counts are 1–16 and logical slots
are `slot_start + actual_local_visit` within 0–63. Recovery generations retain
the same logical slots. Failed and planned samples retain their original labels
and attempt history. Accepted raw artifacts are never repaired or rewritten.

`verify` uses a separate fresh audit namespace and executes the same original
deep program again. File bytes, full modes and observed directory membership
are freshly closed before publication and success. Child writes are allowed
only in its disjoint scratch directory for temporary derived endpoint replay.
Network, Docker, mutable Git, evidence writes and live packet capture are refused.

The initial role covers terminal **serial** run intents with actual host return
code 1 and no interruption. It does not coerce a historical four-visit lane into
a chunk or accept parallel worker retirements. Those need a separate explicit
consumer branch. There is no aggregate lane pass, automatic progress/corpus
credit, current qualification reuse, or physical chunk demonstration claim.

## Public operations

Use absolute paths and fresh audit/output names. The runtime JSON has exactly
`runtime_source_root`, `module_root`, `base_launcher`, `host_launcher`,
`source_manifest`, `client_binary`, and `collection_image_digest`.

```sh
python3 -B tools/rapid_chunk_partial_lane.py bind-source \
  --source-root "$measurement_release" \
  --canonical "$actual_canonical" --canonical-sha256 "$canonical_sha256" \
  --runtime "$runtime_roles_json" --runtime-sha256 "$runtime_roles_sha256" \
  --audit-root "$fresh_runtime_audit" --output "$fresh_source_binding"
python3 -B tools/rapid_chunk_partial_lane.py declare \
  --source-binding "$fresh_source_binding" --spec "$chunk_spec" \
  --evidence-root "$study_evidence" --intent "$terminal_intent" \
  --result "$sealed_incomplete_result" --audit-root "$fresh_declare_audit" \
  --output "$fresh_partial_receipt"
python3 -B tools/rapid_chunk_partial_lane.py verify \
  --receipt "$fresh_partial_receipt" --audit-root "$fresh_verify_audit"
```

TShark must be locally available in the isolated proof interpreter when an
original accepted trace requires offline endpoint replay. Root may execute the
reader in an authenticated image with network none, all original dependencies
read only, and only fresh proof/scratch outputs writable. No hidden diagnostic
bundle or author workspace is required by these entrypoints.

## Dynamic original four-visit role

The same installed-release Source registration also supports a **separate**
`original-serial-v6-four-visit-v1` artifact type. It requires the genuine legacy
formal V6 lane namespace, closed four-visit fields, exact original plan row and
the unchanged historical `accepted_subset` implementation. Logical visits stay
`(block - 1) * 4 + actual_local_visit`; recovery generation never changes these
slots. It does not claim a chunk policy or coerce four visits into chunk authority.
The public declare/verify commands choose the artifact from the original
authenticated lane. Old registered-86 receipts and their reader remain unchanged.
