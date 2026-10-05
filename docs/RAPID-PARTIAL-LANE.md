# Individual traces from an incomplete serial lane

The additive reader [rapid_partial_lane.py](../tools/rapid_partial_lane.py)
creates a separately typed receipt. It preserves the original incomplete
experiment, all planned slots and durable failures. The existing lane-completion
and all-pass validators remain unchanged. The new receipt claims no lane pass
and zero aggregate formal credit.

The initial contract covers the registered V17 release, serial V6 formal lanes
with four local visits per workload. The original release must remain a complete,
clean paired Git checkout. Each accepted individual sample must retain its
original accepted and eligible state and pass the exact original deep verifier,
including full frozen inputs, body policy, traffic, scheduler, packet capture,
endpoint and durable-attempt checks. Logical visit offsets come from the actual
block; a block-two sample maps to visits 4–7.

Root must wait for terminal capture, a result seal, a terminal host-process
receipt and actual actor absence. A running, interrupted, unsealed, parallel or
chunk lane is refused by this version. Use fresh destinations outside the
original Source, study evidence and result directories.

```sh
python3 -I -B tools/rapid_partial_lane.py bind-source \
  --source-root ORIGINAL_RELEASE --lab-head ORIGINAL_LAB_HEAD \
  --native-head ORIGINAL_NATIVE_HEAD --output FRESH_SOURCE_BINDING
python3 -I -B tools/rapid_partial_lane.py declare \
  --source-binding FRESH_SOURCE_BINDING --spec ORIGINAL_CAPTURE_SPEC \
  --evidence-root ORIGINAL_STUDY_ROOT --intent ORIGINAL_INTENT \
  --result ORIGINAL_TERMINAL_RESULT --audit-root FRESH_AUDIT_DIRECTORY \
  --output FRESH_PARTIAL_RECEIPT
python3 -I -B tools/rapid_partial_lane.py verify \
  --receipt FRESH_PARTIAL_RECEIPT --audit-root ANOTHER_FRESH_AUDIT_DIRECTORY
```

Each declaration or verification records one isolated original verifier call.
Original bytes, full permission modes and observed directory membership are
freshly checked before success. Original Source, image, qualification group,
full resource graphs, client, traffic policy and capture limits retain their
measurement labels. No receipt or sample is rewritten or promoted.

Endpoint replay requires local TShark. The isolated reader permits only offline
packet reading and fresh derived scratch files; it refuses Docker, live capture,
network operations and writes to evidence. Root may execute this reader inside
the exact original immutable image with TShark, all original inputs mounted at
their same paths read only, and only the fresh receipt/audit destination writable.
The recorded interpreter and paths must remain the same for receipt verification.

A final corpus consumer and failed-slot recovery dispatcher must explicitly
recognize this new receipt type before using its individual samples. This reader
does not publish a final study, recover a lane or update a counter. Controlled
HOST fixtures exercise joins and isolation; they are not actual TAM proof.
