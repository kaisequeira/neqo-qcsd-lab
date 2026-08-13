# Research defense artifacts

`./qcsd-lab fit <sealed-fitting-result>` creates one fixed, create-only runtime
bundle at `artifacts/research-1200/` containing exactly:

- `traffic-morphing.json`
- `wtf-pad.json`
- `walkie-talkie.json`
- `provenance.json`

Generated bundle contents are intentionally ignored by Git and excluded from
the Docker build context.

The current fitting contract is version 6. It binds Traffic Morphing schema 2,
Walkie-Talkie schema 6, and WTF-PAD schema 2. The Walkie-Talkie numeric
profiles, pairing, moulds, and costs remain byte-for-byte equivalent to the
sealed schema-5 profiles; schema 6 adds per-workload raw-hash bindings for the
standalone prefix specification, immutable chaff-qualification sidecar, and
derived qualified chaff manifest. Qualification evidence is explicitly
runtime-only and excluded from the fitting corpus.

Each sidecar derives one compact, dependency-free navigation root using only
the exact existing `Accept`, `Accept-Encoding`, and `Accept-Language` values in
their original order. Three independent unshaped five-way HTTP/3 runs derive
its stable status, normalized content encoding, body length, body hash, and
production request-stream size. Three independent production prefix-pack runs
then prove the first 1200-byte cell can carry the full application request and
the required continuation-horizon-plus-one compact chaff requests through FIN,
with the required chaff requests peer-acknowledged and no targetless STREAM
bytes. The post-target completion predicate still gates required request,
HTTP/3-control, and QPACK-encoder output; it records and excludes only
post-warmup client QPACK-decoder stream output because that fixed critical-
stream role is outside request-prefix causality. Runtime complete responses
must match the qualified identity; contradictions fail closed.

The bundle that occupied the canonical directory before schema 6 is archived
at `artifacts/research-1200-superseded-schema5-0a141768/`. This frozen
contract-5/Walkie-Talkie-schema-5 artifact remains readable for verification of
preserved contract-5 results but is forbidden for new run, resume, fitting
publication, or current campaign preflight. Ignored temporary candidate
directories are not archives.

At this source-tree stage the six prefix specifications are published in the
clean qualification source state. The qualification sidecars and authoritative
schema-6 bundle have not yet been published. The required order is: verify the
explicit schema-5 archive, derive the exact-six prefix specs from that immutable
numeric artifact, commit/build the clean qualification image, run the atomic
exact-six qualification, then generate and verify schema 6 from the unchanged
sealed fitting result.
