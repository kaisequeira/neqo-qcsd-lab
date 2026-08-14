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
Walkie-Talkie schema 6, and WTF-PAD schema 2. Walkie-Talkie's raw source
envelopes, base symmetric moulds, and pair assignment remain rooted in the
sealed schema-5 numeric evidence. The runtime mould is intentionally different:
it adds one full sender-framing cell to each positive outgoing component and
one receiver-continuation cell to each positive incoming component. Schema 6
also binds each workload's schema-2 prefix specification, immutable schema-2
qualification sidecar, derived qualified chaff manifest, and the sealed q7
runtime-falsification diagnostic. Qualification and diagnostic bytes are
runtime-only and excluded from the fitting corpus.

Each sidecar binds a frozen navigation root and a selected known-valid
same-origin source resource; its derived chaff projection is dependency-free
and preserves the exact existing `Accept`, `Accept-Encoding`, and
`Accept-Language` values in their original order. Three independent unshaped
HTTP/3 runs use `max(5, required_chaff_streams)` parallel requests to derive
stable status, normalized content encoding, body length, body hash, and
production request-stream size. Three independent production prefix-pack runs
then prove every moulded component's exact sender-framed targets, cumulative
application and one-shot chaff requests through FIN, peer acknowledgement of
every required chaff-request STREAM range and FIN, and zero targetless STREAM
bytes. Every activation stage gates pending request-causal HTTP/3 control and
QPACK encoder output; post-warmup client QPACK decoder output is recorded and
excluded. Runtime complete responses must match the qualified identity;
contradictions fail closed.

The bundle that occupied the canonical directory before schema 6 is archived
at `artifacts/research-1200-superseded-schema5-0a141768/`. This frozen
contract-5/Walkie-Talkie-schema-5 artifact remains readable for verification of
preserved contract-5 results but is forbidden for new run, resume, fitting
publication, or current campaign preflight. Ignored temporary candidate
directories are not archives.

The six v2 prefix specifications and six v2 qualification sidecars are
published. The ignored, create-only canonical schema-6 bundle was regenerated
from the unchanged sealed fitting result and verifies with these raw SHA-256
values:

- `provenance.json`: `38303c58933d60f9cdb37ced51d9bfab4f3553aaad1680c3f042d9c61ce73a61`
- `traffic-morphing.json`: `ad278bd31428419b6d402aa30fab041005ada8b48f8d07a6a1641635c90d935c`
- `walkie-talkie.json`: `5e0084cdb0ed8f7c0a56d18442d971ce79042f3ab4a2630c341548e21ae97b97`
- `wtf-pad.json`: `59433577582f8ee89c39aa7649d96d1fd83d13abe6891a0046827f6a055f3dd6`

Unversioned or v1 qualification inputs are historical only and are rejected by
the current schema-6 preflight. The v2 receipts bind the locally preserved,
manifest-sealed q7 diagnostic, but its bytes are not positive qualification or
fitting input.
