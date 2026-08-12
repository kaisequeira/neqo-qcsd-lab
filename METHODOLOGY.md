# Capture methodology

## Research question and unit of measurement

The lab measures how a client-side QCSD defence changes an encrypted QUIC
trace while preserving the requested application responses.

The units are intentionally small:

- a **workload** is one frozen graph of HTTPS requests;
- a **visit** is one configured execution of that graph;
- a **sample** is one visit under one defence;
- a **paired visit** is the set of samples with the same workload, request
  policy, and visit number.

Defences in a paired visit are separate live connections. They share frozen
inputs and deterministic seed derivation, but not transport state or network
noise. The undefended sample is the response and overhead baseline.

## Workload preparation

Preparation and measurement are different phases. Chromium observes candidate
page requests only during preparation. A human-provided origin allowlist
defines the permitted graph. Secret-bearing, unsafe, and unapproved requests
are excluded. Neqo then probes the retained graph and repeats undefended loads
to confirm status, delivered bytes, and body hashes before the manifest is
frozen. Every one of the three runs must also resolve the exact 1200-byte
UDP-payload ceiling and produce a valid runner packet ledger with incoming and
outgoing traffic. The absolute ceiling applies to the whole ledger, including
the QUIC handshake rather than only application or defence packets. Each run's
packet-ledger SHA-256, directional and total counts, maxima, and oversized
counts are sealed into the preparation receipt. Research validation rejects a
missing or malformed qualification receipt.

Each retained resource contains its concrete safe request headers and explicit
dependencies. The measurement runner receives those values directly. It does
not reinterpret a browser-header policy at runtime.

This design makes a one-resource fetch and a complex page graph the same kind
of input. The difference is only the content of `resources`:

- URL and origin;
- concrete request headers;
- dependencies that must complete first;
- expected preparation response identity and provenance.

The workspace-level `results.zip` (SHA-256
`103a82cb95eaa305e38b0084ba16744429b273146be80ab05c7653d52bf66b11`) is only a
catalogue of 17 browser-observed request graphs from the retired discovery workflow. A catalogue record becomes
a workload only after `prepare` passes and writes the consolidated manifest.
The earlier prepared manifests were retired from research use after discovery
was found to merge Chromium header names case-sensitively. The corrected
pipeline canonicalizes that merge and research validation rejects duplicate
header names. A subsequent generation was also retired because it predated
the receipt that qualifies the complete packet ledger, including handshake
traffic, against the absolute 1200-byte ceiling.

Fresh three-run preparation produced six unique request graphs in fixed order:
Bootstrap Home, Bootstrap Introduction, Apache Traffic Server documentation,
NGINX QUIC, Cloudflare QUIC, and nghttp2/ngtcp2. They span five distinct
origins. Every one of the 18 preparation runs was response-stable and recorded
zero UDP payloads above 1200 bytes. Behance was rejected at a whole-capture
maximum of 1452 bytes; Chromium project pages emitted a 1280-byte
pre-handshake Initial; aioquic refused the connection; Guardian reached 1280
bytes; R10 was response-unstable; and TeamViewer's retained assets did not
contain the source/final navigation root. NGINX QUIC and Bootstrap Introduction
passed the unchanged gate and completed the cohort.

The two Bootstrap workloads share an origin and many static dependencies.
They are distinct frozen request graphs, which is the lab's unit of
measurement, but the shared delivery path creates correlation that can reduce
their fitted distance or mould-padding cost. The cohort is therefore a
reproducible adaptation cohort, not six independent websites or a
representativeness claim.

The fitting and evaluation campaigns will reference the same six frozen
manifest definitions and hashes. They perform independent visits: fitting
captures are never reused as evaluation samples, and evaluation observations
cannot influence fitted parameters. The active specification has no
monitored/unmonitored roles, open-world view, dataset label, or split map.

## Ordering and concurrency

Campaign expansion is deterministic:

```text
workload -> request policy -> visit -> seeded defence order
```

The orchestrator executes one sample at a time. This prevents unrelated
samples from competing for the capture interface, CPU, or network path and
makes cooldown enforcement unambiguous.

Concurrency inside a sample is part of the workload realization. Neqo creates
one QUIC connection per distinct origin. Those connections progress in the
same event loop and can be active at the same time. Any request whose dependency
set is complete may also progress concurrently under `as-defined`.
`half-duplex` keeps the same graph and origins but withholds a new application
request while another application stream is in flight. Walkie-Talkie adds its
own defence-specific batch gates on top of that runner behavior.

Thus “multi-origin” does not mean several campaign samples or several PCAPs.
It means one sample whose single PCAP contains the exact union of multiple Neqo
connection tuples.

## Observer and capture boundary

Every defence uses the same observer: Ethernet capture on the collection
container's `eth0`. The retained measurement is `frame.len`, packet time, and
direction relative to Neqo's local endpoint tuple. The PCAP also contains the
ordinary encrypted-protocol and endpoint metadata visible at that boundary and
must be handled as research evidence rather than a sanitized release.

Capture follows one fixed sequence:

```text
dumpcap starts
  -> Neqo starts and establishes its origin connections
  -> application requests complete
  -> the defence tail completes
  -> the configured settle interval elapses
  -> dumpcap stops
  -> the PCAP is filtered to the exact Neqo endpoint tuples
```

The initial capture filter is bounded to UDP because the client port is not
known before Neqo runs. Filtering afterwards uses every local/remote endpoint
tuple recorded in `run.json`, in both directions. No qlog or application event
is used to trim the capture in time.

The collector also records and checks interface offloads. GRO, GSO, TSO, and
UDP segmentation offload can otherwise combine or split datagrams and corrupt
size evidence. Controlled test servers disable their corresponding virtual-
interface offloads. Neqo disables per-socket UDP GRO independently.

## Operational acceptance

An attempt is operationally acceptable only when all relevant checks pass:

- Neqo exits successfully and reports a complete response for every resource;
- the number of reported endpoints equals the number of workload origins;
- the direct PCAP is non-empty, untruncated Ethernet evidence;
- capture began before Neqo and remained active through the defence tail and
  settle interval;
- every retained packet belongs to a reported endpoint tuple;
- interface-offload evidence is valid before and after disablement;
- every observed UDP payload respects the selected profile's ceiling;
- Neqo's packet record reconciles with the direct PCAP under the bounded clock
  alignment;
- the runtime's bounded padding-event guard did not fire.

The reconciliation does not replace the independent observer. It establishes
that transport datagrams recorded by the runner correspond to direct captured
frames, with one uniform clock offset and at most the configured residual. A
clock discontinuity or unexplained datagram is a failed attempt, not something
silently corrected after collection.

After every defence in a paired visit has run, delivered response identity is
compared using resource ID, HTTP status, delivered byte count, body SHA-256,
and outcome. A defence sample with a different response is not eligible for a
paired comparison.

## Defence realization

Operational success proves that a valid page load was captured. It does not by
itself prove that a defence realized its intended schedule. The second gate
uses `schedule.csv` and defence diagnostics to check missed actions, target-size
realization, causal controller behavior, and defence-specific safety bounds.

The configuration layers differ because the algorithms require different
inputs:

- **Undefended** selects no defence.
- **FRONT** is an algorithmic, chaff-only stochastic schedule generated from
  the selected QCSD profile and sample seed.
- **Tamaraw** is an algorithmic bidirectional rate/padding schedule generated
  from the selected profile and seed.
- **Static** replays an explicitly supplied signed schedule file.
- **Traffic Morphing** needs a learned source-to-target size distribution.
- **WTF-PAD** needs learned timing/state histograms.
- **Walkie-Talkie** needs learned half-duplex burst moulds bound to workloads.

FRONT and Tamaraw therefore need configuration, but not fitted corpus files:
their runtime instructions follow directly from algorithm parameters. The
other three are data-driven; omitting their learned structures would change
the defence rather than merely simplify its interface. Static is simple at
runtime precisely because its schedule has already been materialized in an
external file.

This is also why source-code size is not a useful measure of conceptual
simplicity. A short generator can emit a long stochastic schedule, while a
data-driven defence needs additional schema validation, causal accounting,
provenance checks, and failure diagnostics even when the runtime rule sounds
simple. Walkie-Talkie is “static” only in the sense that the mould is chosen
before a defended load; generating and correctly realizing that workload-bound
mould still requires evidence not present in a few scalar profile values.

Traffic Morphing, WTF-PAD, and Walkie-Talkie in this fork are QCSD adaptations
over QUIC datagrams and client-side receive-credit behavior. They are not
byte-for-byte ports of their original Tor environments. Fidelity eligibility
means the declared QCSD adaptation was realized within its explicit bounds; it
does not claim deployment equivalence.

The profile names identify distinct evidence contracts:

- `live` is the bounded 1200-byte smoke profile;
- `research-1200` copies every tagged-source non-size default while changing
  only the common ceiling and all defence packet-size fields to 1200 bytes;
- `published` retains the tagged source's 1450-byte settings for compatibility
  checks, but does not turn a modern run into an exact reproduction of the
  paper experiment.

Static has no fitted model. The research mechanical control is four alternating
signed 1200-byte events at 25, 30, 35, and 40 ms. The 25 ms startup lead lets
the asynchronous client provision its chaff stream before the first exact
slot. The control checks CSV loading, direction, action realization, and
ceiling enforcement; it is not an effectiveness baseline inferred from
training data.

The primary QCSD reference is Smith et al.,
[“QCSD: A QUIC Client-Side Website-Fingerprinting Defence Framework”](https://www.usenix.org/system/files/sec22-smith.pdf).
Runtime adaptation details are documented with the
[Neqo research client](neqo-qcsd/README.md#qcsd-research-client).

## External parameter evidence

An external schedule or parameter file is an input, not a hidden second
workflow. Before execution the campaign loader resolves it relative to the
campaign, validates its schema and profile binding, verifies its provenance
receipt where required, and hashes it. The runner receives a frozen copy from
the result's `inputs/` directory, and its reported runtime identity is checked
against that copy.

The checked-in data-driven files are deliberately marked reviewed engineering
fixtures. They permit bounded smoke testing of plumbing and runtime
realization, but only a `purpose: smoke` campaign may use them. They are not
evidence that the algorithms have been fitted for a research result.

Research fitting accepts only a verified, complete `research-1200` result with
exactly six workloads, ten visits each, `as-defined` then `half-duplex`, and one
undefended mode: 120 eligible samples. `./qcsd-lab fit <fitting-result>` derives
Traffic Morphing matrices from the as-defined traces, WTF-PAD histograms from
the sealed timing corpus, and Walkie-Talkie moulds from half-duplex application
batch observations.

### Exact deterministic fitting methods

All three fitters read accepted `neqo/events.csv` typed observations and the
application-window bounds in `run.json`; they do not infer training packets
from PCAP or `packets.csv`. Production sequence numbers must form the unique
contiguous set starting at zero, and serialized observations must be ordered by
production nanoseconds with sequence as the same-tick tie-break. A fitting packet is a
`classified_datagram` whose serialized class is `natural`, whose size is at
most 1200 bytes, and whose production time lies in the inclusive interval from
defence start through application completion. `defense_cover` packets and the
post-completion tail are excluded, and every trace must contain Natural packets
in both directions. Half-duplex lifecycle extraction additionally requires the
unique causal `application_complete` marker that the runner records at or
immediately after the numeric completion instant; no observation may intervene between the
boundary and that closure marker, and later tail observations remain excluded.

- **Traffic Morphing:** as-defined Natural packet sizes are assigned to the
  fixed upper-edge buckets `64, 150, 300, 500, 700, 900, 1100, 1200` separately
  by workload and direction. For every directed non-self workload pair, a
  padding-only matrix is solved with HiGHS: first minimize L1 distance from the
  target distribution, then minimize expected added bytes while retaining the
  optimal L1 value. Equivalent solutions are made canonical by minimizing each
  row-major cell in order under the first two bounds. The final no-self
  permutation minimizes total bidirectional L1 cost, then estimated added
  bytes, then the lexical target-ID vector.
- **WTF-PAD:** all as-defined traces share one bandwidth threshold, calculated
  in nanoseconds as total Natural bytes multiplied by `1e9` and divided by the
  sum of each trace's first-to-last Natural-packet duration. Adjacent
  same-direction packet pairs use a two-packet instantaneous window; values at
  or above the threshold are intra-burst and lower values are between-burst.
  Delays are rounded up to microseconds. Normal and zero-location lognormal
  maximum-likelihood models compete by minimum KS statistic, with normal first
  on an exact tie. The declared `0.5` tuning quantile (the median)
  transformation applies only to the between-burst model; the intra-burst
  model is unchanged. The fitted 99.5th percentile bounds 19 strictly
  increasing exponential finite bins, plus the
  infinity bin. Exactly 10,000 finite tokens are apportioned by largest
  remainder with lower-bin index as the tie-break; infinity tokens use the
  recorded fake-burst-probability and mean-burst-length formulae.
- **Walkie-Talkie:** only half-duplex traces are used. Global application-batch
  markers and application-stream observations define direction transitions;
  retransmitted outgoing STREAM offset ranges are deduplicated, incoming
  positive `bytes_read` values are counted once as recorded, while valid
  zero-byte no-progress reads contribute no bytes or direction transition.
  Adjacent equal directions are coalesced, and byte totals are rounded up to
  1200-byte cells. The ten
  visits for a workload must have the same batch count and direction structure;
  their component-wise maximum is that workload's envelope. Duplicate visits
  or training-input hashes are rejected. The fitter evaluates every workload
  pair and performs a full-cohort minimum-weight perfect matching by mould
  padding cost, with the lexical pair vector resolving an exact tie; each
  selected mould is the component-wise maximum of its two envelopes.

These are deterministic, client-only QCSD adaptations, and every artifact says
`paper_equivalent: false`. Traffic Morphing cannot move mass to a smaller
bucket, WTF-PAD fits a finite parametric/token representation to this cohort,
and Walkie-Talkie uses client-visible HTTP/3 application-stream bytes and an
enforced half-duplex policy. They neither recreate the papers' original data
and endpoints nor establish defence effectiveness by themselves.

The command atomically creates one fixed four-file bundle under
`artifacts/research-1200/`: three runtime JSON files and one common
`provenance.json`. The receipt hashes all three files and binds the source
result seal, contributing samples, profile, ceiling, fitting decisions, and
workload coverage. Verification requires the exact file set and runtime
schemas. An identical rerun is idempotent; a different existing bundle is a
collision. Fitting does not mutate or reseal its source result.

This describes the implemented evidence boundary, not a completed experiment.
The six-workload cohort and fitting campaign are frozen, but no real
120-sample fitting result or fitted research bundle exists until the capture,
verification, and fitting commands succeed.

The operational order preserves that boundary. `./qcsd-lab test live` first
exercises all defended modes against controlled local HTTP/3 servers and is
the bounded pre-fit networking gate. The six-workload fitting campaign then
collects 120 undefended public-Internet samples; its verified result is fitted
and the four-file bundle is verified. Only then can the checked-in
`research-smoke-1200` campaign (seed `2026081204`) pass preflight. That smoke
uses Cloudflare QUIC and Apache Traffic Server documentation for one new
`as-defined` visit each under all seven modes, producing 14 independent
post-fit evaluation samples. It never reuses a fitting visit. Rehearsal and
final remain separate and explicitly on hold.

## Evidence, sealing, and recovery

`experiment.json` is the single state record. It binds:

- source commits, dirty patches, and collection-image identity;
- the hash of every frozen campaign, workload, and external parameter input;
- exact sample order, path, seed, state, and attempt count;
- structured failure and validation diagnostics;
- hashes of the five files in each accepted sample;
- terminal totals and pass status.

After a run becomes complete or incomplete, `evidence.sha256` exactly indexes
the authoritative files: `experiment.json`, `inputs/`, `samples/`, and
`failures/`. Verification rejects both unlisted additions and listed files that
are missing or changed. Sealing and verification also parse the frozen campaign
again and re-derive its identity, purpose, workload records, defence bindings,
limits, seeds, and ordered sample plan instead of treating duplicated fields in
`experiment.json` as authority. `derived/` is excluded because analysis must
remain deletable and reproducible.

During execution, state changes use atomic experiment checkpoints. A validated
successful attempt records its diagnostics and prospective hashes before an
atomic five-file directory promotion. If execution stops on either side of
that rename, resume validates and finishes the same promotion without another
network request. A sample becomes accepted only after the canonical files bind
to those hashes. Resume never recollects accepted samples and discards only a
genuinely partial, unpromoted attempt; completed failed attempts remain sealed
diagnostic evidence.

The configured `max_attempts` bounds automatic retries within one invocation.
Calling `resume` explicitly begins another retry epoch for incomplete samples;
it never reopens accepted samples. Previously attempted origins begin that new
epoch with a full cooldown, so restarting the process cannot bypass the timing
limit.

## Retroactive analysis

Analysis begins by verifying the evidence seal. It reconstructs the direct
packet trace from `capture.pcapng` and endpoint identity in `run.json`, reads
controller actions from `schedule.csv`, and generates a replacement
`derived/` tree outside the authoritative boundary before atomically swapping
it into place.

Per-sample metrics include direct Ethernet packet/byte totals, UDP payload and
application bytes, completion and trace duration, defence-tail cost, goodput,
schedule realization, and operational/fidelity diagnostics. Where an eligible
undefended baseline exists for the same workload, policy, and visit, analysis
also computes paired wire overhead and application delay.

The trace figure has two observed views:

1. deterministic incoming and outgoing packet-time density, with controller
   action density overlaid;
2. client-relative signed Ethernet `frame.len` scatter over time.

Outgoing sizes are positive and incoming sizes negative. A vertical marker
shows application completion; shading shows traffic after completion during
the defence tail. Each panel retains a local time range so a long tail does not
flatten a short trace. Packet density describes event timing, not bandwidth.

Only complete eligible paired visits receive comparison figures. Aggregate
plots and `summary.csv` still expose the available accepted evidence and make
incomplete or ineligible groups visible in the report. SVG generation is
deterministic, and the report embeds those SVGs so it is self-contained.

## Scope and limitations

- Internet responses and path conditions can vary between separately captured
  defences; response equality rejects content drift but cannot remove all
  timing noise.
- The observer is the collection-container boundary, not an arbitrary remote
  network vantage point.
- A direct PCAP contains endpoint and encrypted-protocol metadata and is not a
  ready-made public release.
- Controlled local smoke fixtures validate mechanics before fitting; the
  checked-in external smoke instead requires the sealed fitted bundle and
  evaluates independent post-fit visits.
- The final 126-sample capture is explicitly on hold. It must follow a sealed
  120-sample fitting result, fitted-bundle verification, and the independent
  42-sample pre-final rehearsal.
