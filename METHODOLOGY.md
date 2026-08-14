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

Fitting used all six frozen manifest definitions; the post-fit smoke selected
two members of that cohort. For those shared workloads the visits were
independent: fitting captures were never reused as evaluation samples, and
evaluation observations did not influence fitted parameters. The capture
specification has no monitored/unmonitored roles or open-world view. The later
POC5 contract labels five approved origin hostnames, each bound to one frozen
workload graph, and evaluates only an undefended-trained five-class
closed-world classifier against undefended, FRONT, and Tamaraw traffic. It is
not a website-population or adaptive-attacker study.

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
  padding cost, with the lexical pair vector resolving an exact tie. That
  pairing objective is the base symmetric mould: the component-wise maximum of
  the two observed envelopes. The runtime mould then adds one 1200-byte
  sender-framing cell to every positive outgoing component and one 1200-byte
  receiver-continuation cell to every positive incoming component. The sender
  cell reserves space for QUIC/HTTP/3 STREAM framing and mandatory control
  overhead absent from request-stream offsets. The receiver cell provides one
  cell beyond the incoming envelope and is a held causal event, not eager
  ordinary receive credit. The raw source envelopes and base pairing objective
  remain unchanged, but the adapted runtime mould and cost do not equal the
  historical schema-5 values.

  Before the first due moulded outgoing actions, the client provisions the
  exact workload-specific one-shot chaff cohort and never replenishes it. A
  response stream is eligible only when its request used a
  zero-required-insert-count, nonblocking QPACK header block and the peer
  acknowledged a positive final size, every unique request-stream offset in
  `[0, final-size)`, and FIN. Retransmitted offsets and acknowledgements are
  union-deduplicated. Before the first incoming base allocation, a latched gate
  requires a peer-acknowledged nonblocking survivor count of at least the total
  number of remaining receiver continuations plus one. Deterministic pristine
  reserves cover all remaining nonzero incoming components and stay reserved
  across later positive outgoing components until their corresponding
  continuation is allocated.

  Fitting traces do not expose HTTP/3/QPACK request-prefix lengths or transport
  STREAM-frame budgets. Each schema-6 workload binding therefore requires
  three independent schema-2 production prefix-pack transcripts. Every
  component is represented by exact full sender-framed packet targets; the
  transcripts prove cumulative application requests through FIN, the
  nondecreasing one-shot chaff cohort through FIN, peer acknowledgement of every
  required chaff-request STREAM range and FIN, and zero targetless STREAM bytes.
  Their stateful every-component capacity recurrence binds exact prepared
  application bodies and the selected qualified response body. Qualification
  bytes are excluded from fitting.

  The prefix transcript starts only after a broad HTTP/3/QPACK warmup drain.
  At every activation stage its completion gate rejects pending application,
  required-chaff, request-causal HTTP/3-control, or QPACK-encoder output. It
  separately records and excludes only post-warmup client QPACK-decoder stream
  output; this fixed critical-stream role is outside request-prefix causality.

  Each reserve is excluded from ordinary base allocation, and its exact
  capacity is subtracted from ordinary base capacity availability, until its
  corresponding continuation is released or the session or endpoint ends.
  Loss of a required survivor after the initial request batch holds allocation
  while the horizon is deterministically reconstituted from an eligible
  peer-acknowledged pristine member of the already provisioned cohort. It fails
  closed only if no eligible replacement remains; no new request replenishes
  the one-shot cohort. Allocation to an active application stream or
  fragmentation across streams is forbidden.

  The initial priority-aware selector binds a known-valid same-origin selected
  source resource; its derived chaff projection is dependency-free and has at
  least one cell of exact qualified capacity. The Lab binds the prepared
  manifest and workload hash before execution. Same-origin eligibility is
  ultimately endpoint-relative, so the runtime revalidates it after connection
  readiness. If too few acknowledged survivors remain after the outgoing
  targets resolve, base and continuation allocation remain held; no targetless
  request retransmission or generic post-loss liveness guarantee is claimed.

  A continuation becomes eligible after issued base events have been
  controller-requested, their request signals observed, and any application
  batch gate has opened. Release normally follows issuance of all base events.
  A real reported ordinary nonreserved-capacity snapshot below one cell,
  including zero, permits early issuance; unknown capacity does not. Allocation
  then follows the coalesced-tail-or-oldest-reserve rules below, while the
  corresponding oldest reserve is discharged exactly once. The initial
  survivor gate still precedes both early continuation and base allocation.

  Every retry recomputes live unconsumed base debt. If one peer-acknowledged
  nonreserved header-phase chaff stream carries a positive debt at or below the
  parser ceiling, an advertised tail is extended in place. If that exact tail
  is awaiting its `MAX_STREAM_DATA` advertisement, the continuation and reserve
  are retained until the advertisement is observed. Otherwise the whole cell
  uses the oldest pristine reserve regardless of unrelated live debt. Split or
  ledger-inconsistent tails are ineligible, and the corresponding reserve is
  removed exactly once. A retryable unadvertised rollback or requeue restores
  the corresponding all-future reserve before further base allocation.

  Ordinary base receive allocation exhausts application streams before
  peer-acknowledged nonreserved controlled chaff streams; exact capacity
  precedes bounded provisional framing claims. Candidate streams must remain in
  `ReceivingHeaders`, have no consumed, terminal, framing, parser-lease, or
  parser-boundary state, retain wholly available reservation, and have one
  exact cell after requested bytes. Pending coalescence additionally requires
  requested-minus-advertised bytes to equal the pending base controller credit.

  A separate bounded bootstrap covers a transport stall before HTTP/3 can
  parse an atomic HEADERS frame. The controller retains an exact
  `STREAM_DATA_BLOCKED` report only for a pristine, wholly pre-header stream.
  Once its prepared body floor and requested, advertised, and known limits
  agree below the fixed absolute 1,000-byte framing target, the controller may
  lease the remaining prefix toward that target, subject to the existing
  lifetime `max_stream_data_excess` budget. This lease is unowned and
  slotless: grant or advertisement cannot satisfy scheduled incoming debt, and
  any typed progress invalidates the retained transport proof. It changes no
  defence parameter, schedule, slot-accounting rule, or acceptance threshold.

  Three independent compact response qualifications use
  `max(5, required_chaff_streams)` parallel requests to derive stable full-body
  identity and length. Three independent every-component prefix-pack
  qualifications establish outgoing request/control fit and peer
  acknowledgement of every required chaff-request STREAM range and FIN. Parser
  consumability and source-envelope bounds remain runtime fail-closed. Neither
  evidence layer enters the numeric fit or proves a general HTTP/3 property.
  Receipts record both the base pairing cost and the adapted runtime padding
  cost; scheduled bytes include sender-framing and receiver-continuation cells.

  FRONT has a separate terminal incoming-slot liveness rule. For `ChaffOnly`
  schedules whose incoming side is proven complete, the last untouched whole
  slot prefers a peer-acknowledged pristine chaff stream with at least one cell
  of exact capacity. This avoids stranding a sub-header residual on a new
  response and changes no capture-clock acceptance rule.

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

The six-workload cohort and fitting campaign are frozen. The sealed fitting
result at `results/research-fitting-1200/20260812T130241.322364Z` contains all
120 accepted, eligible samples. The verified schema-5 historical bundle is
archived read-only at
`artifacts/research-1200-superseded-schema5-0a141768/` and is not accepted by a
current campaign. The canonical schema-6 bundle was generated only after the
standalone specs and exact-six qualifications had been published. That
boundary is now complete: the v2 specifications and sidecars are published,
and the regenerated schema-6 four-file bundle verifies against the sealed
fitting result.

The operational order preserved that boundary. `./qcsd-lab test live` checked
the sealed baseline path and a direct, nonauthoritative schema-6 A/R/C wire path
against controlled local HTTP/3 servers. The six-workload fitting campaign
collected 120 eligible undefended public-Internet samples. The checked-in
`research-smoke-1200` campaign (seed `2026081204`) then used Cloudflare QUIC and
Bootstrap Introduction for one new `as-defined` visit each under all seven
modes. The independent result
`results/research-smoke-1200/20260814T023209.708923Z` is verified and analyzed:
14/14 samples were accepted and eligible on their first attempt, with zero
failures. Its evidence-index and experiment-file SHA-256 values are
`59371aedf7dfa7ce289cce25766af763ede405d2f62527dc16c0d7882b42203a`
and `1cd8c415751736aa43677fac67f1bea666b941a47ae90d3658bf7cb2bf17d248`.

The prior runtime failures remain qualification-excluded diagnostic evidence
at
`results/chaff-qualification-diagnostics/q7-b19cb04-7ebcdb0-schema6-203eee42-runtime-falsification/`.
Its closed outer manifest hashes to
`4ee68a930a344dc0e5874279e09069f92935a2f4f42bc7bb7e88077153b85aa9`.
POC5 is separate from the historical pre-final engineering gate. Its own
30-sample rehearsal and twenty formal campaign definitions are frozen. Its
latest rehearsal is retained as excluded diagnostic evidence, while all twenty
formal campaigns remain unexecuted; the historical 42/126 sequence remains
undefined and on hold.

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

## Classifier proof-of-concept projection and handoff

The authorized POC5 corpus is a five-class closed-world domain-shift study, not
an open-world or adaptive-attacker efficacy corpus. Its five class labels are
the approved origin hostnames `getbootstrap.com`, `cloudflare-quic.com`,
`hyper.rs`, `serde.rs`, and `www.rfc-editor.org`. They are bound one-to-one to
`getbootstrap-home-r3`, `cloudflare-quiche-r3`, `hyper-basic-client-r1`,
`serde-home-r1`, and `rfc9114-text-r1`, respectively. A class therefore means
the fixed page/request graph at that origin, not every possible page on the
domain. The separately prepared Haxx graph `http3-explained-en-r1` is not an
active class and contributes no rehearsal, formal, qualification, or handoff
sample.

FRONT and Tamaraw are the two algorithmic defences in this POC and do not
consume fitted corpus artifacts. The current recovery contract instead uses
the active create-only five-file transaction under
`config/chaff-response-qualification-store/v2/`. Application requests retain
their prepared headers. The distinct chaff-only namespace copies `Accept` and
`Accept-Language` exactly and forces `Accept-Encoding: identity`.

For each class, known-valid same-origin resources with at least 1,200 prepared
body bytes form a deterministic candidate prefix ordered by descending body
size, then resource ID and URL. A candidate receives three independent
connection epochs at fixed 30-second spacing. Each connection issues 40
requests in eight sequential waves of at most five concurrent requests, for
120 completions per candidate. Qualification requires one exact 2xx identity
across all completions: status, identity content encoding, body length, and
body SHA-256. Only a recorded identity or capacity rejection advances to the
next deterministic candidate; transport, DNS, timeout, and protocol failures
abort the transaction.

The resulting response-store v2 artifact is sidecar schema 2 and derives a
runtime chaff manifest at schema 4 with `qualification_scope: response-only`
and the exact request-header primitive. There is no Walkie-Talkie prefix-pack
or fitting-data field. The existing response-store v1/schema-1 sidecars and
their schema-3 manifests remain frozen-compatible historical inputs; one frozen
cohort may not mix schemas 3 and 4. The active v2 transaction was atomically
published from clean Lab commit
`9953cf3a9a29a2cb5f6aaf02439cd13f318b6b39`, clean Neqo commit
`a3bd748c1b3f4e24f7dc88f673365e6842db51a7`, and qualification image
`sha256:c38afc629613bc8e7a5a82b55ad83a7e5787a51f780f14a199e9429be124ff43`:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `37e5e6933b337872b49889886e5930f3aa1a7778032bc9ed85a0372885e8e95d` | `330a8d41db984fc43c0c324e091cfba2906871a47ee06d7fb9c2de0aac1db32a` |
| `cloudflare-quiche-r3` | `e8fe81526aec5fa9af2c1c03ad4f093732ecc738a02bd2dd997104dc253a1957` | `38dfa66be8b0a55857845853c237a37014fe47095328d8d32187871277c3ac3e` |
| `hyper-basic-client-r1` | `816d6bcc0c43cf0d672fc0f21cc0dd871d80fa9ca24ebcadcbc81b48d33a3bed` | `ffc24029a219246cd40060cd70953e4cf0a3590e59a700ec6c6f72ce7800b54d` |
| `serde-home-r1` | `46abffb21b7f93ebe328f56ad82819fcced1586aa3966de2d733fa7a5133018f` | `91ad7a33ed70cfcf4bc1b062e747b1371bad00ca16171ee3539f40755f18c9d3` |
| `rfc9114-text-r1` | `d76a4ff366a6b8dce65b42cca02d2a55c6333e649b28316fcdfe58b060d34c2f` | `9fb65d16532ff6290aa530e4829f87167cd784a30bfb68e5d7d921acd5da8fc5` |

Publication completes the response-qualification gate but does not authorize
capture by itself. The exact sidecars must be committed and included in a
fresh clean collection build, and that build must pass the excluded 30/30
rehearsal and verified interface handoff before any formal sample.
Qualification traffic is diagnostic evidence and never a classifier
observation. “No fitting” therefore does not mean unqualified or unchecked
execution.

The formal corpus has ten temporal acquisition blocks. Each block contains a
100-sample baseline result with 20 undefended visits per class and a 150-sample
paired result with ten visits per class under undefended, FRONT, and Tamaraw.
This produces exactly 300 undefended, 100 FRONT, and 100 Tamaraw captures per
class: 2,500 total. The baseline and paired campaigns in a block have distinct
fixed seeds but the same workload order; across ten blocks each workload
occupies every workload position twice. Prospectively selected paired seeds
place every class/condition in each within-visit position 32--35 times over its
100 visits. Baseline executes first in odd-numbered blocks and paired first in
even-numbered blocks so condition is not synonymous with time of capture; the
exporter enforces this chronology from sealed timestamps. Its command-line
inputs use the separate canonical order `baseline-01, paired-01, ...,
baseline-10, paired-10`.

Undefended samples from blocks 01--08, 09, and 10 form the temporal 8:1:1
split: 240 training, 30 validation, and 30 clean-test samples per class. Every
FRONT and Tamaraw sample is `inference`/`inference-only`. Preprocessing,
feature selection, classifier fitting, and hyperparameter selection must use
only the undefended training and validation rows. Inspecting defended outcomes
to choose a model converts them into development data and invalidates their
locked inference interpretation. This protocol measures transfer of an
undefended-trained classifier to defended traffic; it does not test an attacker
retrained on defended traces.

Before any formal block, `classifier-poc5-rehearsal.yml` collects two visits per
class and condition: 30 samples. It is a clean-clock operational and receiver
ingestion gate and is permanently excluded from the 2,500. The incomplete
six-class diagnostic result at
`results/research-classifier-pilot-01-1200/20260814T064655.275845Z` also
contributes no POC5 samples. Its ATS response drift and FRONT/Tamaraw fidelity
failures are evidence that the strict gates rejected that run, not proof of a
general underlying Neqo implementation defect. The replacement cohort must
complete a fresh rehearsal with exactly 30/30 accepted and eligible samples
and a verified interface handoff. Fitting samples, qualification traffic,
smoke results, failed attempts, and archived diagnostics are never substituted
for a missing formal capture.
That gate authorizes only the exact clean Lab/Neqo/image receipt, frozen
workloads, and campaign commit it exercised. A rebuild, source/workload repair,
parameter change, or class substitution invalidates the rehearsal and requires
a new excluded 30-sample gate. Every one of the twenty formal results must bind
the same source receipt.

The latest sealed rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260814T150747.615059Z` is
valid but incomplete: 26/30 samples were both accepted and eligible. Its four
terminal failures were exactly two Hyper Tamaraw and two Serde Tamaraw
samples. Every accepted defended trace recorded zero schedule misses and valid
clock evidence. The failures confirmed a narrow implementation deadlock rather
than a general QUIC failure: for these small responses, exact body credit was
smaller than the atomic HTTP/3 HEADERS frame; the peer emitted
`STREAM_DATA_BLOCKED` before any bytes; and manual receive discarded the only
transport proof while HTTP/3 could not yet emit typed header progress. The
bounded 1,000-byte pre-header bootstrap above repairs that path using only the
existing lifetime excess budget and cannot satisfy a defence slot by grant or
advertisement.

Recoverable attempts in the same rehearsal also exposed transient compressed
representation mismatches. The separate identity-only chaff namespace and
120-completion stress test the exact response representation before capture.
The latest rehearsal, its retries, and the earlier
`20260814T110741.344914Z` rehearsal remain excluded diagnostic evidence. Formal
capture stays blocked while the now-published v2 cohort awaits its exact
evidence commit and fresh final clean collection build, and until that build's
subsequent rehearsal passes exactly 30/30 accepted and eligible with a verified
interface handoff.

The earlier six-class and stable3 schema-1 campaign/export contracts remain
available as historical pipeline contracts but are not part of POC5. The
schema-2 exporter accepts only the exact twenty POC5 results in alternating
canonical baseline/paired argument order, binds their checked-in campaign
hashes, derives sample-level splits, assigns a shared `acquisition_block_id` to
each result pair, rejects chronology that does not alternate odd
baseline-first/even paired-first, rejects overlapping or out-of-order temporal
blocks, and verifies the 2,500-row aggregate contract.

The exporter is an offline companion outside the qualified capture
implementation. This separation matters because qualification binds the exact
capture launcher and every installed `qcsd_lab` module. The exporter therefore
cannot alter a campaign result or the implementation receipt against which its
defences were qualified. It accepts only complete sealed results for which all
planned samples are accepted and eligible, re-verifies every evidence index,
and publishes a create-only handoff atomically. The handoff's `SHA256SUMS`
closes the derived inventory but does not replace the source result seals.
Before export, every sample's primary direct capture must additionally have a
single constant-offset reconciliation segment, zero modeled clock steps,
evidence-eligible exact runner reconciliation, and a maximum timestamp error
within its sealed tolerance. The elapsed durations independently calculated
from the wrapper's realtime and monotonic anchors may differ by no more than
10 ms. Thus a trace that required accepted clock-step modeling is still
excluded from classifier input.

For each sample, the handoff contains two explicitly different views:

1. a byte-exact raw `capture.pcapng`, full-packet classic-PCAP conversion, and
   `run.json` copy for restricted audit or creation of a revised projection;
2. a model-facing CSV and shape-only classic PCAP derived from the direct
   observer trace.

The shape projection retains only packet-relative nanosecond time, direction
relative to the client, Ethernet `frame.len`, and packet order. Every packet in
the shape-only PCAP uses the same fixed documentation MAC addresses, TEST-NET
IPv4 endpoints, and UDP ports, with an all-zero UDP payload. This removes real
endpoint identities, absolute capture time, QUIC headers and connection IDs,
TLS ClientHello/SNI bytes, and controller/application annotations. It is not a
valid or replayable QUIC transcript. The CSV states the same observation as
`relative_time_ns,direction,length_bytes,signed_length_bytes`, where client
egress is positive and server ingress is negative.

Raw evidence is not a neutral alternative model input. It exposes IP and port
identity, capture time, URLs and headers in the paired run receipt, and QUIC
Initial metadata, any of which can create a label shortcut unrelated to traffic
shape. Classifier code should consume only the stripped PCAP or CSV unless a
separately declared threat model deliberately includes those fields. It must
not use filenames, manifest labels, `run.json`, Neqo packet/event/schedule
ledgers, or defence parameters as features. In POC5, `class_label` is the
approved origin hostname, `workload_id` is provenance, and the defence is an
evaluation condition.

## Scope and limitations

- Internet responses and path conditions can vary between separately captured
  defences; response equality rejects content drift but cannot remove all
  timing noise.
- The observer is the collection-container boundary, not an arbitrary remote
  network vantage point.
- A direct PCAP contains endpoint and encrypted-protocol metadata and is not a
  ready-made public release.
- POC5 has five fixed workload graphs and five approved origins. It can support
  a descriptive five-way closed-world comparison for these pages, not
  website-population generalization, open-world false-positive claims, or
  security against a classifier retrained on defended samples.
- FRONT and Tamaraw use fixed research-profile algorithms and do not consume a
  fitted artifact. Their client-only QCSD adaptations still require qualified
  chaff and strict runtime fidelity; "no fitting" does not waive those gates.
- Controlled local smoke fixtures validate mechanics before fitting; the
  checked-in external smoke instead requires the sealed fitted bundle and
  evaluates independent post-fit visits.
- The historical 42/126 engineering campaign remains explicitly on hold and is
  not combined with POC5.
