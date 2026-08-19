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
header names. The subsequent earlier catalogue cohort generation was also
retired because it predated the receipt that qualifies the complete packet
ledger, including handshake traffic, against the absolute 1200-byte ceiling.
The separately prepared POC5 Hyper r2 replacement has a current whole-run UDP
receipt.

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
container's `eth0`, with dumpcap's `host` timestamp type selected explicitly.
The retained measurement is `frame.len`, packet time, and direction relative
to Neqo's local endpoint tuple. The PCAP also contains the ordinary
encrypted-protocol and endpoint metadata visible at that boundary and must be
handled as research evidence rather than a sanitized release.

Both evidence clocks belong to the Linux execution environment. Dumpcap
records the Linux packet-capture clock and the Rust runner records elapsed
Linux monotonic time. Windows QPC, W32Time, PowerShell, WSL synchronization
status, and other outer-host clocks are neither evidence inputs nor admission
gates. This makes the instrument directly usable on native Linux and on Linux
container hosts. Image binaries remain platform-specific, so a machine with a
different architecture rebuilds from the pinned commits and must complete the
same qualification and excluded rehearsal before acquisition.

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
- Neqo's packet record reconciles with the direct PCAP as one constant-offset
  segment, with zero modeled clock steps and at most 10 ms timestamp error;
- repeated monotonic brackets around the start/end realtime readings establish
  a worst-case elapsed-clock disagreement, including pairing uncertainty, no
  larger than 10 ms;
- when the workload freezes preparation responses, the exact resource ID,
  status, delivered byte count, body SHA-256, and successful outcome match for
  every resource;
- the runtime's bounded padding-event guard did not fire.

The reconciliation does not replace the independent observer. It establishes
that transport datagrams recorded by the runner correspond to direct captured
frames, with one uniform clock offset and at most the configured residual. A
clock discontinuity or unexplained datagram is a failed attempt, not something
silently corrected after collection. Step modeling remains in the failed
attempt diagnostics to explain a rejection, but cannot make an attempt
promotable. The classifier exporter independently revalidates the same gate.

The frozen prepared-response check runs after an otherwise successful attempt
and before promotion. A mismatch becomes the retryable fidelity failure
`StrictPreparedResponseIdentityFailure` and remains under `failures/`; it
cannot become immutable accepted evidence that is merely marked ineligible.
Crash recovery performs the same check before completing promotion of a
successful terminal attempt, so interruption cannot bypass the gate. After
every defence in a paired visit has run, the same response signature is also
compared with the undefended member as a defence-in-depth paired check.

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
  The original small-floor path remains available when the prepared body floor
  and requested, advertised, and known limits agree below the fixed absolute
  1,000-byte framing target. A positive floor does not discard the proof merely
  because scheduled credit has already raised the requested limit: that
  residual branch is permitted only when the controller proves one live
  contiguous advertised scheduled range from the effective initial receive
  offset through `requested == advertised < 1000`, with known capacity beyond
  it. Either branch appends only an ownerless, slotless parser lease through
  absolute offset 1,000, bounded by the existing lifetime
  `max_stream_data_excess` budget. The residual branch neither moves nor
  satisfies the scheduled range or its slot; only consumption retires that
  debt, and any typed progress invalidates the retained transport proof.

  A separate terminal-tail bridge handles a pristine typed boundary after
  DATA. It is available only when incoming scheduling is complete, no incoming
  assignment, continuation, or same-stream backing remains, requested and
  advertised limits agree, known exact capacity continues beyond them, and
  the complete contiguous advertised scheduled tail is between one and
  fifteen bytes. If the full 16-byte parser allowance remains inside the same
  lifetime excess budget, one ordinary unowned, slotless lease is appended.
  The original tail retains its slot: grant and advertisement satisfy no debt,
  and only consumption of those scheduled bytes can settle it. Partial,
  gapped, post-cap, continuation-owned, and nonterminal states fail closed.

  FRONT alone opts into prearming its frozen packet targets. Future incoming
  targets remain private and ineligible before their exact not-before times;
  each endpoint and deadline remains frozen, including the strict 5 ms
  deadline. Each drive reconciles all due fixed events and their incoming
  credit before eligible output and ordinary input, using fresh monotonic time
  and absolute wake instants. Release uses ceiling conversion and deadlines
  use floor conversion, preventing early transmission or deadline extension.
  Static and non-FRONT dynamic schedules retain their existing activation
  behavior.

  Receive-control batches undergo a pure global typed preflight before
  mutation. Exact current-batch identities and persistent
  accepted-but-unencoded `MAX_STREAM_DATA` identities are validated together;
  shared transitive closures are cancelled once, transport LIFO rollback is
  previewed, and encoded or advertised credit is never revoked. A
  lifecycle-invalid receive-limit increase or manual-receive configuration
  becomes terminal or gone only when unavailability is proven. Ledger,
  ordering, identity, and rollback inconsistencies remain fatal. The
  transaction flushes resulting observations and defence realizability before
  unrelated actions, and a fatal case records the raw action with its typed
  error. These recovery rules change no seed, defence parameter, schedule,
  fidelity threshold, or acceptance threshold.

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
`getbootstrap-home-r3`, `cloudflare-quiche-r3`, `hyper-basic-client-r2`,
`serde-home-r1`, and `rfc9114-text-r1`, respectively. A class therefore means
the fixed page/request graph at that origin, not every possible page on the
domain. The separately prepared Haxx graph `http3-explained-en-r1` is not an
active class and contributes no rehearsal, formal, qualification, or handoff
sample.

FRONT and Tamaraw are the two algorithmic defences in this POC and do not
consume fitted corpus artifacts. The legacy POC5 recovery contract instead uses
one create-only five-file transaction under
`config/chaff-response-qualification-store/v2/`. Application requests retain
their prepared headers. The distinct chaff-only namespace copies `Accept` and
`Accept-Language` exactly and forces `Accept-Encoding: identity`.

The historical legacy POC5 exact-five cohort was qualified atomically from
clean Lab Q6
`0d0b1984c1d87b0502899cc451f1ed6ab6463d03`, tree
`2c44a2d00473676776eafbbd7883e4ed739d16de`, and clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`. The qualification collection and
prepare/actual images were respectively
`sha256:91151da64ead1aff662f207107aa06fa2d16c62378f2989043193beca22a24ac`
and
`sha256:e5f1c8153b4238700f06339d94c046ca3d8f5aad14375ae6642ea7785b792881`,
under build tag suffix
`q6-0d0b1984c1d8-6aceaac85243-20260817T191330Z`. Their `source.json` SHA-256
was `a82950c006023d11972913021fd14ad88332c8a8ff028f223472e31d3bd164f0`,
their raw implementation-receipt SHA-256 was
`ebf2eadf174d2fbc43156907b4fd76d3dcf5f2f1f13af606ead404a3d2168a27`,
and every sidecar binds implementation-receipt aggregate
`4137ed63d23c52b897f47c26ed62f1c97e13f0a173b51438c4bcf20979adc5d5`.
The exact Q6 collection image completed its deterministic prerequisite suite
with 732 passed and two environment-gated skips, then passed all three
Linux-local live prerequisites before qualification.

The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads without a rejected candidate. Across 15 independent connection
epochs, 600 stable identity completions produced 61,277 packet observations:
54,444 incoming and 6,833 outgoing. All 120 request waves completed; the ten
within-workload inter-epoch gaps ranged from 30.030177204 to 30.065013514
seconds, the maximum observed UDP payload was 1,200 bytes, and no oversized
packet was observed. Its historical legacy sidecar and derived-manifest hashes
are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `60ff5642bac12a73d0efcfbf74728946cb42d58aae5c18a4d0e9efa6641c899b` | `dd44865c7a0452c2e603c0bfa07994a054a4c1753a08045273f7d542167b4a12` |
| `cloudflare-quiche-r3` | `895c31ce388cf20ace53afeba2abd2f7a03f85054bf3bed37a47db389f8b45ac` | `0c8dab88862df196d303d5f69b177bde8553b978e6acc72d091772540cd6eb1c` |
| `hyper-basic-client-r2` | `24996a0978cda7a9858f39fef720abe3ebc5243cec5eb52943acadcfe79f0468` | `ab36ef6920b106c4f8bd625c8b5e9dc40f7fbca1ab7cb315a224f8b00219bd57` |
| `serde-home-r1` | `7367ef8b340bb5e4624b213f9d78e1008ad2f8e61f3939ab87c504e622d23d52` | `96a361270e81631f0fd50eb676e37cb33aae915319396766f16cc3cf2e198a7f` |
| `rfc9114-text-r1` | `8d35815100de1b1ab8b5beb2c819ba5fdf5d032e3c144d553df911cec62d74ac` | `ad5faeebb1cc186c5b79df01d66315481ba18f623a4afdb65a8ec06fa1709b58` |

P6 published these exact files as the canonical legacy POC5 response cohort
under `config/chaff-response-qualification-store/v2/`. They remain frozen
compatibility evidence and are not the fresh `classifier-multiorigin5-v2` set
or acquisition provenance.

The now-historical P5 exact-five cohort was qualified atomically from clean Lab Q5
`af3403d60f5be008dc88cc52c6ce8ec5a34bc47c`, tree
`7110eebb2e4763a9e197d3c5be8f6b55b0b2feb9`, and clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`. Q5 is the documentation
acquisition child of the test-only controlled-fixture repair
`32f8f4d816cf05ebc483cc547732d146225493c9`; the production Linux-local
capture-integrity implementation remains
`47c91bb36dcddd3943253ee16141febbaf9041e8`. The qualification collection and
prepare/actual images were respectively
`sha256:73c2530d0c14bd272e88a3dff147018fd30d4aa5e848988f3714fb7b1484b990`
and
`sha256:cd238e21e89706e257de75dd94282224bb40ebe70cbc0615511be4072eab2e7a`,
under build tag suffix
`q-af3403d60f5b-6aceaac85243-20260817T171051Z`. Their `source.json` SHA-256 was
`2847eea1cd0988cbb51f3b5086cb4e326011ebfe1bb68136a5b9143501063f35`,
their raw implementation-receipt SHA-256 was
`4db3b6448e988c4674e94c0a7584b63b352fd1115d4dfb8124f6e1b7845c80d9`,
and every sidecar binds implementation-receipt aggregate
`4d96ca1ce6d0711ae8ca4e1c125b8b83451daab683e626c90c95b5c39c37afbb`.
The exact image passed all 731 local prerequisite tests before qualification.

The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads without a rejected candidate. Across 15 independent connection
epochs, 600 stable identity completions produced 61,726 packet observations:
54,454 incoming and 7,272 outgoing. All 120 request waves completed; the ten
within-workload inter-epoch gaps ranged from 30.013367067 to 30.062120752
seconds, the maximum observed UDP payload was 1,200 bytes, and no oversized
packet was observed. Its historical sidecar and derived-manifest hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `cbc90b4f4f1021fc51140cfe23d133dbce17e1f81d34eaa70639be42370ad4ca` | `9a3e3bc6648a91ca0c6ebc884aaa2bfd271c64d1efab087d4594e71a28e785c9` |
| `cloudflare-quiche-r3` | `2506c96d3aee4b145e3ba816f3ee64fe47e2e71df65f3d75d40126694aa01c1e` | `cff7a5fcfddb4d4419efdd80a85b1172942a4c2c8ffa4fc558cc4f2672416589` |
| `hyper-basic-client-r1` | `aee4f47953c89026e4583e2cfd8db1bc78ffa1bfcd6af1f0e9813b2b31a37f51` | `b9407104892141af34581b138aa81d6a58353c1e66fa0a3023ab5c3589d90ef5` |
| `serde-home-r1` | `773f4e4a0c9ecfc50ed59a7787e9102e58b25941fdae874c53d43da4b798903b` | `165436bf45941105d2f29d1b3193564cb416b3e4a3bad4ab441a1819163480b9` |
| `rfc9114-text-r1` | `b77dd117607ce698bcc4ad7da12367621a12baafbc7805f5ff13cf11557eee6c` | `2bb2bf65644172d338496eadba17524d9a5521bf4dff130c42f3482c3081a600` |

P5 `f215b538e043a26038aae8bb93e8926f3de6d322`, tree
`257fb2b0f7433b96279927c109f3397a6d1be733` and parent Q5, published those
exact files. Its final collection and preparation images were respectively
`sha256:3f4f10a47b72d3d280ad1bbed4dc0338e7823abdf62e6304b4e674a3777375ea`
and
`sha256:fbb2560054f5cdc8b789b50698fc093b3d14fe0ef76d101baba913f99b666fdb`,
under build tag suffix
`p5-f215b538e043-6aceaac85243-20260817T175203Z`. Their `source.json` SHA-256
was `370b6b6e1edbbec5137f04381e13db4187263f16e735b68584671c6afa2123f3`,
their raw implementation-receipt SHA-256 was
`6f99ba3b443ee35fb6cd258dc02178ff973cae0fc8a74b6cfd126a0224ea78bd`,
and their implementation-receipt aggregate was
`dda2dfd54b10da49234e14744a844a0befaac90f6694395508cbbb721d61634e`.

The excluded P5 rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260817T181058.212792Z`
sealed `incomplete`: 30 planned, 28 accepted, 24 eligible, and two terminal
failures. Its evidence-index SHA-256 is
`04a4d40a9c09bc8618eec8322d68df07508994a12968535a5e37883c96bae89b`
and its `experiment.json` SHA-256 is
`89338ae55eb4a7124b42dec28386247dfc5c0abd034af51718d8418e5f0cfdfd`.
All 35 retained attempts passed the Linux-local capture-clock gate with one
constant-offset segment, zero modeled steps, and exact direct-runner packet
reconciliation. Hyper r1 had frozen resource 0 at 6,165 bytes and SHA-256
`96411b4e30fa8e579eebf6f9b2b7604ccb7335e990266a2da893fe4ff7426c40`,
while all ten retained Hyper executions returned 5,917 bytes and SHA-256
`59974039ec7fdcbc0461fd86f91fddc294ed7c2eb3cd46f96352be0687eaf106`.
Each of the six Tamaraw attempts correctly failed one slot with
`ReceiveCreditRetired` and exactly 243 retired bytes; the four undefended/FRONT
captures matched each other but not the frozen prepared identity. This is a
prepared-response drift failure, not a Windows, WSL, or capture-clock failure.

The create-only replacement `config/workloads/hyper-basic-client-r2.json`
has SHA-256
`11baf7f3fe0db6f9c86af51fbc4100b2b5f1683385f7f9d30fefd33349569d6f`
and records three stable preparation runs at the new 5,917-byte identity,
with 1,200-byte maximum UDP payloads and zero oversized packets. Q6 changed
only the active POC5 Hyper binding to r2 and kept Neqo F3 unchanged. Because
the workload ID is an input to deterministic defence ordering and to every
Hyper sample seed and ID, Q6 also reselected the ten paired campaign seeds
prospectively from
`2026082001..2026092000` using plan expansion only. The 2,500-sample plan has
unique sample IDs and seeds, every class/defence/position cell occurs 32--35
times, and only three of 45 cells fall outside 33--34. At that POC5 boundary,
canonical legacy response-store `v2` contained only the Q6/F3 exact-five cohort
published by P6. A clean P6/F3 final-image build, excluded 30/30 rehearsal, and
verified interface handoff were required before its formal acquisition could
restart from baseline-01. No P5-bound interface handoff, formal capture, or
classifier export was run.

The immediately preceding Q3/F3 exact-five cohort is historical because the
Lab acquisition implementation changed.

For each class, known-valid same-origin resources with at least 1,200 prepared
body bytes form a deterministic candidate prefix ordered by descending body
size, then resource ID and URL. A candidate receives three independent
connection epochs with at least 30 seconds between epochs. Each connection
issues 40 requests in eight sequential waves of at most five concurrent
requests, for 120 completions per candidate. Qualification requires one exact
2xx identity across all completions: status, identity content encoding, body
length, and body SHA-256. Only a recorded identity or capacity rejection
advances to the next deterministic candidate; transport, DNS, timeout, and
protocol failures abort the transaction.

The resulting response-store v2 artifact is sidecar schema 2 and derives a
runtime chaff manifest at schema 4 with `qualification_scope: response-only`
and the exact request-header primitive. There is no Walkie-Talkie prefix-pack
or fitting-data field. The existing response-store v1/schema-1 sidecars and
their schema-3 manifests remain frozen-compatible historical inputs; one frozen
cohort may not mix schemas 3 and 4.

Q3 pins F3 `6aceaac85243d6e0e34354108e010705d3c83088`, tree
`691209bdd616c25759d508f1af0547904b8ce058`, directly above F2
`a8378520b9740be782bfe526cdb3eb05e6665571`; the F3 patch SHA-256 is
`a4b17821f8c119af9f022a609dd33e40be4f196fcad397b04ba444d859c4a7f8`.
The create-only exact-five transaction succeeded atomically from clean Lab Q3
`06cacddc21ab0ded9422d445723f60f37c530363` and F3. Its qualification
collection image was
`sha256:bea517984b866d0c413ccc3d7c381e07a586a86eac5660717a9b8a809b4da382`;
preparation produced, and the qualification actually used,
`sha256:227a931f5ae410fe298285d69a1d5d7b403ba026970949e5b30723d86b66b68a`.
The qualification build tag suffix was
`q-06cacddc21ab-6aceaac85243-20260815T211610Z`.
Every sidecar binds implementation-receipt aggregate
`558705bb0560ee3a87140670de7140ac087e9a0bf5ab13c1215f214f618f5ea4`.
The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads. Across 15 independent connection epochs, 600 stable identity
completions produced 61,875 packet observations: 54,573 incoming and 7,302
outgoing. Within every workload, consecutive epochs retained at least the
required 30-second gaps, the maximum observed UDP payload was 1,200 bytes, and
no oversized packet was observed. Its now-historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `9b868b3b083c3acca66d6d05c7c9962e3aad28750defbdbe21a340fb054c1148` | `7fb560f246c90b2ad3eaf937f7a97f3bf9661f244fd10fd84e86753db51ddf3d` |
| `cloudflare-quiche-r3` | `c9dacbabdd2861c5ef505fa572f7f1b9407084c7002a5ef28057b66c12788246` | `51e90afbd48747f9a776eeb9fb80158b38f4a909d9fd35932ceb4c7fb1edd80a` |
| `hyper-basic-client-r1` | `92b5090ba4b4d228db652f7d435da3d29867f9ffe221a835e4f6d965cd6840d9` | `2fa47f098191f2c72f9abcf90b4b2f7b0edef1d21bc480c93fc18f5f988df514` |
| `serde-home-r1` | `19fa46e8da00b6af47090ae9857335b9db966a3b55dc9c0592059cdceb2eafc4` | `d463076c6baf2a01fd94d534fae8015f99d523a54ebd4a9dc9d95d4109cf1f11` |
| `rfc9114-text-r1` | `f43285364a01de0f5024632995b83f034911c5d3c7c5770396b240f07c5fcf62` | `0152f1137aa31e5371ad4792829485710cb9218192cf115bc7bbdfa0a26ae797` |

P3 `507cb04c38babcdc0050ddb064007a962efee0a2`, tree
`a600c16c2ef71852ec4002c10f1a09ac03f84280` and parent Q3, published these
exact files without alteration. Its clean final collection and preparation
images were respectively
`sha256:361ab7d677b1399bd0140f75d6cf7a9a30d350a7232fbd5529c1b2b9ddc000bd`
and
`sha256:db75500ff909ffae9fef32967820ec335fc880fb436c96f0db3a120a8911bce1`,
under build tag suffix
`p-507cb04c38ba-6aceaac85243-20260815T215336Z`. Their source receipt
`source.json` had SHA-256
`590b4a856f7d8420329c90aba1d026edfcfbc75767ad9dc27fe75954c59f61dd`;
the raw implementation receipt had SHA-256
`c998823eb1b065e161e9397d079ff10155d0d55870580afe5efd058f9b03c1c4`
and final execution implementation-receipt aggregate
`1115efbaca78ef8eab8bdf5551a598250a82af3812d3a23a2bee820ee600c1a6`.
No rehearsal, interface handoff, formal capture, or classifier export was
launched from P3.
The five historical files remain byte-exact recoverable from P3 and frozen
evidence.

That cohort remains valid historical evidence, but is ineligible for current
execution because the qualification receipt inventories every
`src/qcsd_lab/*.py` file and the Linux capture-integrity implementation commit
`47c91bb36dcddd3943253ee16141febbaf9041e8` changed `capture_session.py`,
`fidelity.py`, and `orchestrator.py`. Q4
`570851923bfaa24aa967f947c38f305138145776`, tree
`11f6946091247f17520958ab29014b7aa04dee1f`, is the documentation/deletion
child of that implementation commit and intentionally has no canonical
response-store v2. Its qualification collection/prepare images were
`sha256:ef2e6a6b9464c34d80657c787d0b1fb15eb8ee03539db141c8cb4b7bcf5cc236`
and
`sha256:228fe4b3a8cf1287dc0d6fdc9a1ba627e1f6393f9d456de105c506f4111a9c88`,
under suffix `q-570851923bfa-6aceaac85243-20260817T164038Z`. The source, raw
implementation-receipt, and aggregate SHA-256 values were respectively
`3d7448fc0025aa20d741ee6cffadca3b5b9312bd327853cfc47619b18819f43f`,
`a45875a057a495d5f5a6c30de7fd697bedc28dc856248e1eb3bdfbd2511d873f`,
and `6c1f190c8e5bfbf7951ea8aba081bb44ada4ffdc264089ff640fad89dca8a050`.

Q4 passed 729 deterministic tests with the two live tests gated. Its first
local-only `test live` passed the canonical capture path but stopped on a
controlled Walkie-Talkie fixture that relabelled a historical schema-five
profile as schema six without deriving the sender-framing cell. Neqo correctly
rejected the inconsistent configuration before clock reconciliation. No
public qualification or acquisition traffic followed. Commit
`32f8f4d816cf05ebc483cc547732d146225493c9`, tree
`d713ca9f665935a4dd953e242a636d2063ffc784`, repairs only that controlled
fixture and its matching prefix specification; production capture semantics
and Neqo F3 are unchanged. Q5
`af3403d60f5be008dc88cc52c6ce8ec5a34bc47c` is the documentation acquisition
child of that repair. Its clean image passed all 731 local prerequisite tests,
and its atomic exact-five qualification is the historical cohort published by P5.

The immediately preceding transaction succeeded atomically from clean Lab
qualification source `fcc6af4394b2b2f7dee5f8b1a214cd7673a9e0e8` (Q2), clean
Neqo `a8378520b9740be782bfe526cdb3eb05e6665571` (F2), qualification collection
image
`sha256:29a6e0adaa65d88e1e30afd3722f20f976fe14ed0676fb28d0448ec9155c0700`,
and prepare/actual qualification image
`sha256:ef5a3e7bcd20e8841f6c32064d40fcf94be48380f390146d5c039a49fc3665c0`.
Every sidecar binds implementation-receipt aggregate
`a8384fd28e9b22c0a683138c0d7a039db3abf927bcc6bd15ffc936bdf2f352a0`.
The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads. Across 15 independent connection epochs, 600 stable identity
completions produced 62,007 packet observations. Within each workload,
consecutive epochs retained at least the required 30-second gaps, the maximum
observed UDP payload was 1,200 bytes, and no oversized packet was observed.
Its historical sidecar and derived-manifest hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `4b63acf9dfa58413500cf8eaa34fc326a71a74d6c5df3404378543ea5ae707cf` | `c2dc6643caa028e137d717adf4fc13561b1e3c07bfbad28bef2267c0ed20fc92` |
| `cloudflare-quiche-r3` | `5728dda8668bc4aca816495d87c56038a7ed267b3e902518cdd7bd84b990c3d2` | `0b7794ebdf2155901f7398c95602e111e27087ce5f945a22b198391aa1054277` |
| `hyper-basic-client-r1` | `e30e877f068a199688948357b19c61803f94cad57123382e79812492750ab55e` | `7b5a2755a6bf47010289df74d40dc45aeaf58c30dd2a8ce32fc928eaa7b70332` |
| `serde-home-r1` | `86b6d3fcdc208e50b71e5cf957770a9e6319dae39a2e87b9d884f713c0ec3da4` | `e433468dcfee5c2ff6de7d4376588e7c104f60d13977894412ee58a04c88a212` |
| `rfc9114-text-r1` | `e55414ca9da748f17b89c02d762b1ac39f74acb349ed60d67833c1d5999e627b` | `20ce6ddd56b4684179c0cec8cac12bcef7ce8ef9327d954c2ecfe2239ec84bd9` |

That exact batch was published without alteration by P2
`8a8d605166bfc27c6a7b8907162119e055ca7ca2`. Its clean final collection and
preparation images were respectively
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`
and
`sha256:82434c67e194d29dc26c0cfa90014f01a2473c61ea92e9213c47ea1afc55297d`.
The complete Q2/F2/P2 lineage—including both qualification images, both final
images, implementation receipt, sidecars, and derived manifests—is historical
and excluded. Its hashes remain verbatim for recovery and audit, but none is
active canonical evidence.

The earlier superseded v2 transaction was
atomically published from clean Lab commit
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

These earlier historical files remain available from Lab commit
`88569f268260b36f0c4ccfc36681f7a42887b66c` and frozen sealed results. They
remain explicitly superseded and are not the active response cohort.

The later fixed transaction was published from clean qualification source Lab
`2290b1f1a100d0d36f2d5ada405d9c26d382716d` (Q) with Neqo
`867246557ec719fc34552b60abf624895be2706c` (F). The qualification collection
image was `sha256:7b556344d65339e5cb399c37f7fe2a84ea248c9608e193f12269018c4ca47920`;
preparation produced, and the actual qualification used,
`sha256:5d85e8d7d090e5a29e77fe5751c65c70299e2cf1fc709cb62c3fde50c16e191d`.
Each sidecar binds implementation-receipt aggregate
`33fe7032e9bf35efb7bb4d3d84b7e2733f4e81a455baef0df1df0120687e2c35`.
That transaction is now superseded because the qualified acquisition
implementation changed in Neqo. All five workloads had qualified deterministic
candidate index zero. Across five candidates, three connection epochs and 40
responses per epoch produced `5 × 3 × 40 = 600` stable identity completions.
Each epoch comprised eight sequential waves of five requests (`8 × 5`),
consecutive epochs kept the 30-second gaps, and every epoch recorded a maximum
UDP payload of 1,200 bytes and zero oversized packets.
Its historical sidecar and derived-manifest hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `0bef93532273f59718e1fc4123eccfa6833922ff34f0d22cc9cf6cf03963cb5d` | `f411d539e656a5abd6a49c94da5a60d4e2898f141b1ebf86e48b2d2bd2ca4372` |
| `cloudflare-quiche-r3` | `d9dc5898464e7cb05f37fe9faf758250a72eaf14209913d7f2e56ffd31ced6ac` | `5d51d0f68d67c1847f49df01640c0ea6ca0a303dc3b567a4dc81f1ed5aef190a` |
| `hyper-basic-client-r1` | `4f8f51722d0c9a3d1d696f845bf2ee91ff45f3387b62c472115f682b5c353428` | `3fc7f34b90e9cbc423dc1f727bf157c5b3910b30bb61c2a52eef7a74cebf8a55` |
| `serde-home-r1` | `ee1f97b15a4f93702eda6c98b6578a2eb958df6f0f6a5129ab6b0a9d27ce3ca1` | `edb21e2792dfe59dd0c30f586709e5310e5b6ba5744a0c0a5ce334bd7746f797` |
| `rfc9114-text-r1` | `1d75fcf42ba170eabe76f5184adcc9551a4b3360d3e869f694108055360541af` | `e9dfb138adbdb18d43bf2c70eb34240dc54894a8e58aa1766853e4fbfdf178b6` |

Those exact files remain recoverable from Lab publication commit
`d5543406359528b1382222d8ef3d3cffd67b7d4d` and frozen sealed results.
All five previously recorded response-store v2 transactions, including Q5/P5,
are historical. Canonical legacy `v2` retains only the POC5 Q6/F3 cohort
published by P6. Commit
`47c91bb36dcddd3943253ee16141febbaf9041e8` remains the causal production
implementation change; `32f8f4d816cf05ebc483cc547732d146225493c9` repairs
only the controlled schema-six live fixture.
No historical sidecar, implementation receipt, image, rehearsal, formal
sample, or export could be mixed into that legacy POC5 Q6/P6 lineage. At that
boundary, a clean P6/F3 final-image build, an excluded 30/30 rehearsal, and a
verified interface handoff were required before any restarted formal sample.
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
class and condition: 30 samples. It is a Linux-local capture-integrity
operational and receiver-ingestion gate and is permanently excluded from the
2,500. The incomplete
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

The superseded clean source receipt—Lab
`d5543406359528b1382222d8ef3d3cffd67b7d4d`, Neqo
`867246557ec719fc34552b60abf624895be2706c`, and collection image
`sha256:5d56c63fdd182ba311392602bad77e8f4c3198c6bd08958a691cac197f74f05e`—
passed the excluded rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260815T132537.356504Z`
with 30/30 accepted and eligible samples. Its sealed evidence-index and
experiment hashes are
`350e015f97d49fa8c14f7e5d82489b05f2fbdd5d0cb9a0345b54abba32d9b560`
and `f3028b05a7908826b003fafb8e07bdd0d0a709a183be0513fa7cc5efb7eb2703`;
the verified interface handoff's `SHA256SUMS` hash is
`392d897369de9e38bbdae116b79c1559a9f5d00a65f33c4b8eccbb887053e02c`.
The same receipt completed baseline-01 at
`results/research-classifier-poc5-baseline-01-1200/20260815T134617.090622Z`
with 100/100 accepted and eligible samples, all on their first attempt. Its
sealed evidence-index and experiment hashes are
`65a858a25a714a534dff1afb7ec57d510fd2ac8ea6b1995b9aad34fd94136bc9`
and `5ae8cded5a7dc117ec21ce302a9a1b12051acc8690939a75fbbe004f76fd593b`.
Paired-01 at
`results/research-classifier-poc5-paired-01-1200/20260815T144004.646818Z`
is sealed and valid but incomplete: 146/150 samples were accepted and eligible
across 166 attempts, split U/F/T as 50/46/50, with four terminal FRONT
failures—Hyper visits 002, 004, and 009, and RFC visit 003. Its sealed
evidence-index and experiment hashes are
`dc1b656a8745d589ff43224862647d46aed67d8cf3687d1d7cd78e7e84ffb2af`
and `767d0237d3172b506d951bdb9a9c1c4b37df6aee3e166d90b9193c3d7c9ab7d2`.
Hyper 002 and RFC 003 exhausted their retries on strict schedule misses. Hyper
004 retained
310–325 scheduled response bytes below the atomic HEADERS boundary until the
120-second timeout. Hyper 009 combined strict misses with a typed transport
`InvalidInput` on one attempt. These observations motivated the prospective
residual scheduled-prefix bootstrap, FRONT-only prearming, and transactional
typed receive-action preflight above. They caused no seed, defence parameter,
schedule, fidelity threshold, or acceptance-threshold change.

P2 then produced the fresh excluded rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260815T201524.981071Z`
from clean Lab P2 `8a8d605166bfc27c6a7b8907162119e055ca7ca2`, F2
`a8378520b9740be782bfe526cdb3eb05e6665571`, and collection image
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`.
The sealed result is incomplete, failed its gate, and is permanently excluded:
29/30 samples were accepted and eligible, while Hyper visit 000 FRONT failed
all three attempts. Its sealed evidence-index and experiment hashes are
`3d9baba02bb87e3e884992c1a215dcb549b8f1628b732826a5b502669e496df7`
and `c9544d06a4349f5160388fb93f7ea8b9be7c5f80435668ef0dd66360379978ff`.
In every failed attempt all application request streams opened and every
application request's bytes and FIN were acknowledged, yet all five response
resources remained incomplete. Scheduled incoming accounting closed as
1,333,200 requested, zero consumed, 1,333,200 retired, and zero unresolved
bytes. Retained capture evidence shows that response datagrams reached the
host.

The first divergence was a two-layer F2 liveness defect rather than a changed
server response or schedule miss. FRONT's fixed `reconcile_due_fixed`
microstep processed due incoming work at exact elapsed time without advancing
the incoming boundary consulted by `next_deadline`; an incoming event that
could not yet allocate therefore retained an already-past retry. The
single-thread runner handled that deadline with an await-free `continue`,
starving Tokio socket readiness while it hot-looped. F3 advances only the
fixed-schedule retry watermark while continuing to process the exact instant,
preserving future-event privacy and global fixed-event order. Its runner takes
a readiness-aware await with a one-microsecond retry timer for an already-due
target and leaves future absolute wake arithmetic exact. Neither layer drops,
reorders, or artificially satisfies a scheduled event.

All five result roots above remain immutable diagnostic evidence. The earlier
passing rehearsal no longer authorizes a replacement image, baseline-01
contributes no sample to the replacement corpus, and no accepted row from
either incomplete result may be reused. P2 produced no formal campaign result
and no classifier export. Q3 completed the atomic exact-five F3 qualification,
and P3 `507cb04c38babcdc0050ddb064007a962efee0a2` published that historical
cohort and built the clean final images recorded above. No P3 rehearsal,
interface handoff, formal capture, or classifier export was launched. The
replacement Lab capture-integrity implementation at
`47c91bb36dcddd3943253ee16141febbaf9041e8` makes those historically valid
sidecars ineligible under the current-implementation contract. Q4 kept
canonical v2 absent and launched no public qualification after its local live
fixture failed. Q5 passed its repaired live prerequisite, completed the new
atomic exact-five Q5/F3 qualification, and P5 published that now-historical
cohort. Its `20260817T181058.212792Z` rehearsal sealed incomplete because the
frozen Hyper r1 response had drifted, even though every retained attempt
passed the Linux-local capture-integrity gate. Q6 changed the then-active POC5 binding
to the independently prepared Hyper r2 graph and removed the prior canonical
v2 cohort at its acquisition boundary. Its completed exact-five Q6/F3
qualification remains published by P6 as legacy evidence. At that boundary,
clean P6/F3 final images were required to pass a wholly new excluded 30/30
rehearsal and verified interface handoff before formal acquisition could
restart from baseline-01 under one homogeneous source receipt.
The earlier `20260815T103924.969402Z`,
`20260814T150747.615059Z`, and `20260814T110741.344914Z` rehearsals and all
their retries remain excluded evidence as well.

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
Before export, every sample's primary direct capture is rechecked against the
same promotion gate: a single constant-offset reconciliation segment, zero
modeled clock steps, evidence-eligible exact runner reconciliation, a maximum
timestamp error no larger than 10 ms, and a bracket-uncertainty-aware wrapper
realtime/monotonic elapsed difference no larger than 10 ms. Thus a trace that
required clock-step modeling cannot be promoted or enter classifier input.
Fresh captures must include the selected `host` timestamp type and both
pairing-uncertainty fields. Historical sealed four-anchor results remain
readable under their prior schema, but an explicit non-`host` timestamp type is
rejected.

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

### Approved-origin multi-origin v2 replacement cohort

The `classifier-multiorigin5-v2` cohort is an independent replacement study,
not an extension of POC5 or the superseded multi-origin v1 acquisition. It
uses fresh campaign seeds, sample IDs, captures, result namespaces, analyses,
and handoffs, together with its own create-only response qualification set.
Its five primary labels and frozen graphs contain 9 Bootstrap resources over
one origin, 6 Cloudflare resources over three origins, 7 Hyper resources over
two origins, 20 Serde resources over one origin, and 2 RFC resources over one
origin.

Its construct is the complete *approved-origin frozen HTTPS GET graph* observed
under the preparation policy. Discovery blocks service workers and pauses each
request before transmission; only approved HTTPS GETs are continued. Strict
coverage admission requires every approved origin to contribute a resource and
every unique approved rendered URL to pass the Neqo HTTP/3 stability gate.
Unapproved origins, non-GET requests, data URLs, and requests never revealed
because an intentionally blocked script did not execute remain outside the
construct. Therefore the cohort is a stronger page-like multi-origin replay of
the fixed admitted graph, but it is not an exact or full browser page load,
renderer state, cache model, or claim about every third-party dependency on
the public site.

During measurement, one sample creates one Neqo QUIC/H3 connection for each
distinct approved origin and one application request stream for each resource
whose dependencies are ready. Connections share the event loop and may overlap;
multiple resources on one origin use multiple streams on that origin's single
connection. The accepted direct PCAP is the exact union of all Neqo endpoint
tuples. This retains multi-origin packet shape while excluding unrelated host
UDP traffic from the authoritative trace.

FRONT and Tamaraw bind the create-only five-file qualification set
`classifier-multiorigin5-v2`; undefended-only baseline campaigns do not need a
response-chaff binding. Each consuming result freezes the selected sidecars in
its inputs, and the published set is never overwritten.

This set was qualified from clean Lab
`44d19f3cf787ef9b0c1eaa121758874fa6e49a67` and clean Neqo
`6aceaac85243d6e0e34354108e010705d3c83088` using preparation image
`sha256:5b4f8268118dbfb37d0c520510a616ff8e24b67b7ceb2b394f97c353be7d9ff5`.
Its audited five-file aggregate SHA-256 is
`9df4d34dc0a7b767e6fb3b2429bd8638ec33914da95ab05733d99b02a38488f8`:

| Workload | v2 set sidecar SHA-256 |
|---|---|
| `getbootstrap-home-r4` | `a3274a15e7c74554fc91efbe71c3d22e0e94843c1008105339bf30cd03309a0a` |
| `cloudflare-quiche-r4` | `5fa1b048aec8294d28086942045829ac2efa6db69aa74eccfb7045949d0c9b84` |
| `hyper-basic-client-r3` | `7d95b91a38530db1d5db3e6bfbbe7019aff0b8ed705292b9db05ee46daa42327` |
| `serde-home-r2` | `d4f71ecc7782d395c711af06fb9f2cfc407dd0c60a35aaffc024f39acf41165c` |
| `rfc9114-text-r2` | `bd528f882ff471fee5bb6e9a21fea44c2d13d46faa863f784b3b67ea10f55f7d` |

The preparation image is qualification provenance, not the final acquisition
collection image. The exact final image for the rehearsal and 2,500 formal
captures remains pending.

The experimental design repeats all five classes from scratch in ten temporal
blocks. Each block has 20 undefended baseline visits per class and ten paired
visits per class under undefended, FRONT, and Tamaraw. This yields 2,500
captures: 500 per class, with 1,500 undefended, 500 FRONT, and 500 Tamaraw.
The physical acquisition order is exactly:

```text
B01, P01, P02, B02, B03, P03, P04, B04, B05, P05,
P06, B06, B07, P07, P08, B08, B09, P09, P10, B10
```

Thus odd blocks run baseline before paired and even blocks reverse the order.
The exporter receives roots in canonical baseline/paired argument order and
uses sealed timestamps to enforce that alternating physical chronology.
Blocks 01--08, 09, and 10 provide undefended train, validation, and clean-test
rows; all defended rows are locked inference-only.

An excluded 30-sample rehearsal—five workloads times two visits under
undefended, FRONT, and Tamaraw—must pass under the exact final
source/image/configuration before B01. It is sealed, verified, analyzed, and
exported only as the interface handoff
`handoffs/classifier-multiorigin5-v2-rehearsal/`; none of its rows enters model
training or evaluation. Every formal campaign is likewise sealed, verified,
and analyzed before acquisition advances. Only after all twenty formal
campaigns pass may the create-only Josh handoff
`handoffs/classifier-multiorigin5-v2/` be exported and verified. Josh's normal
model inputs are `traces/` or `stripped/`; raw PCAPs and receipts remain
restricted audit material. No old POC5 or multi-origin v1 row is eligible for
substitution after a failure.

Current status is implementation/qualification ready and v2 acquisition
pending. The final acquisition image, excluded rehearsal, 2,500 formal
captures, per-campaign analyses, and both handoffs are not yet complete. The
multi-origin v1 rehearsal, B01, P01, and P02 are superseded diagnostic evidence
and must never be mixed with v2. P02 exposed Cloudflare response-identity
drift, was stopped at a sample boundary, and remains unsealed.

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
- The multi-origin replacement improves graph and endpoint realism for
  Cloudflare and Hyper, but remains a five-graph closed-world experiment under
  an explicit approved-origin policy. It does not establish browser-wide or
  open-world generalization.
- FRONT and Tamaraw use fixed research-profile algorithms and do not consume a
  fitted artifact. Their client-only QCSD adaptations still require qualified
  chaff and strict runtime fidelity; "no fitting" does not waive those gates.
- Controlled local smoke fixtures validate mechanics before fitting; the
  checked-in external smoke instead requires the sealed fitted bundle and
  evaluates independent post-fit visits.
- The historical 42/126 engineering campaign remains explicitly on hold and is
  not combined with POC5.
