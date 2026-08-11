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
frozen.

Each retained resource contains its concrete safe request headers and explicit
dependencies. The measurement runner receives those values directly. It does
not reinterpret a browser-header policy at runtime.

This design makes a one-resource fetch and a complex page graph the same kind
of input. The difference is only the content of `resources`:

- URL and origin;
- concrete request headers;
- dependencies that must complete first;
- expected preparation response identity and provenance.

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

Research use requires deterministic fitters and a sealed artifact receipt that
identifies all source evidence and decisions. That implementation is deferred
to the next goal; the consolidated lab does not expose a placeholder command
whose output might be mistaken for a valid fitted artifact.

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
- Smoke fixtures validate mechanics, not fitted-defence effectiveness.
- The final 126-sample capture is explicitly on hold. It must follow fitted
  artifact validation and the separate 42-sample pre-final rehearsal.
