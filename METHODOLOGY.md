# Capture Methodology

## The two questions this lab answers

The lab uses one campaign contract and one collection pipeline, but it supports
several small campaign recipes and two capture modes because replay scope and
observer location answer different research questions.

1. **Direct diagnostics:** did a QCSD defense create the intended packet shape?
   The lab observes the exact QUIC flow on container `eth0`. This isolated view
   is excellent for comparing the produced trace with Neqo's schedule, but it
   exposes origin IP addresses and therefore cannot support the main privacy
   claim.
2. **WireGuard classification:** can a passive network observer still identify
   the requested page after the defense is applied? The lab observes only the
   encrypted UDP flow between the client and a WireGuard gateway. This is the
   authoritative classifier view.

![WireGuard threat model showing the mode-dependent diagnostic tap before encapsulation and the authoritative passive observer on the encrypted outer flow](docs/assets/threat-model.svg)

*Figure 1: Teal marks the pre-encryption diagnostic tap: `wg0` during a
WireGuard run or container `eth0` during a direct run. Amber marks the
WireGuard-only classifier-facing tap and passive observer. Direct mode omits
the tunnel, gateway and amber tap. [TikZ
source](docs/diagrams/threat-model.tex).*

WireGuard is a VPN tunnel. The client wraps its already encrypted QUIC packets
inside a second encrypted UDP flow addressed only to the gateway. The gateway
removes that wrapper and forwards DNS and HTTP/3 traffic. An observer on the
client-to-gateway link can measure packet size, relative timing, direction, and
the known sample boundary, but it cannot see which origin the inner QUIC flow
uses. This is a standard network-traffic-classification model: the attacker
classifies metadata available on an encrypted link rather than plaintext.

The attacker may obtain labelled training traces collected under the same
defense. It may use only:

- relative packet time;
- outgoing or incoming direction;
- the declared observed length;
- the equivalent signed-length sequence.

Destination addresses, plaintext, TLS or WireGuard keys, qlogs, Neqo events,
response hashes, resolved defense parameters, and schedules are prohibited
classifier features. Loads are sequential and do not include unrelated user
traffic. The passive observer is assumed to know the page-load boundary; this
is a deliberately strong attacker assumption used consistently for every
defense.

WireGuard mode can also capture inner QUIC on `wg0`. That trace answers the same
mechanism question as direct mode but is auxiliary. A failed auxiliary capture
does not discard a valid outer trace. Direct `eth0` has an Ethernet header,
whereas `wg0` has a Raw-IP link type; both use `frame.len`, but the numeric
lengths are not interchangeable. The outer trace uses `udp.length`.

## From workloads to classifier samples

The following terms describe the complete data model.

- A **workload** is one frozen page/request definition, such as
  `cloudflare-quiche`.
- A **planned visit** is one requested repetition of that workload, such as
  “cloudflare-quiche, visit 3.” No network request has happened yet.
- A **defense sample** is the actual page load for that visit under one defense.
- A **paired visit** is the set of samples with the same workload and repetition
  across all defenses.
- A **split** is the train/test assignment attached to the paired visit. Every
  defense sample in the pair receives the same assignment.

![Worked example in which workload A visit 3 expands into three defense samples that share one TEST assignment and feed separate classifiers](docs/assets/dataset-flow.svg)

*Figure 2: “Workload A, visit 3” is loaded independently under Undefended,
FRONT, and Tamaraw. The shared split prevents the same visit appearing in both
training and testing through different defense variants. [TikZ
source](docs/diagrams/dataset-flow.tex).*

Each sample is eligible when Neqo succeeds, its primary capture validates, and
its delivered responses match the undefended sample for that paired visit. The
paired visit is usable for classifier comparison only when every configured
defense sample is eligible. If one defense fails or content changes, the whole
pair is excluded from classifier accuracy comparison, but every attempt remains
in failure, drift, latency, and bandwidth statistics. The collector never
silently substitutes a different page.

One deterministic, stratified 80/20 split is computed before collection.
Assignment is by `visit_id`, so retries and defense variants cannot cross
partitions. Small pilot strata may only approximate 80/20 because a visit
cannot be divided. Genuine time-separated evaluation requires collection at a
later time and is deferred to P5; P3 does not label a hash ordering as temporal.

The public campaign distinguishes:

- **monitored workloads**, which are named target classes collected repeatedly;
- **unmonitored workloads**, distinct pages outside those target classes;
- an **open-world view**, containing both roles and asking whether a trace is a
  monitored target (and, if so, which one);
- a **closed-world view**, filtering the same assignments to monitored classes
  only.

These are views of one collected dataset, not duplicated captures.

### Campaign recipes and replay scope

The campaign is supplied by name; the collector does not look for a hard-coded
`campaign.json`. A checked-in YAML recipe is input, while `campaign.json` is the
resolved, immutable receipt written into that particular result root:

```text
campaign recipe → shared workload graphs + visits + defenses + replay scope
replay scope    → as written, final-page origin only, or all reviewed origins
capture flag    → direct diagnostic or WireGuard classifier observer
```

The single-resource recipe preserves the earlier engineering workload. The
Dconn and Dmc recipes deliberately reference the same two browser-discovered
page graphs and the same repetition counts. `primary-origin` removes resources
outside the final page's origin and cleans their dependency edges, producing a
one-origin, multi-resource Dconn-aligned graph. `all-reviewed-origins` retains
the reviewed cross-origin graph and requires at least two origins, producing a
Dmc-aligned graph. The resulting graphs use the same planner, runner, defenses,
capture code, validation, and reporting; they are not separate collection
systems.

Chromium participates only during graph discovery. It loads the page, waits for
a fixed bounded settling period, and records candidate HTTPS GET dependencies.
A reviewer explicitly allows origins, Neqo probes each candidate independently
for HTTP/3 availability, and the frozen result becomes the replay input. During
the measured sample, Chromium is absent: Neqo/QCSD requests every retained
resource according to the cleaned dependency graph.

Replay preflight then makes three complete undefended graph loads, with a
30-second cooldown between them. It seals the resource IDs whose status, byte
count, and body hash remain identical. Dconn and Dmc resolution rejects any
retained resource without this evidence. This is an early stability screen,
not a guarantee that a live site cannot change later; collection still records
and rejects paired content drift.

The minimal replay pilots contain two monitored page classes and three visits
per class. Each scope therefore plans six paired visits and 18 defense samples
under Undefended, FRONT, and Tamaraw. They contain no unmonitored pages, so they
can test collection mechanics and later support a tiny closed-world smoke test,
but they cannot measure open-world false positives or support a classifier
effectiveness claim.

### Minimal Dmc live-pilot evidence

The 2026-07-21 local-WireGuard run
[`20260721T054209Z`](results/20260721T054209Z/report.html) exercised the Dmc
recipe without running Dconn. All 18 planned defense samples produced valid
outer-WireGuard and inner-QUIC captures on their first attempt, and every run
opened the expected two HTTP/3 endpoints. The Chromium graph retained nine
resources; the Google graph retained 17. The standalone dataset validator
reproduced and accepted the sealed capture/trace contract.

The run is intentionally recorded as **incomplete**, not presented as a
classifier dataset. Nine samples matched their paired undefended response and
nine drifted, leaving no paired visit with all three defenses eligible. The
causes were distinct:

- all three Chromium FRONT executions returned a partial application result:
  the first resource failed and its dependency descendants were closed;
- all Google resources completed under every defense, but the live top-level
  document body changed between sequential loads, causing FRONT and Tamaraw to
  differ from their visit baseline.

The first issue exposed both a collector error and a transport interoperability
hole. The collector had accepted a zero runner return code even when
`completion_status` was `partial`; it now requires `complete` plus a successful
outcome for every application resource. At the transport layer, the Chromium
server reported `STREAM_DATA_BLOCKED` at its original 16-byte receive limit
after Neqo had advertised and the server had acknowledged a 1 MiB
`MAX_STREAM_DATA`. Automatic flow control believed no new credit was needed and
did not repeat the current limit, so the application stream idled out. Neqo now
re-advertises its current larger limit when a peer reports an obsolete blocked
limit. A focused FRONT replay completes all nine Chromium resources after this
change.

The Google failure was not caused by FRONT or Tamaraw: every resource completed,
but the top-level HTML genuinely changed on sequential requests. Probe now
performs the repeated response-stability gate described above. The future pilot
recipe uses the qualified Chromium QUIC and Chromium Projects graphs; both
passed all retained resources across three cooldown-separated loads. The old
Google graph and the sealed failed pilot remain unchanged audit evidence. No
second live campaign has been run.

The run took 788.5 seconds (82.18 samples/hour), made 234 application requests,
delivered 7.22 MB, and retained 23.77 MB of dual PCAPNG plus 0.83 MB of observer
traces. Extrapolating this two-page mix to 20,000 visits per defense across the
three configured defenses gives 30.42 sequential days and approximately 41.58
GB of outer PCAPNG, 37.65 GB of inner PCAPNG, and 2.78 GB of normalized traces.
Those are capacity estimates only; the pilot's content drift, local gateway,
two classes, and missing unmonitored population prevent effectiveness claims.

## Capture boundary and validation

Tunnel setup and warm-up happen before a sample. The observable sample is:

```text
capture start → application load → defense tail → settle interval → capture stop
```

Captures are not trimmed using qlogs or Neqo events. Direct captures are
post-filtered to exact Neqo endpoint tuples. Outer captures use the exact
WireGuard peer and client/gateway ports. Empty, truncated, wrong-link-type,
direction-indeterminate, or irreproducible primary captures fail validation.
Every normalized CSV is reproduced from its PCAPNG using its declared length
basis and direction rule.

Live manifests require explicit review and permit only safe credential-free
HTTPS GET definitions. Chaff is same-origin, requests are sequential, an origin
receives at least a 30-second cooldown, and response/capture/retry limits are
sealed into provenance. The tunnel has no persistent keepalive during samples.

## Alignment with the QCSD study

The design follows Smith et al., [“QCSD: A QUIC Client-Side Website-
Fingerprinting Defence Framework”](https://www.usenix.org/system/files/sec22-smith.pdf)
and its [v1.0.1 experiment artifact](https://github.com/jpcsmith/qcsd-experiments/tree/v1.0.1).

### Original QCSD workload models

The original study separated three workload models. These names describe how
application traffic was produced; they do not describe different observer
locations. All three were evaluated from the aggregate WireGuard flow.

| Model | Workload execution | Connections/resources | Defenses | Corpus per setting |
|---|---|---|---|---:|
| `Dconn` | Neqo/QCSD test client replayed a browser-derived dependency graph | Same-origin resources over one QUIC connection | Undefended, FRONT, Tamaraw | 100 × 100 monitored + 10,000 unmonitored = 20,000 |
| `Dmc` | Neqo/QCSD test client replayed a browser-derived dependency graph | Cross-origin resources over multiple QUIC connections | Undefended, FRONT, Tamaraw | 100 × 100 monitored + 1,000 unmonitored = 11,000 |
| `Dfull` | Chromium loaded the real page while a separate QCSD connection added cover traffic | Browser QUIC/TCP traffic plus QCSD FRONT chaff | Undefended and FRONT only | 100 × 100 monitored + 10,000 unmonitored = 20,000 |

The browser-derived, multi-resource replay is therefore the modern counterpart
of `Dmc` when it retains multiple reviewed origins and Neqo opens multiple
connections. The same frozen graph restricted to its final-page origin is
`Dconn`-aligned. The two qualified Chromium-site replay graphs provide a minimal
executable example of both scopes; their common host makes them an engineering
pilot rather than a diverse classifier corpus. The older single-resource
recipe still demonstrates collection machinery only.

`Dfull` requires a genuine browser during trace collection. The original study
evaluated only FRONT in this setting because its separate QCSD connection could
add FRONT chaff alongside Chromium but could not delay or reshape Chromium's
genuine packets as Tamaraw requires. Such a sidecar would therefore not produce
a Tamaraw-shaped browser load.

This methodology uses **`Dmc`-aligned replay** for the planned common
cross-defense workload. It reserves **`Dmc` parity** for a demonstrated
replication that has passed resource and timing coverage, replay-fidelity, and
geographic-network requirements. Likewise, `Dfull` remains reserved for
browser-driven loads rather than any multi-resource Neqo run.

| Dimension | Original QCSD | P3 |
|---|---|---|
| Primary observer | WireGuard UDP flow on host `docker0`, selected by a unique tunnel port | Exact outer WireGuard flow on client-container `eth0` |
| Trace | Relative timestamp and signed `udp.length` | Relative nanoseconds, direction, length, and signed length; outer basis remains `udp.length` |
| Dataset shape | 100 monitored domains × 100 instances plus an unmonitored population whose size depended on the setting | The contract supports the same roles; the minimal replay pilot has only two monitored classes × three visits and makes no classifier claim |
| Split | Stratified random 80/20 | One deterministic paired-visit 80/20 split; genuine later-time evaluation is deferred to P5 |
| Network diversity | Three geographic VPN regions | Named gateway/network condition; the local gateway is engineering evidence, not equivalent geographic evidence |
| Reproducibility | Restartable collection and retained classifier traces | Preplanned IDs/splits, PCAPNG, normalized traces, provenance, attempts, drift, projections, and sealed hashes |

The interface name differs because P3 captures inside an isolated client
container rather than on the host bridge, but both authoritative views observe
the same methodological layer: encrypted WireGuard datagrams before gateway
decapsulation. The direct Docker view is additional mechanism evidence.

P3 exports variable-length time/direction/size sequences compatible with
encrypted-traffic attacks such as [Deep
Fingerprinting](https://arxiv.org/abs/1708.06376) and
[Var-CNN](https://arxiv.org/abs/1802.10215). P5 will perform feature extraction
and train one attacker separately for each defense while keeping paired-visit
membership and splits identical. Defended performance is compared with the
undefended baseline alongside failures, content drift, latency, and bandwidth.

The Neqo runner now executes the retained multi-resource dependency graph over
one or several HTTP/3 origins. This establishes the minimal `Dconn`-/`Dmc`-
aligned replay surface, not parity: explicit browser request offsets and
priorities, measured browser-versus-replay coverage, matched Chromium reference
traces, and geographic network diversity remain outstanding. It does not
reproduce browser-driven `Dfull`. Remote gateways and a separate
storage-retention decision remain prerequisites for QCSD-scale paper claims.

## Interpreting the 28.79-day estimate

An earlier sealed four-defense pilot measured 115.79 sequential defense samples
per hour. Its recorded reference projection was:

```text
20,000 visits/defense × 4 defenses = 80,000 defense samples
80,000 ÷ 115.79 samples/hour = 690.9 hours = 28.79 continuous days
```

This means one collector running samples one after another for 28.79 days. It
is not a required timeout or a command that was started. It assumes the pilot
workload mix and safety delays, one local gateway, no retries, and uninterrupted
operation. Geographic replication would increase work; independently safe
collectors could reduce wall time. The replay pilots have three defenses, so a
new projection uses their measured throughput and configured defense count
rather than copying the old four-defense number.

## Release surface

Research roots retain qlogs, response signatures, endpoint tuples, resolved
defense configuration, and failed attempts for validation. They are not
classifier features. Publication packaging requires a valid WireGuard dataset
and explicit data license, exposes only the selected outer PCAP/normalized
traces and sanitized metadata, and never includes keys, qlogs, events,
schedules, responses, endpoints, or attempts. Direct datasets validate as
diagnostic evidence but cannot be publication-packaged as privacy evidence.
