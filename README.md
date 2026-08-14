# QCSD lab

This repository is the experiment orchestrator for the QCSD Neqo fork. It has
one workflow: freeze a workload, expand a campaign into sequential samples,
capture each Neqo run directly, seal the evidence, and derive plots and a
report afterwards.

The lab does not maintain a second data-processing workflow. A workload is
simply a frozen graph of HTTPS requests. A visit is one execution of that
graph. A sample is one visit under one defence.

The active specification has no dataset, classifier, monitored/unmonitored,
open-world, split, or projection layer. Fitting and evaluation are separate
campaigns over independent visits of the same frozen workload definitions.

Docker is required for every public command. The Neqo source is the
`neqo-qcsd/` Git submodule.

## Commands

The public surface is deliberately limited to the forms documented below.

### `build`

```shell
./qcsd-lab build
```

Builds the collection image and the workload-preparation image from the current
lab checkout and Neqo submodule. There is no development-mode flag. Source
commits, dirty state, and patch hashes are embedded as provenance when the
checkout is not clean.

### `prepare`

```shell
./qcsd-lab prepare example https://example.com/ https://example.com
```

The arguments are a new workload ID, a page URL, and one or more explicitly
approved HTTPS origins. Preparation:

1. observes the page with Chromium;
2. removes unsafe or unapproved requests, sensitive headers, and credentialed URLs;
3. probes the retained requests with the same Neqo client used for capture;
4. checks repeated status, byte count, and body identity;
5. freezes the concrete request headers and dependency graph in
   `config/workloads/<id>.json`.

Preparation refuses to overwrite an existing ID. Chromium is not used during
measurement. There is no runtime header-policy switch: the exact safe headers
stored on each resource are the request input.

### `derive-chaff-prefix-specs`

```shell
./qcsd-lab derive-chaff-prefix-specs
```

Creates one atomic, create-only `config/chaff-prefix-specs/v2/` directory
containing the six standalone schema-2 prefix-pack specifications. The
specifications project the exact sealed schema-5 Walkie-Talkie numeric profiles
through the fixed sender-framing cell and frozen prepared manifests into
every-component activation and capacity stages. They do not consume live
response-qualification evidence or a schema-6 artifact. The source artifact
must have its sealed raw hash and the v2 destination must not already exist.

### `qualify-chaff`

```shell
./qcsd-lab qualify-chaff
```

Qualifies all six frozen workloads as one create-only transaction. For each
workload, three independent unshaped runs issue the exact qualified parallel
cohort, `max(5, required_chaff_streams)` and at most 20, using the frozen
selected same-origin resource and its existing `Accept`, `Accept-Encoding`,
and `Accept-Language` values in their original order. They derive one stable
response identity. Three separate production prefix-pack runs then prove every
moulded component's exact full-packet targets: cumulative application and
required-chaff requests pass through FIN, every required chaff-request STREAM
range and FIN is peer-acknowledged, and no targetless STREAM bytes are emitted.
The command
embeds the exact receipts in each sidecar and publishes all six files together
under `config/chaff-qualification-store/v2/`; any pre-publication validation or
network failure leaves that canonical directory absent. A failure after the
atomic rename can leave a complete canonical directory that requires explicit
audit. It requires the exact clean Lab/Neqo checkout and executable embedded in
the preparation image and does not use fitting or campaign samples.

The staged prefix proof broadly drains HTTP/3/QPACK output before its
transcript. At every activation gate, application and required-chaff request
output, request-causal HTTP/3 control output, and QPACK encoder output must all
be empty. Post-warmup client QPACK decoder-stream output is recorded but
excluded from that completion predicate because this fixed critical-stream
role is not a dependency of the already transmitted request prefix.

### `run`

```shell
./qcsd-lab run <campaign.yml>
```

Validates and freezes the campaign inputs, executes its samples, and prints the
new result directory. A run is successful only when every planned sample is
accepted and eligible. A terminal incomplete run is still retained and sealed
for diagnosis.

The checked-in `smoke.yml` defines the post-fit, 14-sample external evaluation:
Cloudflare QUIC and Bootstrap Introduction, one independent visit
each, the `as-defined` request policy, and all seven current defence modes. It
uses `research-1200`, the fixed seed `2026081204`, the mechanical
`static-control-1200.csv`, and the one create-only production bundle under
`artifacts/research-1200/`. The contract-5 predecessor is archived read-only at
`artifacts/research-1200-superseded-schema5-0a141768/`; it is verification-only
and rejected by current preflight. The canonical schema-6 bundle is published
from the sealed 120-sample fitting result and verifies. The independent result
at `results/research-smoke-1200/20260814T023209.708923Z` is complete: all 14
samples were accepted and eligible on their first attempt, with zero failures.
Both `verify` and `analyze` passed. The raw SHA-256 values of its
`evidence.sha256` and `experiment.json` are respectively
`59371aedf7dfa7ce289cce25766af763ede405d2f62527dc16c0d7882b42203a`
and `1cd8c415751736aa43677fac67f1bea666b941a47ae90d3658bf7cb2bf17d248`.

### `resume`

```shell
./qcsd-lab resume results/<campaign>/<run-id>
```

Continues one exact interrupted or incomplete result. Resume first checks the
frozen inputs, running source fingerprint, accepted sample hashes, and any
existing seal. It re-derives the campaign identity, purpose, limits, workload
records, defence bindings, seeds, and execution order from those frozen files;
editing and re-hashing `experiment.json` cannot change the run contract. It
never repeats accepted samples. If a successful attempt was
validated but interrupted around its atomic promotion, resume completes that
promotion from its recorded hashes without another network request. Otherwise
it removes only the partial working directory of an interrupted, unpromoted
attempt; completed failed attempts remain evidence.

`max_attempts` is the automatic retry budget for each invocation. An explicit
`resume` is a new operator-authorized retry epoch for still-incomplete samples;
accepted samples remain immutable. To avoid bypassing timing controls across a
process restart, every previously attempted origin waits one full configured
cooldown before the first resumed request.

### `verify`

```shell
./qcsd-lab verify <campaign.yml>
./qcsd-lab verify results/<campaign>/<run-id>
```

For YAML, `verify` is a non-executing preflight. It validates workload and
parameter files and prints the sample count and exact seeded execution order.
The checked-in `smoke.yml` now resolves the exact-six v2 qualification bindings
and current schema-6 bundle and preflights to exactly 14 samples. Reviewed
fixtures and the historical schema-5 artifact remain invalid substitutes.

For a result directory, `verify` checks the evidence index, exact authoritative
file set, every file hash, the experiment schema, frozen-input fingerprint,
the configuration re-derived from `inputs/campaign.yml`, each accepted
sample's artifact binding, and the external parameter receipts. Missing,
changed, additional, rebound, or path-escaping authoritative files fail
verification.

For `artifacts/research-1200`, `verify` requires the exact four-file fitted
bundle, checks the common provenance receipt and all artifact hashes, validates
source-result identity and sample contributions, requires exact Traffic
Morphing and Walkie-Talkie workload coverage, and runs the runtime-schema
checks. A fitted bundle is not a campaign result and does not have its own
`evidence.sha256`.

### `analyze`

```shell
./qcsd-lab analyze results/<campaign>/<run-id>
```

Verifies the sealed evidence, builds a complete replacement in a temporary
directory, and atomically replaces `derived/`. It creates:

- `summary.csv` with per-sample and paired-baseline metrics;
- deterministic SVG comparisons for every complete eligible paired visit;
- aggregate application-latency and wire-overhead SVGs;
- a self-contained `report.html` with its SVGs embedded.

The trace comparison preserves the tested QCSD view: incoming/outgoing
packet-time density, controller-action overlays, signed Ethernet-frame-size
scatter, an application-completion marker, and a shaded defence tail. No PDF
or qlog is produced. Deleting `derived/` and rerunning `analyze` reconstructs
it from `capture.pcapng`, `run.json`, and `schedule.csv` without modifying or
resealing evidence.

### `fit`

```shell
./qcsd-lab fit results/<fitting-campaign>/<run-id>
./qcsd-lab verify artifacts/research-1200
```

`fit` first fully verifies a complete sealed fitting result with exactly six
workloads, ten visits per workload, the `as-defined` and `half-duplex` request
policies in that order, only the undefended baseline, and the
`research-1200` profile. All 120 samples must be accepted and eligible.

It then deterministically and atomically creates exactly:

```text
artifacts/research-1200/
  traffic-morphing.json
  wtf-pad.json
  walkie-talkie.json
  provenance.json
```

The common `provenance.json` receipt hashes the three runtime files and binds
the source evidence, contributing samples, profile, ceiling, fitting decisions,
and workload coverage. It contains no timestamp or absolute path. An identical
rerun is idempotent; different content at the fixed destination is rejected.
The fitting result is never modified. No fitted research bundle exists until
this command succeeds against the real 120-sample result.

### `test`

```shell
./qcsd-lab test
```

Runs the deterministic Python suite in the collection image. It does not use
the public Internet or start a research campaign.

### `test live`

```shell
./qcsd-lab test live
```

Starts two controlled local HTTP/3 servers and runs the direct-capture
acceptance tests. This is the bounded networking gate for capture startup and
tail coverage, exact endpoint filtering, interface-offload checks, UDP-payload
ceiling enforcement, runner/PCAP reconciliation, and overlapping connections
to distinct origins within one sample. It exercises the canonical sealed
baseline workflow plus a direct, explicitly nonauthoritative schema-6
Walkie-Talkie wire check with test-local A/R/C inputs. It is not evidence for
the six-workload qualification, does not authorize a campaign artifact, and
does not consume public fitting visits or create research artifacts.

## Profiles

- `live` uses a 1200-byte ceiling and deliberately reduced FRONT, Tamaraw, and
  event limits for bounded smoke tests.
- `research-1200` copies every non-size value from the tagged published source
  profile and changes only the common UDP ceiling and every defence packet-size
  field from 1450 to 1200. FRONT remains 900/1200 packets over 0.1–2.5 seconds;
  Tamaraw remains 5/20 ms with modulo 100; published data-driven budgets remain
  unchanged. This is the study's explicit source-default 1200-byte adaptation,
  not an implicit CLI default.
- `published` retains the tagged source's 1450-byte settings for compatibility
  and controlled source comparison. Modern Neqo, different workloads, and a
  different network mean that selecting it is not an exact reproduction of the
  paper experiment or its results.

All campaign and parameter receipts use those exact spellings. A
`research-1200` schedule or artifact containing a 1201-byte target is invalid.

## Campaigns

A campaign has one schema:

```yaml
schema: 1
name: example
purpose: evaluation            # smoke, fitting, or evaluation
seed: 20260806
profile: research-1200         # live, research-1200, or published

workloads:                     # ID maps to visit count
  prepared-site-a-r1: 1        # evaluation/fitting require preparation receipts
  prepared-site-b-r1: 1

request_policies:
  - as-defined                 # or half-duplex

defenses:
  - undefended
  - front
  - tamaraw
  - name: static-control
    kind: static
    schedule: ../defense-params/static-control-1200.csv
    mode: chaff-only
  - name: traffic-morphing
    kind: traffic_morphing
    parameters: ../../artifacts/research-1200/traffic-morphing.json

limits:
  timeout_seconds: 120
  max_response_bytes: 1048576
  capture_seconds: 180
  capture_megabytes: 64
  max_attempts: 3
  per_origin_cooldown_seconds: 30
  settle_seconds: 1
```

Workload IDs resolve only through `config/workloads/<id>.json`. A workload
contains concrete resources: URL, safe request headers, dependencies, and
preparation provenance where available. It does not carry an evaluation role
or an implicit repetition count.

Purpose is an evidence constraint, not another execution engine. `smoke`
permits the checked-in reviewed fixtures, `fitting` is restricted to
undefended samples, and `evaluation` requires the sealed research bundle
whenever a data-driven defence is selected.

`as-defined` starts every request whose declared dependencies are satisfied.
That can create overlapping streams and connections. `half-duplex` additionally
waits for the current application stream to finish before starting another.
It is an execution policy, not a second workload format.

Static consumes a signed schedule file. The checked-in
`static-control-1200.csv` is four alternating 1200-byte events at 25, 30, 35,
and 40 ms. The 25 ms startup lead lets the asynchronous client provision its
chaff stream before the first exact slot. It is a mechanical schedule-loading
and direction control, not a fitted defence or effectiveness result. Traffic
Morphing, WTF-PAD, and Walkie-Talkie consume a JSON parameter file with an
adjacent receipt: smoke fixtures use `.provenance.json` beside each file,
while the research bundle uses one shared `provenance.json`. Campaign loading
validates these files, their defence/profile binding, and their hashes before
a network run, then freezes copies under `inputs/`. Reviewed engineering
fixtures are permitted only for a `smoke` campaign; an evaluation campaign
requires sealed fitted artifacts.
The fitted Walkie-Talkie source envelopes remain in the raw HTTP/3
request-stream cell domain, and pairing still minimizes the base symmetric
element-wise-mould padding cost. The runtime mould is a separate adaptation: it
adds one 1200-byte sender-framing cell to every positive outgoing component and
one 1200-byte receiver-continuation cell to every positive incoming component.
The sender cell carries QUIC/HTTP/3 STREAM framing and mandatory control
overhead that is absent from request-stream offsets. The receiver cell exceeds
the configured 1000-byte parser allowance and is held as a causal event rather
than eager ordinary credit.

The client provisions the exact workload-specific one-shot chaff cohort before
the first due moulded outgoing actions and never replenishes it. A chaff stream
becomes a continuation candidate only when its zero-required-insert-count,
nonblocking QPACK request has a positive final size and the complete,
gap-free request-stream range `[0, final-size)` plus FIN is peer-acknowledged.
Retransmitted and acknowledged offsets are union-deduplicated. Before the first
incoming base allocation, the latched survivor gate requires a
peer-acknowledged nonblocking survivor count of at least the total number of
remaining receiver continuations plus one. Distinct deterministic pristine
reserves cover every remaining nonzero incoming component and remain reserved
across later positive outgoing components until their corresponding
continuation is allocated.

A continuation is eligible only after issued base events have been requested,
their request signals observed, and any application-batch gate has opened. It
is normally released after all base events have been issued. It may be released
earlier when a real reported ordinary nonreserved-capacity snapshot is below
one full cell, including zero; an unknown snapshot never enables early release.
Allocation then follows the same coalesced-tail-or-oldest-reserve rules below,
while the corresponding oldest reserve is discharged exactly once. This closes
the reserve-capacity deadlock while retaining base-first behavior whenever at
least one ordinary full cell is available. The initial survivor gate still
applies before either early continuation or base allocation.

Every retry recomputes live unconsumed base debt. When exactly one
peer-acknowledged nonreserved header-phase chaff stream carries a positive debt
at or below the parser ceiling, an already advertised tail is extended in
place. If the same exact tail is awaiting its `MAX_STREAM_DATA` advertisement,
the continuation and oldest reserve are retained until that advertisement is
observed, after which the same stream is extended. Otherwise the whole cell is
released to the oldest retained peer-acknowledged pristine reserve regardless
of unrelated live base debt. Split or ledger-inconsistent tails are
ineligible, and each corresponding reserve is removed exactly once.

Ordinary base receive allocation exhausts application streams before
peer-acknowledged nonreserved controlled chaff streams; exact capacity precedes
bounded provisional framing claims. A reserve is excluded from ordinary
capacity until release. If a reserve is lost, allocation holds while the
horizon is deterministically reconstituted from an eligible peer-acknowledged
pristine member of the already provisioned cohort; it fails closed only when no
eligible replacement remains. No new request replenishes the cohort, and the
contract promises neither targetless request retransmission nor generic
post-loss liveness. Retryable unadvertised continuation rollback or requeue
restores the corresponding all-future reserve before further base allocation.

The initial priority-aware selector binds a known-valid same-origin selected
source resource; its derived chaff projection is dependency-free and has exact
qualified body capacity. Campaign loading binds the prepared workload and
runtime rechecks endpoint-relative eligibility. Three independent response
qualifications use `max(5, required_chaff_streams)` parallel requests to bind
the response identity and body length. Three independent schema-2 prefix
qualifications prove every component's exact sender-framed targets, cumulative
application and one-shot chaff requests through FIN, peer acknowledgement of
every required chaff-request STREAM range and FIN, and zero targetless STREAM
bytes. These bytes are runtime-only falsification evidence and never enter
fitting.

Parser consumability and source-envelope bounds remain runtime fail-closed
preconditions. FRONT additionally avoids stranding a final partial receive
slot: for a `ChaffOnly` schedule whose incoming side is proven complete, the
last untouched whole slot prefers a peer-acknowledged pristine chaff stream
with a full cell of exact capacity. This changes no capture-clock acceptance
rule. FRONT and Tamaraw remain profile-generated and have no external fitted
files.

Reported Walkie-Talkie runtime padding cost and scheduled bytes include both
sender-framing and receiver-continuation cells. The base symmetric pairing
objective is unchanged, but the adapted runtime mould and cost are not the
historical schema-5 values. Neither qualification evidence nor the controlled
wire smoke establishes a general HTTP/3 property or defence effectiveness.

Only fields shown by the schema are accepted. Campaigns do not carry dataset,
classifier, monitored/unmonitored, open-world, split, projection, or runtime
header-policy settings, and command behavior is not embedded inside the YAML.
A campaign with several defences must include exactly one
undefended baseline so response identity and overhead can be paired. A
single-defence campaign is valid for capture mechanics, but cannot produce a
paired comparison unless its prepared workload supplies the expected response
identity.

## Workload catalogue and research cohort

The workspace-level [`results.zip`](../results.zip), SHA-256
`103a82cb95eaa305e38b0084ba16744429b273146be80ab05c7653d52bf66b11`, is a
catalogue of 17 Chromium-observed request graphs from the retired discovery
workflow. It is not a lab result, fitting corpus, or accepted campaign input. Its historical
`header_policy` and replay records describe how candidates were observed; they
do not reintroduce runtime header policies into the consolidated lab.

`prepare` promotes a candidate only after origin filtering and three stable
undefended Neqo runs. Each run must resolve the exact 1200-byte UDP-payload
ceiling, produce valid runner packet evidence in both directions, and contain
no UDP payload above 1200 bytes, including handshake traffic. The frozen
preparation receipt records the packet-file SHA-256 plus incoming, outgoing,
and total packet counts, maxima, and oversized counts for every run. Research
validation requires that exact receipt; older manifests remain readable but
are not research inputs.

A case-insensitive Chromium-header merge correction made the earlier `-r1`
manifests ineligible for research because they contained duplicate header
names. The `-r2` manifests then predated absolute whole-run UDP qualification:
their application traffic used a 1200-byte configuration, but their receipts
did not prove that every handshake and application datagram respected that
ceiling. Both generations remain historical preparation evidence only.

The frozen research adaptation cohort was therefore prepared from the clean,
corrected image as six new `-r3` workloads. Each preparation passed three
stable undefended Neqo runs and recorded zero datagrams above 1200 bytes over
the complete packet ledger:

| Workload | Resources | Prepared-manifest SHA-256 |
|---|---:|---|
| `getbootstrap-home-r3` | 9 | `863638bb6bf7a27c2a4e9184dcb9c3db8d748af1e0da1b875d24a21233b92ca2` |
| `bootstrap-introduction-r3` | 9 | `e228029e7c987c63f8218e5471375e62e6d4557825bc6c4c0cb4bbfa0be6c16b` |
| `apache-traffic-server-docs-r3` | 18 | `8f4fa9b10c4488ff99d30e7ac8b2b784867416c84635afe96b9c4ef45ab71ecd` |
| `nginx-quic-r3` | 11 | `56ddd2eee52affc59d0062c83b49e2fd435d0fe9ca40f4f0b30e65c156e7ef09` |
| `cloudflare-quiche-r3` | 1 | `e608366c95d6902234b4a705043435b3868f9572bcb8e103feb71db3110cbacc` |
| `nghttp2-ngtcp2-r3` | 8 | `a871e1d783b52a79fb1f72761ea2771fced38ba408fbed0896a3c280d20927f1` |

The final preparation pass rejected these candidates without weakening the
qualification gates:

| Candidate | Rejection |
|---|---|
| Behance | Whole-capture UDP payload maximum was 1452 bytes. |
| Chromium project pages | A pre-handshake Initial datagram was 1280 bytes. |
| aioquic | The endpoint refused the preparation connection. |
| Guardian | Whole-capture UDP payload maximum was 1280 bytes. |
| R10 | Exact response identity was unstable across the three runs. |
| TeamViewer | The retained assets were orphaned from the source/final navigation root. |

NGINX QUIC and Bootstrap Introduction passed after those rejections and were
promoted. The cohort contains six unique request graphs over five distinct
origins: the two Bootstrap graphs share an origin and many static assets. That
correlation can make their fitted distance or mould-padding cost smaller than
for independent sites, so this is explicitly a reproducible QCSD adaptation
cohort, not six independent websites or a representative sample of the
rejected population. Fitting and later evaluation reference the same frozen
files and hashes but execute independent network visits; fitting traces are
never reused for evaluation.

## Execution order and concurrency

Expansion is deterministic:

```text
workload declaration order
  -> request-policy list order
    -> visit 0..N-1
      -> seeded shuffle of the configured defences
```

The sample count is:

```text
sum(workload visit counts) * number of request policies * number of defences
```

Samples are executed one at a time. A sample is one Neqo page-load process and
one PCAP. Inside that sample, Neqo owns one connection per distinct origin;
connections and ready request streams can progress simultaneously. The
orchestrator does not merge those origins into separate samples and does not
run two samples concurrently. Per-origin cooldowns are applied between samples
and conservatively restarted for previously attempted origins after `resume`.

The seed freezes defence order and per-sample defence randomness. It does not
make independent live network responses identical. Eligibility instead checks
that delivered response identity matches the undefended member of the same
workload, policy, and visit.

## Result contract

This working copy's `results/` directory may also contain two explicitly
documented historical snapshots from the retired workflows. See
`results/README.md`; they are preserved data, not supported result formats, and
no active command writes them.

```text
results/<campaign>/<run-id>/
  experiment.json
  evidence.sha256
  inputs/
    campaign.yml
    source.json
    workloads/
      <workload>.json
    runtime-workloads/
      <selected-workload>.json
    chaff-prefix-specs/
      <workload>.json
    chaff-qualifications/
      <workload>.json
    chaff-manifests/
      <workload>.json
    defense-parameters/
      <defence>/
        schedule.csv | parameters.json
        provenance.json
  samples/
    <workload>/<policy>/visit-000/<defence>/
      capture.pcapng
      neqo/
        run.json
        packets.csv
        events.csv
        schedule.csv
  failures/
    <sample-id>/attempt-001/
      ... diagnostic working evidence ...
  derived/
    summary.csv
    plots/
      aggregate-latency.svg
      aggregate-overhead.svg
      <workload>/<policy>/visit-000/trace-comparison*.svg
    report.html
```

Every remaining file has one job:

- `experiment.json` is the sole experiment receipt and state machine. It owns
  provenance, frozen configuration, exact execution order, sample identity,
  attempts, state, eligibility, failures, diagnostics, accepted artifact
  hashes, and totals.
- `evidence.sha256` is the terminal SHA-256 index. SHA-256 is a content
  fingerprint: changing one covered byte changes the expected digest. The
  index exactly covers `experiment.json`, `inputs/`, `samples/`, and
  `failures/`; it deliberately does not cover itself or `derived/`.
- `inputs/campaign.yml` is the exact campaign submitted to the run.
- `inputs/source.json` records the exact collection-image ID, lab and Neqo
  commits, and dirty/patch provenance used by resume.
- `inputs/workloads/*.json` are the exact prepared graphs supplied to the
  campaign. They are kept once, rather than copied beside every sample.
- `inputs/runtime-workloads/*.json` are the exact stripped runnable graphs for
  the campaign-selected workloads.
- `inputs/chaff-prefix-specs/*.json`, `inputs/chaff-qualifications/*.json`, and
  `inputs/chaff-manifests/*.json` freeze the exact schema-6 Walkie-Talkie
  qualification cohort and its derived runtime projections.
- `inputs/defense-parameters/**` contains the exact external schedule or
  parameter/provenance pair selected by the campaign. Directly configured
  defences create no directory here.
- `capture.pcapng` is the direct Ethernet evidence, filtered after collection
  to the exact bidirectional endpoint tuples reported by Neqo.
- `neqo/run.json` is the runner receipt: resolved configuration, endpoints,
  response identity, completion, timing, and defence diagnostics.
- `neqo/packets.csv` is Neqo's transport-datagram record used to reconcile the
  runner with the independently captured PCAP.
- `neqo/events.csv` records ordered runner, application, and controller events
  needed to interpret completion and defence behavior.
- `neqo/schedule.csv` records one terminal row per scheduled slot and its
  observed realization. `target_time_us` is the defence's requested time;
  `action_time_us` is the first adapter action issued for that slot, including
  an owned parser-liveness lease, while the terminal event remains available
  in `events.csv`. It provides plot overlays and fidelity metrics.
- `failures/<sample-id>/attempt-NNN/` retains logs, partial captures, runner
  output, and other diagnostics produced by a completed failed attempt. The
  exact contents depend on the failure stage; the structured current failure
  is in `experiment.json`.
- `derived/summary.csv` is the reproducible metrics table.
- `derived/plots/**/*.svg` are reproducible vector figures.
- `derived/report.html` is the reproducible, self-contained report and links
  back to authoritative sample files.

An accepted sample contains exactly the five listed files. There is no
`sample.json`, fidelity sidecar, JSONL index, resolved-workload duplicate,
normalized-trace copy, PDF, secondary index, or qlog.

## Capture, acceptance, and recovery

For every attempt the collector follows this boundary:

```text
start dumpcap -> start Neqo -> application completes -> defence tail
  -> settle interval -> stop dumpcap -> filter to Neqo endpoint tuples
```

An attempt is promoted only after direct-capture validation, endpoint-count
validation, response completion, interface GRO/GSO/TSO/USO evidence,
profile-wide UDP-payload-ceiling checks, and bounded runner/PCAP reconciliation.
The paired visit then adds response-identity and defence-realization checks.
Failed attempts stay under `failures/`; a successful attempt is moved once to
the canonical sample path and is not duplicated.

`experiment.json` is checkpointed atomically. Accepted files are independently
bound by hashes before the terminal seal is written. A successful attempt's
diagnostics and prospective artifact hashes are checkpointed before its exact
five-file directory is atomically installed. Resume can therefore finish an
interrupted promotion without recollection. Verified accepted work is reused;
only a genuinely partial, unpromoted working attempt may be discarded.

See [METHODOLOGY.md](METHODOLOGY.md) for the scientific interpretation of the
observer, pairing, fidelity, and derived metrics.

## Research readiness and final hold

The post-fit 14-sample evaluation and 120-sample fitting campaign definitions
are checked in, and their completed results are sealed locally. The six-workload
fitting cohort is frozen. The research definitions and their exact expansions
are:

- fitting: six workloads × ten visits × two request policies × undefended =
  120 samples;
- post-fit smoke: two workloads × one visit × one request policy × seven modes
  = 14 samples;
- pre-final rehearsal: six workloads × one visit × one request policy × seven
  modes = 42 samples;
- final: six workloads × three visits × one request policy × seven modes =
  126 samples.

The implementation goal established the profiles, preparation policy,
fitters, runtime realization, campaign contracts, and evidence boundaries.
The completed sequence was:

```shell
./qcsd-lab test live
./qcsd-lab run config/campaigns/fitting.yml
./qcsd-lab verify results/research-fitting-1200/20260812T130241.322364Z
./qcsd-lab verify artifacts/research-1200-superseded-schema5-0a141768
./qcsd-lab derive-chaff-prefix-specs
# Commit the final qualification code, Neqo gitlink, and six specs as clean Q.
./qcsd-lab build
./qcsd-lab qualify-chaff
# Commit the exact six v2 qualification sidecars.
./qcsd-lab fit results/research-fitting-1200/20260812T130241.322364Z
./qcsd-lab verify artifacts/research-1200
# Rebuild from the sidecar commit before evaluation capture.
./qcsd-lab build
./qcsd-lab verify config/campaigns/smoke.yml
./qcsd-lab run config/campaigns/smoke.yml
./qcsd-lab verify results/research-smoke-1200/20260814T023209.708923Z
./qcsd-lab analyze results/research-smoke-1200/20260814T023209.708923Z
```

`test live` is a bounded baseline/direct-wire mechanics gate, not a substitute
for the exact-six qualification transaction. The sealed fitting result contains
120 accepted and eligible samples. The current schema-6 bundle verifies, and
the checked-in smoke evaluated the fitted defenses on new Internet visits:
`20260814T023209.708923Z` is verified and analyzed with 14/14 accepted and
eligible, zero failures, and every sample accepted on its first attempt.

The superseded runtime-falsification evidence is locally preserved and
manifest-sealed at
`results/chaff-qualification-diagnostics/q7-b19cb04-7ebcdb0-schema6-203eee42-runtime-falsification/`.
Its outer manifest SHA-256 is
`4ee68a930a344dc0e5874279e09069f92935a2f4f42bc7bb7e88077153b85aa9`;
its manifest is bound by the v2 receipts, while its bytes are not positive
qualification or fitting input. This goal did **not**
define or execute the 42-sample rehearsal or 126-sample final campaign. Both
remain explicitly on hold and require later authorization.
