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

The public surface is deliberately limited to these nine forms.

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

### `run`

```shell
./qcsd-lab run <campaign.yml>
```

Validates and freezes the campaign inputs, executes its samples, and prints the
new result directory. A run is successful only when every planned sample is
accepted and eligible. A terminal incomplete run is still retained and sealed
for diagnosis.

The checked-in `smoke.yml` is a post-fit, 14-sample external evaluation:
Cloudflare QUIC and Bootstrap Introduction, one independent visit
each, the `as-defined` request policy, and all seven current defence modes. It
uses `research-1200`, the fixed seed `2026081204`, the mechanical
`static-control-1200.csv`, and the one sealed production bundle under
`artifacts/research-1200/`. The bundle was derived from the sealed 120-sample
fitting result and must verify before this independent smoke can run.

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
Before production fitting, verifying the checked-in `smoke.yml` fails because
its required sealed research bundle does not yet exist; that is its expected
pre-fit state, not permission to substitute the reviewed live fixtures.

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
to distinct origins within one sample. It exercises all defended runtime modes
with controlled workload-bound fixtures and is the defended **pre-fit** gate;
it does not consume public fitting visits or create research artifacts.

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
request-stream cell domain. Pairing minimizes the base symmetric
element-wise-mould padding cost; the runtime mould then adds one 1200-byte
incoming cell to every nonzero incoming component. That explicit adaptation
provides more headroom than the configured 1000-byte parser allowance. The
final cell is held causally: it is released only after every base event has
been requested by the controller and every corresponding request signal has
been observed. At a moulded batch end, release also waits for
application-batch completion. The complete 1200-byte cell is then assigned to
one pristine header-phase controlled chaff stream; it is neither split across
streams nor assigned to an active application stream.

Both candidate branches require a controlled chaff stream in
`ReceivingHeaders`, with zero bytes consumed, requested equal to advertised,
and no more than the parser ceiling. It must have no terminal status, framing
bytes, parser-lease use, or prior/pending parser boundary; its reservation must
be wholly available, and its exact known capacity after requested bytes must be
at least 1200. Provisional framing claims are ineligible. Every allocation
retry recomputes live unconsumed base bytes from the prior credit ledger,
excluding the held continuation slot, and requires that value to be no greater
than 1000. If it is positive, the candidate is a header-blocked stream with
requested and advertised greater than zero, and all live outstanding must be
coalesced there: its advertised-minus-consumed amount must exactly equal the
live ledger value. The cell extends that stream. If the live value has drained
to zero, the candidate is instead an untouched header-phase stream with
requested, advertised, and consumed all equal to zero. A split or
ledger-inconsistent positive base tail is not eligible.

This liveness contract is conditional on the prepared stream having at least
1200 exact additional available bytes and its first `prior_requested + 1200`
raw response bytes being consumable. The fitting inputs contain
application-stream observations and do not observe runtime-created chaff
prefixes, so they cannot prove that precondition or a general HTTP/3 property.
It is explicitly scoped to the frozen prepared cohort and reviewed live
fixture, and a runtime violation is fail-closed and fidelity-ineligible.
Source-envelope overflow likewise fails the strict fidelity gate. No
FIN-residual reallocation or fragment-coalescence claim is part of this
contract. Reported runtime padding cost and scheduled bytes still include the
added continuation cells, so the numeric mould and pairing objective are
unchanged.
FRONT and Tamaraw are generated from the selected QCSD profile and therefore
do not have external fitted files.

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

The post-fit 14-sample evaluation smoke and the 120-sample fitting campaign are
checked in. The six-workload fitting cohort is frozen. The research definitions
and their expected expansions are:

- fitting: six workloads × ten visits × two request policies × undefended =
  120 samples;
- post-fit smoke: two workloads × one visit × one request policy × seven modes
  = 14 samples;
- pre-final rehearsal: six workloads × one visit × one request policy × seven
  modes = 42 samples;
- final: six workloads × three visits × one request policy × seven modes =
  126 samples.

The implementation goal established the profiles, preparation policy,
fitters, runtime realization, campaign contracts, and documentation. The
active sequence is:

```shell
./qcsd-lab test live
./qcsd-lab run config/campaigns/fitting.yml
./qcsd-lab verify results/research-fitting-1200/<run-id>
./qcsd-lab fit results/research-fitting-1200/<run-id>
./qcsd-lab verify artifacts/research-1200
./qcsd-lab verify config/campaigns/smoke.yml
./qcsd-lab run config/campaigns/smoke.yml
./qcsd-lab verify results/research-smoke-1200/<run-id>
./qcsd-lab analyze results/research-smoke-1200/<run-id>
```

`test live` is the bounded defended local gate. The first public-Internet
research capture is fitting, not smoke. The checked-in smoke then evaluates
the fitted defenses on new Internet visits and is verified and analyzed as an
independent post-fit result. This goal does **not** execute the separately
authorized 42-sample rehearsal or final campaign. The eventual
`config/campaigns/final.yml` must pass non-executing `verify`, but its
126-sample capture remains explicitly on hold.
