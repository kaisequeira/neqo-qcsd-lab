# neqo-qcsd-lab

`neqo-qcsd-lab` is the Docker-only collection and analysis environment for the
QCSD fork of Mozilla Neqo. Campaign recipes select a workload replay scope;
each recipe can be run in either of two capture modes:

- `direct` captures the exact QUIC flow at the container edge for defense-shape
  diagnostics;
- `wireguard` captures the encrypted client-to-gateway flow for
  traffic-classification research, with optional inner-QUIC diagnostics.

Both modes use the same planner, sample state machine, collector, validation,
analysis, report, projection, resumption, and checksum paths. Only WireGuard
network provisioning differs. The research rationale is in
[`METHODOLOGY.md`](METHODOLOGY.md).

## Repository layout

```text
config/
  campaigns/                small replay recipes and visit counts
  workloads/                shared frozen page/request graphs
docker/
  collection-entrypoint     common collection-container setup
  wireguard-client-up       tunnel and encrypted-DNS routing
  wireguard-gateway-entrypoint
docs/
  diagrams/                 two standalone TikZ sources and shared styles
  assets/                   matching transparent SVG and vector PDF figures
neqo-qcsd/                  editable Neqo Git submodule
src/qcsd_lab/               campaign, capture, dataset, plot, and report code
tests/                      deterministic and opt-in acceptance gates
results/                    ignored generated evidence
```

The figures are rendered directly with `latexmk` and `dvisvgm`; diagram
rendering is intentionally not a lab command.

## Campaign terminology and configuration

- **Workload:** one frozen page/request graph in `config/workloads/`.
- **Planned visit:** one repetition number for a workload.
- **Defense sample:** one actual page load under one defense.
- **Paired visit:** all defense samples with the same workload and repetition.
- **Split:** one train/test assignment shared by that entire paired visit.

The three recipes in [`config/campaigns/`](config/campaigns/) use the same
campaign contract and shared workload directory:

- `single-resource-pilot.yml` preserves the 24-visit, 72-sample engineering
  recipe and replays each manifest as written;
- `dconn-replay-pilot.yml` restricts each discovered page graph to its final
  page origin, requiring at least two resources on one HTTP/3 connection;
- `dmc-replay-pilot.yml` retains every explicitly reviewed origin, requiring at
  least two HTTP/3 origins/connections.

The Dconn and Dmc pilots use the same two page graphs, three visits per page,
and three defenses: six paired visits and 18 defense samples before retries.
The current pair is the Chromium QUIC page and Chromium Projects page. This is
a deliberately small engineering pair from one stable site, not a diverse
classifier corpus.
Their paired visits receive identical train/test assignments, while scope is
part of each `sample_id`, so Dconn and Dmc executions cannot be confused.
Both replay recipes contain monitored engineering classes only. They deliberately
omit an unmonitored population and are too small for an open-world classifier
claim; current pilot evidence and limitations are recorded in the methodology.

Optional `limits` may override timeout, response bytes, capture duration,
capture size, retries, origin cooldown, inter-sample delay, and settle time.
Every resolved default is sealed into `campaign.json`.

Static is not part of the public research campaign. The former six-row CSV was
only synthetic smoke data and has been deleted. Static remains available for a
researcher-supplied schedule by using an explicit defense object with `kind:
static`, `schedule`, and `mode`; tests create their own temporary fixture.

## Images and preparation

Build from the checked-out Neqo submodule:

```shell
./qcsd-lab image build all
```

For a dirty development checkout, use `--dev`; its commits, dirty state, patch
hashes, and image digest are recorded so incompatible collection resumes are
rejected.

Browser discovery and Neqo HTTP/3 preflight are optional preparation steps for
creating a new frozen workload:

```shell
./qcsd-lab discover --url https://example.com/ \
  --allow-origin https://example.com \
  --allow-origin https://static.example.com \
  --output /lab/config/workloads/example-discovered.json
./qcsd-lab probe \
  --input-manifest /lab/config/workloads/example-discovered.json \
  --output /lab/config/workloads/example.json
```

Chromium is used only before measurement to discover the page graph. The
reviewer must explicitly allow each retained origin; discovery records unsafe,
unreviewed, or non-GET exclusions. Probe then checks resources independently
for HTTP/3 availability without letting one failed parent suppress an otherwise
usable descendant. For replay graphs it also performs three complete undefended
loads separated by 30-second origin cooldowns. A resource is qualified only if
status, delivered bytes, and body hash repeat exactly; a changing page is
rejected before campaign collection. Replay audit and qualification metadata
are sealed as provenance but removed from the runtime manifest passed to Neqo.
Live workloads permit only reviewed, credential-free HTTPS GET requests. Chaff
uses the same frozen, same-origin request definition.

## One pipeline, campaign scope, and capture mode

Run the Dconn-aligned replay through WireGuard:

```shell
./qcsd-lab collect \
  --campaign /lab/config/campaigns/dconn-replay-pilot.yml \
  --capture wireguard
```

Run the Dmc-aligned replay through WireGuard:

```shell
./qcsd-lab collect \
  --campaign /lab/config/campaigns/dmc-replay-pilot.yml \
  --capture wireguard
```

Any recipe can instead use `--capture direct` for container-edge mechanism
diagnostics. There is no separate Dconn/Dmc runtime or model flag: the campaign
scope resolves the shared source graph, and both scopes immediately enter the
same planner, collector, state machine, analysis, and sealing code.

WireGuard mode captures outer tunnel traffic on container `eth0` and, by
default, inner QUIC on `wg0`. Use `--outer-only` to omit the auxiliary inner
view. `--network-condition <name>` records a named gateway/network condition
in provenance and sample identities. Resume either mode with:

```shell
./qcsd-lab collect \
  --campaign /lab/config/campaigns/dmc-replay-pilot.yml \
  --capture wireguard \
  --resume /lab/results/<timestamp>
```

Direct mode starts only the collector. WireGuard mode additionally creates an
ephemeral gateway, configures `/dev/net/tun`, warms the tunnel, and routes DNS
through it. Containers are not privileged.

## Result contract

```text
results/<UTC timestamp>/
  campaign.json             immutable visit plan and resolved provenance
  samples.jsonl             canonical mutable defense-sample state
  dataset.json              threat model and dataset card
  splits.json               one paired-visit train/test assignment map
  metrics.csv               capture, overhead, drift, and retry metrics
  projection.json           measured and reference-scale costs by defense/view
  resolved-workloads/       exact runtime graphs and hashes used by Neqo
  dataset-summary.{pdf,svg} aggregate coverage/storage/health figure
  report.html               compact campaign report and artifact links
  SHA256SUMS                sealed integrity manifest
  <class>/<workload>-visit-<number>/<defense>/
    sample.json
    captures/<valid-view>.pcapng
    traces/<valid-view>.csv
    neqo/
    attempts/
```

Normalized traces contain:

```text
relative_time_ns,direction,length_bytes,signed_length_bytes
```

Outgoing lengths are positive and incoming lengths negative. Outer WireGuard
uses `udp.length`, matching the original QCSD classifier traces. Direct `eth0`
uses Ethernet `frame.len`; inner `wg0` uses Raw-IP `frame.len`, so their lengths
are deliberately declared rather than treated as interchangeable.

An attempt is accepted when the runner succeeds and its primary capture
validates. After all defenses for a visit run, each sample becomes eligible
only if its response matches the undefended baseline. A paired visit is usable
for classifier comparison only when all of its defense samples are eligible.
Auxiliary capture failure is retained but does not invalidate valid primary
evidence.

## Validation and publication

```shell
./qcsd-lab dataset validate /lab/results/<timestamp>
./qcsd-lab dataset package /lab/results/<timestamp> \
  --pcaps primary --data-license CC-BY-4.0
```

Validation reproduces normalized traces from PCAPNG and checks IDs, hashes,
link types, direction/length semantics, responses, paired completeness, split
isolation, purpose, and checksums. A narrow read-only adapter validates sealed
older `group_id` roots; they are never rewritten.

Only a valid WireGuard classification root with an explicit license can be
packaged. `--pcaps primary` includes the primary trace and PCAP, `all` includes
every valid trace and PCAP, and `none` includes only the primary normalized
trace. Packages exclude qlogs, events, schedules, response/endpoint details,
resolved defense parameters, attempts, and keys.
Source URLs, origin audits, discovery exclusions, and resolved workload graphs
also remain private validation provenance and are omitted from packages.

## Tests

```shell
./qcsd-lab test -q
./qcsd-lab test --local-acceptance -q
./qcsd-lab test --capture-acceptance -q
```

The last gate requires `/dev/net/tun` and exercises direct capture, WireGuard
dual capture, outer-only capture, and auxiliary-view failure. No command starts
a live pilot or full dataset implicitly.
