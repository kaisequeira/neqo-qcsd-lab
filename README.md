# neqo-qcsd-lab

`neqo-qcsd-lab` is the Docker-only collection and analysis environment for the
QCSD fork of Mozilla Neqo. It has one measurement path: direct Ethernet capture
of the exact QUIC flows created by a Neqo/QCSD page load.

Campaign recipes may describe a single resource, a same-origin page graph, or a
reviewed multi-origin graph. That changes the requests Neqo makes, not the
observer or the artifacts. Every sample produces one direct PCAPNG, one
normalized trace, runner evidence, metrics, and the classic QCSD comparison
figure. The research rationale and limitations are in
[`METHODOLOGY.md`](METHODOLOGY.md).

## Repository layout

```text
config/
  campaigns/                replay and all-defence recipes
  defense-params/           reviewed runtime parameter fixtures
  workloads/                frozen page/request graphs
docker/
  collection-entrypoint     least-privilege collection-container setup
docs/
  diagrams/                 standalone TikZ sources and shared style
  assets/                   matching transparent SVG and vector PDF figures
neqo-qcsd/                  editable Neqo Git submodule
src/qcsd_lab/               campaign, capture, dataset, plot, and report code
tests/                      deterministic tests and the direct live gate
results/                    ignored generated evidence
```

The diagrams are rendered with `latexmk` and `dvisvgm`; rendering is not a lab
command.

## Campaigns and workloads

The research definitions for workloads, paired visits, split groups, and
eligibility are maintained in
[`METHODOLOGY.md`](METHODOLOGY.md#workloads-visits-and-splits). The
operator-facing campaign recipes all use the same planner and collector:

- `single-resource-pilot.yml` replays manifests as written;
- `dconn-replay-pilot.yml` uses `primary-origin` to retain the final page
  origin;
- `dmc-replay-pilot.yml` uses `all-reviewed-origins`;
- `defense-migration-pilot.yml` runs one simple and one complex workload across
  Undefended, Static, FRONT, Tamaraw, Traffic Morphing, WTF-PAD, and
  Walkie-Talkie.

The supported workload scopes are `as-defined`, `primary-origin`, and
`all-reviewed-origins`. Repetition counts remain explicit under
`workloads.monitored` and `workloads.unmonitored`; a scope never introduces a
second collection workflow or an implicit sample count.

Optional `limits` bound response bytes, runner and capture duration, retained
capture size, retries, origin cooldown, inter-sample delay, and the post-run
settle interval. Every resolved value is written to `campaign.json`.

Static uses `kind: static`, a signed schedule, and a chaff-only or
chaff-and-shape mode. The three new parameterized defences use the same
campaign field:

```yaml
defenses:
  - undefended
  - name: traffic-morphing
    kind: traffic_morphing
    parameters: ../defense-params/traffic-morphing-live.json
    allow_reviewed_fixture: true
  - name: wtf-pad
    kind: wtf_pad
    parameters: ../defense-params/wtfpad-live.json
    allow_reviewed_fixture: true
  - name: walkie-talkie
    kind: walkie_talkie
    parameters: ../defense-params/walkie-talkie-live.json
    allow_reviewed_fixture: true
```

Parameter paths resolve relative to the campaign. The JSON and adjacent
`.provenance.json` sidecar are content-hashed, recorded in the campaign
receipt, copied into each reactive sample, bound to the runner's
`run.json.defense_parameters`, and covered by the result seal.

`allow_reviewed_fixture` is limited to checked-in, reviewed engineering
fixtures used by the internal acceptance campaign. A normal generated
parameter file must have sealed production provenance.

## Build and workload preparation

Build from the checked-out Neqo submodule:

```shell
./qcsd-lab image build all
```

Use `--dev` for a dirty development checkout. The dirty state, patch hashes,
source commits, and image digest are recorded so an incompatible result cannot
be resumed.

Browser discovery and Neqo HTTP/3 preflight create a new frozen workload:

```shell
./qcsd-lab discover \
  --url https://example.com/ \
  --allow-origin https://example.com \
  --allow-origin https://static.example.com \
  --output /lab/config/workloads/example-discovered.json

./qcsd-lab probe \
  --input-manifest /lab/config/workloads/example-discovered.json \
  --output /lab/config/workloads/example.json
```

Chromium participates only during discovery. A reviewer explicitly allows each
retained origin, and Neqo preflight checks HTTP/3 availability and repeated
response stability. Measurement itself is performed only by Neqo/QCSD.

## Runtime defence parameters

Parameter fitting is deliberately outside the lab. The collector accepts a
prepared runtime JSON file and adjacent `.provenance.json` receipt, verifies
its source-campaign seals and train-domain bindings, copies both files into the
sample, and checks the hash reported by Neqo. The lab contains no SciPy,
fitting CLI, matrix optimizer, histogram fitter, or burst-mould generator.

Research campaigns accept only `sealed-completed-campaigns` provenance.
Checked-in `reviewed-engineering-fixture` bundles are restricted to acceptance
campaigns with `allow_reviewed_fixture: true`. Producing a fitted bundle is an
offline thesis-analysis responsibility, not a collection command.

## Collect

Every campaign uses direct capture:

```shell
./qcsd-lab collect \
  --campaign /lab/config/campaigns/defense-migration-pilot.yml
```

An optional network-condition label becomes provenance without changing
capture:

```shell
./qcsd-lab collect \
  --campaign /lab/config/campaigns/dmc-replay-pilot.yml \
  --network-condition campus-wifi
```

Resume an interrupted result with the same inputs:

```shell
./qcsd-lab collect \
  --campaign /lab/config/campaigns/dmc-replay-pilot.yml \
  --resume /lab/results/<timestamp>
```

The collector starts `dumpcap` on container `eth0` before Neqo, captures UDP
through the defence tail and settle interval, then post-filters the retained
PCAP to the exact union of endpoint tuples recorded by the runner. Every
sample must prove that GRO, GSO, TSO, and UDP segmentation offload (USO) are
disabled and that every observed datagram respects the profile-wide
UDP-payload ceiling (1200 bytes for the live profile). QCSD also disables
per-socket Linux `UDP_GRO`, which is independent of interface offload state.
Controlled acceptance origins disable their virtual-interface offloads too,
so bridge capture preserves UDP datagram boundaries. The runner's resolved
ceiling is bound to the same value in every packet-number space.

## Result contract

```text
results/<UTC timestamp>/
  campaign.json             immutable visit plan and resolved provenance
  samples.jsonl             canonical defence-sample state
  dataset.json              observer and dataset card
  splits.json               source/repetition 70/15/15 assignments
  classifier.json           leakage-safe model-input contract
  classifier-samples.jsonl  full variable-length direct sequences
  metrics.csv               capture, overhead, drift, and guard metrics
  projection.json           measured/reference collection costs
  resolved-workloads/       exact runtime graphs used by Neqo
  report.html               figures and artifact links
  SHA256SUMS                exact integrity seal
  <class>/<workload>-visit-<number>/
    trace-comparison.{pdf,svg}
    trace-comparison-2.{pdf,svg}
    <defence>/
      sample.json
      fidelity.yml
      captures/direct-quic.pcapng
      traces/direct-quic.csv
      neqo/
      attempts/
```

Each `sample.json` uses this fixed artifact-view record:

```text
id=direct-quic
interface=eth0
link_type=Ethernet
length_basis=frame.len
```

The normalized trace contract is:

```text
relative_time_ns,direction,length_bytes,signed_length_bytes
```

Outgoing lengths are positive and incoming lengths are negative. It contains
no address or port fields and is reproduced exactly from the direct PCAP.

The classic comparison figure has two rows: packet-time density and signed
Ethernet frame-length scatter. Solid curves/points are observed direct-PCAP
traffic. Dashed curves are densities of recorded controller schedule actions,
including exact incoming receive-credit replacements; they are not logical
target-cell counts. The dotted vertical line is application completion. Seven
selections paginate four plus three. Each defence uses its own time and density
range; both pages retain one common signed-size range. Panels contain no
statistics box; application time, absolute duration, byte overhead, and tail
cost remain in the adjacent report table.

The eligibility, bounded reconciliation, split, and classifier-feature rules
for these artifacts are specified once in
[`METHODOLOGY.md`](METHODOLOGY.md), alongside the observer and research
semantics.

## Validation and privacy boundary

```shell
./qcsd-lab dataset validate /lab/results/<timestamp>
```

Validation checks IDs, paired membership, splits, response equality, observer
declarations, PCAP-to-trace reproduction, fidelity records, classifier
sequences/eligibility, parameter bundles, runner bindings, operational guards,
capture-offload state, the common UDP-payload ceiling, exact classifier
schemas, split and sample-ID recomputation from campaign provenance, exact
defence-plan binding, and a mandatory exact path-safe checksum seal. An
unsealed root is not a valid dataset.

Raw direct PCAPNG retains IP addresses, ports, QUIC Initial packets, and other
passively observable metadata. It is internal validation and plotting evidence,
not a sanitized or public artifact. This repository intentionally has no
dataset-package command. An anonymizer/exporter must be designed and verified
separately before a large corpus is released.

## Tests

```shell
./qcsd-lab test -q
./qcsd-lab test --capture-acceptance -q
```

The ordinary gate runs deterministic Python tests. The opt-in live gate starts
two local HTTP/3 origins and runs one simple and one complex visit through all
seven selections using the real campaign collector. It checks application
integrity, parameter bindings, terminal slots, defence diagnostics, endpoint
isolation, one PCAP/trace per sample, PCAP reproduction, identical core
artifact surfaces, both classic figure pages, and report links.

Exact stochastic/state-machine determinism belongs to pinned Rust defence and
full-controller replay tests. The live gate checks each observed run against
its own causal inputs; independent QUIC connections are not assumed to have
identical packetization or ACK timing.
