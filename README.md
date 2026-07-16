# neqo-qcsd-lab

`neqo-qcsd-lab` is the Docker-only experiment parent for the modern
[`neqo-qcsd`](https://github.com/kaisequeira/neqo-qcsd) client. It discovers
public page request graphs, confirms direct HTTP/3 support, runs reproducible
baseline/Static/FRONT/Tamaraw campaigns against unmodified servers, captures
encrypted QUIC traffic as PCAPNG, and regenerates observer-view figures.

This repository follows the separation used by the authors'
[`qcsd-experiments`](https://github.com/jpcsmith/qcsd-experiments) repository.
It implements research tooling for Smith, Dolfi, Mittal, and Perrig,
“[QCSD: A QUIC Client-Side Website-Fingerprinting Defence Framework](https://www.usenix.org/conference/usenixsecurity22/presentation/smith),”
USENIX Security 2022. The lab is MIT licensed; the Neqo submodule retains its
MIT/Apache-2.0 licensing and upstream attribution.

## Repository boundary

This is the parent repository. `third_party/neqo-qcsd/` is a Git submodule
pinned to one exact migration commit. The root `qcsd-lab` file is only a Docker
launcher: it validates the submodule, chooses the discovery or collection
image, maps the current UID/GID and writable result directories, adds only
`NET_RAW`/`NET_ADMIN`, and invokes the in-container Python CLI. It never builds
or runs a second host-native Neqo.

Clone and build the digest-pinned multi-architecture images:

```sh
git clone --recurse-submodules https://github.com/kaisequeira/neqo-qcsd-lab
cd neqo-qcsd-lab
./qcsd-lab image build
./qcsd-lab doctor
```

The first collection build compiles Neqo and NSS 3.121 and can take several
minutes. Later campaigns reuse the local image. There are deliberately no
automatic GitHub Actions.

## Workflow

Discover and freeze a public workload definition. Discovery records only
public, non-secret GET request metadata; cookies and authorization are never
stored:

```sh
./qcsd-lab discover --url https://example.test/ \
  --output /lab/workloads/example-2026-07-v1.json
./qcsd-lab probe \
  --input-manifest /lab/workloads/example-2026-07-v1.json \
  --output /lab/workloads/example-2026-07-v1-probed.json
```

Review the immutable manifest and its SHA-256 sidecar, reference the probed
file from a campaign YAML, then collect sequential samples:

```sh
./qcsd-lab collect --campaign /lab/campaigns/example-live.yml
./qcsd-lab plot \
  /lab/results/example-live/example/rep-000/00-none \
  /lab/results/example-live/example/rep-000/01-front \
  /lab/results/example-live/example/rep-000/02-tamaraw \
  --output /lab/results/example-live/figures
./qcsd-lab report --results /lab/results/example-live \
  --output /lab/results/example-live/report
```

Defense order is deterministically shuffled, so numeric sample prefixes will
vary. Pass the actual sample paths produced by the campaign. `qcsd-lab test`
runs deterministic tooling tests. Add `--local-acceptance` to start the
bundled unmodified Neqo HTTP/3 server and gate all four modes against its 1 MiB
response. Add `--capture-acceptance` to gate the complete four-mode loopback
PCAPNG collection/filtering/artifact path (it requires the launcher's capture
capabilities).

## Request policies

Application requests support three explicit policies:

- `fresh-browser` replays discovered non-secret end-to-end headers, including
  content negotiation, language, referrer/origin, user agent, client hints,
  fetch metadata, and site-specific fields. Conditional and range fields are
  excluded from a fresh measurement.
- `minimal` ignores discovered per-resource headers and sends only explicit
  manifest overrides.
- `custom` replays safe fields and can explicitly enable conditional and range
  behavior.

HTTP pseudo-headers are regenerated from each URL. Connection-specific HTTP/3
fields and persisted credentials are rejected, not silently altered. These
rules do not narrow QCSD application behavior; they prevent invalid requests
and accidental credential publication. Chaff remains stricter by design:
same-origin GET, `Accept-Encoding: identity`, no credentials, range, cache
conditions, or cross-origin redirect promotion.

## Capture and artifacts

Collection runs as the host's non-root UID in an isolated Docker network with
only raw-capture and interface-administration capabilities. A minimal root
entrypoint uses `SETUID`/`SETGID` once, then the experiment process retains only
`NET_RAW` and `NET_ADMIN` with no-new-privileges. GRO/GSO/TSO are disabled
and recorded. `dumpcap` starts before Neqo and is bounded by time and filesize.
The raw UDP capture is filtered using exact local/remote tuples from
`run.json`; successful samples retain `traffic.pcapng` and discard the raw
capture unless `keep_raw` is set. TLS keys are not exported.

Every sample includes the filtered capture, `traffic.csv`, Neqo's `run.json`,
packet/event/schedule CSV files, qlog, logs, capture/offload metadata, commits,
image ID, comparison eligibility, and checksums. PCAP `frame.len` drives the
paper-style observer plots. Neqo UDP payload observations drive a separate
target-exactness plot.

Results and captures are ignored by Git. Frozen manifests and campaigns are
source-controlled. See [capture design](docs/CAPTURE.md) and
[schemas](docs/SCHEMAS.md) for operational detail.

## Responsible live use

Use only public resources you are authorized to request. Keep repetitions,
timeouts, defense schedules, and chaff manifests conservative. Campaigns are
sequential and impose an inter-run delay; do not remove those safeguards for
third-party services. Public endpoint failures and content drift are retained
as release-gate evidence rather than treated as deterministic unit-test
failures.
