# QCSD lab

This repository is the experiment orchestrator for the QCSD Neqo fork. It has
one workflow: freeze a workload, expand a campaign into sequential samples,
capture each Neqo run directly, seal the evidence, and derive plots and a
report afterwards.

The lab does not maintain a second data-processing workflow. A workload is
simply a frozen graph of HTTPS requests. A visit is one execution of that
graph. A sample is one visit under one defence.

The capture specification does not train a classifier or define an open-world
corpus. Fitting and evaluation are separate campaigns over independent visits
of the same frozen workload definitions. A separate offline companion packages
complete sealed results for a five-class closed-world proof of concept; that
export does not make the five fixed domains a representative website
population or evaluate an attacker retrained on defended traffic.

Docker is required for every public command. The Neqo source is the
`neqo-qcsd/` Git submodule.

## Commands

The capture surface is deliberately limited to the `qcsd-lab` forms documented
below. The classifier handoff exporter is a separate offline tool so adding or
changing it cannot alter the implementation receipt already bound by the
qualified defences.

### BuFLO/CS-BuFLO candidate study

`buflo` and `cs-buflo` are client-only QUIC adaptations. They use ordinary
HTTP/3 servers and standard QUIC traffic; they are not bilateral or
paper-equivalent implementations. Until a typed
class-study `validation-attestation.json` independently verifies every gate,
the project status is **five validated defences plus two candidates / nine
selectable modes**, including the `undefended` and `static` controls.

The BuFLO adaptation drains every allocatable 1,200-byte reviewed-chaff cell
after the inclusive ten-second minimum. If only a sub-cell response tail
remains, it latches only after all scheduled work and parser leases are
terminal and every pending application parser boundary has cleared. Pending
reviewed-chaff parser boundaries are counted and canceled with their streams by
standard client-local HTTP/3 cancellation. The resulting unscheduled
defense-control traffic is explicitly receipted and is an expected QCSD-only
difference from the bilateral TCP study; it is never described as
paper-equivalent or as a server padding-complete signal.

Current BuFLO evidence uses runner-wakeup schema 3. The measured client remains
actively runnable for the complete 5 ms realization window before every exact
20 ms release; after the outgoing handoff it immediately drives only endpoints
with accepted scheduled receive credit that has not yet produced a
`MAX_STREAM_DATA` frame. The half-open deadline remains strict: a release or
credit advertisement at or after the deadline is a typed hard failure and is
never caught up. Historical schema 2 receipts retain their exact 250 microsecond
active-wait semantics and remain readable, but cannot admit a fresh candidate
capture. Full-window active waiting can consume approximately 25% of one CPU
while canonical BuFLO is active, so active-wait nanoseconds and measured client
CPU are retained as performance evidence rather than treated as unavailable
infrastructure overhead.

CS-BuFLO local early termination stops defense chaff and credit work, not the
application. If it occurs before the local onLoad analogue, current receipts
count the application receive streams, parser state, and send endpoints handed
back to ordinary HTTP/3 processing. Natural application bytes after that latch
remain in final accounting while the padding basis, estimator samples, rate
transitions, and terminal interval stay frozen at the local-termination state.
Summary schema 4 also binds the asynchronous client-only translation.  Its
directional stop receipt records the application-complete or strict-quiet
phase, target or crossing reason, stop time, progress and target, scheduled and
terminal counters, and provisional invalidation count.  The handoff reconciles
those counters and timestamps with every schedule row: no new opportunity may
be scheduled after the stop, and each already-advertised receive-credit
opportunity must terminalize exactly once before the local latch.  Outgoing
crossings use observed UDP payload; incoming crossings use fully consumed
scheduled credit and do not claim peer-datagram timing or size.  A resumed
natural byte invalidates provisional stop evidence in the implementation, with
the cumulative invalidation count retained in the final receipt.  This drain
is not the paper's server padding-done signal.

The latest executed candidate checkpoint is cohort v23. Its fresh pull/no-cache
build, isolated reference gate, and 18/18 nine-mode regression passed against
Lab `3ea8490ac8fd1c2b31b0ed828a11ae72d17d79c2` and Neqo
`b7ca4ad8931001c9baa8ad04b064ade7fa9a405f`. The v23 code gate then ended with
1,469 tests passed, 19 failed, and six skipped, so it created no immutable
`code-gate-v23.json` receipt. Seventeen failures exposed collection-image
launcher layout/help assumptions and two exposed installed-path assumptions.

V23 also exposed an independent evidence-contract defect. Its live explicit
two-origin compatibility run exercised all nine modes and physically retained
a rejected first WTF-PAD attempt before accepting its retry, but the schema-1
compatibility receipt bound only accepted attempts. It therefore could still
verify after removal of that rejected attempt. The schema-1 proof is
non-authoritative, and neither it nor any other v23 receipt can authorise the
current source. Source fixes now bind every contiguous attempt and are under
validation; a fresh clean cohort v24 must rerun the build, reference, 18/18
regression, and complete code gate before any controlled qualification or
class-study acquisition proceeds. No class-study qualification or validation
attestation exists yet. The authoritative current heads, progression, and
evidence ledger are maintained in [`../PROJECT.md`](../PROJECT.md); the exact
extended-class protocol and matrices are maintained in
[`../CLASS-STUDY.md`](../CLASS-STUDY.md).

### Prospective 100-class final campaign

`classifier-multiorigin100-v1` replaces the earlier unexecuted five-class
candidate formal stage. Its pinned Tranco receipt and deterministic 600-domain
catalogue are checked in under `config/class-study/v1/`; all 600 candidates are
currently unassessed, so this is runnable infrastructure rather than acquired
evidence. The public acquisition runner admits one exact prepared page per
candidate only after matching start-window observations at 30 seconds, 24
hours, and 72 hours, then freezes 120 pilot classes and finally 100 study
classes plus 20 reserves across five fixed rank strata.

The catalogue contains 120 candidates per stratum, so only a 20% technical
eligibility yield is needed to obtain each stratum's 24 pilot classes. This
margin was fixed before acquisition; selection still uses the first eligible
domains in the pinned hash order and never defence, classifier, latency, or
bandwidth outcomes.

The candidate-domain boundary governs the primary navigation identity and
redirects, not subresource origins. Discovery iteratively expands a frozen
public-HTTPS GET origin allow-list and complete preparation retains rendered
resources from every approved origin. Document-navigation origins are seeded
per page, so optional pages cannot contaminate one another's origin graphs. The
32-origin and eight-pass limits are
fail-closed admission bounds: exceeding either bound or failing to converge
rejects the class rather than truncating an accepted workload. Every discovered
public HTTPS GET subresource is retained in an accepted, converged workload.
The fresh browser load inside final preparation must reproduce the converged
origin set: a newly observed unapproved HTTPS GET fails that probe and forces
reconvergence on a retry, and persisted complete-coverage evidence rejects any
`origin not approved` exclusion independently. Both single-origin and
naturally multi-origin classes are eligible; origin count is not a selection
criterion or quota, and no acquisition or selection stage intentionally omits
multi-origin classes. The closed-checksum handoff
reports the realised per-class origin counts, histogram, and
single-/multi-origin totals in `dataset.json.resource_origin_profile`.

The endpoint is one contemporaneous paired corpus over the same frozen 100
classes and visit indices under `undefended`, FRONT, Tamaraw, Traffic
Morphing, WTF-PAD, Walkie-Talkie, BuFLO, and canonical CTSP CS-BuFLO. Ten
temporal blocks contain two visits per class and mode, giving 16,000 formal
captures. Before any formal block, all 100 classes must first pass a single-
launch 900-cell certification under all nine selectable modes, including the
non-defence `static` control. `static` is excluded from the efficacy corpus;
CPSP CS-BuFLO remains a controlled ablation rather than a tenth mode.
Certification permits exactly one started attempt per class/mode cell. Each
excluded canary sample and each authoritative formal sample permits at most
three total attempts across resumes; every failed or interrupted attempt
remains sealed and cannot be relabelled or omitted.

Traffic Morphing, WTF-PAD, and Walkie-Talkie receive separate, excluded
fitting evidence: 480 pilot fitting captures and 2,000 final fitting captures,
with 720/600 live qualification executions and a 1,080-cell pilot
compatibility screen. The final cohort is not admitted from classifier
performance. Its optional Walkie-Talkie graph contains only pair-specific WT6
profiles with frozen capacity evidence at both endpoints; untested alternate
pairs are not inferred feasible. Publications are create-only and fail-closed;
campaign results resume through `experiment.json`, while acquisition resumes
only through its own `checkpoint.json`. The full protocol, exact matrices,
current zero-progress ledger, and claim boundary are in
[`../CLASS-STUDY.md`](../CLASS-STUDY.md).

Fresh class-study commands use one canonical path graph: generated campaigns
live only in `config/classifier-multiorigin100-v1-campaigns/`, admitted
workloads remain in `config/workloads/`, cohort receipts live under
`config/class-study/v1/`, fitted bundles are direct children of `artifacts/`,
and final named qualification sets are published below
`config/chaff-qualification-store/sets/`. The host launcher derives and checks
those paths through `qcsd_lab.class_layout`; alternate or symlinked fresh roots
fail before Docker launch. Result resume and verification instead use the
hash-bound frozen `inputs/` tree and do not reinterpret it as a live workspace
root. Exact directories and prospective command fragments are listed in the
[canonical-layout section](../CLASS-STUDY.md#26-canonical-fresh-workspace-layout).

After `acquisition-init` has created the canonical provenance and
`checkpoint.json`, supervise the long 30-second/24-hour/72-hour acquisition
from the host with:

```shell
./qcsd-lab class-study acquisition-watch
```

The supervisor validates the catalogue, foundation, exact prepare-image
digest, provenance, and checkpoint before doing any work. It invokes the
existing bounded `acquisition-run` action only when work is due, remains
interruptible while waiting, and resumes from the same `checkpoint.json` when
the command is restarted. It creates no alternative state or completion
receipt. The optional `--heartbeat-seconds` value controls signal-responsive
host sleep slices and must be greater than zero and no more than five seconds;
it does not poll Docker at that frequency.

Operationally, this stage is longer than 72 hours. Serial acquisition and the
190-second pending-baseline guard permit new baselines no faster than once per
25 seconds, so opening 600 baselines takes at least 4 h 9 min 35 s and the last
candidate's earliest `t+72h` probe is at least 75 h 54 min 35 s after the first
baseline. This excludes navigation, preparation, Docker, network, and retry
time; preflight and supervision must allow additional margin.

### Retained focused candidate workflow

The following `buflo-study` workflow is retained as the command reference for
the earlier focused three-mode, 1,500-sample design. It is not the
`classifier-multiorigin100-v1` endpoint, and neither its receipts nor its
versioned attestation can substitute for the class-study
`validation-attestation.json`.

The versioned coordinator exposes nine fail-closed actions: `reference`,
`qualify`, `historical-snapshot`, `freeze-cohort`, `code-gate`, `capture`,
`export`, `evaluate`, and `verify`. The following Bash sequence is the complete
retained focused-study workflow. It assumes the fixed create-only destinations do not yet
exist and that `REFERENCE_ROOT` names the absolute directory containing the
pinned external paper, author-source, and archive inputs. Set `COHORT_VERSION`
in the calling environment to an unused positive integer; the sequence rejects
a missing, non-canonical, or already-used value before it creates anything.

```bash
set -euo pipefail
REFERENCE_ROOT=/absolute/pinned-reference-inputs
: "${COHORT_VERSION:?export COHORT_VERSION as an unused positive integer}"
[[ "$COHORT_VERSION" =~ ^[1-9][0-9]*$ ]] || {
  echo "COHORT_VERSION must be a canonical positive integer" >&2
  exit 2
}
[[ ! -e "artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json" ]] || {
  echo "COHORT_VERSION already has a create-only build receipt" >&2
  exit 2
}
REFERENCE="artifacts/buflo-study/reference-execution-v${COHORT_VERSION}.json"
QUALIFICATION="artifacts/buflo-study/qualification-v${COHORT_VERSION}.json"
CONTROLLED_ROOT="results/buflo-study-controlled-v${COHORT_VERSION}"
REGRESSION_ROOT="results/buflo-study-regression-v${COHORT_VERSION}"
CODE_GATE="artifacts/buflo-study/code-gate-v${COHORT_VERSION}.json"

# Builds all three targets with --pull --no-cache and creates the immutable
# artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json receipt.
./qcsd-lab build --cohort-version "$COHORT_VERSION"
./qcsd-lab buflo-study reference \
  --reference-root "$REFERENCE_ROOT" --destination "$REFERENCE" \
  --cohort-version "$COHORT_VERSION"

# Test-only local captures. The wrapper provisions one shared two-network
# router with receipted ingress/egress shaping and holds the acquisition lock.
./qcsd-lab buflo-study capture --stage controlled \
  --cohort-version "$COHORT_VERSION" --destination "$CONTROLLED_ROOT"
./qcsd-lab buflo-study capture --stage regression \
  --cohort-version "$COHORT_VERSION" --destination "$REGRESSION_ROOT"

mapfile -t CONTROLLED < <(python3 -c '
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
for key in sorted(v["profiles"]): print(v["profiles"][key])
' "$CONTROLLED_ROOT/controlled-results.json")
mapfile -t REGRESSION < <(python3 -c '
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
for key in sorted(v["campaigns"]): print(v["campaigns"][key])
' "$REGRESSION_ROOT/regression-results.json")
CONTROLLED_ARGS=()
for root in "${CONTROLLED[@]}"; do
  CONTROLLED_ARGS+=(--controlled-result "$root")
done
REGRESSION_ARGS=()
for root in "${REGRESSION[@]}"; do
  REGRESSION_ARGS+=(--result "$root")
done

# This one action first revalidates controlled160, creates or resumes the exact
# public5 sustained-chaff set, verifies it, then publishes the typed receipt.
./qcsd-lab buflo-study qualify "${CONTROLLED_ARGS[@]}" \
  --cohort-version "$COHORT_VERSION" --destination "$QUALIFICATION"

./qcsd-lab buflo-study code-gate "${REGRESSION_ARGS[@]}" \
  --cohort-version "$COHORT_VERSION" --destination "$CODE_GATE"

SMOKE="$(
  ./qcsd-lab buflo-study capture --stage smoke \
    --cohort-version "$COHORT_VERSION" \
    --reference-receipt "$REFERENCE" \
    --qualification-receipt "$QUALIFICATION" \
    "${REGRESSION_ARGS[@]}" \
    --destination "artifacts/buflo-study/smoke-admission-v${COHORT_VERSION}.json" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["details"]["captured_results"][0])'
)"
REHEARSAL="$(
  ./qcsd-lab buflo-study capture --stage rehearsal \
    --cohort-version "$COHORT_VERSION" \
    --reference-receipt "$REFERENCE" \
    --qualification-receipt "$QUALIFICATION" \
    "${REGRESSION_ARGS[@]}" --result "$SMOKE" \
    --destination "artifacts/buflo-study/rehearsal-admission-v${COHORT_VERSION}.json" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["details"]["captured_results"][0])'
)"

PRE="artifacts/buflo-study/historical-pre-formal-v${COHORT_VERSION}.json"
COHORT="artifacts/buflo-study/formal-cohort-v${COHORT_VERSION}.json"
./qcsd-lab buflo-study historical-snapshot --snapshot-phase pre-formal \
  --cohort-version "$COHORT_VERSION" --destination "$PRE"
./qcsd-lab buflo-study freeze-cohort \
  --cohort-version "$COHORT_VERSION" --cohort-id "buflo-formal-v${COHORT_VERSION}" \
  --historical-pre-snapshot "$PRE" --destination "$COHORT"

mapfile -t FORMAL < <(
  ./qcsd-lab buflo-study capture --stage formal \
    --cohort-version "$COHORT_VERSION" \
    --reference-receipt "$REFERENCE" \
    --code-gate-receipt "$CODE_GATE" \
    --qualification-receipt "$QUALIFICATION" \
    "${REGRESSION_ARGS[@]}" --result "$SMOKE" --result "$REHEARSAL" \
    --historical-pre-snapshot "$PRE" --formal-cohort "$COHORT" \
    --formal-window-hours 12.5 \
    --destination "artifacts/buflo-study/formal-admission-v${COHORT_VERSION}.json" |
  python3 -c '
import json,sys
for root in json.load(sys.stdin)["details"]["captured_results"]: print(root)
'
)

POST_ARGS=()
FORMAL_ARGS=()
for root in "${FORMAL[@]}"; do
  POST_ARGS+=(--result "$root")
  FORMAL_ARGS+=(--formal-result "$root")
done
POST="artifacts/buflo-study/historical-post-formal-v${COHORT_VERSION}.json"
./qcsd-lab buflo-study historical-snapshot --snapshot-phase post-formal \
  --cohort-version "$COHORT_VERSION" \
  --historical-pre-snapshot "$PRE" "${POST_ARGS[@]}" --destination "$POST"

HANDOFF="handoffs/buflo-study-formal-v${COHORT_VERSION}"
EVALUATION="artifacts/buflo-study/evaluation-formal-v${COHORT_VERSION}.json"
./qcsd-lab buflo-study export --formal "${POST_ARGS[@]}" \
  --cohort-version "$COHORT_VERSION" --destination "$HANDOFF"
./qcsd-lab buflo-study evaluate --formal --handoff "$HANDOFF" \
  --cohort-version "$COHORT_VERSION" \
  --bootstrap-draws 10000 \
  --dlsvm-wall-seconds 45000 --destination "$EVALUATION"
```

Formal evaluation deliberately pauses for a human comparison review. Create
`artifacts/buflo-study/comparison-review-vN.json` with the exact schema enforced
by `validate_comparison_review`: it must hash-bind and substantively classify
every original-study anchor/metric pair as `expected` or `resolved`, explain
the transport/dataset/protocol context, and retain `paper_equivalent: false`.
The retained focused workflow's terminal verification and attestation command
is:

```bash
REVIEW="artifacts/buflo-study/comparison-review-v${COHORT_VERSION}.json"
ATTESTATION="artifacts/buflo-study/validation-attestation-v${COHORT_VERSION}.json"
REGRESSION_VERIFY_ARGS=()
for root in "${REGRESSION[@]}"; do
  REGRESSION_VERIFY_ARGS+=(--regression-result "$root")
done

./qcsd-lab buflo-study verify --formal --destination "$ATTESTATION" \
  --cohort-version "$COHORT_VERSION" \
  --reference-receipt "$REFERENCE" \
  --code-gate-receipt "$CODE_GATE" \
  --qualification-receipt "$QUALIFICATION" \
  "${REGRESSION_VERIFY_ARGS[@]}" "${CONTROLLED_ARGS[@]}" \
  --smoke-result "$SMOKE" --rehearsal-result "$REHEARSAL" \
  "${FORMAL_ARGS[@]}" \
  --capture-admission "artifacts/buflo-study/formal-admission-v${COHORT_VERSION}.json" \
  --formal-cohort "$COHORT" --handoff "$HANDOFF" \
  --evaluation-receipt "$EVALUATION" --comparison-review "$REVIEW" \
  --historical-pre-snapshot "$PRE" --historical-post-snapshot "$POST"
./qcsd-lab buflo-study verify --cohort-version "$COHORT_VERSION" \
  --attestation "$ATTESTATION"
```

Omitting `--cohort-version` preserves the version-1 command contract. A code,
parameter, workload, chaff, or acceptance-rule change after rehearsal instead
starts a new positive version: first run
`./qcsd-lab build --cohort-version N`, then pass the same option to every
`buflo-study` action. Each build creates, and never replaces,
`artifacts/buflo-study/build-execution-vN.json`. Qualification sets, rendered
campaign inputs, reference execution, freeze/admission receipts, captures, and
final verification are all checked against that exact receipt and its
collection, prepare, and reference image IDs. A direct public `run` derives N
from its capture admission; `resume` derives it only from the frozen
`inputs/capture-admission.json`, so neither command can be redirected to a
different cohort. Keep all earlier versioned evidence.

For this retained focused workflow, the exact result arguments are the
immutable result roots reported by the
preceding stage; the coordinator rejects missing, extra, relabelled, or
source-mismatched roots. The staged matrix is 18 test-only nine-mode regression
samples, 160 controlled qualification samples, 20 public smoke samples, 40
public rehearsal samples, then ten formal blocks totalling 1,500 focused
samples. Formal admission additionally requires one exact clean no-cache image,
the executed isolated reference receipt, the hash-bound code-gate receipt, at
least 12.5 declared hours, and three times the storage projected from the
verified smoke and rehearsal data. Cohort v15 and later prospectively freeze
exactly 10,000 block/workload bootstrap draws and their deterministic seed
contract; formal evaluation rejects any different draw count.
`experiment.json` is the only resume checkpoint. The coordinator automatically
resumes the one prospectively selected root, preserves failed/interrupted
physical-launch accounting, caps each study sample at three total launches,
and never rewrites accepted samples. Rerun the same `capture` command with its
existing `--capture-admission` instead of its `--destination` after an
interruption.

The reference image runs with networking disabled and checks the pinned paper,
author-source, and CPSP archive bytes. The collection image never contains the
author implementations. The dedicated handoff and evaluator do not modify the
sealed `classifier-multiorigin5-v2` corpus, and classifiers receive only
identifier-free timestamp, direction, and observer-frame length.

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

For a cohort that must retain its complete approved multi-origin render graph:

```shell
./qcsd-lab prepare example-r2 https://example.com/ \
  https://example.com https://static.example.com \
  --require-complete-coverage
```

The arguments are a new workload ID, a page URL, and one or more explicitly
approved HTTPS origins. Preparation:

1. observes the page with Chromium;
2. removes unsafe or unapproved requests, sensitive headers, and credentialed URLs;
3. probes the retained requests with the same Neqo client used for capture;
4. checks repeated status, byte count, and body identity;
5. freezes the concrete request headers and dependency graph in
   `config/workloads/<id>.json`.

Discovery pauses every request before transmission. Only explicitly approved
HTTPS `GET` requests are continued; other methods and origins are aborted and
recorded as exclusions. `--require-complete-coverage` additionally requires at
least one rendered resource from every approved origin and rejects preparation
if any approved rendered resource is unavailable over HTTP/3. Its frozen
coverage-admission receipt makes that stricter contract auditable. Without the
flag, the historical behavior remains: HTTP/3-unavailable resources and their
orphaned dependency closure may be excluded when the navigation root remains
valid.

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

### `qualify-response-chaff`

```shell
./qcsd-lab qualify-response-chaff \
  getbootstrap-home-r3 \
  cloudflare-quiche-r3 \
  hyper-basic-client-r2 \
  serde-home-r1 \
  rfc9114-text-r1
```

Publishes the five-class FRONT/Tamaraw chaff evidence as one create-only
transaction under `config/chaff-response-qualification-store/v2/`. The public
batch requires exactly five unique workload IDs with five distinct primary
HTTPS origins. It keeps application requests unchanged and creates a separate
chaff-only request namespace: `Accept` and `Accept-Language` are copied exactly
from the prepared resource, while `Accept-Encoding` is forced to `identity`.

For each workload, eligible known-valid same-origin candidates of at least
1,200 prepared body bytes are ordered deterministically by prepared body size,
resource ID, and URL. Each attempted candidate receives three independent
connection epochs separated by at least 30 seconds. One connection per epoch
issues 40 requests as eight sequential waves of at most five concurrent
requests, so a candidate qualifies only after 120 exact completions. Every
completion must have the same successful identity-encoded response status,
body length, and body SHA-256. Only an explicit identity or capacity rejection
advances to the next candidate; transport, DNS, timeout, or protocol failures
abort the transaction. Publication is atomic, and no v2 sidecar hash exists
until that exact five-file transaction succeeds from a clean build.

The unqualified command above is the immutable legacy route to the canonical
set directory named `v2`. The fresh classifier lineage instead uses an
explicit safe set name and a campaign binding:

```shell
./qcsd-lab qualify-response-chaff --set classifier-multiorigin5-v2 \
  getbootstrap-home-r4 cloudflare-quiche-r4 hyper-basic-client-r3 \
  serde-home-r2 rfc9114-text-r2
```

This publishes create-only under
`config/chaff-response-qualification-store/sets/classifier-multiorigin5-v2/`;
the parent `sets/` directory is tracked so a clean clone never creates it as an
unreviewed side effect. Each consuming FRONT/Tamaraw campaign must declare
`chaff_qualification_set: classifier-multiorigin5-v2`. The selected five
sidecars are copied into the result's frozen `inputs/chaff-qualifications/`
tree, so resume and verification never consult the live set. Omitting the
campaign field preserves the exact legacy `v2` lookup.

The fresh `classifier-multiorigin5-v2` set was qualified from clean Lab
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

That image is qualification provenance, not the acquisition collection image.
The later sealed acquisition used clean Lab
`8988a48a8e43cc9d47505cae12ee7758bc7fa5ee`, clean Neqo
`6aceaac85243d6e0e34354108e010705d3c83088`, and collection image
`sha256:38c24b0c5c4a06b223a904e896e1e38401c78fffbe6edab0f17846bb66a04de2`.
The distinction remains important because the qualification image above is not
the source receipt for any of the 2,500 formal samples.

The historical legacy POC5 exact-five cohort was qualified atomically from
clean Lab Q6 `0d0b1984c1d87b0502899cc451f1ed6ab6463d03`, tree
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
packet was observed. Its historical hashes are:

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
reconciliation. The failure was therefore not Windows, WSL, or capture-clock
instability. Hyper r1 had frozen resource 0 at 6,165 bytes and SHA-256
`96411b4e30fa8e579eebf6f9b2b7604ccb7335e990266a2da893fe4ff7426c40`,
while all ten retained Hyper executions returned 5,917 bytes and SHA-256
`59974039ec7fdcbc0461fd86f91fddc294ed7c2eb3cd46f96352be0687eaf106`.
Each of the six Tamaraw attempts correctly failed one slot with
`ReceiveCreditRetired` and exactly 243 retired bytes; the four undefended/FRONT
captures matched each other but not the frozen prepared identity.

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

The immediately preceding, now-historical exact-five cohort was qualified
atomically from clean Lab Q3
`06cacddc21ab0ded9422d445723f60f37c530363` and clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`, tree
`691209bdd616c25759d508f1af0547904b8ce058`, whose parent is F2
`a8378520b9740be782bfe526cdb3eb05e6665571` and whose exact patch hashes to
`a4b17821f8c119af9f022a609dd33e40be4f196fcad397b04ba444d859c4a7f8`.
The qualification collection image was
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
response-store v2. Its uniquely tagged qualification collection and prepare
images were respectively
`sha256:ef2e6a6b9464c34d80657c787d0b1fb15eb8ee03539db141c8cb4b7bcf5cc236`
and
`sha256:228fe4b3a8cf1287dc0d6fdc9a1ba627e1f6393f9d456de105c506f4111a9c88`,
under suffix `q-570851923bfa-6aceaac85243-20260817T164038Z`. Their
`source.json` SHA-256 was
`3d7448fc0025aa20d741ee6cffadca3b5b9312bd327853cfc47619b18819f43f`,
their raw implementation-receipt SHA-256 was
`a45875a057a495d5f5a6c30de7fd697bedc28dc856248e1eb3bdfbd2511d873f`,
and their implementation-receipt aggregate was
`6c1f190c8e5bfbf7951ea8aba081bb44ada4ffdc264089ff640fad89dca8a050`.

The Q4 image passed all 729 deterministic tests, with only the two
launcher-gated live tests skipped. Its first local-only `test live` then
passed the canonical capture path but exposed a stale controlled-test fixture:
the fixture relabelled a historical schema-five Walkie-Talkie profile as
schema six without deriving the added sender-framing cell. Neqo correctly
rejected that inconsistent test configuration before capture-clock
reconciliation. No public response qualification, rehearsal, interface
handoff, formal capture, or classifier export was launched from Q4. Commit
`32f8f4d816cf05ebc483cc547732d146225493c9`, tree
`d713ca9f665935a4dd953e242a636d2063ffc784`, repairs only the controlled
test fixture by deriving the current mold and matching prefix specification;
it does not change production capture semantics or Neqo F3. Q5
`af3403d60f5be008dc88cc52c6ce8ec5a34bc47c` is the documentation acquisition
child of that repair. Its clean image passed all 731 local prerequisite tests,
and its atomic exact-five qualification is the historical cohort published by P5.

The immediately preceding five-file transaction succeeded atomically from
clean Lab qualification source
`fcc6af4394b2b2f7dee5f8b1a214cd7673a9e0e8` (Q2), clean Neqo
`a8378520b9740be782bfe526cdb3eb05e6665571` (F2), qualification collection
image
`sha256:29a6e0adaa65d88e1e30afd3722f20f976fe14ed0676fb28d0448ec9155c0700`,
and prepare/actual qualification image
`sha256:ef5a3e7bcd20e8841f6c32064d40fcf94be48380f390146d5c039a49fc3665c0`.
Every sidecar binds implementation-receipt aggregate
`a8384fd28e9b22c0a683138c0d7a039db3abf927bcc6bd15ffc936bdf2f352a0`.
The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads. Fifteen independent connection epochs produced
`5 × 3 × 40 = 600` stable identity completions and 62,007 packet
observations. Within each workload, consecutive epochs retained at least the
required 30-second gaps, the maximum observed UDP payload was 1,200 bytes, and
no oversized packet was observed. Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `4b63acf9dfa58413500cf8eaa34fc326a71a74d6c5df3404378543ea5ae707cf` | `c2dc6643caa028e137d717adf4fc13561b1e3c07bfbad28bef2267c0ed20fc92` |
| `cloudflare-quiche-r3` | `5728dda8668bc4aca816495d87c56038a7ed267b3e902518cdd7bd84b990c3d2` | `0b7794ebdf2155901f7398c95602e111e27087ce5f945a22b198391aa1054277` |
| `hyper-basic-client-r1` | `e30e877f068a199688948357b19c61803f94cad57123382e79812492750ab55e` | `7b5a2755a6bf47010289df74d40dc45aeaf58c30dd2a8ce32fc928eaa7b70332` |
| `serde-home-r1` | `86b6d3fcdc208e50b71e5cf957770a9e6319dae39a2e87b9d884f713c0ec3da4` | `e433468dcfee5c2ff6de7d4376588e7c104f60d13977894412ee58a04c88a212` |
| `rfc9114-text-r1` | `e55414ca9da748f17b89c02d762b1ac39f74acb349ed60d67833c1d5999e627b` | `20ce6ddd56b4684179c0cec8cac12bcef7ce8ef9327d954c2ecfe2239ec84bd9` |

That exact batch was published without alteration by P2
`8a8d605166bfc27c6a7b8907162119e055ca7ca2`. The clean final P2 collection
and preparation images were respectively
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`
and
`sha256:82434c67e194d29dc26c0cfa90014f01a2473c61ea92e9213c47ea1afc55297d`.
Q2, F2, P2, both qualification images, both final P2 images, the implementation
receipt, and all five files and derived manifests are now historical and
excluded from the replacement source lineage. The hashes remain recorded
verbatim for recovery and audit; none is active canonical evidence.

The fixed transaction published from clean Lab qualification source
`2290b1f1a100d0d36f2d5ada405d9c26d382716d` (Q), clean Neqo
`867246557ec719fc34552b60abf624895be2706c` (F), qualification collection
image `sha256:7b556344d65339e5cb399c37f7fe2a84ea248c9608e193f12269018c4ca47920`,
and prepare/actual qualification image
`sha256:5d85e8d7d090e5a29e77fe5751c65c70299e2cf1fc709cb62c3fde50c16e191d`.
Every sidecar binds implementation-receipt aggregate
`33fe7032e9bf35efb7bb4d3d84b7e2733f4e81a455baef0df1df0120687e2c35`.
That complete transaction is now superseded because the qualified acquisition
implementation changed in Neqo. All five deterministic first candidates
(`candidate_index: 0`) had qualified, for
`5 × 3 × 40 = 600` stable identity completions. Each epoch's 40 completions
used eight waves of five requests (`8 × 5`), epochs retained the 30-second
gaps, and the receipts recorded a maximum UDP payload of 1,200 bytes with zero
oversized packets. Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `0bef93532273f59718e1fc4123eccfa6833922ff34f0d22cc9cf6cf03963cb5d` | `f411d539e656a5abd6a49c94da5a60d4e2898f141b1ebf86e48b2d2bd2ca4372` |
| `cloudflare-quiche-r3` | `d9dc5898464e7cb05f37fe9faf758250a72eaf14209913d7f2e56ffd31ced6ac` | `5d51d0f68d67c1847f49df01640c0ea6ca0a303dc3b567a4dc81f1ed5aef190a` |
| `hyper-basic-client-r1` | `4f8f51722d0c9a3d1d696f845bf2ee91ff45f3387b62c472115f682b5c353428` | `3fc7f34b90e9cbc423dc1f727bf157c5b3910b30bb61c2a52eef7a74cebf8a55` |
| `serde-home-r1` | `ee1f97b15a4f93702eda6c98b6578a2eb958df6f0f6a5129ab6b0a9d27ce3ca1` | `edb21e2792dfe59dd0c30f586709e5310e5b6ba5744a0c0a5ce334bd7746f797` |
| `rfc9114-text-r1` | `1d75fcf42ba170eabe76f5184adcc9551a4b3360d3e869f694108055360541af` | `e9dfb138adbdb18d43bf2c70eb34240dc54894a8e58aa1766853e4fbfdf178b6` |

Those exact files remain recoverable from Lab publication commit
`d5543406359528b1382222d8ef3d3cffd67b7d4d` and from frozen sealed results.

The earlier superseded five-file transaction was atomically published from clean Lab
commit `9953cf3a9a29a2cb5f6aaf02439cd13f318b6b39`, clean Neqo commit
`a3bd748c1b3f4e24f7dc88f673365e6842db51a7`, and qualification image
`sha256:c38afc629613bc8e7a5a82b55ad83a7e5787a51f780f14a199e9429be124ff43`.
Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `37e5e6933b337872b49889886e5930f3aa1a7778032bc9ed85a0372885e8e95d` | `330a8d41db984fc43c0c324e091cfba2906871a47ee06d7fb9c2de0aac1db32a` |
| `cloudflare-quiche-r3` | `e8fe81526aec5fa9af2c1c03ad4f093732ecc738a02bd2dd997104dc253a1957` | `38dfa66be8b0a55857845853c237a37014fe47095328d8d32187871277c3ac3e` |
| `hyper-basic-client-r1` | `816d6bcc0c43cf0d672fc0f21cc0dd871d80fa9ca24ebcadcbc81b48d33a3bed` | `ffc24029a219246cd40060cd70953e4cf0a3590e59a700ec6c6f72ce7800b54d` |
| `serde-home-r1` | `46abffb21b7f93ebe328f56ad82819fcced1586aa3966de2d733fa7a5133018f` | `91ad7a33ed70cfcf4bc1b062e747b1371bad00ca16171ee3539f40755f18c9d3` |
| `rfc9114-text-r1` | `d76a4ff366a6b8dce65b42cca02d2a55c6333e649b28316fcdfe58b060d34c2f` | `9fb65d16532ff6290aa530e4829f87167cd784a30bfb68e5d7d921acd5da8fc5` |

Those exact files remain recoverable from Lab commit
`88569f268260b36f0c4ccfc36681f7a42887b66c` and from frozen sealed results.
All five previously recorded response-store v2 transactions, including Q5/P5,
are historical only. Canonical legacy `v2` retains only the POC5 Q6/F3 cohort
published by P6.
Commit `47c91bb36dcddd3943253ee16141febbaf9041e8` remains the causal production
implementation change, while `32f8f4d816cf05ebc483cc547732d146225493c9`
repairs only the prerequisite's controlled schema-six fixture.
No historical sidecar, implementation receipt, image, rehearsal, formal
sample, or export could be mixed into that legacy POC5 Q6/P6 lineage. At that
boundary, a clean P6/F3 final-image build, an excluded 30/30 rehearsal, and a
verified interface handoff were required before formal acquisition could
restart.

Each response-store v2 file is sidecar schema 2 and derives a schema-4
`qcsd-qualified-chaff-manifest` with `qualification_scope: response-only` and
the exact request-header primitive. It contains neither Walkie-Talkie
prefix-pack fields nor a fitting-artifact binding. Historical response-store
v1 sidecars and their schema-3 runtime manifests remain frozen-compatible
verification inputs, but a frozen cohort cannot mix schema 3 and schema 4.
This narrower evidence is valid only when every defended runtime kind is FRONT
or Tamaraw; a baseline-only campaign needs no chaff qualification, while
campaigns containing another defence continue to require the full-v2
qualification contract. FRONT and Tamaraw are algorithmic and require no
fitting, but they still require response qualification and all ordinary
runtime-fidelity gates.

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
each, the `as-defined` request policy, and all seven then-established
selectable modes: five research defences plus two controls. It
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

For legacy generic campaigns, `max_attempts` is the automatic retry budget for
each invocation and an explicit `resume` begins a new operator-authorised retry
epoch for still-incomplete samples. BuFLO-study and schema-two class-study
campaigns use a stricter durable total instead: every physical collector launch
counts against the same per-sample limit across resumes, and an interrupted
launch is retained as a failure tombstone. Accepted samples remain immutable.
To avoid bypassing timing controls across a process restart, every previously
attempted origin waits one full configured cooldown before the first resumed
request.

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

### Offline classifier-pilot handoff

The classifier exporter is intentionally not a `qcsd-lab` capture command. Run
the separate Docker wrapper from this checkout after every source result
verifies:

```shell
./classifier-pilot export classifier-poc5-v2 \
  results/research-classifier-poc5-baseline-01-1200/<run-id> \
  results/research-classifier-poc5-paired-01-1200/<run-id> \
  results/research-classifier-poc5-baseline-02-1200/<run-id> \
  results/research-classifier-poc5-paired-02-1200/<run-id> \
  results/research-classifier-poc5-baseline-03-1200/<run-id> \
  results/research-classifier-poc5-paired-03-1200/<run-id> \
  results/research-classifier-poc5-baseline-04-1200/<run-id> \
  results/research-classifier-poc5-paired-04-1200/<run-id> \
  results/research-classifier-poc5-baseline-05-1200/<run-id> \
  results/research-classifier-poc5-paired-05-1200/<run-id> \
  results/research-classifier-poc5-baseline-06-1200/<run-id> \
  results/research-classifier-poc5-paired-06-1200/<run-id> \
  results/research-classifier-poc5-baseline-07-1200/<run-id> \
  results/research-classifier-poc5-paired-07-1200/<run-id> \
  results/research-classifier-poc5-baseline-08-1200/<run-id> \
  results/research-classifier-poc5-paired-08-1200/<run-id> \
  results/research-classifier-poc5-baseline-09-1200/<run-id> \
  results/research-classifier-poc5-paired-09-1200/<run-id> \
  results/research-classifier-poc5-baseline-10-1200/<run-id> \
  results/research-classifier-poc5-paired-10-1200/<run-id>
./classifier-pilot verify classifier-poc5-v2
```

The retained legacy POC5 contract binds one workload to each of five distinct
class origins: `getbootstrap-home-r3` to `getbootstrap.com`,
`cloudflare-quiche-r3` to `cloudflare-quic.com`,
`hyper-basic-client-r2` to `hyper.rs`, `serde-home-r1` to `serde.rs`, and
`rfc9114-text-r1` to `www.rfc-editor.org`. Ten acquisition blocks each
contribute a 100-sample baseline result (20 visits per class) and a 150-sample
paired result (ten visits per class under undefended, FRONT, and Tamaraw). The
exact total is 1,500 undefended, 500 FRONT, and 500 Tamaraw captures. The
exporter separately retains the earlier schema-1 six-class and stable3
pipeline contracts and rejects mixed lineages.

The wrapper runs the exact collection image with networking disabled, all
capabilities dropped, the checkout and result evidence read-only, and the
handoff output writable as the invoking UID/GID. Direct
`uv run python tools/classifier_handoff.py ...` execution is an internal
developer path for controlled fixtures only: a native host process lacks the
executed qualification receipt required to verify these research results.

The destination must not exist. Export is create-only and atomic. Every input
must be a complete sealed result in which all planned samples are accepted and
eligible. Inputs are read-only; the exporter verifies each evidence seal before
copying anything and rejects duplicate sample IDs, mismatched block cohorts,
symlinks, or an existing destination.

Attempt acceptance and export apply the same Linux-local timing gate. Every
primary direct capture must use one reconciled, evidence-eligible
constant-offset clock segment with zero steps and timestamp residuals no larger
than 10 ms. The collector brackets each Linux realtime reading with repeated
Linux monotonic readings and charges both pairing uncertainties against the
same 10 ms elapsed-difference budget. A timing-repaired or anchor-drifted
attempt is retained as a bounded retry failure and is never promoted.
Fresh captures must record the `host` timestamp type and both endpoint pairing
uncertainties. The exporter retains read compatibility for historical sealed
four-anchor results that predate those fields; an explicit non-`host`
timestamp type is always rejected.

The handoff is self-contained:

```text
handoffs/classifier-poc5-v2/
  README.md
  dataset.json
  samples.jsonl
  SHA256SUMS
  raw/
    <opaque-sample-id>.pcapng
    <opaque-sample-id>.pcap
    <opaque-sample-id>.run.json
  stripped/
    <opaque-sample-id>.pcap
  traces/
    <opaque-sample-id>.csv
```

The formal handoff contains 2,500 samples: 7,500 files under `raw/`, 2,500
stripped PCAPs, 2,500 CSV traces, and the four top-level receipt/inventory
files. That is 12,504 regular files in total; `SHA256SUMS` governs the other
12,503 files and deliberately excludes itself.

`raw/` preserves byte-exact PCAPNG evidence, a full-packet classic-PCAP format
conversion, and the corresponding Neqo run receipt for a trusted collaborator
who needs to build a different projection. Both capture formats are restricted
material: they contain real endpoint metadata, absolute times, and QUIC Initial
traffic from which handshake metadata may be recovered; the run receipt also
contains URLs and request configuration. They must not be the default
classifier input.

`stripped/` contains synthetic classic PCAP with nanosecond timestamps. Every
packet uses the same fixed documentation-only MAC addresses, TEST-NET IPv4
addresses, and UDP ports; its UDP payload is all zero. It preserves only the
relative packet time, client-relative direction, packet count, and Ethernet
`frame.len`. It is deliberately not a replayable QUIC exchange. `traces/`
provides the same model-facing projection directly as
`relative_time_ns,direction,length_bytes,signed_length_bytes`, with client
egress positive and server ingress negative.

In the schema-2 POC handoff, `class_label` is the approved origin hostname and
`workload_id` retains the exact frozen request-graph identity. `samples.jsonl`
maps each opaque sample ID to those identities, defence, request policy, visit,
source result, shared `acquisition_block_id`, split, and exported file hashes.
The exporter rejects overlapping or out-of-order acquisition blocks.
Undefended samples from
acquisition blocks 01--08, 09, and 10 are respectively `train`, `validation`,
and `test`; all FRONT and Tamaraw rows are `inference` and
`inference-only`, regardless of their temporal block. The exporter derives and
validates these assignments rather than accepting a caller-supplied split list.
`dataset.json` binds the checked-in campaign, source result, and evidence-index
hashes, declares the projection, and summarizes classes, defences, blocks, and
splits. `SHA256SUMS` closes the exported file inventory. These receipts protect
handoff integrity;
they do not replace the authoritative result seals.

Verify the portable inventory from inside the handoff root:

```shell
cd handoffs/classifier-poc5-v2
sha256sum -c SHA256SUMS
```

For the retained schema-1 pilots, `--splits` entries still align with result
roots in command-line order. POC5 instead requires all twenty roots in the
exact baseline/paired order shown above. `verify` rechecks the closed handoff
inventory, protocol counts, split policy, and all hashes without reading the
original result directories.

Josh should train from `traces/` or `stripped/`, use `class_label` as the
prediction target, and fit preprocessing, features, classifiers, and
hyperparameters only from undefended `train`/`validation` rows. The undefended
`test` rows provide the clean baseline; FRONT and Tamaraw are locked
inference-only conditions. Paths, `run.json`, defence/controller schedules,
and other metadata are not model features.

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

Manual receive retains an exact `STREAM_DATA_BLOCKED` report only while a
stream is pristine and wholly pre-header. The original small-floor path remains
available when the prepared body floor and requested, advertised, and known
limits agree below the absolute 1,000-byte framing target. A positive floor no
longer discards the proof merely because scheduled credit has already raised
the requested limit: that residual branch is permitted only when the
controller proves one live contiguous advertised scheduled range from the
effective initial receive offset through
`requested == advertised < 1000`, with known capacity beyond it. Either branch
appends only an ownerless, slotless parser lease through absolute offset 1,000,
bounded by the existing lifetime `max_stream_data_excess` budget. The residual
branch neither moves nor satisfies the scheduled range or its slot; only
consumption retires that debt, and any typed HTTP/3 progress invalidates the
retained transport proof. This bounded bootstrap permits one atomic HEADERS
frame to cross the residual scheduled prefix without changing a defence
schedule, parameter, slot-accounting rule, or capture-fidelity gate.

A separate terminal-tail bridge covers the corresponding post-DATA boundary
without changing scheduled ownership. Once incoming scheduling is complete,
with no queued assignment, continuation, or same-stream backing, a pristine
typed boundary may receive one ordinary 16-byte parser lease only when its
entire outstanding scheduled tail is already advertised, contiguous, and
between one and fifteen bytes; requested and advertised limits agree, known
exact capacity continues beyond them, and the full 16 bytes remain inside the
existing lifetime parser allowance. The lease is unowned and slotless. Its
grant or advertisement satisfies nothing: the original tail retains its slot
and only consuming those scheduled bytes can settle it. Gapped, partial,
post-cap, continuation-owned, or nonterminal states remain fail-closed.

FRONT alone opts into prearming its frozen packet targets. A future incoming
target remains private and ineligible before its exact not-before time; its
endpoint and deadline are frozen, with the strict 5 ms deadline unchanged.
Each drive reconciles every due fixed event and its incoming credit before
eligible output and ordinary input, using fresh monotonic time and absolute
wake instants. Release uses ceiling conversion and deadlines use floor
conversion, so prearming cannot transmit early or extend a deadline. Static
and non-FRONT dynamic schedules retain their existing activation behavior.

Receive-control batches are globally and transactionally preflighted using
typed lifecycle outcomes. Exact current-batch identities and persistent
accepted-but-unencoded `MAX_STREAM_DATA` identities are validated together;
shared transitive closures are cancelled once, transport rollback is previewed
in LIFO order, and encoded or advertised credit is never revoked. A
lifecycle-invalid receive-limit increase or manual-receive configuration
becomes terminal or gone only when unavailability is proven; ledger, ordering,
identity, and rollback inconsistencies remain fatal. Resulting observations
and defence realizability are flushed before unrelated actions, while a fatal
case records both the raw action and typed error. This changes no seed,
defence parameter, schedule, fidelity threshold, or acceptance threshold.

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
names. The earlier catalogue cohort's `-r2` manifests then predated absolute
whole-run UDP qualification: their application traffic used a 1200-byte
configuration, but their receipts did not prove that every handshake and
application datagram respected that ceiling. Those two earlier generations
remain historical preparation evidence only; the separately prepared POC5
Hyper r2 replacement has a current whole-run UDP receipt.

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
  an owned parser-liveness lease. For current incoming fixed opportunities,
  `credit_advertised_at_us` is the complete local on-wire `MAX_STREAM_DATA`
  boundary that rearms cadence, while `credit_consumed_at_us` is the distinct
  later peer stream-offset-consumption boundary that terminalizes the slot;
  both delay columns are measured from `action_time_us`. None of these fields
  claims scheduled server-datagram timing or size. The same versioned nullable
  suffix is present in `packets.csv` and `events.csv`. These records provide
  plot overlays and fidelity metrics.

  For schema-4 CS-BuFLO stop/drain evidence, schedule reconstruction reports
  terminal counts strictly before, exactly at, and at or before the stop
  timestamp. The Rust snapshot must fall between the strict and inclusive
  counts: controller observations sharing a timestamp have a stable production
  order that cannot be inferred from timestamp comparison alone.
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

The collection image is Linux-native and explicitly requests dumpcap's
`host` timestamp type on its container `eth0`. Packet evidence is compared
only with the Rust runner's Linux monotonic timeline. Windows QPC, W32Time,
PowerShell, WSL status flags, and any other outer-host clock are not capture
inputs or admission requirements. The same contract therefore runs on native
Linux and Linux container hosts; a different CPU architecture rebuilds the
image from the pinned commits and then follows the normal qualification and
rehearsal lineage.

An attempt is promoted only after direct-capture validation, endpoint-count
validation, response completion, interface GRO/GSO/TSO/USO evidence,
profile-wide UDP-payload-ceiling checks, and bounded runner/PCAP reconciliation.
That reconciliation must have one constant-offset segment, zero clock steps,
packet residuals no larger than 10 ms, and a bracket-uncertainty-aware Linux
realtime/monotonic elapsed difference no larger than 10 ms. The paired visit
then adds response-identity and defence-realization checks.

When a prepared workload freezes `expected_responses`, every otherwise
successful attempt must also match the exact prepared response signature:
resource ID, HTTP status, delivered byte count, body SHA-256, and successful
outcome. This gate runs before promotion. Drift is retained as the retryable
fidelity failure `StrictPreparedResponseIdentityFailure`, not promoted as an
accepted-but-ineligible sample. Crash recovery applies the same gate to a
successful terminal attempt before completing an interrupted promotion, so a
restart cannot bypass it. Failed attempts stay under `failures/`; a successful
attempt is moved once to the canonical sample path and is not duplicated.

`experiment.json` is checkpointed atomically. Accepted files are independently
bound by hashes before the terminal seal is written. A successful attempt's
diagnostics and prospective artifact hashes are checkpointed before its exact
five-file directory is atomically installed. Resume can therefore finish an
interrupted promotion without recollection. Verified accepted work is reused;
only a genuinely partial, unpromoted working attempt may be discarded.

See [METHODOLOGY.md](METHODOLOGY.md) for the scientific interpretation of the
observer, pairing, fidelity, and derived metrics.

## Research readiness and five-class classifier proof of concept

The post-fit 14-sample evaluation and 120-sample fitting campaign definitions
are checked in, and their completed results are sealed locally. The six-workload
fitting cohort is frozen. The later classifier study is a separately authorized
five-origin, three-condition closed-world proof of concept. The relevant exact
expansions are:

- fitting: six workloads × ten visits × two request policies × undefended =
  120 samples;
- post-fit smoke: two workloads × one visit × one request policy × seven modes
  = 14 samples;
- deferred six-class classifier pilot: seven independently sealed blocks ×
  six workloads × one visit × one request policy × seven modes = 42 samples
  per block and 294 samples in the complete pilot;
- immediate three-class classifier pilot: seven independently sealed blocks ×
  three workloads × one visit × one request policy × seven modes = 21 samples
  per block and 147 samples in the complete, now-superseded pipeline pilot;
- POC5 rehearsal: five workloads × two visits × one request policy ×
  undefended/FRONT/Tamaraw = 30 samples, all excluded from the formal corpus;
- POC5 formal corpus: ten temporal blocks × five workloads ×
  (30 undefended + 10 FRONT + 10 Tamaraw visits) = 2,500 samples;
- pre-final rehearsal: six workloads × one visit × one request policy × seven
  modes = 42 samples;
- final: six workloads × three visits × one request policy × seven modes =
  126 samples.

The retained legacy POC5 workload/class bindings were exactly
`getbootstrap-home-r3`/`getbootstrap.com`,
`cloudflare-quiche-r3`/`cloudflare-quic.com`,
`hyper-basic-client-r2`/`hyper.rs`, `serde-home-r1`/`serde.rs`, and
`rfc9114-text-r1`/`www.rfc-editor.org`. The prepared Haxx workload
`http3-explained-en-r1` is not used by the rehearsal, formal campaigns, or
handoff. FRONT and Tamaraw use their fixed research-profile algorithms and
seeds; the POC neither consumes nor refits the Traffic-Morphing, WTF-PAD, or
Walkie-Talkie artifacts. The legacy POC5 recovery contract requires five
response-store v2 sidecars (schema 2) deriving schema-4 runtime manifests,
with no prefix-pack or fitted-data dependency. All previous v2 transactions
are superseded, and canonical legacy `v2` contains only the POC5 Q6/F3 cohort
published by P6. The historical Q5 image, incorporating Linux-local capture
integrity commit
`47c91bb36dcddd3943253ee16141febbaf9041e8`, passed all 731 local prerequisite
tests before its atomic
qualification, and the P5 final images then passed their image and campaign
preflights; the excluded rehearsal nevertheless rejected the stale Hyper r1
identity as recorded above. The completed Q6/F3 qualification remains
published by P6 as legacy POC5 compatibility evidence; it is not qualification
or image provenance for `classifier-multiorigin5-v2`.
Historical v1/schema-3 evidence remains readable only for its frozen
compatibility role.

Each temporal block has two campaign files:
`classifier-poc5-baseline-NN.yml` contributes 20 undefended visits per class,
and `classifier-poc5-paired-NN.yml` contributes ten visits per class under each
of undefended, FRONT, and Tamaraw. Thus every block contributes 30/10/10 per
class without extending the campaign schema. The workload order rotates so
every class occupies every workload position exactly twice across ten blocks.
The paired seeds were selected prospectively from deterministic plan expansion;
each class/condition occupies each of the three within-visit positions 32--35
times across its 100 visits.
Blocks 01--08, 09, and 10 supply the undefended 240/30/30
train/validation/test split per class. All 100 FRONT and all 100 Tamaraw rows
per class are inference-only. Run baseline before paired in odd-numbered
blocks and paired before baseline in even-numbered blocks, verify both results
immediately, and retain the shared temporal block in the handoff. The exporter
accepts the twenty result arguments in canonical
`baseline-01, paired-01, ..., baseline-10, paired-10` order, checks sealed
timestamps for the odd/even capture chronology, and requires each pair to
finish before the next block starts.

```shell
./qcsd-lab verify config/campaigns/classifier-poc5-rehearsal.yml
./qcsd-lab run config/campaigns/classifier-poc5-rehearsal.yml
./qcsd-lab verify results/research-classifier-poc5-rehearsal-1200/<run-id>
./classifier-pilot export classifier-poc5-rehearsal-v2 \
  results/research-classifier-poc5-rehearsal-1200/<run-id> \
  --splits interface
./classifier-pilot verify classifier-poc5-rehearsal-v2
# Proceed only if all 30 rehearsal samples are accepted and eligible and the
# handoff is ingestible. The rehearsal is never reused in classifier training
# or evaluation. Then run and verify both campaigns in blocks 01 through 10.
```

For odd block `NN`, run the baseline campaign before the paired campaign; for
even `NN`, reverse those two operations. In either case each operation is:

```shell
./qcsd-lab verify config/campaigns/classifier-poc5-<kind>-NN.yml
./qcsd-lab run config/campaigns/classifier-poc5-<kind>-NN.yml
./qcsd-lab verify \
  results/research-classifier-poc5-<kind>-NN-1200/<run-id>
```

Do not start block `NN+1` until both block-`NN` results verify as complete,
with every planned sample accepted and eligible. A failed formal result is
retained and diagnosed; it is never replaced with an ad-hoc campaign or a
different seed. All twenty formal results must bind one identical clean Lab
commit, Neqo commit, and collection-image source receipt. The rehearsal
authorizes only the exact image, workloads, and campaign commit that it ran;
any rebuild, source or workload repair, parameter change, or class replacement
requires a new excluded 30-sample rehearsal before formal acquisition.

### Fresh approved-origin multi-origin v2 cohort

`classifier-multiorigin5-v2` is a wholly fresh 2,500-capture lineage. It does
not reuse any POC5 or `classifier-multiorigin5-v1` capture, seed, sample ID,
response sidecar, campaign namespace, analysis, or handoff row. It measures a
fixed approved-origin HTTPS `GET` graph. This is a page-like replay of every
resource admitted to that frozen graph, including approved cross-origin
resources; it is not a full browser page load, render, cache model, or record
of every third-party request on the public site. The five class labels remain
the primary page domains. Secondary origins contribute encrypted traffic to
that class and are never separate labels.

The frozen workload graphs are:

| workload | class label | approved origins | resources |
| --- | --- | ---: | ---: |
| `getbootstrap-home-r4` | `getbootstrap.com` | 1 | 9 |
| `cloudflare-quiche-r4` | `cloudflare-quic.com` | 3 | 6 |
| `hyper-basic-client-r3` | `hyper.rs` | 2 | 7 |
| `serde-home-r2` | `serde.rs` | 1 | 20 |
| `rfc9114-text-r2` | `www.rfc-editor.org` | 1 | 2 |

Cloudflare uses `cloudflare-quic.com`,
`blog-cloudflare-com-assets.storage.googleapis.com`, and
`blog.cloudflare.com`; Hyper additionally uses `cdn.jsdelivr.net`. Chromium
discovers and admission-filters the graph during preparation only. Collection
replays it with Neqo: one QUIC/H3 connection per approved origin and one
request stream per resource when its dependencies are ready. Multiple resource
streams on the same origin share that origin's connection; streams and origin
connections can progress concurrently in the same sample event loop. Their
exact endpoint-tuple union is retained in one PCAP.

The five-file response qualification set
`config/chaff-response-qualification-store/sets/classifier-multiorigin5-v2/`
has been published as a create-only transaction. Defended campaigns bind
`chaff_qualification_set: classifier-multiorigin5-v2`; baseline campaigns
intentionally omit the set because they contain no response-only defence. Run
the excluded rehearsal first with the exact final collection image:

```shell
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab verify \
  config/campaigns/classifier-multiorigin5-v2-rehearsal.yml
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab run \
  config/campaigns/classifier-multiorigin5-v2-rehearsal.yml
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab verify \
  results/research-classifier-multiorigin5-v2-rehearsal-1200/<run-id>
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab analyze \
  results/research-classifier-multiorigin5-v2-rehearsal-1200/<run-id>
./classifier-pilot export classifier-multiorigin5-v2-rehearsal \
  results/research-classifier-multiorigin5-v2-rehearsal-1200/<run-id> \
  --splits interface
./classifier-pilot verify classifier-multiorigin5-v2-rehearsal
```

The rehearsal is five workloads times two visits times three conditions: 30
captures, permanently excluded from training and evaluation. Proceed only
after all 30 are accepted, eligible, sealed, verified, analyzed, independently
checked for multi-endpoint capture, responses, clocks, schedules, credits,
offloads, and the 1200-byte UDP ceiling, and exported to the verified
interface-only handoff `handoffs/classifier-multiorigin5-v2-rehearsal/`. Any
subsequent source, image, workload, qualification, campaign, or defence change
invalidates it.

The formal files are
`classifier-multiorigin5-v2-{baseline,paired}-NN.yml`. Each of ten temporal
blocks contributes 100 baseline captures and 150 paired captures, for 500
captures per class and 2,500 total. The exact totals are 1,500 undefended, 500
FRONT, and 500 Tamaraw. The exact acquisition chronology is:

```text
B01, P01, P02, B02, B03, P03, P04, B04, B05, P05,
P06, B06, B07, P07, P08, B08, B09, P09, P10, B10
```

That is baseline then paired in odd blocks and paired then baseline in even
blocks. Never begin the next block until both current results are complete,
sealed, verified, and analyzed. Pass roots to the exporter later in canonical
baseline-01, paired-01, ..., baseline-10, paired-10 argument order; their
sealed timestamps must prove the acquisition chronology above.

After each sealed campaign, including the rehearsal and every formal result,
run `./qcsd-lab verify` and then `./qcsd-lab analyze
results/<campaign>/<run-id>` before continuing. Analysis generates
`summary.csv`, `report.html`, paired trace SVGs, and aggregate latency/overhead
SVGs. After all twenty formal results pass, export the separate create-only
handoff `classifier-multiorigin5-v2` and verify it; the destination is
`handoffs/classifier-multiorigin5-v2/`. Josh should normally train from
`traces/` or `stripped/`; `raw/` PCAPNG, classic PCAP, and run receipts are
restricted audit inputs because they retain real endpoint, timing, QUIC
Initial, URL, and request metadata. Use only undefended blocks 01--08 for
training, block 09 for validation, and block 10 for the clean test. FRONT and
Tamaraw remain inference-only.

Status: the excluded v2 rehearsal completed 30/30 accepted and eligible, its
interface handoff is sealed, and all twenty formal result roots completed,
verified, and produced their per-campaign analyses. The create-only formal
handoff at `handoffs/classifier-multiorigin5-v2/` contains all 2,500 samples:
1,500 undefended, 500 FRONT, and 500 Tamaraw. Its `SHA256SUMS`, `dataset.json`,
and `samples.jsonl` SHA-256 values are respectively
`85bfd88be6c2105201ec7ff3eb87a743e378bd748a9c2097db2fb227875ec2d7`,
`46289f368912ee6e90314578814b821eb0dfeadcd794d3422c1af3599623317b`,
and `5974ab9c582793501c558ec294bea4e3afb01bf57039f990fceba33fb0b1e15f`.
This artifact is a five-class classifier-*pipeline* pilot, not evidence of
classifier or defence efficacy: only undefended blocks supply the
train/validation/test observations, while every FRONT and Tamaraw sample is
inference-only. It neither evaluates an attacker retrained within each defence
nor supplies validation evidence for the later BuFLO or CS-BuFLO candidates.

The entire `classifier-multiorigin5-v1` acquisition lineage is retained only
as superseded diagnostic evidence. Its excluded rehearsal, B01, P01, and P02
must never be mixed into v2. P02 exposed live Cloudflare response-identity
drift, was stopped at a sample boundary, and remains deliberately unsealed;
none of its accepted files is a v2 sample or handoff row.

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
It then completed baseline-01 at
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
004 stalled with
310–325 scheduled response bytes still unconsumed below the atomic HEADERS
boundary. Hyper 009 combined strict misses with a typed transport
`InvalidInput` on one attempt. These observations motivated, prospectively,
the residual scheduled-prefix bootstrap, FRONT-only prearming, and
transactional typed receive-action preflight described above; no seed,
schedule, fidelity gate, or acceptance threshold was changed.

P2 then produced a fresh excluded rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260815T201524.981071Z`
from clean Lab P2 `8a8d605166bfc27c6a7b8907162119e055ca7ca2`, F2
`a8378520b9740be782bfe526cdb3eb05e6665571`, and collection image
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`.
It is sealed incomplete and permanently excluded: 29/30 samples were accepted
and eligible, while Hyper visit 000 FRONT failed deterministically across all
three attempts. The sealed evidence-index and experiment hashes are
`3d9baba02bb87e3e884992c1a215dcb549b8f1628b732826a5b502669e496df7`
and `c9544d06a4349f5160388fb93f7ea8b9be7c5f80435668ef0dd66360379978ff`.
Each failed attempt opened every application request stream, and every
application request's bytes and FIN were acknowledged, but all five response
resources remained incomplete; 1,333,200 scheduled incoming bytes were
requested, zero were consumed, and all were retired at timeout. Retained
capture evidence shows that response datagrams reached the host.

The failure was a two-layer F2 liveness defect. FRONT's fixed-schedule
`reconcile_due_fixed` processed due incoming work at the exact elapsed instant
but did not advance the incoming boundary used by `next_deadline`; when that
work could not yet allocate, its retry deadline remained in the past. The
single-thread runner treated the past deadline with an await-free `continue`,
so it hot-looped without polling socket readiness and starved the already
arriving response. F3 advances only that fixed-schedule retry watermark while
retaining exact elapsed processing, private future events, and global order;
the runner now performs a readiness-aware await with a one-microsecond retry
timer for an already-due target while leaving future absolute wake arithmetic
unchanged. No schedule event is dropped, reordered, or artificially satisfied.

All five result roots above remain immutable diagnostic evidence. The earlier
passing rehearsal no longer authorizes a replacement image, baseline-01
contributes no sample to the replacement corpus, and no accepted row from
either incomplete result may be reused. No formal campaign and no classifier
export was run from P2. Q3 completed the atomic exact-five F3 qualification,
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
their retries remain permanently excluded as well.

The incomplete six-class diagnostic at
`results/research-classifier-pilot-01-1200/20260814T064655.275845Z` is excluded
from the POC5 corpus and classifier export. None of its individually accepted
samples is reused. Its Apache response drift and FRONT/Tamaraw fidelity
failures show that the strict gates rejected that particular run; they do not,
by themselves, establish a general defect in Neqo. The replacement cohort was
therefore required to pass a fresh Linux-local capture-integrity rehearsal with
exactly 30/30 accepted and eligible samples and a verified interface handoff
before any formal block; v2 satisfied that prerequisite.
Never weaken fidelity to force a pass. Refresh, repair, or prospectively
replace a failing class under a new frozen contract instead.
The fitting corpus, qualification runs, smoke result, failed attempts, and
qualification diagnostics are likewise never POC5 classifier samples.

These POC5 campaign files, the offline exporter, tests, and documentation are
outside the qualification implementation-file inventory, but the clean Lab
commit remains part of source provenance. Canonical legacy response-store
`v2` retains only the POC5 Q6/F3 cohort published by P6 after the P5 rehearsal
exposed stale Hyper r1 response identity. At that POC5 boundary, formal
acquisition and classifier export required a clean P6/F3 final collection
image, a fresh excluded rehearsal with exactly 30/30 accepted and eligible
samples, and a verified interface handoff before restarting from baseline-01.
Keep the historical response-store v1/schema-3 evidence
frozen-compatible; do not regenerate the separate historical full-v2
sidecars, prefix specs, fitting result, or sealed `research-1200` bundle.

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
qualification or fitting input. The POC5 campaigns do not define or execute
the separately named historical 42-sample pre-final rehearsal or 126-sample
engineering campaign. Both remain explicitly on hold and require later
authorization.
