# Extended-class study: acquisition and continuation

Current protocol summary: 25 September 2026, Australia/Sydney. The
[project ledger](../PROJECT.md) records progress; this document records the
next work and its purpose. The checked-in
[study contract](../config/class-study/v1/study.json), implemented validators
and `./qcsd-lab class-study --help` are authoritative for typed inputs.
Older runbooks remain in the [history](PROJECT-HISTORY.md) for thesis auditing;
their superseded order and schema descriptions do not authorise execution.

## Endpoint and current position

The final experiment is **100 classes × 20 visits × eight conditions = 16,000
accepted formal samples**, preceded by **900 checks covering every final
class under every selectable mode**. Both class identity and visit counts
match across conditions. The conditions in stable order are `undefended`,
`front`, `tamaraw`, `traffic-morphing`, `wtf-pad`, `walkie-talkie`, `buflo`
and canonical CTSP `cs-buflo`. `static` is the ninth certification mode.
CPSP is a controlled CS-BuFLO ablation, not another selectable mode.

The claim remains **five validated defences plus two candidates / nine
selectable modes**. Qualification on the new classes remains pending for all
modes. BuFLO/CS-BuFLO validation requires the final attestation, and describes
client-only QUIC adaptations rather than bilateral paper implementations.

At migration, v116 had 75 passing browser vectors, two operational failures
and an interrupted outstanding attempt, with no recorded semantic failure.
It remains incomplete on the laptop. Accepted extended-study progress is
pilot 0/120, final classes 0/100, certification 0/900 and formal 0/16,000.
The desktop must establish fresh source/build/host authority.

## Cost-escalating sequence

The objective of early checks is to find implementation problems before
repeating expensive qualification. They do not replace mandatory gates.

| Order | Stage | Purpose and exit condition |
|---:|---|---|
| 1 | Focused local tests and synthetic receipt/consumer replay | Check architecture selection, schemas, acquisition rules and lifecycle handling; reproduce known failures cheaply |
| 2 | Native development image, host/ETF/veth and focused browser/teardown diagnostics | Verify timing/network support and known late-failing behaviour before the full browser gate; explicitly non-evidentiary |
| 3 | Clean source freeze, unused cohort, fresh no-cache build and pinned-CDP | Bind exact source, images, browser executable/distribution and host |
| 4 | 110-vector browser-egress gate and acquisition authority | Packet-observed browser coverage plus acquisition-correctness evidence authorise public acquisition |
| 5 | Acquisition and genuine 30-second/24-hour/72-hour observations | Admit the first 24 eligible candidates per stratum; freeze 120-class pilot selection and assembly |
| 6 | Reference, timing stress, 18 regression, code and 160 controlled samples; foundation | Authorise all class-study capture roles, including fitting, on the same source/build/acquisition lineage |
| 7 | 480 pilot fitting, 720 qualification, 1,080 compatibility | Derive pilot profiles, qualify capacity/prefixes and establish each pilot class/mode combination |
| 8 | Final selection, 2,000 authoritative fitting, 600 qualification, 900 certification | Freeze 100 classes plus reserves, refit and prove all final class/mode combinations |
| 9 | Readiness and historical pre-snapshot; ten canary/formal block pairs | Collect 1,000 excluded canaries and 16,000 formal samples |
| 10 | Historical post-snapshot, sealing, handoff, evaluation, comparison and attestation | Establish final correctness, performance and leakage conclusions |

The full foundation is required before any class-study fitting or capture.
Public acquisition can begin under the narrower acquisition authority after
step 4. Both authorities must bind identical source, build, acquisition
contract, pinned-CDP and browser evidence. This is the current registered
order; old prose requiring full foundation before acquisition is superseded.

Run source-bound Docker jobs serially. During a live job all agents only poll
its existing process/session. Investigations, changes and documentation work
wait until it exits. Use a separate authoring clone between operations to
publish progress without moving the pinned execution checkout.

## Desktop bootstrap

Restore and checksum-verify the working set described in the
[evidence index](EVIDENCE-INDEX.md), including all cohort allocation history.
Use native amd64 preparation/browser execution on Windows x64/Ubuntu WSL2;
the historical laptop browser evidence is ARM64. The architecture profile
must bind the pinned Chromium/Playwright version and verified archive,
executable and distribution hashes. Native desktop qualification is pending.

Before an evidentiary build, verify user systemd/cgroup v2, Docker access,
network namespace and traffic-control capability, clock stability, and at least
12 Docker-visible CPUs including indices 10/11. Keep the checkout on the
Linux filesystem. Require 64 GiB free on Docker's actual backing volume.
Disable sleep during collection. Run the cheap diagnostics first, repairing
client-side defects before source freeze.

Begin with these read-only/development commands while no campaign is live:

```shell
git status --short
git -C neqo-qcsd status --short
git submodule status neqo-qcsd
./qcsd-lab --help
./qcsd-lab class-study --help
./qcsd-lab test pinned-cdp --help
./qcsd-lab test browser-egress --help
./qcsd-lab etf-probe --help
./qcsd-lab etf-veth-probe --help
```

Do not hardcode the next cohort from a previous chat. Reconcile the checked-in
consumed-cohort ledger and restored allocation/attempt evidence. The build
allocator must accept the chosen unused positive version. A missing final
receipt does not make a version reusable.

After source freeze and preflight, run these commands **one at a time**, inspect
each exit and receipt, and stop on failure. The shell parameter check requires
an externally chosen version; it does not itself authorise that version.

```shell
: "${COHORT_VERSION:?set the allocator-authorised unused positive cohort}"
BUILD="artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json"
PINNED_CDP="artifacts/buflo-study/pinned-cdp-execution-v${COHORT_VERSION}.json"
BROWSER_EGRESS="artifacts/buflo-study/browser-egress-qualification-v${COHORT_VERSION}"
AUTHORITY="artifacts/class-study-acquisition-authority-v${COHORT_VERSION}.json"

./qcsd-lab build --cohort-version "$COHORT_VERSION"
./qcsd-lab test pinned-cdp --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --destination "$PINNED_CDP"
./qcsd-lab test browser-egress create --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --result-root "$BROWSER_EGRESS"
./qcsd-lab test browser-egress verify --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --result-root "$BROWSER_EGRESS"
./qcsd-lab class-study acquisition-authority --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --pinned-cdp-receipt "$PINNED_CDP" \
  --browser-egress-qualification-root "$BROWSER_EGRESS" \
  --destination "$AUTHORITY"
./qcsd-lab class-study verify --target "$AUTHORITY"
```

For later actions, obtain exact input paths from the preceding verified
receipts and the coordinator's help. Use `acquisition-init` with
`--acquisition-authority`, then `acquisition-run` or `acquisition-watch`.
Complete acquisition with `acquisition-complete`; freeze pilot/final cohorts
with `cohort` and campaigns with `campaigns --stage pilot|authoritative`.
Use `capture`/`resume` through `class-study` for every study capture role;
generic `run`/`resume` cannot bypass its prerequisite ledger. Numeric fitting,
prefix derivation, qualification and final bundle publication use
`fit-numeric`, `prefix-specs`, `qualify-prefix`, and `finalize-fitting`.
The final actions are `readiness`, `historical-snapshot`, `export`, `evaluate`,
`comparison-review`, `attest`, and `verify`.

## Population, complete resource graphs and stability

The pinned Tranco W36Q9 snapshot contains one million domains. The frozen
catalogue has 600 candidates, 120 from each rank stratum: 1–1,000;
1,001–10,000; 10,001–100,000; 100,001–500,000; 500,001–1,000,000.
Order is deterministic from the snapshot hash, study ID and canonical domain.
Take the first 24 scientifically eligible candidates in each stratum for the
pilot; later retain 20 final and four reserves per stratum.

The primary page and redirects stay inside the exact candidate domain and
its subdomains. That navigation boundary does **not** exclude cross-origin
subresources. Discovery iteratively admits observed public HTTPS GET origins
and retains every request instance, including repeated URLs and dependency
edges. Single-origin and multi-origin classes are both eligible. Origin count
is neither a ranking input nor a quota.

Registered discovery limits are 32 approved origins, 512 audited origins and
eight convergence passes. Exceeding a cap or failing convergence produces a
typed class rejection; an admitted workload is never silently truncated.
Each resource has a 1 MiB response ceiling. Authentication, service-worker
dependence and non-replayable actions remain outside admission. Every fitting,
qualification and capture mode must retain the exact admitted graph; a defence
cannot omit an inconvenient origin or resource. Report realised origin counts.

Stability compares final URL, status, content type, body length, body SHA-256
and semantic `resource_graph_sha256`. Per-run provenance differs, so raw
prepared-manifest hashes are recorded but not used as longitudinal identity.

| Observation | Allowed network-observation start after baseline |
|---|---|
| `t+30s` | 25–35 seconds |
| `t+24h` | 23 h 45 min–24 h 15 min |
| `t+72h` | 71 h 45 min–72 h 15 min |

After all three pass, admit the first `t+30s` manifest unchanged. Retries must
start within the same registered window with their own durable attempt ID;
they cannot inherit a previous timestamp or relabel an orphaned manifest.
Missed windows and infrastructure errors block completion rather than count
as selective site rejections.

The scheduler bounds action duration, admits at most two candidates and five
live pages, and preserves terminal batch reservations plus the 40-minute
guard. The ideal all-survivor 120-candidate schedule is about 7.62 days before
real execution and rejections. Preserve the true observation windows; do not
promise immediate acquisition after the browser gate. Completion requires
every earlier candidate in each selected prefix to have a scientific terminal
outcome; the unused catalogue tail remains explicitly unassessed.

## Fitting, qualification and matrices

Traffic Morphing, WTF-PAD and Walkie-Talkie consume natural-traffic fitting
observations. Traffic Morphing uses `as-defined` samples and a deterministic
no-self assignment; WTF-PAD pools `as-defined` timing distributions;
Walkie-Talkie uses `half-duplex` samples and deterministic minimum-weight
pairing. FRONT, Tamaraw, BuFLO and CS-BuFLO use fixed algorithm parameters but
still need runtime/chaff-capacity qualification.

Each numeric and final bundle binds cohort selection and assembly. Prefix
qualification is separate from fitting traffic; the final bundle closes
numeric parameters, prefixes, workload manifests and qualification evidence.
The historic six-workload bundle remains valid for its own cohort only.

| Stage | Matrix | Count | Formal classifier input |
|---|---|---:|:---:|
| Timing stress | BuFLO complex two-origin visits; one launch each | 12 | No |
| Regression | 2 controlled workloads × 9 modes | 18 | No |
| Controlled foundation | 2 workloads × 4 treatments × 4 networks × 5 visits | 160 | No |
| Pilot fitting | 120 classes × 2 visits × 2 policies × undefended | 480 | No |
| Pilot qualification | 120 classes × 6 capacity/prefix executions | 720 | No |
| Pilot compatibility | 120 classes × 9 modes × 1 visit | 1,080 | No |
| Authoritative fitting | 100 classes × 10 visits × 2 policies × undefended | 2,000 | No |
| Final qualification | 100 classes × 6 executions | 600 | No |
| Final certification | 100 classes × 9 modes × 1 visit | 900 | No |
| Canaries | 10 blocks × 100 classes × undefended | 1,000 | No |
| Formal | 10 blocks × 100 classes × 2 visits × 8 modes | 16,000 | Yes |

Controlled treatments are undefended, BuFLO, CTSP and CPSP. Networks are clean;
symmetric 50 ms RTT; symmetric 5 Mbit/s with 25 ms one-way delay and 100-packet
queue; and symmetric 1% loss with 25 ms one-way delay. Both ingress and egress
conditioning must be receipted. Reference, timing stress, regression, code and
controlled receipts combine into full foundation authority.

Timing stress requires 12 first-launch passes. Each includes the 100-second
inclusive prefix (5,001 opportunities per direction), with bounded terminal
drain up to 6,000 opportunities per direction. All outgoing opportunities,
including tick zero, require kernel timing and independent router-ingress
matching. The complete prefix and suffix must pass strict fidelity; this is
separate from the 18 regression samples and has no replacement retries.

Final selection uses boolean technical eligibility and qualified Walkie-Talkie
pair feasibility, never accuracy, privacy, bandwidth or latency outcomes. The
pilot's 60 qualified one-to-one pair edges must supply 50 pairs retaining
20 classes per stratum. Unqualified pairs cannot be inferred feasible.
Freeze final selection and immutable assembly before authoritative fitting.

## What the 900 checks prove, and failure handling

Certification proves one accepted first launch for every final class/mode on
the exact image, source, graph, parameters, fitting bundle and qualification
set. It checks status, redirects, lengths and body hashes; application-byte
integrity; graph preservation; non-trivial defence activity; exact event and
credit accounting; packet ceilings; timestamp reconciliation; and absence of
protocol errors, timeouts, truncation or unexplained traffic. This bounds the
compatibility claim to that frozen experiment; public servers can still change.

BuFLO permits no partial, suppressed, missed, late, mismatched, catch-up or
unresolved events. CS-BuFLO partial/suppressed egress needs transport-proven
congestion/pacing reasons and still permits no actual missed/unresolved event.

| Role | Maximum physical sample launches | Consequence |
|---|---:|---|
| Pilot fitting, compatibility, authoritative fitting | 3 | Retry only explicitly permitted operational failures; preserve all attempts |
| Certification | 1 | Failed cell leaves certification incomplete |
| Canary and formal | 3 | Exhaustion blocks campaign; no substitution after formal starts |

`experiment.json` is checkpointed with `running` and the incremented attempt
count before collector launch. An interruption after that checkpoint consumes
the attempt. A global first-launch claim fixes each campaign result root;
resume cannot choose a fresh root to reset the launch allowance. Acquisition
has its own `checkpoint.json` and bound `provenance.json`.

`StrictDefenseFidelityFailure` and `StrictClientDefenseExecutionFailure`
stop before further cells or retries. Preserve the exact evidence, reproduce
the defect cheaply, repair the client/Lab, and establish a fresh cohort with
all invalidated downstream evidence. Do not drop a class, shrink a graph,
weaken a gate or add server-side defence cooperation to hide the failure.

Only the registered successor path permits pre-formal replacement: a sealed
incomplete certification must contain the same-workload undefended
`StrictPreparedResponseIdentityFailure`. Defence-only, transport, interruption
or infrastructure failures do not authorise replacement. A successor retains
the frozen pilot/pair graph and cumulative exclusions, maximises retention,
and needs fresh 2,000 fitting, 600 qualification and 900 certification evidence.
Reserves never replace a class after formal collection begins.

## Formal capture, evaluation and completion

After readiness and historical pre-snapshot, run all 100 undefended canaries
before each corresponding 1,600-sample formal block. Counterbalance modes with
the deterministic cyclic Latin square. Origin-aware scheduling interleaves
unrelated classes without changing membership or the 30-second per-origin
cooldown. Use 120-second client timeout, 180-second capture, 1 MiB response
ceiling, 64 MiB capture ceiling, 1,200-byte UDP ceiling and one-second settle.

Preflight derives storage/time projections from the sealed 900-cell
certification, requiring three times remaining projected evidence space.
Report expected wall time before launch. This study has no separate rehearsal
stage: old focused-study smoke/rehearsal matrices cannot substitute for its
certification-derived preflight.

Each accepted sample retains exactly:

```text
capture.pcapng
neqo/run.json
neqo/packets.csv
neqo/events.csv
neqo/schedule.csv
```

Keep kernel/router sidecars in their separately closed evidence subtree.
Seal each block; preserve raw PCAPNG/run receipts and the exported classic
PCAP, identifier-free shape PCAP and CSV views. Final handoff schema 3 binds
each sample's full workload/runtime/parameter/qualification identities and
the final cohort, assembly and ten block launch claims. Historical snapshot
verification protects the old 2,500-sample handoff before and after capture.

Temporal training uses blocks 1–8 (12,800 samples), validation block 9 (1,600)
and held-out test block 10 (1,600). No tuning uses block 10. Evaluate adaptive
attackers separately within each mode and an undefended-trained transfer view;
report stratified ten-fold results as secondary. The 100-class chance level
is 1%; the earlier five-class pilot's chance level was 20%.

Panchenko, pinned Weka VNG++ and clean-room DLSVM receive only relative time,
direction and observer-frame length. Exclude addresses, ports, CIDs, hostname,
TLS/QUIC metadata, payload and labels. Report accuracy, balanced accuracy,
confusion matrices, per-class recall and 95% block/workload bootstrap intervals
using 10,000 draws. Report overhead as ratio-of-sums with its additional
percentage separately, paired latency/goodput/resource distributions, tail
metrics, composition, timing and suppression evidence. RAPL is nullable when
unavailable. See [METHODOLOGY.md](../METHODOLOGY.md) for metric definitions.

Only complete sealed formal evidence, verified handoff, correctness/performance
and classifier evaluation, paper comparison with explained discrepancies,
historical post-snapshot and all hashes passing can produce the final
validation attestation. Update the project ledger and append each milestone
to history as it completes; migration and local tests do not finish this goal.
