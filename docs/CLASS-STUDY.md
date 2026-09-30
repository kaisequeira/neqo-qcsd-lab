# Extended-class study: acquisition and continuation

Current protocol summary: 30 September 2026, Australia/Sydney. The
[project ledger](../PROJECT.md) records progress; this document records the
next work and its purpose. The checked-in
[study contract](../config/class-study/v1/study.json), implemented validators
and `./qcsd-lab class-study --help` are authoritative for typed inputs.
The [capture-readiness guide](CAPTURE-READINESS.md) details the evidence
required before public acquisition, fitting, certification and formal capture.
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

The v129 desktop no-cache build, pinned CDP, 110-vector browser gate and
acquisition-only authority passed on their bound source. A versioned
acquisition checkpoint initialized, but its watcher stopped before accepting
any pilot class. `tranco-0000697` missed its probe window after repeated
recoverable Neqo HTTP/3 failures; `tranco-0000984` carries a durable internal
redirect-dependency error. Preserve v129 and its attempts. A standalone v129
image diagnostic, without a formal receipt, passed a Neqo control probe to
`cloudflare-quic.com` and saw `Error: Timeout(12)` for `consultant.ru` and
`www.consultant.ru` on the default Docker bridge. It cannot reclassify v129.
The source fix and prospective schema-11 pre-baseline screen require the next
unused cohort and fresh source-bound proof. V130 passed its no-cache build,
pinned CDP probe and 110-vector browser gate, but acquisition authority failed
its correctness suite (1,885 passed, 93 failed, 6 skipped); it issued no
authority. A bounded v130-image live diagnostic then observed a root CDP
`InvalidInterceptionId` while navigating `consultant.ru`. It selected a page
for `elmundo.es`, but the schema-11 HTTP/3 screen rejected both primary
origins after two classified 12-second timeouts each, with passing controls.
The diagnostic has no formal receipt or accepted credit and cannot reclassify
either historical cohort. Earlier v127 and v126 initialization failures also
remain historical evidence.
Accepted extended-study progress remains pilot 0/120, final classes 0/100,
certification 0/900 and formal 0/16,000.

## Cost-escalating sequence

The objective of early checks is to find implementation problems before
repeating expensive qualification. They do not replace mandatory gates.

| Order | Stage | Purpose and exit condition |
|---:|---|---|
| 1 | Focused host-only checks and synthetic receipt/consumer replay | Check architecture selection, schemas, acquisition rules, lifecycle handling and host prerequisites cheaply |
| 2 | Clean source freeze, allocator, unused cohort and registered no-cache build | Bind exact source and collection image through `./qcsd-lab build --cohort-version N` |
| 3 | ETF/veth diagnostics, pinned CDP and focused browser/teardown checks using the registered image | Verify timing/network support, browser identity and known late-failing behaviour |
| 4 | Acquisition correctness and schema-2 acquisition authority | Clean build, acquisition correctness and pinned CDP authorise public acquisition after the authority independently verifies |
| 5 | Pre-baseline HTTP/3 screen, acquisition and two genuine short-horizon prepared observations | Admit the first 24 eligible candidates per stratum; freeze 120-class pilot selection and assembly |
| 6 | 110-vector browser-egress gate, reference, timing stress, 18 regression, code and 160 controlled samples; full foundation | Authorise all class-study capture roles, including fitting, on the same source/build/acquisition lineage |
| 7 | 480 pilot fitting, 720 qualification, 1,080 compatibility | Derive pilot profiles, qualify capacity/prefixes and establish each pilot class/mode combination |
| 8 | Final selection, 2,000 authoritative fitting, 600 qualification, 900 certification | Freeze 100 classes plus reserves, refit and prove all final class/mode combinations |
| 9 | Readiness and historical pre-snapshot; ten canary/formal block pairs | Collect 1,000 excluded canaries and 16,000 formal samples |
| 10 | Historical post-snapshot, sealing, handoff, evaluation, comparison and attestation | Establish final correctness, performance and leakage conclusions |

The full foundation is required before any class-study fitting or capture.
Under the prospective schema-2 route, public acquisition can begin after a
verified step-4 authority binds the current clean source, no-cache build,
acquisition contract, acquisition correctness and pinned CDP receipt. The
110-vector browser gate is deferred until step 6; its final receipt and the
full foundation must bind the same source/build lineage before fitting or
defense capture. The existing schema-1 route remains available: complete and
verify browser qualification first, then supply its root when creating the
four-gate acquisition authority. No historical or diagnostic receipt gains
credit from this revised order.

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
executable and distribution hashes. V127 passed native desktop qualification on
its bound source; changed source requires a new qualification.

Before an evidentiary build, verify user systemd/cgroup v2, Docker access,
network namespace and traffic-control capability, and clock stability.
Before capture, verify at least three Docker-visible logical CPUs. The launcher
assigns separate CPUs
to collection sidecars, the measured client, and the orchestrator/ETF helper,
then records the selected partition. Timing and isolation gates still decide
whether a host can produce valid evidence. Keep the checkout on the Linux
filesystem.
The launcher probes the CPU IDs available inside the pinned collection image
and assigns the last two observed IDs to the client and helper. All other
observed IDs serve sidecars, so offset and sparse sets retain three separate
partitions. The full ID list is recorded in version 4 scheduler receipts.
Check that Docker's actual backing volume is healthy and has positive free
space, then inspect the build preflight's capacity observation. Disable sleep
during collection. Run the cheap diagnostics first, repairing client-side
defects before source freeze.

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
On a restored workspace, ensure the private
`artifacts/buflo-study/cohort-claims-v1` directory is owned by the invoking
user and has mode `0700`; the guardian refuses a broader mode before publishing
a claim.

After source freeze and preflight, run these commands **one at a time**, inspect
each exit and receipt, and stop on failure. The shell parameter check requires
an externally chosen version; it does not itself authorise that version.

```shell
: "${COHORT_VERSION:?set the allocator-authorised unused positive cohort}"
BUILD="artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json"
PINNED_CDP="artifacts/buflo-study/pinned-cdp-execution-v${COHORT_VERSION}.json"
AUTHORITY="artifacts/class-study-acquisition-authority-v${COHORT_VERSION}.json"

./qcsd-lab build --cohort-version "$COHORT_VERSION"
./qcsd-lab test pinned-cdp --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --destination "$PINNED_CDP"
./qcsd-lab class-study acquisition-authority --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --pinned-cdp-receipt "$PINNED_CDP" \
  --destination "$AUTHORITY"
./qcsd-lab class-study verify --target "$AUTHORITY"
```

This is the prospective schema-2 path; use it only after the amended contract
and producer/consumer validators are implemented and checked on the frozen
source. Its authority producer runs acquisition correctness in the registered
image. A failed gate produces no authority. The schema-1 path still runs the
browser commands below before authority creation and supplies
`--browser-egress-qualification-root "$BROWSER_EGRESS"` to that command.
Use a fresh create-only authority destination for either route.

For later actions, obtain exact input paths from the preceding verified
receipts and the coordinator's help. After the schema-11 source has fresh
verified acquisition authority, choose a create-only versioned root such as
`artifacts/classifier-multiorigin100-v1-acquisition-v${COHORT_VERSION}`.
Pass that same path as `--acquisition-root` to `acquisition-init` with
`--acquisition-authority` and to `acquisition-watch`. Do not resume or relabel
an older checkpoint under changed source or contract. Use
`acquisition-watch` to schedule due actions; direct `acquisition-run` is
reserved for its supervised scope. Initialize from the verified authority,
using a UTC start time at or after its recorded time, then run one action:

```shell
ACQUISITION_ROOT="artifacts/classifier-multiorigin100-v1-acquisition-v${COHORT_VERSION}"
./qcsd-lab class-study acquisition-init \
  --candidate-catalogue config/class-study/v1/classifier-multiorigin100-v1-candidates.json \
  --acquisition-root "$ACQUISITION_ROOT" --acquisition-authority "$AUTHORITY" \
  --acquisition-started-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
./qcsd-lab class-study acquisition-watch --acquisition-root "$ACQUISITION_ROOT" --max-actions 1
```

It exits after one fully verified coordinator action and
prints that action's result, so inspect the checkpoint and failure details
before invoking the watcher again. The registered action still covers up to
two candidates; this limit changes only how many actions one watcher invocation
performs. Omit `--max-actions` after the early batches are healthy to let the
watcher supervise the remaining acquisition.
The stability-receipt and admitted-workload roots remain canonical and
create-only across cohorts. After a first such publication, a new source
cohort can collide on the same candidate. Verify the first live batches before
scaling the watcher, and preserve all published evidence if a later fix needs
a new cohort; a complete namespace migration is required for that restart.
Complete acquisition with `acquisition-complete`; freeze pilot/final cohorts
with `cohort` and campaigns with `campaigns --stage pilot|authoritative`.
Before the full foundation or any fitting/capture role, run and verify the
deferred 110-vector browser gate on the **same source and build**:

```shell
BROWSER_EGRESS="artifacts/buflo-study/browser-egress-qualification-v${COHORT_VERSION}"
./qcsd-lab test browser-egress create --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --result-root "$BROWSER_EGRESS"
./qcsd-lab test browser-egress verify --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" --result-root "$BROWSER_EGRESS"
```

Use `capture`/`resume` through `class-study` for every study capture role;
generic `run`/`resume` cannot bypass its prerequisite ledger. Numeric fitting,
prefix derivation, qualification and final bundle publication use
`fit-numeric`, `prefix-specs`, `qualify-prefix`, and `finalize-fitting`.
The final actions are `readiness`, `historical-snapshot`, `export`, `evaluate`,
`comparison-review`, `attest`, and `verify`.

## Population, complete resource graphs and stability

The separately imported
[`crux-73-v1.source.json`](../config/curated-sources/crux-73-v1.source.json)
records 73 supplied domains in source order, origin and URL-count hints, the
exact source-file SHA-256, and seven matches to the frozen pre-browser safety
policy. The URL observations are provenance hints only: they are not page
URLs, current resource graphs, eligibility results or capture instructions.
The user chose to keep the catalogue below for formal acquisition on 28
September 2026. The curated receipt does not replace it. To import another source,
run `PYTHONPATH=src .venv/bin/python tools/import_curated_source.py SOURCE NEW_RECEIPT`
from the repository root with a fresh destination. The importer validates the
source and publishes a create-only receipt; this import has no acquisition
authority.

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

Before arming a stability baseline, the prospective schema-11 screen probes a
known-good HTTP/3 control at `https://cloudflare-quic.com/`. If it fails, the
screen blocks without candidate or second-control probes. If it passes, the
screen performs two 12-second Neqo attempts per distinct selected-page URL
request origin, then probes the control again. An origin passes only with two
`known_valid=true` results and fails only with two classified connectivity
timeouts or `IdleTimeout` results. With both controls passing, a candidate is
technically rejected if **at least one** origin fails and every other origin
has a definite pass or fail: the fixed timed batch would otherwise still
probe the dead page. If all origins pass, full page preparation follows. Any
mixed or ambiguous origin blocks, even if another origin fails; a failed
second control also blocks. The screen is bound as diagnostic
evidence in the candidate's navigation attempt. It covers selected-page
request origins only; third-party resource origins discovered during timed
preparation can still cause a missed-window blocker. It does not establish
that subresources or the full page graph are replayable. Resolved addresses are
diagnostic observations only; this screen does not claim that Neqo connected to
a pinned address. The registered candidate order and later complete-coverage
requirements remain in force.

| Schema-11 observation | Allowed batch publication after baseline |
|---|---|
| `t+30s` | 25–35 seconds |
| `t+5m` | 4 min 30 sec–35 min |

The baseline records the timing origin; the two prepared observations provide
the response and semantic resource-graph signatures that must agree. After
both pass, admit the first `t+30s` manifest unchanged. Retries must start
within the same registered window with their own durable attempt ID; they
cannot inherit a previous timestamp or relabel an orphaned manifest. Missed
windows and infrastructure errors block completion rather than count as
selective site rejections. This prospective schema-11 rule establishes
short-horizon reproducibility at durably published dispatch windows; the
individual concurrent page workers' network starts are not separately
timestamped. Historical schema-10 receipts retain their two-observation rule
without a pre-baseline HTTP/3 screen. Historical schema-9 receipts retain their
genuine 30-second, 24-hour and 72-hour rule and three-day claim boundary.

The scheduler bounds action duration and admits at most two candidates and
five live pages. Unresolved batches keep a 40-minute collision envelope; once
all members have verified scientific terminals, the next batch may begin
60 seconds after the latest terminal, subject to the watcher's proof that the
previous Docker scope is empty. The paired, all-survivor 120-candidate
schema-11 lower bound is 5 hours 29 minutes from first baseline to last
earliest repeat with zero-duration page work. A five-minute terminal per
batch gives 5 hours 59 minutes before real navigation, HTTP/3 screening,
status and recovery overhead. Preserve the true dispatch windows;
do not promise immediate pilot completion after acquisition authority. Completion requires
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
