# Evidence required to begin class-study capture

Status: 29 September 2026, Australia/Sydney. This is an evidence map and
decision record for the extended class study. The executable rules are the
checked-in [study contract](../config/class-study/v1/study.json), the validators
in [class attestation](../src/qcsd_lab/class_attestation.py) and
[class pipeline](../src/qcsd_lab/class_pipeline.py), and the coordinator's
`./qcsd-lab class-study --help`. The [project ledger](../PROJECT.md) records the
latest accepted counts. The [continuation runbook](CLASS-STUDY.md) gives the
operator sequence. A proposed faster protocol below has no authority until it
is versioned, implemented, tested and bound to fresh execution receipts.

## Define the start line

“Start capture” has several different meanings in this study. Passing an
earlier line does not imply that a later one has passed.

| Activity | Earliest admissible evidence | What may be claimed |
|---|---|---|
| Public-page discovery and stability acquisition | A current, verified acquisition-only authority or stronger current full foundation, followed by an initialized runner bound to it | Candidate observations; no defense or classifier samples |
| Pilot defense fitting and compatibility capture | Completed acquisition, frozen 120-class pilot selection and assembly, and verified full defense foundation on the same source/build/acquisition lineage | Disjoint pilot fitting and compatibility evidence; no formal classifier samples |
| Final fitting and first-launch certification | Verified pilot fitting, qualification and nine-mode compatibility, a feasible qualified Walkie-Talkie pair graph, and frozen final 100-class selection/assembly | Final fitting/qualification evidence and then 900 class-by-mode checks; still no formal classifier samples |
| Ten canary/formal block pairs | Verified class readiness after all 900 final checks, then a verified historical pre-snapshot; each block also needs its prior 100 undefended canaries | Accepted formal samples only after each result deep-verifies and its block seals |
| Final thesis validation | All ten blocks, post-snapshot, verified handoff, evaluation, comparison and validation attestation | Validation of the stated client-only adaptations, subject to the measured claims |

The current study has **zero accepted pilot classes, zero final classes, zero
certification cells and zero formal samples**. Engineering tests and browser
qualification cannot increment any of these scientific numerators. The
registered endpoint is 100 classes × 20 visits × eight formal modes = **16,000
accepted formal samples**; `static` is a ninth compatibility mode but no formal
condition. The study's current claim remains **five validated defenses plus
two candidates / nine selectable modes** until final attestation. The two
candidates are client-only QUIC BuFLO and CS-BuFLO adaptations, with ordinary
HTTP/3 servers. See [methodology](../METHODOLOGY.md) and the
[study contract](../config/class-study/v1/study.json).

## Authority and lineage common to every line

1. Freeze a clean Lab source commit and its clean pinned Rust submodule/Gitlink.
   Allocate the next unused positive cohort. A claimed or attempted cohort
   cannot be reused because its final receipt is absent. Build fresh no-cache
   images and verify the build/completion receipts. The image, source, Rust
   commit, study contract and cohort must agree. Host tests alone are not a
   collection-image or source-bound gate.
2. Verify the pinned CDP integration receipt and the final packet-observed
   browser-egress receipt for **110 of 110 vectors**, zero operational and
   semantic failures. The final receipt and its closed vector inventory,
   rather than a passing prefix or service-journal line, establish the gate.
3. Produce the authority for the intended role. Acquisition authority has four
   reconstructed hard gates: current clean source/no-cache build,
   acquisition-focused correctness, pinned CDP and complete browser egress.
   The full foundation adds independent reference conformance, the complete
   code gate (including its timing-stress dependencies), 18 of 18 nine-mode
   regression samples and 160 of 160 controlled qualification samples. It
   binds the same build, source, contract, CDP and browser evidence. Acquisition
   authority permits public acquisition only; it cannot authorize fitting.
4. Independently verify the authority and every cited immutable receipt. Later
   acquisition, fitting, campaign, readiness and result receipts carry exact
   hashes and source/build bindings. A receipt from an earlier source remains
   historical evidence; it never upgrades itself when code or contract changes.
   Use create-only evidence destinations and preserve unsuccessful attempts.

The registered [study contract](../config/class-study/v1/study.json) says
`waivers: forbidden`. This is a chosen research protocol and implemented
acceptance rule, not a law or an external ethics-board prohibition. It can be
changed **prospectively** with a new, explicit protocol/source identity and
new evidence. An amendment cannot relabel old attempts as formal samples or
silently inherit an authority whose source or contract hash changed. The
[repository rules](../AGENTS.md) also require source-bound Docker campaigns
to run serially and a pinned execution checkout during each live job.

## Public-page acquisition: what is actually required

The registered catalogue is
[`classifier-multiorigin100-v1-candidates.json`](../config/class-study/v1/classifier-multiorigin100-v1-candidates.json),
derived from the pinned Tranco W36Q9
[receipt](../config/class-study/v1/tranco-W36Q9.receipt.json). It has 600
deterministically ordered candidates, 120 in each of five rank strata. These
are a *search pool*, not 600 eligible classes that must all be captured.
Completion takes the first **24 scientifically eligible candidates per stratum**
(120 pilot classes), with a terminal scientific outcome for every earlier
candidate in each prefix. The unvisited tail remains unassessed. An
infrastructure failure, interruption or missed observation window blocks the
run; it is not a reason to reject a site selectively.

The acquisition runner's `checkpoint.json`, `provenance.json`, individual
attempts and terminal receipts must match the frozen catalogue, authority and
study contract. The coordinator publishes active attempts before work, merges
results in catalogue order, and can recover only under unchanged inputs.
`acquisition-init` creates a runner; it does not itself collect a page. The
first accepted observation requires a real network visit, prepared resource
manifest, successful technical admission and all registered stability checks.

The primary navigation and redirects must stay within the exact candidate
domain or its subdomains. Public HTTPS GET subresources may be cross-origin;
their observed request instances, repeated URLs and dependency edges remain
in the graph. The 32 approved-origin, 512 audited-origin and eight-pass
convergence limits produce typed rejection if exceeded; the runner may not
truncate an accepted graph. Authentication, service-worker dependence and
non-replayable actions are outside the admitted workload. Every later mode
must use the same complete prepared graph. Neither origin count nor later
classifier/privacy performance is a selection quota.

The **prospective schema-11 rule** first runs a pre-baseline Neqo HTTP/3
reachability screen. If the first `https://cloudflare-quic.com/` control fails,
the screen blocks without candidate or second-control probes. Otherwise it
runs two 12-second attempts for every distinct selected-page URL request
origin, then a second control. An origin passes only with two
`known_valid=true` results and fails only with two classified connectivity
timeouts or `IdleTimeout` results. With both controls passing, at least one
failed origin technically rejects the whole candidate only when every other
origin has a definite pass or fail. Any mixed or ambiguous origin blocks,
even if another fails; a failed second control also blocks. This screen's
results are embedded in the
hash-bound navigation-attempt ledger. It does not prove complete page-graph
replay, and resolved addresses are diagnostics rather than a claim of pinned
Neqo connections.

After that screen, two genuine prepared observations follow a durably recorded
scheduling baseline. Each probe batch must be
durably published for dispatch within its window:

| Probe | Allowed batch publication after baseline |
|---|---:|
| `t+30s` | 25–35 seconds |
| `t+5m` | 4 min 30 sec–35 min |

Compare final URL, status, content type, body length/hash and semantic
resource-graph hash **between the two real observations**. The scheduling
baseline alone has no prepared graph and cannot supply that comparison. The
first `t+30s` prepared manifest is admitted unchanged only after the second
observation agrees. A retry must have its own durable attempt ID and begin
inside the original window. Both probes normally run in one bounded action.
The recorded time proves dispatch of concurrent page workers; their individual
network starts are not separately timestamped. The claim is short-horizon
replay agreement at the registered dispatch windows, without packet-level
proof of an exact 30-second or five-minute network start. Unresolved batches
retain a 40-minute collision reservation. Once every member has an immutable,
verified scientific terminal, the next batch may be admitted 60 seconds after
the latest terminal; the watcher also waits for the prior scoped Docker action
to exit and prove its scope empty. Each action has up to two compatible
candidates and a five-live-page cap. With zero-duration page work, every
candidate surviving, and every second probe dispatched at its earliest
4-minute-30-second boundary, the 120-candidate lower-bound projection is
**5 hours 29 minutes** from the first baseline to the last second probe.
At a five-minute terminal per batch it is **5 hours 59 minutes**. Real page
time, HTTP/3 screening, navigation, rejected candidates and recovery change
these figures.
They exclude fitting, certification and formal capture; neither is a forecast
for 16,000 samples.

The historical schema-9 rule required `t+30s`, `t+24h` and `t+72h` probes.
Its corresponding all-survivor projection was **7 days 14 hours 50 minutes**.
Schema-10 receipts also remain historical under their two-observation rule
without a pre-baseline screen. None is promoted into schema 11 or implies
three-day stability for newly admitted classes. The new claim is
short-horizon replay agreement, with later final certification and canaries
providing separate drift observations.

After completion, verify the completion receipt, selection receipt and
120-class assembly. The assembly binds each exact admitted prepared graph.
Only then is the pilot cohort available to the fitting campaigns. The
[acquisition code](../src/qcsd_lab/class_acquisition.py) and
[cohort code](../src/qcsd_lab/class_cohort.py) implement these checks.

## Defense foundation, pilot and final cohort

The **full foundation must verify before any class-study capture role**, even
undefended pilot fitting. It needs the same current source/build/CDP/browser
lineage as acquisition, plus reference, code, regression and controlled-gate
evidence described above. The independent BuFLO timing stress consists of 12
first-launch complex two-origin visits in the code-gate chain. A current
acquisition-only authority cannot stand in for this foundation. The foundation
receipt and each result's frozen `inputs/class-study-foundation.json` must
deep-verify against the current collection image and source.

The registered pre-formal work is deliberately separate from classifier data:

| Stage | Required accepted evidence | Why it precedes formal capture |
|---|---:|---|
| Pilot fitting | 120 classes × 2 visits × 2 policies = 480 | Fit natural traffic without using evaluation samples |
| Pilot full chaff/prefix qualification | 120 × 6 = 720 executions | Establish runtime and prefix capacity on admitted graphs |
| Pilot compatibility | 120 × 9 modes = 1,080 | Check class/mode combinations and qualified Walkie-Talkie pairs |
| Final selection and assembly | 100 classes, 20 per stratum, plus 20 reserves | Freeze the eligible classes and exact graphs before final fitting |
| Authoritative fitting | 100 × 10 visits × 2 policies = 2,000 | Produce independent final numeric parameters |
| Final full qualification | 100 × 6 = 600 executions | Bind the final prefix and chaff capacity |
| Final certification | 100 × 9 modes = 900 first-launch checks | Establish one accepted run for every final class and selectable mode |

The pilot's qualified one-to-one Walkie-Talkie pair graph must supply 50
qualified pairs with exactly 20 final classes per stratum. The choice may use
boolean technical eligibility and that frozen pair graph; it must not use
accuracy, leakage, overhead or latency. Numeric, prefix and final fitting
bundles, qualification sidecars, campaigns, cohort selection and assembly are
all create-only and hash-bound. Final fitting and certification must use the
frozen final cohort and its complete graphs, not an opportunistic replacement
or a defense-specific reduced resource set.

Certification requires exactly one **started** physical launch per final
class/mode cell and all 900 accepted. It checks prepared-response identity,
complete graph, application bytes, defense activity, timing/event/credit
accounting, packet limits and absence of protocol errors or unexplained
traffic. A failed cell leaves the original certification incomplete. The
registered successor route permits replacement only before formal capture,
on a sealed incomplete certification with a qualifying same-class undefended
`StrictPreparedResponseIdentityFailure`; it restarts authoritative fitting,
qualification and all 900 checks. Generic defense or infrastructure failures
cannot be turned into selective class replacement. See the
[runbook](CLASS-STUDY.md) and
[successor validator](../src/qcsd_lab/class_successor.py).

## The formal launch gate and accepted sample definition

The readiness attestation reconstructs the foundation, completed acquisition,
pilot and final selection/assembly, fitting, qualification and the sealed
900-cell first-launch certification on one lineage. A verified historical
**pre-snapshot after readiness and before the first canary** proves that the
protected older 2,500-sample handoff remains byte-for-byte intact. The
pre-snapshot and readiness receipts are frozen into every canary/formal result.
The protected corpus has a closed 12,503-entry checksum inventory; see the
[evidence index](EVIDENCE-INDEX.md).

Each of ten blocks first runs 100 undefended canaries, then 1,600 formal
samples (100 classes × 2 visits × eight modes). Canaries are excluded from
classifier input. The eight conditions are `undefended`, `front`, `tamaraw`,
`traffic-morphing`, `wtf-pad`, `walkie-talkie`, `buflo` and canonical CTSP
`cs-buflo`. Modes use a cyclic Latin-square order and origin-aware scheduling
with a 30-second per-origin cooldown. The registered client timeout is 120
seconds, capture ceiling 180 seconds and settle period one second; these
limits do **not** establish a measured per-sample wall time.

Before formal launch, the preflight measures the sealed certification's
bytes and wall time, projects remaining canary/formal work, and requires free
space of at least three times its projected evidence bytes. It reports both an
observed-rate estimate and a conservative time estimate. The code's 151-second
per-cell conservative planning floor is a reporting assumption, not a measured
duration or launch blocker. Each physical launch
is consumed once `experiment.json` records `running` and increments the
attempt count, before collector start. `experiment.json` is the sole resume
authority; the global first-launch claim fixes the result root. Canary and
formal cells allow at most three preserved attempts, only for permitted
operational failures. There is no replacement or relabeling after formal work
starts. A new source or changed workload/parameter/acceptance rule needs a
fresh cohort and downstream evidence, not a resumed old checkpoint.

An accepted sample has the exact five-file inventory `capture.pcapng`,
`neqo/run.json`, `neqo/packets.csv`, `neqo/events.csv` and
`neqo/schedule.csv`, plus separately closed sidecar evidence where required.
The result verifier reopens each file and receipt, checks response status,
length and body hashes for every resource, endpoint-origin and complete
runtime-graph identity, the mode's qualification and parameters, and packet/
runtime fidelity. Only a sealed, deeply verified formal result advances the
16,000 numerator. An interrupted launch, attempted cell, local test,
engineering probe or passing prefix advances none. See
[class pipeline](../src/qcsd_lab/class_pipeline.py) and
[capture orchestrator](../src/qcsd_lab/orchestrator.py).

After block ten, the historical post-snapshot, sealed handoff and its closed
sample/hash inventory, correctness and overhead analyses, temporal classifier
evaluation, paper comparison and final attestation remain necessary for the
thesis's validation claim. The temporal split is blocks 1–8 training, block 9
validation and block 10 held-out test. No block-ten tuning is permitted.

## Current blocker and what v129 actually proves

On source commit `cd5dd7d2a7c711f819a342046c191a3d80a5c3c9` with Rust
Gitlink `e8575fd8e54921ed6ff867de475b4a734064866e`, v129's build, pinned
CDP and browser receipt at
`artifacts/buflo-study/browser-egress-qualification-v129/final.json`
passed and independently verified **110/110** vectors. Its
`artifacts/class-study-acquisition-authority-v129.json` passed all four hard
gates without waivers. These are **public-acquisition-only** receipts on their
recorded source and schema-10 contract; neither is a full defense foundation.

The v129 `acquisition-init` created
`artifacts/classifier-multiorigin100-v1-acquisition-v129/`, but the watcher
stopped with zero accepted classes. `tranco-0000697` has a missed-window
terminal after recoverable Neqo failures, and `tranco-0000984` has a durable
internal redirect-dependency error. A standalone v129-image diagnostic passed
a `cloudflare-quic.com` Neqo control (`known_valid=true`) while
`consultant.ru` and `www.consultant.ru` each returned `Error: Timeout(12)`
on the default Docker bridge. That diagnostic has no formal receipt and cannot
reclassify the v129 checkpoint. The redirect fix and prospective schema-11
screen need a fresh source-bound build, pinned CDP, 110-vector browser gate and
acquisition authority in the allocator's next unused cohort. No acquisition
or formal sample has been accepted. Local evidence paths in this section are
intentionally code paths; local artifacts are not guaranteed to exist in
another clone.

The versioned acquisition checkpoint alone does not isolate every publication
path. Stability receipts under `artifacts/<study>-stability/` and admitted
workloads under `config/workloads/` are still canonical and create-only. If a
new source cohort is required after an earlier cohort publishes either output,
the same candidate can collide there. Historical outputs cannot be silently
reused under a new source. A complete cohort-specific namespace would require
coordinated watcher, layout, receipt and downstream admission changes. Verify
the first live batches and their published outputs before scaling the watcher;
record any source failure and plan that broader namespace change if a restart
becomes necessary.

## Fastest scientifically honest route to substantial three-week progress

The user wants as much progress as possible through the 16,000 formal
captures within three weeks. The current protocol's acquisition projection,
full foundation, **4,460 pre-formal fitting/compatibility/certification
captures**, **1,320 additional pilot/final qualification executions**, and
17,000 later canary/formal cells are a serial critical path. Actual durations
of the later stages have not been measured on the final cohort. Thus no
three-week completion or progress fraction is presently evidenced.

The arithmetic makes both prerequisites and formal throughput important:

| Time available **after readiness** | Cells remaining (1,000 canary + 16,000 formal) | Mean accepted rate needed for all cells |
|---|---:|---:|
| Full 21 days, with zero time for prerequisites | 17,000 | One every 106.7 seconds, continuously |
| 14 days after one week of prerequisites | 17,000 | One every 71.2 seconds, continuously |
| 7 days after two weeks of prerequisites | 17,000 | One every 35.6 seconds, continuously |

These are average *accepted* rates over 24-hour days, including failures,
repairs, canaries, restarts, image and block overhead. For a half-complete
formal corpus (8,000 samples), all 1,000 canaries would not necessarily have
run yet; the exact threshold depends on which blocks are sealed. For example,
five complete blocks require 500 canaries and 8,000 formal samples: **8,500
accepted cells**, or one every 142.3 seconds if 14 days remain after
readiness. This is a planning calculation, not a measured forecast.

The sealed historical five-class, three-mode campaign provides a limited
reference point: 2,500 samples had 103,307.31 seconds of summed result
durations (41.32 seconds/sample) over a 156,837.08-second wall span (62.73
seconds/sample including idle); its final block alone averaged 130.89
seconds/sample. Those workloads, modes and operating conditions differ from
the proposed eight-mode, 100-class corpus. Use the final cohort's 900-cell
certification, rather than extrapolating this older run, to estimate accepted
throughput and storage before formal launch.

A faster study must be registered **before** its first new evidence, on a
new source/contract identity. The short-horizon acquisition amendment is the
immediate change being implemented. The other options require their own
implementation and evidence; none is an implicit waiver:

1. **Use the prospective short-horizon gate.** Schema 11 retains two actual
   prepared observations at `t+30s` and `t+5m` windows after its pre-baseline
   HTTP/3 screen, preserving the semantic response/graph comparison. Relative
   to schema 9, the short windows reduce the ideal first-120 acquisition
   projection by more than six days while narrowing the claim to short-horizon
   reproducibility. The new rule
   still needs fresh qualification and live receipts before it has execution
   authority. Later drift must be reported, including failures, without
   retroactive cohort repair.
2. **Use authenticated terminal release.** The amended rule preserves the
   40-minute collision envelope while a batch is unresolved, then allows the
   next batch after every member is scientifically terminal and a 60-second
   delay has elapsed. The watcher separately proves the earlier scoped Docker
   action exited and its scope emptied before launching another. This removes
   idle reservations without running uncoordinated containers. Actual release
   speed must be measured on live acquisition receipts.
3. **Consider pre-formal repetition only after the first new cohort.** The
   strongest scientific requirement to retain is a frozen, balanced 100-class
   multi-origin corpus and one successful compatibility check for each final
   class/mode. Pilot/final fitting visits and redundant qualification work
   could be prospectively reduced after checking whether the fitting methods
   still have enough independent observations and the per-class chaff/prefix
   capacity remains demonstrated. This changes precision and generality. The
   current amendment retains all registered pre-formal counts because changing
   that matrix would delay the next authority and require wider verifier work.
   Do not use formal samples for fitting.
4. **Measure one end-to-end accepted sample before promising a schedule.**
   Certification provides the first relevant wall-time and byte basis. Use its
   observed distribution, accepted rate, failures and the preflight's storage
   projection to decide whether serial formal capture can make the desired
   progress. Multiple *independent* formal capture lanes would need isolated
   networks, packet sidecars, CPU partitions, result roots and checkpoint
   ownership, with global cooldown and deterministic verification. It is a
   separate engineering change, not a Docker launch flag.

The current execution sequence is: freeze the prospective short-horizon
contract; qualify it on a fresh source-bound cohort; acquire the frozen
population; complete the registered fitting and compatibility matrix; verify
readiness and historical pre-snapshot; then run and seal block pairs
continuously while measuring accepted cells per day. Keep every relaxation
visible in the methods and limitations, preserving complete multi-origin
graphs, disjoint training/certification/formal roles, and all failed evidence.
Do not call a redesigned gate complete until its actual receipt and closed
inventory verify.
