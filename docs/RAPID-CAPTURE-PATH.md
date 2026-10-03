# Rapid capture path: from candidates to 16,000 verified traces

**Planning and implementation status, 3 October 2026 (Australia/Sydney).** This is the run order
for the prospective [50-site study](RAPID-CLASS-STUDY.md). Its formal target is
**50 websites × five traffic settings × 64 visits = 16,000 accepted traces**.
The five settings are undefended, FRONT, Tamaraw, BuFLO and CS-BuFLO. The
ten-site, one-visit-per-setting shakedown produces **50 diagnostic traces with
zero formal credit**. The earlier 100-site and 20-site contracts are separate
historical studies; their long build, browser-vector, fitting and nine-mode
sequence does not gate this prospective five-setting study.

The [targeted capture repairs](RAPID-CAPTURE-REPAIRS.md) explain the variable
homepage credit fix, endpoint-specific final UDP drain evidence and explicit
prospective BuFLO incoming tolerance. They require fresh affected captures;
the previous failed attempts keep their original results.

**Current execution snapshot, 07:08 UTC on 3 October:** the repaired
`cacc4aa`/Native `01ce0a7` runtime is published and independently verified.
Its cached client build took **118 seconds**; the two image builds took
about **one minute each**. A fresh full Poki baseline passed ordinary deep
verification and independent raw-packet review: **260 resources, four origins,
1,503 matched packets**. The host command failed after capture because a
three-second router-removal timeout expired. The original failure remains
saved; standard lifecycle recovery subsequently proved complete removal.
Fresh 120-request qualification passed in **75 seconds**, and the three
defended offline checks passed in **9 seconds**. CS-BuFLO is now being tried;
its result is pending. A prospective input-policy admission revision and
normal router-cleanup repair are being tested in separate checkouts.
The old-source site search stopped normally at checkpoint 84: **31 terminal
decisions and one admitted site**. It is not a current repaired-source cohort.
**0/50 study shakedown traces and 0/16,000 formal traces** are accepted.
The table below retains the earlier 06:25 UTC snapshot for comparison; its
running and pending-build statements describe that earlier time. See the
[exact successor records](EVIDENCE-INDEX.md#repaired-runtime-and-fresh-poki-diagnostics).

The prospective admission contract is [selection revision 7](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v7.json)
under the unchanged v5 profile. It preserves full multi-origin graphs, exact
selected-page HTTP/3 proof and three complete replay witnesses. Complete
4xx/5xx responses may remain only on eligible non-primary terminal leaves;
only primary Document 0 may vary its complete body size/hash. Other resource
identities and qualified padding responses remain exact. Revision 7 permits
an auxiliary padding resource on any of the workload's exact approved origins,
including CDNs, after separate sustained response qualification. Resource 0
cannot supply padding; no resource or origin is removed.

## What happens, in order

| Step | Action | Evidence needed to advance | Current state |
|---:|---|---|---|
| 1 | Freeze the candidate sources and runtime. | Exact source hashes, ordered [v5 rapid profile receipt](../config/curated-sources/crux73-tranco600-rapid-v5.profile.json), revision-7 receipt, image digests, fixed defense parameters and launcher-source hashes. | Published `ffe14ab`/native `e2dcd8a` has matching runtime 004. Its new cached client build took 109 seconds; both images passed installed-byte checks and independent review. Context 014 has 73 fresh, independently verified curated root screens. Installed-runtime checks grant no lane or trace credit. |
| 2 | Find usable pages. | Record verified decisions in frozen order. Keep the controlled root observation, separate controlled H3 pass on the exact selected page, automatic URL/domain screen, complete graph, registered response stability and live cross-origin resource. | Context 014 first admitted Poki after **17 minutes 49 seconds**. Its full 260-resource, four-origin graph and three complete HTTP/3 replays independently verify. The same-source search resumed in batch 002 and is confirmed running. Checkpoint 82 at `2026-10-03T06:24:47.550559Z` records **30 sealed decisions and one admission**. **1/50 final sites admitted.** |
| 3 | Prepare and qualify the first ten sites. | Ten verified prepared workloads, with five-site response-qualification sets matching the exact workload and source bytes. | First-site canary 005 passed **120 fresh padding qualification requests** in **74.211 seconds** and all five ordinary offline preflights in **12.665 seconds**. Both independently verify. At **05:20 UTC**, undefended and FRONT have passed ordinary deep verification and independent raw-evidence review: **2/5 additional diagnostic conditions passed**. Tamaraw, BuFLO and CS-BuFLO each failed three preserved attempts; targeted repairs are underway. These traces do not supply the ten-site study shakedown. |
| 4 | Run the ten-site shakedown across all five settings. | 50 complete, individually deep-verified diagnostic traces, including both BuFLO modes, with failures preserved and repaired before formal capture. | Historical individual clean-runtime diagnostic passes exist on one workload: CS-BuFLO **1/1**, BuFLO retry 004 **1/1**, FRONT and Tamaraw accepted, and an undefended two-second-settle successor **1/1**. The earlier undefended attempt lacked 45 tail packets and remains failed. These separate passes do not supply the ten-site shakedown. **0/50 study shakedown traces accepted.** |
| 5 | Admit 50 sites and freeze formal inputs. | A verified 50-site cohort receipt, exact workloads and qualification sets, fixed parameters, complete lane plan and launch manifest. | 50-site live yield is unproven; the 600-domain catalogue supplies further candidates under the same checks. |
| 6 | Capture the formal grid. | Each defense lane is a separately named, frozen campaign. Deep verification must show its exact sites, setting, visit slots, source/image binding and complete result seal. | The planner and capture adapter represent 800 lanes and preserve failed attempts. Historical runtime and parent-interruption checks have their original source bindings; they do not establish a current study lane. No 50-site cohort or formal bound lane has run. **0/16,000 formal traces accepted.** |
| 7 | Close the evidence campaign. | One manifest enumerating all 16,000 unique accepted slots and result-seal hashes, verification output for each lane, recorded failures and restarts, and a portable source commit. | Pending capture. |

The planned grid divides 50 sites into ten groups of five. Each of 16 time
blocks has four visits per site and five setting-specific lanes per group:
**16 blocks × 10 groups × five settings = 800 lane campaigns**, each with 20
traces. This is an evidence layout, not a claim that 800 campaigns have run.
The settings should be interleaved across time so that network changes do not
systematically favor one setting.

**Repair milestone at 06:25 UTC:** Native `01ce0a7` and the Lab endpoint/timing
changes are integrated in authoring source. The focused Lab suite passed 230
cases; two tests requiring host TShark were excluded. Independent replay
regressions passed 106 cases, and one actual offline Docker/TShark rehearsal
reopened the endpoint-tail fixture after correcting host-user permissions.
These checks do not replace fresh capture proof. The active admission still
uses its original `ffe14ab`/`e2dcd8a` runtime. The next operation is the new
cached client build and targeted first-site capture proof.

## Rough time budget

| Work | Planning estimate | What can change it |
|---|---|---|
| Root HTTP/3 screen | The 73 fresh curated screens for 014 took **93.244 seconds**. All 73 must verify together; fallback may wait until needed. An older 40-candidate fallback batch took about **4 minutes 10 seconds**. | Reuse requires unchanged survey components, native client, actual original runtime proof and applicable freshness barriers. Root decisions grant no site credit. |
| Browser discovery, replay and 50-site admission | **Unknown.** Context 014 reached its first admitted site after **17 minutes 49 seconds**, with ten sealed candidate decisions. | One admission does not establish the yield or duration for 50 sites. Live page behavior and candidate yield dominate. The default one-page operator budget limits exploration, not the successful-admission requirements. A root success is not a prepared site. |
| First-site padding qualification and capture check | Actual qualification took **74.211 seconds**; corrected five-setting offline preflight took **12.665 seconds**. Undefended and FRONT host operations took **153.645 and 147.442 seconds**, including setup and cleanup; their actual recording intervals were **3.434 and 7.940 seconds**. | Both independently deep-verify. The other three settings failed and need targeted fresh proof after repair. One site's intervals do not establish full-grid throughput. These additional diagnostics grant no formal or study-shakedown credit. |
| First ten-site, five-setting shakedown | About **53–109 minutes of recording time** for 50 visits at older 63–131 second per-visit rates, plus site preparation, response qualification and verification. | A complete five-setting shakedown on admitted study sites has not run. Short historical-workload tests diagnose individual capture failures first. |
| Full formal grid | About **12–25 days of serial recording time** for 16,000 visits at those older rates, before retries and verification. | Parallel speedup is unmeasured and requires a separate fidelity/throughput trial. |

The first stop point, **one accepted zero-credit capture through the rapid
launcher**, has passed on a historical workload. The original five-setting
test sealed **3/5** on that workload. A later clean CS-BuFLO successor passed
independent host deep verification **1/1**, with packet capture and all three
origins intact. BuFLO successor 003 stopped after about 1.42 seconds at a Rust
selection deadline and deep-verifies as incomplete **0/1**. Its unchanged-source
retry 004 then passed independent verification **1/1**, with 939 cells and no
ETF timing errors. These separate
results do not replace the ten-site shakedown. The earlier BuFLO-only retry
accepted 0/1 after three attempts. A failing one-visit test
is diagnosed before another 25- or 50-visit job. Changes to the host launch
plan are recorded separately from
changes to the source-bound container images.

## Current checks and remaining blockers

Runtime 004 independently reopens all 2,332 source inventory entries and 12
completed operations, including the actual new cached native build, both
installed image checks and exported source/client bytes. Context 014
initialized, completed all 73 fresh curated root screens and published its
independently verified registry with zero fallback screens. The initial
40-only registry check failed before publication because curated verification
requires all 73; that failed operation and both successful screen chunks are
retained. No new software build was needed to complete the screens.

The first actual coordinator plan-only check passed, then the bounded live
batch started at `2026-10-03T03:56:13.693218Z`. It closed normally at the
first admission at `2026-10-03T04:14:02.160831Z`. Checkpoint 30 has ten sealed
decisions and one admitted site, Poki, with all 260 resources and four origins
retained. The first site's actual sustained 120-request qualification passed
and independently reopened. At the **04:34 UTC** snapshot, no first-site
capture has run; study counters are **1/50 admitted sites, 0/50 study shakedown
traces and 0/16,000 formal traces**.

The first offline preflight failed at its fixture-directory binding:
it expected `/runtime-src/config/defense-params` while the frozen campaigns
and copied fixtures were under `/lab`. The closed failed operation is
preserved. A separate create-only execution layout now places the campaigns
and exact frozen source files under the same `/lab` root. Its corrected
invocation passed all five ordinary installed preflight checks at
`2026-10-03T04:34:08.481047Z`, with independent review underway. It keeps the
original frozen recipe and plan, native client, images, admitted graph and
successful response qualification unchanged, and has its own operation
records. No rebuild or repeat qualification was needed. All five live
diagnostic conditions have now been attempted. Undefended and FRONT
independently deep-verify; the other three conditions failed. The shared
short-primary receive-credit defect, Tamaraw packet-tail limit and BuFLO
release-window failure are being repaired in isolated checkouts. The
same-source site search is running in batch 002. Exact identities and failure records are in the
[first-admission ledger](EVIDENCE-INDEX.md#context-014-first-admission-and-canary-005).

The [optional parallel pilot](PARALLEL-CAPTURE-PILOT.md) has separately
published and reviewed source. Its tests cover two derived peer partitions,
one worker's failure while its peer continues, retirement and result
reopening. An actual matching collection image and concurrent capture trial
remain required. The current serial preparation does not wait for that pilot.

### Preserved context 013 checks

The preserved runtime 003 verifies published source 80c85f5 and the unchanged
native client. Its observed origin-budget repair passed three new focused
cases, nine guard checks, 21 receipt checks and independent review. The new
images built in **57.861 and 63.749 seconds** and passed installed-byte checks
in **16.929 and 13.510 seconds**, without another native compilation. Fresh
context 013 initialized successfully and independently retained the same 113
original root observations with their old runtime identity. Its first bounded
host-coordinator batch closed at the requested boundary. Exact runtime, checkpoint and policy
locations are recorded in the
[evidence index](EVIDENCE-INDEX.md#current-preflight-runtime-and-context-013).

At the final `2026-10-03T03:00:08.631791Z` checkpoint, context 013 has
23 sealed decisions and Bing is next. It has not established a usable
site or completed padding qualification. Study counters remain **0/50
admitted sites, 0/50 shakedown traces and 0/16,000 formal traces**. Canary 004
has only had its runtime/context guard checked, with no staging or capture.

Poki's preserved context-013 attempt completed all 260 resources in each of three native
replays, with stable non-primary responses and HTTP/3 on all four origins.
Revision 6 rejected it because its 231 large stable auxiliary responses are
on CDNs, and only its primary document is on the main origin. The
[domain explanation](README-CURATED-DOMAINS.md#poki-complete-downloads-rejected-by-the-padding-origin-rule)
records that limitation. The explicit revision-7 policy changes preparation,
admission, response qualification and the native schema-4 identity runtime
together. Its 73 focused Python checks and 13 actual native library tests
passed, including legacy cases. Matching runtime checks are now complete;
fresh successful preparation and sustained qualification subsequently passed
in context 014 and canary 005. Live captures remain pending at the snapshot
above. The old failed attempt stays failed and gains no credit.

**Preserved 012 failure:** its private controller stopped with exit 1 at
Futura's selected page ordinal 2, preparation attempt 10. Browser discovery
returned, but origin convergence exceeded its 32-origin bound outside the
observed backend call. The generic error has no observed origin-list proof
and remains unchanged and unsealed. The new repair prospectively retains
such an actual bounded failure through the source-bound unsuccessful-attempt
route; it does not admit the old attempt. Earlier Futura convergence and Poki
response-drift diagnostics also remain failed, with no admission or capture
credit. Poki's failure proof retains three complete 278-request replays.
Successful admission still requires the complete graph and registered
response and padding requirements.

### Portable host coordinator

The [host coordinator](../tools/rapid_acquisition_control.py) provides a
portable operator loop, originally committed separately as `e84b30f`. Its
first recorded plan-only check on fresh context 013 passed, and its first
actual batch closed normally at the requested boundary after 57 actions.
The old 012 controller and generic error remain preserved. Its `--help` lists explicit context, clean verifier
checkout, Docker bootstrap, root registry and create-only operator-log paths,
each with its selected hash or source identity. The operator code and the
scientific verifier have separately selected commits: `--operator-commit` binds the host
coordinator's exact bytes; `--source-commit` binds the unchanged clean checkout
that owns admission and the matched image. Changing the host's page-routing
policy does not install new scientific code in that image or require an image
rebuild. The actual 013 command currently selects 80c85f5 for both identities
and retains the exact coordinator hash and one-page policy.

The actual Albumaty sequence completed one selected-page preparation,
retained its unsuccessful-attempt proof, sealed the zero-credit decision and
moved on. Its four alternative pages remain unassessed. This verifies the
operator's one-page bound on that live sequence; it does not establish a
successful full-site preparation.

The default `--page-budget 1` means **one distinct selected page per candidate
over that candidate's entire unchanged context history**. Restarting the host
loop or choosing a new operator-log directory does not reset that count.
An already verified page sequence completes its remaining probe, screen,
preparation and evidence decision before moving on; an interrupted intent
still blocks rather than being retried automatically. Already observed history
is retained even if it exceeds the new budget. Unattempted alternative ordinals remain
**unassessed**, not failed or scientifically ineligible. Successful admission
still requires the frozen context's full-graph proof. Revision 7 also binds
the exact approved-origin padding policy and its selector source.

Before acting, the coordinator reopens actual history and supporting receipts
through the frozen admission API. A scientific policy failure requires its
exact typed error and independently verified raw proof. An actual unsuccessful
operation or collector limitation remains a distinct zero-credit disposition;
it is not a scientific verdict about page content or the whole domain.
Generic operational errors, pending work, failed controls and invalid evidence
stop the loop for diagnosis.

The first run records a durable context/page-budget binding, a hash-bound
policy and initial status. Each action retains its plan, exact argv, start/end
records and stdout/stderr hashes in a separate create-only operator directory.
A context lock excludes another coordinator for that same context; the older
controller must be fully closed before handoff. `--max-actions` and
`--stop-at-admissions` bound each batch. Creating `--stop-file` requests a
stop at the next action boundary, after the current action finishes.
`--plan-only` publishes the policy and first verified plan without executing
it. The recorded 013 plan-only operation passed; the live batch's recorded
completion is a normal boundary stop with zero admissions. Neither grants capture
authority.

### Historical checkpoints and response-policy rollout

The following snapshots describe their original sources and dates. Their
passing prefixes and failures grant no authority to current context 013.

Context 007's independently reopened checkpoint had
**11 screening decisions and zero admitted sites** at
`2026-10-02T20:53:46.146589Z`. Its second bounded batch subsequently completed
normally at the 40-action limit on the unchanged old image/client. No further
old-context batch has been launched. Context 006 and all its attempts remain
preserved.

The [new response policy](APPLICATION-RESPONSE-POLICY.md) addresses a concrete
preparation failure: a full HTTP/3 error response from an auxiliary resource
was treated as an incomplete workload. It keeps the graph and real response,
and applies only to complete non-primary terminal leaves. The native change
passed **16 focused tests and strict library Clippy**. Final Python integration
passed **142 tests**, and all **24 new admission cases** pass. The new rule is
frozen in [selection revision 5](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v5.json)
under the unchanged v5 profile. Installed-runtime checks and actual
complete-site/five-setting captures were pending at that snapshot. Later
revision-6 runtime checks have their separate current scope above. The
[evidence index](EVIDENCE-INDEX.md#application-response-policy-repair) records
the current proof. The target stays **50 × 5 × 64 = 16,000**; accepted study
counters remain zero.

The fresh three-setting successor on the same clean runtime independently
deep-verifies as **valid but incomplete, 2/3**, with 31 authoritative files.
FRONT and Tamaraw are accepted. The undefended attempt completed application
work, but its independent packet capture lacked 45 of the runner's 462
packets: the pcap contained 417. The failed campaign used
`settle_seconds: 0`. A recorder that closes before buffered final packets are
saved was the leading hypothesis. A fresh create-only, one-visit undefended
successor with `settle_seconds: 2` then independently deep-verified as
**valid, complete 1/1**, with nine authoritative files. The recorder window
change succeeded on this workload; one passing retry does not prove it was
the sole cause of the earlier loss. The missing-packet gate remains intact.
The successor run is `20261002T143630.770731Z`, with result-seal SHA-256
`4e1478185931987cb38da663fa47790eeb433c3a4065f3d46e3bc1d23146daa3`.
The prospective v5 lane plan now uses two seconds of settle time; historical
v4 rendering retains its original zero. This short test required no rebuild
or repeat of the passing CS-BuFLO and BuFLO diagnostics. All five settings
now have individual clean-runtime passes on the same historical workload;
admitted study sites and the ten-site shakedown are still required.

The fresh curated screen is bound to the matching clean prepare image and
the unchanged frozen v5 profile. All 73 decisions have been reopened between
passing controls: **31 known-valid, 27 ambiguous, six peer TLS handshake
failures, two timeouts and seven automatic safety skips**. Those are homepage
observations, not 31 admitted sites. The original acquisition context 001
has one terminal candidate, zero admitted sites and a preserved retryable
error at its next candidate, `www.weerplaza.nl`. Context 002 independently
proved a fresh WebSocket failure and sealed a second terminal screening
decision. Its next candidate, `www.albumaty.com`, passed catalogue navigation
and a separate HTTP/3 test of the exact homepage between passing controls.
Those unchanged supporting proofs were independently reopened for fresh
revision-2 context 004. Its full-resource attempt and explicitly sealed
deferral are described below; Albumaty is not an admitted site.

That navigation triggered `NonReplayableEgressPolicyError` when the browser
attempted a WebSocket to `wss://onweeralarm.nl`. The recorded action starts at
the catalogue HTTPS homepage and may follow optional in-boundary links:
`catalogue-root-and-optional-link-navigation`. The guard does not identify
the failing document, so the evidence records **failure page attribution
unavailable**. It does not establish that the homepage itself, every page,
or the entire domain is scientifically ineligible.

The [selection amendment](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v1.json)
was published at **2026-10-02T14:30:27.785695Z** (3 October in Sydney), with
raw/canonical SHA-256
`ffc91c4a4fafe39ae9ec3875c982d8a5537fcaae6a253ee58e33c7f492bc8486`.
It adds a distinct **zero-credit browser navigation screen deferral** for a
fresh typed guard failure independently bound to the exact candidate,
image, clean source, frozen modules and raw guard evidence. The new failure
must start after publication. The old context 001 failure remains an error;
it is never relabelled or promoted. Independently verified supporting root
observations may be reopened under their unchanged parent-profile bindings.
Candidate order, complete admitted resource graphs, the ten-site shakedown,
and **50 × five × 64 = 16,000** remain unchanged.

### Revision 2: remove the manual review wait and keep screening moving

The [second selection amendment](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v2.json)
was published at **2026-10-02T15:19:12.576895Z** (3 October in Sydney), after
focused source and integrated driver checks passed. Its raw/canonical
SHA-256 is
`32cd9eb8440c86f204919bde64a5f27cdcf1efcf28e7becf127d8e3798266457`.
It binds the unchanged v5 study and the original amendment explicitly.

Each prospective selected page receives an independently verified
**automatic public URL/domain screen**, under declared rules with SHA-256
`cf28b92f80ee5b9da982fa7b326fdc24ca5cb0a713bbea9c8c5a5b1115a9fb3b`.
The rules check the frozen domain restrictions, the canonical query-free
HTTPS page URL, the chosen navigation ordinal and the separate controlled
HTTP/3 proof for that exact page. A named human approval is no longer a
prerequisite under revision 2. This narrow URL/domain check does not claim to
classify page content. Its receipt supplies no admission or trace credit by
itself.

Fresh, independently proved policy failures can be recorded as
**zero-credit page screening deferrals**. During navigation this covers only
the exact passive-render limit error, with the actual failing page recorded
as unavailable. During complete-graph preparation it covers that same typed
render error, verified complete-graph HTTP/3 unavailability, or verified
response-identity instability across three complete successful replay runs.
A preparation deferral must retain the exact navigation, selected-page HTTP/3
and automatic-screen proofs. Generic runtime errors, browser-control errors,
timeouts, missing resource ledgers and cleanup failures remain operational
errors to diagnose. No failed preparation establishes that every page on the
domain is unusable, and no graph is trimmed to pass.

Supporting root, navigation and exact-page HTTP/3 observations can be
independently reopened from the unchanged parent-profile publication barrier
when their image, source and module bindings still match. The new automatic
screen and typed page-failure attempt must start at or after revision 2's
publication. Original failed attempts retain their original policy and
authority. Fresh context 004 binds revision 2; contexts 001, 002 and 003
remain preserved. Candidate order, complete admitted graphs, live
cross-origin proof, **50 sites**, the **50-trace shakedown**, and the
**16,000-trace formal target** are unchanged.

### Albumaty: the homepage passed, but its full resource graph did not

Fresh context 004 discovered **31 resources** for
`https://www.albumaty.com/`. Its actual complete-resource HEAD probe exited
with code 1 after endpoint 2 closed with `Transport(Peer(296))`. The
independently reopened schema-2 proof identifies
`https://use.fontawesome.com` and resource IDs **5, 23 and 25**. The saved
probe input, client run, events, packets, schedule and child execution establish
that exact failure. The probe stopped before GET fallback; its proof has no
resolved probe manifest and invents no `known_valid` decisions.

The preparation driver retained this fresh typed failure and exited 0 because
it successfully recorded evidence, **not because preparation passed**. An
explicit seal then recorded `page-policy-screen-deferred`, with terminal
SHA-256
`4c5c880f46c7d5f51b5f479c93486f81dbb8fb6d77125902ae8732c606142034`.
Independent reopening confirmed **three terminal decisions, zero admitted
sites and zero formal traces** at this checkpoint. Both earlier context 003
generic failures stay operational failures under their original source;
neither was relabelled. The 31-resource graph was kept whole. This decision
allows screening to continue without claiming every page on the domain is
scientifically ineligible. The next controlled-root deferral was subsequently
explicitly sealed and independently reopened, bringing context 004 to
**four terminal decisions, zero admitted sites and zero formal traces**.
Alibaba was the next candidate in that context's frozen order.

### Revision 3: record a collector limitation without blocking every later site

Alibaba's actual context-004 navigation, exact-page HTTP/3 test and automatic
URL/domain screen passed. Complete preparation then reached the 30-second
passive-render limit. During cleanup, the CDP collector raised
`CdpTargetIntegrityError` at its root frame-detachment handler. The retained
traceback records this sequence; it does not reconstruct the missing CDP
event parameters. This is a collector limitation, not a scientific verdict
that Alibaba's page or domain is unusable. The context-004 error remains
unsealed under its original revision-2 rules.

The [third selection amendment](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v3.json)
was published once at **2026-10-02T17:00:14.866744Z** (3 October in Sydney),
after focused collector, admission, cohort and capture-compatibility checks.
Its raw/canonical SHA-256 is
`e175fa86345946999af391ec3a98115abd2b84c4cfffdce075dab10b09e3ad3e`;
its explicit parent is the unchanged revision-2 receipt.

A **fresh** navigation or complete-preparation attempt can receive
`operational-collector-screen-deferred` only after one actual exact
`CdpTargetIntegrityError` is independently reopened from the frozen event
handler source, actual traceback, client/runtime identities and closed
attempt inventory. It is retryable and earns **zero site and trace credit**.
Preparation still requires the exact navigation, passing selected-page H3
and fresh automatic-screen receipts. Generic errors, missing runtime,
dependencies, permissions and Docker failures remain blocking. Old errors
are never relabelled under the new rule.

Revision 3 also makes browser progression explicit for a controlled
`response-known-invalid` homepage result: it is a completed but ambiguous
response, whose exact selected page still needs its own H3 proof. DNS misses,
timeouts and peer failures retain their separate bounded-root dispositions.
The same narrow root rule applies to the inherited browser and page-policy
failure branches. It does not turn ambiguity into `known-valid`, prune
resources or weaken complete-graph admission. The final target remains
**50 × five × 64 = 16,000**, with the separate **50-trace zero-credit shakedown**.

A fresh clean fallback survey independently reopened **40 decisions**:
one known-valid homepage (`bandcamp.com`), 15 ambiguous results, 19 timeouts,
four peer TLS failures and one automatic safety skip. Of the 15 ambiguous
results, **seven are completed-response leads and eight are DNS misses**.
This supplies homepage observations only; it demonstrates neither 50-site
yield nor a prepared site. Runtime 002, fallback observations and the old
Alibaba error are recorded through the [evidence index](EVIDENCE-INDEX.md).

### Preserved revision-3 context 005

Context 005 used the published revision-3 receipt and frozen
implementation groups. Its first two zero-credit terminal decisions were
independently sealed: the controlled root-screen decision and a fresh
Weerplaza navigation failure recorded in about **26 seconds**. No earlier
failed attempt was promoted into these new decisions.

Albumaty's fresh full preparation then completed in about **73 seconds**,
with driver exit 0 and a retained typed page-policy failure, SHA-256
`821e2a9974e960f559205d0ffa859517395ca082f028dd4fa8cd8eac0527c747`.
Exit 0 means that failure evidence was recorded; it is not a successful
prepared workload or admitted site. Its explicit seal then produced terminal
`2690b4ffeec614efb76d748a1d1a959444ff65e265e8bfbabb3e82ed76faf006`.
The next controlled-root deferral was also sealed. Independent reopening
confirms **four terminal decisions**. Alibaba's unchanged positive navigation
and exact-page H3 proofs were independently reopened, and its fresh
context-005 automatic screen passed. Its full preparation then reproduced the
collector failure in **65 seconds**. All 18 retained files, 13 source/client
bindings, traceback and exact-page support independently reopened; the new
collector terminal was explicitly sealed. Context 005 now has **five terminal
decisions**. Pinterest's subsequent navigation failed, as described below.
Counts remain **0/50 admitted sites,
0/50 study shakedown traces and 0/16,000 formal traces**. The latest closure
records are collected through the [evidence index](EVIDENCE-INDEX.md).

Pinterest's actual navigation exited 2 after **13.34 seconds** with
`TerminalProbePolicyError: page-safety-rejected:captcha-or-challenge-widget`.
Only its intent and operational error survived; no page content or selector
matches were retained. The detector also flags mere CAPTCHA script presence,
so this evidence does **not** prove a visible challenge. It supplies no site
decision or admission. Context 005 is stopped, with all attempted bytes kept.

### Revision 4: retain the actual unsuccessful attempt and keep searching

The [fourth selection amendment](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v4.json)
was published at **2026-10-02T18:13:34.038260Z** (3 October in Sydney).
Its raw/canonical SHA-256 is
`0808c27b60b229de938bd8a3ae26aca615455c3c4978130b4792041787420a28`.
One actual unsuccessful navigation, selected-page HTTP/3 probe or complete
preparation operation can now receive a **zero-credit screening disposition**.
The checker reopens the actual exception, retained files and source bindings.
This records an unsuccessful operation, not a proved visible challenge,
particular page-content defect or whole-domain ineligibility. A negative
selected-page probe must still have passing controls. Runtime, dependencies,
permissions, source/configuration mismatches and post-operation validation
errors still block; they cannot be counted as candidate decisions.

Fresh context **006** initialized successfully: exit 0 and empty stderr.
Its provenance SHA-256 is
`a2d728946642e8706b701f08d4ae8a08d550a3e3bfbbca42b7014b1cce1516af`;
its launch snapshot SHA-256 is
`a9629ef6c000132a431de2260504308b0042263d4f26dd145db0a1e1e05dd986`.
Eight implementation groups are frozen, including **18 source/client
bindings** for the new attempt observer. The first bounded **20-action** batch
completed normally at its action limit with **eight screening decisions and
zero admitted sites**. The second 20-action batch also completed normally,
bringing the count to **16 decisions and zero admissions**. Fresh
Weerplaza, Alibaba and Pinterest failure proofs independently reopened all
18 source/client artifacts and their complete retained inventories. Futura
passed navigation, exact-page HTTP/3 and the automatic screen; its preparation
then failed to settle within 30 seconds. That failure proof also independently
reopened. These recorded failures grant no site or capture credit.

A private operational helper revision passed **11 routing checks** and started
a fresh **40-action** batch on the unchanged context. Its first action brought
the count to **17 decisions and zero admitted sites**, observed at
`2026-10-02T18:46Z`. It independently reopens failed-operation proofs, then tries
the smallest unattempted page ordinal from the existing navigation receipt.
A prepared page with no cross-origin resource can also lead to the next page.
Every page still needs its own controlled HTTP/3 pass, matching automatic screen
and complete preparation. Old screen records cannot be reused for a different
page. Each failed page is tried once; its retained evidence remains unchanged.
Already sealed candidates are not reopened.
The source modules, profile, amendment and images are unchanged.

Old matching positive root, navigation and exact-page H3 observations may be
independently reopened only under unchanged source groups. New failure
attempts must start after revision 4's publication; context 005's Pinterest
error stays unsealed under its original rules. Failed preparation now saves
raw logs, manifests, schedules and available packet data before temporary
cleanup. No missing file or page observation is invented. The image and
client are unchanged, and admitted sites still need complete cross-origin
graphs and stable replay: **50 × five × 64 = 16,000** remains fixed.

A separate short Bing discovery diagnostic passed on the exact frozen
preparation software at `2026-10-02T19:19:22.863261Z`. All 78 observed request
occurrences reached terminal events, with no active requests or pending target
setup at the render cutoff. This shows that the earlier 30-second failure is
not inevitable in that path. It does not explain that earlier timeout or prove
full-page preparation. The prior failure remains sealed; the diagnostic grants
no site or trace credit. Its scope, inventory and hashes are recorded in the
[evidence index](EVIDENCE-INDEX.md#short-bing-collector-diagnostic-3-october-2026).

The actual runtime, screen logs, failed attempts and sealed diagnostic
results are host-local evidence described through the
[evidence index](EVIDENCE-INDEX.md). None grants formal capture credit:
**0/50 sites admitted, 0/50 study shakedown traces and 0/16,000 formal traces**.

## The short failure path before formal capture

Use one-site capture tests and one-candidate navigation or preparation
attempts to expose a failure before expanding to the ten-site shakedown.
Repair or prospectively amend the exact failing path, retain its evidence,
and independently verify its fresh successor. Qualification reloading and
planning use the bound collection runtime described below.

For the **first prepared study site**, inspect its saved manifest locally for
a usable, prepared main-origin response with at least **1,200 bytes** and
canonical headers. Do this before paying for live response qualification.
The existing one-workload qualifier and one diagnostic visit under each of
the five settings then check the full capture path early. They give zero
study credit and do not replace the ten admitted sites, five-site qualification
sets or 50-trace shakedown.

Run this one-workload response qualification through the **installed collection
runtime and its complete matching clean source bridge**. The new acquisition
overlay has different preparation/error-observer code and cannot impersonate
that installed source. An internally consistent prepared manifest from the
prepare image is compatible with the collection image; copy its bytes unchanged.
The qualified sidecar can later join a five-workload named set without repeating
qualification when its workload, client, image and implementation bindings remain
unchanged. Neither fitting nor a rebuild is needed for this early check.

### Page changes during a multi-day run

Revision 6 permits only primary Document 0's registered complete body variation.
**Every other resource's status, byte count and body SHA-256 must match its
prepared identity under all five settings**, including undefended traffic.
An auxiliary body change that keeps the same length still fails the
[application-response check](../src/qcsd_lab/orchestrator.py#L5286).
Preparation's three nearby repeats test short-term stability; they do not
establish stability over several days.

Existing lane generations retry an unchanged frozen workload. They cannot
refresh one class's manifest and qualifier within the existing cohort and
formal manifest: [planning requires the admitted bytes](../src/qcsd_lab/rapid_site_admission.py#L2047),
and [formal closure derives the workload from its original terminal](../src/qcsd_lab/rapid_capture_plan.py#L731).
The separate [prospective class-epoch procedure](RAPID-CLASS-EPOCHS.md) now has
an authoring implementation. It must be declared before its first affected
capture and pass a bounded real capture/recovery trial before long-run use;
local fixture tests are not live study evidence. It retains other committed
blocks, independently reopens each fresh complete graph and qualifier, and
requires all five conditions in an affected 100-slot block to share the same
predeclared epoch vector. Final closure still requires **50 × five × 64 =
16,000**, with no relabelling of old failures. Historical plans keep their
original strict byte contracts. Epochs delegate response comparisons to the
original cohort's registered policy; they do not themselves permit variable
primary-document content or source/image changes.

The earliest cheap check is first-site qualification followed by an immediate
baseline capture, then a repeat of the **same frozen workload** later while
site discovery continues. This can expose drift without a blocking long test
cycle. If it fails, inspect `differing_resource_ids` in the saved
`StrictPreparedResponseIdentityFailure` diagnostic. These checks give zero
study credit and do not prove stability for the entire acquisition period.

### Historical failures kept for review

The controlled homepage screen against the historical frozen v4 profile is
complete for the 73 supplied entries. A first Tranco fallback batch then
attempted global candidate positions 74–83 between passing controls. It had
six timeouts and four ambiguous results, three of them local DNS resolver
errors. The frozen
v4 verifier cannot classify that resolver error as a terminal screen outcome,
so **none of those ten raw observations is promoted to a verified v4
first-screen decision**. They remain create-only diagnostic data with no
retroactive v5 credit. A fresh post-freeze v5 run of the same ten positions
passed independent log verification: six timeouts, three exact
DNS-name-not-found operational deferrals and one known-invalid response,
between passing controls. These are ten verified **v5 first-screen
decisions**, with zero clear homepage roots and zero admitted sites. V5
classifies the exact `gaierror -2` name-not-found result as an operational
screen deferral. The original unamended v5 rules kept
the first controlled homepage result, then required human site-safety review
and a distinct controlled HTTP/3 proof for the exact page later captured.
Revision 2 now supplies the automatic screen described above.
An ambiguous homepage result can continue to that page check. The selected
page must be a canonical query-free HTML URL at the frozen domain or a
subdomain. It still needs a complete resource graph, stable replay and a live
cross-origin resource; the profile alone admits no site.
Discovery, preparation, replay and the cross-origin check determine site
admission. The supplied resource URLs are hints only. The dated
[site-source README](README-CURATED-DOMAINS.md) explains why only some supplied
sites are carried forward.

The first five-mode capture diagnostic used existing prepared public workloads
to test the recorder, ETF scheduling and verification quickly. It remains
**zero credit** and cannot stand in for the ten-site shakedown or final cohort.
Its 25 failed visits exposed client DNS resolution in the isolated capture
network. A one-visit retest supplied public IP pins, then failed at QUIC idle
timeout with outgoing packets but no incoming payload. Preserve both
[sealed failed results](EVIDENCE-INDEX.md). A paired router probe then found
that Docker's `--internal` client bridge blocked forwarding, while a dedicated
ordinary bridge returned TCP and UDP traffic through the same router. A new
one-visit capture proved the downloads work, then exposed two acceptance
issues: an extra `tini` task on a protected CPU and 39 runner packets absent
from the direct pcap. A second packet observer found that the packet mismatch
did not recur; a host-only affinity fix then produced a complete, independently
verified **1/1** rapid-launcher diagnostic. The next one-site five-setting
test sealed and independently deep-verified as **incomplete, 3/5**.
Undefended, FRONT and Tamaraw passed on the same historical three-origin
workload. BuFLO's first exact-timed `SCM_TXTIME` send returned `ENOBUFS`;
CS-BuFLO completed application work but the first endpoint later closed with
`IdleTimeout` while egress work remained. Both failed traces stay preserved.
A bounded full-ancillary ETF probe then accepted **13/13** timed sends with
zero ETF drops, ruling out a blanket inability of this kernel/socket setup
to transmit timed packets. A first BuFLO-only launcher retry stopped before
capture on a wrong parameter path. The corrected retry preserved three
attempts and independently deep-verified as **valid but incomplete, 0/1**.
Its first attempt scheduled 940/940 outgoing cells and reconciled all 1,527
kernel transmit items, then failed the incoming-credit delay gate at a recorded
maximum of 6,386 µs against `<5,000 µs`. Attempts two and three hit a timed
enqueue cutoff and a kernel missed-TXTIME outcome. The delay metric starts at
the planned prearm action, about 5 ms before nominal release. The proposed
source gate instead checks a strict 5 ms window from the nominal release,
using the saved defense-start clock and failing closed at the boundary.
Four direct focused tests and 51 related host tests passed, and the old sealed
retry still deep-verifies as incomplete, 0/1; it cannot be promoted by the
new checker. A CS-BuFLO source change addresses a suspected final
parser-credit deadlock. Its three focused offline tests and full 406-test
crate suite passed. A direct debug run stopped on `AdapterDeadlineLateHandoff`
before the parser-tail condition was reached. An incremental release client
then completed a direct run on the historical workload, with 876 incoming
cells and exactly 525,600 bytes of scheduled receive credit requested,
advertised and consumed. This direct run has no independent host packet
capture or sealed lane. A proposed CS-BuFLO host response qualification did
not run: its patched binary was built from an uncommitted Rust edit while the
existing sidecar and image claimed the old clean Rust commit. The
[zero-credit stop record](EVIDENCE-INDEX.md) preserves that provenance blocker.
That provenance stop was subsequently resolved by a clean Rust/Lab successor,
a matching release client and a new response qualifier. Its routed CS-BuFLO
capture passed independent deep verification **1/1**, including the retained
host packet capture and receive-credit accounting. A subsequent BuFLO retry on
the same clean source also passed independent host verification **1/1**. Neither
historical-workload result replaces the ten-site shakedown. See the create-only
[diagnostic receipts](EVIDENCE-INDEX.md). The existing v147 image remains
bound to its own source; the host overlay is recorded separately.

Direct v147 browser discovery for `www.idrlabs.com` failed the 30-second
passive-render quiescence check; the catalogue navigation route separately
hit a recoverable root CDP `InvalidInterceptionId`. `www.weerplaza.nl` failed
the primary redirect-chain audit. `www.sacnilk.com` produced a promising
42-resource discovery, then failed complete-origin convergence and quiescence.
`www.3bmeteo.com` completed 106-resource and 136-resource discovery passes,
but the second still found new analytics origins, including a changing
hostname. None of these sites was admitted. Those historical checks used
v147; current site attempts use the separately bound clean matching prepare image.
Of six further curated browser checks, `poki.com` is the strongest lead:
259 resources with one unapproved-origin GET in its first pass. Its second
pass approved that origin and completed with 268 resources, no unapproved
GETs and one unsafe analytics POST excluded. Its first zero-credit
preparation attempt then failed the complete-resource HTTP/3 check on
`poki-auth.poki.com/sessions/whoami`; no replay or workload followed. Poki
remains a diagnostic lead, not an admitted site. A separate zero-credit
relaxed-coverage test also failed two-run stability for the main document and
52 other resources, so simply omitting the one unavailable resource did not
solve this candidate. A direct check of `www.haberler.com` failed browser
quiescence. Both failures took seconds rather than a long capture cycle.

Both BuFLO modes now have a complete independently verified host diagnostic
on the clean successor. Their earlier failures remain preserved; this one
historical workload does not establish reliability on the selected study
sites. A fresh baseline successor also passed after adding two seconds for
the recorder to settle. Any later reduction in settings would require a new prospective
profile and recalculated formal grid.

## Running and recovering a lane

The authoring host launcher recognizes v5 formal lane names beginning
`rapid-curated-tranco50-v5-formal-` and the ten v5 diagnostic lanes at block
`b01`, shards `s01` and `s02`, one visit per site. It checks the frozen profile
and requires the expected named qualification manifest for defended lanes.
The create-only adapter is `tools/rapid_capture.py`. It checks the real bound
image before launch, records the host process and DNS pins, and grants lane
credit only after deep result verification. Use the frozen study modules for
the host command. After eligible sites, response qualifiers, a verified plan
and the portable operator spec exist, the command shapes are:

```bash
PYTHONPATH="$rapid_source/src" python3 "$rapid_source/tools/rapid_capture.py" \
  launch --spec "$capture_spec" --evidence-root "$lane_evidence" \
  --lane '<published-campaign-name>'
PYTHONPATH="$rapid_source/src" python3 "$rapid_source/tools/rapid_capture.py" \
  verify-lane --spec "$capture_spec" --evidence-root "$lane_evidence" \
  --receipt '<lane-directory>/complete.json'
```

These are **command shapes**, not a claim that a final campaign exists yet.
The spec binds paths, the exact image, source snapshots, client, launchers,
fixed traffic files, cohort and plan. Study inputs must be visible beneath
its mounted data root. Campaigns and workloads use the execution root's
`config/campaigns` and `config/workloads` layout.

**Direct `qcsd-lab resume` is disabled for rapid campaigns** because generic
resume deletes partial attempts and rewinds counters. For an ordinary failed
lane, publish a create-only successor campaign through
`tools/rapid_plan.py successor`, use a new plan/spec binding and launch its generation with
`--predecessor-intent '<old-lane-directory>/intent.json'`. Keep the old files
unchanged. This currently requires identical image, client, source and
launcher identities. A repair that changes those identities remains
unsupported until a targeted proof protocol exists.

The completed adapter/planner suite passed **50 focused tests**. Actual
SIGTERM and SIGKILL tests killed the adapter parent while a separate native
worker held the inherited capture lock. The child host survived, competing
locks were refused, partial capture bytes stayed intact, and its actual
exit status was recorded. These bounded tests use a local test host, not a
public-study capture.

If the worker itself is lost after its durable host-start receipt exists,
`retire-lane --spec "$capture_spec" --evidence-root "$lane_evidence"
--intent '<old-lane-directory>/intent.json'` records zero-credit retirement
only after the original host and worker have gone, both locks are held, and
the guardian, durable ownership and owner-labelled Docker objects are absent.
The retirement and successor tests passed; the query boundary test replaces
only Docker actuation. Real daemon retirement has not been exercised here.
Interruption **before durable host-start publication** remains a quarantined
window; the adapter will not invent a process receipt to recover it. The
installed-runtime preflight 002 below uses the final frozen capture-helper
snapshot. It checks runtime agreement; the actual parent-interruption tests
use a local test host and do not claim a public-study lane inside that image.

### Site admission and campaign planning commands

`tools/rapid_acquire.py` is the v5-profile site driver. `init` freezes the
profile, source catalogue, runtime source metadata and separate implementation
snapshots. Current revision 6 binds its published receipt with
`--selection-amendment` and all required implementation groups, including the
browser-policy, collector, preparation and unsuccessful-attempt snapshots.
Optional `--root-screen-context`, `--root-screen-runtime-proof` and
`--root-screen-runtime-proof-sha256` retain a separately verified original root
runtime only when its survey components, client and prospective input rules
match. They do not change the main page/preparation runtime or rewrite raw logs.
`status` reopens the
retained attempts and identifies the next candidate in the fixed order. The
remaining actions are:

| Action | What it records |
|---|---|
| `navigate` | Raw browser navigation and independently rederived page choices; the frozen amendment may retain a separately verified typed policy failure, collector limitation or actual unsuccessful operation with zero credit |
| `probe-page` | A passing-control probe, the exact selected page's H3 result, then another control |
| `screen-page` | Automatic public URL/domain screen, bound to the selected navigation ordinal and exact-page H3 receipt |
| `review` | A named human's explicit decision for historical contexts whose frozen rules require it; revision 6 uses the automatic screen |
| `prepare` | Complete browser resource graph, complete-origin preparation and three complete replay checks under the registered response policy; requires the actual `--automated-screen` receipt |
| `seal` | Independently derives admission or an explicit frozen zero-credit policy/failed-operation disposition from retained proof; generic errors or missing evidence still block |
| `cohort` | The first ten or fifty eligible sites, with all earlier candidates accounted for |

Navigation, H3 probes and preparation run inside the bound prepare image with
the separately frozen overlay. Inspection, automatic-screen recording,
explicit human-review recording where applicable, and evidence assembly can
run on the host. All failed attempts remain visible. Use
`PYTHONPATH=src .venv/bin/python tools/rapid_acquire.py --help` from the Lab
root for required arguments; a plan file alone does not create image authority.

After a cohort and its five-site response qualifiers exist,
`tools/rapid_plan.py publish` creates the campaign YAML files and a zero-credit
plan receipt. Its `verify` action reopens the site/cohort evidence, workloads,
response qualifiers and every generated campaign. A qualification spec has
this shape, with one entry per five-site shard, in cohort order:

```json
{
  "schema_version": 1,
  "qualification_sets": [
    {
      "qualification_set": "rapid-v5-shard-01",
      "manifest": "execution-root/config/chaff-response-qualification-store/sets/rapid-v5-shard-01/_qualification-set.json",
      "sidecar_root": "execution-root/config/chaff-response-qualification-store/sets/rapid-v5-shard-01",
      "prefix_spec_root": null
    }
  ]
}
```

Paths in that spec are relative to the spec file. A ten-site cohort needs two
entries; the final fifty-site cohort needs ten. The first cohort generates ten
five-visit diagnostic lanes (50 traces); the final cohort generates 800
twenty-visit formal lanes (16,000 traces).
Materialize named response sets in the execution root at the exact
`config/chaff-response-qualification-store/sets/<set>` location: the installed
capture runtime resolves them there. A valid qualifier elsewhere does not
supply that capture input.

Strict qualification **reloading** and planning run inside the exact bound
collection image, with its installed source metadata and runtime gate.
They need no network or image rebuild. A native host call can stop because
it lacks `/usr/share/qcsd-lab/source.json` or the installed runtime gate;
substituting authoring-host metadata would change the binding.
The proven qualification bridge reloaded
`rapid-clean-csfix-diagnostic-one-20261002` as valid, response-only and
zero-credit. Its host-local retained result is
`diagnostic-rehearsals/clean-rapid-runtime-20261002/qualification-bridge-check-001/output.json`,
catalogued through the [evidence index](EVIDENCE-INDEX.md).

A separate **historical installed-runtime preflight passed with exit 0 and empty
stderr** at
`diagnostic-rehearsals/rapid-v5-capture-runtime-20261003-002/output.json`.
Its raw SHA-256 is
`f7b8f22da2880e444bc1ce312ad26ebb56ecf3a5947ca1c088da3c4aafec6355`.
It reopened the installed collection-image implementation, clean Lab source
`6260c3b1a5e0d5a14dbdc8e2fe443bf506969aac`, source manifest
`59b03cf2d715220f2f7a0584ecfdc95b956528627861cd3898524a16c649327e`,
client `a21eb5fa8654e90c9ed18ecfa4280f5fdb311c592a6c89d5b963c3cd03a17380`,
host launcher `7216d6a689d858962d982b5bd01cfc9652f1cbb20d7c5b6fbb4a664d4d27751a`,
the frozen v5 profile and all three fixed traffic files. The separately frozen
101-file Python snapshot has aggregate SHA-256
`033314652aba4bc5cb6e480b3e9c06d6ba93996fc4a4ba2339547dbcd02ba96d`;
it used helper
`ac730c551b6783fb21c556017e8b11212713566d1b86ee0a145a4adf25c03fcd`
and capture CLI
`48ce673eb61ef189bcbd696ef08a765cd53de01d759ae9bd91f9f79a70bc139e`.
This is a runtime check before cohort availability; it is **not** a verified
study lane, ten-site shakedown or formal capture. The later revision-3 site
modules have separate prospective bindings; this receipt covers its saved
snapshot and is never rewritten to claim that later source was executed.

Mount the **complete frozen clean runtime** at `/runtime-src` and the
separately frozen study modules at `/rapid-src`. Set
`QCSD_LAB_ROOT=/runtime-src`, `PYTHONPATH=/rapid-src/src` and
`QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json`. The clean
collection image verified for that historical check is
`sha256:fc3608b0919ee2486d2c6ad0cf03f77551972195b6800fd6c59f193a243b8ad4`.
Use the digest recorded in the acquisition/runtime binding and preserve the
two source identities separately. Do not mount only a partial runtime or
claim that external study modules were installed in the immutable image.

Example command shape after the cohort, qualifiers and writable output
directories exist; the input paths below are placeholders:

```bash
collection_image='sha256:fc3608b0919ee2486d2c6ad0cf03f77551972195b6800fd6c59f193a243b8ad4'
runtime_source='/absolute/path/to/frozen-clean-runtime'
rapid_source='/absolute/path/to/frozen-study-source'
rapid_evidence='/absolute/path/to/study-evidence'
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -e QCSD_LAB_ROOT=/runtime-src -e PYTHONPATH=/rapid-src/src \
  -e QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json \
  -e QCSD_LAB_IMAGE_DIGEST="$collection_image" \
  -v "$runtime_source:/runtime-src:ro" -v "$rapid_source:/rapid-src:ro" \
  -v "$rapid_evidence:/evidence" --entrypoint python3 "$collection_image" \
  /rapid-src/tools/rapid_plan.py publish /evidence/acquisition \
  --cohort /evidence/acquisition/cohorts/launch-10.json \
  --qualification-spec /evidence/qualification-spec.json \
  --workload-root /evidence/execution-root/config/workloads \
  --campaign-dir /evidence/execution-root/config/campaigns \
  --output /evidence/new-plan-receipt.json
```

Use `verify` in the same bound image with the same mounts and arguments to
reopen it. `successor` also takes
`--lane <generation-one-campaign-name> --generation 2` and a new output path;
it creates one replacement lane while preserving its predecessor. That only
publishes a campaign. A changed implementation still needs its corresponding
new source/runtime binding and targeted proof before the lane can launch.

Preserve every failed attempt. An ordinary transient BuFLO failure can be
retried in a fresh successor lane on unchanged source while other completed
lanes remain intact. Keep completed lanes' frozen module snapshots unchanged;
authoring edits elsewhere do not rewrite their source identity. Changed
parameters, workloads or runtime source need a prospectively declared binding
and targeted proof; the current adapter refuses that repair path. The final
`publish-manifest` and `verify-manifest` actions run real closure inside the
bound collection image, rejecting missing, duplicate or diagnostic slots and
requiring all **800 lanes / 16,000 accepted formal traces**.

The current Docker guardian permits **one capture container at a time**.
Defense-specific restart works with serial lanes; concurrent lanes require a
separate two-container test with disjoint resources and verified capture
fidelity. Parallel speedup remains unmeasured. The [study plan](RAPID-CLASS-STUDY.md)
records the timing assumptions and limits.
