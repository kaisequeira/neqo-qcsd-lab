# Rapid capture path: from candidates to 16,000 verified traces

**Planning and implementation status, 3 October 2026 (Australia/Sydney).** This is the run order
for the prospective [50-site study](RAPID-CLASS-STUDY.md). Its formal target is
**50 websites × five traffic settings × 64 visits = 16,000 accepted traces**.
The five settings are undefended, FRONT, Tamaraw, BuFLO and CS-BuFLO. The
ten-site, one-visit-per-setting shakedown produces **50 diagnostic traces with
zero formal credit**. The earlier 100-site and 20-site contracts are separate
historical studies; their long build, browser-vector, fitting and nine-mode
sequence does not gate this prospective five-setting study.

## What happens, in order

| Step | Action | Evidence needed to advance | Current state |
|---:|---|---|---|
| 1 | Freeze the candidate sources and runtime. | Exact source hashes, ordered [v5 rapid profile receipt](../config/curated-sources/crux73-tranco600-rapid-v5.profile.json), image digests, fixed defense parameters and launcher-source hashes. | V5 is frozen (SHA-256 `f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60`), preserving 73 supplied candidates, 600 fallback candidates and 50 × 5 × 64. Clean matching collection and prepare images exist. Selection revision 3 is published. The real installed-runtime preflight 002 passed inside the collection image with the saved client, clean source, fixed traffic files and final capture adapter snapshot; it grants no lane or trace credit. |
| 2 | Find usable pages. | Record verified decisions in frozen order. Revision 3 inherits the automatic public URL/domain screen, controlled homepage observation, separate controlled HTTP/3 pass on the exact selected page, complete browser-observed graph, stable replay and live cross-origin resource. Only a controlled completed-response ambiguity can proceed alongside a known-valid homepage. | All **73 fresh v5 curated first-screen decisions** independently verify: **31 known-valid, 27 ambiguous, six peer TLS failures, two timeouts and seven automatic safety skips**. A fresh 40-candidate fallback batch adds one known-valid homepage and seven completed-response leads. **Context 005 has five independently sealed zero-credit decisions.** Albumaty's fresh 73-second page failure and Alibaba's fresh 65-second collector failure are sealed; all 18 Alibaba raw files and 13 source/client bindings were independently reopened. Pinterest is next. Old context-004 errors remain unpromoted. **0/50 final sites admitted.** |
| 3 | Prepare and qualify the first ten sites. | Ten verified prepared workloads, with five-site response-qualification sets matching the exact workload and source bytes. | A fresh one-workload qualifier matches the clean repaired client. Its response-only receipt independently reloads through the collection-image qualification bridge. This proves the runtime route; the workload is historical and does not supply ten admitted study sites. |
| 4 | Run the ten-site shakedown across all five settings. | 50 complete, individually deep-verified diagnostic traces, including both BuFLO modes, with failures preserved and repaired before formal capture. | All five settings now have individual clean-runtime diagnostic passes on one historical workload: CS-BuFLO **1/1**, BuFLO retry 004 **1/1**, FRONT and Tamaraw accepted, and a fresh undefended two-second-settle successor **1/1**. The previous undefended attempt lacked 45 tail packets and remains failed. These separate passes do not supply the ten-site shakedown. **0/50 study shakedown traces accepted.** |
| 5 | Admit 50 sites and freeze formal inputs. | A verified 50-site cohort receipt, exact workloads and qualification sets, fixed parameters, complete lane plan and launch manifest. | 50-site live yield is unproven; the 600-domain catalogue supplies further candidates under the same checks. |
| 6 | Capture the formal grid. | Each defense lane is a separately named, frozen campaign. Deep verification must show its exact sites, setting, visit slots, source/image binding and complete result seal. | The planner and capture adapter represent 800 lanes, retain failed attempts and verify final manifest closure. The frozen runtime check passed. The completed supervisor passed real parent-interruption tests; retirement and successor tests also passed, with Docker actuation substituted. No v5 50-site cohort or formal bound lane has run. **0/16,000 formal traces accepted.** |
| 7 | Close the evidence campaign. | One manifest enumerating all 16,000 unique accepted slots and result-seal hashes, verification output for each lane, recorded failures and restarts, and a portable source commit. | Pending capture. |

The planned grid divides 50 sites into ten groups of five. Each of 16 time
blocks has four visits per site and five setting-specific lanes per group:
**16 blocks × 10 groups × five settings = 800 lane campaigns**, each with 20
traces. This is an evidence layout, not a claim that 800 campaigns have run.
The settings should be interleaved across time so that network changes do not
systematically favor one setting.

## Rough time budget

| Work | Planning estimate | What can change it |
|---|---|---|
| Root HTTP/3 screen | All 73 fresh supplied-site decisions are verified. A further 40-candidate clean fallback batch took about **4 minutes 10 seconds**. | Public network and control failures cause a fresh, preserved attempt. Root decisions grant no site credit. |
| Browser discovery, replay and 50-site admission | **Unknown.** One recent direct discovery finished in 25 seconds, while other pages failed around the 30-second quiescence limit. | Live page behavior and the number of fallback candidates dominate this stage. A root success is not a prepared site. |
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

### Current milestone: fresh revision-3 context 005

Context 005 is now running with the published revision-3 receipt and frozen
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
decisions**, with Pinterest navigation next. Counts remain **0/50 admitted sites,
0/50 study shakedown traces and 0/16,000 formal traces**. The latest closure
records are collected through the [evidence index](EVIDENCE-INDEX.md).

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

`tools/rapid_acquire.py` is the prospective v5 site driver. `init` freezes the
profile, source catalogue, runtime source metadata and separate implementation
snapshots. For revision 3, bind the published receipt with `--selection-amendment`
and its separate `--browser-policy-module` and `--collector-module` snapshots.
`status` reopens the
retained attempts and identifies the next candidate in the fixed order. The
remaining actions are:

| Action | What it records |
|---|---|
| `navigate` | Raw browser navigation and independently rederived page choices; an amended context may retain a fresh exact typed browser, passive-render or revision-3 collector failure with zero credit |
| `probe-page` | A passing-control probe, the exact selected page's H3 result, then another control |
| `screen-page` | Revision 2's distinct automatic public URL/domain screen, bound to the selected navigation ordinal and exact-page H3 receipt |
| `review` | A named human's explicit decision for contexts whose frozen rules require it; revision 2 uses the automatic screen |
| `prepare` | Full browser resource graph, complete-origin preparation and three immediate replay checks; revision 2 passes the actual `--automated-screen` receipt |
| `seal` | A site decision independently derived from the retained evidence; only the declared exact collector failure receives the new retryable zero-credit disposition; other unexpected errors still block |
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

A separate **real installed-runtime preflight passed with exit 0 and empty
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
collection image currently verified is
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
