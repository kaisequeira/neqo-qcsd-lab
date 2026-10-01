# Acquisition rehearsal before another build

This is an engineering release gate for the next source freeze, not an
acquisition receipt. Run it before claiming another cohort or starting a
no-cache build. The [project ledger](../PROJECT.md) records the current
position, the [study runbook](CLASS-STUDY.md) defines formal commands, and the
[evidence index](EVIDENCE-INDEX.md) distinguishes retained diagnostics from
accepted evidence.

The v131 build was interrupted by the user (exit 130) after its cohort claim
was published. Its retained transaction was archived with a host-local
maintenance receipt. The v132 claim was consumed when lifecycle admission
blocked on that transaction, before a build began. After recovery, v133 built
the collection image (62/62 BuildKit steps), but its post-export tag inspection timed
out at the ordinary three-second Docker API service. The v133 transaction was
archived and recovery passed. None of v131-v133 has a verified build or
acquisition authority receipt, and none created an acquisition checkpoint.
Preserve all three claims; use the allocator's next unused version after the
bounded read-only inspection fix and its affected tests pass. The v130
collection image is useful for cheap diagnostics with development source
mounted read-only. It cannot attest that
source, issue a formal receipt for it, or lend v130's 110/110 browser result to
the next cohort.

## What has actually been verified

| Boundary | Current engineering evidence | Remaining requirement before a long formal run |
|---|---|---|
| Acquisition code and resume contracts | After the paired cohort-root changes, the current read-only source passed the registered 16-file acquisition matrix in the existing collection image: 2,113 passed, 31 skipped, no failures. A downstream host matrix passed 456 tests, and the focused watcher suite passed 400. | Run the registered suite in the eventual clean, newly built collection image and verify its source-bound receipt. The old-image checks carry zero formal credit. |
| Live browser to complete workload | With the new client, frozen candidate `zoomlife.ir` completed exact-page H3 screening, two-origin convergence, three-run Neqo preparation, and deep schema-2 validation of a 63-resource graph. | A fresh source-bound bounded formal acquisition action and later stability observations must produce independently verified terminal evidence. One zero-credit preparation proves no 120-class cohort. |
| Fitting and selection | A sealed synthetic 480-sample fitting handoff passed; integrated synthetic admission reached fitting, final selection, and the 100-class cohort. A separate joined test loaded and preflighted generated 900-cell certification and 1,600-sample formal block plans with fitted and qualification inputs. | Real fitting and qualification need acquired pilot workloads and the same-source full foundation. |
| Capture and handoff | The new client produced schema-4 and schema-5 live response receipts, accepted by the Python packet/identity consumer with only diagnostic source provenance stubbed. Its local two-origin smoke accepted and deep-verified 2/2 sealed samples; FRONT/Tamaraw and Walkie-Talkie local wire paths passed. A later local retry mirrored the capture container's UID/capability transition under a read-only root and accepted, sealed and deep-verified FRONT 1/1 and Walkie-Talkie 1/1, after preserving one earlier strict FRONT timing failure. Eight compact production seal-to-handoff tests cover all formal runtime kinds; all 50 existing handoff tests passed. | A clean source-bound response qualification, prefix qualification, defended public-site capture, 900-cell certification and final handoff still require genuine evidence. The local retry did not invoke the formal launcher or public-origin policy, and used synthetic preparation and Walkie-Talkie parameters. |
| Candidate frame | All 600 frozen origin roots were control-bracketed; 63 returned known-valid. Exact selected pages on DeepL, Dropbox, and OpenStreetMap showed root-only screening can miss H3-reachable pages. Schema 12 now screens exact selected page URLs prospectively. | Prove enough complete, stable workloads in formal acquisition and recheck balanced cohort feasibility as outcomes arrive. |

The watcher now derives the stability and admitted-workload roots from the
allocator's versioned acquisition root. `acquisition-init` creates both only
when they are absent; the watcher rejects pre-existing output for an unstarted
candidate, and cohort/campaign readers bind the same version. Historical
unsuffixed roots remain verify-only. Focused pairing, collision and
same-cohort resume tests pass.

These checks are designed to expose deterministic failures before another long
build. They cannot guarantee future public endpoints, DNS, timing, or all
unexecuted defended captures. Keep the final long watcher closed until the
remaining source-bound and bounded formal gates pass.

### Decision boundary for the long acquisition watcher

**Current decision: hold the unattended long watcher.** The contract tests
exercise the 120-class admission, fitted-bundle and named qualification-set
consumers, generated 900-cell certification and 1,600-cell block plans,
canary checkpoint recovery, sealed-result handoff and the evaluation loader.
Some of those tests substitute unavailable live foundation, qualification or
packet collection evidence. The live diagnostics exercise real Neqo packets,
but have unknown source provenance and do not join every downstream stage in
one authoritative run. This is substantial early fault detection, not proof
that every later site and defence will succeed.

Before an unattended watcher, require a final-source collection-image suite,
clean-source build and acquisition authority, and a bounded formal action
whose checkpoint and terminal evidence deep-verify. A small diagnostic
vertical slice should also carry one two-origin prepared graph through real
response and prefix qualification consumers, a defended capture, seal and
deep verification; keep any diagnostic source/executable authority
substitutions explicit and give it zero scientific credit. Start with
monitored batches and inspect their terminal reasons before scaling. The
production `qualify-prefix` and defended `capture` commands require the full
admitted pilot cohort, its 480-sample fitting bundle and the full foundation;
one-class diagnostics cannot prove those commands. Even a green slice cannot
pre-verify the cohort-dependent 480/2,000 fitting samples, 900 first-launch
cells or 16,000 public-site captures: those require real admitted classes and
must be checked as their evidence arrives.

## Release gate in increasing cost order

| Order | Check | Required observation before moving on |
|---:|---|---|
| 1 | Host-only source and contract tests | Acquisition authority, watcher, runner and class-pipeline tests pass on the proposed source. Exercise eligible and ineligible scientific terminals, infrastructure blockers, interrupted navigation/probe/preparation, orphan-terminal recovery, checkpoint resumption and rejection of changed provenance. No test may silently turn an infrastructure error into site ineligibility. |
| 2 | Existing-image parity check | Run the acquisition correctness suite with the proposed Lab source mounted into the v130 collection image, using the same Python environment, user, filesystem visibility and network isolation as authority creation. Require a clean exit and capture the test summary. This catches collection-container failures such as the absent user-systemd socket before another build. It does not validate a future image's source binding. |
| 3 | Bounded live diagnostic | Use a create-only diagnostic root outside formal acquisition roots. A small, explicit diagnostic input must exercise browser navigation and root CDP handling, the control and exact selected-page HTTP/3 screen, redirect/origin convergence, complete multi-origin preparation, and Neqo replay. Record each stage's start, finish, inputs, exit reason and artifacts. Exercise a known-good control and selected catalogue candidates without changing the frozen 600-candidate catalogue. Preserve every failure. A root CDP interception error is an infrastructure failure, not a scientific site rejection. |
| 4 | Later-consumer contract and live capture tests | Synthetic admitted-workload and receipt fixtures reach acquisition completion and the pilot/final cohort consumers, fitting admission, prefix/qualification dispatch, and capture-foundation validation. Require fail-closed behavior on wrong source, build, browser, image, workload, or fitting lineage. Run the targeted local two-origin H3 capture acceptance tests with ordinary server sidecars to exercise real packets, sealed results and selected defence wire paths. These checks do not replace live fitting on acquired classes, the deferred browser gate, 900-cell certification, or formal capture. |
| 5 | Formal bounded start on newly verified source | Only after the above pass: freeze clean Lab/Rust source, let the allocator claim a fresh cohort, run the registered no-cache build, pinned CDP, schema-2 acquisition authority and independent verification. Initialize a create-only acquisition root and run `acquisition-watch --max-actions 1`. Inspect its checkpoint, action result, detailed failure and receipt inventory before another action. Repeat bounded actions through a real baseline and both short-horizon prepared observations, with a verified eligible terminal or an honest, classified scientific rejection. Scale to unsupervised watching only after the bounded path is healthy. |

The [diagnostic runner](../tools/acquisition_rehearsal.py) implements order 3
with an exact frozen-catalogue `ID=DOMAIN` input or a separately labelled
control domain. It requires a new output directory outside the Lab checkout,
caps targets, selected pages and wall time, and records each stage in a
flushed JSONL log. Its optional [root CDP trace](../tools/acquisition_root_cdp_trace.py)
is enabled only for a diagnostic process and leaves production interception
policy unchanged. All outputs carry **zero scientific credit**. Never import
them into an acquisition checkpoint, reuse them as a baseline, or present
them as eligible terminals.

The schema-12 early HTTP/3 screen checks the exact canonical selected-page
URLs. The prepared workload freezes the request graph, but preparation and
capture still fetch resources from those public endpoints with Neqo. A failed
early screen may be probed further only in the explicitly non-evidentiary
diagnostic lane; successful later preparation after a failed screen cannot
qualify a candidate under the prospective formal contract.

For order 1, the relevant test families are
`tests/test_class_acquisition.py`, `tests/test_class_acquisition_watch.py`,
`tests/test_class_acquisition_authority.py`,
`tests/test_class_build_admission_acquisition_authority.py`, and
`tests/test_class_pipeline.py`. Include `tests/test_class_fitting.py` and
`tests/test_fitting_algorithms.py` for order 4. Run focused failures first and
then the complete registered acquisition-correctness set; record exact test
names and totals. A mock-only success cannot satisfy order 3. Any fix after a
check invalidates that check's result for the changed source; rerun the affected
cheap checks before source freeze.

## What a green rehearsal means

The release gate passes only when its synthetic recovery and consumer cases
pass, the collection-image parity suite exits cleanly, and at least one bounded
live diagnostic completes navigation, HTTP/3 screening, convergence,
preparation and replay with internally consistent artifacts. Failed live
attempts must be retained and classified. If no live candidate reaches replay,
the gate remains open while the fault is diagnosed; substituting a fabricated
eligible terminal would hide the risk this rehearsal is meant to expose.

### Diagnostic results (30 September–1 October 2026 UTC)

The prebuild engineering rehearsal has **passed its diagnostic criteria**;
the unattended formal watcher is still **held**. The collection-image acquisition correctness matrix
passed **1,979 tests with 31 skips and no failures** in 14m37s using an earlier
proposed source mounted read-only. The registered 16-file suite was then rerun
against the current read-only source in the immutable v130 collection image
(`sha256:fb10e8359ff7e3e5ff323027d58f38bf2ee3724e2f26e17399f0cb7a8bcfc8d4`):
**2,112 passed, 31 skipped, zero failures in 15m02s**. A later repeat after
the paired cohort-root changes passed **2,113 with 31 skips and zero failures
in 5m06s** in the same image, with the mounted source explicitly first on
Python's import path. These are diagnostic parity checks, not authority from
a newly built image. The current later-consumer
host matrix passed 388 tests with three skips, including a synthetic completed
120-class prefix carried
through cohort admission and pilot campaign planning. That fixture verifies
the 480 fitting and 1,080 compatibility sample plans but does not execute
live fitting or formal capture. A later current-source downstream matrix passed
411 tests with no skips or failures in 10m09s, covering synthetic late-campaign
planning, recovery, sealed handoff/evaluation joins and watcher collision
admission. Three targeted local container-edge tests
also passed in 32.56s: two-origin H3 capture with sealed packet/receipt
verification, FRONT/Tamaraw response-only capture, and a Walkie-Talkie A/R/C
wire path. Those tests used the old compiled v130 Neqo client and temporary
local servers, so they do not prove public-site stability or source-bound
formal capture. A hand-picked, zero-credit survey of 24 frozen catalogue roots
using the same Neqo HTTP/3 probe found three known-valid roots
(`bandcamp.com`, `doabooks.org`, `poki-gdn.com`), thirteen timeouts and eight
ambiguous outcomes, with known-valid controls before and after. A separate
round-robin survey of the first eight candidates in each of five strata found
four known-valid roots among 40, thirteen timeouts and 23 ambiguous outcomes.
The next eight in each stratum yielded three known-valid roots among 40, 19
timeouts and 18 ambiguous outcomes, again with passing controls before and
after. The two systematic slices therefore found seven known-valid roots
among 80, but were not a random sample of the full catalogue. These surveys
are search aids, not eligibility estimates or scientific samples. The low
early yield is a feasibility warning for the registered 24 eligible classes
per stratum; it is not proof that the remaining catalogue lacks them.

At that checkpoint, no frozen-catalogue diagnostic had reached a deeply
verified prepared workload.
The `cloudflare-quic.com` control passed its screen and origin convergence but
Neqo preparation failed when a public endpoint closed. `creativecommons.org`
was blocked at the screen and its explicit diagnostic continuation hit a CDP
shutdown integrity failure. `kde.org` failed the screen with selected-origin
timeouts. `w3.org` and `google.co.uk` failed navigation policy checks.
`doabooks.org` passed the cheap root HTTP/3 probe but its full navigation hit
`InvalidInterceptionId`; the opt-in trace retains the exact event ordering.
`bandcamp.com` passed navigation and the HTTP/3 screen, then exposed a
Chromium built-in error-page parser column variant (observed 632, pinned 624)
in origin convergence. An explicitly zero-credit +8 column diagnostic passed
that first check, then its passive render did not settle within 30 seconds;
the remaining error-page image sequence and full preparation are unproven.
`poki-gdn.com` passed navigation, the screen and origin convergence, then
complete-coverage preparation rejected its browser-requested `/favicon.ico`.
An isolated Neqo HTTP/3 diagnostic returned a complete 404 on both HEAD and
GET for that URL. It used default headers and no frozen origin-IP pin, so it
diagnoses the endpoint without replacing the preparation receipt.
`srindiamis.org` and `azall.com` each passed navigation, root HTTP/3 screening
and origin convergence; complete-coverage preparation failed when a secondary
origin closed its Neqo endpoint (`img1.wsimg.com` and
`static.cloudflareinsights.com`, respectively). The systematic survey also
found `vortexnetwork.net` root HTTP/3 valid, but its navigation encountered the
same built-in error-page parser check with column 599. These two different live
columns show why a fixed absolute parser column cannot safely identify that
image sequence. The production guard now bounds parser coordinates while
retaining pinned image hashes, ownership, order and lifecycle checks. A repeat
Vortex rehearsal passed its earlier parser check but later encountered
a `Network.loadingFinished` event with no matching active request occurrence.
Its new opt-in trace retained the unmatched event without reclassifying it as
a site rejection. `pinkoi.com` passed navigation and H3 screening, then origin
convergence failed because its HTTP observation and request-stage interception
ledgers differed. A repeat with an opt-in ledger trace found two failed Network
requests without matching Fetch pauses, one of which was already covered by
the narrow CORS preflight exception. Neither reached preparation.

The separate `quic.nginx.org` diagnostic control passed every bounded live
stage in 62.59s: navigation, HTTP/3 screening, origin convergence, complete
preparation with three Neqo stability runs, and deep prepared-manifest
validation. Its one-origin graph is useful engineering proof of the path, but
it is outside the catalogue and contributes no eligible class. A repeat
`azall.com` preparation preserved the failed Neqo probe receipt and confirmed
that the secondary endpoint tried the same IP as the browser pin before a TLS
handshake failure. The live multi-origin catalogue path was then unverified.

The next systematic slice found `rp-online.de` root HTTP/3 known-valid. Its
full rehearsal passed navigation and the H3 screen, then failed origin
convergence when Chromium ExtraInfo could not be associated with a request
occurrence; this remains an infrastructure integrity failure. The other two
known-valid roots in that slice are not yet full-rehearsed. Real-Chromium
integration tests for the changed router passed 12 cases in the bridge
profile and the pinned-CDP isolation case in its required loopback-only
profile. An initial combined run put that isolation case on bridge networking
and failed its interface assertion; rerunning only that case in the correct
profile passed. Neither run published a formal pinned-CDP receipt.

#### Complete frozen-root survey and later path checks (1 October UTC)

Seven control-bracketed survey files cover all 600 frozen catalogue pairs
exactly once, 120 per stratum. Every included bracket's opening and closing
`cloudflare-quic.com` control was known-valid. The Neqo root probe returned
**63 known-valid, 254 timeout and 283 ambiguous** outcomes. Known-valid roots
by ascending rank stratum were **2, 6, 17, 14 and 24**. These are
non-evidentiary observations at one time, not formal site eligibility, and
ambiguous/timeout outcomes must not be reclassified as scientific rejections.
The root-known-valid candidates alone cannot fill the registered 24 eligible
classes in each stratum. This is not an upper bound on eligibility: the probe
used each domain's `/` URL, whereas navigation may select a different final
page URL, and a root marked nonvalid may still reach an H3 endpoint. The
balanced cohort is therefore unproven and a high-risk long-run launch, not a
proven impossibility. Test exact selected URLs and complete graph preparation
before a prospective cohort decision. A first attempt at positions 88–111
stopped after 40
targets when its closing control could not resolve its hostname; those
candidate outcomes were excluded. A fresh create-only repeat passed all
controls. Windows DNS and direct WSL IP connectivity still worked during the
brief WSL resolver failure; a container with explicit public DNS resolved the
control, and WSL's default resolver subsequently recovered. This transient
failure also needs operational monitoring before a long watcher run.

The frozen `tranco-0594249=zoomlife.ir` diagnostic completed real browser
navigation, a passing root H3 screen, two-origin convergence, three-run Neqo
preparation and deep validation of a 63-resource prepared manifest. The second
origin supplied one analytics resource. This is the first complete
multi-origin catalogue rehearsal and has **zero scientific credit**; it does
not establish a stability window or formal eligibility. `sussfamily.net`
completed the same bounded preparation path with one origin, so it is not a
multi-origin class. `create.studio` passed the corrected failed-preflight and
normal-shutdown CDP paths live, then timed out under the passive-render policy.
`homesteady.com` passed its earlier error-document coordinate check, then also
timed out in passive render. `spinworks.nl`, `britspinworks.uk` and
`diecezjatarnow.pl` converged to multi-origin graphs but failed Neqo
preparation with a secondary endpoint `Peer(296)` closure. Other rehearsed
roots still exposed retained navigation or CDP failures; none was counted as
an accepted acquisition terminal.

Current host CDP/discovery tests passed **954 cases** with 26 environment or
browser cases deselected. The exact root shutdown POST `Network Fetch` versus
`Fetch XHR` alias is accepted only after local shutdown cancellation, with
adversarial tests preserving strict request identity. A zero-credit sealed
synthetic 480-sample pilot fitting result passed default trace loading,
numeric-bundle creation, source-bound refit verification and post-seal tamper
rejection in 35.15s. Its compact deterministic fitters and substituted
external authority checks keep that join test bounded; real fitting still
requires genuine acquired workloads and the same-source full foundation.

A further zero-credit integrated host test carried synthetic 120-class
acquisition admission through the 480-sample pilot plan, numeric fitting,
finalized qualification binding, a 100-class final selection and cohort, and
campaign generation. The pilot and authoritative fitting and canary campaigns
loaded and planned; the generated certification and formal documents retained
the 900 and 16,000 sample counts. Direct defended-campaign loading correctly
stopped without the named live qualification and fitted bundle artifacts. This
test passed once in 73.79 seconds. It does not execute those defended captures
or export a formal handoff.

An opt-in, control-bracketed comparison of one canonical selected page on
`deepl.com` found its exact `https://www.deepl.com/en/translator/l/en/uk`
URL HTTP/3 known-valid while the same origin's `/` URL was ambiguous. Both
controls passed. The current formal screen probes `/`, so this candidate
remained blocked under the unchanged policy. The explicit zero-credit
continuation reached origin convergence but its passive render did not settle
within 30 seconds; the selected URL result therefore does not prove a usable
prepared workload. It does establish that the root screen can miss a working
selected page endpoint. A prospective exact-URL screen would need a versioned
contract and receipt, historical verifier compatibility, and tests before use.

The all-selected-page diagnostic then found H3-known-valid alternate pages on
`dropbox.com` and `openstreetmap.org` while their unchanged formal root screens
remained blocked. One explicit Dropbox alternate reached convergence but hit a
normal-shutdown CDP integrity error; a retained opt-in trace identified a
root-page POST `Ping` Fetch pause without a matching Network occurrence. One
explicit OpenStreetMap alternate converged to two origins and started complete
preparation, but its `matomo.openstreetmap.org` endpoint received no QUIC
response and timed out. Neither page became a prepared workload, so the
selected-page screen correction alone cannot establish cohort feasibility.

A separate real-seal synthetic handoff bridge exposed a production consumer
mismatch: the exporter expected a `defense_runtime_inputs` projection that the
frozen experiment schema does not persist. The exporter now derives those
identities from the sealed defense records and checks a redundant legacy
projection for equality when present. The expanded bridge passed eight tests
across all eight formal runtime kinds, including BuFLO kernel evidence; all 50
existing handoff tests passed. The bridge stubs genuine acquisition authority,
packet extraction and performance measurements, so it grants no capture or
export credit. A separate synthetic 100-class test generated, loaded and
preflighted certification and the first formal block with production campaign,
named-set and fitted-bundle validators. It passed once in 25.76 seconds and
rejected wrong foundation and qualification lineage. Its foundation and live
qualification decoding remain explicit test doubles. A further joined canary
test passed in 159.90 seconds: production coordinator preflight, first-launch
claim, interruption on the second physical launch, durable failed-attempt
tombstone, unchanged-source resume to 100/100 synthetic accepted samples,
result seal and deep verification, and duplicate-launch rejection. External
foundation, certification, capacity, live collection and cooldown were test
doubles. This demonstrates recovery wiring but provides zero capture credit.

The latest CDP shutdown change accepts only the observed root-page POST `Ping`
plus POST `XHR` disposal pair with distinct identities and no shutdown Network
occurrence. Its 770-test producer suite and the independent 395-test watcher
suite pass. A fresh Dropbox replay with that source completed navigation and
origin convergence, confirming the previously failing CDP path live. The
formal H3 screen still blocked its discovered-origin set; an explicit
zero-credit continuation reached preparation, where the public server's
incoming UDP datagrams exceeded the study's symmetric 1,200-byte ceiling:
850 incoming payloads exceeded it, maximum 1,452; none outgoing did. This is
an internal acquisition blocker under the current contract, not an accepted
site rejection. The current manifest, capture and fitting validators also
assume that ceiling in both directions, so a preparation-only exception would
defer the failure. A prospective, versioned incoming/outgoing policy decision
is needed before relying on such public endpoints.

The browser's origin-IP pins are a frozen discovery safety and provenance
ledger. Neqo currently resolves each hostname independently for preparation
and capture; its run receipt records the actual remote address. A different
Neqo address is not itself a contract violation under this study, but
comparing it with the browser pin in retained diagnostics may explain a
secondary-origin failure. Do not describe the Neqo fetch as IP-pinned. All
diagnostic records are retained outside the Lab checkout in create-only roots;
none is an acquisition attempt, site eligibility receipt, or accepted class.

This reduces the chance of a cheap, deterministic bug appearing after another
long build. It cannot prove that all 600 changing public
sites will be reachable, that their graphs will stay stable across observation
windows, or that future containers will have identical timing and network
conditions. The first formal actions therefore remain deliberately bounded.
An unexpected exception, provenance mismatch, unclassified CDP failure,
missing action receipt, or an infrastructure error mislabeled as site
ineligibility stops expansion immediately; preserve the checkpoint and trace
before fixing source. An unchanged-source interruption may resume only under
the exact original inputs. A source or contract fix uses a fresh cohort and
create-only evidence paths.

## Release gate before an unattended acquisition run

The prospective source now has two linked changes. Acquisition schema 12
screens **exact canonical selected-page URLs**, retaining all page evidence
but scheduling only pages with two passing Neqo HTTP/3 probes. Its schema-11
origin-screen receipts remain historical and verify-only. The directional UDP
policy keeps the client's outgoing payload ceiling at 1,200 bytes and permits
complete incoming datagrams up to the advertised 65,527-byte receive limit.
Preparation publishes a schema-2 directional qualification; historical
schema-1 qualifications keep their original symmetric limit. Neither change
promotes a diagnostic into an eligible class.

The following checks must be read together before the next long watcher:

| Path | Current engineering check | Remaining live boundary |
|---|---|---|
| Exact-page H3 screen and acquisition resume | Dedicated v2, schema-11 compatibility, mixed-page ordinal and watcher tests pass; the new client probed both exact selected Zoomlife URLs twice under passing controls | First formal bounded checkpoint and both scheduled prepared observations on clean source |
| Preparation and complete graph | The new client deep-prepared 63 Zoomlife resources across two origins in three runs; incoming UDP reached 1,252 bytes under the schema-2 directional policy | Formal observation stability and enough balanced eligible classes |
| Capture, fitting and qualification | The new client produced passing five-request schema-4 and sustained 40-request schema-5 response receipts. Python accepted both packet and identity transcripts with only diagnostic source provenance stubbed. A new-client public smoke captured 1,106 packets, passed directional UDP and deep-verified its sealed incomplete result after the page body changed. Local two-origin FRONT/Tamaraw and Walkie-Talkie wire checks passed. A scoped schema-4 prefix rehearsal passed three qualification waves, and a subsequent Walkie-Talkie sample consumed that exact full sidecar and sealed 1/1 accepted with diagnostic provenance handling. | Clean-source qualification, genuine acquired-workload fitting and defended capture, certification and measured formal sample rate |
| Later campaign and recovery | Synthetic 120-class admission, 100-class final planning, 900/16,000 campaign loads, canary interruption/resume/seal, defended result handoff and evaluation-loader/Panchenko join pass | Genuine completed acquisition, same-source full foundation, real fitting/qualification, 900 final checks and measured sample rate |

The host fixtures test wiring and rejection behavior; they use doubles for
external source authority or cohort evidence where those stages cannot exist
before acquisition. The live diagnostics use a dirty, newly compiled client
mounted into the historical image. Its `migration_commit="unknown"` is
correctly rejected by formal Python provenance checks. The diagnostic-only
receipt checks substituted a valid commit value in memory for that one parser
field; no receipt or production validator was changed. Do not describe these
as formal gate receipts. Before starting an unattended full acquisition
watcher, finish the registered acquisition correctness suite in the eventual
collection image, verify a clean-source build and acquisition authority, and
run a small monitored acquisition batch. Expand only after its checkpoint and
terminal receipts verify and its failures classify cleanly.

The local Walkie-Talkie check exposed a reproducible measurement mismatch:
all 164 runner packets matched the direct capture by direction and size, and
outgoing packets agreed within about 1.3 ms, but one incoming burst was
logged about 30 ms after wire arrival because the client timestamps at its
user-space socket drain. The prospective reconciliation now fits the 10 ms
clock bound on outgoing packets, checks incoming wire-before-drain causality,
and records incoming drain lag. It keeps exact packet inventory, the 10 ms
wrapper clock bound and the direct PCAP as the wire-timing source. All 76
focused fidelity tests passed; the preserved attempt replayed under the new
rule and a fresh local Walkie-Talkie run passed. This is engineering evidence,
not a defence certification or reason to promote earlier failed captures.
The full browser, foundation, fitting and certification gates still precede
defended or formal capture on the same frozen source.

A first zero-credit local vertical diagnostic completed current-client
response qualification (three waves of 40 requests) and accepted, sealed and
deep-verified one two-origin FRONT sample. Full prefix qualification failed at
its first Rust invocation: the single-connection qualifier rejected
resource 2 because it belongs to the second origin, although the Python
prefix spec required that resource in an activation stage. The retained raw
log says `runtime and frozen activation-stage resource 2 disagree or are not
same-origin`. This was a downstream multi-origin contract mismatch, not a
site stability result.

The prospective schema-4 prefix specification and receipt now state
`primary-origin-capacity-v1`. They preserve the complete frozen resource
graph and record the secondary-origin application resources as unproven by
this single-connection capacity proof. They project primary-origin activation
stages from the original graph and check the directional UDP policy. A fresh
zero-credit `local-vertical-2` run passed three 40-request response waves and
three scoped prefix waves, then accepted, sealed and deep-verified a two-origin
FRONT sample. The result was 1/1 accepted with a complete terminal receipt.
Its FRONT capture consumed the response-only qualification sidecar. A follow-up
zero-credit `local-wt-1` used the exact full sidecar from `local-vertical-2`
(SHA-256 `ae5b3d2ed8a1350a8a16f1d0e5dc9546a1d119f685950b1c1e78d180023aa2d6`),
its frozen schema-4 prefix spec, and a controlled Walkie-Talkie schema-6
parameter. It accepted 1/1 two-origin sample in one attempt and sealed a
complete result. The in-process diagnostic deep verifier passed; the
unpatched verifier correctly rejected unknown/dirty source provenance. Its
outgoing and incoming packet counts matched targets (10/10 and 195/195), with
zero reported L1 or batch-lifecycle errors. These diagnostics substituted
current-source/client image provenance and accepted dirty/unknown source only
inside diagnostic validators; preparation, UDP qualification and fitting were
synthetic. An adversarial review then found that the Rust client compared
literal HTTPS authorities where Python canonicalized hostname case and the
explicit default port 443. A shared Rust origin fix now covers response
selection, scoped prefix proof, HTTP/3 chaff and endpoint grouping. Its focused
unit tests and formatting check passed. The rebuilt client completed fresh
`local-vertical-3` response and scoped prefix qualification, then a directly
linked `local-wt-2` Walkie-Talkie capture: both results were complete with
1/1 accepted. The latter froze the exact new full sidecar (SHA-256
`43a9b7e826b74fd9ca4178353dc3104b41189b24a9ed4135962d82817924e5a5`).
Two current-binary local packet tests for multi-origin FRONT/Tamaraw and
Walkie-Talkie passed. A broader controlled capture test reached a complete,
deep-verified result, then failed its formal clean-source assertion because
this diagnostic records `lab_dirty` as unknown; that three-test invocation
therefore exited with two passes and one expected provenance failure.
The earlier registered Lab-source collection-image suite passed 2,112 tests
with 31 skips before this Rust-only fix; the new Rust binary was checked
separately. The later paired-root source passed 2,113 with 31 skips.
The downstream release gate stays open pending clean source-bound checks. The scoped prefix proof
does not qualify secondary-origin prefix capacity.

A separate zero-credit profile replay used two temporary ordinary Neqo HTTP/3
servers and the same rebuilt client. The client container had a read-only root,
`no-new-privileges`, and the production capture entrypoint's `setpriv`
transition to invoking UID/GID 1000:1000 with only `NET_RAW` and `NET_ADMIN`
remaining (`CapEff=0x3000`). Its new diagnostic roots and sealed files were
owned by UID/GID 1000:1000; `DAC_OVERRIDE` was absent. Response and scoped
prefix qualification both passed. The first FRONT capture then failed its
strict fidelity gate: one of 69 scheduled events expired, while the runner
completed, both endpoints were present, the direct PCAP reconciled with all
428 runner packets, and the UDP/offload checks passed. That failed attempt is
retained. After concurrent host regression load ended, a capture-only retry
copied and checked the exact qualified workload and sidecars into fresh roots.
FRONT accepted, sealed and deep-verified 1/1, followed by Walkie-Talkie
accepting, sealing and deep-verifying 1/1 from the exact full sidecar and scoped
prefix spec. Frozen sidecar, spec and controlled parameter hashes matched their
inputs. These checks demonstrate that this local UID, capability and writable
directory profile can carry both later wire paths. They do not exercise the
formal launcher, public-origin restriction, acquired workloads, real fitting,
or source-bound authority. The first timing miss shows that a local replay
cannot guarantee every future capture will pass.

## Source binding and later fitting

Formal receipts currently bind the exact Lab commit, Rust Gitlink, image,
inputs and authority lineage. Merely removing the Git comparison would allow
patched code to produce outputs under an older build identity; downstream
verification could no longer establish what executed. Development diagnostics
may run patched code against the old image, clearly labeled with zero credit.
A future component-scoped provenance design could avoid rebuilding for
unrelated source changes, but it must specify and verify the complete code and
configuration closure for each stage, record component digests in every
receipt, and update all producers, consumers and resume rules prospectively.
That redesign is not implemented by this rehearsal.

Formal acquisition may start under independently verified schema-2 authority
without the long browser gate. Before **any** fitting or defence capture, the
same source and build must pass the deferred 110-vector browser qualification
and full foundation. Pilot and authoritative fitting, class qualification,
certification and formal capture still run on genuine acquired workloads; their
synthetic consumer tests only expose wiring failures early. See the
[capture-readiness guide](CAPTURE-READINESS.md) for those evidence boundaries.
