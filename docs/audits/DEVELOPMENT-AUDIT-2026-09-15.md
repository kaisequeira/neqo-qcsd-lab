# Development and capture-readiness audit, 15–18 September 2026

> **Frozen historical appendix.** Every use of “current”, “active”, “next” or
> similar present-tense language in the source body describes its historical
> checkpoint, not the repository's present state. Use [PROJECT.md](../../PROJECT.md)
> and [CLASS-STUDY.md](../CLASS-STUDY.md) for the maintained contracts.

Source: `DEVELOPMENT-AUDIT-2026-09-15.md`; original SHA-256 `e6dff5be5294dfef41f58dd71ba3a32a6afef7814fe9aecfb2f9367ffbf56e14`; 101,440 bytes; 1,690 lines. The byte-identical
source is retained only in the external migration bundle. This tracked copy adds
stable source-line anchors, retargets links to tracked repository files, renders
ignored evidence locations as inline historical paths, and replaces any
machine-specific home or code-graph identity. No narrative, metric, receipt hash,
command, or status claim is intentionally abridged. See the
[source map](../HISTORY-SOURCE-MAP.md) for exact coverage.

---

<a id="source-development-audit-2026-09-15-md-l1"></a>
# QCSD development and capture-readiness audit

Audit date: 15 September 2026, Australia/Sydney (AEST, UTC+10).

<a id="source-development-audit-2026-09-15-md-l5"></a>
## Conclusion

The delay is not adequately explained by Internet connectivity or necessary
browser work. The implemented pipeline contains substantial orchestration
overhead, repeated test execution hidden inside verification, and prerequisite
coupling that delays acquisition unnecessarily. The acquisition schedule also
contains a conditional month-long projection which should have been presented
before treating the remaining work as an imminent capture launch.

Three independent read-only reviews covered architecture/scope, recurring
correctness failures, and operations/readiness. The primary agent reconciled
their findings against source, receipts and current process state. This is a
bounded critical-path audit, not a complete correctness proof of every defence
or an exhaustive accounting of the preceding ten days. No new test, build,
campaign, recovery operation or protocol change was executed during the audit.
This report is a private workspace document, not a Lab receipt or attestation.

The research endpoint is unchanged: the same frozen 100 classes and visit
schedule, independent fitting excluded from evaluation, 900 class-by-mode
certification captures including static, then 16,000 matched captures across
the eight comparison conditions. Preserve every selected workload's complete
resource/origin graph. Naturally single-origin classes remain permissible;
multi-origin resources must not be intentionally omitted. Defences remain
client-only. The authorised claim is still five validated defences plus two
candidates / nine selectable modes.

<a id="source-development-audit-2026-09-15-md-l31"></a>
## Interrupted run and current evidence

- Clean Lab head: `44142d2e14917e03b26ffa9f819d1768c716087a`.
- Clean Rust head and Lab gitlink:
  `46313bef90ad392b7ca293ab7cf28108d2f35c7f`.
- V88 build and pinned-CDP execution receipts exist. The fresh build took
  approximately 15 minutes 36 seconds.
- The user authorised termination of the browser-egress run after roughly
  3 hours 29 minutes. The launcher received SIGTERM and the session exited 143.
  Both launcher and guardian exited; Docker subsequently reported no running
  containers. This is an authorised interruption, not a demonstrated semantic
  failure of vector 80.
- The retained checkpoint (`artifacts/buflo-study/browser-egress-qualification-v88/experiment.json`)
  contains 79 passing terminal attempt rows, with next vector ordinal 80.
  All 79 raw result hashes match their checkpoint entries. This is a partial
  integrity check, not final independent deep qualification verification.
- Vector 80 has an intent and partial PCAP, but no terminal result. Its identity
  is `popup--page--button-formtarget`. The checkpoint still says `running`;
  that is retained resumable state, not evidence of a live process.
- The stop log (`.cache/build-v88.pGKfDMo5/browser-egress.log`)
  records three missing HANDOFF-candidate errors and one authenticated
  durable-root-removal failure. One HANDOFF remains in the reported lifecycle
  transaction `run.59da4cc55bb955065a8e5377724afefd`. It was not removed or
  recovered during this audit. Empty Docker process state is not proof of
  successful lifecycle retirement.
- The canonical pilot cohort, authoritative cohort, final selection and
  acquisition-completion files are absent. The 100-class set is still a target,
  not an acquired and frozen cohort.
- Final browser-egress qualification remains unproved; certification is 0/900
  and formal capture is 0/16,000. Passing prefixes are not final gate passes.
- The user now has a strong Internet connection. Hotel connectivity is not a
  current explanatory assumption.

No result, input, receipt, historical corpus or source file was edited. No
evidence was deleted, relabelled or promoted. This report is the only new file.

<a id="source-development-audit-2026-09-15-md-l67"></a>
## What the 110-check suite spent time doing

The following measurements come from the 79 completed v88 result chronologies
and checkpoint timestamps. The measured span runs from
`2026-09-15T06:39:46.186118035Z` to
`2026-09-15T10:04:16.778730641Z`; it excludes the unfinished vector and final
interruption/cleanup.

| Component | Measured time | Interpretation |
|---|---:|---|
| Browser/subject intervals | 5m 35.35s | Mean 4.245s per completed vector |
| Reporting grace | 6m 38.97s | About five seconds per vector |
| Observer start to subject start | 24m 21.75s | Setup within observation intervals |
| Grace completion to observer stop | 6m 01.32s | Observation shutdown |
| Whole attempt envelopes | 97m 21.56s | Includes the preceding chronology components and other attempt work |
| Between-attempt gaps | 107m 09.03s | 78 gaps; mean 82.423s |
| First start to last completed finish | **204m 30.59s** | Attempt envelopes plus inter-attempt gaps |

The rows are nested, not additive. Browser subject activity is 2.73% of the
total span. It is not correct to call every remaining second wasted: isolation,
capture, evidence checks and cleanup are necessary. However, this establishes
that public Internet speed is not the primary explanation for this gate.

The wrapper stamps an attempt's finish before prevalidation, teardown,
assembly/publication and next-vector admission. Therefore the gaps contain
real workflow work; they are not necessarily idle waits. The retained evidence
does not separately time each of those operations, so assigning the entire
107 minutes to one component would overclaim. See
[qcsd-lab](../../qcsd-lab), lines 11181–11267.

Historical v87 shows the same pattern: approximately 245m 09s for 99 attempts,
with 6m 46s of browser activity across its 98 passing subjects. This is
corroborating operational context, not a new qualification of v87.

<a id="source-development-audit-2026-09-15-md-l101"></a>
## Ranked findings

<a id="source-development-audit-2026-09-15-md-l103"></a>
### 1. Verification has test-execution side effects — must fix

Acquisition actions call `_validate_runner_runtime`, which reconstructs the
foundation with `deep_code_gate=True`. The code-gate validator responds by
executing the complete Lab pytest suite, followed by a BuFLO subset already
included in that suite. This is an actual subprocess invocation, not merely a
comparison of expected command names.

Relevant source:

- [class_acquisition.py](../../src/qcsd_lab/class_acquisition.py), lines
  1325, 3775 and 3894: acquisition runtime/foundation validation.
- [class_attestation.py](../../src/qcsd_lab/class_attestation.py), lines
  794 and 295: forwarding deep verification and reconstructing authority.
- [buflo_study.py](../../src/qcsd_lab/buflo_study.py), lines 9129,
  9316 and 9733: test commands, subprocess execution and implicit re-execution.
- [class_pipeline.py](../../src/qcsd_lab/class_pipeline.py), lines 1337,
  3565 and 3589: acquisition-aware status and duplicate capture preflight.

Acquisition-aware status forces this deep path even without an explicit deep
request. Capture preflight reconstructs the foundation twice; explicit deep
readiness paths reconstruct code authority at least three times. The audit has
not established full-suite execution for each individual captured sample.

The completed local full suite took about 56m 28s, before the duplicate subset.
That is substantially longer than the acquisition action's 30-minute soft /
34-minute hard allowance and status's 310-second cutoff. Prepare-image runtime
is unmeasured, so a particular future timeout is not proven; the compatibility
risk is nevertheless serious. Buffered subprocess output also hides progress.

Repair direction: separate explicit test execution from immutable evidence
verification. Execute the required gates for the exact source/build, retain
their outputs and inventories, and verify their provenance, hashes, commands
and results on ordinary admissions. Keep explicit independent re-execution at
designated gates. Do not merely set a bypass flag or accept incomplete receipts.

<a id="source-development-audit-2026-09-15-md-l139"></a>
### 2. Per-vector orchestration scales poorly — instrument and reduce

Every vector starts several coordinator operations as well as five isolated
roles and a fresh network. `next`, attempt admission and result append each
reconstruct prior evidence. Reconciliation replays the completed prefix and
separately validates receipt inventory; checkpoint loading performs another
replay. This creates quadratic prefix work as the gate grows. Normal replay is
shallow; it is not repeated full-PCAP decoding.

See [qcsd-lab](../../qcsd-lab), lines 9443, 10782, 10855, 11162,
11186 and 11267, and
[browser_egress_qualification.py](../../src/qcsd_lab/browser_egress_qualification.py),
lines 2929, 2995, 3031, 3563, 3667, 4043 and 4068.

V88 gaps rose from a mean 75.63s for the first ten transitions to 87.48s in the
last group. This is consistent with growing work, not a causal profiling proof.

Repair direction: add stage timing and lightweight progress output; consolidate
trusted coordinator work and use hash-bound incremental admission with explicit
invalidation. Preserve role isolation, create-only publication, crash recovery
and final independent deep verification. Do not launch another whole gate just
to discover whether a changed late vector works.

<a id="source-development-audit-2026-09-15-md-l162"></a>
### 3. The changed DNS boundary has not been tested live — close the gap first

The public browser gate accepts only create, resume and verify; it has no
selected-vector diagnostic. The coordinator takes the next vector strictly
from the checkpoint. V88 therefore spent hours replaying earlier checks and
stopped before reaching the enabled DNS control implicated in v87.

The DNS unit tests manufacture packet bytes for both forwarding legs. They
prove consistency of the validator under those inputs, not actual Docker
forwarding compatibility. See [qcsd-lab](../../qcsd-lab), lines 451–493;
[coordinator](../../tools/browser_egress_qualification.py), line 1221;
and [DNS packet tests](../../tests/test_browser_egress_dns_packets.py),
lines 64–94.

Minimum next evidence: a separately labelled, non-counting enabled/disabled DNS
pair in the pinned image using the production topology, actors, sinks and
decoder. Preserve its PCAP and socket-wire inventories. It must not reorder or
be promoted into the authoritative 110-vector gate.

The existing 13 Chromium integration tests also require an opt-in not supplied
by the ordinary wrapper routes. Pinned-CDP success is not evidence those tests
ran. Explicitly run their two existing modules in the fresh image with the
required environment and identity; another full local pytest run would still
skip them. See [CDP integration tests](../../tests/test_cdp_chromium_integration.py),
line 23, and [driver integration tests](../../tests/test_playwright_driver_chromium_integration.py),
line 52.

<a id="source-development-audit-2026-09-15-md-l189"></a>
### 4. Acquisition scheduling can take a month — prospective protocol decision

The scheduler reserves 40 minutes around each batch's baseline, +24h and +72h
starts. At most two candidates share a batch, and reservations cannot overlap
across batches. The checked-in idealised projection for 600 candidates forming
300 compatible pairs reaches the final baseline at 32.22 days and the final
+72h probe at 35.21 days.

This is conditional, not a universal lower bound: early rejection can shorten
the programme, while singleton batches and interruptions can extend it. It
nevertheless contradicts an expectation of finishing acquisition in hours.
See [acquisition_timing.py](../../src/qcsd_lab/acquisition_timing.py),
lines 17–144 and 168–193.

Stability observations protect comparability. The particular global reservation
policy is an implementation choice. After removing repeated test execution,
reconsider bounded acquisition scheduling using measured operation durations
while preserving the required observation windows, provenance and resource
limits. Do not introduce uncontrolled concurrency into formal traffic
measurements; their serialisation has a separate contamination rationale.

<a id="source-development-audit-2026-09-15-md-l210"></a>
### 5. All-600 completion and full-defence foundation block acquisition

The current completion rule requires terminal evidence for all 600 candidates.
Yet deterministic pilot selection uses only the first 24 eligible candidates
in each of five frozen-order strata: 120 candidates, from which final selection
chooses 100. See [class_acquisition.py](../../src/qcsd_lab/class_acquisition.py),
lines 2498–2512, and [class_study.py](../../src/qcsd_lab/class_study.py),
lines 415–441.

A prospective prefix-completion rule could stop a stratum once its first 24
eligible candidates are established and every earlier candidate is terminal.
Later candidates would be explicitly unassessed/not needed, never falsely
rejected. The catalogue, quotas, ordering and resource graphs would remain
unchanged. Selection is equivalent for fixed eligibility outcomes; differently
timed live observations are not guaranteed to produce identical eligibility.
Current schemas do not permit this shortcut. It requires explicit prospective
approval and versioned evidence semantics.

Acquisition also waits for the complete defence foundation: independent
reference, full code gates, 18 regression captures and 160 controlled captures,
all under a common source/build. See
[class_attestation.py](../../src/qcsd_lab/class_attestation.py), lines
783–831, and [class_acquisition.py](../../src/qcsd_lab/class_acquisition.py),
line 1210.

Browser/preparation correctness must precede acquisition. Complete defence
proof must precede defended research admission, but need not inherently precede
safe undefended workload acquisition. A prospective split into acquisition
authority and defence/capture authority could start the stability clock sooner.
It needs an immutable provenance bridge and dependency-aware invalidation:
changes to preparation, browser behaviour or acceptance still invalidate
affected acquisition. This is not permission to reuse unrelated old evidence.

<a id="source-development-audit-2026-09-15-md-l243"></a>
### 6. Shutdown and monitoring need a bounded repair

The interruption demonstrated lifecycle retirement errors. The exact cause is
unresolved: missing publication, duplicate retirement and identity mismatch
remain possibilities, not findings. Inspect the retained transaction before
recovery; do not equate absent running containers with successful retirement.
See [docker_signal_supervisor.sh](../../tools/docker_signal_supervisor.sh),
lines 6914–7034, and the retained stop log.

The current [agent rules](../../AGENTS.md) also prohibit all repository
inspection and parallel read-only review during any source-bound Docker job.
That policy delayed useful diagnosis behind this multi-hour preliminary gate.
Repeated PID polling established only liveness, not meaningful progress. This
was an operational judgement failure as well as an observability gap.

Review the policy prospectively: source mutations and competing measurements
must remain prohibited during evidentiary capture, but lightweight checkpoint
monitoring and isolated read-only review need not be treated as source changes.
Do not silently change current evidence semantics or perform resource-heavy
audits alongside timing-sensitive captures.

One additional suspected issue is the raw-default-profile control's five-second
dwell starting before asynchronous document readiness. It has not been shown to
cause v88's interruption or v87's known count failure. Record readiness and DNS
timing in the focused probe; defer speculative changes or blanket longer sleeps.

<a id="source-development-audit-2026-09-15-md-l269"></a>
## Actual remaining scale and ETA limits

The [current study contract](../../config/class-study/v1/study.json),
lines 571–624, plans the following after acquisition:

| Stage | Executions |
|---|---:|
| Pilot fitting | 480 |
| Pilot full qualification | 720 |
| Pilot compatibility | 1,080 |
| Authoritative fitting | 2,000 |
| Final full qualification | 600 |
| Final certification | 900 |
| Canaries | 1,000 |
| Formal comparison | 16,000 |

There are 5,780 planned executions before canaries/formal, including the 900
certification captures. These roles are not interchangeable and their costs
need not match. Their necessity and scale should be explicit; do not erase
fitting, qualification or compatibility merely to obtain a faster result.

There is no defensible absolute first-formal-capture ETA yet. Acquisition is
not complete, the frozen classes do not exist, fitting has not been demonstrated
for them, and scheduling/repeated verification require resolution.

For scale only, 900 accepted captures at eventual measured means of 30/60/120
seconds take 7.5/15/30 hours. The 16,000 formal captures take 5.56/11.11/22.22
days at those rates, excluding retries, canaries, preflight, sealing and
verification. These are arithmetic scenarios, not forecasts. Do not extrapolate
the browser gate's topology cost or the 180-second safety cap to every sample.

<a id="source-development-audit-2026-09-15-md-l300"></a>
## Recommended bounded next step

1. Resolve the retained shutdown state and add a targeted interruption check.
   Keep all current partial evidence.
2. Separate gate execution from receipt verification; prevent ordinary status,
   acquisition admission and capture preflight from spawning the full suite.
   Validate the new boundary with focused tests and explicit gate execution,
   not bypass flags.
3. Add only the diagnostic capability needed to exercise the changed DNS pair
   and the existing Chromium integration tests. Add measured stage progress to
   long operations. Use that evidence before another full qualification run.
4. Obtain approval for a prospective acquisition amendment covering authority
   separation, scheduling and deterministic prefix completion. Preserve the
   final scientific gates and endpoint; do not rewrite v1 receipts.
5. Freeze the resulting source/inputs, qualify the affected boundaries once,
   and start real class acquisition under its approved authority. Complete
   defence validation and independent fitting before certification/formal
   admission. Report progress from accepted workload and capture evidence.

Defer broad framework rewrites, successor-system expansion, classifier runs,
paper-comparison work and final export/attestation until their inputs exist.
Do not turn this audit into another open-ended prerequisite programme.

<a id="source-development-audit-2026-09-15-md-l323"></a>
## Evidence hashes recorded during this audit

These hashes support reproducibility of this report; they are not an attestation.

| Evidence | SHA-256 |
|---|---|
| v88 build execution | `d285fd7183b1cca493259637e5c9485149d3cf05ab69d00d8b6426338ae5764b` |
| v88 build completion | `da31ed70d65c6614ac323e7d81e4b6582c9d4ba8f54bcffce33bc54304bd510a` |
| v88 pinned-CDP execution | `901c288c2e6097ae93f3f42d46fb3e27c9c05862385d0c663968bcb528747805` |
| v88 stopped checkpoint | `599f977365d4b7e8a4ac706fa13f8c46d838a4e5d01f70ab4f2c6d4a3ba2f34d` |
| v88 stop log | `04c2902df693e5db7523ada1e5f1cb422e1d3fb98303c6e0113dc1f73ada8dd4` |
| vector-80 intent | `234e902bf7173e27e78a8bcdd3625372953c0be1671824f4637114863faf4c81` |
| vector-80 partial PCAP | `9c41c315bb2247e39fa75cd6432cb8e736eee7873be33980050f6db6b07d64be` |
| retained lifecycle HANDOFF | `2e940578cca09cc566835272aabb8ce1248b872c9b94661601187d5672c3ee85` |

Raw receipt hashes for all 79 terminal rows were checked against the checkpoint.
No final browser-egress receipt was created. Lab and Rust were clean before and
after the audit; the root-level report is outside the Lab repository.

<a id="source-development-audit-2026-09-15-md-l342"></a>
## Post-audit repair checkpoint — 15 September 2026

A subsequent bounded source repair addresses a confirmed interruption window
in `browser_egress_cleanup_topology`: normal cleanup could receive TERM after
retiring an object but before compacting the global tracking arrays. EXIT
cleanup would then retry already-retired identities. The function now latches
terminal signals throughout retirement and array compaction, restores its
previous latch state, and honours pending termination before result publication.
Strict HANDOFF validation and the existing EXIT handler are unchanged.

The launcher and two related test files are modified, uncommitted, against the
Lab head recorded above; Rust remains unchanged. Focused tests cover normal
return, failed-identity retention, prior latch restoration, TERM after retirement,
and native retirement boundaries H3/H13 using fake Docker. An independent rerun
passed 12 tests (292 deselected) in 6.82 seconds. Shell syntax and
`git diff --check` also passed. No real Docker run or full suite was launched.

This verifies the bounded source fix, not a live shutdown or the exact historical
ordering of every v88 warning. The original retained lifecycle state and all
v88 evidence remain untouched; supported retirement recovery is still pending.
Acquisition scheduling, prerequisite ordering and deterministic completion have
not been amended and still require the user's prospective approval. No new
scientific gate pass or capture count follows from this repair.

<a id="source-development-audit-2026-09-15-md-l366"></a>
### Separate execution from code-gate verification

A second bounded repair removes the implicit Lab-suite rerun from
`validate_code_gate_receipt`. Its existing schema, source/build, Rust-log,
ordered-command, stdout-byte/hash, regression and baseline checks remain
unchanged. The `deep` keyword remains compatible; both values verify recorded
execution evidence, not a fresh test execution in the ambient environment.
`create_code_gate_receipt` still executes both required command sequences and
cannot produce a passing receipt when execution fails. No prerequisite,
candidate-selection rule, acquisition schedule or evidence schema was changed.

The independent review and focused regression tests cover current and historical
verification without test execution, explicit execution/failure, prepare-runtime
acquisition authority, and thirteen command/evidence mutations under both deep
flags. The combined rerun passed **39 tests**, with 404 deselected, in 7.85 seconds.
`git diff --check` passed. Ruff could not run because it is not installed locally.
These are deterministic engineering tests, not new live qualification evidence.

The additional uncommitted changes are in `src/qcsd_lab/buflo_study.py`, its two
related test modules, and four operational-explanation lines in the Lab README.
No full suite, build or capture was launched. Fresh source-bound validation is
still required; v88 must not be resumed under the modified source. The pending
acquisition-protocol amendment still needs the user's approval.

<a id="source-development-audit-2026-09-15-md-l390"></a>
### Previously skipped Chromium integration tests executed

At 20:31 AEST, the existing `test_cdp_chromium_integration.py` and
`test_playwright_driver_chromium_integration.py` modules ran explicitly against
the pinned v88 prepare image
`sha256:b0455e6b1921324874239137bd624d69a5f996778ae99b894660d7b63c32f328`.
They used a temporary clean Lab checkout at `44142d2e14917e03b26ffa9f819d1768c716087a`
and clean Rust checkout/gitlink at `46313bef90ad392b7ca293ab7cf28108d2f35c7f`.
The installed image wheel supplied production imports; the read-only checkout
supplied the tests, fixture files and the actor loaded with `runpy`.

Execution used non-root UID/GID 1000, `--network none`, dropped capabilities,
no-new-privileges, a read-only container, temporary storage, the explicit
`QCSD_RUN_PINNED_CDP_PROBE=1` opt-in and a 300-second timeout. All **13 tests
passed in 33.87 seconds**, with no skips, errors or failures. The
JUnit output (`.cache/chromium-integration-v88.dy2RGq/output/junit.xml`)
has SHA-256 `a941566ca2ddd97b9cfc16e513624c22c66dc271a63a925b9c3eb66e46bdefe9`.
The container exited successfully and was automatically removed. The clean
71 MiB temporary source copy was also removed; it is reproducible from the
recorded commits. The output remains, occupying approximately 12 KiB with its
parent directories.

This closes the omitted live-Chromium integration-test gap for that exact v88
image/source. It does not validate the modified harness, the packet-observed
DNS control, the full 110-vector gate, class acquisition, or any scientific
capture. No qualification receipt was created or passing prefix promoted.
The protocol amendment remains unapplied and pending approval.

<a id="source-development-audit-2026-09-15-md-l418"></a>
### Selected DNS-prefetch control pair verified — 20:47 AEST

A non-counting diagnostic exercised the production `actor`, `fixture`,
`forbidden-sink`, `dns-sink` and `observer` roles for the enabled and disabled
DNS-prefetch controls. It used the same pinned v88 prepare image and exact clean
Lab/Rust commits recorded above, with a fresh internal-only Docker network for
each condition. It did not restart the interrupted qualification or publish a
replacement qualification result. Source-receipt and terminal-summary file
timestamps span approximately 47.4 seconds; this is an operational estimate,
not an attested performance measurement.

Both conditions returned zero from all five roles, with no preservation or
cleanup errors. The enabled condition produced three DNS exchanges, each with
all four packet legs and matching socket query/response evidence; the disabled
condition produced none. Both acquired the expected fixture page once. Capture
reported zero dropped packets: 115 packets enabled and 71 disabled.

A separate read-only execution in the pinned image independently decoded the
retained captures and applied the production semantic, fixture, capture-closure,
chronology, DNS packet/socket reconciliation and selected launch/driver checks.
It exited zero. The diagnostic summary (`.cache/dns-control-diagnostic-v88.ovqV7a/output/analysis.json`)
explicitly sets `authoritative=false` and `counting=false`; it does not verify
the foundation, complete runtime/topology attestation, full 110-vector
qualification, or scientific capture acceptance.

| Retained diagnostic evidence | SHA-256 |
|---|---|
| Independent analysis summary | `5254dce49295f82e36e940694abc961f14863a06e9a22f676a06ad5b1c812c8b` |
| Enabled PCAPNG | `97b1ac0490181114058b07a8b09a4d27e329b8471b2a96a4464102218a6e5aaa` |
| Disabled PCAPNG | `17291d6096bd5732a38783902942e24611b801a6546a12535f592b4cd8ec3f24` |
| Diagnostic orchestrator | `9c0270dedac8a1441db93ea8c1ce695fa97114fdb4ef56095664d5b9c7bbf799` |
| Diagnostic analyser | `d0764348876d2f60b9e39ced6d362b6208bf59c740273099eab327d2bb80e380` |

All diagnostic containers, networks and the policy volume were removed after
preservation. The verified-clean, reproducible 71 MiB temporary source copy was
removed; scripts and approximately 432 KiB of outputs remain. The original v88
checkpoint and stop-log hashes are unchanged. No tracked implementation,
configuration, schema, campaign or immutable evidence was modified by this
diagnostic. The retained original lifecycle transaction remains unresolved.

This verifies the repaired DNS control on the pinned v88 image and removes the
need to run another complete 110-vector sequence merely to investigate that
specific failure. It does not establish a full qualification pass or validate
the subsequent uncommitted harness repairs. Acquisition amendments still await
explicit approval; acquisition, fitting, 900-capture certification and the
16,000-capture endpoint remain outstanding.

<a id="source-development-audit-2026-09-15-md-l465"></a>
### Retained lifecycle transaction recovered — 20:50 AEST

The remaining active directory and retirement authority were independently
inspected before recovery. Their exact Docker container, supervisor-label
inventory and systemd scope were absent. The authority's launcher binding
matched the recorded checkout; only the subsequent eleven-line shutdown fix
made the current launcher differ. Guardian, helper and native source identities
and hashes remained unchanged. This explains why recovery under the modified
launcher would fail authentication; it does not establish the original
interruption's precise failure ordering.

Copies of the original HANDOFF, retirement authority and modified launcher were
preserved in `neqo-qcsd-lab/.cache/lifecycle-recovery-v88.FFUwgxrT/`. The shutdown
fix was temporarily removed with an exact patch; the original launcher's full
device/inode/ownership/mode/link-count/size identity and SHA-256 were verified
against the authority. Only the supported `./qcsd-lab lifecycle-recover` command
was then executed. It exited zero with lifecycle reconciliation completed.
The retained directory and retirement authority were removed by authenticated
recovery; no manual bookkeeping deletion or authority edit was used.

After confirming that recovery and its guardian had exited, the shutdown fix
was restored. `cmp` against the preserved modified launcher passed, as did
shell syntax and `git diff --check`. The modified launcher again hashes to
`269a97e9be41bec43fc14fd045b1780278b1ff5e0123a06fdbd562a2c38999c9`.
The lifecycle namespace is empty and Docker reports no running containers.
The original qualification checkpoint and stop-log hashes remain unchanged.

| Preserved recovery evidence | SHA-256 |
|---|---|
| Original HANDOFF copy | `2e940578cca09cc566835272aabb8ce1248b872c9b94661601187d5672c3ee85` |
| Original retirement authority copy | `bd28fd9e444db0927a455819eba8a47e14edbacb6114037f176bd8211e1cb61b` |
| Supported recovery command log | `2cd393d113250d5ce8448e885a61cd0347d22a7039b28925b3b2dc567edaadc6` |

This closes the retained shutdown-bookkeeping issue. It does not validate the
new shutdown fix under a live interrupted campaign, permit v88 resume, or
advance any scientific capture count. No acquisition protocol amendment has
been applied; explicit approval is still outstanding.

<a id="source-development-audit-2026-09-15-md-l503"></a>
### Approved prospective amendment — 22:00 AEST continuation

The user subsequently authorised implementation of the recommendations and
client-only repairs needed to achieve the thesis endpoint. The earlier
approval-pending statements above describe their historical checkpoint only.

The amendment now separates acquisition-only authority (clean pinned build,
pinned CDP, all 110 browser-egress vectors and an explicit acquisition-focused
correctness gate) from the full defence foundation. The latter remains
mandatory for every class-study capture role, including fitting. A later
foundation must join to the same source, build, study contract, pinned CDP and
browser-egress evidence. Verification reads sealed test evidence; only the
explicit creator executes the tests.

The frozen 600-candidate catalogue and ordering are unchanged. Schema-6
acquisition admits the first 24 non-rejected candidates per stratum, resolves
every predecessor of the 24th scientifically eligible candidate, and seals
that prefix in schema-3 completion. The remaining tail is explicitly
unassessed, not rejected. Infrastructure exhaustion and missed windows block
completion and cannot selectively remove classes. Already-started work must
drain or recover before completion. Cohort assembly independently reconciles
the terminal inventory and exact 120-class pilot.

Prospective scheduling schema 3 releases obsolete reservations only after
every member of a batch is scientifically terminal and the full 40-minute
guard has elapsed. Hard deadlines, the two-candidate/five-live-page caps and
the actual 30-second/24-hour/72-hour windows remain unchanged. The ideal
all-survivor 120-candidate schedule is 7 days 14 hours 50 minutes; actual
execution and rejection/replacement work may extend it. This does not make
the old all-600-survivor schedule short or guarantee a completion date.

Implementation covers the CLI, launcher, stdlib host admission and watcher,
runtime acquisition, completion/cohort bridge and the checked-in prospective
contract. Independent review caught and corrected a receipt interpreter-alias
mismatch and a host/CLI authority-flag mismatch before image execution.
Focused component suites passed, followed by a 346-test campaign/fitting/
handoff/successor/pipeline/cohort compatibility run (132.31 seconds). The
combined acquisition/authority/watcher/launcher regression is in progress at
this checkpoint. These are local engineering checks, not scientific gates.

The amended source has not yet been committed or built. No historical
receipt, corpus, capture or result was edited; no scientific count advanced.
The next operation after final review and source freeze is a newly allocated
cohort, not v88 resume. Docker is reachable with 12 CPUs and approximately
16.5 GB RAM; its backing-volume storage must still pass the build's own
preflight. The Ubuntu filesystem reports approximately 864 GiB available,
which is not interchangeable with Windows Docker-VHD backing-volume space.

<a id="source-development-audit-2026-09-15-md-l551"></a>
### Local validation and source freeze — 22:18 AEST

The amendment is now committed locally as Lab
`2c72618132374147ec45ae76e7154a3fef235aed`; the clean Rust checkout and Gitlink
remain `46313bef90ad392b7ca293ab7cf28108d2f35c7f`. Both worktrees are clean.
No commit was pushed, and no historical result, receipt, handoff or capture
was changed. The v88 checkpoint and stop-log hashes still match those recorded
above. Docker has no running containers at this checkpoint.

The combined acquisition/authority/watcher/launcher regression passed
**1,248 tests in 695.53 seconds**. Independent review then found that the host
watcher checked the internal consistency of a reported prefix but did not
bind all its terminal/eligible IDs to the actual checkpoint. Runtime completion
already deeply validated the evidence, so this was an operational false-progress
gap, not a demonstrated scientific-publication bypass. The watcher now
authenticates terminal paths, hashes, provenance, batch identity and normalised
state; reconstructs the same scientific/blocked projection as the runner; and
rejects completion that hides started nonterminal work.

The final watcher module passed **318 tests in 53.84 seconds**, including
24 new join, runtime-projection parity and receipt-drift cases. Its first run
exposed malformed timestamps in synthetic fixtures; those fixtures were
corrected rather than relaxing the production validator. A final affected
selection/timing/authority/cohort/pipeline/study/wrapper set passed
**365 tests in 17.19 seconds**. These runs overlap earlier focused suites and
must not be added into a claimed unique test count. Independent review found
no remaining concrete issue in the bounded receipt/pipeline checks.

Shell syntax, staged and unstaged diff checks passed. All ten relative links
in the Lab README and AGENTS resolve to tracked files, with no private
workspace-ledger or home-directory references. The README now correctly places
canaries after readiness and historical-pre, removes the watcher-private direct
status example, and distinguishes campaign `experiment.json` from acquisition
`checkpoint.json`/`provenance.json`.

No new pinned-image gate or scientific sample has passed yet. The next operation
is the allocator-controlled fresh build (expected next version v89), followed
by pinned CDP, all 110 browser-egress vectors and acquisition-only authority.
The saved goal remains `blocked`; the available goal tools cannot resume it.
The user has been asked to use the interface's Resume control. This is a
product-control limitation, not an outstanding implementation approval.

<a id="source-development-audit-2026-09-15-md-l593"></a>
### Fresh v89 build completed and reverified — 22:35 AEST

The allocator-controlled `./qcsd-lab build --cohort-version 89` completed with
exit code zero. Its build execution spans 22:19:27–22:34:25 AEST
(897.83 seconds); create-only completion was published at 22:34:30 AEST.
All three images used pull/no-cache execution, with only the declared BuildKit
dependency-cache mounts permitted. Embedded Rust tests and Clippy passed.
The existing host build-evidence validator independently accepted the schema-5
execution and schema-1 completion pair after the process exited.

| v89 evidence | Whole-file SHA-256 |
|---|---|
| Build execution (`artifacts/buflo-study/build-execution-v89.json`) | `ee0a07c0fdf20176c68105aa68141343db09bec5dfc2819290c094a69e1dbb10` |
| Build completion (`artifacts/buflo-study/build-completion-v89.json`) | `cbf4c79e9254b657ab340b279a4d03346f39af915f0ed6c825a4330d6bdf5e97` |
| Permanent cohort claim (`artifacts/buflo-study/cohort-claims-v1/claim-v89.json`) | `3d81d713cee10095c2559cee30f7b7cc4a0a6e7cda5ab3e79d7dae7e5ba94434` |
| Build log (`.cache/build-v89.MpQJvpu1/build.log`) | `13e2610a9015b29f6e60b08b0de220553cd06458a9db7a56db3c4e957149e4c6` |

The execution and completion payload SHA-256 values are respectively
`61975f9ef263263b6a4f7e38a400481ff17c3f29f1a3625754b83acfb110ea6f` and
`18b795f4479192acc6c2338859c068098f289b9fd9566674572a578936d46bda`.
The pinned collection, preparation and reference image identities are:

- `sha256:d64df7bf27e335af94466e97a3806e9a5ccd175770df81b535506d8c9b2dd05a`
- `sha256:7e5a79b13fe70f16af3334a65adcf2a0e9f7b71c42ed983d7042532ab1d17904`
- `sha256:52faac310cc9360cec010f248966b0387df8678f375a54e930520fe3bc90299c`

The minimum observed Docker backing-volume space was 218,734,575,616 bytes,
above the 68,719,476,736-byte requirement. Both source worktrees remained clean
at the recorded commits, and no Docker containers remained running. This
proves the fresh build only: v89 pinned-CDP, 110-vector browser qualification,
acquisition-only authority, public acquisition and all class-study captures
remain outstanding. The saved goal was rechecked and still reports `blocked`;
resumption requires the user's interface control, not a new protocol approval.

<a id="source-development-audit-2026-09-15-md-l627"></a>
### Goal resumed; v89 pinned CDP passed — 22:39 AEST

The saved goal is now active. The preceding turn made concrete progress through
the committed amendment and reverified fresh build; there is no remaining
goal-control or approval blocker. The full 100-class/900-certification/16,000-
formal endpoint is unchanged.

The public pinned-CDP command exited zero on v89 and published its schema-13
receipt at 22:38:34 AEST. The creator validated the complete probe against the
current build, prepare image and source before and after publication. Its
receipt (`artifacts/buflo-study/pinned-cdp-execution-v89.json`)
whole-file SHA-256 is
`4fe0fd63eb910c9cc3106d474c82cb3178ecff35211c1db7117aaef7a2bb956e`;
the execution log (`.cache/pinned-cdp-v89.aFsmd2HT/pinned-cdp.log`)
hash is `84025a4c63eb9f6911e014377a4e56a5abacc7bc851fbc0e10bb87ade997b4e9`.
Both worktrees remain clean and the command left no running Docker containers.

The next public command is `test browser-egress create` with cohort 89, its
exact build receipt and canonical `browser-egress-qualification-v89` root.
The preserved v88 prefix's observed cadence suggests about five hours for all
110 vectors, plus final verification or retries. This estimate is not a
completion guarantee. The launcher captures intermediate per-vector output
internally; process polling cannot supply a live accepted-vector count.
No passing prefix counts as a completed browser qualification.

<a id="source-development-audit-2026-09-15-md-l652"></a>
### V89 browser-egress qualification independently verified — 16 September 2026 AEST

The fresh v89 browser-egress create command and the subsequent independent
public `test browser-egress verify` command both terminated with exit code
zero. The checkpoint is complete: **110/110 vectors passed, every vector on
attempt 1, with 110 passing attempts and zero failures**. This is a completed
qualification milestone, not merely a preserved passing prefix.

The create run spanned `2026-09-15T12:40:32.716547769Z` to
`2026-09-15T17:41:23.921375644Z` (5 hours 00 minutes 51 seconds; 22:40:32 AEST
on 15 September to 03:41:23 AEST on 16 September). The final receipt was
recorded at `2026-09-15T17:43:02.267959Z`, or 03:43:02 AEST on 16 September.

| V89 evidence | Whole-file SHA-256 |
|---|---|
| Final qualification receipt (`artifacts/buflo-study/browser-egress-qualification-v89/final.json`) | `8f6eaac21685af0df166f5f8a09686ba45daa7d2226d1d81ecae334afcc7de9e` |
| Complete checkpoint (`artifacts/buflo-study/browser-egress-qualification-v89/experiment.json`) | `c6a2b1142b1f040f440bf2468fa6ba2b2a313b8fac25eed376fa006e0c748055` |
| Create log (`.cache/browser-egress-v89.9MhlXWte/browser-egress.log`) | `b6d2a1a1c20a2ecc8df4b8ab8142f6a6a04e143a57fa803ab361afb9fd803e14` |
| Independent verify log (`.cache/browser-egress-verify-v89.n20AedmH/browser-egress-verify.log`) | `b6d2a1a1c20a2ecc8df4b8ab8142f6a6a04e143a57fa803ab361afb9fd803e14` |

The final receipt payload SHA-256 is
`565fa8e08286b472a17a1efec94cc30fb981481ed11af3c1621a9cc8061ecad4`.
The source remains clean at Lab
`2c72618132374147ec45ae76e7154a3fef235aed` and Rust/Gitlink
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. No historical evidence was changed.

This qualification applies to the exact source, images, Chromium arguments,
environment and controlled fixtures that were verified. It is not a guarantee
of packet behaviour for every subsequent public-page run and does not validate
any defence. The authorised defence claim remains five validated defences
plus two candidates / nine selectable modes.

Current progress is browser qualification **110/110**, pilot **0/120**, final
classes **0/100**, certification **0/900**, and formal capture **0/16,000**.
The goal tool explicitly reports the goal active. Acquisition-only authority
is the next operation and has not yet been launched; public acquisition and
all defended class-study gates remain outstanding.

<a id="source-development-audit-2026-09-15-md-l690"></a>
### V89 acquisition-authority admission failed; receipt-consumer repairs underway — 03:53 AEST, 16 September 2026

The public v89 acquisition-authority command terminated with exit code 1
before Docker launch. Its exact admission error was
`class-study build admission failed: browser-egress qualification has no current build authority`.
The preserved authority launch log (`.cache/acquisition-authority-v89.9hPSBWs7/acquisition-authority.log`)
has SHA-256
`182cfdc505772ec46c967e97126549b6bcc11b07ebaa54496dd466083a2afb30`.
No acquisition authority was established by this failed invocation.

The bounded downstream audit identified two deterministic receipt-consumer
defects: host browser admission expected browser-foundation schema 4 although
the current producer emits schema 5, and class attestation's exact browser
build-binding field set omitted the producer's `size_bytes`. The latter would
have blocked acquisition authority, full foundation and readiness after the
host check was repaired. Both source defects have been corrected: current
browser-foundation schema 5 remains mandatory, and the build binding retains
a strictly typed positive size matching the actual execution-receipt bytes.
The repairs do not admit historical evidence as current authority or weaken
the defended-capture foundation requirement.

Validation is still in progress at this checkpoint. The focused local
attestation/acquisition tests passed **99 tests in 2.61 seconds**, and the host
tests passed **80 tests in 1.89 seconds**. The broader 21-file
acquisition/admission run is still running and has already reported some
failures; it is **not passed**. The full 110-vector synthetic-chain test and
producer-to-consumer bridge regressions are also still being validated; no
success is claimed for those unfinished checks.

These source changes require a fresh allocator-selected cohort, expected to
be v90; v89 evidence cannot authorize the modified source. The preserved v89
**110/110** browser result remains valid for its original exact Lab source
`2c72618132374147ec45ae76e7154a3fef235aed`, not for the current modified source.
Fresh browser qualification for that modified source is therefore **0/110**.
Pilot remains **0/120**, final classes **0/100**, certification **0/900**, and
formal capture **0/16,000**. The goal remains active. Acquisition authority,
public acquisition and defended class-study gates remain outstanding.

<a id="source-development-audit-2026-09-15-md-l728"></a>
### Receipt-consumer validation complete; clean source frozen — 04:12:55 AEST, 16 September 2026

The repaired Lab source is frozen and clean at
`dc0cc4803e76157a054446d9fdf1c30f3384bf8b`. The commit is
`Align browser qualification consumers with produced receipts` (9 files,
283 insertions and 40 deletions). The Rust checkout and Gitlink remain
unchanged at `46313bef90ad392b7ca293ab7cf28108d2f35c7f`.

The final 21-file focused acquisition/admission suite passed **1,221 tests in
185.92 seconds**. Its validation log (`.cache/acquisition-consumer-fix.qKsNdZ5z/local-tests.log`)
has SHA-256
`3782a78d3fc538ce298c479112ead091273045423eba6a49f4e518a5ec2a585c`.
The affected CLI checks passed **92 tests in 1.96 seconds**, and the
attestation checks passed **111 tests in 2.22 seconds**. These runs overlap
the broader suite and must not be summed into a unique-test count.

The full synthetic 110-vector chain, through final receipt construction,
portable deep replay and the producer-to-attestation bridge, completed with
**1 passed, 223 deselected in 972.30 seconds**. Its original agent session
`57942` terminated with exit code zero. No test process remains live at this
checkpoint. This is a passing synthetic integration test, not a fresh live
browser qualification for the repaired source.

The first broader run had **31 failed and 1,178 passed**. Those failures all
came from the shared `test_class_acquisition.py` fixture omitting the producer's
build-size field; the fixture was corrected before the successful final run.
No acceptance rule was weakened to obtain the passing result. Historical
replay now retains and compares completion fields whenever the deep-verified
producer binding carries them; fresh authority still forbids historical
browser foundations. Independent bounded review found no blocking issue in
the production changes or associated regressions.

V89's preserved live **110/110** browser qualification remains evidence only
for its original source. At the newly frozen head, fresh browser qualification
is **0/110**, pilot **0/120**, final classes **0/100**, certification **0/900**,
and formal capture **0/16,000**. The next planned operation is the
allocator-controlled fresh build, expected to claim cohort v90; neither that
claim nor the build has been launched at this checkpoint. The goal remains
active.

<a id="source-development-audit-2026-09-15-md-l768"></a>
### Fresh v90 build and pinned CDP completed — 04:30 AEST, 16 September 2026

The allocator-controlled v90 build and subsequent public pinned-CDP command
both terminated with exit code zero. The main agent independently accepted
the build execution/completion pair with the host build-evidence validator;
this audit independently read the receipts and recomputed all six receipt/log
hashes below. The immutable cohort claim binds v90 to the frozen Lab source
`dc0cc4803e76157a054446d9fdf1c30f3384bf8b` and unchanged Rust/Gitlink
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. The coordinating agent reverified
both clean checkouts and the exact Gitlink before the next launch.

The schema-5 build execution began at `2026-09-15T18:13:55.383921Z` and
finished at `2026-09-15T18:28:42.255843Z` (04:13:55–04:28:42 AEST on
16 September; 886.871922203 seconds). Its schema-1 create-only completion
was recorded at `2026-09-15T18:28:47.612337Z`, or 04:28:47 AEST.
The pinned-CDP receipt records `pass` at `2026-09-15T18:29:59.720228Z`
(04:29:59 AEST), using probe schema 13 and nested probe-contract schema 12.

| V90 evidence | Whole-file SHA-256 |
|---|---|
| Build execution (`artifacts/buflo-study/build-execution-v90.json`) | `8bfc44f97e5c1450d3250ea343e80a3295a05f6dc593e0fb40625902df8cb443` |
| Build completion (`artifacts/buflo-study/build-completion-v90.json`) | `66f54327ed87e3f1e07d09328026f41e79e4ea53016bfa6fa2906d2b4906fbfe` |
| Permanent cohort claim (`artifacts/buflo-study/cohort-claims-v1/claim-v90.json`) | `72ed1aec00caba397d736bb61c0af5365b95e3bbee6e52eb4f00b1967e53b7fb` |
| Build log (`.cache/build-v90.jFwpZjEl/build.log`) | `33d5124a10104376880ac518e59f964f7d0fc75fdb059b28987c8b03cc819179` |
| Pinned-CDP receipt (`artifacts/buflo-study/pinned-cdp-execution-v90.json`) | `16d15d9359d3898247ebd0a959e98b391ca218aabc71f52138a96ceb53fe09c6` |
| Pinned-CDP log (`.cache/pinned-cdp-v90.CeFGfucR/pinned-cdp.log`) | `5ed594db9ff5d5f63d2b56564b5fef56965a2ba66b145adcd77bb9129c47f717` |

The build, completion and pinned-CDP payload SHA-256 values are respectively
`cd841540a9966344daa29197216e12ed855e8ec5e23db108043f7282714efa7c`,
`9e69a96628ff09b04c0f985d39d2164d73f8632e89b702773f537749a5835d6a`, and
`3d3427cde7c7670c69db7938347b1894de894928d0dfdd0d956e7182160ab2df`.
The build receipt pins these image identities:

- Collection: `sha256:2992fb0f14d8cfde6c694fdf486ba6aff7648332eada04ca3aa25c0bb3a70f9f`
- Preparation: `sha256:4fedd7f8b841385bd01b3537431753de315965208cbbd219b21608a5853326db`
- Reference: `sha256:9745a029dbc6302579f885bf8535003c2bc8f6929cb02fc7ccbb43d4081bad60`

The after-reference backing-storage check passed with 202,421,260,288 bytes
available, above the 64 GiB minimum (68,719,476,736 bytes). Pinned CDP binds
the exact preparation image above; it does not substitute for the live
110-vector packet-level browser qualification.

The next operation is the fresh v90 live browser-egress gate, not yet launched
at this checkpoint. Fresh browser qualification remains **0/110**, pilot
**0/120**, final classes **0/100**, certification **0/900**, and formal capture
**0/16,000**. V89's old-source browser pass is preserved and has not been
reused as current authority. The goal remains active.

<a id="source-development-audit-2026-09-15-md-l816"></a>
### V90 interruption recovery audit — 17:53 AEST, 16 September 2026

The original browser qualification launched around 04:32 AEST. Its host
session remained live through the 05:28:27 AEST poll; the next observation
was interrupted. On continuation at 17:52 AEST, that session handle was
missing, no matching host process existed and Docker reported no running
containers. The five retained vector-22 role containers had exited between
05:28:30 and 05:28:46 AEST. This proves the run stopped, not why the wider
interruption occurred; no reboot or network cause is inferred.

The saved checkpoint still says `running`, but records only 21 passing
attempts, each on its first attempt, and `next_vector_ordinal=22`. The last
completed attempt finished at 05:26:21 AEST. The outstanding intent is
`constructor--cross-origin-frame--websocket-stream`, started at 05:27:45 AEST;
its retained evidence directory contains a 26,984-byte `capture.pcapng` and
no result receipt. The original browser log is empty. There is no final
qualification receipt or closed final inventory, so this prefix does not
authorise acquisition or advance the completed scientific gate.

Independent read-only inspection confirmed the source binding, prefix and
whole-file hashes. Before supported recovery, the checkpoint SHA-256 was
`2bce7ab78bb728d3de97a1995e13d353768c827af4f6849f0d921148ccf1b430`;
the foundation hash was
`4dc537dbcd27f7c34c0cbcdee6fcf7718f4fe5916ea8b51898a05006e7df410c`;
result 21 was
`526c512db86fd32d2ecee84040f5857b2390cb45f4b434dd34c25fc4bb75e897`;
and intent 22 was
`01e9d20ca8629db8a61f41512ab4339816bd359a83461be1d2044743422c2997`.
These describe the pre-resume state, not the eventual recovered checkpoint.

Both repositories are still clean at Lab
`dc0cc4803e76157a054446d9fdf1c30f3384bf8b` and Rust/Gitlink
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. Build, completion and pinned-CDP
whole-file hashes still match the 04:30 checkpoint above; the host build
receipt validator again succeeded. The next action is the public v90
`test browser-egress resume` command with the original build/result paths.
Its admitted recovery retains interrupted attempt evidence, seals an
operational interruption and retries within the existing attempt policy.
It does not rebuild, change source, erase the attempt or promote the prefix.
The goal was confirmed active at 17:53 AEST. Public scientific counters remain
pilot 0/120, final classes 0/100, certification 0/900 and formal capture 0/16,000.

<a id="source-development-audit-2026-09-15-md-l858"></a>
### Cross-boot retirement diagnosis — 18:05 AEST, 16 September 2026

The supported v90 resume and two public `lifecycle-recover` attempts returned
125, with no qualification advancement. Logs remain in private cache
directories `browser-egress-resume-v90.R3ATbRPg`,
`lifecycle-recovery-v90.P1br2vr5` and `lifecycle-recovery-v90.IgmpDULC`.
The first resume encountered a three-second transient Docker identity-service
timeout. Later recovery failures had a different, deterministic cause.

WSL reports boot time 17:47:02 AEST and current boot ID
`8390bfeb-b6d9-4a51-9272-4f39299d8aee`. The surviving authority
`retirement.run.301ced8c1e2053a7076d4d0483b109de` records prior boot
`f65a9bdc-1905-4139-a30f-47a2ddb483b1`; both its active and retired roots
are absent. The authority's SHA-256 is
`36d0fccd53370218f927b012705278583c86aeeec5b7e989eeeef43ce2643111`.
Independent inspection confirmed exact base, lock, parent and four source
identity/hash matches, with unchanged Docker daemon identity.

`_qcsd_retirement_terminal_reproof` checks the daemon successfully, then
silently rejects the historical/current boot inequality. Admission exits
before recovery-ready, and the guardian maps that early exit to 125. The
two observed identity services therefore represent separate proofs, not
evidence of two failed retries. Two focused native-holder tests passed;
an isolated real-Docker diagnostic also passed all five leased identity
proofs with guardian status zero. Its private log is
`.cache/real-daemon-native-diagnostic.WJXvkHJj/diagnose.log`, SHA-256
`cfbc09b96caa860b0c39f3b2bb783772b2bf84028342b7ed835cf4cf0a6f7a0c`.
These are engineering diagnostics, not scientific qualification evidence.

There is no supported override for the cross-boot tombstone. The next repair
must retain authenticated source/file bindings, re-prove same-daemon exact
object/label absence and scope absence, and avoid comparing process start
ticks across boots. Merely editing the helper also invalidates the authority's
bound source hash, so the source transition needs explicit review. Do not
rewrite the recorded boot, delete the authority casually, or clear the
lifecycle directory. No production source or ownership state was changed
during diagnosis. A production fix requires a fresh cohort rather than
promotion of the preserved v90 prefix.

The saved goal was confirmed **active** again at 18:02 AEST. No source-bound
capture or recovery process is live; all scientific counters remain unchanged.

<a id="source-development-audit-2026-09-15-md-l900"></a>
### Recovery and generic fix — 18:15 AEST, 16 September 2026

Two independent reviews favoured an exact orphan-authority maintenance step
over adding a historical source-successor exception. The private script used
the real exclusive lifecycle lock, exact authority/source/base/lock hashes
and identities, stable current boot, same-daemon GET-only object/label absence
proofs and absent current scope. It allowed only the test-file worktree edit;
the four executed source files still had to match the old authority exactly.
Two locked dry runs passed. Apply completed at 18:13:17 AEST, after durable
create-only archival and a final exact-target recheck immediately before
unlink. No Docker mutation or scientific receipt change occurred in that step.

The original authority, maintenance script, pre-unlink record and completed
receipt are retained in
`maintenance-evidence/v90-root-absent-retirement-301ced8c1e2053a7076d4d0483b109de/`.
The original authority hash remains
`36d0fccd53370218f927b012705278583c86aeeec5b7e989eeeef43ce2643111`;
the executed script hash is
`8e38d3dcae0828eb091ee2dd33cc6e1bba4352c2c5038ab04a0664f4250fccd0`;
the maintenance receipt hash is
`fdbb4c38ff36d5bdc3209b1a7d6d55a0a27c46bf757115d780af34c4ad97ae1d`.
This archive is operational evidence, not scientific qualification authority.

The unchanged public `lifecycle-recover` command then exited zero, retiring
five stopped qualification containers and their isolated network, including
all six remaining ownership roots. Its log is
`.cache/lifecycle-recovery-v90-reviewed.0OT6bJ7G/recovery.log`.
The real lifecycle namespace was independently observed empty. V90's
`experiment.json` still hashes to
`2bce7ab78bb728d3de97a1995e13d353768c827af4f6849f0d921148ccf1b430`.

Only after that recovery was the production helper changed. The generic fix
permits durable retirement across host boots while retaining current-boot,
exact daemon, source, lock, base, configuration, object and scope proofs.
Historical launcher tuples are not compared against the current process
table or copied into new current-boot authorities; launcher uniqueness keys
include the recorded boot. The special v57 source-successor rule is unchanged.
Nineteen new test cases produced 11 failures and eight passes before the fix;
the first post-fix selection passed 17 cases (the two collision cases are
included in the subsequent full module run). Independent source/test review
found no blocking issue. The full retirement, signal-supervisor and guardian
test modules launched at 18:15 AEST; results are not yet claimed. Fresh
cohort evidence remains mandatory after this source change.

<a id="source-development-audit-2026-09-15-md-l944"></a>
### Validation and source freeze — 18:28 AEST, 16 September 2026

The three-module run completed successfully: **502 passed, nine skipped in
738.52 seconds**. This includes all 19 new cases; do not add the earlier
overlapping 17-case selection to the total. The final log at
`.cache/cross-boot-recovery-tests.IeabNo5y/tests.log` hashes to
`8175e89c161429081689985333ef3d63c5213e7bb540a4315e7a244bbd18d278`.
The helper hash is
`cc46f8e62a666aa5d606a6d2ec4a1b92031f4e62727d41222004497ad2754e68`;
the retirement-test hash is
`6244177346b960a2a2adf4c2fe755658543e2d182dec3da3b3ebe1147dc82aae`.
Shell syntax, `git diff --check` and all seven local README links passed.

Only the helper, retirement tests and targeted README status correction were
committed locally as `8eaf1daa4113cbe261c0c79d7a3404c9fd8b3eda` (no push).
Lab is clean; Rust and the Gitlink are unchanged and clean at
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. The candidate claim boundary and
all scientific acceptance rules are unchanged.

A separate read-only allocator audit reconstructed genesis v1–61 and the 29
immutable claim/consumption pairs v62–90, matching v90's bound chain payload
hash `62e06236e8985b0c7eb916ae2719f9ee8aa87497dd392eed5708ada6486d72e4`.
V91 is next unused, subject to the launch-time authoritative recheck. No v91
claim or build/completion/CDP/browser destination exists at this checkpoint.
Next action is the public `build --cohort-version 91`, followed serially by
pinned-CDP and the full browser gate after each prerequisite verifies.
Recent measured durations imply approximately 15 minutes for the build and
five hours for browser qualification; neither is an execution guarantee.
No acquisition authority or public capture is claimed by this engineering
validation. All previous evidence and the maintenance archive remain intact.

<a id="source-development-audit-2026-09-15-md-l975"></a>
### V91 build verified — 18:47 AEST, 16 September 2026

The public three-image build exited zero. Its receipt records
18:29:49–18:44:35 AEST (886.352 seconds), with completion published at
18:44:40 AEST. All role builds used `--pull --no-cache`; source and Gitlink
remain clean at the 18:28 freeze. The host receipt validator and a separate
read-only audit verified source, images, payload hashes, completion bindings
and the allocator chain through v91 (30 claims after genesis v61).

Whole-file hashes:

- Build execution: `bf4976505417ac0c41f764539f7be3a64298bf384ee91ead805626ef1040d332`.
- Build completion: `e8937b59cc74f88541743557eefe4f3ba277665f1a6833e87d5496690a5f72ba`.
- Build log, `.cache/build-v91.O72vDpmJ/build.log`:
  `a3554cd351cfa55dc59a41d465650194b78fb17ad3aeb870d8e7643ff24aeff4`.

Pinned image IDs:

- Collection: `sha256:bd839eba8ed8ab1a6bef64b2bbcc1fc2341b3c1f5df8421ac3919f95556d8413`.
- Preparation: `sha256:3d7fb5ad5b25f77b594a06ed643886cb8015283cdaabe79ba1e46b9373fdb965`.
- Reference: `sha256:a12c8db9d4bb5ad49e18337330ca1403d056ec77431e32d82ad510e1481cce2d`.

The post-reference storage check recorded 192,400,240,640 available bytes.
The saved goal remains active. Next is pinned-CDP, followed by fresh browser
qualification; neither is claimed complete at this checkpoint. No class,
certification or formal-capture numerator advances from this build.

At 18:47:17 AEST, v91 pinned-CDP passed (outer schema 13, nested contract
12). Its public launcher exited zero, and a separate host invocation of the
receipt validator passed against the exact v91 build. Whole-file receipt
SHA-256 is `70073807faea173b8ecd6fbf3caa97c9e66ed39b07e2438ba60a7986ab5b6253`;
payload SHA-256 is `eafd92ff6e7c1bd5b85d10e8f29089360463f6df577524588407ebd2ca309a87`.
The retained `.cache/build-v91.O72vDpmJ/pinned-cdp.log` hashes to
`2957171f0d5410c5b017b19d77b135e24fe4519edd0c919f2aef11bb152defc8`.
The next operation is the serial public browser-egress `create` for v91;
current-source completed browser qualification remains 0/110 until the final
receipt verifies. No repository source changed after the build freeze.

<a id="source-development-audit-2026-09-15-md-l1013"></a>
### V91 browser gate independently verified — 23:57 AEST, 16 September 2026

The public browser-egress `create` operation exited zero. All 110 distinct,
sequential vectors passed on their first attempt, with no recorded operational
or semantic failures. The checks ran from 18:48:43.635655841 to
23:48:54.971867834 AEST: 5 hours 11.336 seconds. The final receipt was recorded
at 23:50:27.659334 AEST. Process finalisation continued after that publication;
the launcher subsequently exited successfully. No restart, source change or
gate waiver occurred during the run. With the user's explicit permission,
monitoring included read-only checkpoint counts in addition to process polls.

A separate read-only audit verified all 110 result whole/payload hashes, the
result chain, final inventory, and 110 PCAP hashes (2,312,760 bytes). The public
`test browser-egress verify` command then exited zero against the same pinned
preparation image. Both repositories and the Gitlink were reconfirmed clean at
Lab `8eaf1daa4113cbe261c0c79d7a3404c9fd8b3eda` and Rust
`46313bef90ad392b7ca293ab7cf28108d2f35c7f` after verification.

- Final receipt whole-file SHA-256:
  `9d656a54d3861b4e566445f8d20c21143ae0f29403788509fb2cae043434cee0`.
- Final payload SHA-256:
  `dc22fb329d1c4c7affd97527060717f4d3cb45b110c32f06cdc8104bda5709c1`.
- Complete checkpoint SHA-256:
  `a402cf21242448f7fdb73331dcfb4274ffd9bb3b1db815574d1bfd3c8c6b8385`.
- Expanded vectors SHA-256:
  `d9038cf12d733f914ad8e71365d98b8ac9eeb98aa9f02aa4ad43b992d3bd21ba`.
- Both `.cache/build-v91.O72vDpmJ/browser-egress.log` and
  `browser-egress-verify.log` have whole-file SHA-256
  `5c9e7c27920c8959cd59fdd36eea8e3f082b5a7d8fec6cad9390c509a0803a54`.

Current-source browser qualification is now 110/110. Acquisition-only authority
has not yet been launched at this checkpoint; its fixed acquisition/preparation
correctness tests are next. Pilot 0/120, final classes 0/100, certification
0/900 and formal capture 0/16,000 remain unchanged. This gate qualifies only
its bound source/image/browser environment and fixture; it does not certify
public classes, defence correctness, or the final matched campaign.

<a id="source-development-audit-2026-09-15-md-l1050"></a>
### V91 acquisition authority and initialisation — 00:13 AEST, 17 September 2026

The public acquisition-authority command exited zero. Its fixed correctness
inventory recorded 1,029 passes in 157.65 seconds across 14 test files;
execution ran 00:00:11–00:02:50 AEST. A separate read-only audit recomputed
all 16 input hashes and the stdout hash, and checked every gate and source
binding. The public independent receipt verifier then exited zero. Scope is
`public-page-acquisition-only`, with `promotion_authority=false`,
`paper_equivalent=false` and no waivers. This is not full defence foundation.

- Authority whole-file SHA-256:
  `dfd8a0919cc058e3fce19be246e7d5736bc1a588a9009d8212117042a8ce5c2e`.
- Authority payload SHA-256:
  `a389913cc6cf28c02642bd2d33c944bc0fa67df40a9a8b9c6679e25d8ad9e34d`.
- Correctness stdout SHA-256:
  `c175e4e1c9a6f0907a6e0ac0526caeda77dc5aa712ef90325b14717132c4a456`.
- Creation log SHA-256:
  `f38b46bc6ba4dff7554e2146188dde8357d8942a1d8136ef81ea1335fa4203e4`.
- Independent verification log SHA-256:
  `f141733a7b2859becc6c3045dc7e2346d97f5eb8acd4430f152cee2ca589a475`.

Canonical `acquisition-init` launched with the recorded acquisition start
`2026-09-16T14:09:13Z` and exited zero. It created
`artifacts/classifier-multiorigin100-v1-acquisition` with the frozen
600-candidate catalogue, an initial pending prefix of 120, zero terminal or
probing candidates, no active batch and no recorded blockers. The action is
complete, but acquisition itself is not. The supervisor has not yet launched
at this checkpoint, and no public class is accepted.

- Initial provenance whole-file SHA-256:
  `e62a8637e7a869e4df4b069df7101a25c0af654faaff59e4acea91299d334f50`.
- Initial checkpoint whole-file SHA-256 (before any acquisition work):
  `c4f095daf7440d15a829128bae5b6410f191de37c3d3696ea5bbe9c4722bf4e1`.
- Initialisation log SHA-256:
  `63be641d37c13ab4bc0d0336b625c6a64b97fb1b28c9d924abbb9b6e2487ff46`.

At 00:13 AEST both repositories and the Gitlink remained clean at Lab
`8eaf1daa4113cbe261c0c79d7a3404c9fd8b3eda` and Rust
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. No tracked source changed after
the build. The canonical host acquisition watcher is next; the genuine
stability windows, independent fitting, full defence foundation, 900-cell
certification and matched 16,000-capture endpoint remain mandatory.

The independent initialisation audit also passed: all 600 records are pending,
the current admission prefix is 24 per stratum, and there are no terminal,
probing, recovery, missed-window or baseline-batch records. It recomputed the
checkpoint/provenance whole and payload hashes and found no binding anomaly.

The first watcher launch stopped before admission because its canonical
`artifacts/classifier-multiorigin100-v1-stability` directory did not exist.
Source inspection confirms that the host watcher requires this directory
before launching any action; `acquisition-init` does not create it. Both
checkpoint and provenance remained byte-identical. The retained failed-launch
log, `.cache/build-v91.O72vDpmJ/acquisition-watch.log`, has SHA-256
`d8478fbe61a337064816f6295d56076846738b96cdf9c0631611e2ae90255e7c`.
The next launch creates only that absent empty output directory; it changes
no source, scientific input or existing evidence and retains the same cohort.

<a id="source-development-audit-2026-09-15-md-l1108"></a>
### V91 first acquisition batch and teardown defect — 00:25 AEST, 17 September

After the empty stability directory was created, the unchanged canonical
watcher advanced through admission and launched the first navigation batch.
Both candidates began at 00:20:41.416066 AEST. `elmundo.es` failed at
00:20:43.342569; `consultant.ru` at 00:20:44.087085. Both preserved
`internal-acquisition-error` outcomes with `CdpTargetIntegrityError: CDP
repeated a terminal event for a retired Document chain`. The watcher exited
one. No class was rejected, no baseline started and no page was acquired.
All 600 candidate records remain pending; two contain durable internal errors.
The initial provenance is byte-identical and the active batch is cleared.

- Failure checkpoint whole-file SHA-256:
  `c60641b7ead83b958706295735447b6d97d5d75e0894de193eeb508d35854b00`.
- Failure checkpoint payload SHA-256:
  `3840b80a79b6b4835ccad99245f5428d4c8c20006486299d3502911fb8f55a44`.
- `.cache/build-v91.O72vDpmJ/acquisition-watch-02.log` SHA-256:
  `ba3463155920e0b960542e35d76e95efbdf9d09e79f4446db13c025d626eba0f`.

A non-evidentiary, bounded diagnostic ran the installed navigation code in the
exact v91 preparation image, with observation-only router logging and no
study-state mount. Both sites reproduced the failure. Each redirected to its
`www` origin; the first pass correctly blocked that as not yet IP-pinned.
Chromium first emitted `ERR_BLOCKED_BY_CLIENT` with the inspector marker,
then emitted a later `ERR_ABORTED`/`canceled=true` for the same Document chain
while the rejected context closed. This cleanup error masked the expected
origin-pin expansion. It is not permission to omit the redirect or resources.

The first diagnostic projects selected fields; the post-fix replay must also
record raw terminal keys and explicit abort/shutdown flags to prove the exact
exception signature. Original diagnostic files are retained unchanged:

- `.cache/acquisition-cdp-v91.mmZKYcm9/probe.py` SHA-256:
  `dba1a24053ee00439552840fbf75ccc3e29adb7a09bebf89f9db9f459dc3dc43`.
- Its `probe.log` SHA-256:
  `3bfd133631048b1838bfec6a19aaa6520c7ae42f7f72075febadca34ff6ac81d`.

The production repair admits only one exact pending error-document abort
during exceptional disposal, preserving source/request binding, the original
failure, retired-chain rejection and normal rendering/shutdown strictness.
Independent review found no blocking issue; 40 added regressions bring the
CDP target file to 359 passing tests. Wider tests and live source-overlay
diagnostics remain in progress. These changes require a fresh source freeze
and cohort; v91's passing prerequisites remain evidence only for its old code.

<a id="source-development-audit-2026-09-15-md-l1153"></a>
### Acquisition browser repairs validated — 14:06 AEST, 17 September 2026

Successive non-evidentiary source-overlay diagnostics exposed two further
Chromium lifecycle cases after the original error-document abort was fixed:
late request-stage Fetch pauses while a rejected context closes, and inline
`data:` resources marked as served from cache despite not being HTTP(S)
responses. The implementation now handles all three without relaxing network
resource acquisition or promoting failed navigation:

- Consume one exact pending root error-document abort only during explicit
  abort and shutdown, with bound request/source identity, finite strictly later
  timestamp and the exact `ERR_ABORTED`/`canceled=true` signature. Retain the
  retired-chain marker and reject other repeated terminal events.
- Hold late request-stage Fetch interceptions paused during rejected-context
  disposal. Do not call application policy, register resources or send policy
  commands; reject response-stage and malformed events. Direct policy sends
  are forbidden during abort.
- Admit one cache marker only for a unique live same-source `GET data:`
  occurrence, retaining its normal request/response/terminal audit. HTTP(S),
  other schemes, unknown/retired/migrated identities and duplicates remain
  errors. Existing internal error-document handling retains precedence.

The combined diagnostic completed navigation for `consultant.ru` with four
origins and `elmundo.es` with three. Each produced four links and no router
errors or rejections. Independent audit matched all nine inline cache markers
to live same-source data requests, both exact error-document cancellations to
their abort lifecycle, and both late Fetch pauses to zero policy commands.
This proves only these bounded diagnostic executions, not public acquisition,
stability, class admission or defence correctness.

Validation: 417 router tests passed, including 98 added cases. The complete
14-file acquisition correctness suite passed 1,127 tests in 376.86 seconds;
Ruff 0.12.12 lint/format and `git diff --check` passed. Independent AST review
found no existing test changes and no production semantic changes outside the
three fixes and their supporting state/call sites. No Rust code changed.

- Current router source SHA-256:
  `430bc5b67e10158eea815b8836e29196eb6c47f91e8f7c7e641f310fcd4fa28a`.
- Current router tests SHA-256:
  `9d3e474d23c3fe79f2732d9ed0656d4304908b6d2ac47ad862e2329fcec0da6c`.
- `.cache/cdp-abort-fix.gnO71qtc/acquisition-combined-tests.log` SHA-256:
  `7f4358a4b67098d45f0f815527145b1a95ef8a740371e4c149119f17e2412d98`.
- `.cache/acquisition-cdp-v91.mmZKYcm9/probe-combined.log` SHA-256:
  `dee884c6da58ad439545b1160af2488fed460ab10b24dd9e465497064569a62f`.
- Diagnostic container metadata SHA-256:
  `0589ae479b23236721fb479150fe8624ce8aab4fc774fc0226f049cc3446b118`.

The four stopped diagnostic containers were removed only after preserving and
checking their metadata. Their scripts and logs, all study evidence and both
failed acquisition attempts remain. The 13-hour interruption in local work
was an agent usage-limit pause; acquisition was stopped throughout, not silently
collecting. No scientific numerator advanced.

Read-only inspection confirms the public runner cannot initialise over its
existing canonical root or resume it with changed source/image. The host
watcher and launcher also bind that root. A narrowly scoped, independently
reviewed maintenance archival operation is being prepared to preserve the
exact zero-progress failure directory in a create-only archive, holding the
watcher/acquisition locks and proving no owned live resources. No archival
move has occurred at this checkpoint. The next cohort must reprove build,
pinned CDP, browser egress and acquisition-only authority before public work
continues; full defence foundation remains mandatory before fitting/capture.

<a id="source-development-audit-2026-09-15-md-l1216"></a>
### Exact failed-acquisition archive — 14:16 AEST, 17 September 2026

The reviewed private maintenance helper passed nine synthetic tests, including
exact inventory preservation, no-replace rename, hash/inventory/alias refusal,
exclusive locks, create-only intent and external-activity refusal. Root then
executed its locked read-only dry run, followed by explicit apply. Both exited
zero. It checked the exact failed checkpoint/provenance and zero scientific
progress, held the existing watcher and acquisition locks, proved no owned
Docker objects or acquisition scopes, published a durable intent, and
atomically renamed the one directory without replacement.

The original directory is now
`artifacts/class-study-retired-acquisitions/cohort-v91-c60641b7ead8/acquisition`.
An independent post-action audit found the root inode and all six inventory
entries unchanged. The checkpoint remains `c60641b7…35854b00`, provenance
`e62a8637…d334f50`, with both internal failures preserved, all 600 candidates
pending and no pages, terminals, baseline batches or active batch. The old
canonical pathname is absent; the stability directory remains empty with its
original identity. No failed attempt, log or scientific evidence was deleted.

The archive includes a copy of the helper, its pre-move intent and completion
receipt; all explicitly deny scientific authority. Whole-file SHA-256 values:

- Helper: `bcdfce53b36eaf2d6d25fedf019cc3c363a3259baf9fdb2c6c47f93f317939af`.
- Intent: `e1d7c1ccac9ef37b8c90cbade67b59dbd39a64ff96a77024e19c538418746d57`.
- Completion: `b69e25f28e0afd1dfad2e797d9738b7e185b849635df97ff6e972cdd3acd5b61`.

Before source freeze, the instrumentation policy identifier was changed from
v14 to v15 in both the runtime and host watcher, with matching literal tests.
This identifies the changed event-admission semantics. Receipt outer schema
13 and nested contract schema 12 are unchanged. Current validators must not
accept v91's old policy as v15 authority; original source/image remains the
basis for historical semantic reproduction. No permissive fallback was added.
The 14-file suite plus pinned-CDP and full watcher tests is in progress; the
previous 1,127-pass run predates only this explicit policy-identity change.

Read-only allocator-chain inspection identified v92 as the next unused cohort.
At preflight, Ubuntu had approximately 865 GiB free and Windows C: 178 GiB;
the fresh build must still perform its own Docker-VHD backing-volume check.
No v92 allocation or build has occurred at this checkpoint.

<a id="source-development-audit-2026-09-15-md-l1257"></a>
### Policy-v15 source freeze — 14:19 AEST, 17 September 2026

The final 16-file local suite completed with **1,523 passes in 368.57 seconds**,
including the complete 14-file acquisition authority inventory, pinned-CDP
tests and the full host acquisition-watcher module. No tests failed or were
skipped. Its retained log is
`.cache/cdp-abort-fix.gnO71qtc/policy-v15-acquisition-tests.log`, SHA-256
`9c77aa1b73939ab9f788ecfb97c12d741bbf458b23f0aafdc12524b9963b1933`.
Ruff checks and `git diff --check` passed; 376 relative Markdown links in the
four current documents resolved. The two tiny policy-string changes outside
the router/test pair preserve the existing receipt schema versions.

The source freeze is Lab `14c98d5afdf063e860a528c3afa0732ef8ce31e8`
(`Fix aborted navigation and inline data browser lifecycle handling`). Both
checkouts were reconfirmed clean, with Rust and Gitlink unchanged at
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. The commit contains only the
router, its tests, the pinned-CDP policy assertion, watcher policy constant and
concise README status. Private ledgers, diagnostic files and the maintenance
archive are not committed. Current router SHA-256 is
`1c9808e81632883d66ebca9df7b9169c9c3953528785deca72a43262b5028095`;
router tests hash to
`50a7553caaf8de8759d04b842746da68c13a21886f4c251f35345c3f66e62cc6`.

The next serial operation is the public fresh build for allocator-next v92,
with logs reserved in `.cache/build-v92.IRrBdpsT`. No fresh gate is claimed
from the local test pass or commit. The full 100-class, nine-mode compatibility,
independent fitting and matched 16,000-sample endpoint remains unchanged.

<a id="source-development-audit-2026-09-15-md-l1285"></a>
### V92 build-retirement failure — 15:08 AEST, 17 September 2026

The collection role completed all 61 BuildKit steps at 14:32:57 AEST, but
the wrapper exited 1 during terminal lifecycle retirement. The two identity
services exceeded RuntimeMaxSec=3s at 14:33:03 and 14:33:07. The expected
daemon ID and subsequent successful observation both identify
`48f27adb-00f1-41ce-80fe-41360d2eb712`; no exact mismatch was observed.
The supervisor's “daemon identity changed” message conflates unavailable
identity with a returned mismatch and needs correction.

V92 is consumed and incomplete. Prepare/reference roles did not run; no full
build receipt or browser qualification exists. The partial collection image
is `sha256:30f933f15d66482f8842e3fd832a8d96401b51c507cc7902cb1e2a398611ce3b`
and must not be promoted or combined with images from another cohort. The
build log `.cache/build-v92.IRrBdpsT/build.log` hashes to
`7c01f2f2090663f0640ced3ed9aef2e61bbe347802e2a7b54164a952de724585`.
Exact copies of the retained build, retirement and transaction records and
the journal/BuildKit history are in `.cache/build-v92-recovery.5PAUoRAp`.
The journal hash is
`ec926b06cea3356fbe8445eac348de70ed121e92d49f959c95dd20cc6618b04c`;
BuildKit history hashes to
`73c40f62830d61c8583f9c4447ae86f0b6a09bd4299d1baaaaf65ff56e3db401`.

Source inspection confirms that normal lifecycle recovery refuses this
published partial-build transaction. A narrowly scoped, reviewed archival
operation must preserve the exact three metadata entries before source
changes. The proposed repair gives only build-retirement identity reads a
ten-second budget; ordinary three-second API calls, the 120-second run-signal
envelope, immediate mismatch rejection and fail-closed unknown identity are
unchanged. No maintenance apply, source repair or new build has occurred at
this checkpoint. Scientific counters remain unchanged at zero.

<a id="source-development-audit-2026-09-15-md-l1317"></a>
### V92 recovery and bounded repair — 15:15 AEST, 17 September 2026

The exact-state private maintenance helper passed 12 synthetic tests and an
independent review. Its locked read-only preflight and explicit apply both
exited zero. The three lifecycle records were renamed without replacement to
`artifacts/buflo-study/build-failure-v92/metadata`, with the transaction moved
last. No image, tag, claim or historical scientific evidence was changed.
Independent verification confirmed all six copied payload files and five
metadata entries (three files and two directories), their hashes/inode
identities, the unchanged consumed claim and absence of v92 build/completion
receipts. The archive confers no scientific authority and never permits v92
reuse. Public `./qcsd-lab lifecycle-recover` then exited zero.

Maintenance helper SHA-256:
`252dfa870e5b310b1e33d714ca3f06c5ce238db32c91641586cef0c2cf22473e`.
Intent SHA-256:
`5af29426c6f70b97276cfd1e628d92cbc4c2692d9ab7e4b171c4d016bfb1c6ca`.
Completion receipt SHA-256:
`b6174f6c4d9cc4f437b74907d3406333bd78ac53bfeba38adda3d4394f140119`.

The source repair selects a ten-second read-only proof only for a terminal
build retirement. Default identity/API calls retain three seconds; the
two-attempt maximum, immediate exact-mismatch rejection and 120-second
run-signal envelope are unchanged. Invalid purposes/extra arguments fail
before any service call. The error now states that identity could not be
verified, without asserting a mismatch. Independent source review found no
blocking issue. All 24 selected identity/real-retirement tests passed in
17.09 seconds; log SHA-256:
`88b5c1c0847abef15f83afa76bb9685e4edb6896e07684f850ce547bbc31d142`.
The full three-module lifecycle suite is running; source freeze and a fresh
cohort remain pending. No accepted scientific counter has advanced.

<a id="source-development-audit-2026-09-15-md-l1349"></a>
### Timeout repair source freeze — 15:29 AEST, 17 September 2026

The complete supervisor, retirement and lock-guardian suite finished with
**517 passes, nine skips and no failures in 851.49 seconds**. Its retained
log `.cache/build-v92-recovery.5PAUoRAp/timeout-lifecycle-tests.log` hashes to
`32793c672c36389857748c02f7d85e6f77847438b6fdc17b28b22ff7b32629ca`.
The skips remain explicit; this host test result is not the study code gate
or a live browser/defence qualification. Shell syntax and `git diff --check`
also passed. Independent review confirmed only build retirement receives the
longer read-only identity budget.

The three-file repair is frozen in clean Lab
`771b11a03a534b3fc121871e55cfe9a30158fe62`
(`Bound post-build identity checks separately from capture controls`).
Rust/Gitlink remains clean at `46313bef90ad392b7ca293ab7cf28108d2f35c7f`.
The helper SHA-256 is
`4c942c9ed7e9a9fc32ad7dae9dbeee893d3ab6aa4655892c30f5e882b6c52d3c`.
No defence algorithm, workload, parameter, browser policy, acceptance rule,
or prior evidence was changed. Read-only claim inspection finds v93 next,
with all four corresponding claim/consumption/build/completion destinations
absent; the public build will independently validate and allocate it. The
full matched 100-class/900-certification/16,000-capture objective remains
unchanged and scientifically uncompleted.

<a id="source-development-audit-2026-09-15-md-l1373"></a>
### V93 fresh build verified — 15:46 AEST, 17 September 2026

The public pull/no-cache build completed all three roles in **957.718 seconds**,
15:29:28–15:45:25 AEST; completion was published at 15:45:31. Its process exited
zero. Root and independent semantic validation verified the paired receipts,
exact current clean heads/Gitlink, three successful build commands, Buildx
identity checks and the dense on-disk allocator claim chain through v93.
The v92 post-export timeout failure did not recur. This does not promote v92
or establish browser/defence/capture gates.

Whole-file receipt hashes:

- Execution: `06f61f3bb12f64603685fa214ae60a48570042839cce7fdb2f24b78132cb8ee9`.
- Completion: `36542bf83a8b6952120fc2bea1a7ca69a328a960cc1c21861c1c3e4af390ea5a`.
- Retained build log: `d66c58dedc68930318415be9210786b61293fc7928c8fcd36ed999e4984ced81`.

Pinned images:

- Collection: `sha256:f161d94fd80ea79361c369f23bf79f05dc1f382e45f3dde6e604a6ffe60a38a3`.
- Prepare: `sha256:e2a4a16a8a59e157c756b9bda68c4d789c4e61637dd02d57cdbdb598986c4f16`.
- Reference: `sha256:df570559793519c98cc334f9083277ce06349b4560b25685e0d766af036c9e3d`.

The next create-only pinned-CDP destination and browser-egress root were
confirmed absent. Fresh browser qualification remains required for policy-v15
source; v91's policy-v14 result is historical, not current authority. All
accepted class, compatibility and formal sample counters remain zero.

<a id="source-development-audit-2026-09-15-md-l1400"></a>
### V93 pinned-CDP verified — 15:49 AEST, 17 September 2026

The public pinned-CDP command completed successfully and recorded a pass at
15:47:31 AEST. Root and independent semantic verification confirmed probe
schema 13, contract schema 12, current instrumentation policy v15, exact build
and completion bindings, clean source, and preparation/collection images.
Whole-file receipt SHA-256:
`c2155d2e5fcd807b555c211d39a76ab33a3486cfe56d6004856ea8a40817df33`.
Payload SHA-256:
`65060a4d2c7f63d393b30da7a20ce3d78e69d5a236af9b620c830f35b33a30b6`.
The retained pinned-CDP log hashes to
`e038f9577fa9445fbcd2d9534f1dfdd628ed4ae9d761d6a970b37d75edefcf2f`.

Next is create-only browser-egress qualification at
`artifacts/buflo-study/browser-egress-qualification-v93`, using the exact v93
build receipt and unchanged source. The v91 run's roughly five-hour duration
is the planning reference, not a promised completion time. No current-source
110-vector pass, acquisition authority, public class or capture is claimed.

<a id="source-development-audit-2026-09-15-md-l1419"></a>
### V93 interrupted after vector 32 — 17 September 2026

The existing browser creation session exited 1 with private-supervisor
retirement and ambiguous-result-publication diagnostics. At the 17:32 AEST
read-only audit, the checkpoint had 32 passed first attempts, no terminal
failure, no outstanding intent and next ordinal 33. Each of the 32 result-file
hashes matched its checkpoint entry. These are partial integrity observations,
not final packet-deep qualification or accepted classes.

Independent source/journal review identified two ordinary three-second Docker
observation timeouts. Service `qcsd-docker-api-254679fa24c6fa87dc6fb068fcc80a8d`
started at 17:11:47.810 AEST and timed out at 17:11:50.833 while rechecking the
exact container's absence after supervisor-directory retirement. The authority
remained in its supported post-directory-removal recovery phase. The subsequent
reconciliation command itself exited zero, but observation service
`qcsd-docker-api-1be2cd8ea1acb6a43cbea12fff7e12ef` timed out at 17:12:21.557;
its recovery record therefore correctly retained an unknown target state.
The user journal supports observation timeout, not a failed vector, daemon
identity mismatch or site rejection. A later read returned the original daemon
ID and no container under the exact retained supervisor label.

Before recovery, byte-preserving copies of both lifecycle leftovers, checkpoint
and original log were saved in
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/`. SHA-256 values:

- Retirement authority: `fb4e8c88261f40fa6c91c0714446815d9379ee08493e3ab31af606c9ed40bfb4`.
- Recovery record: `4dc3a7de144e2e32cee9b494a1984b58b126b8ad9770e747e0e1577f660c54ec`.
- Checkpoint: `71c8ba15b99d2379ceb0e420bb475148d68f72c53a3c5de1103f577d3f438c5b`.
- Original creation log: `38894d558909a3e828793f6296b48f2343801133efefbe9584eb5afcb103a8b9`.

Lab `771b11a…` and Rust/Gitlink `46313be…` remain clean and unchanged.
The reviewed next action is public `lifecycle-recover`, followed by the public
browser `resume` with the exact v93 receipt/root only if recovery and admission
pass. No bypass, manual deletion, source patch, rerun from zero or scientific
promotion is authorised by this diagnosis. All accepted study counters remain
zero.

<a id="source-development-audit-2026-09-15-md-l1456"></a>
### V93 recovery and identity-query repair — 17:39 AEST, 17 September 2026

Independent prefix review reproduced the stored checkpoint without running
filesystem reconciliation. It verified 65 canonical receipt envelopes and
payload hashes, 32 result/PCAP bindings, 44 source files and two contract
files. The exact open inventory has 98 files and 67 directories, 32 intents,
32 results and no outstanding intent. Next would be vector 33,
`constructor--dedicated-worker--webtransport`, first attempt. This is still
not packet re-decoding or a complete 110-vector qualification.

The first public lifecycle-recovery attempt exited 125 before mutation:
service `qcsd-docker-api-f12132ba9a9839c36a5773285c649b1c` timed out reading
the daemon ID at 17:36:06.807 AEST. A second unchanged public invocation
completed successfully. The lifecycle namespace is now empty; the original
checkpoint hash remains `71c8ba15b99d2379ceb0e420bb475148d68f72c53a3c5de1103f577d3f438c5b`.
The successful recovery log at
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/lifecycle-recover-retry.log`
hashes to `050876c3c2ac6c0e05d2d4dd395bc8cf0ff096269030a4b05ec1243fd2a074e2`.
Only authenticated transient supervisor metadata was retired; exact copies
remain in the snapshot directory. No qualification evidence was removed.
The retained original timeout journal hashes to
`f57498af744f8789bbd6852ccafdd8caea4fb3217946b7465355e7399f4e40a6`.

Read-only latency probes distinguish the Engine from its CLI: three direct
Unix-socket `/info` calls returned the same daemon ID in 0.0369–0.0699 seconds;
CLI identity calls took 1.570–3.082 seconds. Docker CLI v29.0.1's `runInfo`
unconditionally enumerates client plugins before rendering even an ID-only
template ([official source](https://raw.githubusercontent.com/docker/cli/v29.0.1/cli/command/system/info.go)).
This overhead is unnecessary for repeated identity checks and can exhaust the
entire ordinary three-second control-plane budget.

A targeted repair is in the working tree, not yet frozen or qualified. The
existing source-pinned native wrapper performs a fresh read-only Engine ID
request only after authenticating and acknowledging the API-service lease.
Verification and the subsequent one-shot Docker operation remain in the same
bounded service. Strict response/ID validation, exact mismatch handling,
configuration descriptors, signal dispositions, three-second API bound and
120-second signal envelope are preserved. There is no identity cache, Unix
failure fallback or mutation retry. Named-pipe compatibility retains the
existing CLI path; full Docker metadata receipts retain their original data.
The real new Unix reader returned the original ID in 0.0192–0.0885 seconds
in three non-evidentiary read-only probes. Focused and lifecycle integration
testing is underway. Because source is changing, preserve v93 as incomplete
historical evidence and use fresh allocator-authorised cohort qualification
after the repair is validated and frozen. No scientific numerator advances.

<a id="source-development-audit-2026-09-15-md-l1502"></a>
### Identity-repair test interruption — 18:27 AEST, 17 September 2026

The focused native-reader suite had passed 99 tests and three leased Unix-HTTP
integration cases. The subsequent combined identity, supervisor, retirement,
guardian and CLI test run was stopped deliberately with SIGINT after leaked
fixture processes were observed. Session 11274 is terminal, exit 2, with
555 passes, 27 failures, nine skips, five deselections and one teardown error
over 1,521.42 seconds. It is incomplete failing diagnostic evidence, not a
successful gate. Live Docker probes were excluded/disabled.

The complete log is
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/identity-lifecycle-cli-tests.log`,
SHA-256 `be3ca1aa06b9df2cdd25b5892dc53292b125bcf9c3491fd0855b411a01c2e5d9`.
Independent inspection established that two fixture harnesses reached fake
Docker readiness only after their five-second startup waits expired. Neither
had received its intended test signal. Their teardown had already sampled
the scope/root records before the delayed children published them. This is a
concrete test-cleanup race; it does not explain away every reported failure.
Seven guardian failures are being diagnosed separately.

Cleanup authenticated 20 private processes using invoking UID, exact pytest-6
paths, test identities and process birth values, then used PID descriptors for
signals. Follow-up census found no matching live processes; user systemd listed
no loaded QCSD Docker units. No result, receipt, diagnostic file or capture was
deleted. The cleanup log is
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/failed-fixture-process-cleanup.jsonl`,
SHA-256 `20b0d57126b1dc71ec8caf468a03736074e99eb8cd2deb7a8b2417a38bece67a`.

Lab remains at HEAD `771b11a03a534b3fc121871e55cfe9a30158fe62` with the repair
uncommitted; Rust/Gitlink `46313bef90ad392b7ca293ab7cf28108d2f35c7f` remains
clean. V93 checkpoint SHA-256 still equals
`71c8ba15b99d2379ceb0e420bb475148d68f72c53a3c5de1103f577d3f438c5b`.
No new cohort, browser qualification or scientific capture has launched.

After that cleanup, isolated CLI tests passed **267 cases**, with four
name-matched cases deselected, in 20.10 seconds. Three deselected tests require
live Docker; the fourth is a pure capability-shape test whose name also matches
`real_docker`. The next combined suite must include that pure test by using the
narrower `not test_real_docker` selection. Log:
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/identity-cli-isolated-tests.log`,
SHA-256 `c5e13a062881286baf29f80f32b1acfa470defd1482024521656a3bae1e05aa9`.
The native identity suite passed **99 tests in 0.34 seconds**, logged separately
as `identity-reader-isolated-tests.log` in the same directory. Neither result
supersedes the interrupted lifecycle suite; its startup/cleanup defects must
be fixed and the relevant broader tests rerun before source freeze.

<a id="source-development-audit-2026-09-15-md-l1548"></a>
### Fixture ownership and guardian census follow-up — 17 September 2026

All 12 host harness launch sites in the supervisor fixture now register the
child immediately, retaining PID birth/session/group identity and a PID
descriptor. Teardown stops/reaps those producers before sampling their
root/scope records. A controller timeout no longer skips other exact cleanup,
but still causes teardown to fail. Four deterministic cleanup regressions and
seven representative signal/natural-exit cases passed: **11 tests in 35.94
seconds**, with all timeout values unchanged. Log
`signal-fixture-cleanup-focused-1.log` in the same retained cache directory has
SHA-256 `817b098b8f8266fcffd01586299b7903fe51bed956d24e9451c0dec5231ee926`.

Independent review also found a production guardian defect. The census already
excluded other-owner and pre-threshold processes from configuration-reference
inspection, but then required even those excluded candidates' zombie leaders
to have readable pidfds within one millisecond. A pidfd for a thread group need
not be readable while the zombie leader still has live workers. Six new
excluded-candidate tests failed against the original code; three eligible
candidate controls correctly failed closed. The narrow correction applies the
terminal-state assertion only to the existing eligible set, retaining stable
owner/birth checks, final pidfd/rebinding checks, and every eligible-holder
failure. The retained error now includes PID, UID, birth, threshold and state
for future diagnosis. Older logs lack these fields, so this demonstrated
defect is not retrospectively asserted as the cause of every earlier failure.

The corrected source passed the first 24 selected census/guardian regressions,
including earlier census failures. A longer five-handoff retirement test still
exceeded its unchanged 60-second outer test deadline; the second longer case
and phase-cost investigation are pending. This is not a passing broader gate.

<a id="source-development-audit-2026-09-15-md-l1578"></a>
### Retirement phase measurement — 00:09 AEST, 18 September 2026

The native helper's HTTP import was moved into the Unix identity-read branch,
avoiding unrelated HTTP/email/TLS startup for filesystem/process operations.
The 99 native identity tests passed afterwards. The two retirement tests still
exceeded their unchanged 60/90-second aggregate caps on the earlier host run;
this optimisation alone did not establish a solution. The retained
`guardian-census-and-import-summary.md` distinguishes transcribed tool results
from raw test logs and reports the import measurements with their variation.

After the host restart, a private diagnostic copied the real fixture harness
and recorded phase times without changing tracked source or internal bounds.
It used a diagnostic-only 180-second outer cap, preserving the original
assertions and additionally requiring an empty retirement namespace, exactly
three container/two network removals, and no extra removals during retirement.

| Diagnostic phase | Current handoffs | v57 predecessor handoffs |
| --- | ---: | ---: |
| Three run creations | 3.48 / 2.39 / 2.37 s | 3.46 / 3.46 / 2.46 s |
| Two network creations | 2.16 / 2.68 s | 2.12 / 2.37 s |
| Three run retirements | 5.90 / 5.57 / 5.13 s | 10.48 / 9.09 / 7.70 s |
| Two network retirements | 5.10 / 5.21 s | 9.14 / 7.75 s |
| Entire guardian invocation | 40.51 s | 58.55 s |
| Original test budget | 60 s | 90 s |
| Fake-Docker calls, including identity reads | 132 | 202 |
| Identity reads | 75 | 117 |

Both diagnostics and exact fixture cleanup passed; session 22531 exited zero.
This is not a pass claim for the original tests. No deadline increase is
justified by these measurements. Current boot ID is
`99e3055c-3fb9-47d4-a45f-5da3b2ccf244`, replacing
`8390bfeb-b6d9-4a51-9272-4f39299d8aee`; changed host conditions prevent causal
attribution of all prior timeouts to one repair.

Raw diagnostic files under
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/`:

- `retirement-phase-profile-v2.log`: `787bcfd38bb12f5dd38d006328b4168306702ce8644f6484dfcd3c7135d08a3c`.
- `phase-current-imt51ba4/guardian.stderr`: `69fc573669e7b4c4c15359547b41e9a324d6ee3ca26134b3c315e177613565bf`.
- `phase-predecessor-oums50fx/guardian.stderr`: `890e0de0a7c1ba4fb2e7b7f140d6b65d534df0a0e457e69d6e1ca6a14d00c23b`.
- `profile_retirement_phases.py`: `98c8de2e9edf4133fff9ec7ebf039027448778eafc9a9860f0586c42338ab67b`.

The full five-module suite is now running as session 65011, logging to
`identity-lifecycle-cli-repaired-v2.log`, with unchanged original tests and
deadlines, first-failure stopping, and the narrower `not test_real_docker`
selection. Four actual Docker tests are excluded; native Buildx live probes
are disabled explicitly. All tracked source is held unchanged during this
run. Independent read-only review found no material regression in the nine-file
patch but did not certify the pending broader tests or fresh-image execution.
No scientific numerator advances and no fresh cohort has launched.

<a id="source-development-audit-2026-09-15-md-l1629"></a>
### Complete repaired local regression — 00:24 AEST, 18 September 2026

The original, uninstrumented combined suite completed successfully:

```text
902 passed, 9 skipped, 4 deselected in 824.23s (0:13:44)
```

The current-handoff and v57-predecessor five-object retirement tests passed in
39.67 and 62.81 seconds under their unchanged 60/90-second outer budgets. The
longest test was the five-v57-handoff reconciliation at 85.98 seconds. All 915
collected tests are accounted for. The four deselections are the exact tests
whose function names begin with or contain `test_real_docker`: one guardian
Buildx probe and three CLI browser/topology probes. Seven static skips in the
supervisor module delegate equivalent source/handoff replacement scenarios to
guardian or retirement integration; two guardian Buildx metadata/frontend
probes are explicitly opt-in. User-systemd coverage ran rather than skipped.

The closed raw log is
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/identity-lifecycle-cli-repaired-v2.log`,
SHA-256 `685e5e1fb4cbe7eb115f65e0f3cb39e817129a7a09a70f866eda9534577becf2`.
Post-run census found no loaded `qcsd-docker*` user units and no surviving
pytest/QCSD fixture process. `git diff --check`, Bash syntax, Python bytecode
compilation and graph impact/coverage checks pass. Clean Rust/Gitlink remains
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`; v93 checkpoint SHA-256 remains
`71c8ba15b99d2379ceb0e420bb475148d68f72c53a3c5de1103f577d3f438c5b`.

This establishes local engineering validation only. The Lab repair is not yet
committed or bound to a fresh image/cohort. The four live-Docker tests, fresh
pull/no-cache build, pinned-CDP and complete 110-vector browser gate remain
downstream requirements. No scientific numerator advances.

<a id="source-development-audit-2026-09-15-md-l1661"></a>
### Source freeze and live-Docker closure — 00:27 AEST, 18 September 2026

The reviewed nine-file repair was committed as clean Lab
`715789218c6b9d858c87aa7c616bee4d3777de83`. Clean Rust and the Lab gitlink
remain `46313bef90ad392b7ca293ab7cf28108d2f35c7f`; no runtime Rust source or
gitlink changed in this repair. Supported `./qcsd-lab lifecycle-recover`
completed successfully from the clean checkout.

The four previously deselected live-Docker integration tests then passed from
the frozen source:

```text
4 passed in 7.55s
```

Their closed raw log is
`neqo-qcsd-lab/.cache/v93-lifecycle-recovery.kMBYpudj/postfreeze-live-docker-tests.log`,
SHA-256 `c04d60aa89d7a73ae4f8539d3a2ee47a86859c1630b39f1e0769e7657ed4f2db`.
Combined with the non-Docker run, local repair closure totals 906 executed
passes and nine declared skips, with no remaining deselected runnable test.
Post-run checks found both repositories clean, no `qcsd-docker*` user unit, no
matching pytest/QCSD fixture process and an empty lifecycle namespace. V93's
checkpoint remains preserved and unchanged; it cannot authorise the new source.

The next source-bound operation is allocator-authorised selection of a fresh,
unused cohort, followed serially by the pull/no-cache three-role image build,
pinned-CDP qualification and a complete new 110-vector browser-egress gate.
No cohort number is assumed before consulting allocator authority. Pilot,
final-class, compatibility and formal-capture numerators remain respectively
0/120, 0/100, 0/900 and 0/16,000.
