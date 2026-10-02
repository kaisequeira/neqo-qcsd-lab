# Rapid 50-class capture plan

For the operator-facing stage order and live milestone, see the
[rapid capture path](RAPID-CAPTURE-PATH.md).

**Prospective plan, 2 October 2026.** The final target is **50 websites × five
traffic settings × 64 visits = 16,000 accepted recordings**. No recording has
been accepted into this cohort yet. The first ten qualifying websites are a
small **50-visit diagnostic shakedown**, one visit per setting and site. Those
diagnostic traces do not count toward 16,000. We aim to begin the formal run
within seven days, subject to finding live qualifying pages and passing the
focused capture checks below.

The five settings are ordinary traffic, FRONT, Tamaraw, BuFLO, and CS-BuFLO.
The last two are client-only candidate defences. Their parameters are fixed
before capture; this study does not fit them on the selected websites. Traffic
Morphing, WTF-PAD, Walkie-Talkie, and the `static` control are outside this
prospective comparison. The former [100-site](../config/class-study/v1/study.json)
and [20-site](../config/class-study/v2/study.json) contracts and their evidence
remain separate.

## Where the candidate sites come from

The [professor-facing site-source explanation](README-CURATED-DOMAINS.md)
summarizes why the supplied domains are only part of the planned cohort.

The supplied [raw JSON](../config/curated-sources/crux-73-v1.raw.json) is now
copied byte-for-byte into the repository. Its [source receipt](../config/curated-sources/crux-73-v1.source.json)
binds the exact bytes and lists **73 distinct `crUX_domain` entries** and
**5,507 HTTPS resource URL observations**. These entries are candidates, not
verified classes. Ten entries have no listed resources, so 63 have at least
one. The current automatic domain-safety policy flags seven entries, including
one of those ten; 57 have both a listed resource and no automatic flag. Fifty
of the 66 unflagged entries have a different-host resource hint. A listed
resource may no longer load on the live page or support HTTP/3. None of these
counts establishes 50 eligible classes.

The [dated root-screen report](CURATED-H3-SCREEN-2026-10-02.md) records exactly
which domains returned a clear HTTP/3 response, an ambiguous result, a peer
close, a timeout, or a safety skip under the historical v4 screen. Only
**30/66** unflagged homepages clearly passed that root probe, and only 14 of
those have two listed resource-host groups. Under v5, a recorded ambiguous
homepage result may still lead to a separately controlled HTTP/3 pass on the
exact selected page, so 30 is **not** a ceiling on eligible curated sites.
The 600-domain fallback remains frozen because 50-site live yield is unproven.

We found no source file or study rule that defines **58 unique classes** from
this JSON. The exact site-key count is 73. A different exclusion or grouping
rule might yield 58, but without that rule it must not be used as an
eligibility count. The [current v5 rapid profile receipt](../config/curated-sources/crux73-tranco600-rapid-v5.profile.json)
(file SHA-256 `f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60`)
fixes a reproducible order: the 73 curated candidates in hash order, followed
by the frozen 600-domain Tranco catalogue in its recorded order, with domain
overlaps deduplicated. It also fixes the five settings and the two separate
sample targets: **50 zero-credit shakedown visits** and **50 × 5 × 64 = 16,000
formal visits**. V5 records the first bounded homepage result, including an
exact local name-not-found result as an operational deferral, and requires
human site-safety review before page preparation. Admission needs a separate
controlled `known_valid` HTTP/3 result for the exact canonical, query-free
selected page. A homepage that was ambiguous can still pass that page check.
No root survey alone approves a class. The earlier v4 fallback batch of ten
raw probes failed v4 verification and receives no retroactive v5 credit. A
fresh post-freeze v5 screen independently verified the first ten fallback
decisions (six timeouts, three exact DNS-name-not-found deferrals and one
known-invalid response); none is a clear homepage success or an admitted site.

For each chosen class, separately verify the exact selected public page over
HTTP/3, save its complete browser-observed download graph, replay every
approved resource stably, and require at least one live cross-origin resource.
Check site safety and record every earlier candidate's outcome in the fixed
order. An operational failure is a deferral, not a scientific rejection. The
curated file has no selected page URLs or HTTP/3 evidence, so its resource
links are clues for discovery only. **No v5 site has yet been admitted.**

The final 50-site target is conditional on live yield. The tracked Tranco 600
catalogue is registered as a fixed fallback after the curated candidates,
**before formal capture**. It adds candidates, not preapproved classes; they
must pass the same live checks.
Do not silently add sites or count shakedown visits after seeing outcomes.

## Replace the expensive launch sequence

The earlier 20-site route required a new no-cache three-image build, 30 pilot
sites with timed checks, 110 browser vectors, 190 defence trials, fitting and
pairing, nine-mode certification, and a full readiness chain before formal
capture. These requirements were internal rules of that proposal. They do
not gate this new five-setting study.

Use the already verified v147 runtime images for unchanged diagnostic paths
with their exact clean execution checkout. Bind the new study plan and host
launcher separately to their exact source hashes. Reuse of an image does not
claim that later authoring code was installed inside it. A changed defense
client needs a clean source identity, rebuilt runtime and fresh qualification
bound to its actual binary. The generic recorder has already completed one
deep-verified, multi-origin baseline diagnostic trace on v147. It is not a
curated-class or formal-study recording.

The shorter launch check is:

1. Freeze the 50-class profile, candidate order, settings, parameter bytes,
   runtime image identities, and per-block campaign plan.
2. Record the first controlled homepage result, then inspect candidate pages,
   prove HTTP/3 on each exact selected page, prepare and verify each chosen
   workload, and qualify the response chaff required by defended traffic.
   An ambiguous homepage result can proceed; full page and resource proof
   cannot be skipped.
3. Run one complete diagnostic capture per site and setting on ten sites.
   Verify each packet capture, event file, workload, parameter, and failed
   attempt independently. Fix real failures before starting formal visits.
4. Begin the 16,000-visit run in time blocks. Count only complete, sealed,
   deep-verified results whose planned and accepted counts match. Keep the
   diagnostic and formal roots separate and create-only.

At earlier 63–131 second per-visit speeds, the 50 diagnostic captures take
roughly **53–109 minutes of recording time**, plus preparation, chaff
qualification and verification. The 16,000 formal visits would take roughly
**12–25 days if run serially**, before retries and checks. Site yield and
actual machine throughput have not been measured for this new cohort.

## Independent defence lanes and recovery

Independent campaign and result roots for each setting would let a failed
BuFLO lane pause while the other settings continue. An unchanged lane can
resume its own frozen plan and response qualification; another lane's
recorder failure does not require rerunning its qualification. The verifier
must track one attempt budget across resumes and reject duplicate or missing
site, setting, visit and time-block slots. A code or parameter change starts
a new lane generation, preserves the failed evidence, and is recorded in the
final analysis. It cannot rewrite old traces. The five settings must be
spread across time blocks so network drift is not mistaken for a defence
effect.

This is **not yet parallel capture**. The current host launcher holds one
global lifecycle lock for an entire invocation, and its ETF scheduler refuses
another active capture container. A separate host scheduling change, CPU and
memory partition, isolated result roots, and a two-lane throughput/fidelity
test are required before running containers concurrently. Parallelism may
reduce wall time, but two containers can also compete for CPU, disk and
network; no speedup is claimed until measured. Defence-scoped restart is
useful even with one lane running at a time.

## Immediate schedule and current milestone

| Window from 2 October | Work | Evidence to see |
|---|---|---|
| Days 0–2 | Finish portable raw source/profile, cheap HTTP/3 survey, and reuse of v147 for a full multi-origin trace. | A sealed diagnostic result and candidate-yield report. |
| Days 1–4 | Prepare ten live classes, qualify their chaff, and run all 50 diagnostic site-setting visits. | Ten site decisions and 50 individually verified zero-credit traces. |
| Days 3–7 | Freeze the final 50-site source plan and begin the first formal time block. | First accepted formal receipt; exact denominator and attempted failures reported. |
| During capture | Measure one lane, then test two isolated lanes and enable parallel work only if fidelity and throughput both hold. | Per-lane results and an honest measured speedup. |

The target date is conditional. The [project ledger](../PROJECT.md) and
[evidence index](EVIDENCE-INDEX.md) distinguish completed diagnostic evidence
from accepted formal samples.

The first one-site five-setting diagnostic has since sealed as a valid but
incomplete **3/5** on a historical three-origin workload. Undefended, FRONT
and Tamaraw passed; BuFLO failed on its first timed send, and CS-BuFLO later
hit a QUIC idle timeout. All five remain **zero-credit** for this study. The
[rapid capture path](RAPID-CAPTURE-PATH.md) tracks the targeted follow-up.
A patched CS-BuFLO release client completed a direct zero-credit visit, but
its proposed host response qualification did not run because the patched
binary lacked a matching clean Rust source commit and sidecar provenance.
There is no new independently verified CS-BuFLO host trace. The 50-site yield
and formal launch prerequisites remain unproven; **0/16,000 formal traces**
are accepted.
