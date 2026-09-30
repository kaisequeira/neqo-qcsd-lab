# Class-study timeline and estimate assumptions

Planning snapshot: **30 September 2026, Australia/Sydney**. This page explains
the time estimates for reaching and completing the 16,000-sample defense study.
It is a planning model, not evidence that a gate has passed. Read the
[current ledger](../PROJECT.md) for accepted counters, the
[capture-readiness guide](CAPTURE-READINESS.md) for the evidence required at
each gate, and the [runbook](CLASS-STUDY.md) for the actual command sequence.
The checked-in [study contract](../config/class-study/v1/study.json) and its
validators determine what may be accepted.

## What the clock includes

The formal endpoint is **100 classes × 20 visits × eight conditions = 16,000
accepted formal samples**. Ten blocks also require **100 undefended canaries
each**, so the final capture schedule contains **17,000 accepted cells**.
Acquisition, pilot and final fitting, qualification and the 900-cell
certification precede that schedule and do not contribute formal samples.
The source-bound Docker gates and capture stages run serially under the
registered execution rules. The table below assumes no unapproved parallel
capture, skipped gate, reused historical authority, or post-hoc promotion of
an attempt.

The starting point for every relative day below is the **next clean source
freeze**. V129 passed build, pinned CDP, all 110 browser vectors and its
acquisition-only authority on its historical source. Its acquisition watcher
then stopped with zero accepted classes. The prospective schema-11 HTTP/3
screen and redirect fix have no new execution authority. The next execution
needs the allocator's next unused cohort after source freeze; the cohort
number must be checked again before launch.

## Stage-by-stage critical path

“Proxy” below means an arithmetic illustration based on the older five-class
campaign's **62.73 seconds of wall time per accepted sample**. Its workloads,
modes and operating conditions differ from this study. These proxy values are
neither measured durations for the new stage nor promises of continuous
throughput. Counts are required accepted outputs unless a row says otherwise.

| Order | Gate and work | Estimate from the next clean freeze | Basis and limit |
|---:|---|---:|---|
| 1 | No-cache build, pinned CDP, 110 browser-egress vectors and acquisition-only authority | **About 9–10 hours** | Last desktop cohort measured 1h05m26s for build, 7h38m54s for browser qualification and 11m25s for acquisition correctness, plus CDP, authority and handoff time. A failure requires diagnosis and fresh source/cohort as applicable. |
| 2 | Screen selected-page request-origin HTTP/3 reachability, acquire the first 24 eligible classes in each of five strata from the 600-candidate search pool; verify completion and assemble the 120-class pilot | **5h29m ideal baseline-to-repeat lower bound**, or about **5h59m** if each batch terminates near five minutes; screening and assembly extra | Schema 11 retains two real prepared observations with dispatch windows near 30 seconds and five minutes after a separate pre-baseline screen. These projections assume all candidates survive, two per action, zero page-work and screening duration, and prompt terminal release. Rejections, slow pages and recovery extend it. |
| 3 | Full defense foundation on the same source/build lineage: reference/code gates, 12 timing-stress visits, 18 nine-mode regression samples and 160 controlled samples | **Unmeasured**; 190 launches would be **3h19m** at the old proxy, plus reference, code and verification | The 190-count illustration does not estimate the source and reference checks. Acquisition-only authority cannot replace this foundation for fitting or capture. |
| 4 | Pilot fitting: 120 classes × two visits × two policies = 480 | **8h22m proxy** | At 62.73 seconds per accepted cell; no new-cohort rate yet. |
| 5 | Pilot chaff/prefix qualification: 120 × six = 720 | **12h33m proxy** | Qualification work may have a different duration from old formal captures. |
| 6 | Pilot nine-mode compatibility: 120 × nine = 1,080 | **18h49m proxy** | Also establishes qualified Walkie-Talkie pair eligibility. |
| 7 | Select and assemble 100 final classes, 20 per stratum, with 20 reserves and the required qualified pair graph | **Unmeasured** | Selection and graph verification are gates; no time has been measured on the new cohort. |
| 8 | Final fitting: 100 × ten visits × two policies = 2,000 | **34h51m proxy** | The final parameters must use the frozen cohort, separate from formal visits. |
| 9 | Final full qualification: 100 × six = 600 | **10h27m proxy** | Requires the final parameters and complete graphs. |
| 10 | First-launch certification: 100 × nine modes = 900 | **15h41m proxy** | All 900 accepted checks are required. This is the first useful new-cohort measurement of per-mode time, failure rate and evidence bytes. |
| 11 | Readiness attestation and historical pre-snapshot | **Unmeasured** | Both must verify before the first canary. |
| 12 | Ten pairs of 100 canaries followed by 1,600 formal samples | **29h37m per pair; 12d8h14m for all 17,000 cells**, at the old proxy | The historical final block instead averaged 130.89 seconds per cell, which would make these 17,000 cells **25d18h5m** before additional overhead. Each block must seal before its accepted numerator advances. |
| 13 | Historical post-snapshot, handoff, evaluation, comparison and final attestation | **Unmeasured** | These close the thesis evidence and validation claim after capture; they are outside the 16,000-cell acquisition clock. |

Rows 4–6 total **2,280 pilot executions**, or **39h44m** at the old proxy.
Rows 8–10 total **3,500 final executions**, or **60h59m** at that proxy. Thus
the illustrated pre-formal fitting, qualification, compatibility and
certification work totals **5,780 executions and about 100h43m**. The 190
foundation launches, page acquisition, selection, attestations and failures
are additional. The registered work counts are explained in the
[capture-readiness guide](CAPTURE-READINESS.md#defense-foundation-pilot-and-final-cohort).

## Calendar interpretation

If the new run matches every favorable assumption above, the arithmetic is
roughly **9 hours** of fresh proof + **5½ hours** of acquisition + **3⅓ hours**
for 190 foundation launches + **100¾ hours** of pre-formal executions. That
places the first formal cell around **day 5 after source freeze**. At the old
overall 62.73-second wall rate, the 17,000 canary/formal cells then take
**12.34 more days**, placing the last cell around **day 17–18**. This excludes
unmeasured gate, selection, sealing, analysis and repair time. It is a
conditional rate illustration, **not a committed completion date**.

The older campaign's final block ran at **130.89 seconds per sample**. At that
rate the new 17,000-cell capture alone takes **25.75 days**, so completion
within three weeks is impossible even if readiness were immediate. The
conservative 151-second per-cell value printed by current preflight is a
*reporting floor*, not an observed capture rate or launch blocker. It is not
a substitute for the 900-cell certification measurement.

To gauge the three-week objective, use the total **17,000** cells, including
canaries, and count wall time continuously. These thresholds include all
failures, retries, idle periods and block overhead:

| Time spent reaching readiness | Time left in a 21-day window | Mean wall time allowed per accepted cell to finish all 17,000 |
|---:|---:|---:|
| 5 days | 16 days | **81.3 seconds** |
| 7 days | 14 days | **71.2 seconds** |
| 10 days | 11 days | **55.9 seconds** |

If the practical objective is instead to be **far through** the formal run,
five complete blocks represent **500 canaries and 8,000 formal samples**.
That is 8,500 accepted cells. With readiness on day 7, five blocks by day 21
require an average no slower than **142.3 seconds per accepted cell**; with
readiness on day 10, the limit is **111.8 seconds**. Reaching eight thousand
attempts without five sealed blocks does not meet this example milestone.

## Updating the estimate with actual evidence

After each immutable receipt, replace a proxy with the observed wall duration
and accepted count for that stage. After certification, compute the accepted
rate from the full 900-cell first-launch run, broken down by mode if useful.
At each sealed block, use its wall span from first canary to final verified
receipt, including retries and pauses. A simple remaining-time estimate is:

```text
remaining wall time = remaining required cells × observed wall seconds per accepted cell
```

Add known gate, sealing and analysis work separately. Report both an overall
rate and a recent-block rate because the historical run slowed materially in
its final block. Track free space against the preflight's projected bytes and
the registered three-times-free-space rule. If a gate fails or source changes,
preserve its evidence and recalculate from the new cohort's actual start;
do not count an earlier source's receipt as progress under the new contract.
