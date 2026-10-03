# FRONT capture with a small, declared congestion allowance

The final target stays **50 websites × five settings × 64 visits = 16,000
formal traces**. The settings are undefended, FRONT, Tamaraw, BuFLO and
CS-BuFLO. Each website keeps its complete resource and origin graph. The
[Tamaraw policy from v10](RAPID-SELECTION-V10.md) and the
[BuFLO startup policy from v9](RAPID-SELECTION-V9.md) carry forward unchanged.

The [v11 declaration](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v11.json)
is finalized at **2026-10-03T12:04:59Z**, before new live observations.
Its exact [v10 parent](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v10.json)
has SHA-256 `57acfcb997307bb23a34b9d117376e50457659f3a85649cf79d575382798d119`.

## Why this change helps

The fresh v10 FRONT attempt completed all 260 resources in 8.157 seconds. It
failed the old rule because **one outgoing scheduled cell was missed for
`CongestionLimited`**, among 397 outgoing cells and 1,154 incoming cells. That
miss was recorded by the Native transport and had a matching schedule identity.
The original failed attempt remains a v10 failure.

The same attempt reported 71 incoming releases outside the historical 5 ms
window and 586 catch-up observations. Those measurements were already
diagnostics for FRONT; they did not cause its rejection. V11 keeps those raw
measurements and their original targets.

V11 permits a small, measured departure from an ideal FRONT padding schedule:
an outgoing cell may be omitted when the transport records congestion, with
**at most 1% of the outgoing scheduled cells omitted**. The exact rule is
`omitted_cells × 100 <= outgoing_scheduled_cells`. For example, 397 outgoing
cells permit at most three such omissions; 99 permit none. There is no rounding
up or automatic allowance of one cell.

This is a prospectively declared client implementation adaptation. Results
must report the actual omission rate, timing and overhead, and describe this
allowance in the thesis. It establishes neither paper equivalence nor
scientific trace credit by itself.

## What remains required for every FRONT trace

- A complete, successful application graph with every declared resource;
  primary document variation uses the existing explicit comparison policy.
- Actual 1,200-byte shaped outgoing packets, uniquely matched to satisfied
  schedule slots and endpoints. An omitted slot cannot have a fabricated packet.
- Every incoming scheduled cell fully advertised and consumed physically.
  Incoming misses, partial cells and missing credit evidence remain failures.
- Only the exact outgoing `CongestionLimited` reason may use the allowance.
  Pacing limits, deadline misses, aborts and other reasons remain failures.
- Each omission must have its matching raw Native `slot_missed` observation,
  with the same endpoint, slot, target, size, reason and production clock.
  Version 3 transport miss rows legitimately leave the packet composition and
  typed congestion columns empty; their real observation supplies the proof.
- Ordinary capture clock checks, packet correlation, immutable input hashes,
  response identity checks and deep verification remain required.

FRONT's fixed settings remain 900 client cells, 1,200 server cells, 1,200 bytes
per cell, peak parameters 0.1 and 2.5 seconds, a 5 ms control interval, a
1,200-byte maximum UDP payload, and `drop_unsatisfied_events=false`. The
traffic algorithm itself is unchanged. The allowance changes which measured
realizations can be admitted.

## How the policy is bound before capture

The [preparer](../src/qcsd_lab/prepare.py) accepts only
`front_capture_policy=rapid-v5-front-bounded-outgoing-congestion-omission-1pct-v1`.
It validates the declaration before discovery and records it before hashing and
sealing the workload. It requires the existing variable primary document,
completed terminal HTTP response and approved-origin chaff policies.

The Native runner reads that exact frozen source and emits a closed twelve-field
marker only for an actual FRONT run with the fixed settings. The
[acceptance helper](../src/qcsd_lab/capture_acceptance_policy.py) checks its exact
types and values. [Collection](../src/qcsd_lab/capture_session.py) binds the
marker to the actual prepared-source hash, while
[ordinary deep verification](../src/qcsd_lab/verification.py) reopens the frozen
prepared bytes and Native receipt. The
[fidelity validator](../src/qcsd_lab/fidelity.py) reopens the actual schedule,
events and packets, records the new proof separately, and retains the original
miss counter. An absent declaration keeps the strict historical behavior.
The four other modes emit no FRONT marker and receive no FRONT omission allowance.

Expected declarations use a fresh memo within each construction so the frozen
parent chain is built once per unique parent. Returned objects are independent
copies. Every new request still checks its actual receipt bytes, current loaded
contract and publication time; filesystem and evidence checks are not cached.

## Remaining route to the final collection

1. Freeze a clean Lab checkout with the policy-capable Native source and actual
   client/image metadata. Initialize a fresh acquisition root using
   [`rapid_acquire.py init`](../tools/rapid_acquire.py) and the v11 declaration.
   Source tests establish engineering compatibility; they grant no live credit.
2. Exercise fresh ordinary collection and sealed deep verification on a small
   complete website graph across the five settings. Diagnose a failure at that
   attempt before widening the run. Preserve failed attempts and their reason.
3. Prepare and admit fresh complete graphs in the declared order, selecting the
   first 50 eligible websites. Preparation independently reopens all three raw
   replay ledgers. The existing inventories remain **10 preparation modules**
   and **21 unsuccessful-attempt modules**, with the current helper hashes.
   The [coordinator](../tools/rapid_acquisition_control.py) uses registry
   `private-frozen-v11-front-congestion-omission-policy-ordered-root-log-registry-v11`.
4. Complete the ten-site, five-setting shakedown and required response-only
   qualification. These diagnostic visits have zero formal sample credit.
   Publish the final 50-site cohort and its
   [800 recoverable capture lanes](../src/qcsd_lab/rapid_capture_plan.py), each
   containing 20 traces, for the unchanged 16,000-trace total.

Historical declarations, admissions, cohorts and failed traces remain bound to
their original policies. Do not relabel an old failure as a v11 pass or edit an
admitted manifest. A source implementation, a unit fixture or this declaration
cannot establish that fresh live capture will succeed.

Coverage: [raw physical evidence and collection/deep seams](../tests/test_capture_front_policy.py),
[preparation and terminal admission](../tests/test_rapid_front_admission.py), and
[50-site cohort and planner binding](../tests/test_rapid_selection_amendment.py).
