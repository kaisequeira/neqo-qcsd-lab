# Fresh admission with physical Tamaraw credit ownership

Selection v10 keeps **50 sites × five conditions × 64 visits = 16,000 formal
traces**. The conditions remain undefended, FRONT, Tamaraw, BuFLO and CS-BuFLO.
Every site's complete resource and origin graph remains required. The v9 BuFLO
ACK startup policy stays unchanged.

The [v10 declaration](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v10.json)
is finalized at **2026-10-03T10:28:08Z**. Its exact frozen
[v9 parent](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v9.json)
has SHA-256 `a9469ba89ddfa3cf1d36352f40e6f1b2a42eec39f114d7f9548fdfa9e03401ca`.
The new optional preparation field is
`tamaraw_capture_policy=rapid-v5-tamaraw-owned-retry-outgoing-10000us-v1`.
The [preparer](../src/qcsd_lab/prepare.py) validates this value before a live
operation and writes it before sealing the workload. Fresh admission also
requires the registered variable primary document, terminal application
response, approved-origin chaff and BuFLO V2 policies. Admission independently
reopens the sealed manifest, full resource graph and all three raw preparation
replay ledgers. An absent Tamaraw flag retains the legacy contract.

## Physical receive credit and bounded outgoing timing

Tamaraw retains 1,200 byte cells, 5 ms incoming and 20 ms outgoing periods, and
padding counts divisible by 100. The control interval stays 5 ms and
`drop_unsatisfied_events` stays false. The new policy permits partial owned
receive-credit releases to remain pending and retry. It requires actual
whole-cell physical advertisement and consumption receipts. Slotless parser
reads cannot be reclassified as a scheduled advertisement. An advertised owned
parser lease retired at FIN remains retired credit and cannot count as consumed.

Outgoing shaped cells use a prospective **half-open 10 ms release window**.
The [fidelity validator](../src/qcsd_lab/fidelity.py) reopens actual successful
UDP handoff rows in `packets.csv`, binds each unique slot and endpoint to its
outgoing schedule row, and requires all 1,200 bytes. It compares the full
microsecond timestamp interval against the exact defense-start clock and
nominal target. Registration time, a later parser read or a fitted PCAP clock
cannot supply this timing proof. The raw historical 5 ms violation count is
retained beside the new 10 ms measurements. Ordinary direct capture correlation
and all full-cell credit checks remain required.

The Native receipt must contain the exact twelve-field source-bound
`tamaraw_capture_policy` marker. The
[acceptance helper](../src/qcsd_lab/capture_acceptance_policy.py) rejects malformed
types, changed parameters, unbound policy markers and markers on other modes.
The four other conditions omit the Tamaraw marker and retain their existing
behavior. This client-only QUIC adaptation claims neither paper equivalence
nor scientific credit from the marker.

## Fresh source and receipts

1. Freeze a clean current Lab checkout, its pinned policy-capable Native source,
   actual preparation image metadata and actual client bytes. Initialize a new
   acquisition root with [`rapid_acquire.py init`](../tools/rapid_acquire.py)
   and the v10 declaration. Source implementation and tests alone establish no
   runtime or live proof.
2. Reuse the exact **10-module preparation** and **21-module unsuccessful-attempt**
   inventory sets introduced by v8. They already include the capture acceptance
   helper; older inventory sets remain unchanged.
3. Obtain fresh controlled observations and complete graph preparation after
   the declaration time. The [coordinator](../tools/rapid_acquisition_control.py)
   uses `private-frozen-v10-tamaraw-owned-retry-policy-ordered-root-log-registry-v10`
   and requires both exact preparation flags. Select the first 50 admitted sites
   in the frozen order.
4. Complete ordinary qualification, capture and
   [deep verification](../src/qcsd_lab/verification.py) with those source and
   runtime bindings. The [capture planner](../src/qcsd_lab/rapid_capture_plan.py)
   keeps the five-condition, 16,000-trace grid. Admission grants no capture or
   accepted scientific trace credit.

All v1–v9 declarations, failures, admissions and cohorts retain their historical
bytes, source and authority. A policy change requires fresh preparation and
downstream proof. Do not modify an admitted manifest or promote an old failed
trace. Historical specialized study and fitting contracts stay separate.

Focused coverage is in [physical timing and credit tests](../tests/test_capture_tamaraw_policy.py),
[fresh preparation and admission tests](../tests/test_rapid_tamaraw_admission.py),
and [cohort and planner tests](../tests/test_rapid_selection_amendment.py).
