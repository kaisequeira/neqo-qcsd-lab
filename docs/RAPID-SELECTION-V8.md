# Fresh admission with the declared BuFLO tolerance

Selection v8 keeps the rapid study at **50 sites × five conditions × 64 visits =
16,000 formal traces**. The conditions remain undefended, FRONT, Tamaraw,
BuFLO and CS-BuFLO. It changes how one already declared capture acceptance
rule becomes part of each site's prepared workload.

The [v8 declaration](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v8.json)
was published prospectively at **2026-10-03T06:59:59.498734Z**, after its frozen
[v7 parent](../config/curated-sources/crux73-tranco600-rapid-v5-selection-v7.json).
It explicitly requires
`buflo_incoming_credit_release_policy=rapid-v5-half-period-10000us-v1`.
The preparer validates and writes this field before sealing the workload hash.
Admission independently reopens the workload, complete graph, probe evidence
and all three complete native replay ledgers. Its receipt and the final cohort
must bind the same policy. A missing, null or unknown prepared value fails.

## What the rule permits

For fixed BuFLO only, the native source-bound receipt may declare a **10 ms
incoming credit release window**. The traffic still uses 1,200 byte cells at
20 ms intervals. The outgoing deadline remains 5 ms. The other four conditions
gain no BuFLO window or native marker. The existing
[capture acceptance validator](../src/qcsd_lab/capture_acceptance_policy.py)
checks the exact marker and its preparation binding.

This prospective rule reflects the observed incoming scheduling variation. It
does not ignore failed slots, missing packets, shortened responses or incomplete
graphs. Complete live discovery, the existing variable primary document rule,
strict identities for all other resources and approved-origin auxiliary chaff
qualification continue to apply.

## How to use the fresh path

1. Freeze a clean current Lab checkout, its pinned Native source, actual prepare
   image metadata and actual client bytes. Supply the new declaration to
   [`rapid_acquire.py init`](../tools/rapid_acquire.py) in a new acquisition root.
2. Bind the **10-module preparation** and **21-module unsuccessful-attempt**
   inventories. They add `qcsd_lab.capture_acceptance_policy` to v7's inventories;
   the old inventory sets remain unchanged for older declarations.
3. Collect current controlled root/page observations and complete graph
   preparations through the ordinary admission API. The
   [host coordinator](../tools/rapid_acquisition_control.py) accepts the distinct
   v8 registry and keeps its declared page budget and retained failures.
4. Select the first 50 admitted sites in the frozen candidate order, then use
   the existing qualification, capture planning and recoverable class/lane
   evidence paths. Admission gives no formal trace credit; ordinary deep
   verification and final study receipts remain required.

Old acquisition contexts, failed attempts, admissions and cohorts keep their
original source, image, Native bytes and policy. They receive no v8 authority.
Do not add the flag to an admitted workload or relabel an old receipt. Fresh v8
preparations establish their own workload hashes and lineage. Runtime checks
may truthfully reuse an identical Native build artifact when its bytes and
source are independently proven; a Python change alone does not require a new
Native compilation.
