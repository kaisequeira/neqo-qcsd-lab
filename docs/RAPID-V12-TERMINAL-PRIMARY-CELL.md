# V12: complete primary responses with one final partial cell

The target remains **50 sites × five modes × 64 visits = 16,000 accepted
formal traces**. V12 keeps the full resource graph, all origins, the V11 traffic
settings, and the existing recoverable capture lanes.

## Why this change is needed

The fresh V11 Poki checks stopped with an incomplete primary response. The
primary stream had consumed 1,015 bytes, including headers and 457 body bytes.
A scheduled cell then supplied two bytes of owned parser continuation, raising
the advertised stream limit to 1,018. That advertisement was observed on the
physical path, but the primary produced no further progress before timeout.
This observation does not establish the remote server's internal cause.

V12 prospectively gives the uniquely bound primary stream a full **due cell's
owned quantum** at an unknown/pristine DATA boundary with the matching blocked
frontier. This uses the existing scheduled ownership ledger. The unowned
metadata allowance remains 1,000 bytes; the other resources and default
continuation path keep their existing behavior.

A complete variable-length response can end inside its final owned cell. V12
therefore permits one strictly evidenced terminal partial incoming cell:

| Mode | Actual scheduled cell size | Maximum terminal partial cells |
| --- | ---: | ---: |
| Tamaraw | 1,200 bytes | 1 |
| BuFLO | 1,200 bytes | 1 |
| CS-BuFLO | 600 bytes | 1 |

The cell size is checked against the actual resolved defense and Native
receipt. Undefended and FRONT runs carry no terminal-cell marker.

## What is required for acceptance

- The policy is declared before live execution and included in preparation
  before the immutable workload hash is written.
- The stream is the unique actual endpoint/stream dispatched for resource0.
- The primary has an actual FIN, a complete nonempty body, and a 2xx status.
- The requested and physically advertised bytes both equal the full cell.
- Consumed and retired bytes are both positive and sum exactly to the cell.
- Original dispatch, stream opening, owned receive ranges, advertisements,
  DATA/body length, raw reads, and FIN clocks reproduce the reported split.
- The whole-run physical ledger agrees with those bytes and has no unresolved
  credit. Every other incoming cell remains complete; outgoing rules are unchanged.

The partial remains a raw `SlotMissed` with reason `ReceiveCreditRetired`.
It never becomes `SlotSatisfied`, full consumption, or credit for another
resource. CS-BuFLO's terminal and missed counters include it, while its full
counter excludes it. Its full advertisement remains physically recorded.

## Source and evidence binding

The preparation flag is `terminal_primary_partial_cell_policy`, with value
`rapid-v5-one-owned-terminal-primary-partial-incoming-cell-v1`. Native emits
the closed twelve-field policy marker only in the three paced modes. When a
partial occurs, `run.json` and one raw `terminal_primary_partial_cell` event
carry the same closed sixteen-field proof.

The raw stream-binding event records the actual resource0 lookup. The raw FIN
reduction event links the original FIN production identity to the controller's
actual reduction clock. The partial proof and missed schedule row use that
reduction clock; the earlier production clock remains recorded separately.

Intrinsic capture validation and ordinary deep verification both reopen this
source binding and the raw files. The amended private admission receipt and
final cohort retain the flag; all fifty sites must use the declared policy.
The V12 declaration inherits the exact published V11 parent. Earlier failed
runs and old preparations receive no new admission or capture credit.

## Interpretation and current limit

This is a recorded engineering adaptation, not a paper-equivalence claim.
Analysis can report the number of affected visits and actual retired bytes,
and can repeat comparisons excluding affected visits. The existing strict
defaults and old receipts retain their prior meaning.

Focused source tests exercise short-FIN ownership, advertisement and split
proofs; malformed/missing source markers; wrong resource, missing FIN,
duplicate partials, another miss and forged sums; complete preparation through
private admission; and the final fifty-site cohort and 16,000-slot planner.
Passing source tests does not count as live capture. The first fresh V12
canary must also complete ordinary collection and deep verification before
the long run starts.
