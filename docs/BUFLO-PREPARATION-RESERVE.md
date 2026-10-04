# Prospective BuFLO preparation reserve

This opt-in changes when the client may prepare a scheduled cell. It preserves
the existing physical traffic deadlines and admits no omitted cells. It is a
client adaptation, with no claim of paper equivalence.

The policy is
`rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1`.
It requires the existing ACK-start incoming policy and the complete rapid
application and qualified chaff contracts.

| Boundary | Opt-in rule |
| --- | --- |
| First tick | Selection, staging and dispatch confirmation finish before release. |
| Later ticks | Selection and a fresh dispatch confirmation finish before release plus 4 ms. |
| Outgoing physical enqueue, kernel TX and post-veth observation | Strictly before the unchanged release plus 5 ms deadline. |
| Incoming credit carrier | The existing bound 10 ms window remains unchanged. |
| Traffic settings | 20 ms cadence, 1,200-byte cells and every original resource remain unchanged. |
| ETF settings | SCM_TXTIME is release plus 10 ms; delta is 10 ms; deadline mode is false. |

The recorded 1 ms preparation reserve is the difference between the preparation
cutoff and the physical deadline. It does not guarantee that the host will meet
the deadline. Actual clocks, construction lateness, kernel timestamps, packet
identity and ordinary deep verification still decide acceptance. A late entry
records its actual zero wait; it does not claim a full 5 ms dwell.

## Explicit preparation API

Use the public selector before publishing a fresh capture input, hashing it or
qualifying it:

```python
from qcsd_lab.capture_acceptance_policy import (
    BUFLO_KERNEL_PREPARATION_POLICY,
    apply_buflo_kernel_preparation_policy,
)

capture_manifest = apply_buflo_kernel_preparation_policy(
    original_prepared_manifest,
    policy=BUFLO_KERNEL_PREPARATION_POLICY,
)
```

The selector validates the prepared manifest and returns a new object differing
only by `preparation.buflo_kernel_preparation_policy`. It preserves original
source labels, response evidence, resources, origins, request headers and
dependencies. Standard source/application evidence reopening is still required;
the selector itself grants no qualification, enrollment or trace credit.

Existing enrolled inputs and the supplied-static GET producer remain immutable.
A capture plan derived from those inputs needs a separately declared amendment
before it can use the new field. This API does not provide that amendment or
relax an existing plan's exact-input check.

## Evidence versions and current proof limits

The opt-in requires outer runner schema 21, raw kernel schema 12, protected wait
schema 3 and wait entry/failure schema 2. Each entry carries its exact
`preparation_deadline_tai_ns`; the raw receipt and native run carry the same
closed source-bound policy marker. Missing, mismatched or malformed fields fail.
The default remains raw schema 11 / runner schema 20 and its original cutoff.
Historical receipts retain their original interpretation.

A separately recorded Python UDP engineering probe demonstrated one 1,200-byte
packet enqueued about 1.572 ms after release and physically observed about
1.700 ms after release, inside the existing 5 ms window. This is feasibility
evidence for ETF/veth only. It provides no Native QUIC, capture readiness or
formal trace credit. This prospective implementation still requires focused
source checks, a matched installed runtime and an actual original-seed capture.
