# Fixed 200-second BuFLO budget

This prospective option keeps 1,200-byte cells, the 20-millisecond cadence,
the strict five-millisecond physical outgoing window and the selected incoming
policy. It extends the per-direction event budget from 6,000 to 10,000 cells.
It allows no omitted cells and remains a client-only QUIC adaptation.

The exact parameter file is
[buflo-duration200.json](../config/defense-params/buflo-duration200.json), with
[candidate provenance](../config/defense-params/buflo-duration200.json.provenance.json).
The historical `buflo-live.json` and its interpretation remain unchanged.
The new Native optional policy is `rapid-v6-fixed-200s-duration-budget-v1`.

## Evidence required

[buflo_duration_budget.py](../src/qcsd_lab/buflo_duration_budget.py) validates
the fixed tuple: schema 1, 20,000 µs interval, 10,000,000 µs minimum duration,
1,200-byte packets, 10,000 events and 200,000,000 µs budget. An actual run must
retain the matching `defense_parameters.buflo_duration_budget` object. Its
kind, path, resolved defense and SHA-256 must agree with the exact parsed
parameter bytes. Frozen sample parameter files are reopened independently.
Counts or a longer timeout cannot select the policy.

The fidelity branch permits at most 10,000 opportunities in each direction
only after this join. Cadence, cell sizes, actual terminal state, credit
ownership, physical clocks, packets, application completeness and deep
verification keep their existing requirements. Old recordings cannot acquire
the new policy or source identity.

## Prospective capture integration

Before a new BuFLO flight, its typed capture-policy amendment must bind this
helper's source hash, the new parameter/provenance bytes, actual new Native
source/client/image and original complete static GET/preparation references.
It must select the new parameter filename and derive **240 seconds for the
client and 300 seconds for recording** only for BuFLO. All other settings
retain their original 120/180-second limits. The helper provides this explicit
limit derivation; it does not itself publish a plan or authorize a flight.

The original context, GET proof, admission terminal and full graph stay intact.
The existing static adapter and lane/readiness traffic inventories need an
explicit prospective duration branch. Do not replace the historical global
BuFLO traffic hash. A fresh current qualification and affected-setting canary
must prove the actual derived workload and budget. Healthy ordinary/Tamaraw
lanes need no BuFLO repair or global requalification.

## Common-five body headroom

The separately named prospective final-cohort screen is
`rapid-v6-common-five-complete-get-body-at-most-10000000-v1`. It compares the
actual complete ordinary-GET body sum with 10,000,000 bytes. This is selection
headroom against 12,000,000 nominal receive-credit bytes; framing, control
traffic, padding and variable responses still need actual full-graph proof.
It does not retroactively reject an original admission, remove any resource,
or establish capture viability. Until a final-cohort authority selects it,
this helper grants no cohort or capture credit.

## Verification scope

[Focused tests](../tests/test_buflo_duration_budget.py) exercise real public
parameter/provenance loading, legacy bounds, frozen-byte/raw receipt joins,
typed mutations, complete schedule boundaries and mode-specific limit
derivation. They compare the declared tuple with the exact held Native source
as a text oracle. These are HOST checks only. Native compilation, installation,
fresh qualification, canary/deep and formal capture are separate actual steps.
