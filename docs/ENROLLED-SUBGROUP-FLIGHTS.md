# Independent selected-class flights

The public class-mode `stage` and rolling `plan` commands accept
`--class-indices 17` or an ordered vector such as `--class-indices 17 18`.
Indices must be distinct members of the exact current enrollment batch and
retain enrollment order. Omitting the option preserves the whole-tail route.
This first version supports serial selected-input flights with the existing
homogeneous batch caps. Ordinary-only renewal and scheduling capsules are
explicitly refused with a subgroup; their existing routes remain unchanged.

The `enrolled_subgroup` control binds the original enrollment bytes, batch
ordinal, class indices, candidate/workload identities and complete class-record
digests. Setup, canary and formal plans retain that same control. The canary
and formal group must agree exactly. Each selected workload keeps its complete
request graph, repeated headers, dependencies, origins and existing seven
capture limits. Original enrollment and unselected-peer dependencies remain
transported. Selecting a peer grants no new admission or trace credit.

## Root operating sequence

Lab `10e79fa8` publishes this feature. Use a matching installed Source/runtime
for each new flight. The c24 compiled client can be reused by the existing
cached packaging route; the HOST checks claim no installed runtime or physical
qualification.

For the original b0005 class 17, create a fresh flight namespace and append
`--class-indices 17` to the existing public `tools/rapid_class_mode_flight.py
stage` command. Retain the original enrollment, current canonical/runtime,
campaign seed, complete-body policy and fixed TAM8192 policy. With TAM8192,
retain `--renew-selected-inputs`; it reopens the unchanged retained GET proof.
No physical GET or new enrollment is required.

Run the emitted finalize, preamble, qualification, preflight, canary capture,
deep and readiness steps in their existing order. By default, qualification requires
the complete 120-response identity proof for the selected workload. The explicit
[fifteen-completion AEL prerequisite](AEL-FIFTEEN-QUALIFICATION.md) has its own
fresh Native proof and exact identity-header requirement. The emitted
public rolling-plan command includes the same `--class-indices 17` selection.
It refuses a canary or named qualification group for different workloads.
Run and independently verify a fresh claimed formal lane using that plan.

### Two peers from one enrollment batch

Give each selected peer a distinct `stage --name` and fresh `--output` beneath
the declared data root. Each stage then receives its own execution root and
campaign directory. The emitted `plan --evidence-root` still points to the
shared original study root because that root owns the enrollment policy. For
physical `launch`, `complete-lane` and `verify-lane`, pass a separate fresh
`--evidence-root` for each peer. The same textual b0005 lane name can then be
used in both roots without claiming either peer's files or result namespace.

The two-peer HOST check exercised both plans, original lane-intent writers,
public launch parsing and deep-check command construction in separate roots.
It used controlled qualification, canary and installed-runtime boundaries;
it produced no captured lane or accepted trace. Actual formal credit still
requires each peer's own current qualification, canary, physical result and
successful independent deep closure.

Keep the original two-site qualification failure and its passing sidecar as
history. A fresh single-site proof must close before this new flight proceeds.
Class 18 remains enrolled with its original full 66-resource graph; class 17
retains all 58 resources. Recover each class using its genuine remaining slot
vector. Selection does not reserve or credit logical slots and does not change
the final 50 × 5 × 64 target.

## Existing target authority

The target reader's 13 relevant modules are byte and mode unchanged by this
feature. A read-only metadata check authenticated the original target26 and
progress40 artifacts, their producer/reader roles and both b0005 graph records;
the later target31 extension retained those forty accepted rows. That check
replayed no raw/deep proof and granted no trace credit.

After genuine peer closures with matching clean module and installed measurement
Source, use the public `tools/rapid_chunk_partial_lane.py bind-source` command
with that actual Source and canonical runtime. A separate module-overlay
registration is needed only for a genuinely different module/runtime pair
supported by its explicit publication and reader contract; an arbitrary current
publication closure cannot substitute for that contract. Feed the original
closure references and matching Source registration to the fixed target's
public `audit-complete`, then `append-progress`, and eventually `publish-final`.
That reader selects by registered class, condition and logical visit, with
separate physical sample identities. Do not use the older rolling
`publish-manifest` or epoch corpus route to aggregate the two peers: those
readers refuse their repeated textual lane name. Historical TAM32 remains
separate from the fixed TAM8192 target numerator.
