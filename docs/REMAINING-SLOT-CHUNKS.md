# Remaining formal slots in bounded chunks

This prospective control extension collects up to sixteen visits per class in
one recoverable serial lane. The study remains **50 classes × 5 settings × 64
visits = 16,000 formal traces**. Original four-visit campaigns, accepted slots,
qualification, Source and runtime labels retain their original bytes and meaning.

The new planner first reopens a hash-bound Root progress record, its original
installed deep-operation records, launch/plan identities and sealed experiment
visit mapping. Those records exclude already accepted logical slots from the
new plan; they do not award another trace or authorize current capture.

## Public path

Use a freshly qualified and readied **current serial four-visit base spec** for
the selected one to five classes. Supply only settings whose own full-site
canary is ready. The new policy records that exact base spec, membership,
profiles, complete graphs, caps, Source and runtime.

```sh
python -m tools.rapid_rolling_capture chunk-policy \
  --spec CURRENT_SERIAL_SPEC.json \
  --prior-progress ORIGINAL_ROOT_PROGRESS.json \
  --mode tamaraw --maximum-visits 16 \
  --output STUDY/remaining-slot-policy.json

python -m tools.rapid_rolling_capture chunk-plan \
  --spec CURRENT_SERIAL_SPEC.json \
  --slot-chunk-policy STUDY/remaining-slot-policy.json \
  --output STUDY/remaining-slot-plan.json \
  --spec-output STUDY/remaining-slot-spec.json
```

Both outputs are create-only. The policy and plan must belong to the enrollment
study. The resulting spec uses the existing public `launch`, `complete-lane`,
`verify-lane` and immediate `successor` paths. Capture ownership, DNS isolation,
physical deadlines, full resource delivery, independent deep checks and raw
durability remain enforced. The new control action closes exact Source and raw
dependency fences before publication and recovery effects.

## Slot identity and recovery

| Prior accepted logical slots | New `(start, count)` chunks |
| --- | --- |
| None | `(0,16)`, `(16,16)`, `(32,16)`, `(48,16)` |
| `0..3` | `(4,16)`, `(20,16)`, `(36,16)`, `(52,12)` |
| `8..31` | `(0,8)`, `(32,16)`, `(48,16)` |

Each lane records its explicit start and count. Raw experiment visits remain
local `0..count-1`; final logical visits are `start + local_visit`. A generation
`g02` retains the exact graph, inputs and slot vector. The existing lineage
guards require the immediate failed predecessor and refuse a completed peer or
skipped generation. An interrupted lane's unaccepted samples receive no credit.

Named qualification membership remains exact. Classes in one base group must
have identical remaining-slot vectors for a selected setting. Use a separately
authenticated singleton or cohort base plan for a different vector. The
planner refuses before creating campaigns instead of changing a named group.

The historical Root progress type accepts original four-visit identities only.
Future mixed old/chunk counters use
`root-reopened-remaining-slot-chunk-scientific-progress-v1`, basic accepted-slot
rows `{candidate_id, class_index, mode, visit}`, and the same independently
closed lane references. The reader derives old offsets from registered blocks
and new offsets from each sealed chunk policy/plan. It rejects moved slots,
duplicate slots, changed Source, wrong counts and an old progress type claiming
new chunk identity.

## Limits and evidence scope

The selected group's complete graphs, request headers, traffic profiles, body
policy, qualification witness and response/recording caps are inherited from
its authenticated current base. No fitting or Native change is introduced.
Old 16 MiB response / 64 MiB recording and explicit 64 MiB / 256 MiB groups
retain their own limits. A prospective runtime must install the exact chunk
control Source; this authoring package grants no installed or physical success.

The launcher recognizes the exact chunk namespace only for a fresh rolling
run. Its installed typed guard checks the registered start/count, full workload
count and existing profile/request/defense contract, then the existing v6
preflight reopens the sealed plan and intent. Generic chunk resume remains
refused; recovery uses the public immediate-generation successor path.

The prospective launcher changes `qcsd-lab`, so existing qualification
compatibility refuses reuse across that changed Source. Use fresh current
qualification after installation. Original Source715 and e8 groups retain
their producer labels; this extension does not widen their reuse authority.

Focused HOST cases exercise slot bounds, all five fixed settings, full-graph
rendering, caps, public plan/spec parsing, Source/raw mutation refusal and
failed-only recovery. A genuine retained SCI36 record separately verifies the
original sealed-plan/deep-output/experiment slot mapping. Qualification and
actuation boundaries in the synthetic current fixtures are explicitly mocked.
The focused launcher cases execute the actual Bash selector and installed
inline campaign predicate without Docker or Native traffic.

The first implementation supports serial lanes. Existing parallel capsules
retain their four-visit contracts and reject chunk plans; a distinct chunk
capsule is still required before parallel chunk capture. Existing same-study
corpus verification maps chunk offsets, but cross-study final aggregation of
carried original and additive/per-class studies still needs a separate reader
that reopens each original execution epoch. Neither limitation blocks current
serial capture. Sixteen-visit lanes reduce the number of startup/deep boundaries
for virgin classes from sixteen to four per setting; physical throughput has
not yet been measured on this new Source.

See [CLASS-STUDY.md](CLASS-STUDY.md) and
[EVIDENCE-INDEX.md](EVIDENCE-INDEX.md) for the current study and evidence roles.
