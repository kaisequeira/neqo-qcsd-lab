# Retrying a complete site with a larger response budget

## Why this path exists

One original-catalogue GET finished its Native process successfully, but an
individual response reached the old 16 MiB cap before its body was complete.
That is an engineering limit, not evidence that the site is scientifically
ineligible. Its partial run remains preserved without admission or capture
credit. A fresh retry keeps the same catalogue position, every resource and
dependency, all safe request headers and exact URL/query bytes.

## Limits

| Class epoch | Maximum individual response | Packet recording | Ordinary GET timeout |
| --- | ---: | ---: | ---: |
| Existing original classes | 16 MiB | 64 MiB | 120 seconds |
| Newly admitted budget-successor classes | 64 MiB | 256 MiB | 120 seconds |

Each class uses its epoch's response and recording limits across all five
settings. A batch must have one homogeneous limit tuple. Split batches at a
budget boundary; changing limits never discards a resource or response.
The explicitly selected BuFLO200 setting retains its separately declared
traffic-duration timeout while keeping the same response and recording caps.

## Public continuation

Use [rapid_static_budget_successor.py](../tools/rapid_static_budget_successor.py)
to declare the prospective epoch from the immutable original context and its
genuine response-limit attempt. The original GET producer remains unchanged.
Run and independently verify a new full GET in the declared child context,
then use that producer's public `admit` and `verify-terminal` commands.

The bound Core's wrapper-manifest writer requires a candidate directory.
[rapid_static_budget_capture.py](../tools/rapid_static_budget_capture.py) provides
the authenticated, create-only directory claim before invoking unchanged Core:

```sh
python3 -B tools/rapid_static_budget_capture.py account-terminal \
  --context /absolute/path/to/budget-context --position 53
```

Only a genuine closed child terminal can reach that claim. Repeated, missing,
linked or unfinished namespaces fail. A failed publication remains evidence
and requires a separately recorded recovery; it is never overwritten.

The existing rolling study and enrollment commands accept this context as a
successor. Its identity retains the original study's candidate IDs, frozen
order, existing class indices and final target of **50 × 5 × 64 = 16,000**.
Capture plans derive caps from the authenticated selected manifests. The
study's original policy remains unchanged.

For separately discovered supplemental graphs, declare an explicit combined
selector using the budget context and the whole-graph context:

```sh
python3 -B tools/rapid_static_budget_capture.py declare-mixed-context \
  --context /absolute/path/to/fresh-mixed-context \
  --budget-context /absolute/path/to/budget-context \
  --supplement-context /absolute/path/to/whole-graph-context
```

This selector preserves the original catalogue first and appends the genuinely
declared supplemental queue. It does not turn discovery into GET eligibility.
The supplemental graph needs its own independently verified complete GET and
public admission, as described in [WHOLE-GRAPH-SUPPLEMENT.md](WHOLE-GRAPH-SUPPLEMENT.md).
Whole-graph classes currently retain the original 16/64 MiB limits.

FRONT/BuFLO amendments have a separate typed budget-selector declaration. It
binds the current actual capture Source/image/client, original roles and
proofs, complete graphs, homogeneous caps and fixed traffic artifacts. Fresh
current response qualification and the setting's full canary/deep check remain
necessary. The compiled client can be reused in a thin Lab installation when
its exact bytes and Native Source match; no new Native implementation is added.

## Existing evidence and remaining proof

Earlier formal slots keep their original receipts, study identity and Source.
They gain no current qualification or canary authority. Reopen historical
closures under their original frozen Source/image. A final corpus combining
epochs needs Source-scoped verification for each closure, or an explicitly
registered aggregate index; this adapter does not invent that bridge.

HOST tests cover genuine emitter-contract GET/admission/wrapper reconstruction,
all-five campaign caps, mixed-cap refusal before publication, both original and
whole-graph roles, repeated URL occurrences/non-star dependencies, source and
recording tampering, and immutable raw-input fences. These fixtures grant no
physical admission or formal trace credit. Installed new-role canaries and
capture/deep checks must still run. Existing parallel capsules deliberately
refuse the new budget roles pending a separately typed scheduling extension.

## Validation cost

Core002 stays byte-identical for already declared contexts. Its full prefix and
retained-attempt validation can be expensive and is repeated by its public
validators. This adapter does not introduce a persistent cache or suppress
those checks. Capture controls use the existing operation-local facts/fences;
any further optimization must retain fresh raw checks before effects and after
ownership waits. Current qualification is per selected batch/setting, with no
global browser stability or 110-vector prerequisite.
