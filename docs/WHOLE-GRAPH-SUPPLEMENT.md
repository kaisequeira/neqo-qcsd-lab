# Adding complete website graphs to the 50-site study

## Purpose and current limit

The supplied pool remains the first 87 candidates, with its original order,
resource lists and decisions. Additional websites come from the frozen catalogue
and are declared before discovery. Their complete observed resource graphs are
appended to that queue. A retry retains its original reserved position and failed
attempts.

The final target remains **50 eligible sites × five settings × 64 traces =
16,000 traces**. A discovered graph supplies an input, not an eligible class or a
formal trace. A new class requires a separately executed and independently
verified ordinary HTTP/3 GET of every request occurrence.

The first navigation-seeded discovery produced a 57-occurrence input. The
read-only adapter reopened all 57 occurrences, 11 approved origins, five repeated
URL occurrences and 54 resources with dependencies beyond the primary document.
This establishes input compatibility. Its complete GET, admission and formal
capture are separate steps and have not been established by that check.

## What is preserved

- Every resource occurrence, including repeated URLs, retains its ID.
- Every dependency edge, request header and URL query remains unchanged.
- The complete observed and approved origin lists remain bound to discovery.
- Original declarations, discovery passes, navigation records, failed attempts,
  GET process records and raw Native outputs remain independently reopenable.
- The five original static producer modules retain their original bytes and
  receipt meanings.

Eligibility cannot be obtained by trimming a failed resource or origin. An
actually closed discovery or GET failure can be accounted for with zero class
credit. A missing input, incomplete failure record or changed Source blocks
reopening rather than becoming a site rejection.

## Separate runtime identities

There are three roles:

1. **Discovery:** the actual browser image and its original Source export collect
   the complete graph. The versioned producer independently reopens navigation
   and graph evidence in an isolated Python interpreter.
2. **GET:** a new installed Lab image containing this adapter executes strict
   primary bootstrap, then the complete ordinary GET. Its clean Source, client,
   image and actual implementation receipt are bound separately from discovery.
3. **Formal capture:** the capture runtime, fixed traffic settings, named
   qualification and complete-site canary have their own current bindings.

The existing verified Native client can be reused in the new Lab installation.
This adapter does not change Rust, require a new Native compilation, or repeat
the historical 110-vector/browser stability sequence. An older image cannot
claim it has installed these new modules. Existing inspector projections also
cannot silently grant the new data role historical canary authority.

## Public sequence

All paths below are variables supplied by the operator's immutable plan. Use
absolute canonical paths without symlinks. Keep every destination fresh. The
runtime binding JSON is generated from the actual closed GET installation; it
must contain the Source/image/client identity expected by that installation.

### 1. Bind declared graph inputs and actual discovery failures on HOST

```sh
python3 tools/rapid_whole_graph_supplement.py context-init \
  --context "$supplement_context" \
  --original-context "$original_static_context" \
  --runtime-binding "$new_get_runtime_binding" \
  --discovery-plan "$original_discovery_plan" \
  --discovery-plan "$navigation_retry_plan" \
  --graph-input "$complete_graph_input"
```

Repeat `--graph-input` for other successful declared inputs and
`--failed-discovery` for candidates with independently closed failed discovery
records. Include earlier declaration plans in their original order. The retry
plan does not append another copy of its reserved candidates. Use
`--parent-context` only for a new append-only context that preserves all previous
graphs, failures, runtime bindings and immutable terminal decisions.

For each later catalogue batch, use the version 3 producer's `declare` command
before discovery. Its declaration reserves at most five previously unseen
catalogue identities in their frozen order, with a fixed 180-second discovery
budget. Version 3 retains both original batch histories, including all failed
attempts and the earlier successful graph. Add that new declaration after the
original and retry declarations; its candidates append after their reserved
positions. Discovery outcomes do not choose the next reservation.

### 2. Execute the new complete GET inside its declared installed image

```sh
python3 tools/rapid_whole_graph_supplement.py execute-get \
  --context "$supplement_context" --position "$declared_position" \
  --get-root "$fresh_get_root"
```

The installed environment must supply its exact `QCSD_LAB_IMAGE_DIGEST` and
`QCSD_LAB_SOURCE_METADATA`. HOST execution without those bindings is rejected
before output creation. The primary bootstrap retains its strict successful
HTML requirement. The full GET then follows every original occurrence and DAG
edge under the unchanged prospectively declared byte and timeout budgets.

Mount the context, exact external producer pair, discovery Source export and all
authenticated discovery records read-only. Only the new GET destination is
writable. Derive dependency roots with
`whole_graph_input.plan_roots` / `whole_graph_input.roots`; do not invent a broad
dataset mount or omit failed retry ancestry. Preserve the actual outer command,
start/completion and stdout/stderr records.

If the container GET destination differs from its HOST evidence path, publish a
typed `namespace` mapping from those actual closed outer records. Pass that
mapping to the verification/admission commands. The mapping authenticates the
original command and runtime rather than rewriting them.
For a closed failed Native phase, specify `namespace --failed-phase bootstrap`
or `--failed-phase full`; that mapping requires the actual nonzero outer status
and retains the failed inner process records.

### 3. Independently reopen, then admit or account for the actual failure

```sh
python3 tools/rapid_whole_graph_supplement.py verify-get \
  --context "$supplement_context" --position "$declared_position" \
  --get-root "$closed_get_root" --namespace "$closed_namespace"
python3 tools/rapid_whole_graph_supplement.py admit \
  --context "$supplement_context" --position "$declared_position" \
  --get-root "$closed_get_root" --namespace "$closed_namespace"
```

Omit `--namespace` when the execution and evidence roots are identical. Use
`defer` for an independently closed actual failure. With no `--get-root`, it
requires the candidate's bound failed discovery record; with a GET root, it
requires exact failed process/raw evidence or a completed GET that fails the
defined preparation properties. Successful eligible GETs cannot be relabeled
as deferrals.

### 4. Enroll in the existing rolling study

Use the public `rapid_rolling_capture.py enroll` command with the new context as
`--acquisition-root`. It retains the original study identity and ordered prefix.
Existing original decisions keep their original typed authority. New decisions
have their separate whole-graph authority. Enrollment can advance only through
accounted earlier candidates; missing earlier decisions cannot be skipped.

For a new study, `init-static` also accepts the additive context and retains the
original 50-site target and capture budgets. Enrollment, plan publication and
lane recovery use the existing public rolling APIs.

### 5. Fix the setting, qualify and capture the complete site

Original preparation supports serial plans for all five study modes. For the
prospective FRONT/BuFLO settings, the public `static-amendment` command dispatches
to a separate mixed-input declaration. It binds each workload's original data
role, original complete GET, every graph row, the current control Source and the
selected traffic policy before derived manifests and qualification runs exist.

Run the current setting's named qualification and full-site canary using that
exact current Source, client and derived workload. Complete independent deep
verification and readiness before publishing formal lane intents. The new
graphs do not receive qualification or canary credit from the retained
original-only study.

The existing worker and deep transport derive mounts through
`static_evidence_transport.manifest_roots`. The mixed enrollment fence includes
all sealed inherited decisions and their complete discovery/GET ancestry, not
later mutable attempts. Same-input lane recovery remains governed by the public
rolling/formal APIs and immutable predecessor evidence.

## Source and verification

Implementation: [input adapter](../src/qcsd_lab/whole_graph_input.py),
[GET and admission adapter](../src/qcsd_lab/whole_graph_supplement.py),
[mixed setting declaration](../src/qcsd_lab/whole_graph_capture_amendment.py),
[public CLI](../tools/rapid_whole_graph_supplement.py), and
[focused HOST regressions](../tests/test_whole_graph_supplement.py).

Exact historical discovery producers are retained under
[version 1](../tools/whole_graph_discovery_v1/operator.py) and
[version 2](../tools/whole_graph_discovery_v2/operator.py). Their original external
receipt paths and hashes remain part of each input; the tracked copies make the
code reusable without changing historical receipts.

The general navigation-seeded [version 3 producer](../tools/whole_graph_discovery_v3/operator.py)
continues through the same frozen catalogue. Each declaration's exact adjacent
producer pair is executed at its original bound path when reopening evidence.
A copied producer is a reusable source template; it cannot impersonate an
earlier declaration's producer location.

Transport mounts and live evidence fences serve different purposes. The mounts
provide authenticated parent paths read-only. The evidence fence binds exact
declaration, context, navigation and lineage files, together with complete
immutable raw GET/Source trees. Adding a later candidate or lane under a shared
parent does not change an earlier lane's inputs; changing any bound bytes,
permission mode or raw-tree membership rejects reopening.

HOST fixtures verify occurrence/DAG/header preservation, distinct discovery and
GET runtimes, strict raw GET reopening, retry order, source rejection, typed
mixed enrollment, all-five serial plan shape and zero-credit deferrals. HOST
passes do not establish a physical GET or formal capture. The first new complete
GET and its installed independent verification remain required operator work.
