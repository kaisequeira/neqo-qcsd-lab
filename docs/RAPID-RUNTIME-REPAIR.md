# Repair one defense without repeating the whole study

This prospective route allows a reviewed collection repair to restart only the
failed defense's 20-trace lane. Completed traces keep the image, source commit,
client, launcher and workload identities under which they were captured.

The target remains **50 sites × five conditions × 64 visits = 16,000 traces**.
The study still has 160 matched blocks, each containing five 20-trace lanes.
The ordinary packet and result verifiers must pass before a lane can enter a
block commit or the final corpus.

## What can be repaired

The version-one compatibility contract permits explicit, reviewed edits inside
named collection functions. It compares the complete source inventories and all
31 paths in the installed qualification implementation receipt. It derives the
functions used by the response-only qualifier from the actual retained source.

Current permitted functions are listed in
`src/qcsd_lab/rapid_runtime_compatibility.py`:

- Copying and observer startup in `capture_session.py`.
- Checkpoint persistence in `orchestrator.py`; the summary and checkpoint calls
  remain protected.
- The rapid capture lock and supervised host actuator in `rapid_lane_evidence.py`.
- The two explicitly named packet reconciliation functions in `fidelity.py`.

Every edit must name its exact before/after source hashes and changed functions.
Imports, constants, signatures, decorators, other functions, and the rest of
each edited file remain fixed. A permitted collector function becomes protected
if the actual qualifier reaches it. This is a narrow repair contract, rather
than permission to change an arbitrary collector module.

These identities remain fixed:

- Native commit, pinned Gitlink and actual client binary.
- The complete site cohort, labels, selected URLs and full resource graphs.
- Class/body epoch vector and named qualification manifests for the failed block.
- Traffic method, parameters, request headers, limits and logical visit slots.
- Qualification network behavior and its actual 120-response proof.
- Build files, launchers and the compatibility/epoch authority validators.

Changes to these protected identities require a separately declared study
change and appropriate proof. They do not gain authority through this route.

## Set up the route prospectively

Install this source in the initial formal collection image **before** producing
its base qualification sets. The new current-qualification hook is itself a
protected source change. Historical qualification receipts retain their old
contract; they cannot be silently promoted to the new base implementation.

Create the ordinary final-50 capture spec and class-epoch policy first, using
the verified site cohort and actual response qualification sets. Then initialize
runtime authority before any physical formal lane is launched:

```sh
PYTHONPATH=src python tools/rapid_runtime_epochs.py initialize \
  --spec path/to/base-capture-spec.json \
  --evidence-root path/to/class-epoch-evidence
```

Both original and replacement source snapshots, exported metadata, client
snapshots and execution files must live under the operator spec's explicit
`data_root`. The launcher mounts these directories read-only. This directory
can be on any suitable disk; no host name, drive letter or fixed CPU count is
part of the source contract. The replacement uses its own clean installed
collection source while retaining the same execution/config/result layout.

## Repair workflow

1. Let the failed host process finish, or perform the existing actual lifecycle
   retirement. Preserve its logs, partial results, captures and intent. A running
   or unretired worker cannot be replaced.
2. Fix the allowed collector function in a separate clean source checkout. Build
   a new immutable collection image. Reuse the identical Native artifact only
   with its recorded source and binary proof; a Lab repair does not itself
   require recompiling Native.
3. Create a new runtime spec. Only collection source/metadata/image identities
   and the execution generation change. The study/config/result paths remain
   fixed.
4. Write a review JSON containing `schema_version: 1`,
   `artifact_type: qcsd-rapid-collection-repair-review`,
   `repair_scope: collector-lifecycle-only`, an explicit `reason`, and `changes`.
   Each changed source path maps to `before_sha256`, `after_sha256` and the exact
   changed `functions`. The review compares the original base source against
   the replacement, including cumulative earlier repairs.
5. Propose the new runtime:

```sh
PYTHONPATH=src python tools/rapid_runtime_epochs.py propose \
  --spec path/to/base-capture-spec.json \
  --evidence-root path/to/class-epoch-evidence \
  --runtime-spec path/to/replacement-capture-spec.json \
  --failed-intent path/to/failed-lane/intent.json \
  --review path/to/review.json
```

The command runs an actual offline check in the original installed image,
reopening its qualifier and the full raw response proof. It then checks the
replacement's actual installed image, source inventory, client and compatibility
roles. It does **not** repeat the qualification network requests.

6. Run one undefended and one affected-defense canary over the same five complete
   site graphs, one visit each. For a failed BuFLO lane:

```sh
PYTHONPATH=src python tools/rapid_runtime_epochs.py launch-canary \
  --spec path/to/base-capture-spec.json --evidence-root path/to/class-epoch-evidence \
  --proposal path/to/runtime-epochs/e0002/proposal.json --mode undefended
PYTHONPATH=src python tools/rapid_runtime_epochs.py launch-canary \
  --spec path/to/base-capture-spec.json --evidence-root path/to/class-epoch-evidence \
  --proposal path/to/runtime-epochs/e0002/proposal.json --mode buflo
```

Both canaries need successful actual host exits, exact DNS/input/source
bindings, ordinary sealed results and deep verification. Their ten diagnostic
traces add **zero** to the formal numerator.

7. Activate the runtime and launch the failed lane's next physical generation:

```sh
PYTHONPATH=src python tools/rapid_runtime_epochs.py activate \
  --spec path/to/base-capture-spec.json --evidence-root path/to/class-epoch-evidence \
  --proposal path/to/runtime-epochs/e0002/proposal.json
PYTHONPATH=src python tools/rapid_runtime_epochs.py launch-lane \
  --spec path/to/base-capture-spec.json --evidence-root path/to/class-epoch-evidence \
  --activation path/to/runtime-epochs/e0002/activation.json
```

Only the failed condition gets a new physical generation. The unchanged block
declaration continues to bind its five classes, parameter settings and visits.
Previously completed conditions keep their original receipts and runtime.

## Another failure

A transient failure under the same activated runtime can use `launch-lane`
again with `--predecessor-intent` naming its immediate incomplete physical lane.
This advances `g02` to `g03` without repeating the ten canaries. Completed lanes
cannot be selectively replaced through this recovery rule.

If a canary fails, its attempted namespace stays claimed. Diagnose it, then use
`retire-canary` when actual process/lifecycle retirement is needed, and
`retire-candidate --reason ...` to close that runtime candidate. A later fix uses
the next create-only runtime ordinal. Failed candidates remain visible with zero
credit in the final runtime inventory. They cannot be deleted, skipped or
activated using a passing prefix.

## Final verification and limits

Use the existing class-epoch `commit-block`, `publish-manifest` and
`verify-manifest` commands. A prospective runtime study produces the separate
`qcsd-rapid-v5-runtime-epoch-formal-corpus-v1` manifest. It reopens all 160 block
commits, every selected physical lane's original runtime, all failed predecessors,
and every activated or retired runtime candidate. The arithmetic must still be
exactly 50 × five × 64.

Legacy manifests and default current-qualification checks retain their strict
existing semantics. A launch capsule is validated inside the actual collection
image; an environment variable or an arbitrary compatibility JSON cannot grant
authority by itself.

This route supplies repair isolation. Formal launches are currently serialized.
The separate two-container [parallel pilot](PARALLEL-CAPTURE-PILOT.md) remains a
zero-credit Smoke rehearsal; this document makes no concurrent formal capture
or speedup claim. A new runtime path must pass an actual image/canary/lane
rehearsal before it is used for formal evidence. Unit and fixture tests alone
do not establish that live readiness.
