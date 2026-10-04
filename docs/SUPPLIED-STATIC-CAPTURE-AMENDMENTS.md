# Changing capture policies after a complete static GET

This prospective adapter lets an admitted fixed-resource replay use the explicit
FRONT V4 preparation reserve or BuFLO V12 preparation reserve. It preserves the
original complete GET, context, terminal, manifest and all supplied resources.
The study remains **50 sites × 5 settings × 64 visits = 16,000 accepted formal
traces**. Earlier browser traces belong to their original study.

The scientific claim remains a replay of a declared resource graph. Successful
GETs establish complete ordinary HTTP/3 responses; they do not establish browser
rendering, absence of challenges, or response stability. The original primary
and auxiliary response evidence and public-address safeguards remain required.

## What changes

The new preparation role is
`supplied-static-complete-get-amended-capture-preparation-v1`. A separate
declaration binds the original enrollment, terminal, complete GET proof, original
four policy labels, current capture source/client/image, and the exact new file
destinations. It precedes creation of the derived manifests. A closed amendment
then seals those manifest bytes before any new qualification or capture.

Only these explicit policy fields can change:

| Setting | Explicit policy | Preserved physical requirement |
| --- | --- | --- |
| FRONT | `rapid-v5-front-bounded-outgoing-padding-omission-10pct-window-10000us-reserve-1000us-v4` | Original strict 10 ms send window and combined 10% pure padding omission cap |
| BuFLO | `rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1` | Strict actual enqueue, physical TX and post-veth handoff before release + 5 ms; no omissions |

All resource URLs, ordering, headers, dependencies, complete GET response
evidence, original source labels and origin coverage remain byte-for-byte
equivalent. The derived preparation records its new role and declaration
reference. Original GET producer modules and their whole-file hash contracts
are unchanged. No historical failure is relabeled.

These policies alone do **not** establish five-setting viability. For example,
a complete graph can exceed BuFLO's fixed incoming credit budget. A future
cadence/event-budget change needs a separate explicit prospective traffic
amendment and new affected-setting proof. This adapter accepts no arbitrary
traffic settings or resource pruning.

## Serial operator sequence

Use the clean matched collection runtime containing this adapter and its Native
policy producers. The runtime input receipt names its actual source, client,
image and fresh execution/workload paths. Its `workload_root` must be empty for
the selected enrollment; the adapter never overwrites an existing manifest.

```bash
python tools/rapid_rolling_capture.py static-amendment \
  --enrollment "$ENROLLMENT" --runtime-spec "$RUNTIME" \
  --output "$STUDY/capture-policy-001.json" \
  --front-policy rapid-v5-front-bounded-outgoing-padding-omission-10pct-window-10000us-reserve-1000us-v4 \
  --buflo-policy rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1
```

Either setting may be selected alone. The command grants zero trace credit.
It preserves the original admitted workloads and writes the derived manifests
to the new runtime's declared workload root.

1. Run the existing installed named response-only qualification against those
   exact derived manifests. Its actual source, image, client and response epochs
   must match this amendment and start after publication. There is no fitting
   stage and no new browser acquisition.
2. Run the existing full-graph single-visit canary and ordinary deep verification
   for each setting to be launched. The canary's sealed `plan.json` must contain
   `static_capture_amendment` with the exact amendment `{path, sha256}`. Its
   workload hash and complete resource-record hash must match the derived
   manifest, and actual capture must start after amendment publication.
3. Create a serial formal plan with only the independently ready settings:

   ```bash
   python tools/rapid_rolling_capture.py plan \
     --evidence-root "$STUDY" --enrollment "$ENROLLMENT" \
     --runtime-spec "$RUNTIME" --qualification-spec "$QUALIFIERS" \
     --static-capture-amendment "$STUDY/capture-policy-001.json" \
     --readiness "$READINESS" --output "$PLAN" --spec-output "$SPEC"
   ```

4. Launch registered serial lanes through the existing public `launch` command.
   Each setting needs its own canary; a failure does not revoke another setting's
   readiness. The plan still registers all five settings and all 64 visit slots.
   Ordinary DNS/source/CPU/lifecycle/sidecar/deep checks and failed-only recovery
   remain required before final trace credit.

Static parallel scheduling is a separate future extension. Browser amendments,
historical static preparations and unamended plans retain their existing rules.
No source test or amendment receipt constitutes installed-runtime or scientific
capture evidence.

## Verifier and evidence transport authority

An amended preparation authenticates the complete original GET and context
before adding any read-only mounts. The declaration's source roots and original
source/client/launcher references must also be available at their recorded
absolute paths. These roots are derived from the verified declaration; a caller
cannot add unrelated volumes. Original static and browser preparations retain
their existing transport rules.

The new declaration binds the actual FRONT V4 evidence verifier and static
transport module alongside the adapter's existing authority files. Altering an
imported or frozen authority file invalidates the amendment. A prospective
source equivalence for an amended canary adds the explicit
`static-capture-amendment-v1` dependency group. Historical canary equivalence
groups and qualification implementation receipts keep their original meaning.

## Separate fixed 200-second BuFLO flight

The optional `--buflo-duration-policy rapid-v6-fixed-200s-duration-budget-v1`
selects the prospective duration preparation role
`supplied-static-complete-get-amended-buflo-duration200-preparation-v2`. It can
only accompany a BuFLO preparation-policy amendment; FRONT is declared in a
separate amendment. The declaration additionally binds the exact duration
helper and control authority files, parameter/provenance bytes, original GET,
and actual new source/client/image before creating the derived workload.

Its formal plan and single-setting BuFLO canary carry the same explicit
`buflo_duration_policy`. They select `buflo-duration200.json` and derive only
BuFLO's 240-second client and 300-second recording limits. Cell size, cadence,
physical deadlines, the complete graph and all ordinary deep checks remain
required. The mere presence of a new parameter file cannot select this policy.

The historical traffic constants are retained. Every spec reopens its own
authenticated traffic tuple and source/module inventory: original ordinary
lanes retain the original 120/180-second contract, while future BuFLO lanes bind
the new parameter and provenance hashes. Final corpus assembly reopens each
lane's actual spec and closed installed operation, then accounts for the same
unique class/setting/visit slots. Completed original traces are not relabeled
or recaptured when this separate setting changes. An affected failed BuFLO
attempt still requires its own retained failure and unused successor.
