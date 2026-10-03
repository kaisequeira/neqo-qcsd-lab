# Optional two-lane formal capture

The study still collects **50 sites × 5 modes × 64 visits = 16,000 accepted
traces**. Each formal lane contains 20 traces. This optional actuator runs two
official lanes concurrently, using separate worker containers, routers,
networks, capture folders, DNS receipts and writable result folders.

Serial capture remains available. Cloning or running a serial study does not
require five CPUs. The optional pair needs four distinct protected CPU IDs
(one client and one orchestrator per worker), plus at least one residual CPU
for the routers and host. The coordinator derives the allocation from the
available CPU IDs. It rejects an unsafe pair instead of changing traffic.

## What must already exist

- A final 50-site cohort, its full prepared workload graphs and response chaff
  qualification. This feature changes no site admission or fitting rule.
- Official v5 lane plans and campaign files produced by `tools/rapid_plan.py`.
- A clean matching Lab source checkout and immutable collection image that
  actually install both parallel coordinator modules and the updated launcher.
  Both workers use that same image and Native client. A running image is never
  replaced, and an old diagnostic receipt grants no formal credit.
- A portable capture spec naming the source, client, traffic settings, cohort,
  qualification, workload and plan receipt. Its paths may be relative to the
  spec file; the authority records their actual resolved identities.

The source implementation and focused fixture tests do not establish a live
parallel capture pass. The first formal runtime may already include this
coordinator and collect its qualifiers on that same runtime. If an existing
qualified serial study later needs this control package, use the separately
versioned installation below before its first formal flight. The existing
collector lifecycle bridge retains its original scope.

## Registered class blocks

The normal class study declares one five-site block before traffic starts.
Each defense collects four visits per site, so each lane has 20 traces. All
five lanes must deep-verify before `commit-block` grants the matched block its
100 formal traces. A completed parallel lane retains conditional credit until
that ordinary block commitment; a pair alone does not grant 40 formal traces.

After the normal class policy and block declaration exist, prepare two lanes:

```sh
python tools/rapid_formal_parallel.py \
  --spec capture-spec.json --evidence-root capture-evidence \
  --declaration-1 BLOCK_DECLARATION --mode-1 buflo \
  --declaration-2 BLOCK_DECLARATION --mode-2 cs-buflo \
  --output capture-evidence/pair-001-authority.json
```

Use the same launch and verify commands below. For a failed lane, provide its
same block declaration, `--generation-1 2` and its actual `--predecessor-1`
intent, paired with another unclaimed lane. An already qualified runtime repair
uses `--activation-1` instead of inventing a failure or repeating qualification.
Both workers must resolve to the same immutable collection image and source;
different runtime images are captured in separate batches. The completed peer
is never recaptured to repair the failed lane.

## Install capture control while retaining real qualification

This optional path grants zero credit and must precede every formal intent or
result. It preserves the original clean source and image, and uses a separate
clean matching checkout for the new launcher. Prepared graphs, the cohort,
initial plan and response qualification bytes must match. Qualification spec
manifest/sidecar paths must be relative so copying the execution layout retains
the same spec bytes. Native, client, fixed traffic, qualification execution
dependencies and all eight site acquisition inventories remain unchanged.

```sh
python tools/rapid_capture_control_installation.py publish \
  --base-spec serial-capture-spec.json --new-spec capture-spec.json \
  --evidence-root capture-evidence \
  --reason 'Install the reviewed parallel capture control before formal flights.' \
  --output capture-evidence/control-installation.json

python -m qcsd_lab.rapid_class_epochs initialize \
  --spec capture-spec.json --evidence-root capture-evidence \
  --installation capture-evidence/control-installation.json
```

The constructor records actual offline original-image plan/qualification and
new-image installed-source checks, their exact commands, starts, completions
and raw logs. Initialization permits only those sealed installation records in
its otherwise fresh evidence root. It preserves every original sidecar's
source and image labels. Subsequent policy, block, launch and final corpus
checks reopen the sealed reference without requiring ambient environment
variables. Add `--installation capture-evidence/control-installation.json` to
formal pair preparation on this path. A later source repair reopens the
original-to-installed and installed-to-repaired bridges separately; it cannot
substitute a new Native client through this control-only contract.

## Prepare and run a pair

Choose two unclaimed campaign names from the official plan. Run the tools with
the Python package from the matching clean source. The placeholders below are
operator paths and exact campaign names, not fixed machine requirements.

```sh
python tools/rapid_formal_parallel.py \
  --spec capture-spec.json --evidence-root capture-evidence \
  --lane FIRST_OFFICIAL_CAMPAIGN --lane SECOND_OFFICIAL_CAMPAIGN \
  --output capture-evidence/pair-001-authority.json

python tools/rapid_parallel_capture.py launch \
  --authority capture-evidence/pair-001-authority.json \
  --output EXECUTION_ROOT/results/pair-001

python tools/rapid_parallel_capture.py verify \
  --authority capture-evidence/pair-001-authority.json \
  --output EXECUTION_ROOT/results/pair-001
```

Preparation performs the actual bound-image plan check and creates ordinary
lane intents and lineage receipts. It launches no traffic and grants no credit.
The launcher resolves each worker's full origin graph independently and checks
the actual inspected containers before releasing either worker. The first
worker cannot write the second worker's canonical result folder.

## If one lane fails

The launcher records that worker's actual exit and raw logs, removes only its
worker, router and network, and records their observed absence. The running
peer continues. Each worker independently uses the ordinary exact 20-slot
deep verifier; success creates the existing official completion receipt. A
lane that fails capture or deep verification preserves its attempted bytes and
receives no completion credit. A batch exit of 1 does not revoke a separately
deep-verified peer lane.

Use `tools/rapid_plan.py successor` to create a **new** successor plan for the
failed logical lane. Create a new capture spec that names that plan receipt.
Keep the original spec and plan unchanged. Only the plan receipt may differ
between two specs in a pair; source, image, client, cohort, qualification,
workloads and traffic settings must match.

```sh
python tools/rapid_formal_parallel.py \
  --spec failed-lane-g02-spec.json --spec-2 capture-spec.json \
  --evidence-root capture-evidence \
  --lane FAILED_LANE_G02 --lane ANOTHER_FRESH_G01 \
  --predecessor-1 capture-evidence/lanes/FAILED_LANE_G01/intent.json \
  --output capture-evidence/pair-002-authority.json
```

The immediate predecessor must have actual terminal or retirement evidence.
Its logs and partial result inventory remain bound to the successor lineage.
A completed predecessor is refused. A source or traffic repair requires its
prospective runtime authority; this same-input retry command cannot substitute
a new Native client or image.

Whole-session interruption remains a separate lifecycle recovery operation:
`tools/rapid_parallel_capture.py retire-session` retains a global quiescence
observation. It cannot fabricate a missing per-worker terminal record or award
credit to an unfinished lane. Preserve the attempted namespaces for diagnosis.

## Final evidence

The ordinary lane or class-study `verify-lane`, `publish-manifest` and
`verify-manifest` commands continue to reopen official completions. Parallel
lane validation also reopens
the actual batch birth and raw logs, worker exit and absence, separate DNS
receipts, inspected result mounts and every sample's measured peer partition.
The final manifest still requires all 800 logical lanes exactly once, including
all 160 matched blocks on the registered class path. A valid pair contains at
most 40 accepted traces; the study remains 16,000 traces.
