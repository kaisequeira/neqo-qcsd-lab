# Two-container capture pilot

This optional pilot runs one BuFLO container and one CS-BuFLO container at the
same time. It is an engineering rehearsal: **every pilot receipt grants zero
formal traces**. The registered final target remains **50 sites × five modes ×
64 visits = 16,000 traces**. Serial capture can start independently of this pilot.

## Inputs

Use two ordinary, qualified `schema: 1`, `purpose: smoke` campaigns. Their names
must use the existing `rapid-curated-tranco50-v2-diagnostic-...` namespace, with
different names for the two modes. Each has one visit per workload, the same
complete workloads, one named response qualification set, identical capture
limits, `research-1200`, and `as-defined` requests. A first one-site trial is
allowed; this pilot does not claim that the final 50-site cohort is complete.
Keep every observed resource and origin in each supplied workload.

Write an operator authority JSON before launching:

```json
{
  "schema_version": 1,
  "artifact_type": "qcsd-two-worker-diagnostic-authority",
  "runtime": {
    "runtime_source_root": "<absolute clean collection source checkout>",
    "module_root": "<same clean collection source checkout>",
    "execution_root": "<absolute execution checkout with the paired campaigns>",
    "source_manifest": "<absolute actual image source.json export>",
    "client_binary": "<absolute retained actual image client export>",
    "base_launcher": "<absolute collection source qcsd-lab>",
    "host_launcher": "<absolute execution checkout qcsd-lab>",
    "collection_image_digest": "sha256:<actual immutable collection image ID>"
  },
  "campaigns": [
    {"path": "<absolute BuFLO campaign inside execution checkout>", "sha256": "<actual campaign hash>"},
    {"path": "<absolute CS-BuFLO campaign inside execution checkout>", "sha256": "<actual campaign hash>"}
  ]
}
```

These are run-specific paths, not machine paths embedded in source. The tool
reopens clean source and its Native Gitlink, image/client exports, full installed
Python inventory, fixed traffic settings, workload bytes and qualifications.
The collection image must actually install this pilot and its scheduler code;
an older image cannot gain the new collection role by mounting new Python code.
Preparation/admission evidence retains its separately verified source role.

## Launch and verification

From the matching collection source checkout, using its normal Python environment:

```sh
uv run python tools/rapid_parallel_capture.py launch \
  --authority /absolute/operator-authority.json \
  --output /absolute/execution/results/parallel-pilot-001

uv run python tools/rapid_parallel_capture.py verify \
  --authority /absolute/operator-authority.json \
  --output /absolute/execution/results/parallel-pilot-001
```

The output path must be absent, beneath the explicit execution results directory,
with an existing parent. No earlier result can be overwritten. The launcher
records its actual command, process birth, return code and raw output. The one
authenticated guardian and the existing global rapid adapter lock own both workers.

Only this optional capability needs at least five available Docker CPU IDs:
two separate client/helper pairs and at least one remaining CPU for the routers.
Available IDs are observed, including sparse IDs. This adds no hardware minimum
to serial capture. Native scheduling stays `SCHED_RR`, priority 1, under the
existing portable ETF v4 contract; the new peer host/runtime proof uses schema 5.

Each lane has a separate bridge, router, capture secret, capture directory and
writable results mount. Both workers first wait behind a gate. Exact actual
container IDs, image IDs, CPU assignments and router identities must independently
verify before either gate releases. Undeclared containers or overlapping protected
CPU assignments block the pilot. The same observed public DNS pins cover the
entire paired origin graph.

An accepted pilot result still needs the ordinary deep verifier: actual response,
packet, clock, scheduler and kernel transmission evidence. Its scheduler proof
must also bind the exact worker and peer partition used for this launch. A passing
serial result cannot substitute for a parallel result.

## Failures and recovery

When one worker exits, its own worker, router and bridge retire. The other worker
continues and retains its own results. Failed and incomplete files, captures and
raw logs are preserved; a failed lane does not turn its peer into a failure.
The overall pilot reports failure if either lane lacks a deep-verified complete
result, and separately reports whichever lane did verify.

Repairing a failed lane uses a fresh campaign name and new create-only output.
The successful peer's original result remains intact. After the current guardian
session finishes, a focused serial successor can retest the repaired lane using
ordinary `qcsd-lab run`; site acquisition and unrelated defense qualifications
do not restart solely because this host collection coordinator changes. This
first pilot does not hot-swap runtime source into an already running container.

If the entire host session is lost, first finish normal guardian/lifecycle
cleanup. Then observe global retirement with:

```sh
uv run python tools/rapid_parallel_capture.py retire-session \
  --authority /absolute/operator-authority.json \
  --output /absolute/execution/results/parallel-pilot-001
```

This reuses the existing actual process, guardian socket, lifecycle lock,
ownership inventory and Docker-absence checks. A still-running peer prevents
whole-session retirement. Retirement grants no capture completion or formal credit.

## Current implementation milestone

The source implements the opt-in actuator, peer CPU proof, separate lane outputs,
lane-specific retirement, and ordinary deep result reopening. Focused tests cover
the real shell routing with Docker calls replaced, including one failing lane
while its peer continues. These tests are engineering verification. A source-
matched image and an actual serial-versus-concurrent trial are still needed
before making any runtime performance claim or enabling formal parallel capture.
