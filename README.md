# QCSD Lab

QCSD Lab prepares reproducible HTTP/3 workloads, runs client-side Neqo
defenses, captures traffic and runtime evidence, and verifies and exports
the results. Servers remain ordinary HTTP/3 endpoints.

## Current study: resource-domain sessions

The approved collection is **50 exact resource hostnames × five modes ×
400 accepted fresh connections = 100,000 sessions**. Every counted connection
must complete full GETs for its hostname's **20 distinct frozen URLs**.
The modes are ordinary traffic, FRONT, Tamaraw, BuFLO and CS-BuFLO.

**Current checkpoint: three live-enrolled classes and 21 verified formal
sessions:** ordinary 14, FRONT 2, Tamaraw 4, CS-BuFLO 1 and BuFLO 0.
`formal-batch-000002.json` exports all 21. Recovery and verification passed
with no errors, pending attempts, deleted files or running containers. The
first four-session export and actual 4 → 8 → 12 SIGTERM stop/resume evidence
remain unchanged. The importer checks structural eligibility, not 50 live
admissions. The earlier **392 ordinary website recordings** remain historical
and are excluded from this new total.

Implementation is complete and SDK005 is verified. Four zero-credit mode
pilots passed: ordinary on Fonts and Shopify, FRONT/Tamaraw on Shopify and
CS-BuFLO on Dictionary. Fonts remains ordinary-only after chaff qualification
failed. BuFLO's three pilots failed with 22.9–30.8 ms WSL clock shifts and
remain uncredited; its local timing gate is unresolved. Affected cells paused
while healthy cells continued. No Mac ARM runtime pass is claimed.

Start with [the resource-domain guide](docs/RESOURCE-DOMAIN-STUDY.md).
The `./qcsd-lab resource-study` route and `tools/resource_study.py`
provide `prepare`, `capture`, `status`, `verify` and `export` actions. Consult
the installed help and use explicit `--mode undefended` first. Initial unchanged
cells use the approved one-domain mode pilot; changed scientific epochs need
an exact-host/resource pilot. Omitted mode selection requests all five modes.

One fresh Native process replays 20 URLs over one origin's connection.
Capture is on client `eth0` before NAT. Tuple uniqueness, handshake and all
resource completions are verified, and connection migration is never counted
as an extra session. A SQLite ledger with immutable receipts tracks 250
independent class/mode cells. A failed defense does not reset valid progress
in a different mode.

Budget initially for **two workers, six available CPUs and 16 GB RAM**.
The scheduling minimum for N workers is `2N + 1` actual available CPU IDs;
four workers need at least nine and their own successful capability checks.
The illustrative 20-second effective rate gives 11.6 continuous days with
two workers or 5.8 with four. Neither rate has been measured for this study.
The 512 GiB sparse storage limit does not establish sufficient physical space
for 100,000 sessions.

Packet-clock acceptance remains strict at 10 ms; bounded retries preserve
refused disturbances. Host repairs are recorded separately from installed SDK
identity. The final Mac source handoff remains pending; see
[the migration guide](docs/MAC-MIGRATION.md).

Reuse the verified cached Native D2 client for Lab-only changes through a
truthful new SDK/runtime binding. This does not require fresh Rust compilation
or relabel old runtime evidence. See [PROJECT.md](PROJECT.md) for status and
[AGENTS.md](AGENTS.md) for evidence and mode-scoped recovery rules.

## Existing workflows and historical website study

The remaining operator instructions describe existing Lab workflows. Their
whole-page graphs, browser gates and historical class-study contracts retain
their original meaning; they are not additional launch prerequisites for the
prospective resource-domain study.

Start with this operator guide. [PROJECT.md](PROJECT.md) records current
progress and the thesis goal; the [class-study runbook](docs/CLASS-STUDY.md)
explains the collection sequence. [METHODOLOGY.md](METHODOLOGY.md) defines
measurement semantics. The [history](docs/PROJECT-HISTORY.md) and
[evidence index](docs/EVIDENCE-INDEX.md) support research audits.

The claim remains **five validated defences plus two candidates / nine
selectable modes**. BuFLO and CS-BuFLO are candidate client-only QUIC
adaptations. Only a verifying final attestation permits their promotion.

## Setup

Use Linux; the desktop continuation targets Ubuntu under Windows x64 WSL2.
Keep the checkout in the Linux filesystem. Required tools are Git, Python
3.11+, `uv`, and Docker with user systemd/cgroup v2 available. Docker 29.0.1
is the recorded laptop baseline. The `uv` project environment supplies Python
3.11+; Ubuntu 22.04's system Python 3.10 can run the isolated host proof tools.
Evidentiary capture needs at least three
Docker-visible logical CPUs: one for collection sidecars, one for the measured
client, and one for the orchestrator and ETF helper. The scheduler selects and
records this affinity partition from available CPUs. Its isolation and live
timing checks still determine whether a host can produce valid evidence.
The launcher probes the CPU IDs available inside the pinned collection image
and uses the sorted observed IDs, including offset or sparse sets. It records
that list in the environment and prelaunch partition receipts and verifies the
measured container's exact two-CPU affinity before execution.
Prevent sleep and clock changes during collection.

Check that Docker's actual backing volume is healthy and has positive free
space before a fresh build; the build preflight records its capacity. Later
capture admission independently requires three times the projected remaining
evidence storage. Native architecture profiles, browser provenance, network
capabilities and timing must pass on each new collection host.

From a fresh clone:

```shell
git submodule update --init --recursive
uv sync --frozen --all-extras
git status --short
git -C neqo-qcsd status --short
git submodule status neqo-qcsd
./qcsd-lab --help
./qcsd-lab class-study --help
```

Restore the separately transferred evidence before continuing an existing
study. See the [evidence index](docs/EVIDENCE-INDEX.md); a Git clone alone does
not contain captured data, author reference inputs or local receipts.

## Commands

Use the host wrapper `./qcsd-lab`. Its typed arguments and admission checks
are authoritative; consult the appropriate command help before execution.

| Command | Purpose |
|---|---|
| `build --cohort-version N` | Allocate an unused cohort and build pinned collection, preparation and reference images |
| `prepare` | Discover and freeze a workload with response evidence |
| `derive-chaff-prefix-specs`, `qualify-chaff`, `qualify-response-chaff` | Prepare and verify chaff capacity/prefix inputs |
| `run`, `resume`, `verify`, `analyze`, `fit` | Generic campaign execution and analysis; class-study roles use their coordinator below |
| `test live` | Bounded HTTP/3 integration capture |
| `test pinned-cdp` | Verify the pinned browser, target routing and egress contract |
| `test browser-egress {create,resume,verify}` | Operate the ordered 110-vector browser gate |
| `buflo-study` | Reference, timing/regression, code and controlled foundation gates; retained focused-study workflow |
| `class-study` | Acquisition, fitting, qualification, certification, formal capture, evaluation and attestation |
| `class-study acquisition-watch` | Host supervisor for due acquisition observations |
| `etf-probe`, `etf-veth-probe` | Non-evidentiary timing/transport capability diagnostics |
| `lifecycle-recover` | Strict recovery of a retained Docker transaction |

Read-only study inspection, when no source-bound process is live:

```shell
./qcsd-lab class-study status
./qcsd-lab class-study verify --target RECEIPT_OR_RESULT
```

For local Python development checks:

```shell
uv run pytest
git diff --check
```

Local tests do not replace the image-bound code gate or live qualification.

## Execution and recovery

1. Use a clean Lab checkout and its exact clean Rust Gitlink. Choose the
   allocator-authorised unused positive cohort; attempted versions remain
   consumed even if no final receipt exists.
2. Run source-bound Docker stages serially. During a live stage, agents only
   poll that process/session. Repository inspection, edits, tests, Git and
   unrelated Docker operations wait until it exits.
3. Evidence destinations are create-only. Preserve failed attempts and use
   `experiment.json` for capture resume. Acquisition uses `checkpoint.json`
   and bound `provenance.json`. Use the original source, inputs and arguments.
4. Diagnose with the smallest relevant local or live diagnostic first. A
   client/Lab defect requires a client-side fix and fresh affected downstream
   evidence. Source, image, parameter, workload or acceptance changes invalidate
   authority tied to the previous identity.
5. A failed final receipt or incomplete passing prefix is not a completed gate.
   Distinguish operational interruptions from scientific failures before
   choosing resume, repair or a fresh cohort.

Keep an execution checkout pinned for its whole campaign. Publish progress
documentation from a separate authoring clone between live operations, without
changing that checkout. Agent operators must follow [AGENTS.md](AGENTS.md).

## Repository layout

| Path | Contents |
|---|---|
| `src/qcsd_lab/`, `tools/`, `qcsd-lab` | Lab implementation, container roles and host supervisor |
| `neqo-qcsd/` | Rust Neqo/QCSD submodule |
| `docker/`, `Dockerfile` | Pinned image definitions |
| `config/` | Versioned study, workload, parameter and campaign specifications |
| `artifacts/` | Local immutable build, qualification, fitting and authority receipts |
| `results/` | Local attempts, checkpoints and sealed capture campaigns |
| `handoffs/` | Local immutable exports |
| `docs/` | Current research runbook, thesis progression and evidence index |

Treat evidence-bearing directories as immutable inputs or create-only outputs.
Never regenerate, relabel or prune a sealed inventory to make verification pass.
