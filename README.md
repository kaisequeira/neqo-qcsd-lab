# QCSD Lab

QCSD Lab prepares reproducible HTTP/3 workloads, runs the client-side Neqo
defences, captures traffic and runtime evidence, and verifies, seals and exports
the results. Each admitted workload retains its complete resource graph,
including resources from multiple origins. Servers remain ordinary HTTP/3
endpoints.

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
is the recorded laptop baseline. The existing scheduler requires at least
12 visible CPUs, including CPU indices 10 and 11. Prevent sleep and clock
changes during collection.

Fresh builds require at least 64 GiB free on Docker's actual backing volume.
Later capture admission independently requires three times the projected
remaining evidence storage. Native architecture profiles, browser provenance,
network capabilities and timing must pass on each new collection host.

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
