# QCSD Lab operator guide

Documentation refresh: 16 September 2026, Australia/Sydney (AEST, UTC+10)

This repository orchestrates reproducible HTTP/3 traffic capture for the QCSD
Neqo fork. It freezes workload graphs, runs visits under a selected client-side
defence, records packet and runtime evidence, and verifies and seals results
before analysis or export. A workload may contain several origins; a defence
must not remove those resources or reduce it to a single origin.

This README is the checked-in operator entry point. The
[methodology](METHODOLOGY.md) defines observation and metric semantics, the
[class-study contract](config/class-study/v1/study.json) defines the frozen
study inputs, and `./qcsd-lab class-study --help` is the command-line authority.
Detailed cohort chronology is deliberately omitted from this practical guide;
use immutable receipts and Git history when auditing earlier executions.

## Current status

The claim boundary remains **five validated defences plus two candidates / nine
selectable modes**. BuFLO and CS-BuFLO are candidate client-only QUIC
adaptations, not bilateral or paper-equivalent implementations. Do not claim
seven validated defences until the final validation attestation verifies.

Cohort v89 completed its build, pinned-CDP and independently verified
**110/110 browser-egress** gate. Acquisition-authority creation then failed
before Docker: the host reader expected an obsolete browser receipt schema.
The source correction also reconciles the downstream build-size field and
adds producer-to-consumer regression tests. This changed source needs the
allocator's next unused cohort and fresh prerequisite evidence; v89 remains
valid only for its original checkout. Public acquisition has not started:
pilot **0/120**, final classes **0/100**, certification **0/900**, and formal
capture **0/16,000**. Browser qualification is not class or defence validation.
Read the latest immutable receipts for subsequent progress.

The nine modes, in stable order, are `undefended`, `static`, `front`, `tamaraw`,
`traffic-morphing`, `wtf-pad`, `walkie-talkie`, `buflo`, and `cs-buflo`.
`undefended` and `static` are controls; the middle five research defences are
validated; BuFLO and CS-BuFLO remain candidates.

## Prerequisites

- The study's Linux environment (currently Ubuntu under WSL2) with Git and a
  working clock.
- Docker 29.0.1 reachable from this distribution. Public capture and evidence
  commands run through Docker.
- Python 3.11 or newer and `uv` for local development and tests.
- The checked-out `neqo-qcsd/` submodule at its pinned commit.
- At least 64 GiB free on the actual Docker data-VHDX backing volume before a
  fresh image build; the launcher performs stricter stage-specific checks.
- Network access for fresh image pulls and authorised public-page acquisition.
- The separately pinned paper, author-source, and archive inputs when running
  the isolated reference gate.

Initialise a development checkout from this directory:

```shell
git submodule update --init --recursive
uv sync --frozen --all-extras
git status --short
git -C neqo-qcsd status --short
git submodule status neqo-qcsd
./qcsd-lab --help
```

Do not start an evidentiary build from a dirty or unpinned checkout. The wrapper
revalidates source, Gitlink, Docker, storage, and receipt authority at multiple
boundaries and fails closed on drift.

## Repository map

| Path | Purpose |
|---|---|
| `qcsd-lab` | Public host-side command wrapper and Docker supervisor |
| `src/qcsd_lab/` | Python campaign expansion, validation, sealing, analysis, and export logic |
| `tools/` | Container roles and narrowly scoped operator helpers |
| `neqo-qcsd/` | Rust Neqo/QCSD submodule, including `neqo-csdef` |
| `docker/`, `Dockerfile` | Pinned collection, preparation, and reference images |
| `config/` | Versioned campaigns, workloads, parameters, reference receipts, and class-study contracts |
| `artifacts/` | Build, qualification, fitting, foundation, evaluation, and attestation receipts |
| `results/` | Attempt evidence, checkpoints, accepted samples, and sealed campaign results |
| `handoffs/` | Immutable classifier/evaluation exports derived from sealed results |

Treat `config/`, `artifacts/`, `results/`, and `handoffs/` as evidence-bearing
trees. Never casually regenerate, rename, edit, or delete their contents.

## Command surface

Use the wrapper, not internal Python entry points. Start with help because the
typed arguments and prerequisite checks are the authority:

```shell
./qcsd-lab --help
./qcsd-lab class-study --help
./qcsd-lab test --help
./qcsd-lab COMMAND --help
```

The principal commands are:

| Command | Role |
|---|---|
| `build` | Allocate a fresh cohort and build the three pinned images with pull/no-cache evidence |
| `prepare` | Acquire and freeze one workload and its response evidence |
| `derive-chaff-prefix-specs` | Derive fitting-dependent prefix specifications |
| `qualify-chaff` / `qualify-response-chaff` | Qualify controlled chaff capacity and response behaviour |
| `run` / `resume` | Execute or continue a generic capture campaign |
| `verify` | Deep-verify a generic result and its closed inventory |
| `analyze` | Derive reports and plots from verified sealed evidence |
| `fit` | Run the retained fitting workflow for defences that require learned inputs |
| `test live` | Run bounded live HTTP/3 capture integration checks |
| `test pinned-cdp` | Prove the pinned Chromium/Playwright target and egress contract |
| `test browser-egress` | Create, resume, or verify the ordered 110-vector packet-observed browser gate |
| `buflo-study` | Operate the retained focused BuFLO/CS-BuFLO study pipeline |
| `class-study` | Operate the authoritative extended-class acquisition, fitting, capture, export, evaluation, and attestation pipeline |
| `lifecycle-recover` | Inspect and recover a retained Docker lifecycle transaction under its strict policy |
| `etf-probe` | Run the explicitly non-evidentiary ETF capability probe |

`class-study` provides `status`, acquisition, cohort, campaign, fitting,
qualification, capture, export, evaluation, comparison, attestation, successor,
and verification actions. `acquisition-watch` is the host-only bounded
supervisor for due acquisition work.

`buflo-study code-gate` explicitly runs and records the Lab test commands.
Receipt verification checks their recorded outputs and bound evidence; it does
not rerun tests, including during deep status or admission checks.

## Immutable execution rules

1. Supply the allocator-authorised next unused positive cohort version. Receipt
   absence does not make an attempted version reusable.
2. Build from one clean pinned Lab checkout and exact Rust Gitlink. A source,
   parameter, workload, acceptance-rule, or image change requires a fresh
   cohort and fresh downstream evidence.
3. Evidence destinations are create-only. Never overwrite a receipt, accepted
   sample, sealed result, handoff, or attestation.
4. `experiment.json` is the authoritative capture-campaign checkpoint.
   Acquisition uses its `checkpoint.json` and bound `provenance.json`. Resume
   only with the same source and arguments after an ordinary interruption.
   Never resume an old cohort after a source-changing fix.
5. Preserve every failed attempt. Do not delete, substitute, relabel, or promote
   it. A pass counts only when the required final receipt deep-verifies.
6. Run source-bound Docker stages serially. While one is live, do not edit or
   inspect the checkout, run Git or graph tools, issue unrelated Docker
   commands, or start parallel agents; only poll the existing process.
7. Keep all defence fixes client-side. Servers remain ordinary HTTP/3 servers;
   do not introduce a symmetric defence protocol to make a gate pass.

## Extended-class workflow

Do not reconstruct typed arguments from this summary. Before each stage, read
`./qcsd-lab class-study --help` and use the exact paths and identities produced
by the preceding verified receipt. The checked-in
[class-study contract](config/class-study/v1/study.json) is the study-input
authority.

At a high level, the sequence is:

1. After source corrections are validated and committed, allocate the
   next unused cohort, build fresh images, run pinned-CDP and all 110
   browser-egress vectors, then publish `acquisition-authority`. Its fixed
   acquisition/preparation test inventory executes once at creation; subsequent
   verification checks its immutable evidence. This receipt permits only
   public-page acquisition, never defended capture.
2. Initialise with `--acquisition-authority`, then run/watch acquisition. Keep
   the genuine 30-second, 24-hour and 72-hour stability checks. Complete each
   stratum's frozen-order prefix through its 24th eligible class; all earlier
   candidates must have scientific terminal outcomes. The unused catalogue
   tail stays explicitly unassessed. Infrastructure failures block completion,
   not class eligibility. Multi-origin resources must not be omitted.
3. Freeze the 120-class pilot. Before any fitting or class-study capture, pass
   isolated reference, timing-stress, nine-mode regression, code and controlled
   qualification, then publish the full class-foundation attestation. The two
   authorities must bind the same source, build and acquisition inputs.
4. Generate pilot and authoritative fitting campaigns over independent visits;
   derive and qualify every numeric or prefix input required by the applicable
   defences. Pilot compatibility and qualified pairing determine the final 100
   classes and 20 reserves under the checked-in selection rules.
5. Run the 100-class × nine-mode × one-visit certification campaign. A cell
   counts only after exact workload correctness and
   defence evidence pass.
6. Freeze readiness and historical-pre evidence, then run each prescribed
   canary before its formal block and capture the 100-class ×
   eight-mode × 20-visit formal corpus (16,000 accepted samples; includes
   `undefended`, excludes `static`) in
   its prescribed order.
7. Seal and verify results, create the immutable handoff, evaluate, complete the
   comparison review, and publish `validation-attestation.json` only if every
   gate passes.

The acquisition scheduler preserves hard action limits and the two-candidate /
five-live-page caps. It releases obsolete reservations only after every batch
member is scientifically terminal plus the full 40-minute guard. With no
rejections, the ideal 120-candidate schedule still spans about 7.62 days;
actual execution and replacements can extend it. This is not a completion-time
guarantee or permission to shorten the stability windows.

Useful read-only checks include:

```shell
./qcsd-lab class-study status
./qcsd-lab class-study verify --target RECEIPT_OR_RESULT
```

For a published, source-compatible checkpoint, use the exact `resume` action
and arguments admitted by `./qcsd-lab class-study --help` and the checkpoint.
If source changed, retain the old checkpoint and allocate the next cohort
instead.

## Evidence and result handling

An accepted generic sample contains the exact five-file inventory documented in
[METHODOLOGY.md](METHODOLOGY.md). Browser qualification and candidate timing
gates have their own typed sidecars and receipts. Consumers must accept only
the schema versions and historical compatibility paths implemented by their
validators; explanatory prose cannot upgrade evidence.

The source-of-truth order is:

1. the current Git checkout and pinned submodule;
2. checked-in specifications and parameter receipts;
3. immutable executed receipts, checkpoints, and sealed evidence;
4. explanatory documentation.

Use [artifacts/README.md](artifacts/README.md) and
[results/README.md](results/README.md) for local tree conventions. Never use
an archived README, a log line, or a passing prefix as a substitute for a final
verified receipt.

## Troubleshooting and safety

- First inspect the command's terminal message, its campaign or acquisition
  checkpoint, attempt result, and preserved logs. Do not delete a failed root
  to “retry”.
- Confirm the exact heads and Gitlink with the read-only Git commands shown
  above before and after an idle-period diagnosis, never during a live
  source-bound operation.
- Check Docker reachability with `docker info` and host/storage health with
  read-only system tools. Do not prune Docker, caches, results, or evidence
  while a transaction is active.
- Use `./qcsd-lab lifecycle-recover` only for a retained lifecycle transaction
  and follow its reported policy. It is not a way to turn a failed cohort into
  reusable evidence.
- Distinguish operational, semantic, workload, transport, defence-fidelity, and
  infrastructure failures. Fix implementation defects when required, preserve
  the failed evidence, and restart under a fresh cohort if source changes.
- Before claiming progress, deep-verify the final receipt and report the
  scientific numerator, not merely launched attempts or passing prefixes.

Agent and harness operators must also follow the repository-local
[AGENTS.md](AGENTS.md).
