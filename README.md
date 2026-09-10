# QCSD Lab operator guide

Documentation refresh: 11 September 2026, Australia/Sydney (AEST, UTC+10)

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

Cohort v84 binds exact clean Lab
`46eb8172a4fba42a07e7e4da3a40c444ee48259d` and Rust/gitlink
`46313bef90ad392b7ca293ab7cf28108d2f35c7f`. Its fresh no-cache build/completion
and pinned-CDP gates passed with router instrumentation v14, Playwright policy
v8, and the current outer/nested contracts 13/12. Before browser-egress
creation, an unreceipted Docker Chromium integration run passed 11 cases and
then exposed a test-harness mismatch: pinned Playwright Python 1.57 has no
public `BrowserContext.set_http_credentials` method. The server-side v8 guard
was already on the correct protocol mutation boundary; the corrected test
reaches it through Playwright's pinned private protocol channel.

No v84 browser-egress checkpoint, vector, or final receipt exists. Because the
test correction changes tracked source, v84 is immutable historical evidence
and a fresh v85 build must reproduce its gates. Current scientific progress
therefore remains browser-egress **0/110**, certification **0/900**, and formal
capture **0/16,000**.

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

## Immutable execution rules

1. Supply the allocator-authorised next unused positive cohort version. Receipt
   absence does not make an attempted version reusable.
2. Build from one clean pinned Lab checkout and exact Rust Gitlink. A source,
   parameter, workload, acceptance-rule, or image change requires a fresh
   cohort and fresh downstream evidence.
3. Evidence destinations are create-only. Never overwrite a receipt, accepted
   sample, sealed result, handoff, or attestation.
4. `experiment.json` is the authoritative checkpoint. Resume only with the
   same source and arguments after an ordinary interruption. Never resume an
   old cohort after a source-changing fix.
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

1. After any pending source correction is validated and committed, allocate the
   next unused cohort, build fresh images, run pinned-CDP and all 110
   browser-egress vectors, then pass isolated reference, timing-stress,
   nine-mode regression, code, and controlled qualification gates.
2. Publish and verify the class-foundation attestation.
3. Initialise, run/watch, verify, and complete public acquisition before
   freezing the final 100-class cohort. Multi-origin resources remain eligible
   and must not be intentionally omitted.
4. Generate pilot and authoritative fitting campaigns over independent visits;
   derive and qualify every numeric or prefix input required by the applicable
   defences.
5. Run the 100-class × nine-mode × one-visit certification campaign and its
   prescribed canaries. A cell counts only after exact workload correctness and
   defence evidence pass.
6. Freeze readiness and historical-pre evidence, then capture the 100-class ×
   eight research-mode × 20-visit formal corpus (16,000 accepted samples) in
   its prescribed order.
7. Seal and verify results, create the immutable handoff, evaluate, complete the
   comparison review, and publish `validation-attestation.json` only if every
   gate passes.

Useful read-only checks include:

```shell
./qcsd-lab class-study status
./qcsd-lab class-study acquisition-status --acquisition-root PATH
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

- First inspect the command's terminal message and the relevant
  `experiment.json`, attempt result, and preserved logs. Do not delete a failed
  root to “retry”.
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
